"""CPU replacement checks must fail per cell and use sample weight."""
import copy
import importlib.util
import io
import re
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
SPEC = importlib.util.spec_from_file_location("cpu_qualification", Path(__file__).resolve().parents[1] / "scripts/qualify_cpu_profiles.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture():
    cells, captures, profiles = {}, {}, {}
    for number, domain in [(1, "user"), (2, "managed_runtime")]:
        cell_id = f"WC-CPU-{number:04}"
        cells[cell_id] = {
            "identity": {"runtime": "native" if number == 1 else "cpython", "version": "fixture", "build_id": "0123456789abcdef", "architecture": "x86_64", "image_digest": "sha256:" + "a" * 64},
            "process": {"pid": number, "command": "fixture"},
            "query": {"start": 1000, "end": 2000, "labelSelector": f'{{service_name="fixture-{number}"}}', "profileTypeID": "process_cpu:cpu:nanoseconds:cpu:nanoseconds"},
            "stack": [{"symbol": "outer", "domain": domain}, {"symbol": "busy", "domain": domain}],
            "thresholds": {"min_weight_nanos": 100, "min_useful_bps": 9000, "max_unknown_bps": 1000, "max_truncated_bps": 1000, "max_failed_bps": 1000, "max_weight_error_bps": 100},
        }
        captures[cell_id] = {"identity": cells[cell_id]["identity"], "samples": [{
            "schema_version": 1, "host": None, "source": "source.aya_cpu_profile", "kind": "profile_sample_observation", "payload": {
                "timestamp_unix_nanos": 1500000000, "profiling_kind": "cpu", "sample_count": 10, "sampling_period_nanos": 10,
                "correlation_kind": "observed_profile_sample", "confidence": "high", "stack_id": "fixture-stack",
                "container": None, "kubernetes": None, "thread_id": number, "thread_name": "fixture",
                "process": dict(cells[cell_id]["process"]), "stack_frames": list(reversed(copy.deepcopy(cells[cell_id]["stack"]))),
                "attributes": [{"key": "profiling.sample.mode", "value": "on_cpu"}],
            },
        }]}
        profiles[cell_id] = {"flamegraph": {"names": ["total", "outer", "busy"], "total": "100", "levels": [
            {"values": [0, 100, 0, 0]}, {"values": [0, 100, 0, 1]}, {"values": [0, 100, 100, 2]},
        ]}}
    return cells, captures, profiles


class CpuQualificationTests(unittest.TestCase):
    def test_enrollment_fence_cannot_evict_or_allocate_on_unrelated_lifecycle(self):
        # Preserve the safety handshake where native BPF execution needs Linux.
        source = (Path(__file__).resolve().parents[1] / "crates/e-navigator-ebpf-programs/src/main.rs").read_text()
        self.assertIn("static PROFILE_PROCESS_GENERATIONS: HashMap<u32, ProfileGeneration>", source)
        invalidate = source.split("fn invalidate_profile_process()", 1)[1].split("fn profile_generation_matches", 1)[0]
        self.assertNotIn("PROFILE_PROCESS_GENERATIONS.insert", invalidate)
        enter = source.split("pub fn tracepoint_profile_mapping_enter", 1)[1].split("pub fn tracepoint_profile_mapping_exit", 1)[0]
        normalized = re.sub(r"\s+", "", enter)
        self.assertLess(normalized.index("PENDING_PROFILE_MAPPINGS.insert"), normalized.index("PROFILE_PROCESS_GENERATIONS.get_ptr_mut"))
        self.assertIn("PROFILE_GENERATION_POISON.get_ptr_mut", enter)
        self.assertIn("59 |", enter)
        self.assertIn("322 |", enter)
        self.assertIn("221 |", enter)
        self.assertIn("281 |", enter)
        execute = source.split("pub fn tracepoint_profile_process_exec", 1)[1].split("pub fn tracepoint_profile_mapping_enter", 1)[0]
        self.assertIn("ctx.read_at::<u32>(16)", execute)
        self.assertIn("finish_profile_mapping_key(key)", execute)

    def test_checked_in_synthetic_evidence_matches_fixture(self):
        directory = Path(__file__).parent / "fixtures/cpu-qualification"
        inputs = [json.loads((directory / (name + ".json")).read_text()) for name in ["cells", "capture", "profiles"]]
        self.assertEqual(tuple(inputs), fixture())
        MODULE.qualify(*inputs)

    def test_query_mode_uses_exact_cell_selectors_and_never_promotes(self):
        cells, captures, profiles = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, value in [("cells", cells), ("capture", captures)]:
                (directory / (name + ".json")).write_text(json.dumps(value))
            output = directory / "result.json"
            requests = []
            def response(request, timeout):
                cell_id = list(cells)[len(requests)]
                self.assertEqual(json.loads(request.data), dict(cells[cell_id]["query"], maxNodes=MODULE.MAX_NODES))
                self.assertEqual(request.full_url, "https://fixture.invalid/querier.v1.QuerierService/SelectMergeStacktraces")
                self.assertEqual(timeout, 30)
                requests.append(request)
                return io.BytesIO(json.dumps(profiles[cell_id]).encode())
            argv = ["qualify", "--cells", str(directory / "cells.json"), "--capture", str(directory / "capture.json"), "--pyroscope-url", "https://fixture.invalid", "--output", str(output)]
            with patch.object(sys, "argv", argv), patch.object(MODULE, "urlopen", response):
                self.assertEqual(MODULE.main(), 0)
            result = json.loads(output.read_text())
            self.assertEqual(result["mode"], "pyroscope-query")
            self.assertFalse(result["replacement_qualified"])
            self.assertEqual(len(requests), 2)

    def test_native_and_managed_cells_pass_independently(self):
        cells, captures, profiles = fixture()
        result = MODULE.qualify(cells, captures, profiles)
        self.assertEqual(set(result), set(cells))
        self.assertEqual(result["WC-CPU-0002"]["useful_weight_nanos"], 100)

    def test_missing_cell_cannot_be_hidden_by_another(self):
        for target in ["capture", "profiles"]:
            cells, captures, profiles = fixture()
            missing = captures if target == "capture" else profiles
            del missing["WC-CPU-0002"]
            with self.assertRaises(ValueError):
                MODULE.qualify(cells, captures, profiles)
            cells, captures, profiles = fixture()

    def test_failed_truncated_unknown_and_wrong_domain_fail(self):
        for mutation in ["unknown", "truncated", "failed", "domain", "identity", "weight", "time", "off_cpu"]:
            cells, captures, profiles = fixture()
            capture = captures["WC-CPU-0002"]
            sample = capture["samples"][0]["payload"]
            if mutation == "unknown":
                sample["stack_frames"][1] = {"symbol": "0xdead", "domain": "unknown"}
            elif mutation in {"failed", "truncated"}:
                sample["attributes"].append({"key": "profiling.stack.py_stop" if mutation == "failed" else "profiling.stack.truncated", "value": "read_fault" if mutation == "failed" else "true"})
            elif mutation == "domain":
                sample["stack_frames"][0]["domain"] = "user"
            elif mutation == "identity":
                capture["identity"] = dict(capture["identity"], build_id="ffffffff")
            elif mutation == "weight":
                sample["sampling_period_nanos"] = 1000
            elif mutation == "time":
                sample["timestamp_unix_nanos"] = 2000000001
            else:
                sample["attributes"][0]["value"] = "off_cpu"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.qualify(cells, captures, profiles)

    def test_backend_requires_caller_chain_not_just_names(self):
        cells, captures, profiles = fixture()
        profiles["WC-CPU-0002"]["flamegraph"]["levels"] = [
            {"values": [0, 100, 0, 0]}, {"values": [0, 50, 50, 1, 0, 50, 50, 2]},
        ]
        with self.assertRaises(ValueError):
            MODULE.qualify(cells, captures, profiles)

    def test_bad_weight_is_weighted_not_counted(self):
        cells, captures, profiles = fixture()
        sample = copy.deepcopy(captures["WC-CPU-0001"]["samples"][0])
        sample["payload"]["sample_count"] = 1
        sample["payload"]["sampling_period_nanos"] = 1000
        sample["payload"]["stack_frames"] = [{"symbol": "unknown", "domain": "unknown"}]
        captures["WC-CPU-0001"]["samples"].append(sample)
        with self.assertRaises(ValueError):
            MODULE.qualify(cells, captures, profiles)

    def test_empty_malformed_and_pruned_flamegraphs_fail(self):
        cells, captures, profiles = fixture()
        for levels in [[], [{"values": [0, 100, 0]}], [{"values": [0, 100, 0, 99]}], [{"values": [0, 100, -1, 0]}]]:
            profiles["WC-CPU-0001"]["flamegraph"]["levels"] = levels
            with self.assertRaises(ValueError):
                MODULE.qualify(cells, captures, profiles)
        with self.assertRaises(ValueError):
            MODULE.qualify({}, {}, {})

    def test_cli_saved_responses_never_claim_live_qualification(self):
        cells, captures, profiles = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, value in [("cells", cells), ("capture", captures), ("profiles", profiles)]:
                (root / f"{filename}.json").write_text(json.dumps(value))
            for valid in [True, False]:
                if not valid:
                    (root / "profiles.json").write_text("{}")
                result = subprocess.run([sys.executable, MODULE.__file__, "--cells", str(root / "cells.json"), "--capture", str(root / "capture.json"), "--profiles", str(root / "profiles.json"), "--output", str(root / "result.json")], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)
                evidence = json.loads((root / "result.json").read_text())
                self.assertEqual(evidence["mode"], "saved-json")
                self.assertFalse(evidence["replacement_qualified"])
                self.assertEqual(evidence["verdict"], "passed" if valid else "failed")


if __name__ == "__main__":
    unittest.main()
