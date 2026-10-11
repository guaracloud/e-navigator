"""Replacement qualification fails per family and never fabricates history."""
import copy
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_replacement as suite
from replacement_fixture import fixture


class ReplacementQualificationTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.capture = fixture()

    def result(self):
        return suite.evaluate(self.manifest, self.capture)

    def assert_failed(self, cell_id, name="normal"):
        result = self.result()
        self.assertEqual(result["verdict"], "failed")
        self.assertEqual(result["cells"][cell_id]["scenarios"][name]["verdict"], "failed")
        self.assertFalse(result["replacement_qualified"])

    def test_reproducible_fixture_and_all_scenarios(self):
        self.assertEqual((self.manifest, self.capture), fixture())
        result = self.result()
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(sum(len(cell["scenarios"]) for cell in result["cells"].values()), 90)
        self.assertFalse(result["replacement_qualified"])
        self.assertEqual(len(result["blocked_inputs"]), 7)

    def test_each_absent_required_family_fails_despite_other_telemetry(self):
        for cell_id in self.manifest["cells"]:
            saved = self.capture["cells"].pop(cell_id)
            with self.subTest(cell_id=cell_id):
                self.assert_failed(cell_id)
            self.capture["cells"][cell_id] = saved

    def test_inventory_cannot_shrink_to_match_capture(self):
        del self.manifest["cells"]["GW-REDIS-9001"]
        del self.capture["cells"]["GW-REDIS-9001"]
        with self.assertRaises(ValueError):
            self.result()

    def test_required_skip_and_optional_failure_are_explicit(self):
        cell_id = "GW-REDIS-9001"
        self.capture["cells"][cell_id]["normal"] = {"status": "skipped", "reason": "capture not available"}
        result = self.result()
        self.assertEqual(result["verdict"], "failed")
        self.assertEqual(result["cells"][cell_id]["scenarios"]["normal"]["verdict"], "skipped")
        # An optional extra cell cannot hide a required family's skip.
        optional_id = "GW-REDIS-9002"
        self.manifest["cells"][optional_id] = copy.deepcopy(self.manifest["cells"][cell_id])
        self.manifest["cells"][optional_id]["requiredness"] = "optional"
        self.capture["cells"][optional_id] = {}
        result = self.result()
        self.assertEqual(result["cells"][optional_id]["verdict"], "optional-incomplete")
        self.assertEqual(result["verdict"], "failed")

    def test_partial_history_cannot_be_fabricated_even_by_matching_oracle(self):
        cell_id, name = "GW-REDIS-9001", "late-attachment"
        for container in [self.manifest["cells"][cell_id]["scenarios"][name], self.capture["cells"][cell_id][name]]:
            container["native"][0]["payload"]["start_unix_nanos"] = 1500000000
        self.assert_failed(cell_id, name)

    def test_retained_log_history_requires_retention_and_later_observation(self):
        cell_id, name = "GW-LOG-9001", "late-attachment"
        result = self.result()["cells"][cell_id]["scenarios"][name]
        self.assertEqual(result["history"]["historical_records"], 1)
        for container in [self.manifest["cells"][cell_id]["scenarios"][name], self.capture["cells"][cell_id][name]]:
            container["native"][0]["payload"]["observed_at_unix_nanos"] = 1400000000
        self.assert_failed(cell_id, name)

    def test_privacy_canary_in_native_or_backend_fails_and_is_not_persisted(self):
        cell_id, name = "GW-HTTP-9001", "privacy"
        marker = self.manifest["cells"][cell_id]["scenarios"][name]["forbidden_values"][0]
        evidence = self.capture["cells"][cell_id][name]
        for target in [evidence["native"][0], next(iter(evidence["backend"].values()))]:
            target["private"] = marker
            self.assert_failed(cell_id, name)
            self.assertNotIn(marker, json.dumps(self.result()))
            del target["private"]

    def test_unsupported_control_requires_visible_rejection_and_no_stored_data(self):
        cell_id, name = "GW-CPU-9001", "unsupported-version"
        evidence = self.capture["cells"][cell_id][name]
        evidence["counters"]["unsupported_versions"] = 0
        self.assert_failed(cell_id, name)
        evidence["counters"]["unsupported_versions"] = 2
        evidence["backend"] = self.capture["cells"][cell_id]["normal"]["backend"]
        self.assert_failed(cell_id, name)

    def test_parentage_outcome_and_duplicate_span_identity_fail(self):
        cell_id = "GW-HTTP-9001"
        evidence = self.capture["cells"][cell_id]["normal"]
        response = next(iter(evidence["backend"].values()))
        span = response["batches"][1]["scopeSpans"][0]["spans"][0]
        for key, value in [("parentSpanId", "f" * 16), ("status", {"code": 2}), ("spanId", response["batches"][0]["scopeSpans"][0]["spans"][0]["spanId"])]:
            original = span[key]
            span[key] = value
            self.assert_failed(cell_id)
            span[key] = original

    def test_profile_weight_log_content_and_metric_identity_fail(self):
        self.capture["cells"]["GW-CPU-9001"]["normal"]["native"][0]["payload"]["sample_count"] = 100
        self.assert_failed("GW-CPU-9001")
        self.capture["cells"]["GW-LOG-9001"]["normal"]["backend"]["data"]["result"][0]["values"][0][1] = "wrong"
        self.assert_failed("GW-LOG-9001")
        self.capture["cells"]["GW-TCP-9001"]["normal"]["backend"]["data"]["result"][0]["metric"]["owner_name"] = "other-workload"
        self.assert_failed("GW-TCP-9001")

    def test_workload_scenarios_cannot_be_renamed_normal_runs(self):
        cell = self.manifest["cells"]["GW-HTTP-9001"]
        for name in ["concurrent", "pooling", "retry-reconnect", "process-restart", "agent-restart", "late-attachment", "unsupported-version"]:
            original = cell["scenarios"][name]["workload"]
            cell["scenarios"][name]["workload"] = cell["scenarios"]["normal"]["workload"]
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.result()
            cell["scenarios"][name]["workload"] = original

    def test_loss_identity_and_seed_mismatches_fail(self):
        cell_id = "GW-KAFKA-9001"
        evidence = self.capture["cells"][cell_id]["normal"]
        for key, value in [("counters", {"capture_loss": 1, "export_loss": 0, "unsupported_versions": 0}), ("seed", 99), ("identity", {})]:
            original = evidence[key]
            evidence[key] = value
            self.assert_failed(cell_id)
            evidence[key] = original

    def test_reused_trace_ids_and_mismatched_cpu_descriptors_are_rejected(self):
        cell = self.manifest["cells"]["GW-HTTP-9001"]
        original = cell["scenarios"]["concurrent"]["backend"]["query_trace_ids"]
        cell["scenarios"]["concurrent"]["backend"]["query_trace_ids"] = cell["scenarios"]["normal"]["backend"]["query_trace_ids"]
        with self.assertRaises(ValueError):
            self.result()
        cell["scenarios"]["concurrent"]["backend"]["query_trace_ids"] = original
        self.manifest["cells"]["GW-CPU-9001"]["scenarios"]["normal"]["backend"]["cell"]["identity"]["build_id"] = "different-build"
        with self.assertRaises(ValueError):
            self.result()

    def test_backend_credentials_and_redirects_are_rejected(self):
        oracle = self.manifest["cells"]["GW-LOG-9001"]["scenarios"]["normal"]["backend"]
        with patch.object(suite, "build_opener") as opener:
            for url in ["https://user:private@fixture.invalid", "https://fixture.invalid?access=private", "https://fixture.invalid#private", "file:///tmp/input"]:
                with self.assertRaises(ValueError):
                    suite.query_backend(oracle, {"logs": url})
            opener.assert_not_called()
        with self.assertRaises(ValueError):
            suite.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://fixture.invalid")

    def test_live_requires_approved_target_inputs_and_nonfixture_manifest(self):
        endpoints = dict.fromkeys(["traces", "profiles", "logs", "metrics"], "http://fixture.invalid")
        auth = {"approved": True, "target": "synthetic-local", "owner": "test-owner", "reference": "unit-test"}
        with patch.object(suite, "query_backend") as query:
            with self.assertRaises(ValueError):
                suite.evaluate(self.manifest, self.capture, endpoints, auth)
            self.manifest["fixture"] = False
            with self.assertRaises(ValueError):
                suite.evaluate(self.manifest, self.capture, endpoints, auth)
            self.manifest["blocked_inputs"] = []
            auth["target"] = "wrong-target"
            with self.assertRaises(ValueError):
                suite.evaluate(self.manifest, self.capture, endpoints, auth)
            query.assert_not_called()

    def test_live_queries_all_backends_and_cannot_promote_skips(self):
        self.manifest["fixture"] = False
        self.manifest["blocked_inputs"] = []
        responses = {}
        for cell_id, cell in self.manifest["cells"].items():
            cell.update(support="implemented", approval="test-only-approval")
            for name, scenario in cell["scenarios"].items():
                responses[id(scenario["backend"])] = self.capture["cells"][cell_id][name]["backend"]
        endpoints = dict.fromkeys(["traces", "profiles", "logs", "metrics"], "http://fixture.invalid")
        auth = {"approved": True, "target": "synthetic-local", "owner": "test", "reference": "unit-test"}
        with patch.object(suite, "query_backend", side_effect=lambda oracle, _: responses[id(oracle)]) as query:
            result = suite.evaluate(self.manifest, self.capture, endpoints, auth)
            self.assertEqual(query.call_count, 90)
            self.assertEqual(result["verdict"], "passed")
            self.assertFalse(result["replacement_qualified"])
            self.capture["cells"]["GW-LOG-9001"]["normal"] = {"status": "skipped", "reason": "no capture"}
            self.assertEqual(suite.evaluate(self.manifest, self.capture, endpoints, auth)["verdict"], "failed")

    def test_real_http_query_paths_and_response_assertions(self):
        # Loopback API emulation tests transport only, never backend qualification.
        replies, requests = [], []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, None))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(replies.pop(0)).encode())
            def do_POST(self):
                requests.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(replies.pop(0)).encode())
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            endpoints = dict.fromkeys(["traces", "profiles", "logs", "metrics"], f"http://127.0.0.1:{server.server_port}")
            for cell_id in ["GW-HTTP-9001", "GW-CPU-9001", "GW-LOG-9001", "GW-TCP-9001"]:
                oracle = self.manifest["cells"][cell_id]["scenarios"]["normal"]["backend"]
                expected = self.capture["cells"][cell_id]["normal"]["backend"]
                replies.extend(expected.values() if oracle["type"] == "traces" else [expected])
                actual = suite.query_backend(oracle, endpoints)
                self.assertEqual(actual, expected)
                suite.assert_backend(oracle, actual, self.capture["cells"][cell_id]["normal"]["native"])
            self.assertTrue(requests[0][0].startswith("/api/traces/"))
            self.assertEqual(requests[2][0], "/querier.v1.QuerierService/SelectMergeStacktraces")
            self.assertEqual(requests[2][1]["maxNodes"], suite.cpu.MAX_NODES)
            self.assertTrue(requests[3][0].startswith("/loki/api/v1/query_range?"))
            self.assertTrue(requests[4][0].startswith("/api/v1/query?"))
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_malformed_oversized_and_duplicate_json_rejected(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b"x" * (suite.MAX_BYTES + 1)]:
            with self.assertRaises(ValueError):
                suite.read_json(io.BytesIO(raw))

    def test_cli_success_and_failure_always_write_result_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest, capture, output = [directory / name for name in ["manifest.json", "capture.json", "result.json"]]
            manifest.write_text(json.dumps(self.manifest))
            capture.write_text(json.dumps(self.capture))
            command = [sys.executable, str(ROOT / "scripts/qualify_replacement.py"), "--manifest", str(manifest), "--capture", str(capture), "--output", str(output)]
            run = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(output.read_text())["verdict"], "passed")
            capture.write_text("{invalid}")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertEqual(json.loads(output.read_text())["verdict"], "failed")


if __name__ == "__main__":
    unittest.main()
