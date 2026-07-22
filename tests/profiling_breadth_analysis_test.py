#!/usr/bin/env python3
"""Regression tests for the profiling-breadth proof analyzer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_analyzer() -> ModuleType:
    path = Path(__file__).parents[1] / "benchmarks/runner/analyze-profiling-breadth.py"
    spec = importlib.util.spec_from_file_location("profiling_breadth_analysis", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analyzer from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_analyzer()


def profile_signal(mode: str) -> dict[str, object]:
    attributes = [
        {"key": "profiling.sample.mode", "value": mode},
        {"key": "profiling.stack.py_frames", "value": "1" if mode == "on_cpu" else "0"},
    ]
    if mode != "on_cpu":
        attributes.append({"key": "profiling.sample.weight_nanos", "value": "5000000"})
    return {
        "source": "source.aya_cpu_profile",
        "kind": "profile_sample_observation",
        "payload": {
            "process": {"command": "python"},
            "kubernetes": {"namespace": "e-navigator-bench"},
            "attributes": attributes,
            "stack_frames": [
                {"symbol": "profile_leaf"},
                {"symbol": "profile_level_one"},
            ],
        },
    }


class ProfilingBreadthAnalysisTests(unittest.TestCase):
    def test_workload_requires_cpython_311_and_positive_activity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            result = {
                "schema": "e-navigator.profiling-breadth-workload.v1",
                "python_version": "3.11.15",
                "busy_batches": 10,
                "lock_acquisitions": 20,
                "sleeps": 30,
                "elapsed_seconds": 2.0,
            }
            (run_dir / "workload-logs.txt").write_text(json.dumps(result))
            self.assertEqual(ANALYZER.read_workload(run_dir)["busy_batches_per_second"], 5.0)

            result["python_version"] = "3.12.9"
            (run_dir / "workload-logs.txt").write_text(json.dumps(result))
            with self.assertRaises(ValueError):
                ANALYZER.read_workload(run_dir)

    def test_profile_evidence_requires_all_modes_scope_weights_and_zero_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            (run_dir / "logs.txt").write_text(
                "\n".join(
                    json.dumps(profile_signal(mode))
                    for mode in ("on_cpu", "off_cpu", "futex_wait")
                )
            )
            metrics = {
                "profile_events_total": 1000,
                "profile_output_attempts_total": 3,
                "profile_capture_failures_total": 1,
                "profile_state_replacements_total": 0,
                "profile_pending_misses_total": 0,
                "lost_transport_events_total": 0,
                "lost_perf_events_total": 0,
                "ring_buffer_reservation_failures_total": 0,
            }
            (run_dir / "prometheus-http-metrics-e-navigator-test.txt").write_text(
                "\n".join(
                    f'e_navigator_ebpf_source_{name}{{source="source.aya_cpu_profile"}} {value}'
                    for name, value in metrics.items()
                )
            )
            (run_dir / "prometheus-http-pprof-profile-e-navigator-test.pb").write_bytes(b"pprof")

            evidence = ANALYZER.read_profile_evidence(run_dir)
            run = {"agent_pods": ["e-navigator-test"], "profile_evidence": evidence}
            ANALYZER.validate("profiling", run, run_dir)
            self.assertEqual(evidence["sample_counts"], {"on_cpu": 1, "off_cpu": 1, "futex_wait": 1})
            self.assertEqual(evidence["python_frame_names"], ["profile_leaf", "profile_level_one"])
            self.assertEqual(evidence["capture_failure_rate_percent"], 0.1)

            evidence["metrics"]["e_navigator_ebpf_source_lost_transport_events_total"] = 1
            evidence["zero_transport_state_and_unscoped_miss_counters"] = False
            with self.assertRaises(ValueError):
                ANALYZER.validate("profiling", run, run_dir)

    def test_correctness_gate_rejects_a_contaminated_baseline(self) -> None:
        evidence = {
            "zero_transport_state_and_unscoped_miss_counters": True,
            "capture_failure_rate_percent": 0.0,
        }
        resources = {
            "agent_total_cpu_m": {"mean": None},
            "agent_total_memory_mib": {"mean": None},
        }
        runs = [
            {
                "mode": "none",
                "workload": {"busy_batches_per_second": 10.0},
                "agent_pods": ["unexpected-agent"],
                "pod_resources": resources,
                "profile_evidence": None,
            },
            {
                "mode": "profiling",
                "workload": {"busy_batches_per_second": 9.0},
                "agent_pods": ["expected-agent"],
                "pod_resources": resources,
                "profile_evidence": evidence,
            },
        ]
        self.assertFalse(ANALYZER.aggregate(runs)["correctness_gate_passed"])


if __name__ == "__main__":
    unittest.main()
