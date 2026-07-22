#!/usr/bin/env python3
"""Regression tests for the Go crypto/tls proof analyzer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_analyzer() -> ModuleType:
    path = Path(__file__).parents[1] / "benchmarks/runner/analyze-go-tls.py"
    spec = importlib.util.spec_from_file_location("go_tls_analysis", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analyzer from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_analyzer()


class GoTlsAnalysisTests(unittest.TestCase):
    def test_workload_requires_a_complete_success_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            result = {
                "schema": "e-navigator.go-tls-client.v1",
                "requests": 4,
                "succeeded": 4,
                "failed": 0,
            }
            (run_dir / "workload-logs.txt").write_text("prefix " + json.dumps(result))
            self.assertEqual(ANALYZER.read_workload(run_dir)["succeeded"], 4)

            result["failed"] = 1
            (run_dir / "workload-logs.txt").write_text(json.dumps(result))
            with self.assertRaises(ValueError):
                ANALYZER.read_workload(run_dir)

    def test_agent_evidence_is_scoped_and_requires_native_counters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            signal = {
                "source": "source.aya_tls",
                "kind": "protocol_request_observation",
                "payload": {
                    "process": {"command": "go-https-proof"},
                    "kubernetes": {"namespace": "e-navigator-bench"},
                    "attributes": [
                        {"key": "url.path", "value": "/proof"},
                        {"key": "http.response.status_code", "value": "200"},
                    ],
                },
            }
            (run_dir / "logs.txt").write_text(
                'Go crypto/tls executable is capture-ready executable="go-https-proof" '
                'go_version="go1.26.4"\n'
                'Go crypto/tls executable is not capture-ready '
                'executable="go-https-proof-stripped" stripped binaries fail closed\n'
                + json.dumps(signal)
            )
            metric_names = [
                "go_tls_entries_total",
                "go_tls_exits_total",
                "go_tls_fd_resolutions_total",
                "go_tls_output_attempts_total",
            ]
            metrics = [
                f'e_navigator_ebpf_source_{name}{{source="source.aya_tls"}} 1'
                for name in metric_names
            ]
            metrics.extend(
                [
                    'e_navigator_ebpf_source_go_tls_state_update_failures_total{source="source.aya_tls"} 0',
                    'e_navigator_ebpf_source_lost_transport_events_total{source="source.aya_tls"} 0',
                    'e_navigator_ebpf_source_ring_buffer_reservation_failures_total{source="source.aya_tls"} 0',
                ]
            )
            (run_dir / "prometheus-http-metrics.txt").write_text("\n".join(metrics))
            evidence = ANALYZER.read_agent_evidence(run_dir)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence["http_status_200_observations"], 1)
        self.assertEqual(evidence["capture_ready_go_1_26_4_log_count"], 1)
        self.assertEqual(evidence["stripped_fail_closed_log_count"], 1)
        self.assertTrue(evidence["zero_transport_loss"])

    def test_correctness_gate_rejects_contaminated_baseline(self) -> None:
        evidence = {
            "capture_ready_go_1_26_4_log_count": 1,
            "stripped_fail_closed_log_count": 1,
            "http_status_200_observations": 1,
            "zero_transport_loss": True,
            "metrics": {"e_navigator_ebpf_source_go_tls_state_update_failures_total": 0},
        }
        base = {
            "workload": {"throughput_requests_per_second": 10.0, "elapsed_seconds": 1.0},
            "pod_resources": {
                "agent_samples": 1,
                "agent_total_cpu_m": {"mean": 1.0},
                "agent_total_memory_mib": {"mean": 1.0},
            },
        }
        runs = [dict(base, mode="none", agent_evidence=None), dict(base, mode="tls", agent_evidence=evidence)]
        result = ANALYZER.aggregate(runs)
        self.assertFalse(result["no_agent_inventory_clean"])
        self.assertFalse(result["correctness_gate_passed"])


if __name__ == "__main__":
    unittest.main()
