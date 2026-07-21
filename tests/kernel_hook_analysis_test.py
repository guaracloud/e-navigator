#!/usr/bin/env python3
"""Regression tests for the kernel-hook proof analyzer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_analyzer() -> ModuleType:
    path = Path(__file__).parents[1] / "benchmarks/runner/analyze-kernel-hooks.py"
    spec = importlib.util.spec_from_file_location("kernel_hook_analysis", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analyzer from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_analyzer()


class KernelHookAnalysisTests(unittest.TestCase):
    def test_workload_requires_exact_byte_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            payload = {
                "schema": "e-navigator.kernel-hook-workload.v1",
                "operations": 2,
                "payload_bytes": 256,
                "bytes_sent": 512,
                "bytes_received": 512,
            }
            (run_dir / "workload-logs.txt").write_text("prefix " + json.dumps(payload))
            result = ANALYZER.read_workload(run_dir)
        self.assertEqual(result["bytes_sent"], 512)

    def test_agent_evidence_matches_exact_connection_and_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            workload = {
                "server_port": 43210,
                "client_fd": 5,
                "bytes_sent": 1024,
                "bytes_received": 1024,
            }
            signal = {
                "kind": "network_connection_close",
                "payload": {
                    "process": {"command": "python"},
                    "remote_address": "127.0.0.1",
                    "remote_port": 43210,
                    "fd": 5,
                    "bytes_sent": 1024,
                    "bytes_received": 1024,
                    "kubernetes": {"namespace": "e-navigator-bench"},
                },
            }
            (run_dir / "logs.txt").write_text(
                'selected network I/O kernel hook network_io_hook="fexit"\n'
                + json.dumps(signal)
            )
            (run_dir / "runtime-config.toml").write_text('network_io_hook = "fexit"\n')
            metrics = "\n".join(
                f'e_navigator_ebpf_source_{name}{{source="source.aya_network"}} 0'
                for name in [
                    "lost_transport_events_total",
                    "lost_perf_events_total",
                    "ring_buffer_reservation_failures_total",
                ]
            )
            (run_dir / "prometheus-http-metrics.txt").write_text(metrics)
            evidence = ANALYZER.read_agent_evidence(run_dir, workload)
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence["configured_hook"], "fexit")
        self.assertEqual(evidence["hook_selections"], ["fexit"])
        self.assertEqual(evidence["exact_close_count"], 1)
        self.assertTrue(evidence["zero_loss"])


if __name__ == "__main__":
    unittest.main()
