#!/usr/bin/env python3
"""Regression tests for the event-transport proof analyzer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_analyzer() -> ModuleType:
    path = Path(__file__).parents[1] / "benchmarks/runner/analyze-event-transport.py"
    spec = importlib.util.spec_from_file_location("event_transport_analysis", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analyzer from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_analyzer()


class EventTransportAnalysisTests(unittest.TestCase):
    def test_quantity_conversion(self) -> None:
        self.assertEqual(ANALYZER.quantity_cpu_m("2500000n"), 2.5)
        self.assertEqual(ANALYZER.quantity_cpu_m("7m"), 7.0)
        self.assertEqual(ANALYZER.quantity_memory_mib("2Gi"), 2048.0)
        self.assertEqual(ANALYZER.quantity_memory_mib("512Ki"), 0.5)

    def test_resource_totals_exclude_incomplete_agent_samples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            pods = {
                "items": [
                    {
                        "metadata": {
                            "name": "agent-a",
                            "labels": {"app.kubernetes.io/name": "e-navigator"},
                        },
                        "spec": {"nodeName": "node-a"},
                    },
                    {
                        "metadata": {
                            "name": "agent-b",
                            "labels": {"app.kubernetes.io/name": "e-navigator"},
                        },
                        "spec": {"nodeName": "node-b"},
                    },
                    {
                        "metadata": {
                            "name": "load",
                            "labels": {"app.kubernetes.io/component": "load"},
                        },
                        "spec": {"nodeName": "node-a"},
                    },
                ]
            }
            (run_dir / "pod-json.txt").write_text(json.dumps(pods))
            (run_dir / "top-pods-10-samples.txt").write_text(
                "\n".join(
                    [
                        "sample=1 timestamp=one",
                        "agent-a e-navigator 10m 20Mi",
                        "sample=2 timestamp=two",
                        "agent-a e-navigator 11m 21Mi",
                        "agent-b e-navigator 12m 22Mi",
                    ]
                )
            )

            result = ANALYZER.read_pod_top(run_dir)

        self.assertEqual(result["expected_agent_pods"], 2)
        self.assertEqual(result["incomplete_agent_samples_excluded"], 1)
        self.assertEqual(result["agent_total_cpu_m"]["samples"], 1)
        self.assertEqual(result["agent_total_cpu_m"]["mean"], 23.0)
        self.assertEqual(result["agent_workload_node_cpu_m"]["mean"], 11.0)


if __name__ == "__main__":
    unittest.main()
