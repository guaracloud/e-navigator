#!/usr/bin/env python3
"""Regression tests for the bootstrap-window proof analyzer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def load_analyzer() -> ModuleType:
    path = Path(__file__).parents[1] / "benchmarks/runner/analyze-bootstrap-window.py"
    spec = importlib.util.spec_from_file_location("bootstrap_window_analysis", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analyzer from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_analyzer()


def workload_lines(started: int) -> str:
    return "\n".join(
        [
            json.dumps(
                {
                    "schema": "e-navigator.bootstrap-window-start.v1",
                    "started_unix_nanos": started,
                    "uid": 65532,
                }
            ),
            json.dumps(
                {
                    "schema": "e-navigator.bootstrap-window-workload.v1",
                    "attempts": 200,
                    "duration_seconds": 3,
                    "elapsed_seconds": 3.0,
                    "failures": 0,
                    "started_unix_nanos": started,
                    "uid": 65532,
                }
            ),
        ]
    )


def metrics(mode: str) -> str:
    event = mode == "event_driven"
    values = {
        "discovery_notifications_total": 2 if event else 0,
        "discovery_coalesced_total": 1 if event else 0,
        "event_reconciliations_total": 1 if event else 0,
        "fallback_reconciliations_total": 2,
        "inotify_events_total": 4 if event else 0,
        "inotify_watches": 12 if event else 0,
        "inotify_failures_total": 0,
        "inotify_queue_overflows_total": 0,
        "inotify_watch_limit_drops_total": 0,
        "bootstrap_window_observations_total": 2,
        "bootstrap_window_seconds_sum": 0.2,
        "bootstrap_window_seconds_max": 0.1,
        "map_apply_failures_total": 0,
    }
    lines = [f'e_navigator_capture_filter_discovery_info{{mode="{mode}"}} 1']
    lines.extend(
        f"e_navigator_capture_filter_{name} {value}" for name, value in values.items()
    )
    for name in (
        "lost_transport_events_total",
        "lost_perf_events_total",
        "ring_buffer_reservation_failures_total",
        "send_failures_total",
    ):
        lines.append(
            f'e_navigator_ebpf_source_{name}{{source="source.aya_exec"}} 0'
        )
    return "\n".join(lines)


def write_run(path: Path, mode: str, window_millis: float) -> None:
    path.mkdir()
    started = 1_000_000_000
    (path / "workload-logs.txt").write_text(workload_lines(started))
    if mode == "none":
        pods = {"items": []}
    else:
        pods = {
            "items": [
                {
                    "metadata": {
                        "name": f"agent-{index}",
                        "labels": {"app.kubernetes.io/name": "e-navigator"},
                    }
                }
                for index in range(2)
            ]
        }
    (path / "pod-json.txt").write_text(json.dumps(pods))
    if mode == "none":
        return
    configured = "event_driven" if mode == "event" else "polling"
    timestamp = started + int(window_millis * 1_000_000)
    signal = {
        "source": "source.aya_exec",
        "kind": "exec",
        "payload": {
            "command": ANALYZER.PROBE_COMMAND,
            "uid": 65532,
            "timestamp_unix_nanos": timestamp,
        },
    }
    (path / "logs.txt").write_text(json.dumps(signal))
    for index in range(2):
        (path / f"prometheus-http-metrics-e-navigator-{index}.txt").write_text(
            metrics(configured)
        )


class BootstrapWindowAnalysisTests(unittest.TestCase):
    def test_agent_run_requires_matching_mode_and_reports_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "event-r1"
            write_run(run_dir, "event", 42.5)
            result = ANALYZER.validate_run("event", run_dir)

        self.assertEqual(result["signal_window_millis"], 42.5)
        self.assertEqual(result["correlated_signals"], 1)
        self.assertGreater(
            result["native_accounting"][
                "e_navigator_capture_filter_event_reconciliations_total"
            ],
            0,
        )

    def test_aggregate_requires_and_compares_five_runs_per_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_run(root / "none-r1", "none", 0)
            for repetition in range(1, 6):
                write_run(root / f"polling-r{repetition}", "polling", 900 + repetition)
                write_run(root / f"event-r{repetition}", "event", 40 + repetition)

            result = ANALYZER.aggregate(root)

        self.assertEqual(result["verdict"], "pass")
        self.assertGreater(result["median_reduction_millis"], 800)
        self.assertEqual(result["window_millis"]["event_driven"]["samples"], 5)


if __name__ == "__main__":
    unittest.main()
