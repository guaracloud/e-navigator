#!/usr/bin/env python3
"""Validate and summarize guarded capture-filter bootstrap-window runs."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from pathlib import Path
from typing import Any


RUN_NAME = re.compile(r"^(none|polling|event)-r([1-9][0-9]*)$")
METRIC = re.compile(
    r"^(?P<name>e_navigator_[a-zA-Z0-9_:]+)(?:\{(?P<labels>[^}]*)\})? "
    r"(?P<value>-?[0-9]+(?:\.[0-9]+)?)$"
)
PROBE_COMMAND = "/tmp/e-navigator-bootstrap-probe"


def fail(message: str) -> None:
    raise ValueError(message)


def prefixed_json(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(errors="replace").splitlines():
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            value = json.loads(line[marker:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def workload_summary(run_dir: Path) -> dict[str, Any]:
    records = prefixed_json(run_dir / "workload-logs.txt")
    starts = [
        record
        for record in records
        if record.get("schema") == "e-navigator.bootstrap-window-start.v1"
    ]
    summaries = [
        record
        for record in records
        if record.get("schema") == "e-navigator.bootstrap-window-workload.v1"
    ]
    if len(starts) != 1 or len(summaries) != 1:
        fail(f"{run_dir}: expected one start and one workload summary")
    start = starts[0]
    summary = summaries[0]
    if summary.get("uid") != 65532 or start.get("uid") != 65532:
        fail(f"{run_dir}: workload did not run as uid 65532")
    if summary.get("failures") != 0:
        fail(f"{run_dir}: workload reported failures: {summary}")
    if not isinstance(summary.get("attempts"), int) or summary["attempts"] < 100:
        fail(f"{run_dir}: workload produced too few probes: {summary}")
    if summary.get("started_unix_nanos") != start.get("started_unix_nanos"):
        fail(f"{run_dir}: workload start records disagree")
    return summary


def agent_pods(run_dir: Path) -> set[str]:
    inventory = json.loads((run_dir / "pod-json.txt").read_text())
    return {
        item.get("metadata", {}).get("name", "")
        for item in inventory.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    }


def metric_files(run_dir: Path) -> list[Path]:
    return sorted(run_dir.glob("prometheus-http-metrics-e-navigator-*.txt"))


def parse_metrics(path: Path) -> dict[str, list[tuple[str, float]]]:
    metrics: dict[str, list[tuple[str, float]]] = {}
    for line in path.read_text(errors="replace").splitlines():
        match = METRIC.match(line.strip())
        if not match:
            continue
        metrics.setdefault(match.group("name"), []).append(
            (match.group("labels") or "", float(match.group("value")))
        )
    return metrics


def scalar(metrics: dict[str, list[tuple[str, float]]], name: str) -> float:
    values = metrics.get(name, [])
    if len(values) != 1:
        fail(f"expected one {name} metric, got {len(values)}")
    return values[0][1]


def signal_window(run_dir: Path, started_unix_nanos: int) -> tuple[float, int]:
    matches: list[int] = []
    for record in prefixed_json(run_dir / "logs.txt"):
        if record.get("source") != "source.aya_exec" or record.get("kind") != "exec":
            continue
        payload = record.get("payload") or {}
        timestamp = payload.get("timestamp_unix_nanos")
        if (
            payload.get("command") == PROBE_COMMAND
            and payload.get("uid") == 65532
            and isinstance(timestamp, int)
            and timestamp >= started_unix_nanos
        ):
            matches.append(timestamp)
    if not matches:
        fail(f"{run_dir}: no workload-correlated exec signal")
    first = min(matches)
    return (first - started_unix_nanos) / 1_000_000.0, len(matches)


def validate_no_agent(run_dir: Path) -> dict[str, Any]:
    summary = workload_summary(run_dir)
    pods = agent_pods(run_dir)
    if pods:
        fail(f"{run_dir}: no-agent run contained benchmark agents: {sorted(pods)}")
    return {
        "mode": "none",
        "agent": False,
        "workload": summary,
    }


def validate_agent(mode: str, run_dir: Path) -> dict[str, Any]:
    summary = workload_summary(run_dir)
    pods = agent_pods(run_dir)
    if len(pods) != 2:
        fail(f"{run_dir}: expected two agent pods, got {sorted(pods)}")
    window_millis, signal_count = signal_window(
        run_dir, int(summary["started_unix_nanos"])
    )

    files = metric_files(run_dir)
    if len(files) != 2:
        fail(f"{run_dir}: expected two per-pod metric captures, got {len(files)}")
    parsed = [parse_metrics(path) for path in files]
    expected_info = f'mode="{mode}"'
    for metrics in parsed:
        info = metrics.get("e_navigator_capture_filter_discovery_info", [])
        if info != [(expected_info, 1.0)]:
            fail(f"{run_dir}: wrong discovery mode metric: {info}")

    summed_names = [
        "e_navigator_capture_filter_discovery_notifications_total",
        "e_navigator_capture_filter_discovery_coalesced_total",
        "e_navigator_capture_filter_event_reconciliations_total",
        "e_navigator_capture_filter_fallback_reconciliations_total",
        "e_navigator_capture_filter_inotify_events_total",
        "e_navigator_capture_filter_inotify_failures_total",
        "e_navigator_capture_filter_inotify_queue_overflows_total",
        "e_navigator_capture_filter_inotify_watch_limit_drops_total",
        "e_navigator_capture_filter_bootstrap_window_observations_total",
        "e_navigator_capture_filter_bootstrap_window_seconds_sum",
        "e_navigator_capture_filter_map_apply_failures_total",
    ]
    counters = {
        name: sum(scalar(metrics, name) for metrics in parsed) for name in summed_names
    }
    counters["e_navigator_capture_filter_bootstrap_window_seconds_max"] = max(
        scalar(metrics, "e_navigator_capture_filter_bootstrap_window_seconds_max")
        for metrics in parsed
    )
    counters["e_navigator_capture_filter_inotify_watches"] = sum(
        scalar(metrics, "e_navigator_capture_filter_inotify_watches")
        for metrics in parsed
    )

    for metrics in parsed:
        for name in (
            "lost_transport_events_total",
            "lost_perf_events_total",
            "ring_buffer_reservation_failures_total",
            "send_failures_total",
        ):
            entries = metrics.get(f"e_navigator_ebpf_source_{name}", [])
            relevant = [value for labels, value in entries if 'source="source.aya_exec"' in labels]
            if relevant != [0.0]:
                fail(f"{run_dir}: source.aya_exec {name} was not zero: {relevant}")

    if counters["e_navigator_capture_filter_map_apply_failures_total"] != 0:
        fail(f"{run_dir}: capture-filter map application failed")
    if counters["e_navigator_capture_filter_inotify_failures_total"] != 0:
        fail(f"{run_dir}: inotify discovery reported a failure")
    if counters["e_navigator_capture_filter_inotify_queue_overflows_total"] != 0:
        fail(f"{run_dir}: inotify queue overflowed")
    if counters["e_navigator_capture_filter_inotify_watch_limit_drops_total"] != 0:
        fail(f"{run_dir}: inotify watch bound was reached")
    if counters["e_navigator_capture_filter_bootstrap_window_observations_total"] <= 0:
        fail(f"{run_dir}: no residual-window observation was recorded")

    if mode == "event_driven":
        if counters["e_navigator_capture_filter_inotify_events_total"] <= 0:
            fail(f"{run_dir}: event-driven arm received no inotify events")
        if counters["e_navigator_capture_filter_inotify_watches"] <= 0:
            fail(f"{run_dir}: event-driven arm installed no inotify watches")
        if counters["e_navigator_capture_filter_event_reconciliations_total"] <= 0:
            fail(f"{run_dir}: event-driven arm performed no event reconciliation")
    else:
        for name in (
            "e_navigator_capture_filter_discovery_notifications_total",
            "e_navigator_capture_filter_event_reconciliations_total",
            "e_navigator_capture_filter_inotify_events_total",
            "e_navigator_capture_filter_inotify_watches",
        ):
            if counters[name] != 0:
                fail(f"{run_dir}: polling arm unexpectedly reported {name}={counters[name]}")

    return {
        "mode": mode,
        "agent": True,
        "signal_window_millis": round(window_millis, 6),
        "correlated_signals": signal_count,
        "workload": summary,
        "native_accounting": counters,
    }


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def stats(values: list[float]) -> dict[str, float | int]:
    return {
        "samples": len(values),
        "min": round(min(values), 6),
        "mean": round(statistics.fmean(values), 6),
        "median": round(statistics.median(values), 6),
        "p95": round(percentile(values, 0.95), 6),
        "max": round(max(values), 6),
        "stdev": round(statistics.stdev(values), 6) if len(values) > 1 else 0.0,
    }


def validate_run(mode: str, run_dir: Path) -> dict[str, Any]:
    if mode == "none":
        return validate_no_agent(run_dir)
    configured = "event_driven" if mode == "event" else "polling"
    return validate_agent(configured, run_dir)


def aggregate(results_root: Path) -> dict[str, Any]:
    runs: dict[str, dict[str, Any]] = {}
    by_mode: dict[str, list[float]] = {"polling": [], "event": []}
    for path in sorted(results_root.iterdir()):
        if not path.is_dir():
            continue
        match = RUN_NAME.match(path.name)
        if not match:
            continue
        mode = match.group(1)
        result = validate_run(mode, path)
        runs[path.name] = result
        if mode in by_mode:
            by_mode[mode].append(float(result["signal_window_millis"]))

    if len([name for name in runs if name.startswith("none-")]) != 1:
        fail("expected exactly one no-agent run")
    if len(by_mode["polling"]) < 5 or len(by_mode["event"]) < 5:
        fail("expected at least five polling and five event-driven runs")

    polling = stats(by_mode["polling"])
    event = stats(by_mode["event"])
    median_reduction = float(polling["median"]) - float(event["median"])
    reduction_percent = (
        median_reduction / float(polling["median"]) * 100
        if float(polling["median"]) > 0
        else 0.0
    )
    if float(event["median"]) >= float(polling["median"]):
        fail(f"event median did not improve polling: event={event}, polling={polling}")
    if float(event["p95"]) >= float(polling["p95"]):
        fail(f"event p95 did not improve polling: event={event}, polling={polling}")

    return {
        "schema": "e-navigator.bootstrap-window-analysis.v1",
        "runs": runs,
        "window_millis": {"polling": polling, "event_driven": event},
        "median_reduction_millis": round(median_reduction, 6),
        "median_reduction_percent": round(reduction_percent, 6),
        "verdict": "pass",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("mode", choices=("none", "polling", "event"))
    run_parser.add_argument("run_dir", type=Path)
    aggregate_parser = subparsers.add_parser("aggregate")
    aggregate_parser.add_argument("results_root", type=Path)
    args = parser.parse_args()

    try:
        result = (
            validate_run(args.mode, args.run_dir)
            if args.command == "run"
            else aggregate(args.results_root)
        )
    except (OSError, ValueError, json.JSONDecodeError) as err:
        raise SystemExit(str(err)) from err
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
