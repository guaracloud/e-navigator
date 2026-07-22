#!/usr/bin/env python3
"""Validate and summarize guarded homelab profiling-breadth proof bundles."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


RUN_NAME = re.compile(r"^(none|profiling)-r([1-9][0-9]*)$")
METRIC = re.compile(
    r"^(?P<name>e_navigator_ebpf_source_[a-z0-9_]+)"
    r'(?:\{(?P<labels>[^}]*)\})? (?P<value>[0-9]+)$'
)
EXPECTED_NAMESPACE = "e-navigator-bench"
EXPECTED_SOURCE = "source.aya_cpu_profile"


def quantity_cpu_m(value: str) -> float:
    if value.endswith("n"):
        return float(value[:-1]) / 1_000_000
    if value.endswith("u"):
        return float(value[:-1]) / 1_000
    if value.endswith("m"):
        return float(value[:-1])
    return float(value) * 1_000


def quantity_memory_mib(value: str) -> float:
    scales = {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024}
    for suffix, scale in scales.items():
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * scale
    return float(value) / (1024 * 1024)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def summary(values: list[float]) -> dict[str, float | int | None]:
    if not values:
        return {"samples": 0, "mean": None, "stdev": None, "p95": None, "max": None}
    return {
        "samples": len(values),
        "mean": round(statistics.fmean(values), 6),
        "stdev": round(statistics.stdev(values), 6) if len(values) > 1 else 0.0,
        "p95": round(percentile(values, 0.95) or 0.0, 6),
        "max": round(max(values), 6),
    }


def json_objects(path: Path):
    for line in path.read_text(errors="replace").splitlines():
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            yield json.loads(line[marker:])
        except json.JSONDecodeError:
            continue


def read_workload(run_dir: Path) -> dict[str, Any]:
    for value in json_objects(run_dir / "workload-logs.txt"):
        if value.get("schema") != "e-navigator.profiling-breadth-workload.v1":
            continue
        if not str(value.get("python_version", "")).startswith("3.11."):
            raise ValueError(f"workload did not run CPython 3.11 in {run_dir}: {value}")
        for counter in ("busy_batches", "lock_acquisitions", "sleeps"):
            if int(value.get(counter, 0)) <= 0:
                raise ValueError(f"workload counter {counter} was not positive in {run_dir}")
        elapsed = float(value.get("elapsed_seconds", 0))
        if elapsed <= 0:
            raise ValueError(f"workload elapsed time was not positive in {run_dir}")
        value["busy_batches_per_second"] = round(float(value["busy_batches"]) / elapsed, 6)
        return value
    raise ValueError(f"missing profiling workload result in {run_dir}")


def read_pod_inventory(run_dir: Path) -> set[str]:
    payload = json.loads((run_dir / "pod-json.txt").read_text())
    return {
        item.get("metadata", {}).get("name", "")
        for item in payload.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    }


def read_pod_top(run_dir: Path) -> dict[str, Any]:
    current_sample = 0
    sample_agents: dict[int, dict[str, tuple[float, float]]] = defaultdict(dict)
    workload_cpu: list[float] = []
    workload_memory: list[float] = []
    path = run_dir / "top-pods-10-samples.txt"
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("sample="):
            current_sample = int(line.split()[0].split("=", 1)[1])
            continue
        fields = line.split()
        if len(fields) != 4 or fields[0] in {"POD", "error:"}:
            continue
        pod, container, cpu, memory = fields
        cpu_m = quantity_cpu_m(cpu)
        memory_mib = quantity_memory_mib(memory)
        if container == "e-navigator":
            sample_agents[current_sample][pod] = (cpu_m, memory_mib)
        elif container == "python311-profile-load":
            workload_cpu.append(cpu_m)
            workload_memory.append(memory_mib)
    agent_cpu = [sum(value[0] for value in pods.values()) for pods in sample_agents.values()]
    agent_memory = [sum(value[1] for value in pods.values()) for pods in sample_agents.values()]
    return {
        "agent_samples": len(agent_cpu),
        "agent_total_cpu_m": summary(agent_cpu),
        "agent_total_memory_mib": summary(agent_memory),
        "workload_cpu_m": summary(workload_cpu),
        "workload_memory_mib": summary(workload_memory),
    }


def attribute_map(payload: dict[str, Any]) -> dict[str, str]:
    return {
        str(item.get("key", "")): str(item.get("value", ""))
        for item in payload.get("attributes", [])
        if isinstance(item, dict)
    }


def read_metrics(run_dir: Path) -> tuple[dict[str, int], list[str]]:
    paths = sorted(run_dir.glob("prometheus-http-metrics-e-navigator-*.txt"))
    if not paths:
        fallback = run_dir / "prometheus-http-metrics.txt"
        paths = [fallback] if fallback.exists() else []
    totals: dict[str, int] = defaultdict(int)
    used = []
    for path in paths:
        used.append(path.name)
        for line in path.read_text(errors="replace").splitlines():
            match = METRIC.match(line)
            if not match:
                continue
            labels = match.group("labels") or ""
            if 'source="source.aya_cpu_profile"' not in labels:
                continue
            totals[match.group("name")] += int(match.group("value"))
    return dict(totals), used


def read_profile_evidence(run_dir: Path) -> dict[str, Any]:
    counts = {"on_cpu": 0, "off_cpu": 0, "futex_wait": 0}
    weighted_nanos = {"off_cpu": 0, "futex_wait": 0}
    python_named_samples = 0
    python_frame_names: set[str] = set()
    namespaces: set[str] = set()
    commands: set[str] = set()
    malformed_weighted = 0
    for signal in json_objects(run_dir / "logs.txt"):
        if signal.get("source") != EXPECTED_SOURCE or signal.get("kind") != "profile_sample_observation":
            continue
        payload = signal.get("payload", {})
        kubernetes = payload.get("kubernetes") or {}
        namespace = kubernetes.get("namespace")
        if namespace:
            namespaces.add(str(namespace))
        process = payload.get("process") or {}
        if process.get("command"):
            commands.add(str(process["command"]))
        attributes = attribute_map(payload)
        mode = attributes.get("profiling.sample.mode")
        if mode not in counts:
            continue
        counts[mode] += 1
        if mode in weighted_nanos:
            try:
                weight = int(attributes.get("profiling.sample.weight_nanos", "0"))
            except ValueError:
                weight = 0
            if weight <= 0 or payload.get("sampling_period_nanos") is not None:
                malformed_weighted += 1
            else:
                weighted_nanos[mode] += weight
        if mode == "on_cpu" and int(attributes.get("profiling.stack.py_frames", "0")) > 0:
            symbols = {
                str(frame.get("symbol"))
                for frame in payload.get("stack_frames", [])
                if isinstance(frame, dict)
                and isinstance(frame.get("symbol"), str)
                and str(frame.get("symbol")).startswith("profile_")
            }
            if symbols:
                python_named_samples += 1
                python_frame_names.update(symbols)

    metrics, metric_files = read_metrics(run_dir)
    pprof_files = sorted(run_dir.glob("prometheus-http-pprof-profile-e-navigator-*.pb"))
    pprof_nonempty = [path.name for path in pprof_files if path.stat().st_size > 0]
    required_zero = (
        "e_navigator_ebpf_source_profile_state_replacements_total",
        "e_navigator_ebpf_source_profile_pending_misses_total",
        "e_navigator_ebpf_source_lost_transport_events_total",
        "e_navigator_ebpf_source_lost_perf_events_total",
        "e_navigator_ebpf_source_ring_buffer_reservation_failures_total",
    )
    profile_events = metrics.get("e_navigator_ebpf_source_profile_events_total", 0)
    capture_failures = metrics.get(
        "e_navigator_ebpf_source_profile_capture_failures_total", 0
    )
    capture_failure_rate = (
        round(capture_failures / profile_events * 100, 9) if profile_events else None
    )
    return {
        "sample_counts": counts,
        "weighted_nanos": weighted_nanos,
        "python_named_samples": python_named_samples,
        "python_frame_names": sorted(python_frame_names),
        "observed_namespaces": sorted(namespaces),
        "observed_commands": sorted(commands),
        "malformed_weighted_samples": malformed_weighted,
        "metrics": metrics,
        "metric_files": metric_files,
        "pprof_nonempty_files": pprof_nonempty,
        "capture_failure_rate_percent": capture_failure_rate,
        "zero_transport_state_and_unscoped_miss_counters": all(
            metrics.get(name) == 0 for name in required_zero
        ),
    }


def validate(mode: str, run: dict[str, Any], run_dir: Path) -> None:
    agent_pods = run["agent_pods"]
    if mode == "none":
        if agent_pods:
            raise ValueError(f"no-agent arm contained agent pods in {run_dir}: {agent_pods}")
        return
    if not agent_pods:
        raise ValueError(f"profiling arm had no agent pods in {run_dir}")
    evidence = run["profile_evidence"]
    assert evidence is not None
    counts = evidence["sample_counts"]
    for mode_name in ("on_cpu", "off_cpu", "futex_wait"):
        if counts[mode_name] <= 0:
            raise ValueError(f"missing {mode_name} samples in {run_dir}")
    if evidence["python_named_samples"] <= 0:
        raise ValueError(f"missing named CPython frames in {run_dir}")
    if evidence["malformed_weighted_samples"] != 0:
        raise ValueError(f"malformed event weights in {run_dir}")
    if evidence["observed_namespaces"] != [EXPECTED_NAMESPACE]:
        raise ValueError(
            f"profiles escaped the namespace filter in {run_dir}: "
            f"{evidence['observed_namespaces']}"
        )
    metrics = evidence["metrics"]
    for name in (
        "e_navigator_ebpf_source_profile_events_total",
        "e_navigator_ebpf_source_profile_output_attempts_total",
    ):
        if metrics.get(name, 0) <= 0:
            raise ValueError(f"missing positive {name} in {run_dir}")
    if not evidence["zero_transport_state_and_unscoped_miss_counters"]:
        raise ValueError(f"profiling state or transport-loss counter was non-zero in {run_dir}")
    failure_rate = evidence["capture_failure_rate_percent"]
    if failure_rate is None or failure_rate > 0.1:
        raise ValueError(
            f"profile stack-capture failure rate exceeded 0.1% in {run_dir}: {failure_rate}"
        )
    if not evidence["pprof_nonempty_files"]:
        raise ValueError(f"missing non-empty pprof runtime export in {run_dir}")


def read_run(mode: str, repetition: int, run_dir: Path) -> dict[str, Any]:
    agent_pods = sorted(read_pod_inventory(run_dir))
    run = {
        "mode": mode,
        "repetition": repetition,
        "workload": read_workload(run_dir),
        "agent_pods": agent_pods,
        "pod_resources": read_pod_top(run_dir),
        "profile_evidence": read_profile_evidence(run_dir) if mode == "profiling" else None,
    }
    validate(mode, run, run_dir)
    return run


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        grouped[run["mode"]].append(run)
    result: dict[str, Any] = {}
    for mode, mode_runs in sorted(grouped.items()):
        result[mode] = {
            "runs": len(mode_runs),
            "busy_batches_per_second": summary(
                [float(run["workload"]["busy_batches_per_second"]) for run in mode_runs]
            ),
            "agent_total_cpu_m_run_means": summary(
                [
                    float(run["pod_resources"]["agent_total_cpu_m"]["mean"])
                    for run in mode_runs
                    if run["pod_resources"]["agent_total_cpu_m"]["mean"] is not None
                ]
            ),
            "agent_total_memory_mib_run_means": summary(
                [
                    float(run["pod_resources"]["agent_total_memory_mib"]["mean"])
                    for run in mode_runs
                    if run["pod_resources"]["agent_total_memory_mib"]["mean"] is not None
                ]
            ),
        }
    none_rate = result.get("none", {}).get("busy_batches_per_second", {}).get("mean")
    profile_rate = result.get("profiling", {}).get("busy_batches_per_second", {}).get("mean")
    delta = None
    if none_rate not in {None, 0} and profile_rate is not None:
        delta = round((profile_rate - none_rate) / none_rate * 100, 6)
    result["profiling_vs_no_agent_busy_rate_delta_percent"] = delta
    result["correctness_gate_passed"] = all(
        run["mode"] == "none"
        or (
            run["profile_evidence"]["zero_transport_state_and_unscoped_miss_counters"]
            and run["profile_evidence"]["capture_failure_rate_percent"] <= 0.1
        )
        for run in runs
    ) and all(not run["agent_pods"] for run in runs if run["mode"] == "none")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_root", nargs="?", type=Path)
    parser.add_argument("--validate-run", nargs=2, metavar=("MODE", "RUN_DIR"))
    args = parser.parse_args()
    if args.validate_run:
        mode, raw_dir = args.validate_run
        if mode not in {"none", "profiling"}:
            raise SystemExit(f"invalid mode: {mode}")
        run = read_run(mode, 1, Path(raw_dir))
        print(json.dumps(run, indent=2, sort_keys=True))
        return
    if args.results_root is None:
        parser.error("results_root is required unless --validate-run is used")
    runs = []
    for run_dir in sorted(args.results_root.iterdir()):
        match = RUN_NAME.match(run_dir.name)
        if match and run_dir.is_dir():
            runs.append(read_run(match.group(1), int(match.group(2)), run_dir))
    if not runs:
        raise SystemExit(f"no profiling-breadth runs found under {args.results_root}")
    payload = {
        "schema": "e-navigator.profiling-breadth-analysis.v1",
        "results_root": str(args.results_root),
        "runs": runs,
        "aggregate": aggregate(runs),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
