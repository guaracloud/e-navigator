#!/usr/bin/env python3
"""Summarize guarded homelab fexit versus tracepoint result bundles."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


RUN_NAME = re.compile(r"^(none|tracepoint|fexit)-r([1-9][0-9]*)$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
HOOK = re.compile(r'network_io_hook="(?P<hook>fexit|tracepoint)"')
LOSS_METRIC = re.compile(
    r'^e_navigator_ebpf_source_(?P<name>lost_transport_events_total|'
    r'lost_perf_events_total|ring_buffer_reservation_failures_total)'
    r'\{source="source\.aya_network"\} (?P<value>[0-9]+)$'
)
CONFIG_HOOK = re.compile(r'^network_io_hook = "(?P<hook>fexit|tracepoint)"$')


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


def read_workload(run_dir: Path) -> dict[str, Any]:
    for line in (run_dir / "workload-logs.txt").read_text(errors="replace").splitlines():
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            value = json.loads(line[marker:])
        except json.JSONDecodeError:
            continue
        if value.get("schema") == "e-navigator.kernel-hook-workload.v1":
            expected = int(value["operations"]) * int(value["payload_bytes"])
            if value.get("bytes_sent") != expected or value.get("bytes_received") != expected:
                raise ValueError(f"workload byte invariant failed in {run_dir}")
            return value
    raise ValueError(f"missing kernel-hook workload result in {run_dir}")


def read_pod_inventory(run_dir: Path) -> tuple[dict[str, str], set[str], set[str]]:
    payload = json.loads((run_dir / "pod-json.txt").read_text())
    pod_nodes = {
        item["metadata"]["name"]: item.get("spec", {}).get("nodeName", "")
        for item in payload.get("items", [])
    }
    agent_pods = {
        item["metadata"]["name"]
        for item in payload.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    }
    workload_nodes = {
        item.get("spec", {}).get("nodeName", "")
        for item in payload.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == "load"
        and item.get("spec", {}).get("nodeName", "")
    }
    return pod_nodes, agent_pods, workload_nodes


def read_pod_top(run_dir: Path) -> dict[str, Any]:
    pod_nodes, expected_agent_pods, workload_nodes = read_pod_inventory(run_dir)
    current_sample = 0
    sample_agents: dict[int, dict[str, tuple[str, float, float]]] = defaultdict(dict)
    load_cpu: list[float] = []
    load_memory: list[float] = []
    path = run_dir / "top-pods-10-samples.txt"
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("sample="):
            current_sample = int(line.split()[0].split("=", 1)[1])
            continue
        fields = line.split()
        if len(fields) != 4 or fields[0] in {"POD", "error:"}:
            continue
        pod, component, cpu, memory = fields
        cpu_m = quantity_cpu_m(cpu)
        memory_mib = quantity_memory_mib(memory)
        if component == "load":
            load_cpu.append(cpu_m)
            load_memory.append(memory_mib)
        if component == "e-navigator":
            sample_agents[current_sample][pod] = (pod_nodes.get(pod, ""), cpu_m, memory_mib)

    total_cpu: list[float] = []
    total_memory: list[float] = []
    workload_node_cpu: list[float] = []
    incomplete = 0
    for sample in sorted(sample_agents):
        entries = sample_agents[sample]
        if set(entries) != expected_agent_pods:
            incomplete += 1
            continue
        total_cpu.append(sum(entry[1] for entry in entries.values()))
        total_memory.append(sum(entry[2] for entry in entries.values()))
        workload_node_cpu.extend(
            entry[1] for entry in entries.values() if entry[0] in workload_nodes
        )
    return {
        "expected_agent_pods": len(expected_agent_pods),
        "incomplete_agent_samples_excluded": incomplete,
        "agent_total_cpu_m": summary(total_cpu),
        "agent_total_memory_mib": summary(total_memory),
        "agent_workload_node_cpu_m": summary(workload_node_cpu),
        "load_cpu_m": summary(load_cpu),
        "load_memory_mib": summary(load_memory),
    }


def read_node_top(run_dir: Path) -> dict[str, Any]:
    cpu: dict[str, list[float]] = defaultdict(list)
    memory: dict[str, list[float]] = defaultdict(list)
    path = run_dir / "top-nodes-10-samples.txt"
    for line in path.read_text(errors="replace").splitlines():
        fields = line.split()
        if len(fields) != 5 or not fields[0].startswith("homelab-"):
            continue
        node, cpu_value, _cpu_percent, memory_value, _memory_percent = fields
        cpu[node].append(quantity_cpu_m(cpu_value))
        memory[node].append(quantity_memory_mib(memory_value))
    return {
        node: {"cpu_m": summary(cpu[node]), "memory_mib": summary(memory[node])}
        for node in sorted(cpu)
    }


def read_agent_evidence(run_dir: Path, workload: dict[str, Any]) -> dict[str, Any] | None:
    logs_path = run_dir / "logs.txt"
    metrics_path = run_dir / "prometheus-http-metrics.txt"
    if not logs_path.exists() or not metrics_path.exists():
        return None

    configured_hook = None
    for line in (run_dir / "runtime-config.toml").read_text(errors="replace").splitlines():
        match = CONFIG_HOOK.match(line.strip())
        if match:
            configured_hook = match.group("hook")
            break

    hook_selections: list[str] = []
    matching_closes: list[dict[str, Any]] = []
    for raw_line in logs_path.read_text(errors="replace").splitlines():
        line = ANSI.sub("", raw_line)
        hook_match = HOOK.search(line)
        if hook_match:
            hook_selections.append(hook_match.group("hook"))
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            signal = json.loads(line[marker:])
        except json.JSONDecodeError:
            continue
        payload = signal.get("payload", {})
        process = payload.get("process", {})
        if (
            signal.get("kind") == "network_connection_close"
            and process.get("command") == "python"
            and payload.get("remote_address") == "127.0.0.1"
            and payload.get("remote_port") == workload["server_port"]
            and payload.get("fd") == workload["client_fd"]
        ):
            matching_closes.append(payload)

    losses: dict[str, int] = {}
    for line in metrics_path.read_text(errors="replace").splitlines():
        match = LOSS_METRIC.match(line)
        if match:
            losses[match.group("name")] = int(match.group("value"))

    exact_closes = [
        payload
        for payload in matching_closes
        if payload.get("bytes_sent") == workload["bytes_sent"]
        and payload.get("bytes_received") == workload["bytes_received"]
        and payload.get("kubernetes", {}).get("namespace") == "e-navigator-bench"
    ]
    return {
        "configured_hook": configured_hook,
        "hook_selections": hook_selections,
        "matching_close_count": len(matching_closes),
        "exact_close_count": len(exact_closes),
        "loss_counters": losses,
        "zero_loss": bool(losses) and all(value == 0 for value in losses.values()),
    }


def aggregate_modes(runs: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        grouped[run["mode"]].append(run)
    aggregated: dict[str, Any] = {}
    for mode, mode_runs in sorted(grouped.items()):
        workload = [run["workload"] for run in mode_runs]
        aggregated[mode] = {
            "runs": len(mode_runs),
            "throughput_operations_per_second": summary(
                [float(item["throughput_operations_per_second"]) for item in workload]
            ),
            "latency_mean_us": summary([float(item["latency_mean_us"]) for item in workload]),
            "latency_p95_upper_bound_us": summary(
                [float(item["latency_p95_upper_bound_us"]) for item in workload]
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
            "load_cpu_m_run_means": summary(
                [
                    float(run["pod_resources"]["load_cpu_m"]["mean"])
                    for run in mode_runs
                    if run["pod_resources"]["load_cpu_m"]["mean"] is not None
                ]
            ),
        }

    def delta(left: str, right: str, metric: str) -> float | None:
        left_value = aggregated[left][metric]["mean"]
        right_value = aggregated[right][metric]["mean"]
        if left_value is None or right_value in {None, 0}:
            return None
        return round((left_value - right_value) / right_value * 100, 6)

    deltas = {
        "fexit_vs_tracepoint_throughput": delta(
            "fexit", "tracepoint", "throughput_operations_per_second"
        ),
        "fexit_vs_tracepoint_mean_latency": delta("fexit", "tracepoint", "latency_mean_us"),
        "fexit_vs_tracepoint_agent_cpu": delta(
            "fexit", "tracepoint", "agent_total_cpu_m_run_means"
        ),
        "fexit_vs_none_throughput": delta(
            "fexit", "none", "throughput_operations_per_second"
        ),
        "tracepoint_vs_none_throughput": delta(
            "tracepoint", "none", "throughput_operations_per_second"
        ),
    }
    aggregated["deltas_percent"] = deltas

    agent_runs = [run for run in runs if run["mode"] != "none"]
    correctness = all(
        run["agent_evidence"] is not None
        and run["agent_evidence"]["exact_close_count"] == 1
        and run["agent_evidence"]["zero_loss"]
        and run["agent_evidence"]["configured_hook"] == run["mode"]
        and (
            not run["agent_evidence"]["hook_selections"]
            or set(run["agent_evidence"]["hook_selections"]) == {run["mode"]}
        )
        for run in agent_runs
    )
    throughput_delta = deltas["fexit_vs_tracepoint_throughput"]
    latency_delta = deltas["fexit_vs_tracepoint_mean_latency"]
    measured_win = (
        throughput_delta is not None
        and throughput_delta >= 5.0
        and latency_delta is not None
        and latency_delta <= 2.0
    )
    aggregated["adoption_decision"] = {
        "correctness_gate_passed": correctness,
        "predeclared_throughput_win_percent": 5.0,
        "predeclared_max_mean_latency_regression_percent": 2.0,
        "measured_win_gate_passed": measured_win,
        "adopt_fexit": correctness and measured_win,
    }
    return aggregated


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_root", type=Path)
    args = parser.parse_args()
    runs = []
    for run_dir in sorted(args.results_root.iterdir()):
        match = RUN_NAME.match(run_dir.name)
        if not match or not run_dir.is_dir():
            continue
        workload = read_workload(run_dir)
        runs.append(
            {
                "mode": match.group(1),
                "repetition": int(match.group(2)),
                "workload": workload,
                "pod_resources": read_pod_top(run_dir),
                "node_resources": read_node_top(run_dir),
                "agent_evidence": read_agent_evidence(run_dir, workload),
            }
        )
    if not runs:
        raise SystemExit(f"no kernel-hook runs found under {args.results_root}")
    payload = {
        "schema": "e-navigator.kernel-hook-analysis.v1",
        "results_root": str(args.results_root),
        "runs": runs,
        "aggregate": aggregate_modes(runs),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
