#!/usr/bin/env python3
"""Summarize guarded homelab event-transport A/B result bundles."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


RUN_NAME = re.compile(r"^(none|perf_buffer|ring_buffer)-r([1-9][0-9]*)$")
METRIC = re.compile(
    r'^e_navigator_ebpf_source_(?P<name>lost_transport_events_total|'
    r'lost_perf_events_total|ring_buffer_reservation_failures_total)'
    r'\{source="(?P<source>[^"]+)"\} (?P<value>[0-9]+)$'
)
TRANSPORT = re.compile(
    r'^e_navigator_ebpf_source_event_transport'
    r'\{source="(?P<source>[^"]+)",transport="(?P<transport>[^"]+)"\} 1$'
)


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
        if value.get("schema") == "e-navigator.event-transport-workload.v1":
            return value
    raise ValueError(f"missing workload result in {run_dir}")


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
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component")
        in {"load", "server"}
        and item.get("spec", {}).get("nodeName", "")
    }
    return pod_nodes, agent_pods, workload_nodes


def read_pod_top(run_dir: Path) -> dict[str, Any]:
    pod_nodes, expected_agent_pods, workload_nodes = read_pod_inventory(run_dir)
    current_sample = 0
    sample_agents: dict[int, dict[str, tuple[str, float, float]]] = defaultdict(dict)
    components: dict[str, list[float]] = defaultdict(list)
    component_memory: dict[str, list[float]] = defaultdict(list)

    for line in (run_dir / "top-pods-10-samples.txt").read_text(errors="replace").splitlines():
        if line.startswith("sample="):
            current_sample = int(line.split()[0].split("=", 1)[1])
            continue
        fields = line.split()
        if len(fields) != 4 or fields[0] in {"POD", "error:"}:
            continue
        pod, component, cpu, memory = fields
        cpu_m = quantity_cpu_m(cpu)
        memory_mib = quantity_memory_mib(memory)
        components[component].append(cpu_m)
        component_memory[component].append(memory_mib)
        if component == "e-navigator":
            sample_agents[current_sample][pod] = (pod_nodes.get(pod, ""), cpu_m, memory_mib)

    total_agent_cpu = []
    total_agent_memory = []
    workload_node_agent_cpu = []
    workload_node_agent_memory = []
    incomplete_agent_samples = 0
    for sample in sorted(sample_agents):
        entries = sample_agents[sample]
        if set(entries) != expected_agent_pods:
            incomplete_agent_samples += 1
            continue
        total_agent_cpu.append(sum(entry[1] for entry in entries.values()))
        total_agent_memory.append(sum(entry[2] for entry in entries.values()))
        for node, cpu_m, memory_mib in entries.values():
            if node in workload_nodes:
                workload_node_agent_cpu.append(cpu_m)
                workload_node_agent_memory.append(memory_mib)

    return {
        "agent_total_cpu_m": summary(total_agent_cpu),
        "agent_total_memory_mib": summary(total_agent_memory),
        "agent_workload_node_cpu_m": summary(workload_node_agent_cpu),
        "agent_workload_node_memory_mib": summary(workload_node_agent_memory),
        "expected_agent_pods": len(expected_agent_pods),
        "incomplete_agent_samples_excluded": incomplete_agent_samples,
        "load_cpu_m": summary(components["load"]),
        "load_memory_mib": summary(component_memory["load"]),
        "server_cpu_m": summary(components["server"]),
        "server_memory_mib": summary(component_memory["server"]),
    }


def read_node_top(run_dir: Path) -> dict[str, Any]:
    cpu: dict[str, list[float]] = defaultdict(list)
    memory: dict[str, list[float]] = defaultdict(list)
    for line in (run_dir / "top-nodes-10-samples.txt").read_text(errors="replace").splitlines():
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


def read_transport_metrics(run_dir: Path) -> dict[str, Any] | None:
    metrics_path = run_dir / "prometheus-http-metrics.txt"
    if not metrics_path.exists():
        return None
    counters: dict[str, dict[str, int]] = defaultdict(dict)
    transports: dict[str, str] = {}
    for line in metrics_path.read_text(errors="replace").splitlines():
        metric_match = METRIC.match(line)
        if metric_match:
            counters[metric_match.group("source")][metric_match.group("name")] = int(
                metric_match.group("value")
            )
        transport_match = TRANSPORT.match(line)
        if transport_match:
            transports[transport_match.group("source")] = transport_match.group("transport")
    return {
        "active": dict(sorted(transports.items())),
        "counters": {source: dict(sorted(values.items())) for source, values in sorted(counters.items())},
    }


def aggregate_modes(runs: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        grouped[run["mode"]].append(run)

    aggregated: dict[str, Any] = {}
    for mode, mode_runs in sorted(grouped.items()):
        workload = [run["workload"] for run in mode_runs]
        nodes = sorted(
            {
                node
                for run in mode_runs
                for node in run["node_resources"]
            }
        )
        aggregated[mode] = {
            "runs": len(mode_runs),
            "throughput_requests_per_second": summary(
                [float(item["throughput_requests_per_second"]) for item in workload]
            ),
            "latency_mean_ms": summary([float(item["latency_mean_ms"]) for item in workload]),
            "latency_p50_upper_bound_ms": summary(
                [float(item["latency_p50_upper_bound_ms"]) for item in workload]
            ),
            "latency_p95_upper_bound_ms": summary(
                [float(item["latency_p95_upper_bound_ms"]) for item in workload]
            ),
            "latency_p99_upper_bound_ms": summary(
                [float(item["latency_p99_upper_bound_ms"]) for item in workload]
            ),
            "latency_max_ms": summary([float(item["latency_max_ms"]) for item in workload]),
            "request_failures": summary([float(item["failures"]) for item in workload]),
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
            "node_cpu_m_run_means": {
                node: summary(
                    [
                        float(run["node_resources"][node]["cpu_m"]["mean"])
                        for run in mode_runs
                        if node in run["node_resources"]
                        and run["node_resources"][node]["cpu_m"]["mean"] is not None
                    ]
                )
                for node in nodes
            },
            "node_memory_mib_run_means": {
                node: summary(
                    [
                        float(run["node_resources"][node]["memory_mib"]["mean"])
                        for run in mode_runs
                        if node in run["node_resources"]
                        and run["node_resources"][node]["memory_mib"]["mean"] is not None
                    ]
                )
                for node in nodes
            },
        }

    def delta(left: str, right: str, metric: str) -> float | None:
        left_value = aggregated[left][metric]["mean"]
        right_value = aggregated[right][metric]["mean"]
        if left_value is None or right_value in {None, 0}:
            return None
        return round((left_value - right_value) / right_value * 100, 6)

    aggregated["deltas_percent"] = {
        "ring_vs_perf_throughput": delta(
            "ring_buffer", "perf_buffer", "throughput_requests_per_second"
        ),
        "ring_vs_perf_mean_latency": delta("ring_buffer", "perf_buffer", "latency_mean_ms"),
        "ring_vs_perf_agent_cpu": delta(
            "ring_buffer", "perf_buffer", "agent_total_cpu_m_run_means"
        ),
        "ring_vs_perf_agent_memory": delta(
            "ring_buffer", "perf_buffer", "agent_total_memory_mib_run_means"
        ),
        "ring_vs_none_throughput": delta(
            "ring_buffer", "none", "throughput_requests_per_second"
        ),
        "perf_vs_none_throughput": delta(
            "perf_buffer", "none", "throughput_requests_per_second"
        ),
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
        runs.append(
            {
                "mode": match.group(1),
                "repetition": int(match.group(2)),
                "workload": read_workload(run_dir),
                "pod_resources": read_pod_top(run_dir),
                "node_resources": read_node_top(run_dir),
                "transport_metrics": read_transport_metrics(run_dir),
            }
        )

    if not runs:
        raise SystemExit(f"no event-transport runs found under {args.results_root}")
    payload = {
        "schema": "e-navigator.event-transport-analysis.v1",
        "results_root": str(args.results_root),
        "runs": runs,
        "aggregate": aggregate_modes(runs),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
