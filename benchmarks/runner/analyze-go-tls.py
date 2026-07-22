#!/usr/bin/env python3
"""Summarize guarded homelab Go crypto/tls proof result bundles."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


RUN_NAME = re.compile(r"^(none|tls)-r([1-9][0-9]*)$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
METRIC = re.compile(
    r"^(?P<name>e_navigator_ebpf_source_[a-z0-9_]+)"
    r'(?:\{source="source\.aya_tls"\})? (?P<value>[0-9]+)$'
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
    path = run_dir / "workload-logs.txt"
    for line in path.read_text(errors="replace").splitlines():
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            value = json.loads(line[marker:])
        except json.JSONDecodeError:
            continue
        if value.get("schema") == "e-navigator.go-tls-client.v1":
            if value.get("failed") != 0 or value.get("succeeded") != value.get("requests"):
                raise ValueError(f"workload invariant failed in {run_dir}")
            return value
    raise ValueError(f"missing Go TLS workload result in {run_dir}")


def read_pod_top(run_dir: Path) -> dict[str, Any]:
    current_sample = 0
    sample_agents: dict[int, dict[str, tuple[float, float]]] = defaultdict(dict)
    load_cpu: list[float] = []
    load_memory: list[float] = []
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
        if component == "load":
            load_cpu.append(cpu_m)
            load_memory.append(memory_mib)
        elif component == "e-navigator":
            sample_agents[current_sample][pod] = (cpu_m, memory_mib)
    agent_cpu = [sum(value[0] for value in pods.values()) for pods in sample_agents.values()]
    agent_memory = [sum(value[1] for value in pods.values()) for pods in sample_agents.values()]
    return {
        "agent_samples": len(agent_cpu),
        "agent_total_cpu_m": summary(agent_cpu),
        "agent_total_memory_mib": summary(agent_memory),
        "load_cpu_m": summary(load_cpu),
        "load_memory_mib": summary(load_memory),
    }


def read_agent_evidence(run_dir: Path) -> dict[str, Any] | None:
    logs_path = run_dir / "logs.txt"
    metrics_path = run_dir / "prometheus-http-metrics.txt"
    if not logs_path.exists() or not metrics_path.exists():
        return None
    logs = logs_path.read_text(errors="replace")
    status_200 = 0
    observations = 0
    for raw_line in logs.splitlines():
        marker = raw_line.find("{")
        if marker < 0:
            continue
        try:
            signal = json.loads(raw_line[marker:])
        except json.JSONDecodeError:
            continue
        if signal.get("source") != "source.aya_tls" or signal.get("kind") != "protocol_request_observation":
            continue
        observations += 1
        payload = signal.get("payload", {})
        attributes = payload.get("attributes", [])
        kubernetes = payload.get("kubernetes") or {}
        if (
            payload.get("process", {}).get("command") == "go-https-proof"
            and kubernetes.get("namespace") == "e-navigator-bench"
            and any(item.get("key") == "url.path" and item.get("value") == "/proof" for item in attributes)
            and any(item.get("key") == "http.response.status_code" and item.get("value") == "200" for item in attributes)
        ):
            status_200 += 1

    metrics: dict[str, int] = {}
    for line in metrics_path.read_text(errors="replace").splitlines():
        match = METRIC.match(line)
        if match:
            metrics[match.group("name")] = int(match.group("value"))
    loss_names = (
        "e_navigator_ebpf_source_lost_transport_events_total",
        "e_navigator_ebpf_source_ring_buffer_reservation_failures_total",
    )
    clean_logs = ANSI.sub("", logs)
    clean_lines = clean_logs.splitlines()
    ready_count = sum(
        "Go crypto/tls executable is capture-ready" in line
        and 'executable="go-https-proof"' in line
        and 'go_version="go1.26.4"' in line
        for line in clean_lines
    )
    stripped_count = sum(
        'executable="go-https-proof-stripped"' in line
        and "stripped binaries fail closed" in line
        for line in clean_lines
    )
    return {
        "capture_ready_go_1_26_4_log_count": ready_count,
        "stripped_fail_closed_log_count": stripped_count,
        "protocol_observations": observations,
        "http_status_200_observations": status_200,
        "metrics": metrics,
        "zero_transport_loss": all(metrics.get(name) == 0 for name in loss_names),
    }


def aggregate(runs: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        grouped[run["mode"]].append(run)
    result: dict[str, Any] = {}
    for mode, mode_runs in sorted(grouped.items()):
        result[mode] = {
            "runs": len(mode_runs),
            "throughput_requests_per_second": summary(
                [float(run["workload"]["throughput_requests_per_second"]) for run in mode_runs]
            ),
            "elapsed_seconds": summary(
                [float(run["workload"]["elapsed_seconds"]) for run in mode_runs]
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

    none_throughput = result["none"]["throughput_requests_per_second"]["mean"]
    tls_throughput = result["tls"]["throughput_requests_per_second"]["mean"]
    throughput_delta = None
    if none_throughput not in {None, 0} and tls_throughput is not None:
        throughput_delta = round((tls_throughput - none_throughput) / none_throughput * 100, 6)
    agent_runs = [run for run in runs if run["mode"] == "tls"]
    no_agent_runs = [run for run in runs if run["mode"] == "none"]
    no_agent_inventory_clean = all(
        run["pod_resources"]["agent_samples"] == 0 for run in no_agent_runs
    )
    result["tls_vs_no_agent_throughput_delta_percent"] = throughput_delta
    result["no_agent_inventory_clean"] = no_agent_inventory_clean
    result["correctness_gate_passed"] = no_agent_inventory_clean and all(
        run["agent_evidence"] is not None
        and run["agent_evidence"]["capture_ready_go_1_26_4_log_count"] > 0
        and run["agent_evidence"]["stripped_fail_closed_log_count"] > 0
        and run["agent_evidence"]["http_status_200_observations"] > 0
        and run["agent_evidence"]["zero_transport_loss"]
        and run["agent_evidence"]["metrics"].get(
            "e_navigator_ebpf_source_go_tls_state_update_failures_total"
        )
        == 0
        for run in agent_runs
    )
    return result


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
                "agent_evidence": read_agent_evidence(run_dir),
            }
        )
    if not runs:
        raise SystemExit(f"no Go TLS runs found under {args.results_root}")
    payload = {
        "schema": "e-navigator.go-tls-analysis.v1",
        "results_root": str(args.results_root),
        "runs": runs,
        "aggregate": aggregate(runs),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
