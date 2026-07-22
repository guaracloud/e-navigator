#!/usr/bin/env python3
"""Validate and summarize guarded protocol-surface proof bundles."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator


RUN_NAME = re.compile(r"^(none|protocol)-r([1-9][0-9]*)$")
METRIC = re.compile(
    r"^(?P<name>e_navigator_ebpf_source_[a-z0-9_]+)"
    r'(?:\{(?P<labels>[^}]*)\})? (?P<value>[0-9]+)$'
)
EXPECTED_NAMESPACE = "e-navigator-bench"
EXPECTED_SOURCE = "source.aya_protocol"
WEBSOCKET_UPGRADES_METRIC = (
    "e_navigator_ebpf_source_protocol_websocket_upgrades_total"
)
WEBSOCKET_FRAMES_METRIC = "e_navigator_ebpf_source_protocol_websocket_frames_total"
WEBSOCKET_REJECTIONS_METRIC = (
    "e_navigator_ebpf_source_protocol_websocket_transition_rejections_total"
)
GRPC_WEB_REQUESTS_METRIC = (
    "e_navigator_ebpf_source_protocol_grpc_web_requests_total"
)


def json_objects(path: Path) -> Iterator[dict[str, Any]]:
    for line in path.read_text(errors="replace").splitlines():
        marker = line.find("{")
        if marker < 0:
            continue
        try:
            value = json.loads(line[marker:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            yield value


def read_workload(run_dir: Path) -> dict[str, Any]:
    for value in json_objects(run_dir / "workload-logs.txt"):
        if value.get("schema") != "e-navigator.protocol-surface-workload.v1":
            continue
        for counter in (
            "websocket_successes",
            "grpc_web_successes",
            "http3_successes",
        ):
            if int(value.get(counter, 0)) <= 0:
                raise ValueError(f"workload counter {counter} was not positive in {run_dir}")
        if value.get("http3_alpn") not in {"h3", "h3-29"}:
            raise ValueError(f"workload did not negotiate HTTP/3 in {run_dir}: {value}")
        if int(value.get("failures", -1)) != 0:
            raise ValueError(f"workload failed in {run_dir}: {value}")
        return value
    raise ValueError(f"missing protocol-surface workload result in {run_dir}")


def read_pod_inventory(run_dir: Path) -> set[str]:
    payload = json.loads((run_dir / "pod-json.txt").read_text())
    return {
        item.get("metadata", {}).get("name", "")
        for item in payload.get("items", [])
        if item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        == "e-navigator"
    }


def quantity_cpu_m(value: str) -> float:
    if value.endswith("n"):
        return float(value[:-1]) / 1_000_000
    if value.endswith("u"):
        return float(value[:-1]) / 1_000
    if value.endswith("m"):
        return float(value[:-1])
    return float(value) * 1_000


def quantity_memory_mib(value: str) -> float:
    for suffix, scale in {"Ki": 1 / 1024, "Mi": 1, "Gi": 1024}.items():
        if value.endswith(suffix):
            return float(value[: -len(suffix)]) * scale
    return float(value) / (1024 * 1024)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


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


def read_pod_top(run_dir: Path) -> dict[str, Any]:
    current_sample = 0
    sample_agents: dict[int, dict[str, tuple[float, float]]] = defaultdict(dict)
    workload_cpu: list[float] = []
    workload_memory: list[float] = []
    for line in (run_dir / "top-pods-10-samples.txt").read_text(errors="replace").splitlines():
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
        elif container == "protocol-surface":
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
    if not paths and (run_dir / "prometheus-http-metrics.txt").exists():
        paths = [run_dir / "prometheus-http-metrics.txt"]
    totals: dict[str, int] = defaultdict(int)
    for path in paths:
        for line in path.read_text(errors="replace").splitlines():
            match = METRIC.match(line)
            if not match:
                continue
            labels = match.group("labels") or ""
            if labels and f'source="{EXPECTED_SOURCE}"' not in labels:
                continue
            totals[match.group("name")] += int(match.group("value"))
    return dict(totals), [path.name for path in paths]


def read_protocol_evidence(run_dir: Path) -> dict[str, Any]:
    websocket = 0
    websocket_handshakes = 0
    websocket_frames = 0
    grpc_web = 0
    grpc_status_zero = 0
    http3_semantic = 0
    namespaces: set[str] = set()
    methods: set[str] = set()
    logs_text = (run_dir / "logs.txt").read_text(errors="replace")
    if "client-secret-blue" in logs_text or "server-secret-red" in logs_text:
        raise ValueError(f"payload secret appeared in agent output in {run_dir}")
    for signal in json_objects(run_dir / "logs.txt"):
        if signal.get("source") != EXPECTED_SOURCE or signal.get("kind") != "protocol_request_observation":
            continue
        payload = signal.get("payload", {})
        namespace = (payload.get("kubernetes") or {}).get("namespace")
        if namespace:
            namespaces.add(str(namespace))
        protocol = str(payload.get("protocol", ""))
        method = str(payload.get("method", ""))
        if method:
            methods.add(method)
        attributes = attribute_map(payload)
        if protocol == "websocket":
            websocket += 1
            if method == "handshake" and payload.get("status_code") == 101:
                websocket_handshakes += 1
            elif "websocket.frame.opcode" in attributes:
                websocket_frames += 1
        if (
            protocol == "grpc"
            and attributes.get("rpc.grpc.transport") == "grpc_web"
        ):
            grpc_web += 1
            if payload.get("status_code") == 0:
                grpc_status_zero += 1
        if protocol in {"http3", "quic"} or attributes.get("network.protocol.name") in {
            "http3",
            "quic",
        }:
            http3_semantic += 1
    metrics, metric_files = read_metrics(run_dir)
    zero_loss_names = (
        "e_navigator_ebpf_source_lost_transport_events_total",
        "e_navigator_ebpf_source_lost_perf_events_total",
        "e_navigator_ebpf_source_ring_buffer_reservation_failures_total",
    )
    return {
        "websocket_observations": websocket,
        "websocket_handshakes": websocket_handshakes,
        "websocket_frames": websocket_frames,
        "grpc_web_observations": grpc_web,
        "grpc_status_zero_observations": grpc_status_zero,
        "http3_semantic_observations": http3_semantic,
        "observed_namespaces": sorted(namespaces),
        "observed_methods": sorted(methods),
        "metrics": metrics,
        "metric_files": metric_files,
        "native_websocket_upgrades": metrics.get(WEBSOCKET_UPGRADES_METRIC, 0),
        "native_websocket_frames": metrics.get(WEBSOCKET_FRAMES_METRIC, 0),
        "native_websocket_transition_rejections": metrics.get(
            WEBSOCKET_REJECTIONS_METRIC, 0
        ),
        "native_grpc_web_requests": metrics.get(GRPC_WEB_REQUESTS_METRIC, 0),
        "zero_transport_loss": all(metrics.get(name) == 0 for name in zero_loss_names),
    }


def validate(mode: str, run: dict[str, Any], run_dir: Path) -> None:
    if mode == "none":
        if run["agent_pods"]:
            raise ValueError(f"no-agent arm contained agent pods in {run_dir}")
        return
    if not run["agent_pods"]:
        raise ValueError(f"protocol arm had no agent pods in {run_dir}")
    evidence = run["protocol_evidence"]
    if evidence is None:
        raise ValueError(f"protocol arm had no evidence in {run_dir}")
    for name in (
        "websocket_observations",
        "websocket_handshakes",
        "websocket_frames",
        "grpc_web_observations",
        "grpc_status_zero_observations",
    ):
        if evidence[name] <= 0:
            raise ValueError(f"missing positive {name} in {run_dir}")
    for name in (
        "native_websocket_upgrades",
        "native_websocket_frames",
        "native_grpc_web_requests",
    ):
        if evidence[name] <= 0:
            raise ValueError(f"missing positive {name} in {run_dir}")
    if evidence["native_websocket_transition_rejections"] != 0:
        raise ValueError(f"WebSocket transition rejection was non-zero in {run_dir}")
    if evidence["http3_semantic_observations"] != 0:
        raise ValueError(f"unexpected HTTP/3 semantic claim in {run_dir}")
    if evidence["observed_namespaces"] != [EXPECTED_NAMESPACE]:
        raise ValueError(
            f"protocol observations escaped namespace filter in {run_dir}: "
            f"{evidence['observed_namespaces']}"
        )
    if not evidence["zero_transport_loss"]:
        raise ValueError(f"protocol transport loss was non-zero in {run_dir}")


def read_run(mode: str, repetition: int, run_dir: Path) -> dict[str, Any]:
    run = {
        "mode": mode,
        "repetition": repetition,
        "workload": read_workload(run_dir),
        "agent_pods": sorted(read_pod_inventory(run_dir)),
        "pod_resources": read_pod_top(run_dir),
        "protocol_evidence": read_protocol_evidence(run_dir) if mode == "protocol" else None,
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
            "operations_per_second": summary(
                [float(run["workload"]["operations_per_second"]) for run in mode_runs]
            ),
            "iteration_latency_p95_ms": summary(
                [float(run["workload"]["iteration_latency_ms"]["p95"]) for run in mode_runs]
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
    none_rate = result["none"]["operations_per_second"]["mean"]
    protocol_rate = result["protocol"]["operations_per_second"]["mean"]
    delta = None
    if none_rate not in {None, 0} and protocol_rate is not None:
        delta = round((protocol_rate - none_rate) / none_rate * 100, 6)
    result["protocol_vs_no_agent_operations_delta_percent"] = delta
    result["correctness_gate_passed"] = all(
        not run["agent_pods"] if run["mode"] == "none" else run["protocol_evidence"] is not None
        for run in runs
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_root", type=Path, nargs="?")
    parser.add_argument("--validate-run", nargs=3, metavar=("MODE", "REPETITION", "RUN_DIR"))
    args = parser.parse_args()
    if args.validate_run:
        mode, repetition, run_dir = args.validate_run
        run = read_run(mode, int(repetition), Path(run_dir))
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
        raise SystemExit(f"no protocol-surface runs found under {args.results_root}")
    print(
        json.dumps(
            {
                "schema": "e-navigator.protocol-surface-analysis.v1",
                "results_root": str(args.results_root),
                "runs": runs,
                "aggregate": aggregate(runs),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
