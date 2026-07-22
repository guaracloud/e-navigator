#!/usr/bin/env python3
"""Render, validate, and aggregate the guarded homelab head-to-head campaign."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


STAGES = ("http", "grpc", "redis", "postgres", "profile")
COMPONENTS = {
    "http": ("http",),
    "grpc": ("http", "grpc"),
    "redis": ("http", "grpc", "redis-proxy"),
    "postgres": ("http", "grpc", "redis-proxy", "postgres-proxy"),
    "profile": ("http", "grpc", "redis-proxy", "postgres-proxy", "python-cpu"),
}
FAMILIES = ("http", "grpc", "redis", "postgres", "python_cpu")
RUN_NAME = re.compile(
    r"^(?:(?P<none>none)|(?P<collector>beyla|e-navigator)-(?P<stage>http|grpc|redis|postgres|profile))-r(?P<repetition>[1-3])$"
)
PROMETHEUS_LINE = re.compile(
    r"^(?P<name>[A-Za-z_:][A-Za-z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>-?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)$"
)
BEYLA_IMAGE = "docker.io/grafana/beyla@sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566"
BEYLA_CHART_VERSION = "1.16.10"
ALLOY_IMAGE = "docker.io/grafana/alloy@sha256:491b0578c04983fd54fe99b587b6fab4404dc46d0dc16677bd6b00cc1140b308"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_PROMETHEUS_SERIES = 100_000
MAX_MATRIX_SAMPLES = 100_000


def fail(message: str) -> None:
    raise ValueError(message)


def bounded_text(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        fail(f"{path}: input exceeds {MAX_INPUT_BYTES} bytes")
    return path.read_text(errors="replace")


def bounded_json(path: Path) -> Any:
    return json.loads(bounded_text(path))


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        fail("cannot calculate percentile of an empty sample")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def stats(values: Iterable[float]) -> dict[str, float | int]:
    sample = list(values)
    if not sample:
        fail("cannot summarize an empty sample")
    mean = statistics.fmean(sample)
    return {
        "samples": len(sample),
        "min": round(min(sample), 9),
        "mean": round(mean, 9),
        "median": round(statistics.median(sample), 9),
        "p95": round(percentile(sample, 0.95), 9),
        "max": round(max(sample), 9),
        "stdev": round(statistics.stdev(sample), 9) if len(sample) > 1 else 0.0,
        "coefficient_of_variation_percent": (
            round(statistics.stdev(sample) / mean * 100, 6)
            if len(sample) > 1 and mean != 0
            else 0.0
        ),
    }


def percent_change(value: float, baseline: float) -> float:
    if baseline == 0:
        fail("cannot compare against a zero baseline")
    return round((value - baseline) / baseline * 100, 6)


def render_beyla(stage: str) -> dict[str, Any]:
    if stage not in COMPONENTS:
        fail(f"unknown stage: {stage}")
    selectors = [
        {
            "k8s_namespace": "e-navigator-bench",
            "k8s_deployment_name": f"head-to-head-{component}",
        }
        for component in COMPONENTS[stage]
    ]
    return {
        "fullnameOverride": "head-to-head-beyla",
        "image": {
            "registry": "docker.io",
            "repository": "grafana/beyla",
            "digest": "sha256:133b8d66190f21e20365d9972e1621513ea5e44518fb71e1c3e0180c64815566",
            "pullPolicy": "IfNotPresent",
        },
        "contextPropagation": {"enabled": False},
        "podLabels": {
            "e-navigator.dev/collector": "beyla",
            "e-navigator.dev/disposable": "true",
        },
        "config": {
            "create": True,
            "data": {
                "log_level": "info",
                "attributes": {"kubernetes": {"enable": True}},
                "discovery": {"instrument": selectors},
                "ebpf": {
                    "buffer_sizes": {"http": 8192, "postgres": 8192},
                    "heuristic_sql_detect": False,
                },
                "otel_traces_export": {
                    "endpoint": "http://head-to-head-otlp-sink.e-navigator-bench.svc.cluster.local:4318",
                    "protocol": "http/protobuf",
                },
                "prometheus_export": {
                    "port": 9090,
                    "path": "/metrics",
                    "features": ["application"],
                },
                "internal_metrics": {
                    "exporter": "prometheus",
                    "prometheus": {"port": 9090, "path": "/internal/metrics"},
                },
            },
        },
        "service": {"enabled": True, "type": "ClusterIP"},
        "serviceMonitor": {"enabled": False},
        "nodeSelector": {"kubernetes.io/hostname": "homelab-02"},
        "tolerations": [{"operator": "Exists"}],
        "resources": {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "2", "memory": "1Gi"},
        },
    }


def read_workload(run_dir: Path) -> dict[str, Any]:
    matches = []
    for line in bounded_text(run_dir / "workload.log").splitlines():
        if "HEAD2HEAD_RESULT " not in line:
            continue
        _, payload = line.split("HEAD2HEAD_RESULT ", 1)
        matches.append(json.loads(payload))
    if len(matches) != 1:
        fail(f"{run_dir}: expected exactly one HEAD2HEAD_RESULT, got {len(matches)}")
    result = matches[0]
    if result.get("schema") != "e-navigator.head-to-head-workload.v1":
        fail(f"{run_dir}: unexpected workload schema")
    if result.get("server_node") != "homelab-02":
        fail(f"{run_dir}: workload server node drifted")
    if result.get("load_node") != "homelab-01":
        fail(f"{run_dir}: workload load-generator node drifted")
    for phase_name in ("warmup", "measured"):
        phase = result.get(phase_name, {})
        families = phase.get("families", {})
        if set(families) != set(FAMILIES):
            fail(f"{run_dir}: {phase_name} family set drifted: {sorted(families)}")
        for family, value in families.items():
            scheduled = value.get("scheduled")
            successes = value.get("successes")
            errors = value.get("errors")
            if not isinstance(scheduled, int) or scheduled < 100:
                fail(f"{run_dir}: {phase_name}/{family} scheduled too little work")
            if successes != scheduled or errors != 0:
                fail(
                    f"{run_dir}: {phase_name}/{family} lost workload operations: "
                    f"scheduled={scheduled} successes={successes} errors={errors}"
                )
            if phase_name == "measured":
                latencies = value.get("latency_us", {})
                ordered = [latencies.get(key) for key in ("p50", "p95", "p99", "max")]
                if any(not isinstance(item, int) or item <= 0 for item in ordered):
                    fail(f"{run_dir}: invalid {family} latency percentiles: {latencies}")
                if ordered != sorted(ordered):
                    fail(f"{run_dir}: non-monotonic {family} latency percentiles: {latencies}")
                if float(value.get("throughput_rps", 0)) <= 0:
                    fail(f"{run_dir}: invalid {family} throughput")
    return result


def parse_prometheus(path: Path) -> dict[tuple[str, str], float]:
    parsed: dict[tuple[str, str], float] = {}
    for line in bounded_text(path).splitlines():
        match = PROMETHEUS_LINE.match(line.strip())
        if not match:
            continue
        value = float(match.group("value"))
        if math.isfinite(value):
            key = (match.group("name"), match.group("labels") or "")
            if key not in parsed and len(parsed) >= MAX_PROMETHEUS_SERIES:
                fail(f"{path}: Prometheus series exceed {MAX_PROMETHEUS_SERIES}")
            parsed[key] = value
    return parsed


def prometheus_delta(
    before: dict[tuple[str, str], float], after: dict[tuple[str, str], float]
) -> dict[str, float]:
    result: dict[str, float] = {}
    for key, value in after.items():
        name, labels = key
        if not name.endswith("_total") and not name.endswith("_count"):
            continue
        delta = value - before.get(key, 0.0)
        result[f"{name}{{{labels}}}" if labels else name] = max(0.0, delta)
    return dict(sorted(result.items()))


def scalar_deltas_by_name(deltas: dict[str, float], names: Iterable[str]) -> float:
    selected = tuple(names)
    return sum(
        value
        for key, value in deltas.items()
        if any(key == name or key.startswith(f"{name}{{") for name in selected)
    )


def expected_operations(workload: dict[str, Any], stage: str) -> dict[str, int]:
    enabled = {
        "http": ("http",),
        "grpc": ("http", "grpc"),
        "redis": ("http", "grpc", "redis"),
        "postgres": ("http", "grpc", "redis", "postgres"),
        "profile": FAMILIES,
    }[stage]
    return {
        family: sum(
            int(workload[phase]["families"][family]["successes"])
            for phase in ("warmup", "measured")
        )
        for family in enabled
    }


def beyla_accounting(run_dir: Path, workload: dict[str, Any], stage: str) -> dict[str, Any]:
    before = parse_prometheus(run_dir / "collector-app-before.prom")
    after = parse_prometheus(run_dir / "collector-app-after.prom")
    app_delta = prometheus_delta(before, after)
    internal_before = parse_prometheus(run_dir / "collector-internal-before.prom")
    internal_after = parse_prometheus(run_dir / "collector-internal-after.prom")
    internal_delta = prometheus_delta(internal_before, internal_after)
    expected = expected_operations(workload, stage)

    observed: dict[str, float | None] = {
        "http": scalar_deltas_by_name(app_delta, ("http_server_request_duration_seconds_count",)),
        "grpc": scalar_deltas_by_name(
            app_delta,
            (
                "rpc_server_call_duration_seconds_count",
                "rpc_server_duration_seconds_count",
            ),
        ),
        "redis": sum(
            value
            for key, value in app_delta.items()
            if key.startswith("db_client_operation_duration_seconds_count{")
            and "redis" in key.lower()
        ),
        "postgres": sum(
            value
            for key, value in app_delta.items()
            if key.startswith("db_client_operation_duration_seconds_count{")
            and ("postgres" in key.lower() or "postgresql" in key.lower())
        ),
        "python_cpu": None,
    }
    coverage = {}
    for family, count in expected.items():
        if family == "python_cpu":
            continue
        seen = float(observed.get(family) or 0.0)
        coverage[family] = {
            "expected_operations": count,
            "observed_metric_count": seen,
            "observed_minus_expected": seen - count,
            "unaccounted_operations": max(0.0, count - seen),
            "unaccounted_percent": round(max(0.0, count - seen) / count * 100, 6),
            "overcounted_operations": max(0.0, seen - count),
            "overcounted_percent": round(max(0.0, seen - count) / count * 100, 6),
        }

    hard_error_names = (
        "beyla_otel_trace_export_errors_total",
        "beyla_otel_metric_export_errors_total",
        "beyla_instrumentation_errors_total",
    )
    hard_errors = scalar_deltas_by_name(internal_delta, hard_error_names)
    accounting: dict[str, Any] = {
        "expected": expected,
        "observed": observed,
        "coverage": coverage,
        "internal_hard_errors": hard_errors,
        "application_metric_deltas": app_delta,
        "internal_metric_deltas": internal_delta,
    }
    if stage == "profile":
        alloy_before = parse_prometheus(run_dir / "alloy-before.prom")
        alloy_after = parse_prometheus(run_dir / "alloy-after.prom")
        alloy_delta = prometheus_delta(alloy_before, alloy_after)
        accounting["alloy"] = {
            "profile_metric_deltas": alloy_delta,
            "profiles_collected": scalar_deltas_by_name(
                alloy_delta, ("pyroscope_ebpf_pprofs_total",)
            ),
            "profiles_dropped": scalar_deltas_by_name(
                alloy_delta, ("pyroscope_ebpf_pprofs_dropped_total",)
            ),
            "profiles_forwarded": scalar_deltas_by_name(
                alloy_delta, ("pyroscope_forwarded_entries_total",)
            ),
            "sessions": scalar_deltas_by_name(
                alloy_delta, ("pyroscope_ebpf_profiling_sessions_total",)
            ),
            "failing_sessions": scalar_deltas_by_name(
                alloy_delta, ("pyroscope_ebpf_profiling_sessions_failing_total",)
            ),
            "error_or_loss_metrics": {
                key: value
                for key, value in alloy_delta.items()
                if any(token in key.lower() for token in ("error", "fail", "lost", "drop"))
            },
        }
    return accounting


def e_navigator_accounting(run_dir: Path) -> dict[str, Any]:
    before = parse_prometheus(run_dir / "collector-app-before.prom")
    after = parse_prometheus(run_dir / "collector-app-after.prom")
    deltas = prometheus_delta(before, after)
    source_names = (
        "e_navigator_ebpf_source_decoded_samples_total",
        "e_navigator_ebpf_source_filtered_samples_total",
        "e_navigator_ebpf_source_invalid_samples_total",
        "e_navigator_ebpf_source_sent_signals_total",
        "e_navigator_ebpf_source_send_failures_total",
        "e_navigator_ebpf_source_lost_transport_events_total",
        "e_navigator_ebpf_source_lost_perf_events_total",
        "e_navigator_ebpf_source_ring_buffer_reservation_failures_total",
        "e_navigator_ebpf_source_profile_events_total",
        "e_navigator_ebpf_source_profile_capture_failures_total",
        "e_navigator_ebpf_source_profile_pending_misses_total",
        "e_navigator_ebpf_source_profile_state_replacements_total",
        "e_navigator_ebpf_source_profile_output_attempts_total",
        "e_navigator_source_failures_total",
    )
    export_names = (
        "e_navigator_export_enqueued_total",
        "e_navigator_export_sent_total",
        "e_navigator_export_dropped_queue_full_total",
        "e_navigator_export_dropped_worker_closed_total",
        "e_navigator_export_dropped_failure_total",
        "e_navigator_export_dropped_circuit_open_total",
        "e_navigator_export_failed_batches_total",
        "e_navigator_export_retry_attempts_total",
        "e_navigator_export_circuit_opened_total",
        "e_navigator_export_partial_success_total",
        "e_navigator_export_rejected_items_total",
        "e_navigator_export_retryable_responses_total",
        "e_navigator_export_permanent_responses_total",
        "e_navigator_export_invalid_responses_total",
        "e_navigator_export_invalid_trace_records_total",
    )
    selected = {
        key: value
        for key, value in deltas.items()
        if any(key == name or key.startswith(f"{name}{{") for name in source_names + export_names)
    }
    hard_loss_names = (
        "e_navigator_ebpf_source_invalid_samples_total",
        "e_navigator_ebpf_source_send_failures_total",
        "e_navigator_ebpf_source_lost_transport_events_total",
        "e_navigator_ebpf_source_lost_perf_events_total",
        "e_navigator_ebpf_source_ring_buffer_reservation_failures_total",
        "e_navigator_ebpf_source_profile_capture_failures_total",
        "e_navigator_ebpf_source_profile_pending_misses_total",
        "e_navigator_ebpf_source_profile_state_replacements_total",
        "e_navigator_source_failures_total",
        "e_navigator_export_dropped_queue_full_total",
        "e_navigator_export_dropped_worker_closed_total",
        "e_navigator_export_dropped_failure_total",
        "e_navigator_export_dropped_circuit_open_total",
        "e_navigator_export_failed_batches_total",
        "e_navigator_export_rejected_items_total",
        "e_navigator_export_permanent_responses_total",
        "e_navigator_export_invalid_responses_total",
        "e_navigator_export_invalid_trace_records_total",
    )
    export_family_names = (
        "e_navigator_export_enqueued_total",
        "e_navigator_export_sent_total",
        "e_navigator_export_dropped_queue_full_total",
        "e_navigator_export_dropped_worker_closed_total",
        "e_navigator_export_dropped_failure_total",
        "e_navigator_export_dropped_circuit_open_total",
        "e_navigator_export_failed_batches_total",
        "e_navigator_export_rejected_items_total",
        "e_navigator_export_permanent_responses_total",
        "e_navigator_export_invalid_responses_total",
    )
    per_signal_family = {}
    for family in ("metrics", "traces", "profiles"):
        family_deltas = {
            key: value
            for key, value in selected.items()
            if f'signal_family="{family}"' in key
            and any(key.startswith(name) for name in export_family_names)
        }
        per_signal_family[family] = {
            "metric_deltas": family_deltas,
            "enqueued": scalar_deltas_by_name(
                family_deltas, ("e_navigator_export_enqueued_total",)
            ),
            "sent": scalar_deltas_by_name(
                family_deltas, ("e_navigator_export_sent_total",)
            ),
            "hard_loss_total": scalar_deltas_by_name(family_deltas, hard_loss_names),
        }
    profile_source_deltas = {
        key: value
        for key, value in selected.items()
        if 'source="source.aya_cpu_profile"' in key
    }
    return {
        "metric_deltas": dict(sorted(selected.items())),
        "hard_loss_total": scalar_deltas_by_name(deltas, hard_loss_names),
        "source_samples_decoded": scalar_deltas_by_name(
            deltas, ("e_navigator_ebpf_source_decoded_samples_total",)
        ),
        "source_signals_sent": scalar_deltas_by_name(
            deltas, ("e_navigator_ebpf_source_sent_signals_total",)
        ),
        "per_signal_family": per_signal_family,
        "profile_capture_failures": scalar_deltas_by_name(
            deltas, ("e_navigator_ebpf_source_profile_capture_failures_total",)
        ),
        "profile_samples_decoded": scalar_deltas_by_name(
            profile_source_deltas, ("e_navigator_ebpf_source_decoded_samples_total",)
        ),
        "profile_signals_sent": scalar_deltas_by_name(
            profile_source_deltas, ("e_navigator_ebpf_source_sent_signals_total",)
        ),
        "profile_events": scalar_deltas_by_name(
            deltas, ("e_navigator_ebpf_source_profile_events_total",)
        ),
    }


def topology_summary(run_dir: Path) -> dict[str, Any]:
    payload = bounded_json(run_dir / "pods-after.json")
    pods = []
    components = Counter()
    collector_image_ids: dict[str, set[str]] = defaultdict(set)
    workload_image_ids = set()
    for item in payload.get("items", []):
        metadata = item.get("metadata", {})
        labels = metadata.get("labels", {})
        collector = labels.get("e-navigator.dev/collector")
        if (
            labels.get("app.kubernetes.io/part-of") != "e-navigator-head-to-head"
            and not collector
        ):
            continue
        component = labels.get("e-navigator.dev/component")
        node = item.get("spec", {}).get("nodeName")
        if component:
            components[component] += 1
            expected_node = (
                "homelab-01"
                if component in ("load-generator", "otlp-sink")
                else "homelab-02"
            )
            if node != expected_node:
                fail(
                    f"{run_dir}: {metadata.get('name')} ran on {node}, "
                    f"expected {expected_node}"
                )
        if collector and node != "homelab-02":
            fail(f"{run_dir}: collector {metadata.get('name')} drifted from homelab-02")
        containers = []
        for status in item.get("status", {}).get("containerStatuses", []):
            image = str(status.get("image", ""))
            image_id = str(status.get("imageID", ""))
            containers.append(
                {"name": status.get("name"), "image": image, "image_id": image_id}
            )
            if "e-navigator-head-to-head" in image:
                workload_image_ids.add(image_id)
            if collector:
                collector_image_ids[collector].add(image_id)
        pods.append(
            {
                "name": metadata.get("name"),
                "node": node,
                "phase": item.get("status", {}).get("phase"),
                "component": component,
                "collector": collector,
                "containers": containers,
            }
        )
    required = {
        "http",
        "grpc",
        "redis",
        "postgres",
        "python-cpu",
        "backend",
        "otlp-sink",
        "load-generator",
    }
    missing = required - set(components)
    if missing:
        fail(f"{run_dir}: missing workload components in topology: {sorted(missing)}")
    if len(workload_image_ids) != 1 or "" in workload_image_ids:
        fail(f"{run_dir}: workload image identity drifted: {sorted(workload_image_ids)}")
    if any("" in image_ids or len(image_ids) != 1 for image_ids in collector_image_ids.values()):
        fail(f"{run_dir}: collector image identity drifted inside one arm")
    return {
        "components": dict(sorted(components.items())),
        "workload_image_id": next(iter(workload_image_ids)),
        "collector_image_ids": {
            collector: next(iter(image_ids))
            for collector, image_ids in sorted(collector_image_ids.items())
        },
        "pods": sorted(pods, key=lambda pod: str(pod["name"])),
    }


def matrix_values(path: Path) -> dict[str, list[float]]:
    response = bounded_json(path)
    if response.get("status") != "success":
        fail(f"{path}: Prometheus query failed")
    result = response.get("data", {}).get("result", [])
    values: dict[str, list[float]] = defaultdict(list)
    sample_count = 0
    for series in result:
        metric = series.get("metric", {})
        identity = str(metric.get("node") or metric.get("instance") or "total")
        for _timestamp, raw_value in series.get("values", []):
            value = float(raw_value)
            if math.isfinite(value):
                sample_count += 1
                if sample_count > MAX_MATRIX_SAMPLES:
                    fail(f"{path}: matrix samples exceed {MAX_MATRIX_SAMPLES}")
                values[identity].append(value)
    return dict(values)


def resource_summary(run_dir: Path, collector: str) -> dict[str, Any]:
    node_cpu = matrix_values(run_dir / "prom-node-cpu.json")
    node_memory = matrix_values(run_dir / "prom-node-memory.json")
    if not node_cpu or not node_memory:
        fail(f"{run_dir}: node resource series are empty")
    result: dict[str, Any] = {
        "node_cpu_cores": {node: stats(values) for node, values in sorted(node_cpu.items())},
        "node_memory_bytes": {
            node: stats(values) for node, values in sorted(node_memory.items())
        },
    }
    agent_cpu = matrix_values(run_dir / "prom-agent-cpu.json")
    agent_rss = matrix_values(run_dir / "prom-agent-rss.json")
    if collector == "none":
        if any(agent_cpu.values()) or any(agent_rss.values()):
            fail(f"{run_dir}: no-agent run contained collector resource samples")
        result["agent"] = None
    else:
        cpu_values = [value for values in agent_cpu.values() for value in values]
        rss_values = [value for values in agent_rss.values() for value in values]
        if len(cpu_values) < 2 or len(rss_values) < 2:
            fail(f"{run_dir}: insufficient collector resource samples")
        result["agent"] = {
            "cpu_cores": stats(cpu_values),
            "rss_bytes": stats(rss_values),
        }
    return result


def validate_run(run_dir: Path) -> dict[str, Any]:
    match = RUN_NAME.match(run_dir.name)
    if not match:
        fail(f"invalid run directory name: {run_dir.name}")
    collector = "none" if match.group("none") else str(match.group("collector"))
    stage = "none" if collector == "none" else str(match.group("stage"))
    repetition = int(match.group("repetition"))
    workload = read_workload(run_dir)
    if workload.get("condition") != ("none" if collector == "none" else f"{collector}-{stage}"):
        fail(f"{run_dir}: workload condition did not match directory")
    if workload.get("repetition") != repetition:
        fail(f"{run_dir}: workload repetition did not match directory")

    sink = bounded_json(run_dir / "otlp-sink-after.json")
    if sink.get("schema") != "e-navigator.head-to-head-otlp-sink.v1":
        fail(f"{run_dir}: invalid OTLP sink schema")
    accounting: dict[str, Any] | None = None
    if collector == "beyla":
        accounting = beyla_accounting(run_dir, workload, stage)
        if accounting["internal_hard_errors"] != 0:
            fail(f"{run_dir}: Beyla reported instrumentation or export errors")
        if stage == "profile":
            alloy = accounting.get("alloy", {})
            if (
                alloy.get("profiles_collected", 0) <= 0
                or alloy.get("profiles_forwarded", 0) <= 0
                or alloy.get("profiles_dropped") != 0
                or alloy.get("failing_sessions") != 0
            ):
                fail(f"{run_dir}: Alloy profile accounting failed: {alloy}")
    elif collector == "e-navigator":
        accounting = e_navigator_accounting(run_dir)
        if accounting["hard_loss_total"] != 0:
            fail(f"{run_dir}: E-Navigator reported hard signal loss")
        if accounting["source_samples_decoded"] <= 0 or accounting["source_signals_sent"] <= 0:
            fail(f"{run_dir}: E-Navigator emitted no source signals")
        if stage == "profile" and (
            accounting["profile_samples_decoded"] <= 0
            or accounting["profile_signals_sent"] <= 0
            or accounting["per_signal_family"]["profiles"]["enqueued"] <= 0
            or accounting["per_signal_family"]["profiles"]["sent"] <= 0
        ):
            fail(f"{run_dir}: E-Navigator emitted no on-CPU profile samples")
    elif sink.get("requests"):
        fail(f"{run_dir}: no-agent run unexpectedly exported OTLP data")
    if collector != "none" and sum(int(value) for value in sink.get("requests", {}).values()) <= 0:
        fail(f"{run_dir}: collector exported no OTLP requests")

    return {
        "schema": "e-navigator.head-to-head-run.v1",
        "run": run_dir.name,
        "collector": collector,
        "stage": stage,
        "repetition": repetition,
        "workload": workload,
        "resources": resource_summary(run_dir, collector),
        "topology": topology_summary(run_dir),
        "signal_accounting": accounting,
        "otlp_sink": sink,
    }


def aggregate_node_resources(grouped: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = set(grouped[0]["resources"]["node_cpu_cores"])
    if any(set(run["resources"]["node_cpu_cores"]) != nodes for run in grouped):
        fail("node CPU resource identities drifted between repetitions")
    if any(set(run["resources"]["node_memory_bytes"]) != nodes for run in grouped):
        fail("node memory resource identities drifted between repetitions")
    return {
        node: {
            "cpu_cores": stats(
                float(run["resources"]["node_cpu_cores"][node]["mean"])
                for run in grouped
            ),
            "memory_bytes": stats(
                float(run["resources"]["node_memory_bytes"][node]["mean"])
                for run in grouped
            ),
        }
        for node in sorted(nodes)
    }


def aggregate_signal_accounting(
    collector: str, grouped: list[dict[str, Any]]
) -> dict[str, Any] | None:
    accounting = [run["signal_accounting"] for run in grouped]
    if not accounting or any(item is None for item in accounting):
        return None
    if collector == "e-navigator":
        return {
            "hard_loss_total": sum(float(item["hard_loss_total"]) for item in accounting),
            "source_samples_decoded": sum(
                float(item["source_samples_decoded"]) for item in accounting
            ),
            "source_signals_sent": sum(
                float(item["source_signals_sent"]) for item in accounting
            ),
            "profile_samples_decoded": sum(
                float(item["profile_samples_decoded"]) for item in accounting
            ),
            "profile_signals_sent": sum(
                float(item["profile_signals_sent"]) for item in accounting
            ),
            "per_signal_family": {
                family: {
                    key: sum(
                        float(item["per_signal_family"][family][key])
                        for item in accounting
                    )
                    for key in ("enqueued", "sent", "hard_loss_total")
                }
                for family in ("metrics", "traces", "profiles")
            },
        }

    families = sorted(
        {family for item in accounting for family in item["coverage"]}
    )
    coverage = {}
    for family in families:
        expected = sum(
            float(item["coverage"][family]["expected_operations"])
            for item in accounting
            if family in item["coverage"]
        )
        observed = sum(
            float(item["coverage"][family]["observed_metric_count"])
            for item in accounting
            if family in item["coverage"]
        )
        coverage[family] = {
            "expected_operations": expected,
            "observed_metric_count": observed,
            "observed_minus_expected": observed - expected,
            "unaccounted_operations": max(0.0, expected - observed),
            "unaccounted_percent": round(
                max(0.0, expected - observed) / expected * 100, 6
            ),
            "overcounted_operations": max(0.0, observed - expected),
            "overcounted_percent": round(
                max(0.0, observed - expected) / expected * 100, 6
            ),
        }
    result: dict[str, Any] = {
        "internal_hard_errors": sum(
            float(item["internal_hard_errors"]) for item in accounting
        ),
        "coverage": coverage,
    }
    alloy = [item["alloy"] for item in accounting if "alloy" in item]
    if alloy:
        error_or_loss: dict[str, float] = defaultdict(float)
        for item in alloy:
            for metric, value in item["error_or_loss_metrics"].items():
                error_or_loss[metric] += float(value)
        result["alloy"] = {
            key: sum(float(item[key]) for item in alloy)
            for key in (
                "profiles_collected",
                "profiles_dropped",
                "profiles_forwarded",
                "sessions",
                "failing_sessions",
            )
        }
        result["alloy"]["error_or_loss_metric_deltas"] = dict(
            sorted(error_or_loss.items())
        )
    return result


def aggregate(results_root: Path) -> dict[str, Any]:
    runs = []
    for path in sorted(results_root.iterdir()):
        if path.is_dir() and RUN_NAME.match(path.name):
            runs.append(validate_run(path))
    expected_runs = 3 + 2 * len(STAGES) * 3
    if len(runs) != expected_runs:
        fail(f"expected {expected_runs} validated runs, got {len(runs)}")

    workload_contracts = {
        json.dumps(
            {
                "warmup_seconds": run["workload"]["warmup_seconds"],
                "duration_seconds": run["workload"]["duration_seconds"],
                "families": {
                    family: {
                        "offered_rps": run["workload"]["measured"]["families"][family][
                            "offered_rps"
                        ],
                        "concurrency": run["workload"]["measured"]["families"][family][
                            "concurrency"
                        ],
                    }
                    for family in FAMILIES
                },
            },
            sort_keys=True,
        )
        for run in runs
    }
    if len(workload_contracts) != 1:
        fail("workload duration, offered rate, or concurrency drifted between arms")
    workload_contract = json.loads(next(iter(workload_contracts)))
    workload_image_ids = {run["topology"]["workload_image_id"] for run in runs}
    if len(workload_image_ids) != 1:
        fail(f"workload image identity drifted between arms: {sorted(workload_image_ids)}")
    collector_image_ids: dict[str, set[str]] = defaultdict(set)
    for run in runs:
        for collector, image_id in run["topology"]["collector_image_ids"].items():
            collector_image_ids[collector].add(image_id)
    for collector in ("beyla", "alloy", "e-navigator"):
        if len(collector_image_ids[collector]) != 1:
            fail(
                f"collector image identity drifted for {collector}: "
                f"{sorted(collector_image_ids[collector])}"
            )

    node_payload = bounded_json(results_root / "nodes.json")
    node_evidence = {}
    for item in node_payload.get("items", []):
        name = item.get("metadata", {}).get("name")
        if name not in ("homelab-01", "homelab-02"):
            continue
        info = item.get("status", {}).get("nodeInfo", {})
        node_evidence[name] = {
            "kernel_version": info.get("kernelVersion"),
            "architecture": info.get("architecture"),
            "container_runtime_version": info.get("containerRuntimeVersion"),
            "kubelet_version": info.get("kubeletVersion"),
        }
    if set(node_evidence) != {"homelab-01", "homelab-02"}:
        fail(f"required benchmark nodes were not present: {sorted(node_evidence)}")
    kernels = {value["kernel_version"] for value in node_evidence.values()}
    if len(kernels) != 1:
        fail(f"benchmark node kernels differ: {sorted(kernels)}")

    run_order = [
        line.split(" ", 1)[1]
        for line in bounded_text(results_root / "validated-run-order.log").splitlines()
        if " " in line
    ]
    expected_names = {run["run"] for run in runs}
    if len(run_order) != expected_runs or set(run_order) != expected_names:
        fail("executed run order did not contain each expected arm exactly once")

    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        groups[(run["collector"], run["stage"])].append(run)
    if len(groups[("none", "none")]) != 3:
        fail("expected three no-agent repetitions")
    for collector in ("beyla", "e-navigator"):
        for stage in STAGES:
            if len(groups[(collector, stage)]) != 3:
                fail(f"expected three {collector}/{stage} repetitions")

    baseline = groups[("none", "none")]
    baseline_family = {
        family: {
            "throughput_rps": stats(
                float(run["workload"]["measured"]["families"][family]["throughput_rps"])
                for run in baseline
            ),
            "latency_p50_us": stats(
                float(run["workload"]["measured"]["families"][family]["latency_us"]["p50"])
                for run in baseline
            ),
            "latency_p95_us": stats(
                float(run["workload"]["measured"]["families"][family]["latency_us"]["p95"])
                for run in baseline
            ),
            "latency_p99_us": stats(
                float(run["workload"]["measured"]["families"][family]["latency_us"]["p99"])
                for run in baseline
            ),
        }
        for family in FAMILIES
    }

    conditions: dict[str, Any] = {
        "none": {
            "runs": [run["run"] for run in baseline],
            "families": baseline_family,
            "agent": None,
            "nodes": aggregate_node_resources(baseline),
            "signal_summary": None,
        }
    }
    for collector in ("beyla", "e-navigator"):
        for stage in STAGES:
            grouped = groups[(collector, stage)]
            families = {}
            for family in FAMILIES:
                throughput = stats(
                    float(run["workload"]["measured"]["families"][family]["throughput_rps"])
                    for run in grouped
                )
                p50 = stats(
                    float(run["workload"]["measured"]["families"][family]["latency_us"]["p50"])
                    for run in grouped
                )
                p95 = stats(
                    float(run["workload"]["measured"]["families"][family]["latency_us"]["p95"])
                    for run in grouped
                )
                p99 = stats(
                    float(run["workload"]["measured"]["families"][family]["latency_us"]["p99"])
                    for run in grouped
                )
                families[family] = {
                    "throughput_rps": throughput,
                    "latency_p50_us": p50,
                    "latency_p95_us": p95,
                    "latency_p99_us": p99,
                    "throughput_change_vs_none_percent": percent_change(
                        float(throughput["mean"]),
                        float(baseline_family[family]["throughput_rps"]["mean"]),
                    ),
                    "p99_change_vs_none_percent": percent_change(
                        float(p99["mean"]),
                        float(baseline_family[family]["latency_p99_us"]["mean"]),
                    ),
                }
            cpu = stats(
                float(run["resources"]["agent"]["cpu_cores"]["mean"])
                for run in grouped
            )
            rss = stats(
                float(run["resources"]["agent"]["rss_bytes"]["mean"])
                for run in grouped
            )
            key = f"{collector}-{stage}"
            conditions[key] = {
                "runs": [run["run"] for run in grouped],
                "families": families,
                "agent": {"cpu_cores": cpu, "rss_bytes": rss},
                "nodes": aggregate_node_resources(grouped),
                "signal_summary": aggregate_signal_accounting(collector, grouped),
                "signal_accounting": [run["signal_accounting"] for run in grouped],
            }

    final_beyla = conditions["beyla-profile"]
    final_enav = conditions["e-navigator-profile"]
    final_comparison = {
        "e_navigator_agent_cpu_change_vs_beyla_alloy_percent": percent_change(
            float(final_enav["agent"]["cpu_cores"]["mean"]),
            float(final_beyla["agent"]["cpu_cores"]["mean"]),
        ),
        "e_navigator_agent_rss_change_vs_beyla_alloy_percent": percent_change(
            float(final_enav["agent"]["rss_bytes"]["mean"]),
            float(final_beyla["agent"]["rss_bytes"]["mean"]),
        ),
        "families": {
            family: {
                metric: percent_change(
                    float(final_enav["families"][family][metric]["mean"]),
                    float(final_beyla["families"][family][metric]["mean"]),
                )
                for metric in (
                    "throughput_rps",
                    "latency_p50_us",
                    "latency_p95_us",
                    "latency_p99_us",
                )
            }
            for family in FAMILIES
        },
        "nodes": {
            node: {
                "cpu_change_percent": percent_change(
                    float(final_enav["nodes"][node]["cpu_cores"]["mean"]),
                    float(final_beyla["nodes"][node]["cpu_cores"]["mean"]),
                ),
                "memory_change_percent": percent_change(
                    float(final_enav["nodes"][node]["memory_bytes"]["mean"]),
                    float(final_beyla["nodes"][node]["memory_bytes"]["mean"]),
                ),
            }
            for node in sorted(final_enav["nodes"])
        },
    }
    return {
        "schema": "e-navigator.head-to-head-analysis.v1",
        "decision": "PASS",
        "environment": {
            "cluster": "homelab",
            "server_node": "homelab-02",
            "load_node": "homelab-01",
            "nodes": node_evidence,
            "kernel": next(iter(kernels)),
            "repetitions": 3,
            "workload_contract": workload_contract,
            "workload_image_id": next(iter(workload_image_ids)),
            "collector_image_ids": {
                collector: next(iter(image_ids))
                for collector, image_ids in sorted(collector_image_ids.items())
            },
            "beyla_image": BEYLA_IMAGE,
            "beyla_chart_version": BEYLA_CHART_VERSION,
            "alloy_image": ALLOY_IMAGE,
        },
        "conditions": conditions,
        "final_stack_comparison": final_comparison,
        "run_order": run_order,
        "runs": runs,
    }


def compact_signal_accounting(accounting: dict[str, Any] | None) -> dict[str, Any] | None:
    if accounting is None:
        return None
    if "coverage" in accounting:
        result = {
            "expected": accounting["expected"],
            "observed": accounting["observed"],
            "coverage": accounting["coverage"],
            "internal_hard_errors": accounting["internal_hard_errors"],
        }
        if "alloy" in accounting:
            alloy = accounting["alloy"]
            result["alloy"] = {
                key: value
                for key, value in alloy.items()
                if key != "profile_metric_deltas"
            }
        return result
    return {
        key: value
        for key, value in accounting.items()
        if key != "metric_deltas"
    } | {
        "per_signal_family": {
            family: {
                key: value
                for key, value in family_accounting.items()
                if key != "metric_deltas"
            }
            for family, family_accounting in accounting["per_signal_family"].items()
        }
    }


def proof_runs(analysis: dict[str, Any]) -> dict[str, Any]:
    runs = []
    for run in analysis["runs"]:
        topology = run["topology"]
        runs.append(
            {
                "run": run["run"],
                "collector": run["collector"],
                "stage": run["stage"],
                "repetition": run["repetition"],
                "workload": run["workload"],
                "resources": run["resources"],
                "topology": {
                    "components": topology["components"],
                    "workload_image_id": topology["workload_image_id"],
                    "collector_image_ids": topology["collector_image_ids"],
                },
                "signal_accounting": compact_signal_accounting(
                    run["signal_accounting"]
                ),
                "otlp_sink": run["otlp_sink"],
            }
        )
    return {
        "schema": "e-navigator.head-to-head-proof-runs.v1",
        "runs": runs,
    }


def proof_analysis(analysis: dict[str, Any]) -> dict[str, Any]:
    conditions = {}
    for name, condition in analysis["conditions"].items():
        conditions[name] = {
            key: value
            for key, value in condition.items()
            if key != "signal_accounting"
        }
    return {
        "schema": "e-navigator.head-to-head-proof-analysis.v1",
        "decision": analysis["decision"],
        "environment": analysis["environment"],
        "conditions": conditions,
        "final_stack_comparison": analysis["final_stack_comparison"],
        "run_order": analysis["run_order"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render-beyla")
    render.add_argument("stage", choices=STAGES)
    validate = subparsers.add_parser("validate-run")
    validate.add_argument("run_dir", type=Path)
    aggregate_parser = subparsers.add_parser("aggregate")
    aggregate_parser.add_argument("results_root", type=Path)
    proof_analysis_parser = subparsers.add_parser("proof-analysis")
    proof_analysis_parser.add_argument("results_root", type=Path)
    proof_runs_parser = subparsers.add_parser("proof-runs")
    proof_runs_parser.add_argument("results_root", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "render-beyla":
        output = render_beyla(args.stage)
    elif args.command == "validate-run":
        output = validate_run(args.run_dir)
    elif args.command == "aggregate":
        output = aggregate(args.results_root)
    elif args.command == "proof-analysis":
        output = proof_analysis(aggregate(args.results_root))
    else:
        output = proof_runs(aggregate(args.results_root))
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
