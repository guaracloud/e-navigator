#!/usr/bin/env python3
"""Regression and boundary tests for the homelab head-to-head analyzer."""

from __future__ import annotations

import importlib.util
import json
import random
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock


def load_analyzer() -> ModuleType:
    path = Path(__file__).parents[1] / "benchmarks/runner/analyze-head-to-head.py"
    spec = importlib.util.spec_from_file_location("head_to_head_analysis", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load analyzer from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ANALYZER = load_analyzer()


def family_result(family: str, successes: int = 200) -> dict[str, object]:
    return {
        "offered_rps": ANALYZER.DEFAULT_RATES[family]
        if hasattr(ANALYZER, "DEFAULT_RATES")
        else {"http": 100, "grpc": 80, "redis": 160, "postgres": 50, "python_cpu": 8}[
            family
        ],
        "concurrency": {"http": 8, "grpc": 8, "redis": 8, "postgres": 5, "python_cpu": 2}[
            family
        ],
        "scheduled": successes,
        "successes": successes,
        "errors": 0,
        "throughput_rps": float(successes) / 10,
        "latency_us": {"p50": 100, "p95": 200, "p99": 300, "max": 400},
    }


def workload(condition: str, repetition: int) -> dict[str, object]:
    families = {family: family_result(family) for family in ANALYZER.FAMILIES}
    return {
        "schema": "e-navigator.head-to-head-workload.v1",
        "condition": condition,
        "repetition": repetition,
        "load_node": "homelab-01",
        "server_node": "homelab-02",
        "python_version": "3.13.11",
        "warmup_seconds": 15,
        "duration_seconds": 45,
        "warmup": {
            "started_unix_nanos": 1_000_000_000,
            "finished_unix_nanos": 16_000_000_000,
            "elapsed_seconds": 15.0,
            "families": families,
        },
        "measured": {
            "started_unix_nanos": 16_000_000_000,
            "finished_unix_nanos": 61_000_000_000,
            "elapsed_seconds": 45.0,
            "families": families,
        },
    }


def write_prometheus(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n")


class HeadToHeadAnalysisTests(unittest.TestCase):
    def test_beyla_render_targets_the_instrumented_proxies_cumulatively(self) -> None:
        rendered = ANALYZER.render_beyla("profile")
        selectors = rendered["config"]["data"]["discovery"]["instrument"]
        deployments = [selector["k8s_deployment_name"] for selector in selectors]

        self.assertEqual(
            deployments,
            [
                "head-to-head-http",
                "head-to-head-grpc",
                "head-to-head-redis-proxy",
                "head-to-head-postgres-proxy",
                "head-to-head-python-cpu",
            ],
        )
        self.assertNotIn("head-to-head-redis", deployments)
        self.assertEqual(rendered["image"]["digest"], ANALYZER.BEYLA_IMAGE.split("@", 1)[1])

    def test_beyla_accounting_reports_per_protocol_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            write_prometheus(run_dir / "collector-app-before.prom", [])
            write_prometheus(
                run_dir / "collector-app-after.prom",
                [
                    "http_server_request_duration_seconds_count 400",
                    "rpc_server_duration_seconds_count 400",
                    'db_client_operation_duration_seconds_count{db_system="redis"} 400',
                ],
            )
            write_prometheus(run_dir / "collector-internal-before.prom", [])
            write_prometheus(
                run_dir / "collector-internal-after.prom",
                [
                    "beyla_otel_trace_export_errors_total 0",
                    "beyla_otel_metric_export_errors_total 0",
                    "beyla_instrumentation_errors_total 0",
                ],
            )

            result = ANALYZER.beyla_accounting(run_dir, workload("beyla-redis", 1), "redis")

        self.assertEqual(result["coverage"]["http"]["unaccounted_operations"], 0)
        self.assertEqual(result["coverage"]["grpc"]["unaccounted_operations"], 0)
        self.assertEqual(result["coverage"]["redis"]["unaccounted_operations"], 0)
        self.assertEqual(result["internal_hard_errors"], 0)

    def test_e_navigator_accounting_is_partitioned_by_signal_family(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            write_prometheus(run_dir / "collector-app-before.prom", [])
            write_prometheus(
                run_dir / "collector-app-after.prom",
                [
                    'e_navigator_export_enqueued_total{signal_family="traces"} 120',
                    'e_navigator_export_sent_total{signal_family="traces"} 120',
                    'e_navigator_export_dropped_queue_full_total{signal_family="traces"} 0',
                    'e_navigator_export_enqueued_total{signal_family="profiles"} 12',
                    'e_navigator_export_sent_total{signal_family="profiles"} 12',
                    'e_navigator_export_dropped_queue_full_total{signal_family="profiles"} 0',
                    "e_navigator_ebpf_source_lost_transport_events_total 0",
                    'e_navigator_ebpf_source_decoded_samples_total{source="source.aya_cpu_profile"} 12',
                    'e_navigator_ebpf_source_sent_signals_total{source="source.aya_cpu_profile"} 12',
                    'e_navigator_ebpf_source_profile_events_total{source="source.aya_cpu_profile"} 0',
                    'e_navigator_ebpf_source_profile_capture_failures_total{source="source.aya_cpu_profile"} 0',
                ],
            )

            result = ANALYZER.e_navigator_accounting(run_dir)

        self.assertEqual(result["hard_loss_total"], 0)
        self.assertEqual(result["per_signal_family"]["traces"]["enqueued"], 120)
        self.assertEqual(result["per_signal_family"]["profiles"]["sent"], 12)
        self.assertEqual(result["per_signal_family"]["metrics"]["enqueued"], 0)
        self.assertEqual(result["profile_samples_decoded"], 12)
        self.assertEqual(result["profile_signals_sent"], 12)

    def test_topology_enforces_fixed_load_and_server_nodes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            items = []
            for component in (
                "http",
                "grpc",
                "redis",
                "postgres",
                "python-cpu",
                "backend",
                "otlp-sink",
                "load-generator",
            ):
                items.append(
                    {
                        "metadata": {
                            "name": f"head-to-head-{component}",
                            "labels": {
                                "app.kubernetes.io/part-of": "e-navigator-head-to-head",
                                "e-navigator.dev/component": component,
                            },
                        },
                        "spec": {
                            "nodeName": "homelab-01"
                            if component in ("load-generator", "otlp-sink")
                            else "homelab-02"
                        },
                        "status": {
                            "phase": "Running",
                            "containerStatuses": [
                                {
                                    "name": "fixture",
                                    "image": "docker.io/library/e-navigator-head-to-head:gap9-amd64",
                                    "imageID": "sha256:fixture",
                                }
                            ],
                        },
                    }
                )
            (run_dir / "pods-after.json").write_text(json.dumps({"items": items}))

            result = ANALYZER.topology_summary(run_dir)
            items[0]["spec"]["nodeName"] = "homelab-01"
            (run_dir / "pods-after.json").write_text(json.dumps({"items": items}))
            with self.assertRaisesRegex(ValueError, "expected homelab-02"):
                ANALYZER.topology_summary(run_dir)

        self.assertEqual(result["workload_image_id"], "sha256:fixture")

    def test_prometheus_parser_tolerates_fuzzed_untrusted_lines(self) -> None:
        generator = random.Random(9)
        valid_values = {}
        lines = []
        for index in range(500):
            if generator.random() < 0.5:
                name = f"metric_{index}_total"
                value = generator.uniform(-10_000, 10_000)
                lines.append(f'{name}{{family="f{index % 5}"}} {value:.9e}')
                valid_values[(name, f'family="f{index % 5}"')] = value
            else:
                lines.append("".join(chr(generator.randint(32, 126)) for _ in range(40)))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.prom"
            path.write_text("\n".join(lines))
            parsed = ANALYZER.parse_prometheus(path)

        self.assertEqual(set(parsed), set(valid_values))
        for key, expected in valid_values.items():
            self.assertAlmostEqual(parsed[key], expected, places=4)

    def test_prometheus_parser_rejects_oversized_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.prom"
            path.write_text("metric_total 1\n")
            with mock.patch.object(ANALYZER, "MAX_INPUT_BYTES", 4):
                with self.assertRaisesRegex(ValueError, "input exceeds 4 bytes"):
                    ANALYZER.parse_prometheus(path)

    def test_proof_projection_removes_bulk_metric_and_pod_payloads(self) -> None:
        accounting = {
            "metric_deltas": {"large": 1},
            "hard_loss_total": 0,
            "per_signal_family": {
                "traces": {
                    "metric_deltas": {"large": 1},
                    "enqueued": 1,
                    "sent": 1,
                    "hard_loss_total": 0,
                }
            },
        }
        analysis = {
            "runs": [
                {
                    "run": "e-navigator-http-r1",
                    "collector": "e-navigator",
                    "stage": "http",
                    "repetition": 1,
                    "workload": {"schema": "fixture"},
                    "resources": {"agent": {}},
                    "topology": {
                        "components": {"http": 1},
                        "workload_image_id": "sha256:fixture",
                        "collector_image_ids": {"e-navigator": "sha256:agent"},
                        "pods": [{"large": "payload"}],
                    },
                    "signal_accounting": accounting,
                    "otlp_sink": {"requests": {"/v1/traces": 1}},
                }
            ]
        }

        projected = ANALYZER.proof_runs(analysis)["runs"][0]

        self.assertNotIn("pods", projected["topology"])
        self.assertNotIn("metric_deltas", projected["signal_accounting"])
        self.assertNotIn(
            "metric_deltas",
            projected["signal_accounting"]["per_signal_family"]["traces"],
        )

    def test_aggregate_requires_complete_symmetric_matrix(self) -> None:
        names = [f"none-r{repetition}" for repetition in range(1, 4)]
        names.extend(
            f"{collector}-{stage}-r{repetition}"
            for collector in ("beyla", "e-navigator")
            for stage in ANALYZER.STAGES
            for repetition in range(1, 4)
        )

        def fake_run(path: Path) -> dict[str, object]:
            match = ANALYZER.RUN_NAME.match(path.name)
            assert match is not None
            collector = "none" if match.group("none") else str(match.group("collector"))
            stage = "none" if collector == "none" else str(match.group("stage"))
            repetition = int(match.group("repetition"))
            condition = "none" if collector == "none" else f"{collector}-{stage}"
            agent = None
            if collector != "none":
                cpu = 0.2 if collector == "beyla" else 0.1
                rss = 200_000_000 if collector == "beyla" else 100_000_000
                agent = {
                    "cpu_cores": {"mean": cpu},
                    "rss_bytes": {"mean": rss},
                }
            collector_image_ids = {}
            if collector == "beyla":
                collector_image_ids["beyla"] = "sha256:beyla"
                if stage == "profile":
                    collector_image_ids["alloy"] = "sha256:alloy"
            elif collector == "e-navigator":
                collector_image_ids["e-navigator"] = "sha256:e-navigator"
            return {
                "run": path.name,
                "collector": collector,
                "stage": stage,
                "repetition": repetition,
                "workload": workload(condition, repetition),
                "resources": {
                    "agent": agent,
                    "node_cpu_cores": {
                        node: {"mean": 0.5}
                        for node in ("homelab-01", "homelab-02")
                    },
                    "node_memory_bytes": {
                        node: {"mean": 1_000_000_000}
                        for node in ("homelab-01", "homelab-02")
                    },
                },
                "topology": {
                    "workload_image_id": "sha256:fixture",
                    "collector_image_ids": collector_image_ids,
                },
                "signal_accounting": None,
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                (root / name).mkdir()
            nodes = {
                "items": [
                    {
                        "metadata": {"name": name},
                        "status": {
                            "nodeInfo": {
                                "kernelVersion": "6.6.68",
                                "architecture": "amd64",
                                "containerRuntimeVersion": "containerd://1.7",
                                "kubeletVersion": "v1.30.4+k3s1",
                            }
                        },
                    }
                    for name in ("homelab-01", "homelab-02")
                ]
            }
            (root / "nodes.json").write_text(json.dumps(nodes))
            (root / "validated-run-order.log").write_text(
                "".join(f"2026-07-22T00:00:00Z {name}\n" for name in names)
            )
            with mock.patch.object(ANALYZER, "validate_run", side_effect=fake_run):
                result = ANALYZER.aggregate(root)

        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(len(result["runs"]), 33)
        self.assertEqual(
            result["final_stack_comparison"][
                "e_navigator_agent_cpu_change_vs_beyla_alloy_percent"
            ],
            -50.0,
        )
        self.assertEqual(result["environment"]["kernel"], "6.6.68")


if __name__ == "__main__":
    unittest.main()
