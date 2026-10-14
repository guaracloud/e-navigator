#!/usr/bin/env python3
"""Deterministic synthetic checker fixtures. These do not execute the collector."""
import copy
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ["HTTP", "GRPC", "POSTGRESQL", "MYSQL", "REDIS", "MONGODB", "KAFKA", "TCP", "CPU", "LOG"]
SCENARIOS = ["normal", "concurrent", "pooling", "retry-reconnect", "process-restart", "agent-restart", "late-attachment", "privacy", "unsupported-version"]


def fixture(namespace="WC"):
    golden = {s["kind"]: s for s in json.loads((ROOT / "crates/e-navigator-signals/tests/golden/signal_families.json").read_text())}
    directory = ROOT / "tests/fixtures/cpu-qualification"
    cpu_cell = json.loads((directory / "cells.json").read_text())["WC-CPU-0001"]
    cpu_native = json.loads((directory / "capture.json").read_text())["WC-CPU-0001"]["samples"]
    cpu_response = json.loads((directory / "profiles.json").read_text())["WC-CPU-0001"]
    environment = {"target": "synthetic-local", "kernel": "fixture-no-kernel", "architecture": "x86_64",
                   "cgroup": "fixture", "collector_commit": "0" * 40,
                   "backends": {name: "sha256:" + "b" * 64 for name in ["traces", "profiles", "metrics", "logs"]}}
    manifest = {"schema_version": 1, "fixture": True, "environment": environment,
                "blocked_inputs": [f"IN-{i:02}" for i in range(1, 8)], "cells": {}}
    capture = {"environment": copy.deepcopy(environment), "cells": {}}
    rng = random.Random(48)
    for family_index, family in enumerate(FAMILIES):
        cell_id = f"{namespace}-{family}-9001"
        identity = {"workload_image": "sha256:" + "a" * 64, "collector_image": "sha256:" + "c" * 64,
                    "config": "sha256:" + "d" * 64, "runtime": "synthetic-python-fixture",
                    "runtime_version": "fixture", "build": "fixture-revision-1", "client": "synthetic", "server": "synthetic",
                    "tls": "cleartext-fixture", "architecture": "x86_64", "io_path": "saved-json"}
        if family == "CPU":
            identity.update(runtime=cpu_cell["identity"]["runtime"], build=cpu_cell["identity"]["build_id"])
        cell = {"requiredness": "required", "support": "unknown", "identity": identity,
                "seed": 48 + family_index, "approval": None, "scenarios": {}}
        manifest["cells"][cell_id] = cell
        capture["cells"][cell_id] = {}
        for scenario_index, name in enumerate(SCENARIOS):
            late = name == "late-attachment"
            unsupported = name == "unsupported-version"
            start = 1700000000 if late else 1500000000
            attach = 1600000000 if late else 1400000000
            actions = [{"operation": i, "connection": i, "process_generation": 1, "agent_generation": 1,
                        "attempt": 1, "start_nanos": start + i * 1000,
                        "end_nanos": start + i * 1000 + 900, "outcome": "success" if i == 0 else "failure"} for i in range(2)]
            if name == "concurrent":
                actions[0]["end_nanos"] = actions[1]["end_nanos"]
            if name == "pooling":
                actions[1]["connection"] = 0
            if name == "retry-reconnect":
                actions[0]["outcome"] = "failure"
                actions[1].update(operation=0, attempt=2, outcome="success")
            if name in {"process-restart", "agent-restart"}:
                actions[1]["process_generation" if name == "process-restart" else "agent_generation"] = 2
            if late:
                actions[0]["start_nanos"] = 1500000000
                actions[0]["end_nanos"] = 1500000900
            if unsupported:
                for action in actions:
                    action["outcome"] = "unsupported"
            backend_type = {"CPU": "profiles", "LOG": "logs", "TCP": "metrics"}.get(family, "traces")
            oracle = {"type": backend_type, "empty": unsupported}
            native, response = [], {}
            if backend_type == "traces":
                trees, outcomes, responses = {}, {}, {}
                for operation in range(2):
                    trace_id = f"{rng.getrandbits(128):032x}"
                    span_ids = [f"{rng.getrandbits(64):016x}" for _ in range(2)]
                    spans = []
                    for index, span_id in enumerate(span_ids):
                        parent = "" if index == 0 else span_ids[0]
                        kind = "SPAN_KIND_CLIENT" if index == 0 else "SPAN_KIND_SERVER"
                        spans.append({"span_id": span_id, "parent_span_id": parent, "service": "fixture-client" if index == 0 else "fixture-server", "name": family.lower() + "/operation", "kind": kind})
                        outcomes[span_id] = {"status": 1 if operation == 0 else 2, "error_type": None if operation == 0 else "fixture.failure"}
                        signal = copy.deepcopy(golden["request_span_observation"])
                        signal["source"] = "fixture.request_correlation"
                        signal["payload"].update(name=family.lower() + "/operation", protocol={"POSTGRESQL": "postgres"}.get(family, family.lower()), trace_id=trace_id, span_id=span_id,
                                                 parent_span_id=parent or None, start_unix_nanos=start, end_unix_nanos=start + 200,
                                                 service_name=spans[-1]["service"], status_code=200 if operation == 0 else 500)
                        native.append(signal)
                    trees[trace_id] = spans
                    responses[trace_id] = {"batches": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": span["service"]}}]},
                        "scopeSpans": [{"spans": [{"traceId": trace_id, "spanId": span["span_id"], "parentSpanId": span["parent_span_id"],
                            "name": span["name"], "kind": span["kind"], "status": {"code": outcomes[span["span_id"]]["status"]},
                            "attributes": [] if operation == 0 else [{"key": "error.type", "value": {"stringValue": "fixture.failure"}}]}]}]} for span in spans]}
                oracle.update(trees={} if unsupported else trees, outcomes={} if unsupported else outcomes, query_trace_ids=list(trees))
                response = {} if unsupported else responses
            elif backend_type == "profiles":
                oracle["cell"] = copy.deepcopy(cpu_cell)
                native = copy.deepcopy(cpu_native)
                native[0]["payload"]["timestamp_unix_nanos"] = start
                response = {"flamegraph": {"total": 0, "levels": [], "names": []}} if unsupported else copy.deepcopy(cpu_response)
            elif backend_type == "logs":
                records = []
                for index in range(2):
                    signal = copy.deepcopy(golden["application_log_observation"])
                    signal["payload"].update(body=None, timestamp="1970-01-01T00:00:01." + f"{start - 10**9 + index:09}" + "Z", observed_at_unix_nanos=1800000000)
                    if late and index == 0:
                        signal["payload"]["timestamp"] = "1970-01-01T00:00:01.500000000Z"
                    native.append(signal)
                    # Backend fixtures represent explicitly redacted export, not current log support.
                    records.append({"labels": {"namespace": "default", "pod": "app", "stream": "stdout"}, "timestamp": str(1500000000 if late and index == 0 else start + index), "body": "[redacted]"})
                oracle.update(records=[] if unsupported else records, query={"query": '{namespace="default",pod="app"}', "start": "1000000000", "end": "2000000000", "limit": "4096"})
                response = {"status": "success", "data": {"resultType": "streams", "result": [] if unsupported else [{"stream": records[0]["labels"], "values": [[r["timestamp"], r["body"]] for r in records]}]}}
            else:
                signal = copy.deepcopy(golden["network_peer_flow_metric"])
                signal["payload"]["window"] = {"start_unix_nanos": start, "end_unix_nanos": start + 200}
                native = [signal]
                labels = {"__name__": "e_navigator_network_peer_flow_bytes", "direction": "egress", "owner_name": "shop/checkout"}
                oracle.update(series=[] if unsupported else [{"labels": labels, "value": 2048}], query={"query": 'e_navigator_network_peer_flow_bytes{owner_name="shop/checkout"}', "time": "1.8"})
                response = {"status": "success", "data": {"resultType": "vector", "result": [] if unsupported else [{"metric": labels, "value": [1.8, "2048"]}]}}
            if unsupported:
                warning_kind = {"CPU": "profiling_warning_observation", "LOG": "log_collection_warning", "TCP": "network_flow_warning"}.get(family, "request_correlation_warning")
                native = [copy.deepcopy(golden[warning_kind])]
            history = {"policy": "retained" if late and family == "LOG" else "partial", "attach_nanos": attach,
                       "retained_from_nanos": 1000000000, "expected_historical_records": int(late and family == "LOG")}
            limits = {"capture_loss": 0, "export_loss": 0, "unsupported_versions": 2 if unsupported else 0}
            scenario_identity = dict(identity, runtime="unsupported-fixture-version" if unsupported else identity["runtime"])
            if family == "CPU":
                oracle["cell"]["identity"]["runtime"] = scenario_identity["runtime"]
            scenario = {"native": copy.deepcopy(native), "backend": oracle, "workload": copy.deepcopy(actions),
                        "identity": scenario_identity, "history": history, "counter_limits": limits,
                        "counter_minimums": dict(limits), "forbidden_values": [f"private-canary-{family_index}-{scenario_index}"]}
            cell["scenarios"][name] = scenario
            capture["cells"][cell_id][name] = {"status": "executed", "identity": copy.deepcopy(scenario_identity), "seed": cell["seed"],
                "commands": [["synthetic-fixture", "--seed", str(cell["seed"]), "--scenario", name]],
                "start_nanos": 1200000000, "end_nanos": 1900000000, "workload": actions, "native": native, "counters": copy.deepcopy(limits), "backend": copy.deepcopy(response)}
    return manifest, capture


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    directory.mkdir(parents=True, exist_ok=True)
    for filename, value in zip(["manifest.json", "capture.json"], fixture()):
        (directory / filename).write_text(json.dumps(value, indent=2) + "\n")
    print(f"synthetic checker fixtures written to {directory}")
