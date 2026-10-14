#!/usr/bin/env python3
"""A synthetic complete campaign. Values and commands are not Guara requirements."""
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import qualify_backends as backend
import qualify_replacement as suite
from backend_fixture import fixture as backend_fixture
from protocol_qualification_test import protocol_fixture
from replacement_fixture import fixture as replacement_fixture


def write_artifact(root, name, value):
    raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}


def fixture(root):
    root.mkdir(parents=True, exist_ok=True)
    manifest, capture = replacement_fixture()
    protocol, protocol_capture = protocol_fixture()
    backend_plan, backend_evidence = backend_fixture()
    # Expand the existing backend fixture to every cell and all four families.
    for cell_id, cell in manifest["cells"].items():
        kind = cell["scenarios"]["normal"]["backend"]["type"]
        oracle = copy.deepcopy(cell["scenarios"]["normal"]["backend"])
        native = copy.deepcopy(capture["cells"][cell_id]["normal"]["native"])
        response = copy.deepcopy(capture["cells"][cell_id]["normal"]["backend"])
        if kind not in backend_plan["backends"]:
            template = backend_plan["backends"]["traces"]
            backend_plan["backends"][kind] = dict(copy.deepcopy(template), cells=[], queries={})
            backend_evidence["backends"][kind] = dict(copy.deepcopy(backend_evidence["backends"]["traces"]), queries={})
        target = backend_plan["backends"][kind]
        observed = backend_evidence["backends"][kind]
        if cell_id not in target["cells"]:
            target["cells"].append(cell_id)
        expired = copy.deepcopy(oracle)
        expired["empty"] = True
        if kind == "traces":
            expired.update(trees={}, outcomes={})
            empty, end = {}, (max(signal["payload"]["end_unix_nanos"] for signal in native) + 999999) // 1000000
        elif kind == "profiles":
            empty, end = {"flamegraph": {"total": 0, "levels": [], "names": []}}, 2000
        else:
            expired["records" if kind == "logs" else "series"] = []
            empty = {"status": "success", "data": {"resultType": "streams" if kind == "logs" else "vector", "result": []}}
            end = int(oracle["query"]["end"]) // 1000000 if kind == "logs" else int(float(oracle["query"]["time"]) * 1000)
        for phase in ["stored", "expired"]:
            query_id = f"{cell_id}-{phase}"
            target["queries"][query_id] = {"cell": cell_id, "phase": phase,
                "oracle": oracle if phase == "stored" else expired, "data_end_ms": end,
                "min_age_ms": 1000 if phase == "stored" else 11001}
            observed["queries"][query_id] = {"observed_at_ms": end + (1000 if phase == "stored" else 12000),
                "native": native if phase == "stored" else [], "response": response if phase == "stored" else empty}
            if phase == "expired":
                target["queries"][query_id]["prior_oracle"] = copy.deepcopy(oracle)
                observed["queries"][query_id]["prior_stored"] = {"observed_at_ms": end + 1000,
                    "native": copy.deepcopy(native), "response": copy.deepcopy(response)}
    environment = copy.deepcopy(manifest["environment"])
    reference = {name: "sha256:" + "a" * 64 for name in ["beyla", "alloy", "logs", "config"]}
    approval = {"owner": "fixture-owner", "reference": "fixture-approval", "rationale": "checker example"}
    limits = {
        "coverage_ratio": ["TH-COVERAGE", "ratio", "min", 1],
        "overcount_ratio": ["TH-COVERAGE", "ratio", "max", 0],
        "loss_ratio": ["TH-LOSS", "ratio", "max", 0],
        "duplicate_ratio": ["TH-LOSS", "ratio", "max", 0],
        "collector_cpu_cores": ["TH-OVERHEAD", "cores", "max", 1],
        "collector_rss_bytes": ["TH-OVERHEAD", "bytes", "max", 10000000],
        "node_cpu_delta_cores": ["TH-OVERHEAD", "cores", "max", 1],
        "node_rss_delta_bytes": ["TH-OVERHEAD", "bytes", "max", 10000000],
        "throughput_ratio": ["TH-OVERHEAD", "ratio", "min", 0.95],
        "p50_delta_ms": ["TH-LATENCY", "ms", "max", 1],
        "p95_delta_ms": ["TH-LATENCY", "ms", "max", 1],
        "p99_delta_ms": ["TH-LATENCY", "ms", "max", 1],
        "recovery_seconds": ["TH-OUTAGE", "seconds", "max", 10],
        "retention_seconds": ["TH-RETENTION", "seconds", "min", 1],
        "attribution_age_seconds": ["TH-COVERAGE", "seconds", "max", 1],
    }
    plan = {"schema_version": 1, "fixture": True, "contract_revision": "fixture-1", "environment": environment, "reference": reference,
            "inputs": {}, "cells": {}, "consumers": {}, "publication": {}}
    evidence = {"suites": {}, "trials": {}, "consumers": {}, "records": {}}
    record_index = 0
    def record(value, canonical=True):
        nonlocal record_index
        ref = write_artifact(root, f"record-{record_index}.json", value)
        record_index += 1
        digest = suite.digest(value) if canonical else ref["sha256"]
        evidence["records"][digest] = ref
        return digest
    for observed in [capture, protocol_capture]:
        for scenarios in observed["cells"].values():
            for run in scenarios.values():
                for field in ["backend", "metrics"]:
                    if field in run:
                        record(run[field])
    for observed in backend_evidence["backends"].values():
        observed["ingest"]["artifact_sha256"] = record({"synthetic": "ingest"}, False)
        for query in observed["queries"].values():
            record(query["response"])
            if "prior_stored" in query:
                record(query["prior_stored"])
    for workflow in backend_evidence["workflows"].values():
        workflow["artifact_sha256"] = record({"synthetic": "Grafana recording"}, False)
    quality_log = write_artifact(root, "quality-log.json", {"synthetic": "quality output"})
    evidence["quality"] = write_artifact(root, "quality.json", {"collector_commit": environment["collector_commit"],
        "command": ["scripts/quality.sh"], "exit_code": 0, "skips": {}, "log": quality_log})
    for key in [f"IN-{i:02}" for i in range(1, 8)]:
        plan["inputs"][key] = dict(approval, artifact=write_artifact(root, key + ".json", {"synthetic": key}))
    for key in ["runbook", "ledger", "public_contract"]:
        plan["publication"][key] = write_artifact(root, key + ".json", {"contract_revision": plan["contract_revision"],
            "cells": {key: "required" for key in manifest["cells"]}})
    for name, definition, observed, result in [
        ("replacement", manifest, capture, suite.evaluate(manifest, capture)),
        ("protocol", protocol, protocol_capture, suite.evaluate(protocol, protocol_capture)),
        ("backends", backend_plan, backend_evidence, backend.evaluate(backend_plan, backend_evidence)),
    ]:
        assert result["verdict"] == "passed", name
        evidence["suites"][name] = {key: write_artifact(root, name + "-" + key + ".json", value)
            for key, value in [("manifest", definition), ("evidence", observed), ("result", result)]}
    for cell_id, cell in manifest["cells"].items():
        thresholds = copy.deepcopy(limits)
        if cell_id.startswith("GW-CPU-"):
            thresholds["unknown_stack_ratio"] = ["TH-STACK", "ratio", "max", 0.1]
        plan["cells"][cell_id] = {"requiredness": "required", "identity": copy.deepcopy(cell["identity"]),
            "approval": copy.deepcopy(approval), "settings": {"placement": "fixture-node", "offered_rate": 100,
                "sample_period_nanos": 1000000, "load_digest": "sha256:" + "c" * 64},
            "thresholds": {metric: dict(approval, category=values[0], unit=values[1], comparator=values[2], value=values[3])
                           for metric, values in thresholds.items()},
            "scenarios": {name: {"min_duration_seconds": 60, "repetitions": 3 if name in {"normal", "sustained-load"} else 1}
                for name in ["normal", "sustained-load", "churn", "saturation", "outage-recovery", "rollback"]}}
        trials = {}
        for name, settings in plan["cells"][cell_id]["scenarios"].items():
            trials[name] = []
            for repetition in range(settings["repetitions"]):
                arms = {}
                for index, arm in enumerate(["no-agent", "reference", "candidate"]):
                    metrics = {"expected": 100, "observed": 0 if arm == "no-agent" else 100, "lost": 0, "duplicates": 0,
                        "collector_cpu_cores": 0 if arm == "no-agent" else 0.1,
                        "collector_rss_bytes": 0 if arm == "no-agent" else 1000000, "node_cpu_cores": 1,
                        "node_rss_bytes": 10000000, "throughput_per_second": 100,
                        "p50_ms": 1, "p95_ms": 2, "p99_ms": 3, "recovery_seconds": 1,
                        "retention_seconds": 10, "attribution_age_seconds": 0.1,
                        "unknown_weight": 0, "total_weight": 0 if arm == "no-agent" else 100}
                    start = 1000000000 + (repetition * 3 + index) * 61000000000
                    arms[arm] = {"status": "executed", "environment": environment, "cell": cell_id,
                        "identity": {} if arm == "no-agent" else reference if arm == "reference" else cell["identity"],
                        "settings": copy.deepcopy(plan["cells"][cell_id]["settings"]), "seed": repetition,
                        "commands": [["fixture-only", name, arm]], "start_nanos": start,
                        "end_nanos": start + 60000000000, "metrics": metrics}
                if name == "rollback":
                    arms["candidate"].update(restored=reference,
                        delivery={"pending_before": 100, "delivered": 100, "pending_after": 0, "lost": 0})
                trials[name].append(arms)
        evidence["trials"][cell_id] = write_artifact(root, cell_id + "-trials.json", trials)
        query_id = f"GQ-{len(plan['consumers']) + 1:04}"
        query = {"cells": [cell_id], "original": "fixture_vendor_query", "native": "fixture_native_query",
                 "expected": {"count": 100}, "approval": copy.deepcopy(approval)}
        plan["consumers"][query_id] = query
        evidence["consumers"][query_id] = write_artifact(root, query_id + ".json",
            {"status": "executed", "environment": environment, "query": query["native"], "response": query["expected"]})
    return plan, evidence


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    plan, evidence = fixture(directory)
    for name, value in [("plan.json", plan), ("evidence.json", evidence)]:
        (directory / name).write_text(json.dumps(value, indent=2) + "\n")
