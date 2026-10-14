#!/usr/bin/env python3
"""Synthetic backend checker example, never deployment or retention proof."""
import copy
import json
from pathlib import Path
import sys

from replacement_fixture import fixture as replacement_fixture


def fixture(namespace="WC"):
    manifest, capture = replacement_fixture(namespace)
    targets, observations, workflows = {}, {}, {}
    for family, kind in [("HTTP", "traces"), ("CPU", "profiles")]:
        cell_id = f"{namespace}-{family}-9001"
        scenario = manifest["cells"][cell_id]["scenarios"]["normal"]
        record = capture["cells"][cell_id]["normal"]
        oracle = copy.deepcopy(scenario["backend"])
        expired = copy.deepcopy(oracle)
        expired["empty"] = True
        if kind == "traces":
            expired.update(trees={}, outcomes={})
            empty = {}
        else:
            empty = {"flamegraph": {"total": 0, "levels": [], "names": []}}
        identity = {"release": "fixture-1", "image_digest": "sha256:" + "b" * 64,
                    "config_digest": "sha256:" + "c" * 64, "wire_contract": "fixture-wire"}
        data_end_ms = 1501 if kind == "traces" else 2000
        targets[kind] = {"identity": identity, "retention_ms": 10000, "expiry_grace_ms": 1000,
                         "approval": "fixture", "cells": [cell_id],
                         "queries": {"stored": {"cell": cell_id, "phase": "stored", "oracle": oracle, "data_end_ms": data_end_ms, "min_age_ms": 1000},
                                     "expired": {"cell": cell_id, "phase": "expired", "oracle": expired, "prior_oracle": copy.deepcopy(oracle), "data_end_ms": data_end_ms, "min_age_ms": 11001}}}
        observations[kind] = {"identity": copy.deepcopy(identity), "ingest": {"accepted": 1, "rejected": 0, "artifact_sha256": "d" * 64},
                              "queries": {"stored": {"observed_at_ms": 4000, "native": record["native"], "response": record["backend"]},
                                          "expired": {"observed_at_ms": 14000, "native": [], "response": empty,
                                                      "prior_stored": {"observed_at_ms": 4000, "native": copy.deepcopy(record["native"]), "response": copy.deepcopy(record["backend"])}}}}
        workflows[kind] = {"backend": kind, "query": "stored", "cell": cell_id,
                           "required": True, "dashboard_uid": "fixture", "panel_id": 1,
                           "datasource_uid": kind, "navigation": "trace" if kind == "traces" else "application-frames"}
    plan = {"schema_version": 1, "fixture": True, "target": "synthetic-local", "blocked_inputs": ["IN-03"],
            "backends": targets, "grafana": {"release": "fixture", "image_digest": "sha256:" + "a" * 64},
            "workflows": workflows, "correlation": "optional"}
    evidence = {"target": plan["target"], "backends": observations, "grafana": copy.deepcopy(plan["grafana"]),
                "workflows": {key: {"status": "executed", "definition": copy.deepcopy(value),
                                    "artifact_sha256": "e" * 64} for key, value in workflows.items()}}
    return plan, evidence


if __name__ == "__main__":
    directory = Path(sys.argv[1])
    directory.mkdir(parents=True, exist_ok=True)
    for name, value in zip(["manifest.json", "evidence.json"], fixture()):
        (directory / name).write_text(json.dumps(value, indent=2) + "\n")
