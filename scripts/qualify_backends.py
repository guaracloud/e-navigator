#!/usr/bin/env python3
"""Check pinned backend, retention and recorded Grafana workflow evidence."""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import re
import sys
import time

import qualify_replacement as suite


def text(value):
    suite.require(isinstance(value, str) and 0 < len(value) <= 256)
    suite.require(not re.search(r"(?i)(https?://|password|token|secret|credential|\n|\r)", value))


def artifact(value):
    suite.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def validate(plan):
    suite.require(plan["schema_version"] == 1 and type(plan["fixture"]) is bool)
    text(plan["target"])
    suite.require(isinstance(plan["blocked_inputs"], list) and set(plan["blocked_inputs"]) <= {f"IN-{i:02}" for i in range(1, 8)})
    # Exact execution ownership is not currently available in the profile contract.
    # Never substitute matching service/time windows for span ownership.
    suite.require(plan["correlation"] in {"optional", "excluded"})
    targets = plan["backends"]
    suite.require(isinstance(targets, dict) and {"traces", "profiles"} <= set(targets) <= {"traces", "profiles", "logs", "metrics"})
    request_count = 0
    for kind, target in targets.items():
        identity = target["identity"]
        suite.require(set(identity) == {"release", "image_digest", "config_digest", "wire_contract"})
        for value in identity.values():
            text(value)
        suite.require(all(suite.DIGEST.fullmatch(identity[key]) for key in ["image_digest", "config_digest"]))
        suite.require(suite.natural(target["retention_ms"]) > 0)
        suite.natural(target["expiry_grace_ms"])
        text(target["approval"])
        cells = target["cells"]
        suite.require(isinstance(cells, list) and 0 < len(cells) <= 64 and len(set(cells)) == len(cells))
        suite.require(all(isinstance(cell, str) and re.fullmatch(r"GW-[A-Z]+-[0-9]{4}", cell) for cell in cells))
        queries = target["queries"]
        suite.require(isinstance(queries, dict) and 2 <= len(queries) <= 64)
        suite.require({query["phase"] for query in queries.values()} == {"stored", "expired"})
        for query_id, query in queries.items():
            text(query_id)
            suite.require(query["cell"] in cells)
            suite.require(query["oracle"]["type"] == kind)
            suite.require(query["oracle"]["empty"] is (query["phase"] == "expired"))
            suite.natural(query["data_end_ms"])
            oracle = query["oracle"]
            if kind == "profiles":
                request_count += 1
                suite.cpu.validate_cells({"GW-CPU-0001": oracle["cell"]})
                suite.require(query["data_end_ms"] == suite.cpu.integer(oracle["cell"]["query"]["end"]))
            elif kind == "traces":
                ids = oracle["query_trace_ids"]
                suite.require(isinstance(ids, list) and 0 < len(ids) <= 64 and len(set(ids)) == len(ids))
                suite.require(all(suite.tempo.identity(value, 16) == value for value in ids))
                suite.require(set(oracle["trees"]) == (set() if oracle["empty"] else set(ids)))
                request_count += len(ids)
            else:
                request_count += 1
                parameters = oracle["query"]
                suite.require(set(parameters) == ({"query", "start", "end", "limit"} if kind == "logs" else {"query", "time"}))
                suite.require(all(isinstance(value, str) and 0 < len(value) <= 4096 for value in parameters.values()))
                if kind == "logs":
                    suite.require(parameters["end"].isdecimal() and parameters["start"].isdecimal())
                    suite.require(0 <= int(parameters["start"]) < int(parameters["end"]))
                    suite.require(int(parameters["end"]) == query["data_end_ms"] * 1000000)
                    suite.require(parameters["limit"].isdecimal() and 0 < int(parameters["limit"]) <= suite.MAX_RECORDS)
                else:
                    suite.require(re.fullmatch(r"[0-9]+(?:\.[0-9]{1,3})?", parameters["time"]) is not None)
                    suite.require(Decimal(parameters["time"]) * 1000 == query["data_end_ms"])
            minimum = suite.natural(query["min_age_ms"])
            suite.require(minimum > 0)
            if query["phase"] == "stored":
                suite.require(minimum < target["retention_ms"])
            else:
                suite.require(minimum > target["retention_ms"] + target["expiry_grace_ms"])
                prior = query["prior_oracle"]
                suite.require(prior["type"] == kind and prior["empty"] is False)
                if kind == "traces":
                    suite.require(prior["query_trace_ids"] == oracle["query_trace_ids"])
                    suite.require(set(prior["trees"]) == set(oracle["query_trace_ids"]))
                else:
                    suite.require(prior["cell" if kind == "profiles" else "query"] == oracle["cell" if kind == "profiles" else "query"])
        for cell in cells:
            suite.require({query["phase"] for query in queries.values() if query["cell"] == cell} == {"stored", "expired"})
    suite.require(request_count <= 2048)
    grafana = plan["grafana"]
    suite.require(set(grafana) == {"release", "image_digest"})
    text(grafana["release"])
    suite.require(suite.DIGEST.fullmatch(grafana["image_digest"]) is not None)
    workflows = plan["workflows"]
    suite.require(isinstance(workflows, dict) and 2 <= len(workflows) <= 64)
    required_navigation = set()
    for workflow_id, workflow in workflows.items():
        text(workflow_id)
        suite.require(type(workflow["required"]) is bool)
        target = targets[workflow["backend"]]
        suite.require(workflow["cell"] in target["cells"])
        suite.require(target["queries"][workflow["query"]]["phase"] == "stored")
        suite.require(target["queries"][workflow["query"]]["cell"] == workflow["cell"])
        for key in ["dashboard_uid", "datasource_uid"]:
            text(workflow[key])
        suite.require(suite.natural(workflow["panel_id"]) > 0)
        suite.require((workflow["backend"], workflow["navigation"]) in {("traces", "trace"), ("profiles", "application-frames")})
        if workflow["required"]:
            required_navigation.add(workflow["navigation"])
    suite.require(required_navigation == {"trace", "application-frames"})


def assert_query(oracle, response, native, data_end_ms):
    if oracle["type"] == "traces" and not oracle["empty"]:
        suite.require(isinstance(native, list) and 0 < len(native) <= suite.MAX_RECORDS)
        suite.require((max(suite.natural(sample["payload"]["end_unix_nanos"]) for sample in native) + 999999) // 1000000 == data_end_ms)
        wanted = {(trace_id, span["span_id"]): span for trace_id, spans in oracle["trees"].items() for span in spans}
        actual = {}
        for sample in native:
            suite.require(sample["kind"] == "request_span_observation")
            payload = sample["payload"]
            identity = (payload["trace_id"], payload["span_id"])
            suite.require(identity not in actual)
            actual[identity] = payload
        suite.require(set(actual) == set(wanted))
        for identity, span in wanted.items():
            payload = actual[identity]
            suite.require(payload["name"] == span["name"] and payload["service_name"] == span["service"])
            suite.require((payload["parent_span_id"] or "") == span["parent_span_id"])
    return suite.assert_backend(oracle, response, native)


def evaluate(plan, evidence, endpoints=None, authorization=None):
    validate(plan)
    live = endpoints is not None
    suite.require(live != plan["fixture"])
    if live:
        suite.require(not plan["blocked_inputs"] and authorization is not None)
        suite.require(authorization["approved"] is True and authorization["target"] == plan["target"])
        text(authorization["owner"])
        text(authorization["reference"])
        suite.require(set(endpoints) == set(plan["backends"]))
    suite.require(evidence["target"] == plan["target"])
    suite.require(set(evidence["backends"]) == set(plan["backends"]))
    result = {"schema_version": 1, "mode": "live-query" if live else "fixture", "verdict": "failed",
              "live_qualified": False, "replacement_qualified": False, "backends": {}, "workflows": {},
              "blocked_inputs": plan["blocked_inputs"], "correlation": plan["correlation"],
              "sha256": {"manifest": suite.digest(plan), "evidence": suite.digest(evidence)}}
    if live:
        result["sha256"]["authorization"] = suite.digest(authorization)
    for kind, target in plan["backends"].items():
        record = {"verdict": "failed", "queries": {}}
        result["backends"][kind] = record
        try:
            observation = evidence["backends"][kind]
            suite.require(observation["identity"] == target["identity"])
            ingest = observation["ingest"]
            suite.require(suite.natural(ingest["accepted"]) > 0 and suite.natural(ingest["rejected"]) == 0)
            artifact(ingest["artifact_sha256"])
            suite.require(set(observation["queries"]) == set(target["queries"]))
            for query_id, query in target["queries"].items():
                saved = observation["queries"][query_id]
                observed_at = int(time.time() * 1000) if live else suite.natural(saved["observed_at_ms"])
                age = observed_at - query["data_end_ms"]
                suite.require(age >= query["min_age_ms"])
                if query["phase"] == "stored":
                    suite.require(age < target["retention_ms"])
                else:
                    prior = saved["prior_stored"]
                    prior_age = suite.natural(prior["observed_at_ms"]) - query["data_end_ms"]
                    suite.require(0 < prior_age < target["retention_ms"])
                    suite.require(prior["observed_at_ms"] < observed_at)
                    assert_query(query["prior_oracle"], prior["response"], prior["native"], query["data_end_ms"])
                response = suite.query_backend(query["oracle"], endpoints) if live else saved["response"]
                assertions = assert_query(query["oracle"], response, saved["native"], query["data_end_ms"])
                record["queries"][query_id] = {"verdict": "passed", "phase": query["phase"],
                    "observed_at_ms": observed_at, "age_ms": age, "assertions": assertions,
                    "response_sha256": suite.digest(response)}
                if query["phase"] == "expired":
                    record["queries"][query_id]["prior_stored_sha256"] = suite.digest(saved["prior_stored"])
            record.update(verdict="passed", identity=target["identity"], ingest_artifact_sha256=ingest["artifact_sha256"])
        except (ValueError, OSError, KeyError, IndexError, TypeError, AttributeError, OverflowError):
            record["failure"] = "invalid identity, ingest, retention or stored-data evidence"
    for workflow_id, workflow in plan["workflows"].items():
        record = {"verdict": "failed" if workflow["required"] else "optional-incomplete"}
        result["workflows"][workflow_id] = record
        try:
            saved = evidence["workflows"][workflow_id]
            suite.require(evidence["grafana"] == plan["grafana"])
            suite.require(saved["status"] == "executed" and saved["definition"] == workflow)
            artifact(saved["artifact_sha256"])
            suite.require(result["backends"][workflow["backend"]]["verdict"] == "passed")
            record.update(verdict="passed", artifact_sha256=saved["artifact_sha256"],
                          definition_sha256=suite.digest(workflow))
        except (ValueError, KeyError, TypeError):
            record["failure"] = "missing or mismatched recorded Grafana execution"
    if all(record["verdict"] == "passed" for record in result["backends"].values()) and all(record["verdict"] != "failed" for record in result["workflows"].values()):
        result["verdict"] = "passed"
    # Stored queries can be performed here. Ingest, deployed identities and UI
    # execution still need review of their original artifacts, not attestations.
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["manifest", "evidence", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--endpoints", type=Path)
    parser.add_argument("--authorization", type=Path)
    args = parser.parse_args()
    result = {"schema_version": 1, "verdict": "failed", "live_qualified": False, "replacement_qualified": False}
    try:
        suite.require(bool(args.endpoints) == bool(args.authorization))
        result = evaluate(suite.load(args.manifest), suite.load(args.evidence),
                          suite.load(args.endpoints) if args.endpoints else None,
                          suite.load(args.authorization) if args.authorization else None)
    except (ValueError, OSError, KeyError, IndexError, TypeError, AttributeError, RecursionError, OverflowError):
        result["failure"] = "invalid backend manifest, evidence or authorization"
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(f"backend suite {result['verdict']}; live_qualified=false")
    return 0 if result["verdict"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
