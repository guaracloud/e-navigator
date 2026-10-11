#!/usr/bin/env python3
"""Evaluate independent replacement-cell oracles against capture and stored data."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import qualify_cpu_profiles as cpu
import qualify_propagation_tempo as tempo

FAMILIES = {"HTTP", "GRPC", "POSTGRESQL", "MYSQL", "REDIS", "MONGODB", "KAFKA", "TCP", "CPU", "LOG"}
SCENARIOS = {"normal", "concurrent", "pooling", "retry-reconnect", "process-restart", "agent-restart", "late-attachment", "privacy", "unsupported-version"}
MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 4096
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def require(condition):
    if not condition:
        raise ValueError("invalid evidence or unmet assertion")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def read_json(stream):
    raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False))


def load(path):
    with path.open("rb") as stream:
        return read_json(stream)


def subset(wanted, actual):
    if isinstance(wanted, dict):
        require(isinstance(actual, dict))
        for key, value in wanted.items():
            subset(value, actual[key])
    elif isinstance(wanted, list):
        require(isinstance(actual, list) and len(wanted) == len(actual))
        for left, right in zip(wanted, actual):
            subset(left, right)
    else:
        require(type(wanted) is type(actual) and wanted == actual)


def natural(value):
    require(type(value) is int and 0 <= value <= (1 << 63) - 1)
    return value


def validate_identity(identity):
    for name in ["workload_image", "collector_image", "config"]:
        require(isinstance(identity[name], str) and DIGEST.fullmatch(identity[name]) is not None)
    for name in ["runtime", "runtime_version", "build", "client", "server", "tls", "architecture", "io_path"]:
        require(isinstance(identity[name], str) and 0 < len(identity[name]) <= 256)
        require(not re.search(r"(?i)(https?://|password|token|secret|credential|\n|\r)", identity[name]))


def validate(manifest):
    require(manifest["schema_version"] == 1 and type(manifest["fixture"]) is bool)
    environment = manifest["environment"]
    require(set(environment) == {"target", "kernel", "architecture", "cgroup", "collector_commit", "backends"})
    for key in set(environment) - {"backends"}:
        require(isinstance(environment[key], str) and 0 < len(environment[key]) <= 256)
        require(not re.search(r"(?i)(https?://|password|token|secret|credential|\n|\r)", environment[key]))
    require(re.fullmatch(r"[0-9a-f]{40}", environment["collector_commit"]) is not None)
    require(set(environment["backends"]) == {"traces", "profiles", "metrics", "logs"})
    require(all(DIGEST.fullmatch(value) is not None for value in environment["backends"].values()))
    require(isinstance(manifest["blocked_inputs"], list) and set(manifest["blocked_inputs"]) <= {f"IN-{i:02}" for i in range(1, 8)})
    cells = manifest["cells"]
    require(isinstance(cells, dict) and 0 < len(cells) <= 64)
    families = set()
    query_count = 0
    for cell_id, cell in cells.items():
        require(re.fullmatch(r"GW-([A-Z]+)-[0-9]{4}", cell_id) is not None)
        family = cell_id.split("-")[1]
        require(family in FAMILIES and cell["requiredness"] in {"required", "optional", "excluded"})
        require(cell["support"] in {"implemented", "unsupported", "unknown"})
        families.add(family)
        if cell["requiredness"] == "excluded":
            require(bool(cell["exclusion"]) and bool(cell["approval"]))
            continue
        identity = cell["identity"]
        validate_identity(identity)
        require(type(cell["seed"]) is int and 0 <= cell["seed"] < 2**32)
        require(set(cell["scenarios"]) == SCENARIOS)
        used_trace_ids = set()
        for name, scenario in cell["scenarios"].items():
            validate_identity(scenario["identity"])
            require(all(scenario["identity"][key] == identity[key] for key in ["collector_image", "config", "architecture"]))
            assert_workload(name, scenario["workload"], scenario["history"])
            native = scenario["native"]
            require(isinstance(native, list) and 0 < len(native) <= MAX_RECORDS)
            for signal in native:
                require(signal["schema_version"] == 1 and bool(signal["kind"]) and bool(signal["source"]))
            require(scenario["backend"]["type"] == {"CPU": "profiles", "LOG": "logs", "TCP": "metrics"}.get(family, "traces"))
            backend = scenario["backend"]
            require(type(backend["empty"]) is bool and backend["empty"] == (name == "unsupported-version"))
            if backend["type"] == "traces":
                ids = backend["query_trace_ids"]
                require(isinstance(ids, list) and 0 < len(ids) <= tempo.MAX_TRACES and len(set(ids)) == len(ids))
                require(all(tempo.identity(trace_id, 16) == trace_id for trace_id in ids))
                require(not used_trace_ids.intersection(ids))
                used_trace_ids.update(ids)
                query_count += len(ids)
                if not backend["empty"]:
                    require(set(ids) == set(backend["trees"]))
                    span_ids = set()
                    for spans in backend["trees"].values():
                        indexed = tempo.span_index(spans)
                        require(not span_ids.intersection(indexed))
                        span_ids.update(indexed)
                    require(set(backend["outcomes"]) == span_ids)
                    for outcome in backend["outcomes"].values():
                        require(set(outcome) == {"status", "error_type"} and type(outcome["status"]) is int and outcome["status"] in {0, 1, 2})
                        require(outcome["error_type"] is None or isinstance(outcome["error_type"], str))
                    native_spans = {}
                    for signal in native:
                        require(signal["kind"] == "request_span_observation")
                        payload = signal["payload"]
                        span_id = payload["span_id"]
                        require(span_id not in native_spans)
                        native_spans[span_id] = payload
                    require(set(native_spans) == span_ids)
                    for trace_id, spans in backend["trees"].items():
                        for span in spans:
                            payload = native_spans[span["span_id"]]
                            require(payload["trace_id"] == trace_id and (payload["parent_span_id"] or "") == span["parent_span_id"])
                            require(payload["name"] == span["name"] and payload["service_name"] == span["service"])
                else:
                    require(backend["trees"] == {} and backend["outcomes"] == {})
            elif backend["type"] == "profiles":
                query_count += 1
                cpu.validate_cells({"GW-CPU-0001": backend["cell"]})
                profile_identity = backend["cell"]["identity"]
                require(all(profile_identity[key] == scenario["identity"][value] for key, value in {
                    "runtime": "runtime", "version": "runtime_version", "build_id": "build",
                    "architecture": "architecture", "image_digest": "workload_image"}.items()))
            else:
                query_count += 1
                query = backend["query"]
                require(set(query) == ({"query", "start", "end", "limit"} if family == "LOG" else {"query", "time"}))
                require(all(isinstance(value, str) and 0 < len(value) <= 4096 for value in query.values()))
                if family == "LOG":
                    require(query["start"].isdecimal() and query["end"].isdecimal() and int(query["start"]) < int(query["end"]))
                    require(query["limit"].isdecimal() and 0 < int(query["limit"]) <= MAX_RECORDS)
            require(isinstance(scenario["counter_limits"], dict) and bool(scenario["counter_limits"]))
            for key, value in scenario["counter_limits"].items():
                require(re.fullmatch(r"[a-z][a-z0-9_]{0,127}", key) is not None)
                natural(value)
            require(set(scenario["counter_minimums"]) == set(scenario["counter_limits"]))
            for key, minimum in scenario["counter_minimums"].items():
                require(natural(minimum) <= scenario["counter_limits"][key])
            if name == "unsupported-version":
                require(scenario["counter_minimums"]["unsupported_versions"] > 0)
            forbidden = scenario["forbidden_values"]
            require(isinstance(forbidden, list) and 0 < len(forbidden) <= 64)
            require(all(isinstance(value, str) and 8 <= len(value) <= 256 for value in forbidden))
            history = scenario["history"]
            require(history["policy"] in {"partial", "retained"})
            natural(history["attach_nanos"])
            natural(history["retained_from_nanos"])
            require(history["retained_from_nanos"] <= history["attach_nanos"])
            if history["policy"] == "retained":
                require(family == "LOG")
            if name == "unsupported-version":
                require(all("warning" in signal["kind"] for signal in native))
                require(scenario["backend"]["empty"] is True)
            else:
                kind = {"CPU": "profile_sample_observation", "LOG": "application_log_observation", "TCP": "network_peer_flow_metric"}.get(family, "request_span_observation")
                require(all(signal["kind"] == kind for signal in native))
                if family not in {"CPU", "LOG"}:
                    protocol = {"POSTGRESQL": "postgres"}.get(family, family.lower())
                    require(all(signal["payload"]["protocol"] == protocol for signal in native))
    # Inventory coverage is independent of observed telemetry and cannot shrink.
    require(families == FAMILIES)
    require(any(cell["requiredness"] == "required" for cell in cells.values()))
    require(query_count <= 2048)


def assert_workload(name, actions, history):
    require(isinstance(actions, list) and 2 <= len(actions) <= MAX_RECORDS)
    identities = set()
    for action in actions:
        require(set(action) == {"operation", "connection", "process_generation", "agent_generation", "attempt", "start_nanos", "end_nanos", "outcome"})
        require(action["outcome"] in {"success", "failure", "unsupported"})
        for key in set(action) - {"outcome"}:
            natural(action[key])
        require(action["start_nanos"] < action["end_nanos"])
        identity = (action["operation"], action["attempt"])
        require(identity not in identities)
        identities.add(identity)
    if name == "concurrent":
        ordered = sorted(actions, key=lambda a: a["start_nanos"])
        require(any(a["end_nanos"] > b["start_nanos"] for a, b in zip(ordered, ordered[1:])))
    if name == "pooling":
        require(len({a["connection"] for a in actions}) < len({a["operation"] for a in actions}))
    if name == "retry-reconnect":
        require(len({a["operation"] for a in actions}) < len(actions))
        require(len({a["connection"] for a in actions}) > 1)
        require({a["outcome"] for a in actions} >= {"success", "failure"})
    if name in {"process-restart", "agent-restart"}:
        key = "process_generation" if name == "process-restart" else "agent_generation"
        require(len({a[key] for a in actions}) > 1)
    if name == "late-attachment":
        require(any(a["start_nanos"] < history["attach_nanos"] for a in actions))
        require(any(a["start_nanos"] >= history["attach_nanos"] for a in actions))
    if name == "unsupported-version":
        require(all(a["outcome"] == "unsupported" for a in actions))


def event_nanos(signal):
    payload = signal["payload"]
    if signal["kind"] == "application_log_observation":
        timestamp = payload["timestamp"]
        match = re.fullmatch(r"(.{19})(?:\.([0-9]{1,9}))?Z", timestamp)
        require(match is not None)
        seconds = int(datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
        return seconds * 10**9 + int((match[2] or "").ljust(9, "0"))
    if "window" in payload:
        return natural(payload["window"]["start_unix_nanos"])
    return natural(payload.get("start_unix_nanos", payload.get("timestamp_unix_nanos")))


def assert_history(scenario, signals):
    history = scenario["history"]
    historical = 0
    for signal in signals:
        if "warning" in signal["kind"]:
            continue
        timestamp = event_nanos(signal)
        if timestamp < history["attach_nanos"]:
            require(history["policy"] == "retained" and timestamp >= history["retained_from_nanos"])
            require(signal["kind"] == "application_log_observation")
            require(natural(signal["payload"]["observed_at_unix_nanos"]) >= history["attach_nanos"])
            historical += 1
    require(historical == natural(history["expected_historical_records"]))
    return {"policy": history["policy"], "historical_records": historical,
            "observation": "retained-file-replay" if history["policy"] == "retained" else "attachment-forward-only"}


def assert_backend(oracle, response, native):
    kind = oracle["type"]
    if kind == "traces":
        trees = oracle["trees"]
        if oracle["empty"]:
            require(not trees and response == {})
            return {"trace_count": 0}
        tempo.assert_trees(trees, response)
        spans = {}
        for trace_id, document in response.items():
            for batch in document.get("batches", document.get("resourceSpans", [])):
                for scope in batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", [])):
                    for span in scope.get("spans", []):
                        span_id = tempo.identity(span["spanId"], 8)
                        errors = [a["value"].get("stringValue") for a in span.get("attributes", []) if a.get("key") == "error.type"]
                        require(len(errors) <= 1)
                        status = span.get("status", {}).get("code", 0)
                        status = {"STATUS_CODE_UNSET": 0, "STATUS_CODE_OK": 1, "STATUS_CODE_ERROR": 2}.get(status, status)
                        require(type(status) is int and status in {0, 1, 2})
                        spans[span_id] = {"status": status, "error_type": errors[0] if errors else None}
        require(spans == oracle["outcomes"])
        return {"trace_count": len(trees), "span_count": len(spans)}
    if kind == "profiles":
        if oracle["empty"]:
            graph = response["flamegraph"]
            require(cpu.integer(graph["total"]) == 0 and graph["levels"] == [] and graph["names"] == [])
            return {"total_weight_nanos": 0}
        cell = oracle["cell"]
        return cpu.qualify({"GW-CPU-0001": cell}, {"GW-CPU-0001": {"identity": cell["identity"], "samples": native}}, {"GW-CPU-0001": response})["GW-CPU-0001"]
    require(response["status"] == "success")
    data = response["data"]
    if kind == "logs":
        require(data["resultType"] == "streams")
        records = []
        for stream in data["result"]:
            for timestamp, body in stream["values"]:
                require(isinstance(timestamp, str) and timestamp.isdecimal() and isinstance(body, str))
                records.append({"labels": stream["stream"], "timestamp": timestamp, "body": body})
        require(len(records) <= MAX_RECORDS)
        require(sorted(records, key=digest) == sorted(oracle["records"], key=digest))
        require(bool(records) != oracle["empty"])
        return {"stored_records": len(records)}
    require(kind == "metrics" and data["resultType"] == "vector")
    series = {}
    for row in data["result"]:
        labels = json.dumps(row["metric"], sort_keys=True)
        require(labels not in series)
        value = float(row["value"][1])
        require(math.isfinite(value))
        series[labels] = value
    wanted = {json.dumps(row["labels"], sort_keys=True): row["value"] for row in oracle["series"]}
    require(len(wanted) == len(oracle["series"]) and series == wanted and bool(series) != oracle["empty"])
    return {"stored_series": len(series)}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("backend redirects are not qualification evidence")


def query_backend(oracle, endpoints):
    kind = oracle["type"]
    base = endpoints[kind]
    url = urlsplit(base)
    require(url.scheme in {"http", "https"} and bool(url.hostname) and not any([url.username, url.password, url.query, url.fragment]))
    opener = build_opener(NoRedirect())
    def fetch(path, data=None):
        request = Request(base.rstrip("/") + path, data=data, headers={"Accept": "application/json", "Content-Type": "application/json"})
        with opener.open(request, timeout=30) as stream:
            return read_json(stream)
    if kind == "traces":
        # Empty negative controls still query independently allocated trace IDs.
        traces = {}
        for trace_id in oracle["query_trace_ids"]:
            require(tempo.identity(trace_id, 16) == trace_id)
            try:
                traces[trace_id] = fetch("/api/traces/" + trace_id)
            except OSError as error:
                if oracle["empty"] and getattr(error, "code", None) == 404:
                    continue
                raise
        return traces
    if kind == "profiles":
        return fetch("/querier.v1.QuerierService/SelectMergeStacktraces", json.dumps(dict(oracle["cell"]["query"], maxNodes=cpu.MAX_NODES)).encode())
    path = "/loki/api/v1/query_range" if kind == "logs" else "/api/v1/query"
    return fetch(path + "?" + urlencode(oracle["query"]))


def evaluate(manifest, capture, endpoints=None, authorization=None):
    validate(manifest)
    result = {"schema_version": 1, "mode": "live-query" if endpoints is not None else "fixture",
              "verdict": "failed", "replacement_qualified": False, "cells": {},
              "sha256": {"manifest": digest(manifest), "capture": digest(capture)}}
    live = endpoints is not None
    require(live != manifest["fixture"])
    if live:
        require(authorization is not None and authorization["approved"] is True)
        require(authorization["target"] == manifest["environment"]["target"])
        require(not manifest["blocked_inputs"])
        require(bool(authorization["owner"]) and bool(authorization["reference"]))
        require(set(endpoints) == {"traces", "profiles", "logs", "metrics"})
        result["sha256"]["authorization"] = digest(authorization)
    require(capture["environment"] == manifest["environment"])
    result["blocked_inputs"] = manifest["blocked_inputs"]
    result["environment"] = manifest["environment"]
    require(set(capture["cells"]) <= set(manifest["cells"]))
    for cell_id, scenarios in capture["cells"].items():
        if manifest["cells"][cell_id]["requiredness"] != "excluded":
            require(set(scenarios) <= SCENARIOS)
    for cell_id, cell in manifest["cells"].items():
        verdicts = {}
        result["cells"][cell_id] = {"requiredness": cell["requiredness"], "scenarios": verdicts}
        if cell["requiredness"] == "excluded":
            result["cells"][cell_id]["verdict"] = "excluded"
            continue
        result["cells"][cell_id].update(identity={key: cell["identity"][key] for key in ["workload_image", "collector_image", "config"]}, seed=cell["seed"])
        for name, scenario in cell["scenarios"].items():
            record = {"verdict": "failed"}
            verdicts[name] = record
            try:
                evidence = capture["cells"][cell_id][name]
                record["sha256"] = {"evidence": digest(evidence), "scenario_identity": digest(scenario["identity"])}
                if evidence["status"] == "skipped":
                    require(bool(evidence["reason"]))
                    record["verdict"] = "skipped"
                    record["reason_sha256"] = digest(evidence["reason"])
                    continue
                require(evidence["status"] == "executed" and evidence["identity"] == scenario["identity"] and evidence["seed"] == cell["seed"])
                if live:
                    require(cell["support"] == "implemented" and bool(cell["approval"]))
                subset(scenario["workload"], evidence["workload"])
                commands = evidence["commands"]
                require(isinstance(commands, list) and 0 < len(commands) <= 32)
                require(all(isinstance(argv, list) and argv and all(isinstance(arg, str) and 0 < len(arg) <= 1024 for arg in argv) for argv in commands))
                # Commands must be sanitized before import; do not persist URLs or access values.
                require(not re.search(r"(?i)(https?://|password|token|secret|credential|authorization|\n|\r)", json.dumps(commands)))
                natural(evidence["start_nanos"])
                require(evidence["start_nanos"] < natural(evidence["end_nanos"]))
                require(all(evidence["start_nanos"] <= action["start_nanos"] < action["end_nanos"] <= evidence["end_nanos"] for action in evidence["workload"]))
                native = evidence["native"]
                require(isinstance(native, list) and len(native) <= MAX_RECORDS)
                subset(scenario["native"], native)
                history = assert_history(scenario, native)
                counters = evidence["counters"]
                require(set(counters) == set(scenario["counter_limits"]))
                require(all(type(value) is int and 0 <= value <= (1 << 63) - 1 for value in counters.values()))
                record["counters"] = counters
                for counter, limit in scenario["counter_limits"].items():
                    require(scenario["counter_minimums"][counter] <= natural(counters[counter]) <= limit)
                backend = query_backend(scenario["backend"], endpoints) if live else evidence["backend"]
                raw = json.dumps([native, backend], sort_keys=True)
                require(not any(value in raw for value in scenario["forbidden_values"]))
                assertions = assert_backend(scenario["backend"], backend, native)
                record.update(verdict="passed", history=history, counters=counters, backend_assertions=assertions,
                              commands=commands, start_nanos=evidence["start_nanos"], end_nanos=evidence["end_nanos"],
                              sha256=dict(record["sha256"], backend_response=digest(backend)))
            except (ValueError, OSError, KeyError, TypeError, AttributeError, OverflowError):
                record["failure"] = "missing, invalid or mismatched per-cell evidence"
        required = cell["requiredness"] == "required"
        passed = all(value["verdict"] == "passed" for value in verdicts.values())
        result["cells"][cell_id]["verdict"] = "passed" if passed else "failed" if required else "optional-incomplete"
    if all(cell["verdict"] != "failed" for cell in result["cells"].values()):
        result["verdict"] = "passed"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--endpoints", type=Path, help="live read-only backend base URLs by type")
    parser.add_argument("--authorization", type=Path, help="approved target, owner and reference; required in live mode")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"schema_version": 1, "verdict": "failed", "replacement_qualified": False}
    try:
        require(bool(args.endpoints) == bool(args.authorization))
        result = evaluate(load(args.manifest), load(args.capture), load(args.endpoints) if args.endpoints else None,
                          load(args.authorization) if args.authorization else None)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        result["failure"] = "invalid manifest, capture or live authorization"
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(f"replacement suite {result['verdict']}; replacement_qualified=false")
    return 0 if result["verdict"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
