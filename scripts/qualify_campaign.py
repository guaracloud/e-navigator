#!/usr/bin/env python3
"""Check a collector replacement campaign without deploying or promoting it."""
import argparse
import copy
import hashlib
import io
import json
import math
from pathlib import Path
import re
import statistics
import sys

import qualify_backends as backend
import qualify_replacement as suite

SCENARIOS = {"normal", "sustained-load", "churn", "saturation", "outage-recovery", "rollback"}
ARMS = {"no-agent", "reference", "candidate"}
# Fixed units and direction prevent an approval from changing a metric's meaning.
METRICS = {
    "coverage_ratio": ("TH-COVERAGE", "ratio", "min"),
    "overcount_ratio": ("TH-COVERAGE", "ratio", "max"),
    "loss_ratio": ("TH-LOSS", "ratio", "max"),
    "duplicate_ratio": ("TH-LOSS", "ratio", "max"),
    "collector_cpu_cores": ("TH-OVERHEAD", "cores", "max"),
    "collector_rss_bytes": ("TH-OVERHEAD", "bytes", "max"),
    "node_cpu_delta_cores": ("TH-OVERHEAD", "cores", "max"),
    "node_rss_delta_bytes": ("TH-OVERHEAD", "bytes", "max"),
    "throughput_ratio": ("TH-OVERHEAD", "ratio", "min"),
    "p50_delta_ms": ("TH-LATENCY", "ms", "max"),
    "p95_delta_ms": ("TH-LATENCY", "ms", "max"),
    "p99_delta_ms": ("TH-LATENCY", "ms", "max"),
    "recovery_seconds": ("TH-OUTAGE", "seconds", "max"),
    "retention_seconds": ("TH-RETENTION", "seconds", "min"),
    "attribution_age_seconds": ("TH-COVERAGE", "seconds", "max"),
    "unknown_stack_ratio": ("TH-STACK", "ratio", "max"),
}
ERRORS = (ValueError, OSError, KeyError, IndexError, TypeError, AttributeError, RecursionError, OverflowError)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def approval(value):
    for field in ["owner", "reference", "rationale"]:
        backend.text(value[field])


def number(value):
    require(type(value) in {int, float} and math.isfinite(value) and value >= 0, "invalid numeric measurement")
    return value


def passes(value, threshold):
    return value >= threshold["value"] if threshold["comparator"] == "min" else value <= threshold["value"]


def measures(actual, baseline, cpu):
    for value in actual.values():
        number(value)
    for name in ["expected", "observed", "lost", "duplicates", "unknown_weight", "total_weight"]:
        suite.natural(actual[name])
    require(actual["expected"] > 0 and baseline["throughput_per_second"] > 0, "empty independent oracle")
    require(actual["p50_ms"] <= actual["p95_ms"] <= actual["p99_ms"], "invalid latency quantiles")
    values = {key: actual[key] for key in ["collector_cpu_cores", "collector_rss_bytes", "recovery_seconds",
                                          "retention_seconds", "attribution_age_seconds"]}
    values.update(coverage_ratio=actual["observed"] / actual["expected"],
                  overcount_ratio=max(0, actual["observed"] - actual["expected"]) / actual["expected"],
                  loss_ratio=actual["lost"] / actual["expected"], duplicate_ratio=actual["duplicates"] / actual["expected"],
                  node_cpu_delta_cores=actual["node_cpu_cores"] - baseline["node_cpu_cores"],
                  node_rss_delta_bytes=actual["node_rss_bytes"] - baseline["node_rss_bytes"],
                  throughput_ratio=actual["throughput_per_second"] / baseline["throughput_per_second"])
    for quantile in ["p50", "p95", "p99"]:
        values[quantile + "_delta_ms"] = actual[quantile + "_ms"] - baseline[quantile + "_ms"]
    if cpu:
        require(0 <= actual["unknown_weight"] <= actual["total_weight"] and actual["total_weight"] > 0,
                "invalid stack weight")
        values["unknown_stack_ratio"] = actual["unknown_weight"] / actual["total_weight"]
    require(all(math.isfinite(value) for value in values.values()), "nonfinite derived measurement")
    return values


def check_suites(plan, evidence, read):
    required = {key for key, cell in plan["cells"].items() if cell["requiredness"] == "required"}
    require(isinstance(evidence["records"], dict) and len(evidence["records"]) <= 4096, "invalid recording inventory")
    def recording(digest, canonical=True):
        backend.artifact(digest)
        ref = evidence["records"][digest]
        if canonical:
            value = read(ref)
            require(suite.digest(value) == digest, "recorded response differs from suite assertion")
            return value
        else:
            read(ref, False)
            require(ref["sha256"] == digest, "execution recording digest mismatch")
    for name in ["replacement", "protocol", "backends"]:
        refs = evidence["suites"][name]
        manifest, capture, report = [read(refs[key]) for key in ["manifest", "evidence", "result"]]
        replay_manifest, replay_capture = copy.deepcopy(manifest), copy.deepcopy(capture)
        # Reuse the original validators with preserved query responses. This is
        # offline replay, not a new live request or a promotion of fixture mode.
        replay_manifest["fixture"] = True
        require(report["schema_version"] == 1 and report["verdict"] == "passed", "capability suite failed")
        require(manifest["fixture"] is plan["fixture"] and report["mode"] == ("fixture" if plan["fixture"] else "live-query"),
                "fixture cannot satisfy recorded execution")
        require(report["sha256"]["manifest"] == suite.digest(manifest), "suite manifest digest mismatch")
        require(report["sha256"]["evidence" if name == "backends" else "capture"] == suite.digest(capture),
                "suite evidence digest mismatch")
        if not plan["fixture"]:
            require(not manifest["blocked_inputs"] and not report["blocked_inputs"], "unresolved deployment inputs")
            authorization = read(refs["authorization"])
            require(authorization == read(plan["authorization"]), "suite authorization differs from campaign")
            require(report["sha256"]["authorization"] == suite.digest(authorization), "authorization digest mismatch")
        if name == "backends":
            backend.validate(manifest)
            require(manifest["target"] == plan["environment"]["target"], "backend target mismatch")
            needed = {{"CPU": "profiles", "LOG": "logs", "TCP": "metrics"}.get(key.split("-")[1], "traces") for key in required}
            require(set(manifest["backends"]) == set(report["backends"]) and needed <= set(manifest["backends"]),
                    "missing backend family")
            for kind, target in manifest["backends"].items():
                result = report["backends"][kind]
                require(result["verdict"] == "passed" and result["identity"] == target["identity"], "backend identity or verdict mismatch")
                require(target["identity"]["image_digest"] == plan["environment"]["backends"][kind], "backend image mismatch")
                require(set(result["queries"]) == set(target["queries"]), "missing retention query")
                for query_id, query in target["queries"].items():
                    require(result["queries"][query_id]["verdict"] == "passed" and result["queries"][query_id]["phase"] == query["phase"],
                            "stored or expiry query failed")
                    replay = replay_capture["backends"][kind]["queries"][query_id]
                    replay["response"] = recording(result["queries"][query_id]["response_sha256"])
                    replay["observed_at_ms"] = result["queries"][query_id]["observed_at_ms"]
                    if query["phase"] == "expired":
                        replay["prior_stored"] = recording(result["queries"][query_id]["prior_stored_sha256"])
                recording(result["ingest_artifact_sha256"], False)
            require(set(report["workflows"]) == set(manifest["workflows"]), "missing Grafana workflow")
            for key, workflow in manifest["workflows"].items():
                if workflow["required"]:
                    require(report["workflows"][key]["verdict"] == "passed", "Grafana workflow failed")
                    recording(report["workflows"][key]["artifact_sha256"], False)
            for cell_id in required:
                family = cell_id.split("-")[1]
                kind = {"CPU": "profiles", "LOG": "logs", "TCP": "metrics"}.get(family, "traces")
                require(cell_id in manifest["backends"][kind]["cells"], "required cell lacks backend evidence")
            require(backend.evaluate(replay_manifest, replay_capture)["verdict"] == "passed", "recorded backend assertions fail replay")
            continue
        suite.validate(manifest)
        require(manifest["environment"] == report["environment"] == plan["environment"], "suite environment mismatch")
        require(set(report["cells"]) == set(manifest["cells"]), "suite cell inventory mismatch")
        selected = required if name == "replacement" else {key for key in required if key.split("-")[1] in suite.PROTOCOL_FAMILIES}
        if name == "replacement":
            require(set(manifest["cells"]) == set(plan["cells"]), "replacement inventory differs from approved contract")
            require(all(cell["requiredness"] == plan["cells"][key]["requiredness"] for key, cell in manifest["cells"].items()),
                    "requiredness changed in capability suite")
        else:
            require(manifest.get("protocol_qualification") is True, "missing protocol metrics and controls")
        for cell_id in selected:
            cell, result = manifest["cells"][cell_id], report["cells"][cell_id]
            require(cell["requiredness"] == "required" and cell["identity"] == plan["cells"][cell_id]["identity"], "required cell identity mismatch")
            require(result["verdict"] == "passed" and set(result["scenarios"]) == set(cell["scenarios"]), "required cell failed or incomplete")
            require(all(value["verdict"] == "passed" for value in result["scenarios"].values()), "required scenario failed or skipped")
            require(result["identity"] == {key: cell["identity"][key] for key in ["workload_image", "collector_image", "config"]},
                    "result cell identity differs from manifest")
            for key, scenario in cell["scenarios"].items():
                saved = result["scenarios"][key]
                require(saved["sha256"]["evidence"] == suite.digest(capture["cells"][cell_id][key]) and
                        saved["sha256"]["scenario_identity"] == suite.digest(scenario["identity"]), "scenario evidence digest mismatch")
                replay = replay_capture["cells"][cell_id][key]
                replay["backend"] = recording(saved["sha256"]["backend_response"])
                if name == "protocol":
                    require("metric_assertions" in saved, "missing stored request metrics")
                    replay["metrics"] = recording(saved["sha256"]["metrics_response"])
            if not plan["fixture"]:
                require(cell["support"] == "implemented" and bool(cell["approval"]), "unsupported required cell")
        require(suite.evaluate(replay_manifest, replay_capture)["verdict"] == "passed", "recorded capability assertions fail replay")


def check_trials(plan, cell_id, trials):
    cell = plan["cells"][cell_id]
    cpu = suite.cell_family(cell_id) == "CPU"
    require(set(trials) == SCENARIOS, "missing production scenario")
    results = {}
    for name in sorted(SCENARIOS):
        results[name] = {"verdict": "failed"}
        try:
            expected = cell["scenarios"][name]
            require(len(trials[name]) == expected["repetitions"], "wrong repetition count")
            samples = {key: [] for key in cell["thresholds"]}
            seeds, intervals = set(), []
            for arms in trials[name]:
                require(set(arms) == ARMS, "missing comparison arm")
                seed = suite.natural(arms["candidate"]["seed"])
                require(seed not in seeds, "reused repetition seed")
                seeds.add(seed)
                duration = None
                for arm, run in arms.items():
                    require(run["status"] == "executed" and run["cell"] == cell_id, "trial skipped or foreign cell")
                    require(run["environment"] == plan["environment"] and run["settings"] == cell["settings"] and run["seed"] == seed,
                            "unmatched workload, placement, sampling or target")
                    identity = cell["identity"] if arm == "candidate" else plan["reference"] if arm == "reference" else {}
                    require(run["identity"] == identity, "comparison arm identity mismatch")
                    start, end = suite.natural(run["start_nanos"]), suite.natural(run["end_nanos"])
                    require(end > start and (end - start) / 1e9 >= expected["min_duration_seconds"], "trial too short")
                    require(duration is None or duration == end - start, "unmatched measurement windows")
                    duration = end - start
                    require(all(end <= left or start >= right for left, right in intervals), "overlapping comparison arms")
                    intervals.append((start, end))
                    commands = run["commands"]
                    require(isinstance(commands, list) and 0 < len(commands) <= 32, "missing execution commands")
                    require(all(isinstance(argv, list) and argv and all(isinstance(arg, str) and 0 < len(arg) <= 1024 for arg in argv) for argv in commands),
                            "invalid command arguments")
                    require(not re.search(r"(?i)(https?://|password|token|secret|credential|authorization|\n|\r)", json.dumps(commands)),
                            "unsanitized command")
                    for value in run["metrics"].values():
                        number(value)
                # Reference and candidate coverage must pass before performance is accepted.
                baseline = arms["no-agent"]["metrics"]
                measures(baseline, baseline, False)
                require(baseline["collector_cpu_cores"] == baseline["collector_rss_bytes"] == 0, "no-agent arm contains a collector")
                require(all(run["metrics"]["expected"] == baseline["expected"] for run in arms.values()), "unmatched independent operation counts")
                values = measures(arms["candidate"]["metrics"], baseline, cpu)
                reference = measures(arms["reference"]["metrics"], baseline, cpu)
                for key in set(cell["thresholds"]) - set(METRICS):
                    values[key] = number(arms["candidate"]["metrics"][key])
                for key in ["coverage_ratio", "overcount_ratio", "loss_ratio", "duplicate_ratio"]:
                    require(passes(values[key], cell["thresholds"][key]) and passes(reference[key], cell["thresholds"][key]),
                            "unequal per-family quality")
                if name == "rollback":
                    run = arms["candidate"]
                    require(run["restored"] == plan["reference"], "previous collectors not restored")
                    delivery = run["delivery"]
                    for value in delivery.values():
                        suite.natural(value)
                    require(delivery["pending_before"] > 0 and delivery["pending_after"] == 0 and
                            delivery["pending_before"] == delivery["delivered"] + delivery["lost"] and
                            delivery["lost"] == run["metrics"]["lost"], "rollback delivery unaccounted")
                for key, threshold in cell["thresholds"].items():
                    require(passes(values[key], threshold), "production threshold failed")
                    samples[key].append(values[key])
            results[name].update(verdict="passed", repetitions=len(trials[name]), measurements={key: {
                "min": min(values), "median": statistics.median(values), "max": max(values),
                "stdev": statistics.stdev(values) if len(values) > 1 else 0} for key, values in samples.items()})
        except ERRORS:
            results[name]["failure"] = "missing, invalid, unmatched or failing trial evidence"
    return results


def evaluate(plan, evidence, root):
    result = {"schema_version": 1, "verdict": "failed", "replacement_qualified": False,
              "review_required": True, "cells": {}, "artifacts": {},
              "sha256": {"plan": suite.digest(plan), "evidence": suite.digest(evidence)}}
    total_bytes = 0
    def read(reference, document=True):
        nonlocal total_bytes
        path = Path(reference["path"])
        require(not path.is_absolute() and ".." not in path.parts and 0 < len(str(path)) <= 256, "invalid artifact path")
        resolved = (root / path).resolve()
        require(resolved.is_relative_to(root.resolve()), "artifact escapes bundle")
        with resolved.open("rb") as stream:
            raw = stream.read(suite.MAX_BYTES + 1)
        total_bytes += len(raw)
        require(0 < len(raw) <= suite.MAX_BYTES and total_bytes <= 128 * 1024 * 1024, "artifact budget exceeded")
        backend.artifact(reference["sha256"])
        require(hashlib.sha256(raw).hexdigest() == reference["sha256"], "artifact digest mismatch")
        result["artifacts"][str(path)] = reference["sha256"]
        return suite.read_json(io.BytesIO(raw)) if document else raw
    try:
        require(plan["schema_version"] == 1 and type(plan["fixture"]) is bool, "invalid campaign schema")
        result["mode"] = "fixture" if plan["fixture"] else "recorded-evidence"
        require(set(plan["inputs"]) == {f"IN-{i:02}" for i in range(1, 8)}, "missing deployment input")
        for value in plan["inputs"].values():
            approval(value)
            read(value["artifact"], False)
        require(set(plan["publication"]) == {"runbook", "ledger", "public_contract"}, "missing published migration record")
        read(plan["publication"]["runbook"], False)
        backend.text(plan["contract_revision"])
        for name in ["ledger", "public_contract"]:
            published = read(plan["publication"][name])
            require(published["contract_revision"] == plan["contract_revision"] and
                    published["cells"] == {key: cell["requiredness"] for key, cell in plan["cells"].items()},
                    "published inventory differs from approved contract")
        quality = read(evidence["quality"])
        require(quality["collector_commit"] == plan["environment"]["collector_commit"] and
                quality["command"] == ["scripts/quality.sh"] and type(quality["exit_code"]) is int and quality["exit_code"] == 0,
                "quality gate failed or belongs to another revision")
        require(set(quality["skips"]) <= {"E_NAVIGATOR_SKIP_SUPPLY_CHAIN", "E_NAVIGATOR_SKIP_DOCKER", "E_NAVIGATOR_SKIP_KUBERNETES"},
                "unknown quality skip")
        for reason in quality["skips"].values():
            backend.text(reason)
        read(quality["log"], False)
        result["quality_skips"] = quality["skips"]
        require(isinstance(plan["reference"], dict) and 2 <= len(plan["reference"]) <= 64 and
                "config" in plan["reference"] and
                all(isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key) for key in plan["reference"]),
                "missing or invalid reference collectors")
        require(all(suite.DIGEST.fullmatch(value) for value in plan["reference"].values()), "unpinned reference collector")
        if not plan["fixture"]:
            authorization = read(plan["authorization"])
            require(authorization["approved"] is True and authorization["target"] == plan["environment"]["target"], "unauthorized campaign target")
            backend.text(authorization["owner"])
            backend.text(authorization["reference"])
        cells = plan["cells"]
        require(isinstance(cells, dict) and 0 < len(cells) <= 64, "invalid cell budget")
        require({suite.cell_family(key) for key in cells} == suite.FAMILIES, "missing inventory family")
        for cell_id, cell in cells.items():
            approval(cell["approval"])
            require(cell["requiredness"] in {"required", "optional", "excluded"}, "invalid requiredness")
            if cell["requiredness"] != "required":
                if cell["requiredness"] == "excluded":
                    backend.text(cell["exclusion"])
                result["cells"][cell_id] = {"verdict": "excluded" if cell["requiredness"] == "excluded" else "optional-not-evaluated"}
                continue
            suite.validate_identity(cell["identity"])
            settings = cell["settings"]
            require(set(settings) == {"placement", "offered_rate", "sample_period_nanos", "load_digest"}, "missing matched-load setting")
            backend.text(settings["placement"])
            require(number(settings["offered_rate"]) > 0 and suite.natural(settings["sample_period_nanos"]) > 0 and
                    suite.DIGEST.fullmatch(settings["load_digest"]) is not None, "invalid load or sampling setting")
            metrics = set(METRICS) - ({"unknown_stack_ratio"} if suite.cell_family(cell_id) != "CPU" else set())
            require(metrics <= set(cell["thresholds"]) and len(cell["thresholds"]) <= 64, "missing threshold or threshold budget exceeded")
            for key, threshold in cell["thresholds"].items():
                approval(threshold)
                if key in METRICS:
                    require(tuple(threshold[field] for field in ["category", "unit", "comparator"]) == METRICS[key], "threshold semantics changed")
                else:
                    require(re.fullmatch(r"[a-z][a-z0-9_]{0,127}", key) is not None and
                            threshold["category"] in {value[0] for value in METRICS.values()} and
                            threshold["comparator"] in {"min", "max"}, "invalid additional threshold")
                    backend.text(threshold["unit"])
                number(threshold["value"])
            require(0 < cell["thresholds"]["coverage_ratio"]["value"] <= 1, "invalid required coverage threshold")
            require(set(cell["scenarios"]) == SCENARIOS, "missing scenario requirement")
            for name, scenario in cell["scenarios"].items():
                require(number(scenario["min_duration_seconds"]) > 0, "missing measurement window")
                require((3 if name in {"normal", "sustained-load"} else 1) <= suite.natural(scenario["repetitions"]) <= 32, "invalid repetition budget")
        check_suites(plan, evidence, read)
        required = {key for key, cell in cells.items() if cell["requiredness"] == "required"}
        require(bool(required) and set(evidence["trials"]) <= set(cells), "empty or foreign trial inventory")
        for cell_id in sorted(required):
            scenarios = check_trials(plan, cell_id, read(evidence["trials"][cell_id]))
            result["cells"][cell_id] = {"verdict": "passed" if all(value["verdict"] == "passed" for value in scenarios.values()) else "failed",
                                        "scenarios": scenarios}
        require(isinstance(plan["consumers"], dict) and 0 < len(plan["consumers"]) <= 4096 and
                set(plan["consumers"]) == set(evidence["consumers"]), "missing consumer migration")
        covered = set()
        for key, query in plan["consumers"].items():
            require(isinstance(key, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,15}-[0-9]{4}", key) is not None,
                    "invalid consumer query ID")
            approval(query["approval"])
            backend.text(query["original"])
            backend.text(query["native"])
            require(bool(query["cells"]) and set(query["cells"]) <= set(cells), "foreign consumer cell")
            recorded = read(evidence["consumers"][key])
            require(recorded["status"] == "executed" and recorded["environment"] == plan["environment"] and
                    recorded["query"] == query["native"] and suite.digest(recorded["response"]) == suite.digest(query["expected"]),
                    "consumer stored query differs from expected answer")
            covered.update(query["cells"])
        require(required <= covered, "required cell has no migrated consumer")
        if all(result["cells"][key]["verdict"] == "passed" for key in required):
            result["verdict"] = "passed"
    except ERRORS:
        result["failure"] = "missing, invalid or mismatched campaign inputs or artifacts"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["plan", "evidence", "artifacts", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = {"schema_version": 1, "verdict": "failed", "replacement_qualified": False, "review_required": True}
    try:
        result = evaluate(suite.load(args.plan), suite.load(args.evidence), args.artifacts)
    except ERRORS:
        result["failure"] = "invalid campaign JSON or artifact directory"
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(f"replacement campaign {result['verdict']}; replacement_qualified=false; review required")
    return 0 if result["verdict"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
