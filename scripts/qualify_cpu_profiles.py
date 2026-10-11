#!/usr/bin/env python3
"""Check per-cell CPU stack quality against native samples and stored Pyroscope stacks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_BYTES = 16 * 1024 * 1024
MAX_CELLS = 64
MAX_SAMPLES = 65536
MAX_NODES = 65536
CPU_TYPE = "process_cpu:cpu:nanoseconds:cpu:nanoseconds"
UNKNOWN = re.compile(r"^(?:other|unknown|\[.*unresolved.*\]|(?:py:)?0x[0-9a-f]+|\[python:.*\])$|\+0x[0-9a-f]+$", re.I)
THRESHOLDS = {"min_weight_nanos", "min_useful_bps", "max_unknown_bps", "max_truncated_bps", "max_failed_bps", "max_weight_error_bps"}


def integer(value):
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,19}", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise ValueError("expected a nonnegative int64")
    return value


def validate_cells(cells):
    if not isinstance(cells, dict) or not 0 < len(cells) <= MAX_CELLS:
        raise ValueError("empty cell matrix or cell budget exceeded")
    for cell_id, cell in cells.items():
        if not re.fullmatch(r"GW-CPU-[0-9]{4}", cell_id):
            raise ValueError("invalid CPU cell ID")
        if set(cell) != {"identity", "process", "query", "stack", "thresholds"}:
            raise ValueError("incomplete or unknown cell fields")
        identity = cell["identity"]
        if set(identity) != {"runtime", "version", "build_id", "architecture", "image_digest"} or not all(isinstance(value, str) and 0 < len(value) <= 256 for value in identity.values()):
            raise ValueError("exact runtime identity required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity["image_digest"]):
            raise ValueError("immutable workload image digest required")
        if set(cell["process"]) != {"pid", "command"} or integer(cell["process"]["pid"]) == 0 or not isinstance(cell["process"]["command"], str) or not cell["process"]["command"]:
            raise ValueError("exact process oracle required")
        query = cell["query"]
        if set(query) != {"start", "end", "labelSelector", "profileTypeID"} or query["profileTypeID"] != CPU_TYPE:
            raise ValueError("CPU nanosecond query required")
        if not 0 < integer(query["start"]) < integer(query["end"]) or not isinstance(query["labelSelector"], str) or not 0 < len(query["labelSelector"]) <= 4096 or query["labelSelector"].strip() == "{}":
            raise ValueError("bounded time window and workload selector required")
        stack = cell["stack"]
        if not isinstance(stack, list) or not 2 <= len(stack) <= 128:
            raise ValueError("application caller chain required")
        for frame in stack:
            if set(frame) != {"symbol", "domain"} or frame["domain"] not in {"user", "managed_runtime"} or not isinstance(frame["symbol"], str) or not 0 < len(frame["symbol"]) <= 1024 or UNKNOWN.search(frame["symbol"]):
                raise ValueError("named application frames and explicit domains required")
        thresholds = cell["thresholds"]
        if set(thresholds) != THRESHOLDS or integer(thresholds["min_weight_nanos"]) == 0:
            raise ValueError("all CPU quality thresholds required")
        for key in THRESHOLDS - {"min_weight_nanos"}:
            if integer(thresholds[key]) > 10000:
                raise ValueError("fraction thresholds must be basis points")
        if integer(thresholds["min_useful_bps"]) == 0:
            raise ValueError("useful stack coverage cannot be disabled")


def contains_chain(stack, wanted):
    return any(stack[index:index + len(wanted)] == wanted for index in range(len(stack) - len(wanted) + 1))


def native_quality(cell, capture):
    if capture["identity"] != cell["identity"]:
        raise ValueError("capture runtime identity mismatch")
    samples = capture["samples"]
    if not isinstance(samples, list) or not 0 < len(samples) <= MAX_SAMPLES:
        raise ValueError("empty capture or sample budget exceeded")
    quality = dict.fromkeys(["total", "useful", "unknown", "truncated", "failed"], 0)
    for envelope in samples:
        if envelope["schema_version"] != 1 or envelope["source"] != "source.aya_cpu_profile" or envelope["kind"] != "profile_sample_observation":
            raise ValueError("native CPU source required")
        sample = envelope["payload"]
        attrs = {item["key"]: item["value"] for item in sample["attributes"]}
        if len(attrs) != len(sample["attributes"]):
            raise ValueError("ambiguous duplicate sample attributes")
        if sample["profiling_kind"] != "cpu" or attrs.get("profiling.sample.mode") != "on_cpu" or "profiling.sample.weight_nanos" in attrs:
            raise ValueError("periodic CPU sample semantics required")
        if any(sample["process"].get(key) != value for key, value in cell["process"].items()):
            raise ValueError("foreign process in capture")
        if not integer(cell["query"]["start"]) * 1000000 <= integer(sample["timestamp_unix_nanos"]) < integer(cell["query"]["end"]) * 1000000:
            raise ValueError("capture outside backend query window")
        weight = integer(sample["sample_count"]) * integer(sample["sampling_period_nanos"])
        if not 0 < weight <= (1 << 63) - 1:
            raise ValueError("positive CPU sample weight required")
        frames = sample["stack_frames"]
        if not isinstance(frames, list) or len(frames) > 256:
            raise ValueError("native frame budget exceeded")
        stack = [{"symbol": frame.get("symbol"), "domain": frame.get("domain")} for frame in frames]
        application_frames = [frame for frame in stack if frame["domain"] != "kernel"]
        unknown = not application_frames or any(frame["domain"] == "unknown" or not isinstance(frame["symbol"], str) or not frame["symbol"] or UNKNOWN.search(frame["symbol"]) for frame in application_frames)
        truncated = any(attrs.get(key) == "true" for key in ["profiling.stack.truncated", "profiling.stack.capture_truncated"]) or attrs.get("profiling.stack.py_stop") == "truncated" or attrs.get("profiling.stack.dwarf_stop") == "depth"
        failed = attrs.get("profiling.stack.pid_ns") == "unverified" or any(attrs.get(key, "complete") not in {"complete", "depth", "truncated"} for key in ["profiling.stack.py_stop", "profiling.stack.dwarf_stop"])
        quality["total"] += weight
        quality["useful"] += weight * contains_chain(stack, list(reversed(cell["stack"])))
        quality["unknown"] += weight * bool(unknown)
        quality["truncated"] += weight * truncated
        quality["failed"] += weight * failed
    return quality


def stored_quality(cell, response):
    # Pyroscope Level values are delta-x, inclusive weight, self weight, name
    # index. Reconstruct ancestry; name presence alone does not prove walking.
    graph = response["flamegraph"]
    names, levels = graph["names"], graph["levels"]
    if not isinstance(names, list) or not names or len(names) > MAX_NODES or not all(isinstance(name, str) and len(name) <= 4096 for name in names) or not isinstance(levels, list) or not 1 <= len(levels) <= 256:
        raise ValueError("invalid or empty stored flamegraph")
    total = integer(graph["total"])
    quality = {"total": total, "useful": 0, "unknown": 0}
    previous, count, self_sum = [], 0, 0
    wanted = [frame["symbol"] for frame in cell["stack"]]
    for depth, level in enumerate(levels):
        values = level["values"]
        if not isinstance(values, list) or not values or len(values) % 4:
            raise ValueError("malformed flamegraph level")
        current, right, parent_index = [], 0, 0
        for index in range(0, len(values), 4):
            delta, weight, own, name_index = map(integer, values[index:index + 4])
            left = right + delta
            right = left + weight
            count += 1
            if count > MAX_NODES or weight == 0 or own > weight or name_index >= len(names) or right > total:
                raise ValueError("invalid flamegraph weights or node budget exceeded")
            if depth == 0:
                if index != 0 or left != 0 or weight != total:
                    raise ValueError("single conserved flamegraph root required")
                path = []
            else:
                while parent_index < len(previous) and previous[parent_index]["right"] <= left:
                    parent_index += 1
                if parent_index == len(previous):
                    raise ValueError("orphan flamegraph node")
                parent = previous[parent_index]
                if left < parent["left"] or right > parent["right"]:
                    raise ValueError("flamegraph child outside parent")
                parent["children"] += weight
                path = parent["path"] + [names[name_index]]
            current.append({"left": left, "right": right, "weight": weight, "own": own, "children": 0, "path": path})
            self_sum += own
            quality["useful"] += own * contains_chain(path, wanted)
            quality["unknown"] += own * (not path or any(UNKNOWN.search(name) for name in path))
        if any(node["children"] + node["own"] != node["weight"] for node in previous):
            raise ValueError("pruned or nonconserving flamegraph")
        previous = current
    if total == 0 or self_sum != total or any(node["own"] != node["weight"] for node in previous):
        raise ValueError("empty or nonconserving stored profile")
    return quality


def qualify(cells, captures, profiles):
    validate_cells(cells)
    if set(cells) != set(captures) or set(cells) != set(profiles):
        raise ValueError("missing or unexpected CPU cell")
    results = {}
    for cell_id, cell in cells.items():
        native = native_quality(cell, captures[cell_id])
        stored = stored_quality(cell, profiles[cell_id])
        limits = cell["thresholds"]
        for quality in [native, stored]:
            if quality["total"] < integer(limits["min_weight_nanos"]) or quality["useful"] * 10000 < quality["total"] * integer(limits["min_useful_bps"]):
                raise ValueError("CPU sample weight or useful caller coverage below threshold")
            for kind in set(quality) - {"total", "useful"}:
                if quality[kind] * 10000 > quality["total"] * integer(limits[f"max_{kind}_bps"]):
                    raise ValueError("CPU degradation weight exceeds threshold")
        if abs(stored["total"] - native["total"]) * 10000 > native["total"] * integer(limits["max_weight_error_bps"]):
            raise ValueError("stored CPU weight differs from capture")
        results[cell_id] = {"total_weight_nanos": native["total"], "useful_weight_nanos": native["useful"], "unknown_weight_nanos": native["unknown"], "truncated_weight_nanos": native["truncated"], "failed_weight_nanos": native["failed"], "stored": stored}
    return results


def read_json(stream):
    payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError("JSON budget exceeded")
    return json.loads(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", type=Path, required=True)
    parser.add_argument("--capture", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--profiles", type=Path, help="saved SelectMergeStacktraces responses by cell ID")
    mode.add_argument("--pyroscope-url", help="authorized read-only Pyroscope base URL")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = {"schema_version": 1, "mode": "pyroscope-query" if args.pyroscope_url else "saved-json", "verdict": "failed", "replacement_qualified": False}
    try:
        with args.cells.open("rb") as stream:
            cells = read_json(stream)
        validate_cells(cells)
        with args.capture.open("rb") as stream:
            captures = read_json(stream)
        if args.profiles:
            with args.profiles.open("rb") as stream:
                profiles = read_json(stream)
        else:
            url = urlsplit(args.pyroscope_url)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise ValueError("HTTP(S) base URL required without credentials, query or fragment")
            profiles = {}
            for cell_id, cell in cells.items():
                request = Request(args.pyroscope_url.rstrip("/") + "/querier.v1.QuerierService/SelectMergeStacktraces", data=json.dumps(dict(cell["query"], maxNodes=MAX_NODES)).encode(), headers={"Content-Type": "application/json", "Accept": "application/json"})
                with urlopen(request, timeout=30) as response:
                    profiles[cell_id] = read_json(response)
        result["sha256"] = {name: hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() for name, value in [("cells", cells), ("capture", captures), ("profiles", profiles)]}
        result["cells"] = qualify(cells, captures, profiles)
        result["verdict"] = "passed"
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        # Neither arbitrary backend data nor exception text enters the bundle.
        result["failure"] = "invalid CPU evidence or unmet per-cell quality threshold"
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"CPU stack assertions {result['verdict']}, mode={result['mode']}")
    return 0 if result["verdict"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
