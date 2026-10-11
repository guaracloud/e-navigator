#!/usr/bin/env python3
"""Assert exact request trees from Tempo JSON, without changing workloads."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_BYTES = 16 * 1024 * 1024
MAX_TRACES = 128
MAX_SPANS = 4096
KINDS = {0: "SPAN_KIND_UNSPECIFIED", 1: "SPAN_KIND_INTERNAL", 2: "SPAN_KIND_SERVER", 3: "SPAN_KIND_CLIENT", 4: "SPAN_KIND_PRODUCER", 5: "SPAN_KIND_CONSUMER"}


def identity(value, size, allow_empty=False):
    if allow_empty and value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ValueError("identity must be a string")
    if re.fullmatch(rf"[0-9a-fA-F]{{{size * 2}}}", value):
        decoded = bytes.fromhex(value)
    else:
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as error:
            raise ValueError("invalid span/trace identity") from error
    if len(decoded) != size or not any(decoded):
        raise ValueError("invalid span/trace identity length or zero identity")
    return decoded.hex()


def actual_spans(document, trace_id):
    spans = []
    batches = document.get("batches", document.get("resourceSpans"))
    if not isinstance(batches, list):
        raise ValueError("missing Tempo resource spans")
    for batch in batches:
        attributes = batch.get("resource", {}).get("attributes", [])
        services = [item["value"].get("stringValue") for item in attributes if item.get("key") == "service.name"]
        if len(services) != 1 or not services[0]:
            raise ValueError("missing or ambiguous service ownership")
        scopes = batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", []))
        for scope in scopes:
            for span in scope.get("spans", []):
                if identity(span.get("traceId"), 16) != trace_id:
                    raise ValueError("foreign trace in queried tree")
                kind = span.get("kind")
                spans.append({
                    "span_id": identity(span.get("spanId"), 8),
                    "parent_span_id": identity(span.get("parentSpanId"), 8, allow_empty=True),
                    "service": services[0],
                    "name": span.get("name"),
                    "kind": KINDS.get(kind, kind),
                })
                if len(spans) > MAX_SPANS:
                    raise ValueError("span budget exceeded")
    return spans


def span_index(spans):
    if not isinstance(spans, list) or not 0 < len(spans) <= MAX_SPANS:
        raise ValueError("empty tree or span budget exceeded")
    indexed = {}
    for span in spans:
        if set(span) != {"span_id", "parent_span_id", "service", "name", "kind"}:
            raise ValueError("expected span fields are incomplete or unknown")
        span_id = identity(span["span_id"], 8)
        parent = identity(span["parent_span_id"], 8, allow_empty=True)
        if span_id in indexed:
            raise ValueError("duplicate span identity")
        if not isinstance(span["name"], str) or not span["name"] or not isinstance(span["service"], str) or not span["service"] or span["kind"] not in KINDS.values():
            raise ValueError("invalid name, service or kind")
        indexed[span_id] = dict(span, span_id=span_id, parent_span_id=parent)
    for span_id in indexed:
        visited = set()
        cursor = span_id
        while cursor in indexed:
            if cursor in visited:
                raise ValueError("trace tree cycle")
            visited.add(cursor)
            cursor = indexed[cursor]["parent_span_id"]
    return indexed


def assert_trees(expected, traces):
    if not isinstance(expected, dict) or not 0 < len(expected) <= MAX_TRACES:
        raise ValueError("empty expectation or trace budget exceeded")
    if set(expected) != set(traces):
        raise ValueError("missing or unexpected traces")
    indexes = {}
    owners = {}
    for trace_id, spans in expected.items():
        if identity(trace_id, 16) != trace_id:
            raise ValueError("expected trace IDs must use lowercase hex")
        indexes[trace_id] = span_index(spans)
        for span_id in indexes[trace_id]:
            if span_id in owners:
                raise ValueError("expected request trees reuse a span identity")
            owners[span_id] = trace_id
    for trace_id, wanted in indexes.items():
        for span in wanted.values():
            parent_owner = owners.get(span["parent_span_id"], trace_id)
            if parent_owner != trace_id:
                raise ValueError("expected tree contains cross-request parent")
        if span_index(actual_spans(traces[trace_id], trace_id)) != wanted:
            raise ValueError(f"tree mismatch for {trace_id}")


def read_json(stream):
    payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError("JSON budget exceeded")
    return json.loads(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, required=True, help="independent oracle, trace ID to exact span records")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--traces", type=Path, help="fixture or saved Tempo responses, trace ID to response")
    mode.add_argument("--tempo-url", help="authorized read-only Tempo base URL")
    parser.add_argument("--output", type=Path, required=True, help="evidence bundle; does not imply wire safety qualification")
    args = parser.parse_args()
    result = {"schema_version": 1, "mode": "tempo-query" if args.tempo_url else "saved-json", "verdict": "failed"}
    try:
        with args.expected.open("rb") as stream:
            expected = read_json(stream)
        # Validate the independent oracle before constructing any backend URL.
        if not isinstance(expected, dict) or not 0 < len(expected) <= MAX_TRACES:
            raise ValueError("empty expectation or trace budget exceeded")
        for trace_id, spans in expected.items():
            if identity(trace_id, 16) != trace_id:
                raise ValueError("expected trace IDs must use lowercase hex")
            span_index(spans)
        if args.traces:
            with args.traces.open("rb") as stream:
                traces = read_json(stream)
        else:
            url = urlsplit(args.tempo_url)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment:
                raise ValueError("Tempo URL must be an HTTP(S) base URL without credentials, query or fragment")
            traces = {}
            for trace_id in expected:
                request = Request(f"{args.tempo_url.rstrip('/')}/api/traces/{trace_id}", headers={"Accept": "application/json"})
                with urlopen(request, timeout=30) as response:
                    traces[trace_id] = read_json(response)
        result["expected_sha256"] = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
        result["responses_sha256"] = hashlib.sha256(json.dumps(traces, sort_keys=True).encode()).hexdigest()
        assert_trees(expected, traces)
        result["verdict"] = "passed"
        result["trace_count"] = len(expected)
        # Persist the independent oracle, not arbitrary backend attributes.
        result["verified_trees"] = expected
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Do not record backend URLs or exception text that may contain access data.
        result["failure_type"] = type(error).__name__
        if isinstance(error, ValueError):
            result["failure"] = str(error)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if result["verdict"] != "passed":
        print("propagation tree qualification failed; inspect the oracle and responses", file=sys.stderr)
        return 1
    print(f"propagation tree assertions passed, mode={result['mode']} traces={result['trace_count']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
