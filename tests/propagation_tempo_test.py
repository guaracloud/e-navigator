import copy
import base64
import importlib.util
from pathlib import Path
import unittest
import json
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

SPEC = importlib.util.spec_from_file_location(
    "propagation_tempo", Path(__file__).resolve().parents[1] / "scripts/qualify_propagation_tempo.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture():
    expected, traces = {}, {}
    for request in range(1, 9):
        trace_id = f"{request:032x}"
        spans = [
            {"span_id": f"{request * 10:016x}", "parent_span_id": "", "service": "proxy", "name": "/proxy", "kind": "SPAN_KIND_SERVER"},
            {"span_id": f"{request * 10 + 1:016x}", "parent_span_id": f"{request * 10:016x}", "service": "proxy", "name": "/sink", "kind": "SPAN_KIND_CLIENT"},
            {"span_id": f"{request * 10 + 2:016x}", "parent_span_id": f"{request * 10 + 1:016x}", "service": "sink", "name": "/sink", "kind": "SPAN_KIND_SERVER"},
        ]
        expected[trace_id] = spans
        traces[trace_id] = {"batches": [
            {"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": span["service"]}}]},
             "scopeSpans": [{"spans": [{"traceId": trace_id, "spanId": span["span_id"], "parentSpanId": span["parent_span_id"], "name": span["name"], "kind": span["kind"]}]}]}
            for span in spans
        ]}
    return expected, traces


class TempoTreeTests(unittest.TestCase):
    def test_complete_concurrent_trees(self):
        expected, traces = fixture()
        MODULE.assert_trees(expected, traces)

    def test_cross_request_parent_contamination(self):
        expected, traces = fixture()
        traces[f"{2:032x}"]["batches"][1]["scopeSpans"][0]["spans"][0]["parentSpanId"] = f"{10:016x}"
        with self.assertRaisesRegex(ValueError, "tree mismatch"):
            MODULE.assert_trees(expected, traces)

    def test_missing_extra_duplicate_and_changed_spans(self):
        expected, traces = fixture()
        trace_id = next(iter(traces))
        for mutation in ["missing", "extra", "duplicate", "ownership", "kind", "foreign_trace"]:
            changed = copy.deepcopy(traces)
            batches = changed[trace_id]["batches"]
            if mutation == "missing":
                batches.pop()
            elif mutation in {"extra", "duplicate"}:
                batches.append(copy.deepcopy(batches[-1]))
                if mutation == "extra":
                    batches[-1]["scopeSpans"][0]["spans"][0]["spanId"] = "000000000000ffff"
            elif mutation == "ownership":
                batches[0]["resource"]["attributes"][0]["value"]["stringValue"] = "sdk"
            else:
                span = batches[0]["scopeSpans"][0]["spans"][0]
                span["kind" if mutation == "kind" else "traceId"] = "SPAN_KIND_CLIENT" if mutation == "kind" else f"{2:032x}"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                MODULE.assert_trees(expected, changed)

    def test_empty_and_incomplete_evidence_cannot_pass(self):
        expected, traces = fixture()
        for wanted, observed in [({}, {}), (expected, {}), (expected, {next(iter(traces)): next(iter(traces.values()))})]:
            with self.assertRaises(ValueError):
                MODULE.assert_trees(wanted, observed)

    def test_expected_tree_cannot_contain_cycles(self):
        expected, traces = fixture()
        spans = next(iter(expected.values()))
        spans[0]["parent_span_id"] = spans[-1]["span_id"]
        with self.assertRaisesRegex(ValueError, "cycle"):
            MODULE.assert_trees(expected, traces)

    def test_protobuf_json_ids_and_numeric_kinds(self):
        expected, traces = fixture()
        for document in traces.values():
            document["resourceSpans"] = document.pop("batches")
            for batch in document["resourceSpans"]:
                for span in batch["scopeSpans"][0]["spans"]:
                    for key in ["traceId", "spanId", "parentSpanId"]:
                        span[key] = base64.b64encode(bytes.fromhex(span[key])).decode()
                    span["kind"] = 2 if span["kind"] == "SPAN_KIND_SERVER" else 3
        MODULE.assert_trees(expected, traces)

    def test_cli_records_failure_and_distinguishes_saved_json(self):
        expected, traces = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "expected.json").write_text(json.dumps(expected))
            for valid in [True, False]:
                (root / "traces.json").write_text(json.dumps(traces if valid else {}))
                result = subprocess.run([
                    sys.executable, str(Path(MODULE.__file__)),
                    "--expected", str(root / "expected.json"),
                    "--traces", str(root / "traces.json"),
                    "--output", str(root / "result.json"),
                ], capture_output=True, text=True)
                evidence = json.loads((root / "result.json").read_text())
                self.assertEqual(result.returncode, 0 if valid else 1)
                self.assertEqual(evidence["mode"], "saved-json")
                self.assertEqual(evidence["verdict"], "passed" if valid else "failed")
                self.assertIn("responses_sha256", evidence)

    def test_query_mode_fetches_every_trace_without_persisting_backend_attributes(self):
        expected, traces = fixture()
        for document in traces.values():
            document["batches"][0]["resource"]["attributes"].append(
                {"key": "private.fixture", "value": {"stringValue": "do-not-persist"}}
            )
        queried = []

        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                trace_id = self.path.removeprefix("/api/traces/")
                queried.append(trace_id)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(traces[trace_id]).encode())

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Backend)
        worker = threading.Thread(target=server.serve_forever)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "expected.json").write_text(json.dumps(expected))
                result = subprocess.run([
                    sys.executable, str(Path(MODULE.__file__)),
                    "--expected", str(root / "expected.json"),
                    "--tempo-url", f"http://127.0.0.1:{server.server_port}",
                    "--output", str(root / "result.json"),
                ], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                evidence = json.loads((root / "result.json").read_text())
                self.assertEqual(evidence["mode"], "tempo-query")
                self.assertEqual(evidence["verified_trees"], expected)
                self.assertNotIn("do-not-persist", (root / "result.json").read_text())
                self.assertEqual(set(queried), set(expected))
        finally:
            server.shutdown()
            worker.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
