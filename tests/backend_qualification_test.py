"""Backend evidence must fail closed without confusing fixtures with live proof."""
import copy
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import qualify_backends as backend
from backend_fixture import fixture
from replacement_fixture import fixture as replacement_fixture




class BackendTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.evidence = fixture()

    def test_fixture_checks_stored_and_expired_data_without_live_promotion(self):
        result = backend.evaluate(self.plan, self.evidence)
        self.assertEqual(result["verdict"], "passed")
        self.assertFalse(result["live_qualified"])
        self.assertEqual(result["backends"]["profiles"]["queries"]["stored"]["assertions"]["total_weight_nanos"], 100)

    def test_invalid_version_retention_frame_ingest_or_workflow_fails(self):
        mutations = [
            lambda e: e["backends"]["profiles"]["identity"].update(release="different"),
            lambda e: e["backends"]["profiles"]["queries"]["stored"].update(observed_at_ms=2001),
            lambda e: e["backends"]["profiles"]["queries"]["expired"].update(observed_at_ms=4000),
            lambda e: e["backends"]["profiles"]["queries"]["expired"].update(response=e["backends"]["profiles"]["queries"]["stored"]["response"]),
            lambda e: e["backends"]["profiles"]["queries"]["stored"]["response"]["flamegraph"].update(names=["missing"]),
            lambda e: e["backends"]["traces"]["ingest"].update(rejected=1),
            lambda e: e["workflows"]["traces"].update(status="skipped"),
            lambda e: e["workflows"]["profiles"]["definition"].update(datasource_uid="wrong"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                evidence = copy.deepcopy(self.evidence)
                mutate(evidence)
                self.assertEqual(backend.evaluate(self.plan, evidence)["verdict"], "failed")

    def test_live_requires_authorization_and_resolved_inputs(self):
        self.plan["fixture"] = False
        with self.assertRaises(ValueError):
            backend.evaluate(self.plan, self.evidence, endpoints={})

    def test_live_queries_ignore_saved_responses_and_preserve_query_digests(self):
        self.plan.update(fixture=False, blocked_inputs=[])
        for kind, target in self.plan["backends"].items():
            target.update(retention_ms=1000, expiry_grace_ms=100)
            target["queries"]["stored"].update(data_end_ms=3900, min_age_ms=100)
            target["queries"]["expired"]["min_age_ms"] = 1101
            prior = self.evidence["backends"][kind]["queries"]["expired"]["prior_stored"]
            prior["observed_at_ms"] = target["queries"]["expired"]["data_end_ms"] + 100
        profile = self.plan["backends"]["profiles"]["queries"]["stored"]["oracle"]["cell"]
        profile["query"].update(start=3000, end=3900)
        native = self.evidence["backends"]["profiles"]["queries"]["stored"]["native"]
        for sample in native:
            sample["payload"]["timestamp_unix_nanos"] += 2000000000
        traces = self.plan["backends"]["traces"]["queries"]["stored"]
        traces["data_end_ms"] = 3501
        observation = self.evidence["backends"]["traces"]["queries"]["stored"]
        serialized = json.dumps([traces["oracle"], observation])
        for trace_id in traces["oracle"]["query_trace_ids"]:
            serialized = serialized.replace(trace_id, f"{int(trace_id, 16) ^ (1 << 127):032x}")
        traces["oracle"], observation = json.loads(serialized)
        for sample in observation["native"]:
            sample["payload"]["start_unix_nanos"] += 2000000000
            sample["payload"]["end_unix_nanos"] += 2000000000
        self.evidence["backends"]["traces"]["queries"]["stored"] = observation
        responses = copy.deepcopy(self.evidence)
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requests.append(self.path)
                trace_id = self.path.rsplit("/", 1)[-1]
                document = responses["backends"]["traces"]["queries"]["stored"]["response"].get(trace_id)
                self.send_response(200 if document else 404)
                self.end_headers()
                if document:
                    self.wfile.write(json.dumps(document).encode())

            def do_POST(self):
                query = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(query)
                phase = "stored" if query["end"] == 3900 else "expired"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(responses["backends"]["profiles"]["queries"][phase]["response"]).encode())

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            for observation in self.evidence["backends"].values():
                for query in observation["queries"].values():
                    query["response"] = {"invalid": "must not be used"}
            url = f"http://127.0.0.1:{server.server_port}"
            with patch.object(backend.time, "time", return_value=4):
                result = backend.evaluate(self.plan, self.evidence, {"profiles": url, "traces": url},
                                          {"approved": True, "target": self.plan["target"], "owner": "test", "reference": "test"})
            self.assertEqual(result["verdict"], "passed")
            self.assertEqual(len(requests), 6)
            self.assertEqual(result["mode"], "live-query")
            self.assertFalse(result["live_qualified"])
            self.assertEqual(len(result["backends"]["profiles"]["queries"]["stored"]["response_sha256"]), 64)
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

    def test_required_correlation_is_not_inferred_from_time(self):
        self.plan["correlation"] = "required"
        with self.assertRaises(ValueError):
            backend.evaluate(self.plan, self.evidence)

    def test_expiry_requires_previous_storage_of_the_same_cohort(self):
        for kind in ["traces", "profiles"]:
            with self.subTest(kind=kind):
                evidence = copy.deepcopy(self.evidence)
                evidence["backends"][kind]["queries"]["expired"]["prior_stored"]["response"] = {}
                self.assertEqual(backend.evaluate(self.plan, evidence)["verdict"], "failed")
        query = self.plan["backends"]["traces"]["queries"]["expired"]
        query["oracle"]["query_trace_ids"] = ["f" * 32]
        with self.assertRaises(ValueError):
            backend.evaluate(self.plan, self.evidence)

    def test_trace_age_must_match_native_cohort(self):
        self.plan["backends"]["traces"]["queries"]["stored"]["data_end_ms"] += 1000
        self.assertEqual(backend.evaluate(self.plan, self.evidence)["verdict"], "failed")

    def test_metric_query_time_and_malformed_response_fail_closed(self):
        manifest, capture = replacement_fixture()
        scenario = manifest["cells"]["GW-TCP-9001"]["scenarios"]["normal"]
        observation = capture["cells"]["GW-TCP-9001"]["normal"]
        target = copy.deepcopy(self.plan["backends"]["traces"])
        target["cells"] = ["GW-TCP-9001"]
        for phase, query in target["queries"].items():
            query.update(cell="GW-TCP-9001", data_end_ms=2000, oracle=copy.deepcopy(scenario["backend"]))
            query["oracle"]["query"]["time"] = "2"
            if phase == "expired":
                query["prior_oracle"] = copy.deepcopy(query["oracle"])
                query["oracle"].update(empty=True, series=[])
        self.plan["backends"]["metrics"] = target
        empty = {"status": "success", "data": {"resultType": "vector", "result": []}}
        self.evidence["backends"]["metrics"] = {
            "identity": target["identity"], "ingest": self.evidence["backends"]["traces"]["ingest"],
            "queries": {"stored": {"observed_at_ms": 4000, "native": observation["native"], "response": observation["backend"]},
                        "expired": {"observed_at_ms": 14000, "native": [], "response": empty,
                                    "prior_stored": {"observed_at_ms": 4000, "native": observation["native"], "response": observation["backend"]}}}}
        self.assertEqual(backend.evaluate(self.plan, self.evidence)["verdict"], "passed")
        target["queries"]["stored"]["oracle"]["query"]["time"] = "3"
        with self.assertRaises(ValueError):
            backend.evaluate(self.plan, self.evidence)
        target["queries"]["stored"]["oracle"]["query"]["time"] = "2"
        self.evidence["backends"]["metrics"]["queries"]["stored"]["response"] = {
            "status": "success", "data": {"resultType": "vector", "result": [{"metric": {}, "value": []}]}}
        self.assertEqual(backend.evaluate(self.plan, self.evidence)["verdict"], "failed")

    def test_optional_workflow_skip_is_explicit(self):
        self.plan["workflows"]["extra"] = dict(self.plan["workflows"]["profiles"], required=False)
        self.evidence["workflows"]["extra"] = {"status": "skipped"}
        result = backend.evaluate(self.plan, self.evidence)
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(result["workflows"]["extra"]["verdict"], "optional-incomplete")


if __name__ == "__main__":
    unittest.main()
