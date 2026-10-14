"""Protocol evidence requires both stored metrics and protocol-specific controls."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_replacement as suite
from replacement_fixture import fixture

EXTRA = {"pipelining", "out-of-order", "compression", "malformed", "truncated", "ambiguous"}
FAMILIES = {"HTTP", "GRPC", "POSTGRESQL", "MYSQL", "REDIS", "MONGODB", "KAFKA"}


def protocol_fixture(namespace="WC"):
    manifest, capture = fixture(namespace)
    manifest["protocol_qualification"] = True
    for cell_id, cell in manifest["cells"].items():
        family = cell_id.split("-")[1]
        if family not in FAMILIES:
            cell.update(requiredness="excluded", exclusion="outside issue 49", approval="synthetic exclusion")
            del capture["cells"][cell_id]
            continue
        for index, name in enumerate(sorted(EXTRA)):
            source = "normal" if name in {"pipelining", "out-of-order", "compression"} else "unsupported-version"
            scenario = copy.deepcopy(cell["scenarios"][source])
            evidence = copy.deepcopy(capture["cells"][cell_id][source])
            # Independent IDs prevent negative controls from querying earlier work.
            ids = [f"{int(value, 16) + index + 1:032x}" for value in scenario["backend"]["query_trace_ids"]]
            replacements = dict(zip(scenario["backend"]["query_trace_ids"], ids))
            if source == "normal":
                replacements.update({span["span_id"]: f"{int(span['span_id'], 16) + index + 1:016x}"
                                     for spans in scenario["backend"]["trees"].values() for span in spans})
            for old, new in replacements.items():
                scenario = json.loads(json.dumps(scenario).replace(old, new))
                evidence = json.loads(json.dumps(evidence).replace(old, new))
            if name in {"pipelining", "out-of-order"}:
                for record in [scenario, evidence]:
                    record["workload"][1]["connection"] = 0
                    record["workload"][0]["end_nanos"] = record["workload"][1]["end_nanos"] + 100
            scenario["backend"]["query_trace_ids"] = ids
            scenario["diagnostic"] = {"layer": "parser", "reason": "synthetic unsupported control"}
            cell["scenarios"][name] = scenario
            capture["cells"][cell_id][name] = evidence
        for name, scenario in cell["scenarios"].items():
            evidence = capture["cells"][cell_id][name]
            empty = scenario["backend"]["empty"]
            labels = {"__name__": "e_navigator_fixture_requests", "cell": cell_id, "scenario": name}
            metrics = {"type": "metrics", "empty": empty,
                       "query": {"query": f'e_navigator_fixture_requests{{cell="{cell_id}",scenario="{name}"}}', "time": "1.8"},
                       "series": [] if empty else [{"labels": labels, "value": 2}]}
            scenario["metrics"] = metrics
            evidence["metrics"] = {"status": "success", "data": {"resultType": "vector", "result": [] if empty else [{"metric": copy.deepcopy(labels), "value": [1.8, "2"]}]}}
            if not empty:
                for signal in scenario["native"]:
                    payload = signal["payload"]
                    role = "server" if payload["parent_span_id"] else "client"
                    payload["attributes"] = [{"key": "e.navigator.protocol.capture.role", "value": role}]
                evidence["native"] = copy.deepcopy(scenario["native"])
                for document in evidence["backend"].values():
                    for batch in document["batches"]:
                        for scope in batch["scopeSpans"]:
                            for span in scope["spans"]:
                                span.update(startTimeUnixNano="1500000000", endTimeUnixNano="1500000200")
                                if name == "late-attachment":
                                    span.update(startTimeUnixNano="1700000000", endTimeUnixNano="1700000200")
            if empty:
                scenario.setdefault("diagnostic", {"layer": "capture", "reason": "synthetic unsupported version"})
    return manifest, capture


class ProtocolQualificationTests(unittest.TestCase):
    def test_fixture_passes_without_promoting_cells(self):
        manifest, capture = protocol_fixture()
        result = suite.evaluate(manifest, capture)
        self.assertEqual(result["verdict"], "passed")
        self.assertFalse(result["replacement_qualified"])
        self.assertEqual(result["cells"]["WC-REDIS-9001"]["scenarios"]["normal"]["metric_assertions"], {"stored_series": 1})

    def test_missing_metrics_fails_each_family(self):
        for family in FAMILIES:
            manifest, capture = protocol_fixture()
            capture["cells"][f"WC-{family}-9001"]["normal"]["metrics"]["data"]["result"] = []
            self.assertEqual(suite.evaluate(manifest, capture)["verdict"], "failed")

    def test_latency_role_count_and_cardinality_mismatches_fail(self):
        for mutation in ["latency", "role", "count", "labels", "route"]:
            manifest, capture = protocol_fixture()
            evidence = capture["cells"]["WC-HTTP-9001"]["normal"]
            if mutation in {"latency", "role", "route"}:
                span = evidence["backend"][next(iter(evidence["backend"]))]["batches"][0]["scopeSpans"][0]["spans"][0]
                if mutation == "latency":
                    span["endTimeUnixNano"] = "1500000201"
                elif mutation == "role":
                    span["kind"] = "SPAN_KIND_SERVER"
                else:
                    span["attributes"].append({"key": "http.route", "value": {"stringValue": "/guessed"}})
            elif mutation == "count":
                evidence["native"].pop()
            else:
                evidence["metrics"]["data"]["result"][0]["metric"]["raw_value"] = "unbounded"
            self.assertEqual(suite.evaluate(manifest, capture)["verdict"], "failed")

    def test_stored_route_values_must_match_without_duplicates(self):
        for mutation in ["changed", "missing", "duplicate"]:
            manifest, capture = protocol_fixture()
            scenario = manifest["cells"]["WC-HTTP-9001"]["scenarios"]["normal"]
            evidence = capture["cells"]["WC-HTTP-9001"]["normal"]
            for record in [scenario, evidence]:
                record["native"][0]["payload"]["attributes"].append({"key": "http.route", "value": "/observed"})
            span = evidence["backend"][next(iter(evidence["backend"]))]["batches"][0]["scopeSpans"][0]["spans"][0]
            if mutation != "missing":
                span["attributes"].append({"key": "http.route", "value": {"stringValue": "/fabricated" if mutation == "changed" else "/observed"}})
            if mutation == "duplicate":
                span["attributes"].append(copy.deepcopy(span["attributes"][-1]))
            self.assertEqual(suite.evaluate(manifest, capture)["verdict"], "failed")

    def test_live_mode_ignores_saved_metrics_and_traces(self):
        manifest, capture = protocol_fixture()
        manifest.update(fixture=False, blocked_inputs=[])
        responses = {}
        for cell_id, cell in manifest["cells"].items():
            if cell["requiredness"] == "excluded":
                continue
            cell.update(support="implemented", approval="fixture approval")
            for name, scenario in cell["scenarios"].items():
                evidence = capture["cells"][cell_id][name]
                for key in ["backend", "metrics"]:
                    responses[suite.digest(scenario[key])] = evidence[key]
                    evidence[key] = {"invalid": "saved response must be ignored"}
        def query(oracle, endpoints):
            return responses[suite.digest(oracle)]
        with patch.object(suite, "query_backend", side_effect=query) as queries:
            result = suite.evaluate(manifest, capture, {name: "http://fixture.invalid" for name in ["traces", "profiles", "metrics", "logs"]},
                                    {"approved": True, "target": manifest["environment"]["target"], "owner": "fixture", "reference": "fixture"})
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(queries.call_count, 210)
        self.assertFalse(result["protocol_qualified"])

    def test_live_queries_require_resolved_inputs_before_any_request(self):
        manifest, capture = protocol_fixture()
        manifest["fixture"] = False
        with self.assertRaises(ValueError):
            suite.evaluate(manifest, capture, {name: "http://127.0.0.1:1" for name in ["traces", "profiles", "metrics", "logs"]},
                           {"approved": True, "target": manifest["environment"]["target"], "owner": "fixture", "reference": "fixture"})

    def test_missing_control_or_diagnostic_rejected(self):
        for field in ["control", "diagnostic", "metrics"]:
            manifest, capture = protocol_fixture()
            scenarios = manifest["cells"]["WC-REDIS-9001"]["scenarios"]
            if field == "control":
                del scenarios["ambiguous"]
            else:
                del scenarios["ambiguous"][field]
            with self.assertRaises((ValueError, KeyError)):
                suite.evaluate(manifest, capture)

    def test_negative_controls_require_positive_counters_and_no_spans(self):
        for mutation in ["counter", "span", "metric", "privacy"]:
            manifest, capture = protocol_fixture()
            scenario = manifest["cells"]["WC-MYSQL-9001"]["scenarios"]["ambiguous"]
            evidence = capture["cells"]["WC-MYSQL-9001"]["ambiguous"]
            if mutation == "counter":
                evidence["counters"]["unsupported_versions"] = 0
            elif mutation == "span":
                evidence["native"] = capture["cells"]["WC-MYSQL-9001"]["normal"]["native"]
            elif mutation == "metric":
                evidence["metrics"] = capture["cells"]["WC-MYSQL-9001"]["normal"]["metrics"]
            else:
                evidence["metrics"]["leak"] = scenario["forbidden_values"][0]
            self.assertEqual(suite.evaluate(manifest, capture)["verdict"], "failed")


if __name__ == "__main__":
    if len(sys.argv) == 2:
        directory = Path(sys.argv.pop())
        directory.mkdir(parents=True, exist_ok=True)
        for name, value in zip(["manifest", "capture"], protocol_fixture()):
            (directory / f"{name}.json").write_text(json.dumps(value, indent=2) + "\n")
    else:
        unittest.main()
