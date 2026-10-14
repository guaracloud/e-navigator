"""The complete campaign cannot pass on individual capability checks alone."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from campaign_fixture import fixture, write_artifact

ROOT = Path(__file__).resolve().parents[1]


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.plan, self.evidence = fixture(self.directory)

    def run_campaign(self):
        for name, value in [("plan.json", self.plan), ("evidence.json", self.evidence)]:
            (self.directory / name).write_text(json.dumps(value))
        output = self.directory / "result.json"
        run = subprocess.run([sys.executable, str(ROOT / "scripts/qualify_campaign.py"),
            "--plan", str(self.directory / "plan.json"), "--evidence", str(self.directory / "evidence.json"),
            "--artifacts", str(self.directory), "--output", str(output)], capture_output=True)
        return run.returncode, json.loads(output.read_text())

    def change_artifact(self, reference, mutate):
        value = json.loads((self.directory / reference["path"]).read_text())
        mutate(value)
        reference.update(write_artifact(self.directory, reference["path"], value))

    def assert_failed(self):
        code, result = self.run_campaign()
        self.assertEqual(code, 1)
        self.assertEqual(result["verdict"], "failed")
        self.assertFalse(result["replacement_qualified"])
        return result

    def test_complete_fixture_checks_campaign_without_promoting_replacement(self):
        code, result = self.run_campaign()
        self.assertEqual(code, 0)
        self.assertEqual(result["verdict"], "passed")
        self.assertEqual(result["mode"], "fixture")
        self.assertEqual(len(result["cells"]), 10)
        self.assertEqual(result["cells"]["GW-REDIS-9001"]["scenarios"]["normal"]["repetitions"], 3)
        self.assertEqual(result["cells"]["GW-REDIS-9001"]["scenarios"]["normal"]["measurements"]["coverage_ratio"]["min"], 1)
        self.assertFalse(result["replacement_qualified"])
        self.assertTrue(result["review_required"])

    def test_every_missing_required_family_fails(self):
        for cell_id in list(self.plan["cells"]):
            with self.subTest(cell=cell_id):
                saved = self.plan["cells"].pop(cell_id)
                self.assert_failed()
                self.plan["cells"][cell_id] = saved

    def test_required_scenarios_cannot_be_skipped_or_shortened(self):
        reference = self.evidence["trials"]["GW-REDIS-9001"]
        original = reference.copy()
        raw = (self.directory / reference["path"]).read_bytes()
        for mutate in [lambda v: v.pop("sustained-load"), lambda v: v["normal"].pop(),
                       lambda v: v["normal"][0]["candidate"].update(status="skipped"),
                       lambda v: v["normal"][0]["candidate"].update(end_nanos=1),
                       lambda v: v["normal"][0]["candidate"].update(seed=999),
                       lambda v: v["normal"][0]["candidate"]["settings"].update(offered_rate=1)]:
            with self.subTest(mutation=mutate):
                self.change_artifact(reference, mutate)
                self.assert_failed()
                (self.directory / reference["path"]).write_bytes(raw)
                reference.update(original)

    def test_per_family_coverage_precedes_performance_acceptance(self):
        self.change_artifact(self.evidence["trials"]["GW-REDIS-9001"],
            lambda v: v["normal"][0]["reference"]["metrics"].update(observed=0))
        result = self.assert_failed()
        self.assertNotIn("measurements", result["cells"]["GW-REDIS-9001"]["scenarios"]["normal"])

    def test_threshold_failures_and_nonfinite_counts_fail(self):
        reference = self.evidence["trials"]["GW-CPU-9001"]
        original = reference.copy()
        raw = (self.directory / reference["path"]).read_bytes()
        for metric, value in [("p99_ms", 100), ("collector_cpu_cores", 2), ("node_cpu_cores", 3),
                              ("throughput_per_second", 1), ("unknown_weight", 90),
                              ("expected", 0), ("expected", True), ("lost", -1), ("observed", 101),
                              ("duplicates", 1), ("retention_seconds", 0), ("recovery_seconds", 100)]:
            with self.subTest(metric=metric):
                self.change_artifact(reference, lambda v: v["normal"][0]["candidate"]["metrics"].update({metric: value}))
                self.assert_failed()
                (self.directory / reference["path"]).write_bytes(raw)
                reference.update(original)

    def test_unapproved_or_missing_thresholds_fail(self):
        cell = self.plan["cells"]["GW-REDIS-9001"]
        threshold = cell["thresholds"]["coverage_ratio"]
        for field, value in [("owner", ""), ("unit", "ms"), ("value", float("nan")),
                             ("comparator", "max"), ("rationale", "")]:
            with self.subTest(field=field):
                saved = threshold[field]
                threshold[field] = value
                self.assert_failed()
                threshold[field] = saved
        del cell["thresholds"]["loss_ratio"]
        self.assert_failed()

    def test_rollback_requires_exact_restoration_and_accounted_delivery(self):
        reference = self.evidence["trials"]["GW-LOG-9001"]
        self.change_artifact(reference, lambda v: v["rollback"][0]["candidate"]["delivery"].update(delivered=0))
        self.assert_failed()

    def test_suite_pass_cannot_hide_failed_or_unbound_cell(self):
        reference = self.evidence["suites"]["replacement"]["result"]
        self.change_artifact(reference, lambda v: v["cells"]["GW-REDIS-9001"]["scenarios"]["normal"].update(verdict="skipped"))
        self.assert_failed()

    def test_backend_report_must_cover_all_required_cells(self):
        reference = self.evidence["suites"]["backends"]["result"]
        self.change_artifact(reference, lambda v: v["backends"].pop("logs"))
        self.assert_failed()

    def test_missing_consumer_and_wrong_native_response_fail(self):
        reference = self.evidence["consumers"]["GQ-0001"]
        self.change_artifact(reference, lambda v: v.update(response={"count": 99}))
        self.assert_failed()
        del self.evidence["consumers"]["GQ-0001"]
        self.assert_failed()

    def test_fixture_reports_cannot_satisfy_recorded_execution_mode(self):
        self.plan["fixture"] = False
        self.assert_failed()

    def test_hash_mismatch_and_paths_outside_bundle_fail(self):
        reference = self.plan["publication"]["runbook"]
        (self.directory / reference["path"]).write_text("tampered")
        self.assert_failed()
        for path in ["../outside", "/etc/passwd"]:
            reference["path"] = path
            self.assert_failed()

    def test_missing_original_recording_fails_even_with_suite_pass(self):
        self.evidence["records"] = {}
        self.assert_failed()

    def test_public_contract_cannot_omit_required_cells(self):
        self.change_artifact(self.plan["publication"]["public_contract"], lambda v: v["cells"].pop("GW-REDIS-9001"))
        self.assert_failed()

    def test_failed_quality_gate_or_unexplained_skip_fails(self):
        reference = self.evidence["quality"]
        self.change_artifact(reference, lambda v: v.update(skips={"E_NAVIGATOR_SKIP_DOCKER": ""}))
        self.assert_failed()
        self.change_artifact(reference, lambda v: v.update(skips={}, exit_code=1))
        self.assert_failed()

    def test_trial_requires_exact_settings_and_equal_independent_oracles(self):
        self.plan["cells"]["GW-REDIS-9001"]["settings"].pop("sample_period_nanos")
        self.assert_failed()

    def test_reference_cannot_use_another_oracle_count(self):
        self.change_artifact(self.evidence["trials"]["GW-REDIS-9001"],
            lambda v: v["normal"][0]["reference"]["metrics"].update(expected=1, observed=1))
        self.assert_failed()

    def test_forged_suite_pass_cannot_override_invalid_raw_capture(self):
        refs = self.evidence["suites"]["replacement"]
        self.change_artifact(refs["evidence"], lambda v: v["cells"]["GW-REDIS-9001"]["normal"]["counters"].update(capture_loss=1))
        # Keep all declared digests consistent. Replaying the original assertions
        # must still detect the failed counter instead of trusting PASS metadata.
        sys.path.insert(0, str(ROOT / "scripts"))
        import qualify_replacement as suite
        capture = json.loads((self.directory / refs["evidence"]["path"]).read_text())
        def update_report(report):
            report["sha256"]["capture"] = suite.digest(capture)
            report["cells"]["GW-REDIS-9001"]["scenarios"]["normal"]["sha256"]["evidence"] = suite.digest(capture["cells"]["GW-REDIS-9001"]["normal"])
        self.change_artifact(refs["result"], update_report)
        self.assert_failed()

    def test_invalid_baseline_quantiles_cannot_hide_candidate_latency(self):
        self.change_artifact(self.evidence["trials"]["GW-REDIS-9001"],
            lambda v: v["normal"][0]["no-agent"]["metrics"].update(p50_ms=100))
        self.assert_failed()

    def test_invalid_baseline_count_types_fail(self):
        self.change_artifact(self.evidence["trials"]["GW-REDIS-9001"],
            lambda v: v["normal"][0]["no-agent"]["metrics"].update(expected=True))
        self.assert_failed()

    def test_recorded_report_archive_replays_without_qualification(self):
        import qualify_replacement as suite
        # Exercise recorded-mode schema handling with synthetic files. Relabeling
        # these test records never establishes execution or approval authenticity.
        self.plan["fixture"] = False
        auth = {"approved": True, "target": self.plan["environment"]["target"],
                "owner": "test-only", "reference": "synthetic-schema-test"}
        self.plan["authorization"] = write_artifact(self.directory, "authorization.json", auth)
        for name, refs in self.evidence["suites"].items():
            def update_manifest(manifest):
                manifest.update(fixture=False, blocked_inputs=[])
                if name != "backends":
                    for cell in manifest["cells"].values():
                        cell.update(support="implemented", approval="synthetic-schema-test")
            self.change_artifact(refs["manifest"], update_manifest)
            manifest = json.loads((self.directory / refs["manifest"]["path"]).read_text())
            def update_report(report):
                report.update(mode="live-query", blocked_inputs=[])
                report["sha256"].update(manifest=suite.digest(manifest), authorization=suite.digest(auth))
            self.change_artifact(refs["result"], update_report)
            refs["authorization"] = self.plan["authorization"]
        code, result = self.run_campaign()
        self.assertEqual(code, 0)
        self.assertEqual(result["mode"], "recorded-evidence")
        self.assertFalse(result["replacement_qualified"])
        self.assertTrue(result["review_required"])
        auth["target"] = "wrong-target"
        self.plan["authorization"] = write_artifact(self.directory, "authorization.json", auth)
        self.assert_failed()

    def test_every_additional_approved_threshold_is_enforced(self):
        cell = self.plan["cells"]["GW-REDIS-9001"]
        cell["thresholds"]["allocation_bytes_per_second"] = {
            "category": "TH-OVERHEAD", "unit": "bytes/second", "comparator": "max", "value": 100,
            "owner": "fixture-owner", "reference": "fixture-approval", "rationale": "fixture allocation budget"}
        reference = self.evidence["trials"]["GW-REDIS-9001"]
        def allocations(trials):
            for repetitions in trials.values():
                for arms in repetitions:
                    for run in arms.values():
                        run["metrics"]["allocation_bytes_per_second"] = 50
        self.change_artifact(reference, allocations)
        self.assertEqual(self.run_campaign()[0], 0)
        self.change_artifact(reference, lambda v: v["sustained-load"][0]["candidate"]["metrics"].update(allocation_bytes_per_second=101))
        self.assert_failed()

    def test_optional_cell_does_not_require_production_trials(self):
        cell_id = "GW-REDIS-9001"
        self.plan["cells"][cell_id]["requiredness"] = "optional"
        for name in ["ledger", "public_contract"]:
            self.change_artifact(self.plan["publication"][name], lambda v: v["cells"].update({cell_id: "optional"}))
        refs = self.evidence["suites"]["replacement"]
        self.change_artifact(refs["manifest"], lambda v: v["cells"][cell_id].update(requiredness="optional"))
        import qualify_replacement as suite
        manifest = json.loads((self.directory / refs["manifest"]["path"]).read_text())
        self.change_artifact(refs["result"], lambda v: (v["sha256"].update(manifest=suite.digest(manifest)),
                                                      v["cells"][cell_id].update(requiredness="optional")))
        del self.evidence["trials"][cell_id]
        code, result = self.run_campaign()
        self.assertEqual(code, 0)
        self.assertEqual(result["cells"][cell_id]["verdict"], "optional-not-evaluated")

    def test_excluded_log_family_does_not_require_log_backend_or_trials(self):
        import qualify_backends as backend
        import qualify_replacement as suite
        cell_id = "GW-LOG-9001"
        self.plan["cells"][cell_id].update(requiredness="excluded", exclusion="fixture exclusion")
        for name in ["ledger", "public_contract"]:
            self.change_artifact(self.plan["publication"][name], lambda v: v["cells"].update({cell_id: "excluded"}))
        refs = self.evidence["suites"]["replacement"]
        self.change_artifact(refs["manifest"], lambda v: v["cells"][cell_id].update(
            requiredness="excluded", exclusion="fixture exclusion", approval="fixture approval"))
        manifest, capture = [json.loads((self.directory / refs[key]["path"]).read_text()) for key in ["manifest", "evidence"]]
        refs["result"].update(write_artifact(self.directory, refs["result"]["path"], suite.evaluate(manifest, capture)))
        refs = self.evidence["suites"]["backends"]
        for name in ["manifest", "evidence"]:
            self.change_artifact(refs[name], lambda v: v["backends"].pop("logs"))
        manifest, capture = [json.loads((self.directory / refs[key]["path"]).read_text()) for key in ["manifest", "evidence"]]
        refs["result"].update(write_artifact(self.directory, refs["result"]["path"], backend.evaluate(manifest, capture)))
        del self.evidence["trials"][cell_id]
        self.assertEqual(self.run_campaign()[0], 0)

    def test_invalid_campaign_writes_failed_result_without_qualification(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            plan, evidence, output = [directory / name for name in ["plan.json", "evidence.json", "result.json"]]
            plan.write_text("{}")
            evidence.write_text("{}")
            run = subprocess.run([sys.executable, str(ROOT / "scripts/qualify_campaign.py"),
                                  "--plan", str(plan), "--evidence", str(evidence),
                                  "--artifacts", tmp, "--output", str(output)], capture_output=True)
            self.assertEqual(run.returncode, 1, run.stderr)
            result = json.loads(output.read_text())
            self.assertEqual(result["verdict"], "failed")
            self.assertFalse(result["replacement_qualified"])


if __name__ == "__main__":
    unittest.main()
