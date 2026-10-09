#!/usr/bin/env python3
"""Check cross-document inventory and missing-input integrity for Guara."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "documentation/guara-replacement-acceptance.md"
LEDGER = ROOT / "documentation/guara-workload-matrix.md"


def rows(text, prefix):
    return [
        [field.strip() for field in line.strip().strip("|").split("|")]
        for line in text.splitlines()
        if line.startswith(f"| {prefix}")
    ]


class GuaraContractTests(unittest.TestCase):
    def test_inventory_references_owned_inputs_and_ledger(self):
        contract = CONTRACT.read_text()
        ledger = LEDGER.read_text()
        inputs = rows(contract, "IN-")
        ids = [row[0] for row in inputs]
        self.assertEqual(len(ids), len(set(ids)), "input IDs must be unique")
        self.assertTrue(inputs)
        for row in inputs:
            self.assertEqual(len(row), 3)
            self.assertTrue(row[1], f"{row[0]} needs an exact missing input")
            self.assertTrue(row[2], f"{row[0]} needs an owner")
        inventory = rows(contract, "GW-")
        cell_ids = [row[0] for row in inventory]
        self.assertEqual(len(cell_ids), len(set(cell_ids)))
        self.assertEqual(set(cell_ids), {
            "GW-HTTP", "GW-GRPC", "GW-POSTGRESQL", "GW-MYSQL", "GW-REDIS",
            "GW-MONGODB", "GW-KAFKA", "GW-TCP", "GW-CPU", "GW-LOG",
        })
        for row in inventory:
            self.assertEqual(len(row), 3)
            self.assertIn(row[0], ledger, "ledger and contract inventory drift")
            refs = re.findall(r"IN-\d+", row[2])
            self.assertTrue(refs, f"{row[0]} cannot omit its missing inputs")
            self.assertLessEqual(set(refs), set(ids), "unowned input reference")

    def test_all_quality_dimensions_have_owners(self):
        thresholds = rows(CONTRACT.read_text(), "TH-")
        self.assertEqual(
            {row[0] for row in thresholds},
            {"TH-COVERAGE", "TH-STACK", "TH-OVERHEAD", "TH-LATENCY",
             "TH-OUTAGE", "TH-RETENTION", "TH-LOSS"},
        )
        for row in thresholds:
            self.assertEqual(len(row), 3)
            self.assertTrue(row[1])
            self.assertTrue(row[2], f"{row[0]} needs an approving owner role")


if __name__ == "__main__":
    unittest.main()
