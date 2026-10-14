"""Qualification evidence must not depend on a customer's cell namespace."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import qualify_backends as backend
import qualify_cpu_profiles as cpu
import qualify_replacement as suite
from backend_fixture import fixture as backend_fixture
from cpu_qualification_test import fixture as cpu_fixture
from replacement_fixture import fixture as replacement_fixture


def namespace(value, prefix):
    if isinstance(value, dict):
        return {namespace(key, prefix): namespace(item, prefix) for key, item in value.items()}
    if isinstance(value, list):
        return [namespace(item, prefix) for item in value]
    if isinstance(value, str):
        parts = value.split("-")
        if len(parts) >= 3 and parts[1] in suite.FAMILIES and parts[2].isdigit():
            return "-".join([prefix, *parts[1:]])
    return value


class StandaloneQualificationTests(unittest.TestCase):
    def accepted(self, operation, *values):
        try:
            return operation(*values)
        except ValueError as error:
            self.fail(f"operator-defined cell namespace was rejected: {error}")

    def test_operator_namespaces_preserve_cpu_quality(self):
        for prefix in ["WC", "OPS", "TEAM_2", "ABCDEFGHIJKLMNOP"]:
            with self.subTest(prefix=prefix):
                result = self.accepted(cpu.qualify, *[namespace(value, prefix) for value in cpu_fixture()])
                self.assertEqual(set(result), {f"{prefix}-CPU-0001", f"{prefix}-CPU-0002"})
                self.assertTrue(all(cell["useful_weight_nanos"] == 100 for cell in result.values()))

    def test_operator_namespaces_preserve_replacement_and_backend_assertions(self):
        for prefix in ["WC", "OPS", "TEAM_2", "ABCDEFGHIJKLMNOP"]:
            with self.subTest(prefix=prefix):
                result = self.accepted(suite.evaluate, *[namespace(value, prefix) for value in replacement_fixture()])
                self.assertEqual(result["verdict"], "passed")
                self.assertFalse(result["replacement_qualified"])
                plan, evidence = [namespace(value, prefix) for value in backend_fixture()]
                self.accepted(backend.validate, plan)
                self.assertEqual(backend.evaluate(plan, evidence)["verdict"], "passed")

    def test_invalid_namespaces_remain_rejected(self):
        for prefix in ["", "lowercase", "A" * 17, "WITH-SEP", "WITH SPACE"]:
            with self.subTest(prefix=prefix):
                with self.assertRaises(ValueError):
                    cpu.validate_cells(namespace(cpu_fixture()[0], prefix))
                with self.assertRaises(ValueError):
                    suite.validate(namespace(replacement_fixture()[0], prefix))


if __name__ == "__main__":
    unittest.main()
