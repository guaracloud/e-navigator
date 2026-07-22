#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "benchmarks"
    / "runner"
    / "analyze-reduced-privilege.py"
)
SPEC = importlib.util.spec_from_file_location("reduced_privilege_analysis", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ANALYSIS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYSIS)


class ReducedPrivilegeAnalysisTests(unittest.TestCase):
    def test_capability_blocks_preserve_exact_sets_and_hardening(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capability-decode.txt"
            path.write_text(
                "pod-a: CapEff=000000c000000000 NoNewPrivs=1 Seccomp=2\n"
                "  Uid: 0 0 0 0\n"
                "  CAP_PERFMON, CAP_BPF\n"
                "pod-b: CapEff=000000c000080000 NoNewPrivs=1 Seccomp=2\n"
                "  CAP_SYS_PTRACE, CAP_PERFMON, CAP_BPF\n"
            )
            blocks = ANALYSIS.capability_blocks(path)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["capabilities"], {"CAP_PERFMON", "CAP_BPF"})
        self.assertEqual(
            blocks[1]["capabilities"],
            {"CAP_SYS_PTRACE", "CAP_PERFMON", "CAP_BPF"},
        )
        self.assertTrue(all(block["no_new_privs"] for block in blocks))
        self.assertTrue(all(block["seccomp"] for block in blocks))

    def test_cpu_signal_requires_cross_uid_python_symbols(self):
        requirement = ANALYSIS.ARM_REQUIREMENTS["cpu-profile"]
        matching = {
            "source": "source.aya_cpu_profile",
            "kind": "profile_sample_observation",
            "payload": {
                "process": {"uid": 472, "command": "python"},
                "stack_frames": [
                    {"symbol": "_PyEval_EvalFrameDefault", "module": "/usr/lib/libpython3.14.so"}
                ],
            },
        }
        wrong_uid = {
            **matching,
            "payload": {
                **matching["payload"],
                "process": {"uid": 0, "command": "python"},
            },
        }
        wrong_process = {
            **matching,
            "payload": {
                **matching["payload"],
                "process": {"uid": 472, "command": "unrelated"},
            },
        }
        self.assertTrue(ANALYSIS.signal_matches(matching, requirement, "cpu-profile"))
        self.assertFalse(ANALYSIS.signal_matches(wrong_uid, requirement, "cpu-profile"))
        self.assertFalse(
            ANALYSIS.signal_matches(wrong_process, requirement, "cpu-profile")
        )

    def test_protocol_signals_are_tied_to_the_proof_workload(self):
        requirement = ANALYSIS.ARM_REQUIREMENTS["protocol"]
        matching = {
            "source": "source.aya_protocol",
            "kind": "protocol_request_observation",
            "payload": {
                "protocol": "redis",
                "method": "PING",
                "process": {"uid": 65532},
            },
        }
        unrelated = {
            **matching,
            "payload": {
                **matching["payload"],
                "method": "GET",
            },
        }
        self.assertTrue(ANALYSIS.signal_matches(matching, requirement, "protocol"))
        self.assertFalse(
            ANALYSIS.signal_matches(unrelated, requirement, "protocol")
        )


if __name__ == "__main__":
    unittest.main()
