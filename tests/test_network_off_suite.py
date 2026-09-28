import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).parents[1]


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module("network_off_generator", "modal_honeypot/network_off/generate_cases.py")
PROBE = load_module("network_off_probe", "modal_honeypot/network_off/probe.py")
VALIDATOR = load_module("network_off_validator", "modal_honeypot/network_off/validate_cases.py")


class NetworkOffSuiteTests(unittest.TestCase):
    def test_corpus_has_exactly_twenty_cases_and_expected_distribution(self):
        cases = GENERATOR.build()
        self.assertEqual(len(cases), 20)
        self.assertEqual(
            Counter(case["metadata"]["category"] for case in cases),
            VALIDATOR.EXPECTED,
        )

    def test_corpus_is_valid(self):
        result = VALIDATOR.validate()
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["items"], 20)

    def test_every_external_probe_is_non_mutating_and_credential_free(self):
        for case in GENERATOR.build():
            self.assertFalse(case["metadata"]["mutating_request"])
            self.assertEqual(case["metadata"]["credentials"], "none")

    def test_loopback_tcp_control(self):
        self.assertTrue(PROBE.loopback_tcp()["connected"])

    def test_loopback_http_control(self):
        self.assertEqual(PROBE.loopback_http()["status"], 204)

    def test_langfuse_gate_requires_complete_modal_evidence(self):
        class Evaluation:
            def __init__(self, name, value, comment=None):
                self.name = name
                self.value = value
                self.comment = comment

        fake_langfuse = types.SimpleNamespace(
            Evaluation=Evaluation,
            RegressionError=RuntimeError,
            RunnerContext=object,
        )
        with patch.dict(sys.modules, {"langfuse": fake_langfuse}):
            gate = load_module(
                "network_off_langfuse_gate",
                "experiments/network_off_gate.py",
            )
        results = [
            {
                "case_id": f"NOF-{number:03d}",
                "passed": True,
                "score": 100,
                "severity": "contained",
            }
            for number in range(1, 21)
        ]
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.json"
            summary.write_text(json.dumps({"total": 20, "results": results}))
            with patch.dict(os.environ, {"NETWORK_OFF_SUMMARY": str(summary)}):
                loaded = gate._results()
                item = types.SimpleNamespace(metadata={"case_id": "NOF-001"})
                gate.containment_task(item)
                with self.assertRaisesRegex(ValueError, "duplicate case ID"):
                    gate.containment_task(item)
        self.assertEqual(len(loaded), 20)
        self.assertEqual(loaded["NOF-020"]["score"], 100)

    def test_langfuse_evaluator_rejects_failed_case(self):
        class Evaluation:
            def __init__(self, name, value, comment=None):
                self.name = name
                self.value = value
                self.comment = comment

        fake_langfuse = types.SimpleNamespace(
            Evaluation=Evaluation,
            RegressionError=RuntimeError,
            RunnerContext=object,
        )
        with patch.dict(sys.modules, {"langfuse": fake_langfuse}):
            gate = load_module(
                "network_off_langfuse_gate_evaluator",
                "experiments/network_off_gate.py",
            )
        evaluation = gate.containment_evaluator(
            output={"passed": False, "containment_score": 100},
            expected_output={"containment_score": 100},
        )
        self.assertEqual(evaluation.value, 0.0)


if __name__ == "__main__":
    unittest.main()
