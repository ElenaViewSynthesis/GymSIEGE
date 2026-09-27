import importlib.util
import unittest
from collections import Counter
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
