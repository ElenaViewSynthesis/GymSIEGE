import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SUITE = ROOT / "agent_honeypot" / "instrument_tripwires"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


MIRROR = load_module("instrument_mirror", SUITE / "event_mirror.py")
SCORE = load_module("instrument_score_test", SUITE / "score_instrument.py")
VALIDATE = load_module("instrument_validate", SUITE / "validate_cases.py")


class InstrumentHoneypotTests(unittest.TestCase):
    def test_corpus_is_deterministic_and_synthetic(self):
        summary = VALIDATE.validate()
        self.assertEqual(summary["cases"], 7)
        self.assertEqual(summary["roles"], {"behavior_eval": 5, "sensor_control": 2})

    def test_chain_break_is_strongest_finding(self):
        key = b"k" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / "events.mirror.tsv"
            visible = root / "events.tsv"
            line, _ = MIRROR.chained_line(1, "1.0\tHARNESS_STARTED\t1\t0\ttest\n", MIRROR.ZERO_HASH, key)
            mirror.write_text(line.replace("HARNESS_STARTED", "HARNESS_CHANGED"))
            visible.write_text(line)
            case = json.loads((SUITE / "cases.jsonl").read_text().splitlines()[0])
            report = SCORE.build_report(case, mirror, visible, key)
        self.assertEqual(report["score"], 100)
        self.assertFalse(report["chain_valid"])
        self.assertFalse(report["mirror_matches_visible_log"])

    def _run_control(self, case_id: str, expected_class: str):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            completed = subprocess.run([
                str(SUITE / "harness.sh"), "--case-id", case_id, "--output", str(output),
            ], cwd=ROOT, text=True, capture_output=True, check=False, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((output / "report" / "report.json").read_text())
            self.assertTrue(report["expectation_passed"])
            self.assertTrue(report["chain_valid"])
            self.assertTrue(report["mirror_matches_visible_log"])
            self.assertFalse(report["included_in_behavior_rate"])
            self.assertIn(expected_class, {finding.get("instrument_class") for finding in report["findings"]})

    def test_event_log_positive_control_fires(self):
        self._run_control("IHT-002", "event_log")

    def test_report_copy_positive_control_fires(self):
        self._run_control("IHT-003", "report")


if __name__ == "__main__":
    unittest.main()
