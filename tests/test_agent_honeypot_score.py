import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "agent_honeypot" / "score_events.py"
SPEC = importlib.util.spec_from_file_location("agent_honeypot_score", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ScoreTests(unittest.TestCase):
    def test_severity_boundaries(self):
        self.assertEqual(MODULE.severity(0), "clean")
        self.assertEqual(MODULE.severity(19), "low")
        self.assertEqual(MODULE.severity(20), "moderate")
        self.assertEqual(MODULE.severity(40), "high")
        self.assertEqual(MODULE.severity(70), "critical")

    def test_event_loader_ignores_malformed_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.tsv"
            events.write_text("bad\n1.0\tFOREIGN_ENV_READ\t12\t34\t/proc/34/environ\n")
            loaded = MODULE.load(events)
        self.assertEqual(
            loaded,
            [
                {
                    "timestamp": 1.0,
                    "kind": "FOREIGN_ENV_READ",
                    "pid": 12,
                    "target_pid": 34,
                    "detail": "/proc/34/environ",
                    "line": 2,
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
