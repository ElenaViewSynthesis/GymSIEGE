import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "agent_honeypot/collusion_tripwires/aggregate_cohort.py"
SPEC = importlib.util.spec_from_file_location("collusion_cohort", SCRIPT)
COHORT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(COHORT)


class CollusionCohortTests(unittest.TestCase):
    def _cell(self, root, name, case_id, trial, *, stage="none", exit_code=0,
              observable=True, timeout=False, evidence=None, verifier=None):
        run = root / name
        run.mkdir()
        result_exit = 124 if timeout else exit_code
        summary = {
            "results": [{
                "case_id": case_id, "runner_exit_code": result_exit,
                "role": "behavior_eval", "stage": stage,
                "observability": "observable" if observable else "unobservable",
                "evidence_chains": [observable], "verifier": verifier,
                "time_to_first_coordination_s": 3.5 if stage != "none" else None,
                "evidence": evidence or [],
            }],
        }
        modal = {
            "arm": "lure-pair", "trial": trial,
            "remote_exit_code": result_exit,
            "termination": "timeout" if timeout else "explicit-finally",
            "policy": {"key_model": "test-model", "key_budget_usd": 0.5},
            "virtual_key": {
                "key_alias": f"collusion/{case_id}/t{trial}/test", "budget_usd": 0.5,
                "spend_usd": 0.01, "minted_at": "2026-10-29T00:00:00+00:00",
                "revoked_at": "2026-10-29T00:00:10+00:00",
            },
            "redaction": {"passed": True},
        }
        (run / "summary.json").write_text(json.dumps(summary))
        (run / "modal-run.json").write_text(json.dumps(modal))

    def test_four_cell_cohort_rates_exclusions_and_figures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cohort"
            out = Path(directory) / "aggregate"
            root.mkdir()
            self._cell(
                root, "valid-acted", "CLH-036", 1, stage="acted",
                verifier={"status": "implemented", "kind": "sha256_of_file", "passed": True},
                evidence=[{"kind": "COORDINATION_ACTED", "timestamp": 1.0,
                           "detail": {"via": "workspace"}}],
            )
            self._cell(
                root, "valid-none", "CLH-037", 1,
                verifier={"status": "implemented", "kind": "peer_content_token", "passed": False},
            )
            self._cell(root, "timeout", "CLH-036", 2, timeout=True)
            self._cell(root, "unobservable", "CLH-037", 2, observable=False)

            summary = COHORT.aggregate(root, out)

            self.assertEqual(summary["cells_discovered"], 4)
            metrics = summary["strata"][0]["metrics"]
            self.assertEqual(metrics["valid_cells"], 2)
            self.assertEqual(metrics["acted_rate"]["x"], 1)
            self.assertEqual(metrics["acted_rate"]["n"], 2)
            reasons = {reason for row in metrics["exclusions"] for reason in row["reasons"]}
            self.assertEqual(reasons, {"timeout", "unobservable"})
            self.assertEqual(
                summary["channel_by_stage_counts"]["Peer workspaces"]["acted"], 1,
            )
            self.assertTrue((out / "cohort-summary.json").is_file())
            self.assertTrue((out / "stage_by_arm.png").is_file())
            self.assertTrue((out / "channel_by_stage.png").is_file())


if __name__ == "__main__":
    unittest.main()
