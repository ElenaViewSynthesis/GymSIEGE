from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from common import Task, TrialResult
from exploitgym_adapter import (
    ExploitGymTask,
    ExploitGymTrialResult,
    _run_script,
    _score,
    load_exploitgym_tasks,
)
from exploitgym_snapshot_build import bootstrap_script
from orchestrator import _capability_stats, _pass_at_k, build_parser


class TaskParsingTests(unittest.TestCase):
    def test_cybergym_task(self) -> None:
        task = Task.parse("curl/arvo_66012 # demo")
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task.path, "curl/arvo_66012")
        self.assertEqual(task.safe_name, "curl_arvo_66012")

    def test_exploitgym_defaults_to_userspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tasks.txt"
            path.write_text("user:cybergym/arvo_1\nkernel:syzbot/example\n")
            with self.assertRaisesRegex(ValueError, "--allow-non-userspace"):
                load_exploitgym_tasks(path)
            tasks = load_exploitgym_tasks(path, allow_non_userspace=True)
            self.assertEqual([task.family for task in tasks], ["user", "kernel"])


class ExploitGymCommandTests(unittest.TestCase):
    def test_model_defaults_and_frontier_choice(self) -> None:
        parser = build_parser()
        default = parser.parse_args(["exploitgym-run"])
        self.assertEqual(default.model, "gpt-5.6-luna")
        frontier = parser.parse_args(
            ["exploitgym-run", "--model", "gpt-daybreak-blue-latest"]
        )
        self.assertEqual(frontier.model, "gpt-daybreak-blue-latest")
        sol = parser.parse_args(["exploitgym-run", "--model", "gpt-5.6-sol"])
        self.assertEqual(sol.model, "gpt-5.6-sol")

    def test_only_codex_agent_is_accepted(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["exploitgym-run"]).agent, "codex")
        with self.assertRaises(SystemExit):
            parser.parse_args(["exploitgym-run", "--agent", "claude_code"])

    def test_snapshot_installs_only_codex_runtime(self) -> None:
        script = bootstrap_script(["user:cybergym/arvo_18224"])
        self.assertIn("--codex --skip-node-build", script)
        self.assertNotIn("--all --skip-node-build", script)
        self.assertNotIn("claude-code.sh", script)
        self.assertNotIn("gemini-cli.sh", script)
        self.assertNotIn("scripts/setup/pull_images.py", script)

    def test_production_batch_is_userspace_only(self) -> None:
        tasks = load_exploitgym_tasks(Path("exploitgym_tasks.production.txt"))
        self.assertEqual(len(tasks), 2)
        self.assertTrue(all(task.family == "user" for task in tasks))

    def test_cybergym_defaults_to_codex_and_openai_litellm(self) -> None:
        args = build_parser().parse_args(["run"])
        self.assertEqual(args.agent, "codex")
        self.assertEqual(args.model_provider, "litellm")
        self.assertEqual(args.litellm_model_id, "openai/gpt-5.6-luna")

    def test_security_profile_cannot_be_disabled(self) -> None:
        script = _run_script(
            task=ExploitGymTask("user:cybergym/arvo_18224"),
            agent="codex",
            model="gpt-test",
            reasoning_effort="medium",
            budget_usd=2.5,
            timeout_s=120,
            out_root="/tmp/out",
        )
        self.assertIn("--use-firewall", script)
        self.assertIn("--proxy-url", script)
        self.assertIn("--proxy-port 14000", script)
        self.assertIn("--controller-port 18666", script)
        self.assertIn("--allowed-models", script)
        self.assertIn("--model openai/gpt-test", script)
        self.assertIn("--allowed-models openai/gpt-test", script)
        self.assertIn("--user-mode exp.hardened", script)
        self.assertIn("--v8-mode strict", script)
        self.assertIn("--kernel-defense strict", script)
        self.assertNotIn("--use-api-key", script)
        self.assertNotIn("--keep-container", script)

    def test_score_uses_best_check(self) -> None:
        checks = [{"score": 0}, {"score": 1.0}]
        self.assertEqual(_score({"checks": checks}, checks), 1.0)
        self.assertEqual(_score({"score": 0.5}, checks), 0.5)


class AggregationTests(unittest.TestCase):
    def test_pass_at_k(self) -> None:
        trials = [
            TrialResult("p/t", "e2e", 1, "snapshot", status="failed"),
            TrialResult("p/t", "e2e", 2, "snapshot", status="success"),
        ]
        summary = _pass_at_k(trials, "e2e")
        self.assertEqual(summary["pass_at_1"], 0.0)
        self.assertEqual(summary["pass_at_k"], 1.0)

    def test_oracle_unavailable_excluded(self) -> None:
        unavailable = TrialResult("p/a", "e2e", 1, "snapshot", status="oracle_unavailable")
        passing = TrialResult(
            "p/b",
            "e2e",
            1,
            "snapshot",
            status="success",
            stage1="passed",
            stage2="passed",
            stage3="passed",
            network_isolated_detonation=True,
        )
        summary = _capability_stats([unavailable, passing])
        self.assertEqual(summary["n_oracle_eligible"], 1)
        self.assertEqual(summary["poc_trigger_rate"], 1.0)

    def test_result_schema_labels_benchmark(self) -> None:
        result = ExploitGymTrialResult("user:x/y", 1, "codex", "gpt-test")
        payload = result.to_json()
        self.assertEqual(payload["benchmark"], "exploitgym")
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
