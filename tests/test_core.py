from __future__ import annotations

import argparse
import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common import Task, TrialResult, sandbox_secret_refs
from configure_secrets import credential_value
from exploitgym_adapter import (
    EXPLOITGYM_CONTROLLER_PORT,
    EXPLOITGYM_PROXY_PORT,
    ExploitGymTask,
    ExploitGymTrialResult,
    _cleanup_exploitgym_sandbox,
    _run_script,
    _score,
    load_exploitgym_tasks,
)
from exploitgym_snapshot_build import bootstrap_script
from orchestrator import (
    _capability_stats,
    _pass_at_k,
    _run_exploitgym_job,
    _write_exploitgym_results,
    build_parser,
)
from snapshot_build import BOOTSTRAP_SH, CLEANUP_AND_DISK_SH


class TaskParsingTests(unittest.TestCase):
    def test_cybergym_task(self) -> None:
        task = Task.parse("curl/arvo_66012 # demo")
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task.path, "curl/arvo_66012")
        self.assertEqual(task.safe_name, "curl_arvo_66012")

    def test_huggingface_secret_reference(self) -> None:
        previous = os.environ.get("GYMSIEGE_HF_SECRET_NAME")
        os.environ["GYMSIEGE_HF_SECRET_NAME"] = "test-hf-secret"
        try:
            self.assertEqual(
                sandbox_secret_refs(("HF_TOKEN",)),
                {"HF_TOKEN": "test-hf-secret"},
            )
        finally:
            if previous is None:
                os.environ.pop("GYMSIEGE_HF_SECRET_NAME", None)
            else:
                os.environ["GYMSIEGE_HF_SECRET_NAME"] = previous

    def test_huggingface_credential_uses_wsl_login_cache(self) -> None:
        with patch.dict(os.environ, {"HF_TOKEN": ""}), patch(
            "configure_secrets.get_token", return_value="cached-token"
        ):
            self.assertEqual(
                credential_value("huggingface", "HF_TOKEN"),
                "cached-token",
            )

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
        self.assertEqual(sol.trial_timeout, 7200)
        selected = parser.parse_args(
            ["exploitgym-run", "--task", "user:cybergym/arvo_66311"]
        )
        self.assertEqual(selected.task, ["user:cybergym/arvo_66311"])

    def test_stalled_task_diagnostic_command(self) -> None:
        args = build_parser().parse_args(
            [
                "exploitgym-run",
                "--task",
                "user:cybergym/arvo_66311",
                "--k",
                "1",
                "--max-parallel",
                "1",
                "--agent",
                "codex",
                "--model",
                "gpt-5.6-sol",
                "--reasoning-effort",
                "medium",
                "--budget-usd",
                "5",
                "--timeout",
                "3600",
                "--trial-timeout",
                "5400",
                "--cleanup-timeout",
                "360",
            ]
        )
        self.assertEqual(args.task, ["user:cybergym/arvo_66311"])
        self.assertEqual(args.model, "gpt-5.6-sol")
        self.assertEqual(args.trial_timeout, 5400)
        self.assertEqual(args.cleanup_timeout, 360)

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

    def test_cybergym_snapshot_uses_current_transfer_and_disk_hygiene(self) -> None:
        source = Path("snapshot_build.py").read_text(encoding="utf-8")
        self.assertIn("Resources(cpu=2, memory=4, disk=10)", source)
        self.assertNotIn("docker.io docker-cli", BOOTSTRAP_SH)
        self.assertIn("huggingface_hub[hf_xet]", BOOTSTRAP_SH)
        self.assertIn("HF_XET_HIGH_PERFORMANCE=1", BOOTSTRAP_SH)
        self.assertNotIn("HF_HUB_ENABLE_HF_TRANSFER", BOOTSTRAP_SH)
        self.assertIn("apt-get clean", CLEANUP_AND_DISK_SH)
        self.assertIn("df -h /", CLEANUP_AND_DISK_SH)
        self.assertIn("df -i /", CLEANUP_AND_DISK_SH)
        self.assertIn("available_bytes", CLEANUP_AND_DISK_SH)
        rendered = CLEANUP_AND_DISK_SH.format(
            repo_dir="/tmp/cybergym", minimum_free_bytes=123
        )
        self.assertIn('${HF_HOME:-$HOME/.cache/huggingface}/xet', rendered)
        self.assertIn("minimum_bytes=123", rendered)

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

    def test_restore_hygiene_covers_default_and_configured_ports(self) -> None:
        self.assertNotEqual(EXPLOITGYM_PROXY_PORT, 4000)
        self.assertNotEqual(EXPLOITGYM_CONTROLLER_PORT, 8666)
        source = Path("exploitgym_adapter.py").read_text(encoding="utf-8")
        self.assertIn(
            "{4000, 8666, EXPLOITGYM_PROXY_PORT, EXPLOITGYM_CONTROLLER_PORT}",
            source,
        )
        self.assertIn("ttl_minutes=SANDBOX_SAFETY_TTL_MINUTES", source)
        self.assertIn('stage=result_collection start', source)

    def test_score_uses_best_check(self) -> None:
        checks = [{"score": 0}, {"score": 1.0}]
        self.assertEqual(_score({"checks": checks}, checks), 1.0)
        self.assertEqual(_score({"score": 0.5}, checks), 0.5)


class AggregationTests(unittest.TestCase):
    def test_interrupted_exploitgym_result_is_not_marked_live(self) -> None:
        import orchestrator

        previous = orchestrator.EXPLOITGYM_RESULTS_JSON
        with tempfile.TemporaryDirectory() as tmp:
            orchestrator.EXPLOITGYM_RESULTS_JSON = Path(tmp) / "results.json"
            try:
                _write_exploitgym_results(
                    [],
                    {"k": 1, "expected_trials": 2},
                    complete=False,
                    status="interrupted",
                    run_error="cancelled",
                )
                payload = json.loads(orchestrator.EXPLOITGYM_RESULTS_JSON.read_text())
            finally:
                orchestrator.EXPLOITGYM_RESULTS_JSON = previous
        self.assertEqual(payload["status"], "interrupted")
        self.assertEqual(payload["run_error"], "cancelled")

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


class ExploitGymTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_outer_timeout_returns_structured_progress_after_cleanup(self) -> None:
        async def stalled_trial(*args, result, **kwargs):
            result.started_at = "2026-09-02T00:00:00+00:00"
            result.last_stage = "evaluation"
            result.stage_timings["evaluation"] = {
                "started_at": "2026-09-02T00:00:00+00:00",
                "finished_at": None,
                "duration_s": None,
                "status": "running",
            }
            try:
                await asyncio.sleep(60)
            finally:
                result.failure_stage = "evaluation"
                result.stage_timings["evaluation"]["status"] = "interrupted"
                result.cleanup_ttl_set = True
                result.cleanup_destroyed = True

        args = argparse.Namespace(
            agent="codex",
            model="gpt-5.6-sol",
            reasoning_effort="medium",
            budget_usd=5.0,
            timeout=30,
            trial_timeout=0.01,
            cleanup_timeout=1,
        )
        progress = ExploitGymTrialResult(
            "user:cybergym/arvo_66311", 1, "codex", "gpt-5.6-sol"
        )
        with patch("orchestrator.run_exploitgym_trial", stalled_trial):
            result = await _run_exploitgym_job(
                object(), ExploitGymTask(progress.task), 1, args, progress
            )
        self.assertIs(result, progress)
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.failure_stage, "evaluation")
        self.assertEqual(result.stage_timings["evaluation"]["status"], "timeout")
        self.assertTrue(result.cleanup_ttl_set)
        self.assertTrue(result.cleanup_destroyed)

    async def test_cleanup_finishes_when_parent_is_cancelled(self) -> None:
        delete_started = asyncio.Event()

        class Sandbox:
            async def set_ttl(self, minutes):
                return None

            async def delete(self, wait=True, timeout=None):
                delete_started.set()
                await asyncio.sleep(0.02)

        result = ExploitGymTrialResult("user:x/y", 1, "codex", "gpt-5.6-sol")
        cleanup = asyncio.create_task(
            _cleanup_exploitgym_sandbox(
                Sandbox(), result, result.task, timeout_s=1
            )
        )
        await delete_started.wait()
        cleanup.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cleanup
        self.assertTrue(result.cleanup_ttl_set)
        self.assertTrue(result.cleanup_destroyed)
        self.assertEqual(result.stage_timings["cleanup"]["status"], "complete")


if __name__ == "__main__":
    unittest.main()
