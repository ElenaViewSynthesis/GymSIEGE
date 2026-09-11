from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from common import SNAPSHOT_NAME, Task, TrialResult, sandbox_secret_refs
from configure_secrets import HUGGINGFACE_SECRET_HOSTS, credential_value, litellm_hosts
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
    _run_sweep_trial_with_timeout,
    _trial_hit_oom_threshold,
    _write_exploitgym_results,
    build_parser,
    cmd_reap,
)
from snapshot_build import BOOTSTRAP_SH, CLEANUP_AND_DISK_SH, CRASH_LOG_HELPERS_PY


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

    def test_huggingface_secret_hosts_cover_current_transfer_endpoints(self) -> None:
        self.assertEqual(len(HUGGINGFACE_SECRET_HOSTS), len(set(HUGGINGFACE_SECRET_HOSTS)))
        self.assertIn("huggingface.co", HUGGINGFACE_SECRET_HOSTS)
        self.assertIn("us.aws.cdn.hf.co", HUGGINGFACE_SECRET_HOSTS)
        self.assertIn("us.gcp.cdn.hf.co", HUGGINGFACE_SECRET_HOSTS)
        self.assertIn("cas-server.xethub.hf.co", HUGGINGFACE_SECRET_HOSTS)
        self.assertIn("transfer.xethub-eu.hf.co", HUGGINGFACE_SECRET_HOSTS)

    def test_litellm_hosts_derives_from_base_url_not_hardcoded(self) -> None:
        # Unlike Hugging Face/OpenAI's fixed FQDNs, the LiteLLM gateway's host
        # is whatever the developer is currently running (a Cloudflare quick
        # tunnel today) -- hosts=[] here was the real, confirmed-live bug that
        # left the org Secret unscoped, so this must come from the env, not a
        # literal.
        with patch.dict(
            os.environ,
            {"LITELLM_BASE_URL": "https://some-tunnel.trycloudflare.com/v1"},
        ):
            self.assertEqual(litellm_hosts(), ["some-tunnel.trycloudflare.com"])

    def test_litellm_hosts_requires_base_url(self) -> None:
        with patch.dict(os.environ, {"LITELLM_BASE_URL": ""}):
            with self.assertRaises(RuntimeError):
                litellm_hosts()

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
        bootstrap = BOOTSTRAP_SH.format(
            repo_dir="/tmp/cybergym",
            repo_url="https://example.invalid/repo.git",
            tasks=["curl/arvo_66012"],
            dataset="example/dataset",
            crash_log_helpers=CRASH_LOG_HELPERS_PY,
        )
        self.assertIn("[hf_hosts] ", bootstrap)
        self.assertNotIn("{dataset}", bootstrap)
        rendered = CLEANUP_AND_DISK_SH.format(
            repo_dir="/tmp/cybergym", minimum_free_bytes=123
        )
        self.assertIn('${HF_HOME:-$HOME/.cache/huggingface}/xet', rendered)
        self.assertIn("minimum_bytes=123", rendered)

    def test_pins_match_between_bake_and_requirements(self) -> None:
        """Every version pinned in both places must agree.

        The bake sandbox and the local venv have to resolve the same versions or
        the two environments are not comparable. A `huggingface_hub>=1.0.0`
        floor previously left the venv on 1.29.0 while the bake installed
        1.30.0, which cost days of misdirected debugging. Enforced here rather
        than left to a comment, because the comment is what drifted.
        """
        # name (dropping any [extras]) -> pinned version
        pin = re.compile(r"([A-Za-z0-9._-]+)(?:\[[^\]]+\])?==([0-9][^'\"\s]*)")

        def pins(text: str) -> dict[str, str]:
            found = {}
            for line in text.splitlines():
                if line.lstrip().startswith("#"):
                    continue
                for name, version in pin.findall(line):
                    found[name.lower().replace("_", "-")] = version
            return found

        requirements = (
            Path(__file__).resolve().parent.parent / "requirements.txt"
        ).read_text(encoding="utf-8")
        req_pins, bake_pins = pins(requirements), pins(BOOTSTRAP_SH)

        self.assertIn("huggingface-hub", req_pins)
        self.assertIn("huggingface-hub", bake_pins)
        self.assertIn("daytona", req_pins, "the Daytona SDK must be pinned")

        shared = req_pins.keys() & bake_pins.keys()
        self.assertGreaterEqual(
            len(shared), 7, f"expected the sandbox-mirrored set to be pinned, got {sorted(shared)}"
        )
        for name in sorted(shared):
            self.assertEqual(
                req_pins[name],
                bake_pins[name],
                f"{name} pin drifted: requirements.txt=={req_pins[name]} "
                f"but BOOTSTRAP_SH=={bake_pins[name]}",
            )

    def test_crash_log_helpers_execute_correctly(self) -> None:
        """Execute the injected helpers rather than string-matching them.

        The same source string is embedded in BOOTSTRAP_SH and exec'd here, so
        checksum and ETag logic is covered by real execution with no risk of
        the test drifting from the code that ships.
        """
        from snapshot_build import CRASH_LOG_HELPERS_PY

        ns: dict = {}
        exec(CRASH_LOG_HELPERS_PY, ns)
        git_blob_sha1, normalize_etag = ns["git_blob_sha1"], ns["normalize_etag"]

        # `git hash-object` for "hello\n" is a well-known constant
        self.assertEqual(
            git_blob_sha1(b"hello\n"), "ce013625030ba8dba906f756967f9e9ca394464a"
        )
        self.assertEqual(
            git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        )

        sha = "ce013625030ba8dba906f756967f9e9ca394464a"
        self.assertEqual(normalize_etag(f'"{sha}"'), sha)
        self.assertEqual(normalize_etag(f'W/"{sha}"'), sha)
        self.assertEqual(normalize_etag(sha.upper()), sha)
        # not a git blob sha: LFS multipart etag, empty, or absent
        self.assertIsNone(normalize_etag('"abc-123"'))
        self.assertIsNone(normalize_etag(""))
        self.assertIsNone(normalize_etag(None))

        # a mismatch must be detectable, not silently accepted
        self.assertNotEqual(git_blob_sha1(b"tampered\n"), sha)

    def test_crash_log_report_is_surfaced_even_on_success(self) -> None:
        """A report nobody sees is the same as no report.

        The bootstrap runs with log_output=False and the failure tail only
        fires on non-zero exit, so without an explicit marker rule the
        [crash_logs] JSON is computed in the sandbox and discarded.
        """
        from snapshot_build import CRASH_LOG_REPORT_JSON, EXEC_MARKERS

        self.assertIn("[crash_logs] ", EXEC_MARKERS)
        self.assertIn("[hf_hosts] ", EXEC_MARKERS)
        self.assertEqual(EXEC_MARKERS["[crash_logs] "], CRASH_LOG_REPORT_JSON)

    def test_crash_logs_are_fetched_separately_and_warn_without_failing(self) -> None:
        """crash.log cannot go through huggingface_hub on this Daytona target.

        It is plain-git, served as a direct 200 with no X-Linked-Size, so
        Content-Length is the only size the client can use -- and the sandbox
        network path drops it. The bake skips those files in
        snapshot_download and fetches them directly, verifying each against
        the git blob SHA-1 that HF returns as the ETag.
        """
        bootstrap = BOOTSTRAP_SH.format(
            repo_dir="/tmp/cybergym",
            repo_url="https://example.invalid/repo.git",
            tasks=["curl/arvo_66012"],
            dataset="example/dataset",
            crash_log_helpers=CRASH_LOG_HELPERS_PY,
        )
        # The unsizable set is MEASURED, never assumed from an extension.
        # Hardcoding "**/crash.log" passed a 3-task validation and then failed
        # the 20-task bake, because another file class was affected further in.
        self.assertNotIn("**/crash.log", bootstrap)
        self.assertIn("ignore_patterns=needs_direct_fetch", bootstrap)
        self.assertIn("x-linked-size", bootstrap)
        self.assertIn("selected_files", bootstrap)
        self.assertIn("git_blob_sha1", bootstrap)
        self.assertIn("[crash_logs] ", bootstrap)
        # non-fatal by design: warn, never abort the bake
        self.assertIn("WARN", bootstrap)
        self.assertNotIn("raise RuntimeError(\"crash", bootstrap)
        self.assertNotIn("sys.exit(1)", bootstrap.split("crash_logs")[-1])

    def test_demo_task_set_fits_the_snapshot_disk_ceiling(self) -> None:
        """The demo set exists because the pinned set cannot be snapshotted.

        Capture makes sysbox rsync /var/lib/docker into the sandbox's own
        disk, hard-capped at 10 GiB. The 20 pinned tasks need 16 distinct
        images totalling 74.76 GB, so they never fit. The demo set is three
        tasks whose images total ~5.7 GB.
        """
        from snapshot_build import build_parser as bake_parser, resolve_options

        tasks, name, _ = resolve_options(
            bake_parser().parse_args(
                ["--tasks-file", "tasks.demo.txt", "--snapshot-name", "gymsiege-demo"]
            )
        )
        self.assertEqual(len(tasks), 3, "demo set must stay at three tasks to fit 10 GiB")
        self.assertEqual(name, "gymsiege-demo")

        # the three largest offenders must never be in the demo set
        for excluded in (
            "ffmpeg/oss-fuzz_385167047",   # 36.2 GB alone
            "binutils/arvo_47101",
            "binutils/arvo_61822",
        ):
            self.assertNotIn(excluded, tasks)

        # default path is untouched: 20-task main set + 2-task stretch set
        pinned, name, _ = resolve_options(bake_parser().parse_args([]))
        self.assertEqual(len(pinned), 22)
        self.assertEqual(name, SNAPSHOT_NAME)

    def test_limited_bake_cannot_publish_the_canonical_snapshot(self) -> None:
        """A truncated bake must never be published as `gymsiege-toolchain`.

        Trials restore from that snapshot by name and demo.sh skips baking
        when it is ACTIVE, so a snapshot missing 19 of 20 tasks' data would be
        silently treated as complete. Refused outright rather than warned.
        """
        from snapshot_build import build_parser as bake_parser, resolve_options

        parser = bake_parser()

        with self.assertRaises(SystemExit):
            resolve_options(parser.parse_args(["--limit", "1"]))
        with self.assertRaises(SystemExit):
            resolve_options(parser.parse_args(["--limit", "0", "--no-snapshot"]))
        # a snapshot with no build images is unusable at trial time
        with self.assertRaises(SystemExit):
            resolve_options(parser.parse_args(["--skip-image-pull"]))

        # the default path is untouched: all pinned tasks, canonical name
        tasks, name, skip = resolve_options(parser.parse_args([]))
        self.assertEqual(name, SNAPSHOT_NAME)
        self.assertGreater(len(tasks), 1)
        self.assertFalse(skip)

        # validation runs are allowed when they cannot corrupt anything
        tasks, name, _ = resolve_options(parser.parse_args(["--limit", "1", "--no-snapshot"]))
        self.assertEqual(len(tasks), 1)
        self.assertIsNone(name)

        tasks, name, _ = resolve_options(
            parser.parse_args(["--limit", "2", "--snapshot-name", "gymsiege-scratch"])
        )
        self.assertEqual(len(tasks), 2)
        self.assertEqual(name, "gymsiege-scratch")

    def test_bake_cleanup_never_masks_the_original_failure(self) -> None:
        """A raise inside `finally` replaces the real error and skips delete().

        A failed bake raised DaytonaNotFoundError from set_ttl() because the
        sandbox's TTL had already deleted it, which hid the
        DaytonaConnectionTimeoutError that actually ended the run and meant
        delete() was never attempted.
        """
        source = Path("snapshot_build.py").read_text(encoding="utf-8")
        finally_block = source.split("        finally:\n", 1)[1].split("\n\n", 1)[0]
        self.assertIn("try:", finally_block)
        self.assertIn("await sandbox.set_ttl(60)", finally_block)
        self.assertIn("await sandbox.delete(", finally_block)
        # both calls guarded, and an already-deleted sandbox is not an error
        self.assertGreaterEqual(finally_block.count("except Exception"), 2)
        self.assertIn("not found", finally_block.lower())

    def test_metrics_fetch_cannot_overwrite_a_real_result(self) -> None:
        """A telemetry hiccup previously relabeled a real, scored result as an error.

        A live trial completed evaluation, parsed result.json, and set
        status="failed" with a real score of 0 (flag.txt not found) -- then
        sandbox.get_metrics_latest()/get_metrics() hit a Daytona API 401,
        which was unguarded and propagated to the outer `except Exception`,
        overwriting the already-correct status with "error". Because the
        metrics calls also ran before the result.json/task.log downloads,
        those were skipped too (result_local_path/log_local_path stayed
        None). Metrics must be best-effort and must run after the artifacts
        that constitute the real outcome, not before them.
        """
        source = Path("exploitgym_adapter.py").read_text(encoding="utf-8")
        latest_idx = source.index("get_metrics_latest()")
        download_idx = source.index("fs.download_file(result_json_path")
        self.assertLess(
            download_idx, latest_idx,
            "result.json must be downloaded before the best-effort metrics fetch",
        )
        # the log couldn't tell get_metrics_latest() and get_metrics() apart
        # because they shared one try/except -- each now needs its own, so a
        # repeat failure identifies which call it is and whether it recurs.
        latest_idx = source.index("await sandbox.get_metrics_latest()")
        metrics_idx = source.index("await sandbox.get_metrics(start=None, end=None)")
        self.assertLess(latest_idx, metrics_idx)
        latest_block = source[latest_idx - 30 : latest_idx + 300]
        metrics_block = source[metrics_idx - 30 : metrics_idx + 300]
        for block, label in ((latest_block, "get_metrics_latest"), (metrics_block, "get_metrics")):
            self.assertIn("try:", block, label)
            self.assertIn("except Exception", block, label)
            self.assertIn("non-fatal", block, label)
            self.assertIn("traceback.format_exc", block, label)
        # regression: they must not still share a single try/except -- that
        # was exactly what made the earlier failure impossible to attribute
        self.assertNotEqual(latest_block, metrics_block)

    def test_bake_ttl_outlasts_its_own_step_timeouts(self) -> None:
        """The safety net must not expire before the work it protects.

        A full bake was stopped mid-`docker pull` because the sandbox carried
        the 60-minute trial TTL while the bake's own step timeouts total 160
        minutes, and because auto-stop was never set -- a long pull issues no
        API calls, so the sandbox reads as idle.
        """
        from snapshot_build import BAKE_STEP_TIMEOUT_BUDGET_S, BAKE_TTL_MINUTES

        budget_minutes = BAKE_STEP_TIMEOUT_BUDGET_S / 60
        self.assertGreater(
            BAKE_TTL_MINUTES,
            budget_minutes,
            f"bake TTL {BAKE_TTL_MINUTES}min must exceed its own "
            f"{budget_minutes:.0f}min timeout budget",
        )
        # and it must be longer than the trial default it replaces
        from common import SANDBOX_SAFETY_TTL_MINUTES

        self.assertGreater(BAKE_TTL_MINUTES, SANDBOX_SAFETY_TTL_MINUTES)

        source = Path("snapshot_build.py").read_text(encoding="utf-8")
        self.assertIn("auto_stop_interval=BAKE_TTL_MINUTES", source)
        self.assertIn("set_autostop_interval(BAKE_TTL_MINUTES)", source)

    def test_trial_sandboxes_disable_platform_autostop(self) -> None:
        """The bake sandbox fix above has a trial-sandbox twin, added later.

        A live ExploitGym trial (`user:cybergym/arvo_62183`, 2026-09-06) was
        stopped by Daytona mid-`evaluation` -- the same "long-running exec()
        issues no Sandbox events, so the platform's 15-minute auto-stop
        default fires" bug as the bake incident above, just never applied to
        trial sandboxes. Both `exploitgym_adapter.py` (ExploitGym) and
        `sandbox_runner.py` (CyberGym) create their trial sandbox with
        `auto_stop_interval=0`, and re-apply `set_autostop_interval(0)` after
        their post-secret-attach stop/start cycle, since a restart does not
        necessarily preserve the creation-time value -- see FINDINGS.md#9.
        """
        for filename in ("exploitgym_adapter.py", "sandbox_runner.py"):
            source = Path(filename).read_text(encoding="utf-8")
            self.assertIn("auto_stop_interval=0", source, filename)
            self.assertIn("set_autostop_interval(0)", source, filename)

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


class ReapTests(unittest.IsolatedAsyncioTestCase):
    """A stuck sandbox made reap's own summary line lie about what happened.

    Two sandboxes named siege-*, one deletes cleanly, one fails with a
    platform-side "state change in progress" error (observed live: a
    sandbox stuck in CREATING that also refuses delete). The old summary
    line counted sandboxes *found*, not *deleted*, so it printed
    "2 sandbox(es) reaped" even though only one actually was.
    """

    async def test_summary_reports_actual_deletions_not_sandboxes_found(self) -> None:
        class FakeSandbox:
            def __init__(self, name, id_, should_fail):
                self.name, self.id, self._fail = name, id_, should_fail

            async def delete(self, wait=True, timeout=None):
                if self._fail:
                    raise RuntimeError("Failed to remove sandbox: Sandbox state change in progress")

        ok = FakeSandbox("siege-ok", "id-ok", should_fail=False)
        stuck = FakeSandbox("siege-stuck", "id-stuck", should_fail=True)

        class FakeDaytona:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def list(self):
                for s in (ok, stuck):
                    yield s

        with patch("orchestrator.AsyncDaytona", return_value=FakeDaytona()), \
             patch("orchestrator.require_env"), \
             patch("orchestrator.atomic_write_json") as write_json, \
             self.assertRaises(SystemExit) as ctx:
            await cmd_reap(argparse.Namespace(dry_run=False))

        # exits non-zero specifically because a delete failed
        self.assertEqual(ctx.exception.code, 1)

        # the persisted log must record the failure, not just successes
        logged = write_json.call_args[0][1]
        run = logged["runs"][-1]
        self.assertEqual([r["name"] for r in run["reaped"]], ["siege-ok"])
        self.assertEqual([f["name"] for f in run["failed"]], ["siege-stuck"])
        self.assertIn("state change in progress", run["failed"][0]["error"])

    async def test_summary_is_clean_when_every_delete_succeeds(self) -> None:
        class FakeSandbox:
            name, id = "siege-ok", "id-ok"
            async def delete(self, wait=True, timeout=None):
                return None

        class FakeDaytona:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *exc):
                return False
            async def list(self):
                yield FakeSandbox()

        with patch("orchestrator.AsyncDaytona", return_value=FakeDaytona()), \
             patch("orchestrator.require_env"), \
             patch("orchestrator.atomic_write_json"):
            await cmd_reap(argparse.Namespace(dry_run=False))  # must not raise


class StatusLabelTests(unittest.TestCase):
    """"failed" in the terminal reads as "something broke".

    It actually means the opposite of a harness problem: the trial ran end to
    end and the agent did not exploit the target. That is the distinction this
    harness exists to report, so the log line spells it out. The stored status
    strings are untouched -- pass@k and the dashboard key off them.
    """

    def test_a_clean_non_exploitation_does_not_read_as_breakage(self) -> None:
        from orchestrator import status_label

        self.assertEqual(status_label("failed"), "completed - no exploitation")
        # and a real breakage still reads as one
        self.assertIn("harness/platform failure", status_label("error"))

    def test_success_is_not_reused_for_the_no_exploitation_case(self) -> None:
        """`success` means "exploited" and pass@k counts exactly those."""
        from orchestrator import status_label

        self.assertIn("exploited", status_label("success"))
        self.assertNotIn("success", status_label("failed"))

    def test_unknown_statuses_pass_through_unchanged(self) -> None:
        from orchestrator import status_label

        self.assertEqual(status_label("some_new_status"), "some_new_status")
        self.assertEqual(status_label(None), "unknown")

    def test_every_stored_status_has_a_label(self) -> None:
        """A status with no label silently falls back to the raw string."""
        from orchestrator import STATUS_LABELS

        # the vocabulary documented on TrialResult.status in common.py
        documented = {
            "success", "other_vuln", "failed", "error",
            "oracle_unavailable", "timeout",
        }
        self.assertTrue(documented.issubset(STATUS_LABELS.keys()))

    def test_node_incompatible_target_reads_as_a_known_category_not_a_generic_error(
        self,
    ) -> None:
        """A target whose glibc predates the baked Node runtime always fails
        the node_compatibility_probe stage before any model call, so it
        always surfaces as status="error". Left as the generic label, that
        reads identically to a real infra fault worth retrying -- it isn't;
        it is a known, non-retryable ExploitGym/target mismatch. See
        FINDINGS.md.
        """
        from orchestrator import status_label

        label = status_label("error", "node_compatibility_probe")
        self.assertIn("glibc", label)
        self.assertNotIn("harness/platform failure", label)
        # an unrelated error at a different stage still reads generically
        self.assertIn("harness/platform failure", status_label("error", "docker_start"))
        # and the two-argument form stays backward compatible for old callers
        self.assertIn("harness/platform failure", status_label("error"))


class TargetedReapTests(unittest.IsolatedAsyncioTestCase):
    """`reap` with no target deletes every siege-* sandbox, live trials included.

    With an organization-wide memory ceiling, an orphan blocks the next run,
    so it has to go -- but sweeping everything would also destroy a trial
    still in flight. `--sandbox` names the ones to remove and leaves the rest
    alone, and a value matching nothing must fail loudly rather than quietly
    reporting a clean sweep.
    """

    class _Sandbox:
        def __init__(self, name, id_):
            self.name, self.id, self.deleted = name, id_, False

        async def delete(self, wait=True, timeout=None):
            self.deleted = True

    def _fake_daytona(self, sandboxes):
        class FakeDaytona:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def list(self):
                for sandbox in sandboxes:
                    yield sandbox

        return FakeDaytona()

    async def test_only_the_named_sandbox_is_deleted(self) -> None:
        orphan = self._Sandbox("siege-eg-orphan-t1-1", "id-orphan")
        live = self._Sandbox("siege-eg-live-t1-2", "id-live")

        with patch("orchestrator.AsyncDaytona", return_value=self._fake_daytona([orphan, live])), \
             patch("orchestrator.require_env"), \
             patch("orchestrator.atomic_write_json") as write_json:
            await cmd_reap(argparse.Namespace(dry_run=False, sandbox=["id-orphan"]))

        self.assertTrue(orphan.deleted)
        self.assertFalse(live.deleted, "a live trial must survive a targeted reap")
        run = write_json.call_args[0][1]["runs"][-1]
        self.assertEqual([r["name"] for r in run["reaped"]], ["siege-eg-orphan-t1-1"])

    async def test_a_name_works_as_well_as_an_id(self) -> None:
        orphan = self._Sandbox("siege-eg-orphan-t1-1", "id-orphan")
        live = self._Sandbox("siege-eg-live-t1-2", "id-live")

        with patch("orchestrator.AsyncDaytona", return_value=self._fake_daytona([orphan, live])), \
             patch("orchestrator.require_env"), \
             patch("orchestrator.atomic_write_json"):
            await cmd_reap(
                argparse.Namespace(dry_run=False, sandbox=["siege-eg-orphan-t1-1"])
            )

        self.assertTrue(orphan.deleted)
        self.assertFalse(live.deleted)

    async def test_an_unmatched_target_is_an_error_not_a_clean_sweep(self) -> None:
        live = self._Sandbox("siege-eg-live-t1-2", "id-live")

        with patch("orchestrator.AsyncDaytona", return_value=self._fake_daytona([live])), \
             patch("orchestrator.require_env"), \
             patch("orchestrator.atomic_write_json"), \
             self.assertRaises(SystemExit) as ctx:
            await cmd_reap(argparse.Namespace(dry_run=False, sandbox=["id-typo"]))

        self.assertIn("id-typo", str(ctx.exception))
        self.assertFalse(live.deleted, "an unmatched target must delete nothing")

    async def test_default_sweep_still_takes_everything(self) -> None:
        one = self._Sandbox("siege-eg-a-t1-1", "id-a")
        two = self._Sandbox("siege-eg-b-t1-2", "id-b")

        with patch("orchestrator.AsyncDaytona", return_value=self._fake_daytona([one, two])), \
             patch("orchestrator.require_env"), \
             patch("orchestrator.atomic_write_json"):
            await cmd_reap(argparse.Namespace(dry_run=False, sandbox=None))

        self.assertTrue(one.deleted and two.deleted)


class ConcurrencyCeilingTests(unittest.TestCase):
    """Concurrency is capped by an organization-wide memory quota, not by choice.

    The ExploitGym snapshot restores at 8 GiB per sandbox (see
    exploitgym_snapshot_build.py) against a 10 GiB organization-wide total,
    so two concurrent trials cannot both be scheduled: the second is refused
    with "Total memory limit exceeded. Maximum allowed: 10GiB", and a sandbox
    refused capacity was observed wedging in CREATING while still holding its
    reservation -- which then blocked the next run too. The flag stays, so a
    tier upgrade only needs a different value, but the default must be serial.
    """

    def test_exploitgym_defaults_to_serial_trials(self) -> None:
        args = build_parser().parse_args(["exploitgym-run"])
        self.assertEqual(args.max_parallel, 1)

    def test_the_flag_still_exists_for_a_raised_tier(self) -> None:
        args = build_parser().parse_args(["exploitgym-run", "--max-parallel", "4"])
        self.assertEqual(args.max_parallel, 4)

    def test_snapshot_memory_and_quota_are_documented_together(self) -> None:
        # the 8 GiB figure the default is derived from must stay discoverable
        self.assertIn(
            "Resources(cpu=4, memory=8, disk=10)",
            Path("exploitgym_snapshot_build.py").read_text(encoding="utf-8"),
        )
        help_text = Path("orchestrator.py").read_text(encoding="utf-8")
        self.assertIn("10 GiB organization-wide", help_text)


class SandboxCreateAdoptionTests(unittest.IsolatedAsyncioTestCase):
    """A client-side create() timeout orphaned a sandbox the platform built.

    `daytona.create()`'s timeout is documented as client-side only: it bounds
    the HTTP wait and does not cancel the server-side operation. A restore
    that normally took ~5s exceeded 300s, the call raised, and because the
    caller never got a handle, its `finally` cleanup was skipped entirely --
    `reap --dry-run` then found the sandbox alive server-side. The restore
    must look the sandbox up by name before treating the failure as final.
    """

    async def test_adopts_the_sandbox_the_platform_created_anyway(self) -> None:
        from exploitgym_adapter import _create_or_adopt_sandbox

        class Adopted:
            id, state = "71f84cd7", "started"

        class FakeDaytona:
            @staticmethod
            async def create(params, timeout=None):
                raise RuntimeError("Function 'create' exceeded timeout of 300 seconds.")

            @staticmethod
            async def get(name, request_timeout=None):
                return Adopted()

        sandbox = await _create_or_adopt_sandbox(FakeDaytona(), "siege-eg-x-t1", "user:x/y")
        self.assertEqual(sandbox.id, "71f84cd7")

    async def test_original_error_survives_when_there_is_nothing_to_adopt(self) -> None:
        from exploitgym_adapter import _create_or_adopt_sandbox

        class FakeDaytona:
            @staticmethod
            async def create(params, timeout=None):
                raise RuntimeError("Function 'create' exceeded timeout of 300 seconds.")

            @staticmethod
            async def get(name, request_timeout=None):
                raise RuntimeError("Sandbox not found")

        with self.assertRaises(RuntimeError) as ctx:
            await _create_or_adopt_sandbox(FakeDaytona(), "siege-eg-x-t1", "user:x/y")
        # the create failure, not the lookup miss, is what gets reported
        self.assertIn("exceeded timeout", str(ctx.exception))

    async def test_normal_path_returns_the_created_sandbox(self) -> None:
        from exploitgym_adapter import _create_or_adopt_sandbox

        class Created:
            id, state = "fresh", "started"

        class FakeDaytona:
            @staticmethod
            async def create(params, timeout=None):
                return Created()

            @staticmethod
            async def get(name, request_timeout=None):
                raise AssertionError("get() must not be called when create() succeeds")

        sandbox = await _create_or_adopt_sandbox(FakeDaytona(), "siege-eg-x-t1", "user:x/y")
        self.assertEqual(sandbox.id, "fresh")


class SnapshotCaptureTests(unittest.IsolatedAsyncioTestCase):
    """create_snapshot() reported success before capture actually failed.

    `sandbox.create_snapshot()` only waits for the *sandbox* to leave its
    'snapshotting' state; a real bake returned success in 46s while the
    registered Snapshot resource went to ERROR asynchronously afterward
    (rsync ENOSPC), and nothing in the bake caught it (FINDINGS.md #3,
    daytonaio/daytona#5156). `wait_for_snapshot_active` must poll the
    Snapshot resource itself to a terminal state and refuse to trust
    anything but ACTIVE.
    """

    async def test_raises_when_snapshot_lands_in_error(self) -> None:
        from snapshot_build import wait_for_snapshot_active

        class FakeSnapshot:
            state = "error"
            error_reason = "rsync ENOSPC during container pause"

        class FakeDaytona:
            class snapshot:
                @staticmethod
                async def get(name):
                    return FakeSnapshot()

        with self.assertRaises(RuntimeError) as ctx:
            await wait_for_snapshot_active(FakeDaytona(), "gymsiege-toolchain", timeout=5)
        self.assertIn("error", str(ctx.exception))
        self.assertIn("rsync ENOSPC", str(ctx.exception))

    async def test_polls_through_non_terminal_states_to_active(self) -> None:
        from snapshot_build import wait_for_snapshot_active

        states = iter(["pending", "snapshotting", "active"])

        class FakeSnapshot:
            def __init__(self, state):
                self.state = state
                self.error_reason = None

        class FakeDaytona:
            class snapshot:
                @staticmethod
                async def get(name):
                    return FakeSnapshot(next(states))

        result = await wait_for_snapshot_active(
            FakeDaytona(), "gymsiege-toolchain", timeout=5, interval=0.01
        )
        self.assertEqual(result, "active")

    async def test_raises_on_timeout_without_reaching_a_terminal_state(self) -> None:
        from snapshot_build import wait_for_snapshot_active

        class FakeSnapshot:
            state = "snapshotting"
            error_reason = None

        class FakeDaytona:
            class snapshot:
                @staticmethod
                async def get(name):
                    return FakeSnapshot()

        with self.assertRaises(RuntimeError) as ctx:
            await wait_for_snapshot_active(
                FakeDaytona(), "gymsiege-toolchain", timeout=0.05, interval=0.01
            )
        self.assertIn("did not reach a terminal state", str(ctx.exception))


class BudgetGuardTests(unittest.IsolatedAsyncioTestCase):
    """CyberGym run/sweep had no spend cap at all before this.

    `run` defaults to --k 3 --modes e2e patch-only, i.e. six trials per task,
    each making unbounded LLM calls. The one measured trial in this project
    cost $0.65, so a default 20-task run could plausibly reach three figures
    with nothing to stop it.
    """

    async def test_cap_blocks_further_launches_once_reached(self) -> None:
        from orchestrator import BudgetGuard

        guard = BudgetGuard(1.0)

        class R:
            solver_cost_usd = 0.60

        self.assertTrue(await guard.allow())
        await guard.record(R())
        self.assertTrue(await guard.allow(), "0.60 < 1.00 must still allow")
        await guard.record(R())
        self.assertFalse(await guard.allow(), "1.20 >= 1.00 must block")
        self.assertEqual(guard.skipped, 1)

        s = guard.summary()
        self.assertTrue(s["budget_exhausted"])
        self.assertAlmostEqual(s["solver_spend_usd"], 1.20, places=6)

    async def test_zero_or_none_disables_the_cap_rather_than_blocking(self) -> None:
        """A disabled cap must not become a total block.

        Storing 0.0 as the cap would make `spent >= cap` true immediately and
        skip every trial -- the opposite of what --budget-usd 0 documents.
        """
        from orchestrator import BudgetGuard

        for cap in (0.0, None, -5.0):
            guard = BudgetGuard(cap)
            self.assertIsNone(guard.cap_usd, f"cap={cap!r} should disable, not clamp")
            self.assertTrue(await guard.allow(), f"cap={cap!r} must not block trials")

    async def test_untracked_cost_does_not_corrupt_the_total(self) -> None:
        from orchestrator import BudgetGuard

        guard = BudgetGuard(10.0)
        await guard.record(None)                       # trial returned nothing
        await guard.record(type("R", (), {"solver_cost_usd": None})())
        self.assertEqual(guard.spent_usd, 0.0)
        self.assertTrue(await guard.allow())

    def test_run_and_sweep_expose_the_cap(self) -> None:
        parser = build_parser()
        self.assertEqual(parser.parse_args(["run"]).budget_usd, 36.0)
        self.assertEqual(parser.parse_args(["sweep"]).budget_usd, 36.0)
        self.assertEqual(
            parser.parse_args(["run", "--budget-usd", "5"]).budget_usd, 5.0
        )


class SweepTimeoutTelemetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_timed_out_trial_retains_metrics_for_oom_accounting(self) -> None:
        async def stalled_trial(*args, result, **kwargs):
            try:
                await asyncio.sleep(60)
            finally:
                result.metrics_latest = {"mem_total": 100, "mem_used": 98}
                result.metrics_series = [{"mem_total": 100, "mem_used": 96}]

        task = Task("curl", "arvo_66012")
        with patch("orchestrator.run_trial", stalled_trial):
            _, result, error, _ = await _run_sweep_trial_with_timeout(
                object(), task, 1, object(), 0.01
            )
        self.assertEqual(error, "timeout")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.status, "timeout")
        self.assertTrue(_trial_hit_oom_threshold(result))


if __name__ == "__main__":
    unittest.main()
