from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# run_cvebench.py lives under CVE-bench/ (a hyphenated dir that can't be a
# package), so load it by path rather than `import`.
_MODULE_PATH = Path(__file__).resolve().parent.parent / "CVE-bench" / "run_cvebench.py"
_MANIFEST_PATH = (
    Path(__file__).resolve().parent.parent / "CVE-bench" / "top10-2024-cvss-9_7plus.yml"
)
_spec = importlib.util.spec_from_file_location("run_cvebench", _MODULE_PATH)
assert _spec and _spec.loader
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

_DOCKER_DIR_HELPER_PATH = (
    Path(__file__).resolve().parent.parent
    / "CVE-bench"
    / "ensure_upstream_docker_dir.py"
)
_helper_spec = importlib.util.spec_from_file_location(
    "ensure_upstream_docker_dir", _DOCKER_DIR_HELPER_PATH
)
assert _helper_spec and _helper_spec.loader
docker_dir_helper = importlib.util.module_from_spec(_helper_spec)
_helper_spec.loader.exec_module(docker_dir_helper)


def _make_repo(tmp: str) -> Path:
    """A minimal fake cve-bench checkout: just the ./run entrypoint main() checks."""
    repo = Path(tmp)
    (repo / "run").write_text("#!/bin/sh\n")
    return repo


class ParseChallengeListTests(unittest.TestCase):
    def test_single_id(self) -> None:
        self.assertEqual(rc.parse_challenge_list("CVE-2024-36412"), ["CVE-2024-36412"])

    def test_comma_separated_list_preserves_order(self) -> None:
        self.assertEqual(
            rc.parse_challenge_list("CVE-2024-36412,CVE-2024-4701"),
            ["CVE-2024-36412", "CVE-2024-4701"],
        )

    def test_whitespace_and_trailing_comma_tolerated(self) -> None:
        self.assertEqual(
            rc.parse_challenge_list(" CVE-2024-36412 , CVE-2024-4701 ,"),
            ["CVE-2024-36412", "CVE-2024-4701"],
        )

    def test_long_numeric_tail_allowed(self) -> None:
        # NVD zero-pads to 4 digits but allows more.
        self.assertEqual(rc.parse_challenge_list("CVE-2024-123456"), ["CVE-2024-123456"])

    def test_empty_rejected(self) -> None:
        for value in ("", "   ", ",", " , "):
            with self.assertRaises(ValueError):
                rc.parse_challenge_list(value)

    def test_garbage_item_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a CVE id"):
            rc.parse_challenge_list("CVE-2024-36412,notacve")
        with self.assertRaises(ValueError):
            rc.parse_challenge_list("CVE-24-1")  # year too short


class PreserveUpstreamDockerDirTests(unittest.TestCase):
    def _runner(self, directory: str, assignment: str) -> Path:
        runner = Path(directory) / "run"
        runner.write_text(
            "#!/usr/bin/env bash\n"
            f"{assignment}\n"
            "printf '%s\\n' \"$CVEBENCH_DOCKER_DIR\"\n",
            encoding="utf-8",
        )
        runner.chmod(0o755)
        return runner

    def test_patch_preserves_wrapper_value_when_runner_executes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp, docker_dir_helper.UPSTREAM_ASSIGNMENT)
            self.assertTrue(
                docker_dir_helper.ensure_runner_preserves_docker_dir(runner)
            )
            env = {**os.environ, "CVEBENCH_DOCKER_DIR": "/tmp/staged-docker"}
            result = subprocess.run(
                ["bash", str(runner)],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
        self.assertEqual(result.stdout.strip(), "/tmp/staged-docker")

    def test_patch_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(tmp, docker_dir_helper.UPSTREAM_ASSIGNMENT)
            self.assertTrue(
                docker_dir_helper.ensure_runner_preserves_docker_dir(runner)
            )
            once = runner.read_bytes()
            self.assertFalse(
                docker_dir_helper.ensure_runner_preserves_docker_dir(runner)
            )
            self.assertEqual(runner.read_bytes(), once)
            self.assertEqual(
                runner.read_text(encoding="utf-8").count(
                    docker_dir_helper.PRESERVING_ASSIGNMENT
                ),
                1,
            )

    def test_unknown_upstream_shape_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(
                tmp, "export CVEBENCH_DOCKER_DIR=/unexpected/upstream/layout"
            )
            original = runner.read_bytes()
            with self.assertRaisesRegex(RuntimeError, "cannot safely patch"):
                docker_dir_helper.ensure_runner_preserves_docker_dir(runner)
            self.assertEqual(runner.read_bytes(), original)


class ResolveSolverTests(unittest.TestCase):
    def test_auto_anthropic_uses_claude_code(self) -> None:
        self.assertEqual(
            rc.resolve_solver("auto", "anthropic/claude-opus-4-8"), "claude_code_agent"
        )

    def test_auto_openai_uses_codex(self) -> None:
        self.assertEqual(
            rc.resolve_solver("auto", "openai/gpt-5.6-luna"), "codex_cli_agent"
        )

    def test_auto_gateway_model_uses_codex(self) -> None:
        # The LiteLLM gateway is addressed with the openai/ provider prefix.
        self.assertEqual(
            rc.resolve_solver("auto", "openai/gpt-5.6-sol"), "codex_cli_agent"
        )

    def test_explicit_value_returned_verbatim(self) -> None:
        # An explicit choice overrides provider inference, even a "wrong" one.
        self.assertEqual(
            rc.resolve_solver("claude_code_agent", "openai/gpt-5.6-luna"),
            "claude_code_agent",
        )


class ReadEnvFileTests(unittest.TestCase):
    def _write(self, tmp: str, text: str) -> Path:
        path = Path(tmp) / ".env"
        path.write_text(text)
        return path

    def test_plain_key_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "OPENAI_API_KEY=sk-abc\n")
            self.assertEqual(rc.read_env_file(path, "OPENAI_API_KEY"), "sk-abc")

    def test_quotes_stripped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, 'OPENAI_API_KEY="sk-abc"\n')
            self.assertEqual(rc.read_env_file(path, "OPENAI_API_KEY"), "sk-abc")

    def test_comments_and_blanks_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "# a comment\n\nOPENAI_API_KEY=sk-abc\n")
            self.assertEqual(rc.read_env_file(path, "OPENAI_API_KEY"), "sk-abc")

    def test_missing_key_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "OTHER=1\n")
            self.assertIsNone(rc.read_env_file(path, "OPENAI_API_KEY"))

    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(rc.read_env_file(Path("/no/such/file.env"), "OPENAI_API_KEY"))


class ResolveKeyTests(unittest.TestCase):
    def test_shell_env_wins_over_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "k.env"
            env_file.write_text("OPENAI_API_KEY=from-file\n")
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "from-env"}):
                key, source = rc.resolve_key("OPENAI_API_KEY", env_file, Path(tmp))
        self.assertEqual(key, "from-env")
        self.assertEqual(source, "shell env")

    def test_explicit_file_used_when_env_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "k.env"
            env_file.write_text("OPENAI_API_KEY=from-file\n")
            with mock.patch.dict(os.environ, {}, clear=True):
                key, source = rc.resolve_key("OPENAI_API_KEY", env_file, Path(tmp))
        self.assertEqual(key, "from-file")
        self.assertEqual(source, str(env_file))

    def test_repo_dotenv_used_when_no_explicit_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as home:
            repo = Path(tmp)
            (repo / ".env").write_text("OPENAI_API_KEY=from-repo\n")
            # Patch home so a real ~/.cve-bench.env can't shadow repo/.env, and
            # clear the env so the file path is exercised.
            with mock.patch.object(rc.Path, "home", return_value=Path(home)), \
                    mock.patch.dict(os.environ, {}, clear=True):
                key, _ = rc.resolve_key("OPENAI_API_KEY", None, repo)
        self.assertEqual(key, "from-repo")

    def test_not_found_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
                tempfile.TemporaryDirectory() as home:
            with mock.patch.object(rc.Path, "home", return_value=Path(home)), \
                    mock.patch.dict(os.environ, {}, clear=True):
                key, source = rc.resolve_key("OPENAI_API_KEY", None, Path(tmp))
        self.assertIsNone(key)
        self.assertEqual(source, "")


class ParseArgsDefaultsTests(unittest.TestCase):
    def test_defaults(self) -> None:
        args = rc.parse_args(["--challenge", "CVE-2024-36412"])
        self.assertEqual(args.variant, "one_day")
        self.assertEqual(args.model, "openai/gpt-5.6-luna")
        self.assertEqual(args.solver, "auto")
        self.assertFalse(args.internet)
        self.assertFalse(args.health_check)

    def test_invalid_variant_rejected(self) -> None:
        with self.assertRaises(SystemExit):
            rc.parse_args(["--challenge", "CVE-2024-36412", "--variant", "two_day"])


class MainDryRunTests(unittest.TestCase):
    """Exercise main()'s containment + command assembly via --dry-run (no spend)."""

    def _dry_run(self, extra_args: list[str]) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(tmp)
            argv = ["--repo", str(repo), "--dry-run", *extra_args]
            buf = io.StringIO()
            with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}), \
                    contextlib.redirect_stdout(buf):
                code = rc.main(argv)
            return code, buf.getvalue()

    def test_egress_off_by_default(self) -> None:
        code, out = self._dry_run(["--challenge", "CVE-2024-36412"])
        self.assertEqual(code, 0)
        self.assertIn("CVEBENCH_AGENT_INTERNET=false", out)

    def test_internet_flag_enables_egress(self) -> None:
        code, out = self._dry_run(["--challenge", "CVE-2024-36412", "--internet"])
        self.assertEqual(code, 0)
        self.assertIn("CVEBENCH_AGENT_INTERNET=true", out)

    def test_challenge_list_flows_into_eval_command(self) -> None:
        code, out = self._dry_run(["--challenge", "CVE-2024-36412,CVE-2024-4701"])
        self.assertEqual(code, 0)
        self.assertIn("challenges=CVE-2024-36412,CVE-2024-4701", out)

    def test_auto_solver_picks_codex_for_openai_model(self) -> None:
        _, out = self._dry_run(["--challenge", "CVE-2024-36412"])
        self.assertIn("--solver codex_cli_agent", out)


class MainValidationTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> int:
        buf = io.StringIO()
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}), \
                contextlib.redirect_stderr(buf):
            return rc.main(argv)

    def test_invalid_challenge_fails_before_repo_check(self) -> None:
        # Bad challenge is rejected (rc 2) even with a bogus --repo, proving the
        # check runs up front, before any Docker/model work.
        self.assertEqual(
            self._run(["--challenge", "notacve", "--repo", "/no/such/repo"]), 2
        )

    def test_health_check_with_list_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo(tmp)
            code = self._run(
                ["--challenge", "CVE-2024-36412,CVE-2024-4701",
                 "--health-check", "--repo", str(repo)]
            )
        self.assertEqual(code, 2)

    def test_missing_runner_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # no ./run created
            code = self._run(["--challenge", "CVE-2024-36412", "--repo", tmp])
        self.assertEqual(code, 2)


class ManifestConsistencyTests(unittest.TestCase):
    """The 'all' CI path trusts the manifest's `challenges:` line; keep it in
    sync with `count:` and the per-task `cve:` entries."""

    def _manifest(self) -> dict[str, object]:
        challenges: list[str] = []
        count = None
        cves: list[str] = []
        for raw in _MANIFEST_PATH.read_text().splitlines():
            line = raw.strip()
            if line.startswith("challenges:"):
                challenges = line.split('"')[1].split(",")
            elif line.startswith("count:"):
                count = int(line.split(":", 1)[1].strip())
            elif line.startswith("cve:"):
                cves.append(line.split(":", 1)[1].strip())
        return {"challenges": challenges, "count": count, "cves": cves}

    def test_challenges_count_matches_declared_count(self) -> None:
        m = self._manifest()
        self.assertEqual(len(m["challenges"]), m["count"])
        self.assertEqual(m["count"], 10)

    def test_every_challenge_is_a_cve_id(self) -> None:
        for cve in self._manifest()["challenges"]:
            self.assertRegex(cve, rc.CVE_ID_RE)

    def test_challenges_line_matches_task_entries_in_order(self) -> None:
        m = self._manifest()
        self.assertEqual(m["challenges"], m["cves"])

    def test_parse_challenge_list_accepts_the_whole_manifest(self) -> None:
        joined = ",".join(self._manifest()["challenges"])
        self.assertEqual(len(rc.parse_challenge_list(joined)), 10)


if __name__ == "__main__":
    unittest.main()
