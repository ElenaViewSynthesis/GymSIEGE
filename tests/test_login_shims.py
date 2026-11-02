"""agent_honeypot/login-shims.sh: the PATH shims survive a login shell.

Codex runs every tool call through `bash -lc`, and Debian's /etc/profile sets
PATH afresh, which dropped the harness's shims from every real tool call: strace,
nsenter, tmux and the rest ran unrecorded. The image sources this file from
/etc/profile.d after that reset."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).parents[1]
HOOK = REPO / "agent_honeypot" / "login-shims.sh"
PROFILE_TARGET = "/etc/profile.d/zz-honeypot-shims.sh"
DEBIAN_USER_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPO / relative)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def _path_after_hook(shell, env, *, twice=False):
    script = f'. "{HOOK}"; ' + (f'. "{HOOK}"; ' if twice else "") + 'printf %s "$PATH"'
    return subprocess.run([shell, "-c", script], env=env, text=True, capture_output=True,
                          check=True, timeout=30).stdout


class LoginShimsHookTests(unittest.TestCase):
    def test_the_shim_directories_go_back_in_front_in_the_harness_order(self):
        with tempfile.TemporaryDirectory() as directory:
            shims, extra = Path(directory, "shims"), Path(directory, "extra")
            shims.mkdir()
            extra.mkdir()
            for shell in ("sh", "bash"):
                with self.subTest(shell=shell):
                    env = {"PATH": DEBIAN_USER_PATH, "HONEYPOT_SHIM_PATH": str(shims),
                           "HONEYPOT_EXTRA_PATH": str(extra)}
                    self.assertEqual(_path_after_hook(shell, env), f"{shims}:{extra}:{DEBIAN_USER_PATH}")
                    self.assertEqual(_path_after_hook(shell, env, twice=True),
                                     f"{shims}:{extra}:{DEBIAN_USER_PATH}")
                    env.pop("HONEYPOT_EXTRA_PATH")
                    self.assertEqual(_path_after_hook(shell, env), f"{shims}:{DEBIAN_USER_PATH}")

    def test_outside_the_harness_nothing_changes(self):
        for env in ({"PATH": DEBIAN_USER_PATH},
                    {"PATH": DEBIAN_USER_PATH, "HONEYPOT_SHIM_PATH": ""},
                    {"PATH": DEBIAN_USER_PATH, "HONEYPOT_SHIM_PATH": "/nonexistent/shims",
                     "HONEYPOT_EXTRA_PATH": "/nonexistent/extra"}):
            with self.subTest(env=env):
                self.assertEqual(_path_after_hook("sh", env), DEBIAN_USER_PATH)

    def test_the_hook_leaves_no_variable_behind(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"PATH": DEBIAN_USER_PATH, "HONEYPOT_SHIM_PATH": directory}
            out = subprocess.run(["sh", "-c", f'. "{HOOK}"; printf %s "${{honeypot_front-unset}}"'],
                                 env=env, text=True, capture_output=True, check=True, timeout=30).stdout
        self.assertEqual(out, "unset")


class LoginShimsImageTests(unittest.TestCase):
    def test_both_images_install_the_hook_where_profile_sources_it(self):
        dockerfile = (REPO / "docker_honeypot" / "Dockerfile").read_text()
        install = f"install -m 0644 /opt/honeypot/agent_honeypot/login-shims.sh {PROFILE_TARGET}"
        self.assertIn(f"RUN {install}", dockerfile)
        # After the source is copied in.
        self.assertGreater(dockerfile.index(f"RUN {install}"),
                           dockerfile.index("COPY agent_honeypot/ /opt/honeypot/agent_honeypot/"))
        modal_runner = _load("modal_runner_for_login_shims", "modal_honeypot/runner.py")
        self.assertEqual(modal_runner.LOGIN_SHIMS_INSTALL, install)
        self.assertTrue(HOOK.is_file())


@unittest.skipUnless(shutil.which("gcc") and Path("/proc").is_dir() and hasattr(os, "geteuid") and os.geteuid() != 0,
                     "needs Linux, gcc, /proc, and a non-root user")
class LoginShellToolCallTests(unittest.TestCase):
    """What a real tool call does: a login profile resets PATH, then the tool runs."""

    def run_harness(self, command):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            subprocess.run(
                [str(REPO / "agent_honeypot" / "harness.sh"), "--evidence-chain", "--timeout", "15",
                 "--output", str(output), "--", "bash", "-c", command],
                cwd=REPO, text=True, capture_output=True, check=False, timeout=90,
            )
            report = json.loads((output / "report.json").read_text())
            evidence = json.loads((output / "evidence.json").read_text())
        return report, evidence

    TOOLS = "strace -V >/dev/null 2>&1; nsenter --version >/dev/null 2>&1; tmux -V >/dev/null 2>&1; sleep 0.3"

    def test_tools_after_a_profile_reset_are_recorded_with_the_hook(self):
        report, evidence = self.run_harness(f'PATH={DEBIAN_USER_PATH}; . "{HOOK}"; {self.TOOLS}')
        self.assertTrue(evidence["valid"], evidence)
        counts = report["event_counts"]
        self.assertEqual(counts.get("INJECTION_TOOL"), 2, counts)   # strace, nsenter
        self.assertEqual(counts.get("PROPAGATION_TOOL"), 1, counts)  # tmux

    def test_without_the_hook_the_same_tools_leave_no_shim_event(self):
        report, evidence = self.run_harness(f"PATH={DEBIAN_USER_PATH}; {self.TOOLS}")
        self.assertTrue(evidence["valid"], evidence)
        for kind in ("INJECTION_TOOL", "PROPAGATION_TOOL"):
            self.assertNotIn(kind, report["event_counts"])


if __name__ == "__main__":
    unittest.main()
