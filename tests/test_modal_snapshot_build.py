from __future__ import annotations

import argparse
import subprocess
import tempfile
import unittest
from pathlib import Path

from modal_snapshot_build import (
    CODEX_INSTALL_CONTROL_TASK,
    NVM_COMMIT,
    NVM_CONTAINER_MIRROR,
    NVM_PATCH_MARKER,
    NVM_TAG_OBJECT,
    NVM_VERSION,
    _MIRRORED_CODEX_INSTALL_BLOCK,
    _assert_control_parity,
    _nvm_container_visibility_command,
    _nvm_mirror_preflight_script,
    _snapshot_validation_script,
    selected_tasks,
)


class ModalSnapshotBuildTests(unittest.TestCase):
    def test_missing_nvm_mirror_fails_snapshot_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "cybergym"
            scripts = repo / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "run_agent.py").write_text(f"# {NVM_PATCH_MARKER}\n")

            checked = subprocess.run(
                ["bash", "-lc", _nvm_mirror_preflight_script(str(repo))],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(checked.returncode, 0)

    def test_task_image_visibility_rejects_incomplete_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            mirror = Path(temp_dir) / "nvm.git"
            command = _nvm_container_visibility_command(str(mirror))
            self.assertNotEqual(
                subprocess.run(["bash", "-lc", command]).returncode,
                0,
            )

            (mirror / "objects" / "pack").mkdir(parents=True)
            (mirror / "HEAD").write_text("ref: refs/heads/master\n")
            (mirror / "packed-refs").write_text(
                f"{NVM_TAG_OBJECT} refs/tags/{NVM_VERSION}\n"
            )
            self.assertNotEqual(
                subprocess.run(["bash", "-lc", command]).returncode,
                0,
            )

            (mirror / "objects" / "pack" / "pack-test.pack").write_bytes(b"test")
            self.assertEqual(
                subprocess.run(["bash", "-lc", command]).returncode,
                0,
            )

    def test_snapshot_validation_checks_every_source_image_for_mirror(self) -> None:
        rendered = _snapshot_validation_script([CODEX_INSTALL_CONTROL_TASK])

        self.assertIn(
            "for source_image, image_tasks in sorted(source_images.items())",
            rendered,
        )
        self.assertIn('"docker", "cp"', rendered)
        self.assertIn(_nvm_container_visibility_command(), rendered)
        self.assertIn(NVM_COMMIT, rendered)

    def test_codex_patch_is_conditional_on_github_file_rewrite(self) -> None:
        self.assertIn(NVM_PATCH_MARKER, _MIRRORED_CODEX_INSTALL_BLOCK)
        self.assertIn(
            "url.file:///deps/git/github.com/.insteadOf",
            _MIRRORED_CODEX_INSTALL_BLOCK,
        )
        self.assertIn(
            'target.rstrip("/") == "https://github.com"',
            _MIRRORED_CODEX_INSTALL_BLOCK,
        )
        self.assertIn(NVM_CONTAINER_MIRROR, _MIRRORED_CODEX_INSTALL_BLOCK)

    def test_control_parity_fails_on_toolchain_drift(self) -> None:
        task = {
            "image": "image@sha256:abc",
            "node": "v22.23.3",
            "npm": "10.9.9",
            "nvm": "0.40.2",
            "codex": "codex-cli 0.118.0",
            "nvm_mirror": "absent",
            "github_rewrite": "",
        }
        baseline = {
            "cybergym_revision": "abc",
            "tasks": {CODEX_INSTALL_CONTROL_TASK: task},
        }
        fresh = {
            "cybergym_revision": "abc",
            "tasks": {CODEX_INSTALL_CONTROL_TASK: dict(task)},
        }
        _assert_control_parity(baseline, fresh)

        fresh["tasks"][CODEX_INSTALL_CONTROL_TASK]["node"] = "v22.24.0"
        with self.assertRaisesRegex(RuntimeError, "control drifted"):
            _assert_control_parity(baseline, fresh)

    def test_upgrade_rejects_development_task_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            args = argparse.Namespace(
                upgrade_from_manifest=root / "base.json",
                limit=1,
                tasks_file="txt/tasks.pinned.txt",
                output=root / "out.json",
            )
            with self.assertRaisesRegex(SystemExit, "cannot be combined"):
                selected_tasks(args)


if __name__ == "__main__":
    unittest.main()
