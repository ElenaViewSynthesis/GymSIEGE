#!/usr/bin/env python3
"""Bake and verify the complete CyberGym toolchain as a Modal VM snapshot.

The returned filesystem snapshot is a Modal Image.  Its ID is written locally
only after an independent Sandbox restored from it can start Docker and see
the expected task/image manifest.  Modal credentials are read by the Modal
SDK; the gated Hugging Face credential is attached as a named Modal Secret.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import common
from common import atomic_write_json, get_logger
from snapshot_build import (
    BOOTSTRAP_SH,
    CLEANUP_AND_DISK_SH,
    CRASH_LOG_HELPERS_PY,
    MIN_SNAPSHOT_FREE_BYTES,
    PULL_IMAGES_PY,
    VALIDATOR_IMAGE_MANIFEST,
    VALIDATOR_IMAGE_RECIPE_VERSION,
    VALIDATOR_UV_VERSION,
    pinned_task_paths,
)

log = get_logger("modal_snapshot_build")

DEFAULT_APP = "gymsiege-cybergym"
DEFAULT_SECRET = "gymsiege-huggingface"
DEFAULT_MANIFEST = common.RESULTS_DIR / "modal_snapshot.json"
REMOTE_REPO_DIR = "/root/cybergym-e2e"
BAKE_TIMEOUT_S = 4 * 60 * 60
DOCKER_READY_TIMEOUT_S = 180
# The SDK's own default (55s) is tuned for small sandboxes: an 8-task/83 GB
# bake's snapshot_filesystem() call already exceeded it and raised
# modal.exception.ServiceError: Timeout expired. The full 20-task/74.76 GB
# pinned set is a further ~9x, so this needs real headroom, not a tweak.
SNAPSHOT_FILESYSTEM_TIMEOUT_S = 1800


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bake the full CyberGym task set into a Modal VM filesystem snapshot."
    )
    parser.add_argument("--app", default=DEFAULT_APP, help="Modal App name")
    parser.add_argument(
        "--hf-secret",
        default=DEFAULT_SECRET,
        help="named Modal Secret that supplies HF_TOKEN",
    )
    parser.add_argument("--tasks-file", default="txt/tasks.pinned.txt")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="local manifest that receives the verified snapshot Image ID",
    )
    parser.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="development-only task limit; requires --output outside the canonical path",
    )
    return parser


def selected_tasks(args: argparse.Namespace) -> list[str]:
    tasks = pinned_task_paths(args.tasks_file)
    if args.limit is None:
        return tasks
    if args.limit < 1:
        raise SystemExit("--limit must be >= 1")
    if args.output.resolve() == DEFAULT_MANIFEST.resolve():
        raise SystemExit(
            "a limited bake cannot overwrite the canonical Modal snapshot manifest; "
            "pass a distinct --output path"
        )
    return tasks[: args.limit]


def _process_result(process: Any, label: str) -> dict[str, Any]:
    process.wait()
    stdout = process.stdout.read()
    stderr = process.stderr.read()
    returncode = process.returncode
    if stdout:
        log.info("[%s] stdout tail:\n%s", label, stdout[-8000:])
    if returncode != 0:
        raise RuntimeError(
            f"Modal bake step {label!r} failed with exit {returncode}:\n"
            f"{stderr[-8000:]}"
        )
    if stderr:
        log.debug("[%s] stderr tail:\n%s", label, stderr[-4000:])
    return {"label": label, "returncode": returncode}


def _exec(sb: Any, label: str, script: str, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    log.info("[%s] starting (timeout=%ss)", label, timeout)
    result = _process_result(sb.exec("bash", "-lc", script, timeout=timeout), label)
    result["duration_s"] = time.monotonic() - started
    log.info("[%s] completed in %.1fs", label, result["duration_s"])
    return result


def _wait_for_docker(sb: Any) -> dict[str, Any]:
    return _exec(
        sb,
        "docker_ready",
        "for i in $(seq 1 180); do "
        "if [ -S /var/run/docker.sock ] && docker info >/dev/null 2>&1; then "
        "echo ready; exit 0; fi; sleep 1; done; "
        "echo 'dockerd not ready after 180s' >&2; exit 1",
        DOCKER_READY_TIMEOUT_S,
    )


def _snapshot_validation_script(tasks: list[str]) -> str:
    expected = json.dumps(tasks)
    return f"""
set -euo pipefail
docker info >/dev/null
test -d {REMOTE_REPO_DIR}/data/projects
test "$(git -C {REMOTE_REPO_DIR} rev-parse HEAD)" != ""
python3 - <<'PY'
import json
from pathlib import Path
import tomli

tasks = json.loads({expected!r})
default_image = "gcr.io/oss-fuzz-base/base-builder@sha256:8eda74a11e800aead5a041ee479a65b33dab3150d6e89e5694e2b6eb27be98fc"
wanted = set()
firewall_proxy_image = "ubuntu/squid:latest"
for task in tasks:
    project, task_id = task.split("/", 1)
    project_toml = Path({REMOTE_REPO_DIR!r}) / "projects" / project / "project.toml"
    task_toml = Path({REMOTE_REPO_DIR!r}) / "projects" / project / task_id / "config.toml"
    if not project_toml.is_file() or not task_toml.is_file():
        raise FileNotFoundError(f"missing CyberGym metadata for {{task}}")
    cfg = tomli.loads(project_toml.read_text())
    cfg.update(tomli.loads(task_toml.read_text()))
    wanted.add(cfg.get("build_image", default_image))
wanted.add(firewall_proxy_image)

import docker
import subprocess
client = docker.from_env()
missing = []
for image in sorted(wanted):
    try:
        client.images.get(image)
    except docker.errors.ImageNotFound:
        missing.append(image)
if missing:
    raise RuntimeError(f"snapshot is missing {{len(missing)}} image(s): {{missing}}")
validator_manifest = json.loads(Path({VALIDATOR_IMAGE_MANIFEST!r}).read_text())
validator_images = validator_manifest.get("images", {{}})
task_images = wanted - {{firewall_proxy_image}}
if set(validator_images) != task_images:
    raise RuntimeError(
        "validator image mapping mismatch: "
        f"missing={{sorted(task_images - set(validator_images))}}, "
        f"extra={{sorted(set(validator_images) - task_images)}}"
    )
if validator_manifest.get("recipe_version") != {VALIDATOR_IMAGE_RECIPE_VERSION!r}:
    raise RuntimeError("validator image recipe version mismatch")
if validator_manifest.get("uv_version") != {VALIDATOR_UV_VERSION!r}:
    raise RuntimeError("validator uv version mismatch")
validator_check = (
    "command -v sudo git curl uv >/dev/null && "
    "test -x /scripts/.venv/bin/python && "
    "/scripts/.venv/bin/python -c 'import tomli' && "
    "ldconfig -p | grep -q 'libBlocksRuntime.so.0' && "
    "ldconfig -p | grep -q 'libunwind-ptrace.so.0' && "
    "ldconfig -p | grep -q 'libunwind-x86_64.so.8' && "
    "if test -x /src/honggfuzz/honggfuzz; then "
    "/src/honggfuzz/honggfuzz --help >/dev/null; fi"
)
for source_image, validator_image in sorted(validator_images.items()):
    try:
        client.images.get(validator_image)
    except docker.errors.ImageNotFound:
        raise RuntimeError(
            f"snapshot is missing validator image {{validator_image}} for {{source_image}}"
        )
    check = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", validator_image,
         "bash", "-lc", validator_check],
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        raise RuntimeError(
            f"offline validator dependency check failed for {{validator_image}}: "
            f"{{check.stdout[-1000:]}} {{check.stderr[-1000:]}}"
        )
Path("/root/gymsiege-modal-snapshot.json").write_text(json.dumps({{
    "tasks": tasks,
    "task_count": len(tasks),
    "images": sorted(wanted),
    "image_count": len(wanted),
    "validator_images": validator_images,
    "validator_image_count": len(validator_images),
}}, sort_keys=True))
print(json.dumps({{
    "task_count": len(tasks),
    "image_count": len(wanted),
    "validator_image_count": len(validator_images),
}}))
PY
"""


def _sandbox_create(
    modal: Any,
    app: Any,
    image: Any,
    *,
    secret: Any | None = None,
    vm_runtime: bool = False,
) -> Any:
    kwargs: dict[str, Any] = {
        "app": app,
        "image": image,
        "cpu": 2,
        "memory": 8192,
        "timeout": BAKE_TIMEOUT_S,
    }
    if vm_runtime:
        kwargs["experimental_options"] = {"vm_runtime": True}
    if secret is not None:
        kwargs["secrets"] = [secret]
    return modal.Sandbox.create(
        "/usr/bin/dockerd",
        "--host=unix:///var/run/docker.sock",
        **kwargs,
    )


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    try:
        import modal
    except ImportError as exc:
        raise RuntimeError("Modal SDK is missing; install requirements.txt") from exc

    tasks = selected_tasks(args)
    if not tasks:
        raise RuntimeError("no CyberGym tasks selected")

    app = modal.App.lookup(args.app, create_if_missing=True)
    hf_secret = modal.Secret.from_name(args.hf_secret)
    base_image = (
        modal.Image.from_registry("ubuntu:24.04")
        .env({"DEBIAN_FRONTEND": "noninteractive"})
        .apt_install(["docker.io", "docker-buildx"])
    )
    source = None
    fork = None
    steps: list[dict[str, Any]] = []
    started = time.monotonic()
    try:
        with modal.enable_output():
            source = _sandbox_create(
                modal, app, base_image, secret=hf_secret, vm_runtime=True
            )
        log.info("created Modal VM bake Sandbox %s", source.object_id)
        steps.append(_wait_for_docker(source))

        bootstrap = BOOTSTRAP_SH.format(
            repo_dir=REMOTE_REPO_DIR,
            repo_url=common.CYBERGYM_REPO_URL,
            tasks=tasks,
            dataset=common.HF_DATASET,
            crash_log_helpers=CRASH_LOG_HELPERS_PY,
        )
        steps.append(_exec(source, "bootstrap_toolchain", bootstrap, 3600))
        steps.append(
            _exec(
                source,
                "pull_pinned_images",
                PULL_IMAGES_PY.format(
                    repo_dir=REMOTE_REPO_DIR,
                    tasks=tasks,
                    validator_manifest=VALIDATOR_IMAGE_MANIFEST,
                    validator_recipe_version=VALIDATOR_IMAGE_RECIPE_VERSION,
                    validator_uv_version=VALIDATOR_UV_VERSION,
                ),
                7200,
            )
        )
        steps.append(
            _exec(
                source,
                "validate_snapshot_contents",
                _snapshot_validation_script(tasks),
                600,
            )
        )
        steps.append(
            _exec(
                source,
                "cleanup_and_disk_headroom",
                CLEANUP_AND_DISK_SH.format(
                    repo_dir=REMOTE_REPO_DIR,
                    minimum_free_bytes=MIN_SNAPSHOT_FREE_BYTES,
                ),
                600,
            )
        )

        snapshot_started = time.monotonic()
        snapshot = source.snapshot_filesystem(
            SNAPSHOT_FILESYSTEM_TIMEOUT_S, ttl=None
        )
        steps.append(
            {
                "label": "snapshot_filesystem",
                "returncode": 0,
                "duration_s": time.monotonic() - snapshot_started,
            }
        )
        snapshot_id = snapshot.object_id
        log.info("captured persistent Modal filesystem snapshot %s", snapshot_id)

        # Verify the documented fork path before publishing the Image ID.
        # vm_runtime=True is required here too: the snapshot's baked-in
        # /var/lib/docker only restores meaningfully under the VM Sandbox's
        # real kernel (see modal-docs/modal-vm-sandboxes.md). Without it, the
        # fork's dockerd entrypoint fails to start and the whole Sandbox
        # container exits within seconds -- which surfaces as an opaque
        # "already shut down" NotFoundError on the very next exec call.
        with modal.enable_output():
            fork = _sandbox_create(
                modal, app, modal.Image.from_id(snapshot_id), vm_runtime=True
            )
        steps.append(_wait_for_docker(fork))
        steps.append(
            _exec(
                fork,
                "verify_snapshot_fork",
                _snapshot_validation_script(tasks),
                600,
            )
        )

        manifest = {
            "provider": "modal",
            "app": args.app,
            "snapshot_image_id": snapshot_id,
            "snapshot_ttl": None,
            "vm_runtime_bake": True,
            "task_count": len(tasks),
            "tasks": tasks,
            "created_at": time.time(),
            "duration_s": time.monotonic() - started,
            "steps": steps,
        }
        atomic_write_json(args.output, manifest)
        log.info("verified snapshot manifest written to %s", args.output)
        return manifest
    finally:
        for label, sb in (("fork", fork), ("bake", source)):
            if sb is None:
                continue
            try:
                sb.terminate()
                log.info("terminated %s Sandbox %s", label, sb.object_id)
            except Exception as exc:
                log.error("failed to terminate %s Sandbox %s: %s", label, sb.object_id, exc)


def main() -> None:
    manifest = build_snapshot(build_parser().parse_args())
    print(manifest["snapshot_image_id"])


if __name__ == "__main__":
    main()
