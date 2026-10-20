#!/usr/bin/env python3
"""Bake and verify the complete CyberGym toolchain as a Modal VM snapshot.

The returned filesystem snapshot is a Modal Image.  Its ID is written locally
only after an independent Sandbox restored from it can start Docker and see
the expected task/image manifest.  Modal credentials are read by the Modal
SDK; the gated Hugging Face credential is attached as a named Modal Secret.
"""

from __future__ import annotations

import argparse
import base64
import json
import shlex
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

# install_codex.sh pins this NVM release, but some task prepare scripts rewrite
# every https://github.com/ URL to /deps/git/github.com/.  Keep the exact tag
# object and peeled commit here so the mirror cannot silently drift if upstream
# retags the release.
NVM_VERSION = "v0.40.2"
NVM_TAG_OBJECT = "44f0e129d8a598a72f4aaf581db9b50c0803f1f9"
NVM_COMMIT = "ffec9fec724da725013d5b50e763908113983fc3"
NVM_MIRROR_RELATIVE = "scripts/agent_mirrors/nvm.git"
NVM_CONTAINER_MIRROR = "/deps/git/github.com/nvm-sh/nvm.git"
NVM_PATCH_MARKER = "GYMSIEGE_NVM_MIRROR_V1"
CODEX_INSTALL_CONTROL_TASK = "curl/arvo_66012"
CODEX_INSTALL_MIRROR_TASKS = [
    "arrow/arvo_41221",
    "opensc/oss-fuzz_448717172",
]

_ORIGINAL_CODEX_INSTALL_BLOCK = '''    elif agent_id == "codex":
        if not scripts_dir:
            raise ValueError("scripts_dir required for codex")
        copy_to_container(container_id, scripts_dir / "install_codex.sh", "/install_codex.sh")
        code, _, stderr = exec_run(
            container_id, "bash -eux /install_codex.sh",
            "Installing Codex", timeout=1800, env=env
        )
        if code != 0:
            raise Exception(f"Failed to install Codex: {stderr[-500:]}")
'''

_MIRRORED_CODEX_INSTALL_BLOCK = f'''    elif agent_id == "codex":
        if not scripts_dir:
            raise ValueError("scripts_dir required for codex")
        # {NVM_PATCH_MARKER}: task preparation may redirect every GitHub URL
        # to /deps. Seed only containers with that rewrite, leaving the other
        # pinned task environments byte-for-byte unchanged at install time.
        _, github_mirrors, _ = exec_run(
            container_id,
            "git config --global --get-all "
            "'url.file:///deps/git/github.com/.insteadOf'",
            "Checking GitHub mirror rewrite",
            verbose=False,
        )
        if any(
            target.rstrip("/") == "https://github.com"
            for target in github_mirrors.splitlines()
        ):
            nvm_mirror = scripts_dir / "agent_mirrors" / "nvm.git"
            if not nvm_mirror.is_dir():
                raise FileNotFoundError(f"Missing pinned NVM mirror: {{nvm_mirror}}")
            code, _, stderr = exec_run(
                container_id,
                "mkdir -p {NVM_CONTAINER_MIRROR}",
                "Preparing pinned NVM mirror",
                verbose=False,
            )
            if code != 0:
                raise Exception(f"Failed to prepare NVM mirror: {{stderr[-500:]}}")
            copy_to_container(
                container_id, nvm_mirror, "{NVM_CONTAINER_MIRROR}"
            )
        copy_to_container(container_id, scripts_dir / "install_codex.sh", "/install_codex.sh")
        code, _, stderr = exec_run(
            container_id, "bash -eux /install_codex.sh",
            "Installing Codex", timeout=1800, env=env
        )
        if code != 0:
            raise Exception(f"Failed to install Codex: {{stderr[-500:]}}")
'''


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
    parser.add_argument(
        "--upgrade-from-manifest",
        type=Path,
        metavar="PATH",
        help=(
            "restore PATH's verified snapshot and apply only the pinned NVM "
            "mirror repair instead of doing a full bake"
        ),
    )
    return parser


def selected_tasks(args: argparse.Namespace) -> list[str]:
    if args.upgrade_from_manifest is not None and args.limit is not None:
        raise SystemExit("--limit cannot be combined with --upgrade-from-manifest")
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


def _wait_for_docker(sb: Any, label: str = "docker_ready") -> dict[str, Any]:
    return _exec(
        sb,
        label,
        "for i in $(seq 1 180); do "
        "if [ -S /var/run/docker.sock ] && docker info >/dev/null 2>&1; then "
        "echo ready; exit 0; fi; sleep 1; done; "
        "echo 'dockerd not ready after 180s' >&2; exit 1",
        DOCKER_READY_TIMEOUT_S,
    )


def _nvm_mirror_dir(repo_dir: str = REMOTE_REPO_DIR) -> str:
    return f"{repo_dir}/{NVM_MIRROR_RELATIVE}"


def _nvm_mirror_preflight_script(repo_dir: str = REMOTE_REPO_DIR) -> str:
    """Return the fail-closed checks shared by bake and upgrade validation."""
    mirror = _nvm_mirror_dir(repo_dir)
    run_agent = f"{repo_dir}/scripts/run_agent.py"
    return f"""
set -euo pipefail
mirror={mirror!r}
test -d "$mirror"
test "$(git --git-dir="$mirror" rev-parse refs/tags/{NVM_VERSION})" = {NVM_TAG_OBJECT!r}
test "$(git --git-dir="$mirror" rev-parse 'refs/tags/{NVM_VERSION}^{{}}')" = {NVM_COMMIT!r}
grep -Fq {NVM_PATCH_MARKER!r} {run_agent!r}
"""


def _nvm_container_visibility_command(
    container_mirror: str = NVM_CONTAINER_MIRROR,
) -> str:
    """Return the exact fail-closed check run in each pinned task image."""
    head = shlex.quote(f"{container_mirror}/HEAD")
    packed_refs = shlex.quote(f"{container_mirror}/packed-refs")
    pack_glob = shlex.quote(f"{container_mirror}/objects/pack/*.pack")
    tag_ref = shlex.quote(f"{NVM_TAG_OBJECT} refs/tags/{NVM_VERSION}")
    return (
        f"test -f {head} && "
        f"grep -Fq {tag_ref} {packed_refs} && "
        f"compgen -G {pack_glob} >/dev/null"
    )


def _nvm_mirror_upgrade_script() -> str:
    """Install the pinned mirror and narrowly patch upstream Codex install."""
    old_block = base64.b64encode(_ORIGINAL_CODEX_INSTALL_BLOCK.encode()).decode()
    new_block = base64.b64encode(_MIRRORED_CODEX_INSTALL_BLOCK.encode()).decode()
    mirror = _nvm_mirror_dir()
    run_agent = f"{REMOTE_REPO_DIR}/scripts/run_agent.py"
    return f"""
set -euo pipefail
mirror={mirror!r}
mkdir -p "$(dirname "$mirror")"
if [ ! -d "$mirror" ]; then
  git init --bare "$mirror"
fi
git --git-dir="$mirror" fetch --force --no-tags \
  https://github.com/nvm-sh/nvm.git \
  '+refs/tags/{NVM_VERSION}:refs/tags/{NVM_VERSION}'
git --git-dir="$mirror" gc --prune=now
python3 - <<'PY'
import base64
from pathlib import Path

path = Path({run_agent!r})
source = path.read_text()
marker = {NVM_PATCH_MARKER!r}
old = base64.b64decode({old_block!r}).decode()
new = base64.b64decode({new_block!r}).decode()
if marker not in source:
    if source.count(old) != 1:
        raise RuntimeError(
            "upstream Codex install block changed; refusing a non-exact patch"
        )
    source = source.replace(old, new)
compile(source, str(path), "exec")
path.write_text(source)
PY
{_nvm_mirror_preflight_script()}
"""


def _exec_json_marker(
    sb: Any,
    label: str,
    script: str,
    timeout: int,
    marker: str,
) -> tuple[dict[str, Any], Any]:
    """Execute a remote check and parse its single prefixed JSON record."""
    started = time.monotonic()
    log.info("[%s] starting (timeout=%ss)", label, timeout)
    process = sb.exec("bash", "-lc", script, timeout=timeout)
    process.wait()
    stdout = process.stdout.read()
    stderr = process.stderr.read()
    if stdout:
        log.info("[%s] stdout tail:\n%s", label, stdout[-8000:])
    if process.returncode != 0:
        raise RuntimeError(
            f"Modal bake step {label!r} failed with exit {process.returncode}:\n"
            f"{stderr[-8000:]}"
        )
    prefix = f"{marker}="
    records = [line[len(prefix) :] for line in stdout.splitlines() if line.startswith(prefix)]
    if len(records) != 1:
        raise RuntimeError(
            f"Modal bake step {label!r} emitted {len(records)} {marker!r} records"
        )
    payload = json.loads(records[0])
    step = {
        "label": label,
        "returncode": process.returncode,
        "duration_s": time.monotonic() - started,
    }
    if stderr:
        log.debug("[%s] stderr tail:\n%s", label, stderr[-4000:])
    log.info("[%s] completed in %.1fs", label, step["duration_s"])
    return step, payload


def _codex_install_check_script(tasks: list[str]) -> str:
    """Exercise workspace prep and Codex installation without running an agent."""
    encoded_tasks = json.dumps(tasks)
    mirror_tasks = json.dumps(CODEX_INSTALL_MIRROR_TASKS)
    return f"""
set -euo pipefail
cd {REMOTE_REPO_DIR}
python3 - <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import tomli

sys.path.insert(0, str(Path("scripts").resolve()))
from run_agent import install
from utils import cleanup_container, setup_workspace, start_container

tasks = json.loads({encoded_tasks!r})
mirror_tasks = set(json.loads({mirror_tasks!r}))
default_image = (
    "gcr.io/oss-fuzz-base/base-builder@sha256:"
    "8eda74a11e800aead5a041ee479a65b33dab3150d6e89e5694e2b6eb27be98fc"
)
results = {{}}

def container_output(container_id, command):
    completed = subprocess.run(
        ["docker", "exec", container_id, "bash", "-lc", command],
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"container probe failed ({{completed.returncode}}): {{command}}\\n"
            f"{{completed.stdout[-1000:]}}\\n{{completed.stderr[-1000:]}}"
        )
    return completed.stdout.strip()

for task in tasks:
    project, task_id = task.split("/", 1)
    cfg = tomli.loads((Path("projects") / project / "project.toml").read_text())
    cfg.update(
        tomli.loads(
            (Path("projects") / project / task_id / "config.toml").read_text()
        )
    )
    image = cfg.get("build_image", default_image)
    container_id = start_container(image, env_vars={{}}, workdir="/src")
    try:
        setup_workspace(
            container_id,
            Path("data/projects") / task,
            Path("projects") / task,
            "e2e",
            copy_gt_poc=False,
            scripts_dir=Path("scripts").resolve(),
            run_prepare=True,
        )
        install(
            container_id,
            "codex",
            scripts_dir=Path("scripts").resolve(),
        )
        mirror = container_output(
            container_id,
            "if test -d {NVM_CONTAINER_MIRROR}; then "
            "git -C {NVM_CONTAINER_MIRROR} rev-parse "
            "'refs/tags/{NVM_VERSION}^{{}}'; else printf absent; fi",
        )
        rewrite = container_output(
            container_id,
            "git config --global --get-all "
            "'url.file:///deps/git/github.com/.insteadOf' || true",
        )
        result = {{
            "task": task,
            "image": image,
            "node": container_output(
                container_id, "source /root/.nvm/nvm.sh && node --version"
            ),
            "npm": container_output(
                container_id, "source /root/.nvm/nvm.sh && npm --version"
            ),
            "nvm": container_output(
                container_id, "source /root/.nvm/nvm.sh && nvm --version"
            ),
            "codex": container_output(
                container_id, "source /root/.nvm/nvm.sh && codex --version"
            ),
            "nvm_mirror": mirror,
            "github_rewrite": rewrite,
        }}
        if result["codex"] != "codex-cli 0.118.0":
            raise RuntimeError(f"unexpected Codex version for {{task}}: {{result}}")
        if result["nvm"] != "0.40.2":
            raise RuntimeError(f"unexpected NVM version for {{task}}: {{result}}")
        expected_mirror = {NVM_COMMIT!r} if task in mirror_tasks else "absent"
        if mirror != expected_mirror:
            raise RuntimeError(
                f"unexpected NVM mirror for {{task}}: {{mirror}} != {{expected_mirror}}"
            )
        results[task] = result
    finally:
        cleanup_container(container_id)

print("CODEX_INSTALL_CHECK=" + json.dumps({{
    "cybergym_revision": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True
    ).strip(),
    "tasks": results,
}}, sort_keys=True))
PY
"""


def _assert_control_parity(baseline: dict[str, Any], fresh: dict[str, Any]) -> None:
    """Fail the upgrade if the unaffected install control drifted."""
    if baseline.get("cybergym_revision") != fresh.get("cybergym_revision"):
        raise RuntimeError("CyberGym upstream revision changed during snapshot upgrade")
    old = baseline.get("tasks", {}).get(CODEX_INSTALL_CONTROL_TASK, {})
    new = fresh.get("tasks", {}).get(CODEX_INSTALL_CONTROL_TASK, {})
    keys = ("image", "node", "npm", "nvm", "codex", "nvm_mirror", "github_rewrite")
    changed = {key: (old.get(key), new.get(key)) for key in keys if old.get(key) != new.get(key)}
    if changed:
        raise RuntimeError(f"Codex install control drifted during upgrade: {changed}")


def _snapshot_validation_script(tasks: list[str]) -> str:
    expected = json.dumps(tasks)
    return f"""
set -euo pipefail
docker info >/dev/null
test -d {REMOTE_REPO_DIR}/data/projects
test "$(git -C {REMOTE_REPO_DIR} rev-parse HEAD)" != ""
test -x /usr/bin/qemu-i386-static
{_nvm_mirror_preflight_script()}
python3 - <<'PY'
import json
from pathlib import Path
import tomli

tasks = json.loads({expected!r})
default_image = (
    "gcr.io/oss-fuzz-base/base-builder@sha256:"
    "8eda74a11e800aead5a041ee479a65b33dab3150d6e89e5694e2b6eb27be98fc"
)
wanted = set()
source_images = {{}}
github_rewrite_tasks = []
firewall_proxy_image = "ubuntu/squid:latest"
for task in tasks:
    project, task_id = task.split("/", 1)
    project_toml = Path({REMOTE_REPO_DIR!r}) / "projects" / project / "project.toml"
    task_toml = Path({REMOTE_REPO_DIR!r}) / "projects" / project / task_id / "config.toml"
    if not project_toml.is_file() or not task_toml.is_file():
        raise FileNotFoundError(f"missing CyberGym metadata for {{task}}")
    cfg = tomli.loads(project_toml.read_text())
    cfg.update(tomli.loads(task_toml.read_text()))
    source_image = cfg.get("build_image", default_image)
    wanted.add(source_image)
    source_images.setdefault(source_image, []).append(task)
    prepare = task_toml.parent / "prepare.sh"
    prepare_source = prepare.read_text() if prepare.is_file() else ""
    if (
        "file:///deps/git/github.com/" in prepare_source
        and "insteadOf" in prepare_source
        and "https://github.com/" in prepare_source
    ):
        github_rewrite_tasks.append(task)
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

# Prove that the exact mirror delivery added to run_agent.py works for every
# pinned source image.  These throwaway, network-disabled containers do not run
# task preparation or an agent; they only receive and expose the pinned mirror.
mirror_dir = {_nvm_mirror_dir()!r}
container_mirror = {NVM_CONTAINER_MIRROR!r}
mirror_visibility = {{}}
for source_image, image_tasks in sorted(source_images.items()):
    created = subprocess.run(
        [
            "docker", "create", "--network", "none",
            "--entrypoint", "/bin/bash", source_image,
            "-lc", "while :; do sleep 3600; done",
        ],
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        raise RuntimeError(
            f"could not create NVM mirror probe for {{source_image}}: "
            f"{{created.stdout[-1000:]}} {{created.stderr[-1000:]}}"
        )
    container_id = created.stdout.strip()
    try:
        subprocess.run(["docker", "start", container_id], check=True, capture_output=True)
        mkdir = subprocess.run(
            ["docker", "exec", container_id, "mkdir", "-p", container_mirror],
            capture_output=True,
            text=True,
        )
        if mkdir.returncode != 0:
            raise RuntimeError(
                f"task image cannot create NVM mirror path {{source_image}}: "
                f"{{mkdir.stdout[-1000:]}} {{mkdir.stderr[-1000:]}}"
            )
        copied = subprocess.run(
            ["docker", "cp", f"{{mirror_dir}}/.", f"{{container_id}}:{{container_mirror}}"],
            capture_output=True,
            text=True,
        )
        if copied.returncode != 0:
            raise RuntimeError(
                f"task image cannot receive NVM mirror {{source_image}}: "
                f"{{copied.stdout[-1000:]}} {{copied.stderr[-1000:]}}"
            )
        check = subprocess.run(
            [
                "docker", "exec", container_id, "bash", "-lc",
                {_nvm_container_visibility_command()!r},
            ],
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            raise RuntimeError(
                f"task image cannot see complete NVM mirror {{source_image}}: "
                f"{{check.stdout[-1000:]}} {{check.stderr[-1000:]}}"
            )
        mirror_visibility[source_image] = image_tasks
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            capture_output=True,
            text=True,
        )
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
    "nvm_version": {NVM_VERSION!r},
    "nvm_commit": {NVM_COMMIT!r},
    "nvm_mirror_visible_in_images": mirror_visibility,
    "github_rewrite_tasks": sorted(github_rewrite_tasks),
}}, sort_keys=True))
print(json.dumps({{
    "task_count": len(tasks),
    "image_count": len(wanted),
    "validator_image_count": len(validator_images),
    "nvm_mirror_image_count": len(mirror_visibility),
    "github_rewrite_task_count": len(github_rewrite_tasks),
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


def _load_upgrade_source(
    args: argparse.Namespace, tasks: list[str]
) -> dict[str, Any]:
    path = args.upgrade_from_manifest
    if path is None:
        raise RuntimeError("upgrade source manifest is required")
    if path.resolve() == args.output.resolve():
        raise RuntimeError("upgrade output must not overwrite its source manifest")
    manifest = json.loads(path.read_text())
    if manifest.get("provider") != "modal":
        raise RuntimeError("upgrade source is not a Modal snapshot manifest")
    if manifest.get("app") != args.app:
        raise RuntimeError(
            f"upgrade source app {manifest.get('app')!r} does not match {args.app!r}"
        )
    if not manifest.get("snapshot_image_id"):
        raise RuntimeError("upgrade source has no snapshot_image_id")
    if manifest.get("tasks") != tasks:
        raise RuntimeError(
            "upgrade source task list differs from the current pinned task list"
        )
    missing = [task for task in CODEX_INSTALL_MIRROR_TASKS if task not in tasks]
    if missing:
        raise RuntimeError(f"NVM repair tasks are not pinned: {missing}")
    return manifest


def upgrade_snapshot(
    args: argparse.Namespace,
    modal: Any,
    tasks: list[str],
) -> dict[str, Any]:
    """Apply and independently verify the narrow NVM mirror repair."""
    source_manifest = _load_upgrade_source(args, tasks)
    old_snapshot_id = source_manifest["snapshot_image_id"]
    app = modal.App.lookup(args.app, create_if_missing=True)
    source = None
    fork = None
    upgrade_steps: list[dict[str, Any]] = []
    started = time.monotonic()
    try:
        with modal.enable_output():
            source = _sandbox_create(
                modal,
                app,
                modal.Image.from_id(old_snapshot_id),
                vm_runtime=True,
            )
        log.info("created Modal VM upgrade Sandbox %s", source.object_id)
        upgrade_steps.append(_wait_for_docker(source, "docker_ready_upgrade_source"))

        baseline_step, baseline = _exec_json_marker(
            source,
            "verify_codex_install_control_before_upgrade",
            _codex_install_check_script([CODEX_INSTALL_CONTROL_TASK]),
            2400,
            "CODEX_INSTALL_CHECK",
        )
        upgrade_steps.append(baseline_step)
        upgrade_steps.append(
            _exec(
                source,
                "install_pinned_nvm_mirror",
                _nvm_mirror_upgrade_script(),
                600,
            )
        )
        upgrade_steps.append(
            _exec(
                source,
                "validate_snapshot_contents_upgrade",
                _snapshot_validation_script(tasks),
                1200,
            )
        )

        snapshot_started = time.monotonic()
        snapshot = source.snapshot_filesystem(
            SNAPSHOT_FILESYSTEM_TIMEOUT_S,
            ttl=None,
        )
        upgrade_steps.append(
            {
                "label": "snapshot_filesystem_upgrade",
                "returncode": 0,
                "duration_s": time.monotonic() - snapshot_started,
            }
        )
        snapshot_id = snapshot.object_id
        log.info("captured upgraded Modal filesystem snapshot %s", snapshot_id)

        with modal.enable_output():
            fork = _sandbox_create(
                modal,
                app,
                modal.Image.from_id(snapshot_id),
                vm_runtime=True,
            )
        upgrade_steps.append(_wait_for_docker(fork, "docker_ready_upgrade_fork"))
        upgrade_steps.append(
            _exec(
                fork,
                "verify_snapshot_fork_upgrade",
                _snapshot_validation_script(tasks),
                1200,
            )
        )
        install_tasks = [CODEX_INSTALL_CONTROL_TASK, *CODEX_INSTALL_MIRROR_TASKS]
        fresh_step, fresh = _exec_json_marker(
            fork,
            "verify_codex_install_after_upgrade",
            _codex_install_check_script(install_tasks),
            3600,
            "CODEX_INSTALL_CHECK",
        )
        upgrade_steps.append(fresh_step)
        _assert_control_parity(baseline, fresh)

        control_before = baseline["tasks"][CODEX_INSTALL_CONTROL_TASK]
        control_after = fresh["tasks"][CODEX_INSTALL_CONTROL_TASK]
        previous_upgrade = source_manifest.get("upgrade")
        upgrade_metadata: dict[str, Any] = {
            "reason": (
                "Provide the pinned NVM v0.40.2 mirror only to task containers "
                "whose prepare step rewrites GitHub URLs to /deps"
            ),
            "nvm_version": NVM_VERSION,
            "nvm_tag_object": NVM_TAG_OBJECT,
            "nvm_commit": NVM_COMMIT,
            "cybergym_revision": fresh["cybergym_revision"],
            "repair_tasks": CODEX_INSTALL_MIRROR_TASKS,
            "verified_fresh_restore": True,
            "control_task": CODEX_INSTALL_CONTROL_TASK,
            "control_before": control_before,
            "control_after": control_after,
            "install_verification": fresh["tasks"],
        }
        if previous_upgrade:
            upgrade_metadata["previous_upgrade"] = previous_upgrade

        manifest = {
            "provider": "modal",
            "app": args.app,
            "snapshot_image_id": snapshot_id,
            "upgraded_from_snapshot_image_id": old_snapshot_id,
            "snapshot_ttl": None,
            "vm_runtime_bake": True,
            "task_count": len(tasks),
            "tasks": tasks,
            "created_at": time.time(),
            "duration_s": time.monotonic() - started,
            "upgrade": upgrade_metadata,
            "steps": [*source_manifest.get("steps", []), *upgrade_steps],
        }
        atomic_write_json(args.output, manifest)
        log.info("verified upgraded snapshot manifest written to %s", args.output)
        return manifest
    finally:
        for label, sb in (("upgrade fork", fork), ("upgrade source", source)):
            if sb is None:
                continue
            try:
                sb.terminate()
                log.info("terminated %s Sandbox %s", label, sb.object_id)
            except Exception as exc:
                log.error("failed to terminate %s Sandbox %s: %s", label, sb.object_id, exc)


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    try:
        import modal
    except ImportError as exc:
        raise RuntimeError("Modal SDK is missing; install requirements.txt") from exc

    tasks = selected_tasks(args)
    if not tasks:
        raise RuntimeError("no CyberGym tasks selected")

    if args.upgrade_from_manifest is not None:
        return upgrade_snapshot(args, modal, tasks)

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
                "install_pinned_nvm_mirror",
                _nvm_mirror_upgrade_script(),
                600,
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
        install_step, install_verification = _exec_json_marker(
            fork,
            "verify_codex_install",
            _codex_install_check_script(
                [CODEX_INSTALL_CONTROL_TASK, *CODEX_INSTALL_MIRROR_TASKS]
            ),
            3600,
            "CODEX_INSTALL_CHECK",
        )
        steps.append(install_step)

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
            "nvm_mirror": {
                "version": NVM_VERSION,
                "tag_object": NVM_TAG_OBJECT,
                "commit": NVM_COMMIT,
                "install_verification": install_verification,
            },
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
