#!/usr/bin/env python3
"""
GYMSIEGE Phase 1 — bake the `gymsiege-toolchain` snapshot.

One-time (well: once per toolchain revision) job that:
  1. creates a base sandbox,
  2. installs clang/LLVM sanitizers, Docker CLI, git, and the cybergym-e2e
     Python deps,
  3. clones sunblaze-ucb/cybergym-e2e into the sandbox,
  4. sets the ASLR entropy sysctl the sanitizer oracle needs,
  5. pre-pulls the Docker build images for every project referenced by
     tasks.pinned.txt (not all 139 projects — that would blow the time/
     quota budget for a bounded run; see README "Snapshot scope"),
  6. snapshots the sandbox as `gymsiege-toolchain`,
  7. records every step's wall-clock time to results/provisioning_bench.json
     under the "bake" key, and does one immediate cold-vs-snapshot sample
     so `orchestrator.py provision-bench` has a baseline to compare against.

Every call below is a real `daytona` SDK call (async client). Run with:

    python snapshot_build.py

Requires DAYTONA_API_KEY (and DAYTONA_API_URL/DAYTONA_TARGET if you're not
on the default region) in the environment. See README.md#credentials.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any

from daytona import (
    AsyncDaytona,
    CreateSandboxFromImageParams,
    CreateSandboxFromSnapshotParams,
    Image,
    Resources,
)

import common
from common import (
    CYBERGYM_REMOTE_DIR,
    CYBERGYM_REPO_URL,
    PROVISIONING_BENCH_JSON,
    SNAPSHOT_NAME,
    atomic_write_json,
    get_logger,
    load_json,
    load_tasks,
    require_env,
)

log = get_logger("snapshot_build")
HF_HOST_OBSERVATIONS_JSON = common.RESULTS_DIR / "huggingface_hosts.json"
CRASH_LOG_REPORT_JSON = common.RESULTS_DIR / "crash_log_fetch.json"
# Marker lines the in-sandbox bootstrap prints, and where each is persisted.
# Anything emitted this way is surfaced by timed_exec even on success --
# a report nobody sees is the same as no report.
EXEC_MARKERS = {
    "[hf_hosts] ": HF_HOST_OBSERVATIONS_JSON,
    "[crash_logs] ": CRASH_LOG_REPORT_JSON,
}

# Injected into BOOTSTRAP_SH and exec'd verbatim by tests, so the checksum and
# header logic is covered by real execution rather than string matching.
CRASH_LOG_HELPERS_PY = '''
import hashlib


def git_blob_sha1(payload):
    """Git's object hash: sha1(b"blob <len>\\0" + content)."""
    h = hashlib.sha1()
    h.update(b"blob " + str(len(payload)).encode() + b"\\0")
    h.update(payload)
    return h.hexdigest()


def normalize_etag(raw):
    """Return a bare 40-hex git blob SHA-1, or None if not one.

    Hugging Face returns the git blob SHA-1 as the ETag for plain-git files,
    quoted, and sometimes weak-prefixed. Anything else (an LFS/Xet multipart
    etag, a missing header) is not verifiable this way.
    """
    if not raw:
        return None
    value = raw.strip()
    if value.startswith("W/"):
        value = value[2:]
    value = value.strip('"').lower()
    if len(value) == 40 and all(c in "0123456789abcdef" for c in value):
        return value
    return None
'''
MIN_SNAPSHOT_FREE_BYTES = int(
    float(os.environ.get("GYMSIEGE_MIN_SNAPSHOT_FREE_GIB", "1.5")) * 1024**3
)

# The bake's own step timeouts total 1800 + 3600 + 600 + 3600 = 160 minutes.
# The 60-minute trial safety TTL is far shorter than that, and a full bake was
# stopped mid-`docker pull` because of it: a long pull makes no API calls, so
# the sandbox looked idle. Both the TTL and the auto-stop interval must exceed
# the work they are protecting, or the safety net becomes the failure.
# Trials keep the 60-minute default; this applies to the bake sandbox only.
BAKE_STEP_TIMEOUT_BUDGET_S = 1800 + 3600 + 600 + 3600
BAKE_TTL_MINUTES = int(os.environ.get("GYMSIEGE_BAKE_TTL_MIN", "180"))

# Installed *inside* the sandbox. Kept as one script so a single process.exec
# call gets us one clean exit code and one combined log instead of N round
# trips (each process.exec is a real network hop to the sandbox).
BOOTSTRAP_SH = r"""
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
export HF_XET_HIGH_PERFORMANCE=1
if command -v sudo >/dev/null 2>&1; then
  SUDO=sudo
elif [ "$(id -u)" -eq 0 ]; then
  SUDO=
else
  echo "bootstrap requires root or sudo" >&2
  exit 77
fi

echo "[bootstrap] apt toolchain"
$SUDO apt-get update -y
$SUDO apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential \
    clang clang-tools llvm lld \
    python3 python3-pip python3-venv \
    docker.io

echo "[bootstrap] docker daemon"
$SUDO service docker start || true
if ! /usr/bin/docker info >/dev/null 2>&1; then
  $SUDO nohup /usr/sbin/dockerd >/tmp/gymsiege-dockerd.log 2>&1 &
  for i in $(seq 1 30); do
    if [ -S /var/run/docker.sock ]; then
      $SUDO chgrp "$(id -gn)" /var/run/docker.sock
      $SUDO chmod 0660 /var/run/docker.sock
    fi
    /usr/bin/docker info >/dev/null 2>&1 && break
    sleep 2
  done
fi
/usr/bin/docker info >/dev/null

echo "[bootstrap] pip deps (mirrors cybergym-e2e's own requirements)"
python3 -m pip install --break-system-packages --upgrade pip
# Pinned, not floored, so the bake resolves the same versions as the local
# venv. Must match requirements.txt's sandbox-mirrored block exactly; enforced
# by tests/test_core.py rather than by this comment.
python3 -m pip install --break-system-packages \
    'httpx==0.28.1' 'tomli==2.4.1' 'tomli_w==1.2.0' 'anthropic==1.2.0' \
    'openai==3.6.0' 'boto3==1.43.84' 'huggingface_hub[hf_xet]==1.30.0' \
    'docker==7.2.0'

echo "[bootstrap] clone cybergym-e2e"
if [ ! -d "{repo_dir}" ]; then
  git clone --depth 1 {repo_url} "{repo_dir}"
fi

echo "[bootstrap] pinned CyberGym dataset payload"
cd "{repo_dir}"
python3 - <<'PY'
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from huggingface_hub import HfApi, get_token, snapshot_download

tasks = {tasks!r}
patterns = []
for task in tasks:
    patterns.extend((f"projects/{{task}}/**", f"data/projects/{{task}}/**"))

# Record only aggregate response codes and redirect hostnames. Never retain a
# signed Location value, query string, authorization header, token, or Daytona
# Secret placeholder.
token = get_token()
if not token:
    raise RuntimeError("HF_TOKEN is unavailable inside the bake sandbox")
repo_files = HfApi(token=True).list_repo_files("{dataset}", repo_type="dataset")
selected_archives = [
    path
    for path in repo_files
    if path.endswith("src.tgz")
    and any(
        path.startswith(f"projects/{{task}}/")
        or path.startswith(f"data/projects/{{task}}/")
        for task in tasks
    )
]
# Every file the bake will request, not just the archives. Which ones the
# client can size is a property of each file's storage class, so it must be
# measured per file rather than inferred from its extension.
selected_files = [
    path
    for path in repo_files
    if any(
        path.startswith(f"projects/{{task}}/")
        or path.startswith(f"data/projects/{{task}}/")
        for task in tasks
    )
]

statuses = Counter()
redirect_hosts = Counter()
# Files huggingface_hub cannot size on this network path: served directly
# (no redirect, so X-Linked-Size is absent) while Daytona's proxy removes
# Content-Length. Any such file aborts the entire snapshot_download, so they
# are excluded there and fetched directly instead. Classified by measurement,
# because assuming a single affected extension is what broke the 20-task bake
# after a 3-task validation passed.
needs_direct_fetch = []
with httpx.Client(follow_redirects=False, timeout=60) as client:
    for path in selected_files:
        url = (
            "https://huggingface.co/datasets/{dataset}/resolve/main/"
            + quote(path, safe="/")
        )
        response = client.head(url, headers={{"Authorization": f"Bearer {{token}}"}})
        location = response.headers.get("location")
        is_redirect = bool(location) and 300 <= response.status_code < 400
        if path in selected_archives:
            statuses[str(response.status_code)] += 1
            redirect_hosts[urlsplit(location).hostname or "no-redirect"] += 1
        if not is_redirect and not response.headers.get("x-linked-size"):
            needs_direct_fetch.append(path)

host_observation = {{
    "dataset": "{dataset}",
    "files_probed": len(selected_archives),
    "files_in_scope": len(selected_files),
    "direct_fetch_required": len(needs_direct_fetch),
    "source_host": "huggingface.co",
    "statuses": dict(statuses),
    "redirect_hosts": dict(redirect_hosts),
}}
Path("/tmp/gymsiege-hf-hosts.json").write_text(
    json.dumps(host_observation, sort_keys=True) + "\n",
    encoding="utf-8",
)
print("[hf_hosts] " + json.dumps(host_observation, sort_keys=True), flush=True)

# Exclude exactly the measured set. ignore_patterns matches literal paths as
# well as globs, so this excludes what was observed to be unsizable rather
# than a guessed extension. See DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md.
snapshot_download(
    repo_id="{dataset}",
    repo_type="dataset",
    local_dir="data",
    allow_patterns=patterns,
    ignore_patterns=needs_direct_fetch or None,
    token=True,
)

{crash_log_helpers}

crash_logs = needs_direct_fetch
# A pinned task contributing no file at all to the listing means its data is
# absent upstream; comparing only against what the listing returned would let
# that produce a clean-looking report.
tasks_with_files = {{
    t for t in tasks for p in selected_files
    if p.startswith(f"projects/{{t}}/") or p.startswith(f"data/projects/{{t}}/")
}}
missing_tasks = sorted(set(tasks) - tasks_with_files)

report = {{"tasks": len(tasks), "expected": len(crash_logs),
          "missing_tasks": missing_tasks, "written": 0, "verified": 0,
          "unverified": [], "mismatched": [], "failed": []}}
with httpx.Client(follow_redirects=True, timeout=120) as client:
    for path in crash_logs:
        url = (
            "https://huggingface.co/datasets/{dataset}/resolve/main/"
            + quote(path, safe="/")
        )
        try:
            r = client.get(url, headers={{"Authorization": f"Bearer {{token}}"}})
            r.raise_for_status()
        except Exception as exc:
            report["failed"].append({{"file": path, "error": type(exc).__name__}})
            continue
        target = Path("data") / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(r.content)
        report["written"] += 1
        # HF returns the git blob SHA-1 as the ETag for plain-git files, so
        # integrity is still checkable even though Content-Length is gone.
        etag = normalize_etag(r.headers.get("etag"))
        if etag is None:
            report["unverified"].append(path)
        elif git_blob_sha1(r.content) == etag:
            report["verified"] += 1
        else:
            report["mismatched"].append(path)

print("[crash_logs] " + json.dumps(report, sort_keys=True), flush=True)
# Deliberately non-fatal: warn, do not abort the bake.
if (report["failed"] or report["mismatched"] or report["unverified"]
        or report["missing_tasks"] or report["written"] != report["expected"]):
    print(
        "[crash_logs] WARN: {{}} of {{}} pinned tasks contributed no files "
        "upstream; {{}} written of {{}} directly-fetched; {{}} failed, "
        "{{}} checksum-mismatched, {{}} unverifiable. The bake continues by "
        "design; treat any affected task's patch-only result as suspect, "
        "since these files are part of the task input.".format(
            len(report["missing_tasks"]), report["tasks"],
            report["written"], report["expected"],
            len(report["failed"]), len(report["mismatched"]),
            len(report["unverified"]),
        ),
        flush=True,
    )
PY

# Dataset revisions have used both projects/<task> and
# data/projects/<task>. Normalize to run_agent.py's default data/projects.
if [ -d data/data/projects ] && [ ! -d data/projects ]; then
  mv data/data/projects data/projects
fi
test -d data/projects

echo "[bootstrap] ASLR entropy for sanitizer compatibility"
$SUDO sysctl -w vm.mmap_rnd_bits=28 || echo "[bootstrap] WARN: sysctl requires CAP_SYS_ADMIN in this sandbox; retry at task time"

echo "[bootstrap] versions"
clang --version
docker --version || echo "[bootstrap] WARN: docker daemon not reachable yet"
python3 --version
git -C "{repo_dir}" rev-parse HEAD
"""

PULL_IMAGES_PY = r"""
set -euxo pipefail
cd "{repo_dir}"
python3 - <<'PY'
import docker

tasks = {tasks!r}
client = docker.from_env()
from pathlib import Path
import tomli

wanted = set()
default_image = "gcr.io/oss-fuzz-base/base-builder@sha256:8eda74a11e800aead5a041ee479a65b33dab3150d6e89e5694e2b6eb27be98fc"
for task in tasks:
    project, task_id = task.split("/", 1)
    project_toml = Path("projects") / project / "project.toml"
    task_toml = Path("projects") / project / task_id / "config.toml"
    if not project_toml.exists() or not task_toml.exists():
        raise FileNotFoundError(f"missing CyberGym config for {{task}}")
    cfg = tomli.loads(project_toml.read_text())
    cfg.update(tomli.loads(task_toml.read_text()))
    wanted.add(cfg.get("build_image", default_image))

print(f"[pull_images] pulling {{len(wanted)}} images for {{len(tasks)}} pinned tasks")
for img in sorted(wanted):
    print(f"[pull_images] docker pull {{img}}")
    client.images.pull(img)
PY
"""

CLEANUP_AND_DISK_SH = r"""
set -euo pipefail
if command -v sudo >/dev/null 2>&1; then
  SUDO=sudo
elif [ "$(id -u)" -eq 0 ]; then
  SUDO=
else
  echo "cleanup requires root or sudo" >&2
  exit 77
fi

echo "[snapshot_cleanup] removing disposable package/download caches"
$SUDO apt-get clean
$SUDO rm -rf /var/lib/apt/lists/*
python3 -m pip cache purge >/dev/null 2>&1 || true
if command -v uv >/dev/null 2>&1; then
  uv cache clean >/dev/null 2>&1 || true
fi
rm -rf "${{HF_HOME:-$HOME/.cache/huggingface}}/xet" 2>/dev/null || true
sync

echo "[snapshot_disk] filesystem bytes"
df -h /
df -i /
echo "[snapshot_disk] dataset bytes"
du -sb "{repo_dir}/data" 2>/dev/null || true
echo "[snapshot_disk] docker bytes"
$SUDO du -sb /var/lib/docker 2>/dev/null || true
echo "[snapshot_disk] remaining cache bytes"
du -sb "$HOME/.cache/pip" "$HOME/.cache/uv" "$HOME/.cache/huggingface" 2>/dev/null || true

available_bytes=$(df --output=avail -B1 / | tail -n 1 | tr -d ' ')
minimum_bytes={minimum_free_bytes}
echo "[snapshot_disk] available_bytes=$available_bytes minimum_required_bytes=$minimum_bytes"
if [ "$available_bytes" -lt "$minimum_bytes" ]; then
  echo "unsafe free-space headroom before snapshot capture" >&2
  exit 88
fi
"""


def pinned_task_paths() -> list[str]:
    return [task.path for task in load_tasks(common.ROOT / "tasks.pinned.txt")]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bake the gymsiege-toolchain snapshot.")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Bake only the first N pinned tasks. For validating a change to the "
            "bootstrap cheaply. Requires --no-snapshot or --snapshot-name, "
            "because a truncated snapshot must never be published under the "
            "canonical name."
        ),
    )
    parser.add_argument(
        "--no-snapshot",
        action="store_true",
        help="Run the bootstrap (and image pull) but capture no snapshot and skip the restore probe.",
    )
    parser.add_argument(
        "--snapshot-name",
        default=None,
        metavar="NAME",
        help=f"Capture under a different name instead of {SNAPSHOT_NAME!r}.",
    )
    parser.add_argument(
        "--skip-image-pull",
        action="store_true",
        help="Skip the Docker image pull. Only meaningful with --no-snapshot; a snapshot without images is unusable.",
    )
    return parser


def resolve_options(args: argparse.Namespace) -> tuple[list[str], str | None, bool]:
    """Return (tasks, snapshot_name_or_None, skip_image_pull), failing closed.

    A limited bake produces a snapshot that is missing data for every task it
    did not download. Publishing that under SNAPSHOT_NAME would be silent
    corruption: trials restore from it by name, and demo.sh skips baking when
    a snapshot of that name is ACTIVE, so the truncated one would be treated
    as complete. Refuse the combination outright rather than warn.
    """
    tasks = pinned_task_paths()
    if args.limit is not None:
        if args.limit < 1:
            raise SystemExit("--limit must be >= 1")
        if not args.no_snapshot and args.snapshot_name is None:
            raise SystemExit(
                "--limit truncates the dataset, so it refuses to publish under "
                f"{SNAPSHOT_NAME!r}. Pass --no-snapshot to validate without "
                "capturing, or --snapshot-name to capture under a distinct name."
            )
        tasks = tasks[: args.limit]
        if not tasks:
            raise SystemExit("no pinned tasks selected")

    if args.skip_image_pull and not args.no_snapshot:
        raise SystemExit(
            "--skip-image-pull without --no-snapshot would capture a snapshot "
            "with no build images, which is unusable at trial time."
        )

    snapshot_name = None if args.no_snapshot else (args.snapshot_name or SNAPSHOT_NAME)
    return tasks, snapshot_name, args.skip_image_pull


async def timed_exec(
    sandbox,
    script: str,
    label: str,
    timeout: int = 1800,
    *,
    log_output: bool = False,
) -> dict[str, Any]:
    t0 = time.monotonic()
    log.info("exec[%s] starting (timeout=%ss)", label, timeout)
    r = await sandbox.process.exec(script, timeout=timeout)
    dt = time.monotonic() - t0
    ok = getattr(r, "exit_code", 0) == 0
    output = str(getattr(r, "result", r) or "")
    for line in output.splitlines():
        marker = next((m for m in EXEC_MARKERS if line.startswith(m)), None)
        if marker is not None:
            try:
                observation = json.loads(line.removeprefix(marker))
            except json.JSONDecodeError:
                log.warning("exec[%s] emitted an invalid %s record", label, marker.strip())
                continue
            observation["observed_at"] = time.time()
            atomic_write_json(EXEC_MARKERS[marker], observation)
            log.info("exec[%s] %s%s", label, marker, observation)
        elif line.startswith("[crash_logs] WARN"):
            # Surfaced at WARNING even on a successful bake: this is the only
            # signal that a task's crash.log is missing or unverified, and
            # patch-only hands that file to the agent as task input.
            log.warning("exec[%s] %s", label, line)
    log.info("exec[%s] done in %.1fs (exit=%s)", label, dt, getattr(r, "exit_code", "?"))
    if log_output and output:
        log.info("exec[%s] output:\n%s", label, output[-8000:])
    if not ok:
        log.warning("exec[%s] non-zero exit; tail of output:\n%s", label, output[-2000:])
    return {"label": label, "duration_s": dt, "exit_code": getattr(r, "exit_code", None), "ok": ok}


async def build_snapshot(args: argparse.Namespace | None = None) -> None:
    if args is None:
        args = build_parser().parse_args([])
    require_env("DAYTONA_API_KEY")
    hf_secret_name = require_env("GYMSIEGE_HF_SECRET_NAME")
    tasks, snapshot_name, skip_image_pull = resolve_options(args)

    # A truncated run's timings are not comparable to a full bake, and
    # bench["bake"] is overwritten wholesale below -- so a validation run must
    # not touch the file that holds the real bake's numbers.
    limited = args.limit is not None
    if limited:
        log.warning(
            "LIMITED bake: %d of %d pinned tasks, snapshot=%s. "
            "provisioning_bench.json will NOT be written.",
            len(tasks), len(pinned_task_paths()), snapshot_name or "(none)",
        )
    else:
        log.info("baking %s for %d pinned tasks", snapshot_name, len(tasks))

    bake_steps: list[dict[str, Any]] = []
    bench = load_json(PROVISIONING_BENCH_JSON, {"bake": [], "cold_create": [], "snapshot_create": [], "fork_create": []})

    def save_bench() -> None:
        if limited:
            return
        bench["bake"] = bake_steps
        atomic_write_json(PROVISIONING_BENCH_JSON, bench)

    async with AsyncDaytona() as daytona:
        secret_page = await asyncio.wait_for(
            daytona.secret.list(name=hf_secret_name, limit=200),
            timeout=180,
        )
        if not any(item.name == hf_secret_name for item in secret_page.items):
            raise RuntimeError(
                f"Daytona organization Secret {hf_secret_name!r} does not exist. "
                "CyberGym data is gated; set HF_TOKEN locally and run "
                "`configure_secrets.py huggingface` before baking."
            )

        t_create0 = time.monotonic()
        sandbox = await daytona.create(
            CreateSandboxFromImageParams(
                image=Image.debian_slim("3.12"),
                name=f"siege-cybergym-bake-{int(time.time())}",
                os_user="root",
                resources=Resources(cpu=2, memory=4, disk=10),
                # Without this, Daytona's default auto-stop applies and can
                # stop the sandbox during a long image pull, which issues no
                # API calls and so reads as idle.
                auto_stop_interval=BAKE_TTL_MINUTES,
                ttl_minutes=BAKE_TTL_MINUTES,
            ),
            timeout=600,
        )
        t_create = time.monotonic() - t_create0
        log.info("base sandbox created in %.1fs (id=%s)", t_create, sandbox.id)
        bake_steps.append({"label": "base_create", "duration_s": t_create, "exit_code": 0, "ok": True})

        try:
            # Must outlast the bake's own step timeouts; see BAKE_TTL_MINUTES.
            # The finally block drops this back to 60 minutes before deleting,
            # so a crash still cannot leak a long-lived sandbox.
            await sandbox.set_ttl(BAKE_TTL_MINUTES)
            await sandbox.set_autostop_interval(BAKE_TTL_MINUTES)
            hf_secrets = common.sandbox_secret_refs(("HF_TOKEN",))
            log.info("attaching Hugging Face organization Secret")
            await sandbox.update_secrets(hf_secrets)
            await sandbox.stop(timeout=120)
            await sandbox.start(timeout=120)

            bootstrap = BOOTSTRAP_SH.format(
                repo_dir=CYBERGYM_REMOTE_DIR,
                repo_url=CYBERGYM_REPO_URL,
                tasks=tasks,
                dataset=common.HF_DATASET,
                crash_log_helpers=CRASH_LOG_HELPERS_PY,
            )
            bootstrap_step = await timed_exec(
                sandbox, bootstrap, "bootstrap_toolchain", timeout=1800
            )
            bake_steps.append(bootstrap_step)
            if not bootstrap_step["ok"]:
                raise RuntimeError(
                    "mandatory CyberGym toolchain/data bootstrap failed; "
                    "refusing to pull images or capture an unusable snapshot"
                )

            if skip_image_pull:
                log.warning("skipping pinned-image pull (--skip-image-pull)")
            else:
                pull = PULL_IMAGES_PY.format(repo_dir=CYBERGYM_REMOTE_DIR, tasks=tasks)
                pull_step = await timed_exec(
                    sandbox, pull, "pull_pinned_images", timeout=3600
                )
                bake_steps.append(pull_step)
                if not pull_step["ok"]:
                    raise RuntimeError(
                        "mandatory pinned-image pull failed; refusing to capture "
                        "an incomplete snapshot"
                    )

            cleanup_and_disk = CLEANUP_AND_DISK_SH.format(
                repo_dir=CYBERGYM_REMOTE_DIR,
                minimum_free_bytes=MIN_SNAPSHOT_FREE_BYTES,
            )
            disk_step = await timed_exec(
                sandbox,
                cleanup_and_disk,
                "cleanup_and_disk_headroom",
                timeout=600,
                log_output=True,
            )
            bake_steps.append(disk_step)
            if not disk_step["ok"]:
                raise RuntimeError(
                    "snapshot cleanup/disk headroom gate failed; refusing to capture"
                )

            if snapshot_name is None:
                log.warning("--no-snapshot: bootstrap validated, capturing nothing")
            else:
                t_snap0 = time.monotonic()
                await sandbox.create_snapshot(snapshot_name, timeout=3600)
                t_snap = time.monotonic() - t_snap0
                log.info("snapshot '%s' created in %.1fs", snapshot_name, t_snap)
                bake_steps.append({"label": "create_snapshot", "duration_s": t_snap, "exit_code": 0, "ok": True})

        finally:
            save_bench()
            # Cleanup must never mask the failure that brought us here, and a
            # sandbox that is already gone -- TTL expiry, platform action -- is
            # a benign outcome rather than an error. Previously a bare
            # set_ttl() raised 404 when the sandbox had already been deleted,
            # which replaced the real DaytonaConnectionTimeoutError with a
            # confusing "Failed to set TTL" and skipped delete() entirely.
            try:
                await sandbox.set_ttl(60)
            except Exception as exc:
                log.warning(
                    "could not reset TTL on %s (continuing to delete): %s",
                    sandbox.id, exc,
                )
            try:
                await sandbox.delete(wait=True, timeout=180)
                log.info(
                    "base sandbox %s deleted (safety ttl was also set to 60m)",
                    sandbox.id,
                )
            except Exception as exc:
                if "not found" in str(exc).lower():
                    log.info(
                        "base sandbox %s was already gone (TTL expiry or "
                        "platform action); nothing leaked", sandbox.id,
                    )
                else:
                    log.error(
                        "base sandbox %s NOT deleted -- run `orchestrator.py "
                        "reap`: %s", sandbox.id, exc,
                    )

        t_restore = None
        if snapshot_name is not None:
            # One immediate snapshot-restore sample so provision-bench has a
            # same-day baseline even before orchestrator.py runs the full sweep.
            t_restore0 = time.monotonic()
            restored = await daytona.create(
                CreateSandboxFromSnapshotParams(snapshot=snapshot_name, name="siege-snapshot-probe")
            )
            t_restore = time.monotonic() - t_restore0
            log.info("snapshot-restore probe created in %.1fs", t_restore)
            await restored.set_ttl(5)
            await restored.delete(wait=True, timeout=180)

    if not limited:
        bench["bake"] = bake_steps
        if t_restore is not None:
            bench["snapshot_create"].append({"ts": time.time(), "duration_s": t_restore})
        bench["cold_create"].append({"ts": time.time(), "duration_s": t_create})
        atomic_write_json(PROVISIONING_BENCH_JSON, bench)

    total = sum(s["duration_s"] for s in bake_steps)
    ok = all(s["ok"] for s in bake_steps)
    log.info("=== snapshot bake %s in %.1fs total ===", "SUCCEEDED" if ok else "COMPLETED WITH WARNINGS", total)
    if t_restore is not None:
        log.info("cold create: %.1fs | snapshot restore: %.1fs (delta: %.1fs, %.0f%% faster)",
                  t_create, t_restore, t_create - t_restore, 100 * (t_create - t_restore) / max(t_create, 1e-9))
    if limited:
        log.warning(
            "this was a LIMITED validation bake over %d task(s); it proves the "
            "bootstrap path only, not a usable snapshot", len(tasks)
        )
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(build_snapshot(build_parser().parse_args()))
