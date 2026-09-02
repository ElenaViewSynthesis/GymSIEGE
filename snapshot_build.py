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

import asyncio
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
MIN_SNAPSHOT_FREE_BYTES = int(
    float(os.environ.get("GYMSIEGE_MIN_SNAPSHOT_FREE_GIB", "1.5")) * 1024**3
)

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
python3 -m pip install --break-system-packages \
    tomli tomli_w anthropic openai boto3 httpx 'huggingface_hub[hf_xet]>=1.0.0' docker

echo "[bootstrap] clone cybergym-e2e"
if [ ! -d "{repo_dir}" ]; then
  git clone --depth 1 {repo_url} "{repo_dir}"
fi

echo "[bootstrap] pinned CyberGym dataset payload"
cd "{repo_dir}"
python3 - <<'PY'
from huggingface_hub import snapshot_download

tasks = {tasks!r}
patterns = []
for task in tasks:
    patterns.extend((f"projects/{{task}}/**", f"data/projects/{{task}}/**"))
snapshot_download(
    repo_id="{dataset}",
    repo_type="dataset",
    local_dir="data",
    allow_patterns=patterns,
    token=True,
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
    log.info("exec[%s] done in %.1fs (exit=%s)", label, dt, getattr(r, "exit_code", "?"))
    if log_output and output:
        log.info("exec[%s] output:\n%s", label, output[-8000:])
    if not ok:
        log.warning("exec[%s] non-zero exit; tail of output:\n%s", label, output[-2000:])
    return {"label": label, "duration_s": dt, "exit_code": getattr(r, "exit_code", None), "ok": ok}


async def build_snapshot() -> None:
    require_env("DAYTONA_API_KEY")
    hf_secret_name = require_env("GYMSIEGE_HF_SECRET_NAME")
    tasks = pinned_task_paths()
    log.info("baking %s for %d pinned tasks", SNAPSHOT_NAME, len(tasks))

    bake_steps: list[dict[str, Any]] = []
    bench = load_json(PROVISIONING_BENCH_JSON, {"bake": [], "cold_create": [], "snapshot_create": [], "fork_create": []})

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
            ),
            timeout=600,
        )
        t_create = time.monotonic() - t_create0
        log.info("base sandbox created in %.1fs (id=%s)", t_create, sandbox.id)
        bake_steps.append({"label": "base_create", "duration_s": t_create, "exit_code": 0, "ok": True})

        try:
            await sandbox.set_ttl(common.SANDBOX_SAFETY_TTL_MINUTES)
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

            t_snap0 = time.monotonic()
            await sandbox.create_snapshot(SNAPSHOT_NAME, timeout=3600)
            t_snap = time.monotonic() - t_snap0
            log.info("snapshot '%s' created in %.1fs", SNAPSHOT_NAME, t_snap)
            bake_steps.append({"label": "create_snapshot", "duration_s": t_snap, "exit_code": 0, "ok": True})

        finally:
            bench["bake"] = bake_steps
            atomic_write_json(PROVISIONING_BENCH_JSON, bench)
            await sandbox.set_ttl(60)
            await sandbox.delete(wait=True, timeout=180)
            log.info("base sandbox %s deleted (safety ttl was also set to 60m)", sandbox.id)

        # One immediate snapshot-restore sample so provision-bench has a
        # same-day baseline even before orchestrator.py runs the full sweep.
        t_restore0 = time.monotonic()
        restored = await daytona.create(
            CreateSandboxFromSnapshotParams(snapshot=SNAPSHOT_NAME, name="siege-snapshot-probe")
        )
        t_restore = time.monotonic() - t_restore0
        log.info("snapshot-restore probe created in %.1fs", t_restore)
        await restored.set_ttl(5)
        await restored.delete(wait=True, timeout=180)

    bench["bake"] = bake_steps
    bench["snapshot_create"].append({"ts": time.time(), "duration_s": t_restore})
    bench["cold_create"].append({"ts": time.time(), "duration_s": t_create})
    atomic_write_json(PROVISIONING_BENCH_JSON, bench)

    total = sum(s["duration_s"] for s in bake_steps)
    ok = all(s["ok"] for s in bake_steps)
    log.info("=== snapshot bake %s in %.1fs total ===", "SUCCEEDED" if ok else "COMPLETED WITH WARNINGS", total)
    log.info("cold create: %.1fs | snapshot restore: %.1fs (delta: %.1fs, %.0f%% faster)",
              t_create, t_restore, t_create - t_restore, 100 * (t_create - t_restore) / max(t_create, 1e-9))
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(build_snapshot())
