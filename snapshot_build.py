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
import sys
import time
from typing import Any

from daytona import AsyncDaytona, CreateSandboxFromSnapshotParams

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

# Installed *inside* the sandbox. Kept as one script so a single process.exec
# call gets us one clean exit code and one combined log instead of N round
# trips (each process.exec is a real network hop to the sandbox).
BOOTSTRAP_SH = r"""
set -euxo pipefail

echo "[bootstrap] apt toolchain"
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
    git curl ca-certificates build-essential \
    clang clang-tools llvm lld \
    python3 python3-pip python3-venv \
    docker.io docker-cli

echo "[bootstrap] docker daemon"
sudo service docker start || true
if ! /usr/bin/docker info >/dev/null 2>&1; then
  sudo nohup /usr/sbin/dockerd >/tmp/gymsiege-dockerd.log 2>&1 &
  for i in $(seq 1 30); do
    if [ -S /var/run/docker.sock ]; then
      sudo chgrp "$(id -gn)" /var/run/docker.sock
      sudo chmod 0660 /var/run/docker.sock
    fi
    /usr/bin/docker info >/dev/null 2>&1 && break
    sleep 2
  done
fi
/usr/bin/docker info >/dev/null

echo "[bootstrap] pip deps (mirrors cybergym-e2e's own requirements)"
python3 -m pip install --break-system-packages --upgrade pip
python3 -m pip install --break-system-packages \
    tomli tomli_w anthropic openai boto3 httpx huggingface_hub docker

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
)
PY

# Dataset revisions have used both projects/<task> and
# data/projects/<task>. Normalize to run_agent.py's default data/projects.
if [ -d data/data/projects ] && [ ! -d data/projects ]; then
  mv data/data/projects data/projects
fi
test -d data/projects

echo "[bootstrap] ASLR entropy for sanitizer compatibility"
sudo sysctl -w vm.mmap_rnd_bits=28 || echo "[bootstrap] WARN: sysctl requires CAP_SYS_ADMIN in this sandbox; retry at task time"

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
        print(f"[pull_images] WARN: missing config for {{task}}, skipping")
        continue
    cfg = tomli.loads(project_toml.read_text())
    cfg.update(tomli.loads(task_toml.read_text()))
    wanted.add(cfg.get("build_image", default_image))

print(f"[pull_images] pulling {{len(wanted)}} images for {{len(tasks)}} pinned tasks")
for img in sorted(wanted):
    print(f"[pull_images] docker pull {{img}}")
    try:
        client.images.pull(img)
    except Exception as e:
        print(f"[pull_images] WARN: failed to pull {{img}}: {{e}}")
PY
"""


def pinned_task_paths() -> list[str]:
    return [task.path for task in load_tasks(common.ROOT / "tasks.pinned.txt")]


async def timed_exec(sandbox, script: str, label: str, timeout: int = 1800) -> dict[str, Any]:
    t0 = time.monotonic()
    log.info("exec[%s] starting (timeout=%ss)", label, timeout)
    r = await sandbox.process.exec(script, timeout=timeout)
    dt = time.monotonic() - t0
    ok = getattr(r, "exit_code", 0) == 0
    log.info("exec[%s] done in %.1fs (exit=%s)", label, dt, getattr(r, "exit_code", "?"))
    if not ok:
        log.warning("exec[%s] non-zero exit; tail of output:\n%s", label, str(getattr(r, "result", r))[-2000:])
    return {"label": label, "duration_s": dt, "exit_code": getattr(r, "exit_code", None), "ok": ok}


async def build_snapshot() -> None:
    require_env("DAYTONA_API_KEY")
    tasks = pinned_task_paths()
    log.info("baking %s for %d pinned tasks", SNAPSHOT_NAME, len(tasks))

    bake_steps: list[dict[str, Any]] = []
    bench = load_json(PROVISIONING_BENCH_JSON, {"bake": [], "cold_create": [], "snapshot_create": [], "fork_create": []})

    async with AsyncDaytona() as daytona:
        t_create0 = time.monotonic()
        # No custom env / no snapshot param here on purpose: this is the
        # base warm-pool-eligible create, so its latency is directly
        # comparable to the "cold" arm of the three-way provisioning bench.
        sandbox = await daytona.create()
        t_create = time.monotonic() - t_create0
        log.info("base sandbox created in %.1fs (id=%s)", t_create, sandbox.id)
        bake_steps.append({"label": "base_create", "duration_s": t_create, "exit_code": 0, "ok": True})

        try:
            await sandbox.set_ttl(common.SANDBOX_SAFETY_TTL_MINUTES)
            bootstrap = BOOTSTRAP_SH.format(
                repo_dir=CYBERGYM_REMOTE_DIR,
                repo_url=CYBERGYM_REPO_URL,
                tasks=tasks,
                dataset=common.HF_DATASET,
            )
            bake_steps.append(await timed_exec(sandbox, bootstrap, "bootstrap_toolchain", timeout=1800))

            pull = PULL_IMAGES_PY.format(repo_dir=CYBERGYM_REMOTE_DIR, tasks=tasks)
            bake_steps.append(await timed_exec(sandbox, pull, "pull_pinned_images", timeout=3600))

            t_snap0 = time.monotonic()
            await sandbox.create_snapshot(SNAPSHOT_NAME, timeout=3600)
            t_snap = time.monotonic() - t_snap0
            log.info("snapshot '%s' created in %.1fs", SNAPSHOT_NAME, t_snap)
            bake_steps.append({"label": "create_snapshot", "duration_s": t_snap, "exit_code": 0, "ok": True})

        finally:
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
