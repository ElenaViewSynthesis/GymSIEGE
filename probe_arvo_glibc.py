#!/usr/bin/env python3
"""Probe each ARVO/CVE target's own glibc version directly.

node_compatibility_probe (exploitgym_adapter.py:467-493) only tells you
pass/fail against the baked Node runtime's specific requirements -- it
never reports what a target's glibc actually IS. Four tasks have hit that
wall so far with an identical missing-symbol signature (GLIBC_2.27, 2.28,
2.25 -- see FINDINGS.md#8), and a prior guess that several *other* specific
tasks would "more likely" hit it too was wrong: three of the four it named
turned out compatible. This script replaces guessing with real per-image
data: restore gymsiege-exploitgym once, pull each requested task's
exp.hardened image, and run probe_arvo_glibc.sh against it to report the
target's actual highest available GLIBC_x.y symbol and OS release --
before spending any solver budget finding out the hard way.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shlex
import time
from pathlib import Path

from daytona import AsyncDaytona, CreateSandboxFromSnapshotParams

import common
from common import (
    EXPLOITGYM_REMOTE_DIR,
    EXPLOITGYM_SNAPSHOT_NAME,
    SANDBOX_NAME_PREFIX,
    SANDBOX_SAFETY_TTL_MINUTES,
    get_logger,
    require_env,
)
from exploitgym_adapter import ExploitGymTask, load_exploitgym_tasks

log = get_logger("probe_arvo_glibc")

PROBE_SCRIPT_LOCAL = Path(__file__).parent / "probe_arvo_glibc.sh"
PROBE_SCRIPT_REMOTE = f"{EXPLOITGYM_REMOTE_DIR}/probe_arvo_glibc.sh"

DOCKER_START_SH = r"""
set -u
if command -v sudo >/dev/null 2>&1; then
  SUDO=sudo
elif [ "$(id -u)" -eq 0 ]; then
  SUDO=
else
  echo "Docker startup requires root or sudo" >&2
  exit 77
fi
$SUDO service docker start >/dev/null 2>&1 || true
if ! docker info >/dev/null 2>&1; then
  $SUDO nohup dockerd >/tmp/gymsiege-dockerd.log 2>&1 &
  for _ in $(seq 1 60); do
    if [ -S /var/run/docker.sock ]; then
      $SUDO chgrp "$(id -gn)" /var/run/docker.sock
      $SUDO chmod 0660 /var/run/docker.sock
    fi
    docker info >/dev/null 2>&1 && break
    sleep 1
  done
fi
docker info >/dev/null
"""


async def _resolve_image(sandbox, task: ExploitGymTask) -> str:
    result = await sandbox.process.exec(
        f"""
set -euo pipefail
cd {shlex.quote(EXPLOITGYM_REMOTE_DIR)}
uv run python - {shlex.quote(task.task_id)} <<'PY'
import sys
from cybergym.task.metadata import TASK_METADATA
print(TASK_METADATA[sys.argv[1]].images["exp.hardened"])
PY
""",
        timeout=60,
    )
    if getattr(result, "exit_code", 1) != 0:
        raise RuntimeError(f"could not resolve image: {(result.result or '')[-1000:]}")
    lines = (result.result or "").strip().splitlines()
    if not lines:
        raise RuntimeError("image resolution produced no output")
    return lines[-1]


async def _pull_image(sandbox, task: ExploitGymTask) -> None:
    task_file = f"/tmp/gymsiege-glibc-probe-{task.safe_name}.txt"
    pull = await sandbox.process.exec(
        f"""
set -euo pipefail
printf '%s\\n' {shlex.quote(task.task_id)} > {shlex.quote(task_file)}
cd {shlex.quote(EXPLOITGYM_REMOTE_DIR)}
uv run scripts/setup/pull_images.py {shlex.quote(task_file)} --user-modes exp.hardened --workers 1
""",
        timeout=1800,
    )
    if getattr(pull, "exit_code", 1) != 0:
        raise RuntimeError(f"image pull failed: {(pull.result or '')[-1000:]}")


async def probe(tasks: list[ExploitGymTask]) -> list[dict]:
    require_env("DAYTONA_API_KEY")
    records: list[dict] = []
    async with AsyncDaytona() as daytona:
        name = f"{SANDBOX_NAME_PREFIX}-glibc-probe-{int(time.time())}"
        log.info("restoring %s from %s", name, EXPLOITGYM_SNAPSHOT_NAME)
        sandbox = await daytona.create(
            CreateSandboxFromSnapshotParams(
                snapshot=EXPLOITGYM_SNAPSHOT_NAME,
                name=name,
                ttl_minutes=SANDBOX_SAFETY_TTL_MINUTES,
                # Same class of bug as FINDINGS.md#9 -- this sandbox will
                # sit quietly between docker pulls for a diagnostic sweep,
                # not just one trial's exec(); don't let platform auto-stop
                # kill it mid-sweep.
                auto_stop_interval=0,
            ),
            timeout=300,
        )
        try:
            await sandbox.set_ttl(SANDBOX_SAFETY_TTL_MINUTES)
            docker = await sandbox.process.exec(DOCKER_START_SH, timeout=120)
            if getattr(docker, "exit_code", 1) != 0:
                raise RuntimeError("Docker daemon unavailable in probe sandbox")

            script_text = PROBE_SCRIPT_LOCAL.read_text(encoding="utf-8")
            await sandbox.fs.upload_file(script_text.encode("utf-8"), PROBE_SCRIPT_REMOTE)
            await sandbox.process.exec(f"chmod +x {shlex.quote(PROBE_SCRIPT_REMOTE)}", timeout=30)

            for task in tasks:
                log.info("[%s] resolving image", task.task_id)
                try:
                    image = await _resolve_image(sandbox, task)
                    log.info("[%s] pulling %s", task.task_id, image)
                    await _pull_image(sandbox, task)
                    probe_result = await sandbox.process.exec(
                        f"{shlex.quote(PROBE_SCRIPT_REMOTE)} -i {shlex.quote(image)} "
                        f"-t {shlex.quote(task.task_id)} -o json",
                        timeout=180,
                    )
                    lines = (probe_result.result or "").strip().splitlines()
                    record = json.loads(lines[-1]) if lines else {
                        "task_id": task.task_id, "ok": False, "error": "empty probe output"
                    }
                except Exception as exc:  # noqa: BLE001 -- one bad task must not kill the sweep
                    record = {"task_id": task.task_id, "ok": False, "error": str(exc)}
                log.info("[%s] %s", task.task_id, record)
                records.append(record)
        finally:
            try:
                await sandbox.delete(wait=True, timeout=180)
            except Exception:
                log.warning(
                    "probe sandbox %s cleanup failed; check `orchestrator.py reap`", name
                )
    return records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--task", action="append", dest="tasks", help="task id, repeatable")
    group.add_argument("--tasks-file", type=Path, help="file of task ids, one per line")
    parser.add_argument(
        "--out",
        type=Path,
        default=common.RESULTS_DIR / "glibc_probe.json",
        help="where to write the JSON report (default: results/glibc_probe.json)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.tasks:
        tasks = [ExploitGymTask(t) for t in args.tasks]
    else:
        tasks = load_exploitgym_tasks(args.tasks_file, allow_non_userspace=True)

    records = asyncio.run(probe(tasks))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(records, indent=2), encoding="utf-8")
    ok = sum(1 for r in records if r.get("ok"))
    log.info("wrote %d/%d successful probes to %s", ok, len(records), args.out)


if __name__ == "__main__":
    main()
