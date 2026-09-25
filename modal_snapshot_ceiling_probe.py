#!/usr/bin/env python3
"""Measure Modal VM Sandbox filesystem-snapshot limits with disposable probes."""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any


SNAPSHOT_TIMEOUT_S = 1800
SANDBOX_TIMEOUT_S = 3600
DEFAULT_SNAPSHOT_TTL_S = 60
GB = 1_000_000_000

log = logging.getLogger("modal-snapshot-ceiling-probe")


def parse_size_gb(value: str) -> int:
    try:
        size = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid GB value: {value!r}") from exc
    if size <= 0:
        raise argparse.ArgumentTypeError("size must be positive")
    return round(size * GB)


def fill_script(target_bytes: int, target_inodes: int | None) -> str:
    inode_block = ""
    if target_inodes is not None:
        inode_block = f"""
python3 - <<'PY'
import os
from pathlib import Path

target = {target_inodes}
root = Path('/snapshot-probe-inodes')
root.mkdir(exist_ok=True)
existing = int(os.statvfs('/').f_files - os.statvfs('/').f_ffree)
needed = max(0, target - existing)
for start in range(0, needed, 10_000):
    directory = root / f'd{{start // 10_000:06d}}'
    directory.mkdir()
    for number in range(start, min(start + 10_000, needed)):
        fd = os.open(directory / f'f{{number:09d}}', os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
print(f'created_inodes={{needed}}', flush=True)
PY
"""
    return f"""set -euo pipefail
{inode_block}
used=$(df -B1 --output=used / | tail -1 | tr -d ' ')
target={target_bytes}
if [ "$used" -gt "$target" ]; then
  echo "baseline $used exceeds target $target" >&2
  exit 2
fi
fallocate -l "$((target - used))" /snapshot-probe.bin
sync
python3 - <<'PY'
import json
import os
import subprocess

stat = os.statvfs('/')
df = subprocess.check_output(
    ['df', '-B1', '--output=size,used,avail,pcent', '/'], text=True
).splitlines()[-1].split()
print(json.dumps({{
    'filesystem_bytes': int(df[0]),
    'used_bytes': int(df[1]),
    'available_bytes': int(df[2]),
    'percent_used': df[3],
    'used_inodes': stat.f_files - stat.f_ffree,
    'free_inodes': stat.f_ffree,
    'probe_file_bytes': os.stat('/snapshot-probe.bin').st_size,
}}, sort_keys=True))
PY
"""


def _process_result(process: Any) -> dict[str, Any]:
    process.wait()
    return {
        "returncode": process.returncode,
        "stdout": process.stdout.read(),
        "stderr": process.stderr.read(),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-gb", required=True, type=parse_size_gb, metavar="GB")
    parser.add_argument(
        "--target-inodes",
        type=int,
        help="create empty files until the filesystem reaches this used-inode count",
    )
    parser.add_argument("--app", default="gymsiege-snapshot-ceiling-probe")
    parser.add_argument("--snapshot-timeout", type=int, default=SNAPSHOT_TIMEOUT_S)
    parser.add_argument("--snapshot-ttl", type=int, default=DEFAULT_SNAPSHOT_TTL_S)
    parser.add_argument("--sandbox-timeout", type=int, default=SANDBOX_TIMEOUT_S)
    parser.add_argument(
        "--output", type=Path, default=Path("results/modal_snapshot_ceiling_probe.jsonl")
    )
    return parser


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    try:
        import modal
    except ImportError as exc:
        raise RuntimeError("Modal SDK is missing; install requirements.txt") from exc

    if args.target_inodes is not None and args.target_inodes <= 0:
        raise ValueError("target_inodes must be positive")

    app = modal.App.lookup(args.app, create_if_missing=True)
    image = modal.Image.from_registry("ubuntu:24.04").apt_install(["python3"])
    sandbox = None
    result: dict[str, Any] = {
        "observed_at": time.time(),
        "app": args.app,
        "modal_version": getattr(modal, "__version__", "unknown"),
        "sandbox_id": None,
        "target_bytes": args.target_gb,
        "target_inodes": args.target_inodes,
        "snapshot_timeout_s": args.snapshot_timeout,
        "snapshot_ttl_s": args.snapshot_ttl,
        "fill": None,
        "snapshot": None,
        "probe_error": None,
        "termination_error": None,
    }
    try:
        with modal.enable_output():
            sandbox = modal.Sandbox.create(
                "sleep",
                "infinity",
                app=app,
                image=image,
                cpu=1,
                memory=1024,
                timeout=args.sandbox_timeout,
                experimental_options={"vm_runtime": True},
            )
        result["sandbox_id"] = sandbox.object_id
        log.info("created probe Sandbox %s", sandbox.object_id)

        fill_started = time.monotonic()
        fill = _process_result(
            sandbox.exec(
                "bash",
                "-lc",
                fill_script(args.target_gb, args.target_inodes),
                timeout=args.sandbox_timeout - 60,
            )
        )
        fill["duration_s"] = round(time.monotonic() - fill_started, 3)
        result["fill"] = fill
        if fill["returncode"] != 0:
            result["probe_error"] = f"fill failed: {fill['stderr'][-1000:]}"
            return result
        lines = [line for line in fill["stdout"].splitlines() if line.strip()]
        fill["measurement"] = json.loads(lines[-1])

        snapshot_started = time.monotonic()
        try:
            snapshot = sandbox.snapshot_filesystem(
                args.snapshot_timeout, ttl=args.snapshot_ttl
            )
        except Exception as exc:
            result["snapshot"] = {
                "passed": False,
                "duration_s": round(time.monotonic() - snapshot_started, 3),
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        else:
            result["snapshot"] = {
                "passed": True,
                "duration_s": round(time.monotonic() - snapshot_started, 3),
                "image_id": snapshot.object_id,
                "expires_after_s": args.snapshot_ttl,
            }
    finally:
        if sandbox is not None:
            try:
                sandbox.terminate()
            except Exception as exc:
                result["termination_error"] = f"{type(exc).__name__}: {exc}"
    return result


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args()
    result = run_probe(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    snapshot = result.get("snapshot")
    return 0 if isinstance(snapshot, dict) and snapshot.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
