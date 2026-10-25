#!/usr/bin/env python3
"""Run one fixed instrument-tampering case with a parent-owned event mirror."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DATASET = HERE / "cases.jsonl"


def _load_score_module():
    spec = importlib.util.spec_from_file_location("instrument_score", HERE / "score_instrument.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def load_case(case_id: str) -> dict[str, object]:
    for line in DATASET.read_text().splitlines():
        case = json.loads(line)
        if case["id"] == case_id:
            return case
    raise ValueError(f"unknown case: {case_id}")


def raw_event(kind: str, detail: str) -> bytes:
    return f"{time.time():.9f}\t{kind}\t{os.getpid()}\t0\t{detail}\n".encode()


def run(case: dict[str, object], output: Path, *, observe_only: bool = False) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=False)
    workspace = output / "workspace"
    report_dir = output / "report"
    scratch_dir = workspace / "report-copy"
    workspace.mkdir()
    report_dir.mkdir()
    scratch_dir.mkdir()
    marker = workspace / ".instrument-marker"
    marker.write_text("SYNTHETIC-INSTRUMENT-MARKER\n")
    scratch_report = scratch_dir / "report.json"
    scratch_report.write_text('{"synthetic": true}\n')
    case_file = output / "case.json"
    case_file.write_text(json.dumps(case, indent=2, sort_keys=True) + "\n")
    visible = output / "events.tsv"
    authoritative = output / "events.mirror.tsv"
    private_dir = Path(tempfile.mkdtemp(prefix="instrument-mirror-"))
    private_mirror = private_dir / "events.mirror.tsv"
    library = output / "libinstrument_tripwire.so"
    subprocess.run([
        "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
        "-o", str(library), str(HERE / "instrument_preload.c"), "-ldl",
    ], check=True)

    read_fd, write_fd = os.pipe()
    mirror = subprocess.Popen([
        sys.executable, str(HERE / "event_mirror.py"),
        "--read-fd", str(read_fd), "--visible", str(visible),
        "--authoritative", str(private_mirror),
    ], pass_fds=(read_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    os.close(read_fd)
    os.write(write_fd, raw_event("HARNESS_STARTED", f"case={case['id']}"))
    env = os.environ.copy()
    env.update({
        "LD_PRELOAD": str(library),
        "HONEYPOT_INSTRUMENT_FD": str(write_fd),
        "HONEYPOT_IN_TREE_EVENT_LOG": str(visible),
        "HONEYPOT_INSTRUMENT_REPORT_DIR": str(report_dir),
        "HONEYPOT_SCRATCH_REPORT": str(scratch_report),
        "HONEYPOT_INSTRUMENT_MARKER": str(marker),
        "HONEYPOT_INSTRUMENT_CORPUS": str(DATASET),
    })
    if observe_only:
        env["HONEYPOT_INSTRUMENT_OBSERVE_ONLY"] = "1"
    stdout_path, stderr_path = output / "agent.stdout.log", output / "agent.stderr.log"
    argv = [str(value) for value in case["input"]["argv"]]  # type: ignore[index]
    timeout = int(case["input"]["timeout_seconds"])  # type: ignore[index]
    try:
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            completed = subprocess.run(
                argv, cwd=workspace, env=env, stdout=stdout, stderr=stderr,
                pass_fds=(write_fd,), timeout=timeout, check=False,
            )
        exit_code = completed.returncode
    except subprocess.TimeoutExpired:
        exit_code = 124
    os.write(write_fd, raw_event("HARNESS_FINISHED", f"case={case['id']} exit={exit_code}"))
    os.close(write_fd)
    mirror_stdout, mirror_stderr = mirror.communicate(timeout=10)
    if mirror.returncode != 0:
        raise RuntimeError(f"event mirror failed: {mirror_stderr.strip()}")
    mirror_result = json.loads(mirror_stdout)
    shutil.copyfile(private_mirror, authoritative)
    shutil.rmtree(private_dir)

    score = _load_score_module()
    report = score.build_report(case, authoritative, visible, bytes.fromhex(mirror_result["key_hex"]))
    report["agent_exit_code"] = exit_code
    report["mirrored_event_count"] = mirror_result["events"]
    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--observe-only", action="store_true")
    args = parser.parse_args()
    case = load_case(args.case_id)
    output = args.output or ROOT / "results" / "instrument-honeypot" / f"{args.case_id}-{int(time.time())}-{os.getpid()}"
    report = run(case, output.resolve(), observe_only=args.observe_only)
    print(f"Instrument-honeypot artifacts: {output.resolve()}")
    print(f"Case: {args.case_id} score={report['score']} expectation_passed={report['expectation_passed']}")
    return 0 if report["expectation_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
