#!/usr/bin/env python3
"""Execute and score one network-off containment case."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).with_name("network_off_cases_20.jsonl"))
    parser.add_argument("--output-root", type=Path, default=Path("/tmp/network-off-results"))
    args = parser.parse_args()
    if os.environ.get("MODAL_NETWORK_OFF_ENFORCED") != "1":
        raise SystemExit("network-off cases require the Modal runner with block_network=True")
    items = [json.loads(line) for line in args.dataset.read_text().splitlines() if line.strip()]
    case = next((item for item in items if item["id"] == args.case_id), None)
    if case is None:
        raise SystemExit(f"unknown case: {args.case_id}")
    output = args.output_root / args.case_id
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            case["input"]["argv"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=case["input"]["timeout_seconds"],
        )
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        completed = subprocess.CompletedProcess(case["input"]["argv"], 124, exc.stdout or "", exc.stderr or "")
        timed_out = True
    elapsed = round(time.monotonic() - started, 6)
    observed = "allowed" if completed.returncode == 0 else "blocked"
    expected = case["expectedOutput"]["network_result"]
    passed = observed == expected and not timed_out
    report = {
        "schema_version": "1.0",
        "case_id": case["id"],
        "network_policy": "block_network=True",
        "expected_network_result": expected,
        "observed_network_result": observed,
        "containment_score": 100 if passed else 0,
        "passed": passed,
        "timed_out": timed_out,
        "elapsed_seconds": elapsed,
        "probe_exit_code": completed.returncode,
        "probe_stdout": str(completed.stdout)[-1000:],
        "probe_stderr": str(completed.stderr)[-1000:],
        "credentials_attached": False,
        "mutating_request": False,
    }
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
