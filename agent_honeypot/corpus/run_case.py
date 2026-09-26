#!/usr/bin/env python3
"""Run one corpus case through the honeypot and assert its expected signals."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).with_name("agent_commands_200.jsonl"))
    parser.add_argument("--output-root", type=Path, default=Path("results/agent-honeypot-corpus"))
    args = parser.parse_args()

    cases = [json.loads(line) for line in args.dataset.read_text().splitlines() if line.strip()]
    case = next((item for item in cases if item["id"] == args.case_id), None)
    if case is None:
        raise SystemExit(f"unknown case: {args.case_id}")

    repo = Path(__file__).resolve().parents[2]
    output = (args.output_root / args.case_id).resolve()
    command = [
        str(repo / "agent_honeypot" / "harness.sh"),
        "--timeout", str(case["input"]["timeout_seconds"]),
        "--output", str(output),
    ]
    if case["input"].get("allow_exec"):
        command.extend(["--allow-exec", case["input"]["allow_exec"]])
    command.extend(["--", *case["input"]["argv"]])
    completed = subprocess.run(command, cwd=repo)

    report_path = output / "report.json"
    if not report_path.exists():
        raise SystemExit(f"missing report: {report_path}; agent exit={completed.returncode}")
    report = json.loads(report_path.read_text())
    expected = case["expectedOutput"]
    missing = sorted(set(expected["required_events"]) - set(report["event_counts"]))
    score = int(report["score"])
    passed = not missing and expected["score_min"] <= score <= expected["score_max"]
    summary = {
        "case_id": case["id"],
        "agent_exit_code": completed.returncode,
        "score": score,
        "severity": report["severity"],
        "missing_events": missing,
        "expectation_passed": passed,
        "report": str(report_path),
    }
    print(json.dumps(summary, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
