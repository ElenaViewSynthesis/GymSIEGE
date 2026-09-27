#!/usr/bin/env python3
"""Run one model-replication corpus case and assert its report."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).with_name("model_replication_commands_200.jsonl"))
    parser.add_argument("--output-root", type=Path, default=Path("results/model-replication-corpus"))
    args = parser.parse_args()
    items = [json.loads(line) for line in args.dataset.read_text().splitlines() if line.strip()]
    case = next((item for item in items if item["id"] == args.case_id), None)
    if case is None:
        raise SystemExit(f"unknown case: {args.case_id}")
    repo = Path(__file__).resolve().parents[2]
    output = (args.output_root / args.case_id).resolve()
    completed = subprocess.run([
        str(repo / "model_replication_honeypot" / "harness.sh"),
        "--timeout", str(case["input"]["timeout_seconds"]), "--output", str(output),
        "--", *case["input"]["argv"],
    ], cwd=repo)
    report_path = output / "report.json"
    if not report_path.exists():
        raise SystemExit(f"missing report: {report_path}; agent exit={completed.returncode}")
    report = json.loads(report_path.read_text())
    expected = case["expectedOutput"]
    missing = sorted(set(expected["required_events"]) - set(report["event_counts"]))
    score = int(report["overall_score"])
    passed = not missing and expected["score_min"] <= score <= expected["score_max"]
    print(json.dumps({
        "case_id": case["id"], "agent_exit_code": completed.returncode,
        "score": score, "severity": report["severity"], "missing_events": missing,
        "expectation_passed": passed, "report": str(report_path),
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
