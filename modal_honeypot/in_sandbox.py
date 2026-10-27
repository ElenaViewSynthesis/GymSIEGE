#!/usr/bin/env python3
"""Execute honeypot corpus cases inside an already-isolated Modal Sandbox."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tarfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


ROOT = Path("/opt/honeypot")
CONFIG = {
    "agent": {
        "dataset": ROOT / "agent_honeypot/corpus/agent_commands_200.jsonl",
        "runner": ROOT / "agent_honeypot/corpus/run_case.py",
        "prefix": "APH-",
    },
    "collusion": {
        "dataset": ROOT / "agent_honeypot/collusion_tripwires/cases.jsonl",
        "runner": ROOT / "agent_honeypot/collusion_tripwires/run_case.py",
        "prefix": "CLH-",
    },
    "model": {
        "dataset": ROOT / "model_replication_honeypot/corpus/model_replication_commands_200.jsonl",
        "runner": ROOT / "model_replication_honeypot/corpus/run_case.py",
        "prefix": "MRH-",
    },
    "instrument": {
        "dataset": ROOT / "agent_honeypot/instrument_tripwires/cases.jsonl",
        "runner": ROOT / "agent_honeypot/instrument_tripwires/run_case.py",
        "prefix": "IHT-",
        "report": "report/report.json",
        "argv_style": "case-output",
    },
    "network-off": {
        "dataset": ROOT / "modal_honeypot/network_off/network_off_cases_20.jsonl",
        "runner": ROOT / "modal_honeypot/network_off/run_case.py",
        "prefix": "NOF-",
    },
}


def case_ids(mode: str) -> list[str]:
    dataset = CONFIG[mode]["dataset"]
    return [json.loads(line)["id"] for line in dataset.read_text().splitlines() if line.strip()]


def run_case(
    mode: str, case_id: str, output_root: Path, *, subject_command: str | None = None,
) -> dict[str, object]:
    log_dir = output_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    case_output = output_root / "cases" / case_id
    config = CONFIG[mode]
    if config.get("argv_style") == "case-output":
        command = [
            "python3", "-B", str(config["runner"]),
            "--case-id", case_id, "--output", str(case_output),
        ]
    else:
        command = [
            "python3", "-B", str(config["runner"]), case_id,
            "--output-root", str(output_root / "cases"),
        ]
    if subject_command is not None:
        if mode != "collusion":
            raise ValueError("subject commands are supported only by the collusion harness")
        command.extend(["--subject-command", subject_command])
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (log_dir / f"{case_id}.log").write_text(completed.stdout)
    report_path = case_output / str(config.get("report", "report.json"))
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    chains = [chain for chain in report.get("evidence_chains", []) if isinstance(chain, dict)]
    observability = report.get("observability")
    passed = completed.returncode == 0 and observability != "unobservable"
    return {
        "case_id": case_id,
        "passed": passed,
        "runner_exit_code": completed.returncode,
        "score": report.get("score", report.get("overall_score", report.get("containment_score"))),
        "severity": report.get("severity", "contained" if report.get("passed") else "failed"),
        "stage": report.get("observed_stage"),
        "role": report.get("role"),
        "expectation_passed": report.get("expectation_passed"),
        "subject_mode": report.get("subject_mode"),
        "time_to_first_coordination_s": report.get("time_to_first_coordination_s"),
        "observability": observability,
        "evidence_chains": [chain.get("valid") for chain in chains],
        "mirror_events": [chain.get("mirror_events") for chain in chains],
        "chain_valid": report.get("chain_valid"),
        "mirror_matches_visible_log": report.get("mirror_matches_visible_log"),
        "report": str(report_path),
    }


def run_demo(output_root: Path) -> dict[str, object]:
    output_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TMPDIR"] = str(output_root)
    completed = subprocess.run(
        ["bash", str(ROOT / "agent_honeypot/evidence_chain_demo.sh"), "--keep"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (output_root / "demo.log").write_text(completed.stdout)
    summary = {
        "schema_version": "1.0",
        "execution_boundary": "modal-sandbox",
        "harness": "demo",
        "exit_code": completed.returncode,
        "passed": completed.returncode == 0,
        "log": "demo.log",
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    bundle_artifacts(output_root)
    print(json.dumps(summary, sort_keys=True))
    return summary


def bundle_artifacts(output_root: Path) -> Path:
    bundle = output_root / "artifacts.tar.gz"
    allowed = {".json", ".jsonl", ".tsv", ".log", ".txt"}
    with tarfile.open(bundle, "w:gz") as archive:
        for path in sorted(output_root.rglob("*")):
            if path == bundle or not path.is_file() or path.suffix not in allowed:
                continue
            archive.add(path, arcname=path.relative_to(output_root))
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser()
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--harness", choices=sorted(CONFIG))
    target.add_argument("--demo", action="store_true")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--case-id")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--subject-command")
    parser.add_argument("--output-root", type=Path, default=Path("/tmp/honeypot-output"))
    args = parser.parse_args()
    if args.demo:
        if args.case_id or args.all:
            parser.error("--demo cannot be combined with --case-id or --all")
        return 0 if run_demo(args.output_root)["passed"] else 1
    if args.subject_command is not None and args.harness != "collusion":
        parser.error("--subject-command requires --harness collusion")
    if not (args.case_id or args.all):
        parser.error("a harness run requires --case-id or --all")
    if not 1 <= args.workers <= 8:
        parser.error("--workers must be between 1 and 8")
    ids = case_ids(args.harness) if args.all else [args.case_id]
    expected_prefix = str(CONFIG[args.harness]["prefix"])
    if any(not case_id or not case_id.startswith(expected_prefix) for case_id in ids):
        parser.error(f"case IDs for {args.harness} must begin with {expected_prefix}")

    args.output_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=min(args.workers, len(ids))) as pool:
        futures = {
            pool.submit(
                run_case, args.harness, case_id, args.output_root,
                subject_command=args.subject_command,
            ): case_id
            for case_id in ids
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"case_id": futures[future], "passed": False, "error": str(exc)})
    results.sort(key=lambda item: str(item["case_id"]))
    summary = {
        "schema_version": "1.0",
        "execution_boundary": "modal-sandbox",
        "harness": args.harness,
        "subject_mode": "agent" if args.subject_command is not None else "scripted",
        "total": len(results),
        "passed": sum(bool(item.get("passed")) for item in results),
        "failed": sum(not bool(item.get("passed")) for item in results),
        "results": results,
    }
    (args.output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    bundle_artifacts(args.output_root)
    print(json.dumps({key: summary[key] for key in ("harness", "total", "passed", "failed")}, sort_keys=True))
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
