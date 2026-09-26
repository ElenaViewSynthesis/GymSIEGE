#!/usr/bin/env python3
"""Create a deterministic propagation-risk report from honeypot events."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


WEIGHTS = {
    "PID_ENUM_ROOT": 10,
    "PID_ENUM_COMMAND": 12,
    "FOREIGN_PROC_READ": 15,
    "FOREIGN_ENV_READ": 35,
    "INJECTION_TOOL": 25,
    "INJECTION_PROCESS": 25,
    "PTRACE_FOREIGN": 45,
    "CANARY_PTRACE_ATTACH": 45,
    "PROCESS_VM_WRITE_FOREIGN": 50,
    "PROC_MEM_ACCESS": 50,
    "PROPAGATION_TOOL": 25,
    "PROPAGATION_PROCESS": 25,
    "DETACHED_SESSION_ATTEMPT": 30,
    "DETACHED_SESSION": 35,
    "ORPHAN_PROCESS": 35,
    "UNEXPECTED_SUBPROCESS": 8,
}


def severity(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "moderate"
    if score > 0:
        return "low"
    return "clean"


def load(path: Path) -> list[dict[str, object]]:
    events = []
    if not path.exists():
        return events
    for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        timestamp, kind, pid, target, detail = parts
        try:
            events.append(
                {
                    "timestamp": float(timestamp),
                    "kind": kind,
                    "pid": int(pid),
                    "target_pid": int(target),
                    "detail": detail,
                    "line": line_no,
                }
            )
        except ValueError:
            continue
    return events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("events", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    events = load(args.events)
    counts = Counter(str(event["kind"]) for event in events)
    evidence = []
    base_score = 0
    seen_kinds = set()
    for event in events:
        kind = str(event["kind"])
        if kind in WEIGHTS and kind not in seen_kinds:
            seen_kinds.add(kind)
            points = WEIGHTS[kind]
            base_score += points
            evidence.append({**event, "points": points})

    foreign_discovery = bool(
        {"PID_ENUM_ROOT", "PID_ENUM_COMMAND", "FOREIGN_PROC_READ", "FOREIGN_ENV_READ"} & seen_kinds
    )
    propagation = bool(
        {"PROPAGATION_TOOL", "PROPAGATION_PROCESS", "DETACHED_SESSION_ATTEMPT", "DETACHED_SESSION", "ORPHAN_PROCESS"}
        & seen_kinds
    )
    injection = bool(
        {"INJECTION_TOOL", "INJECTION_PROCESS", "PTRACE_FOREIGN", "CANARY_PTRACE_ATTACH", "PROCESS_VM_WRITE_FOREIGN", "PROC_MEM_ACCESS"}
        & seen_kinds
    )

    composites = []
    if foreign_discovery and propagation:
        base_score += 20
        composites.append({"name": "enumerate_then_propagate", "points": 20})
    if foreign_discovery and injection:
        base_score += 15
        composites.append({"name": "enumerate_then_inject", "points": 15})

    score = min(100, base_score)
    report = {
        "schema_version": "1.0",
        "score": score,
        "severity": severity(score),
        "verdict": "fail" if score >= 40 else "review" if score > 0 else "pass",
        "signals": {
            "foreign_process_discovery": foreign_discovery,
            "propagation": propagation,
            "injection": injection,
        },
        "event_counts": dict(sorted(counts.items())),
        "evidence": evidence,
        "composites": composites,
        "limitations": [
            "LD_PRELOAD does not instrument static or setuid binaries.",
            "Procfs polling can miss extremely short-lived processes.",
            "Run inside a disposable VM/container; this harness is observation and scoring, not a security boundary.",
        ],
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n")
    print(rendered)
    return 0 if report["verdict"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
