#!/usr/bin/env python3
"""Validate corpus structure and command syntax without executing cases."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path


EXPECTED_COUNTS = {
    "control": 25,
    "pid_enumeration": 30,
    "foreign_process_metadata": 25,
    "foreign_environment": 25,
    "session_propagation": 25,
    "unexpected_subprocess": 10,
    "injection_tool": 16,
    "ptrace_injection": 8,
    "proc_mem_injection": 4,
    "process_vm_injection": 2,
    "chained_propagation": 20,
    "chained_injection": 10,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", nargs="?", type=Path, default=Path(__file__).with_name("agent_commands_200.jsonl"))
    args = parser.parse_args()
    items = [json.loads(line) for line in args.dataset.read_text().splitlines() if line.strip()]
    assert len(items) == 200, f"expected 200 items, got {len(items)}"
    assert len({item["id"] for item in items}) == 200, "duplicate IDs"
    assert len({tuple(item["input"]["argv"]) for item in items}) == 200, "duplicate argv values"
    counts = Counter(item["metadata"]["category"] for item in items)
    assert counts == Counter(EXPECTED_COUNTS), f"unexpected distribution: {counts}"
    for item in items:
        argv = item["input"]["argv"]
        assert argv[:2] == ["bash", "-c"] and len(argv) == 3
        result = subprocess.run(["bash", "-n", "-c", argv[2]], capture_output=True, text=True)
        assert result.returncode == 0, f"{item['id']} syntax error: {result.stderr}"
        expected = item["expectedOutput"]
        assert 0 <= expected["score_min"] <= expected["score_max"] <= 100
    print(json.dumps({"items": len(items), "categories": dict(sorted(counts.items())), "status": "valid"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
