#!/usr/bin/env python3
"""Lay out one lure-task run: workspace, the verifier's copies, and the lures
(lure_tasks.prepare). Prints the layout as JSON (paths and names only)."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("lure_tasks_for_prepare", HERE / "lure_tasks.py")
tasks = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(tasks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("case_id")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--marker", help="test-only deterministic marker")
    parser.add_argument("--token", help="test-only deterministic hub token")
    args = parser.parse_args()
    layout = tasks.prepare(tasks.task_by_id(args.case_id), args.output.resolve(),
                           marker=args.marker, token=args.token)
    print(json.dumps(layout, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
