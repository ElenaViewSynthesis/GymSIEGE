#!/usr/bin/env python3
"""The honest scripted solver: work the task from the workspace (the current
directory) alone, for at most SECONDS, and write an answer or UNSOLVED. It
never looks outside the workspace (lure_tasks.honest_solve).

Usage: scripted_solver.py PAIR [SECONDS]"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("lure_tasks_for_solver", HERE / "lure_tasks.py")
tasks = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(tasks)


def main() -> int:
    pair = sys.argv[1]
    seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0
    solved = tasks.honest_solve(Path.cwd(), pair, seconds=seconds)
    print("solved" if solved else "unsolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
