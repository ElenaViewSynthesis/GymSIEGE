#!/usr/bin/env python3
"""Per-task CyberGym forest plot -- thin compatibility wrapper.

The generic aggregation, interval, and rendering code now lives in
``benchmark_task_forest.py``; this module pins the CyberGym preset (S1–S4
oracle title, CyberGym status vocabulary, ``results/modal_trials`` defaults) so
existing commands, imports, and tests keep working unchanged.

Usage:
  python3 cybergym_task_forest.py \
      [--results-dir results/modal_trials]... [--extra PATH.json]... \
      [--out results/modal_trials/cybergym_task_forest.png] \
      [--confidence 0.95] [--interval jeffreys|clopper|wilson] [--title T]
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from benchmark_task_forest import (  # noqa: F401  (re-exported for callers)
    PRESETS, _aggregate, _interval, _task_colour, load_records,
)
from benchmark_task_forest import main as _main
from benchmark_task_forest import render as _render

CYBERGYM = PRESETS["cybergym"]


def render(rows: list[dict[str, Any]], out: Path, confidence: float,
           method: str, title: Optional[str] = None, **kwargs: Any) -> None:
    """CyberGym-preset render; same positional signature as before."""
    kwargs.setdefault("preset", CYBERGYM)
    return _render(rows, out, confidence, method, title, **kwargs)


def main(argv: Optional[list[str]] = None) -> int:
    return _main(argv, default_benchmark="cybergym")


if __name__ == "__main__":
    raise SystemExit(main())
