#!/usr/bin/env python3
"""Per-task CyberGym forest plot: each task's success probability with a
small-sample confidence interval, sorted best-to-worst.

This is the honest companion to ``cybergym_capability_curve_rate.py``. The rate
curve plots the *cumulative* success rate in run-date order, which mixes task
difficulty with the accident of which tasks ran first -- the shape is largely an
arrival-order artefact and its "peaks" move if you reshuffle the trials. A forest
plot instead shows, per task, the point estimate p-hat = successes / trials and a
confidence interval, with no dependence on run order. It is the figure a reviewer
expects when the claim is "how capable is the agent, task by task".

With one trial per task (the current data) every interval is wide and every point
sits at 0% or 100% -- which is the correct, honest picture: a single Bernoulli
draw tells you almost nothing about a task's true p. The plot sharpens for free
as repeated trials (``trial`` 2, 3, ...) are added; tasks are grouped by name, so
reruns of the same task become replicate draws and tighten its interval.

Interval estimators (the ``--interval`` flag) -- deliberately NOT just Wilson,
since Wilson behaves poorly at the k=0 / k=n extremes where single-trial data
lives:
  * jeffreys  (default) -- Bayesian Beta(1/2,1/2); well-behaved at the extremes,
    always brackets the point. Needs SciPy; falls back to Wilson without it.
  * clopper   -- Clopper-Pearson exact; guaranteed >= nominal coverage, always
    contains p-hat. Needs SciPy.
  * wilson    -- the house score interval (see cybergym_capability_curve_rate);
    the dot can sit slightly off the band centre at the extremes.

Usage:
  python3 cybergym_task_forest.py \
      [--results-dir results/modal_trials]... [--extra PATH.json]... \
      [--out results/modal_trials/cybergym_task_forest.png] \
      [--confidence 0.95] [--interval jeffreys|clopper|wilson]
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

from cybergym_capability_curve import (
    ATT, NONE, SUCC, _ATT_STATUS, load_trials,
)
from cybergym_capability_curve_rate import _z_for, wilson


def _interval(k: int, n: int, method: str, conf: float) -> tuple[float, float, float]:
    """(-> p_hat, lo, hi) for k successes of n trials, in [0, 1]."""
    if n == 0:
        return 0.0, 0.0, 1.0
    phat = k / n
    if method == "wilson":
        _, lo, hi = wilson(k, n, _z_for(conf))
        return phat, lo, hi
    alpha = 1.0 - conf
    try:
        from scipy.stats import beta
    except Exception:  # no SciPy -> the one interval we can do closed-form
        _, lo, hi = wilson(k, n, _z_for(conf))
        return phat, lo, hi
    if method == "jeffreys":
        lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k + 0.5, n - k + 0.5))
        hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 0.5, n - k + 0.5))
    else:  # clopper-pearson (exact)
        lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
        hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return phat, lo, hi


def _task_colour(statuses: list[str]) -> str:
    """Green if the task ever succeeded; else amber if genuinely attempted;
    else grey (only errors / no capability signal)."""
    if any(s == "success" for s in statuses):
        return SUCC
    if any(s in _ATT_STATUS for s in statuses):
        return ATT
    return NONE


def _aggregate(rows: list[dict[str, Any]]) -> "OrderedDict[str, list[str]]":
    """task -> list of per-trial statuses, insertion-ordered by first sighting."""
    by_task: "OrderedDict[str, list[str]]" = OrderedDict()
    for r in rows:
        by_task.setdefault(r["task"], []).append(r["status"])
    return by_task


def render(rows: list[dict[str, Any]], out: Path, confidence: float,
           method: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.lines import Line2D

    INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"

    by_task = _aggregate(rows)
    tasks = []
    for task, statuses in by_task.items():
        n = len(statuses)
        k = sum(1 for s in statuses if s == "success")
        phat, lo, hi = _interval(k, n, method, confidence)
        tasks.append({
            "task": task, "k": k, "n": n,
            "p": phat, "lo": lo, "hi": hi,
            "colour": _task_colour(statuses),
        })
    # Best first (high p-hat on top); break ties by more trials, then name.
    tasks.sort(key=lambda t: (t["p"], t["n"], t["task"]))  # low->high; invert y below

    tot_k = sum(t["k"] for t in tasks)
    tot_n = sum(t["n"] for t in tasks)
    pooled = (tot_k / tot_n * 100.0) if tot_n else 0.0

    ys = np.arange(len(tasks))
    fig_h = max(2.4, 0.34 * len(tasks) + 1.5)
    fig, ax = plt.subplots(figsize=(9, fig_h), dpi=150)
    ax.set_facecolor("white")
    fig.patch.set_facecolor("white")
    ax.set_xlim(-2, 102)
    ax.set_ylim(-0.7, len(tasks) - 0.3)

    # Pooled suite rate: a reference line everything is read against.
    ax.axvline(pooled, color=CURVE, lw=1.3, ls=(0, (4, 3)), alpha=0.8, zorder=1)
    ax.annotate(f"pooled {pooled:.1f}%", xy=(pooled, len(tasks) - 0.4),
                xytext=(3, 0), textcoords="offset points", va="top",
                fontsize=7.5, color=CURVE, fontweight="bold")

    for y, t in zip(ys, tasks):
        p, lo, hi = t["p"] * 100, t["lo"] * 100, t["hi"] * 100
        xerr = [[max(0.0, p - lo)], [max(0.0, hi - p)]]
        ax.errorbar(p, y, xerr=xerr, fmt="none", ecolor=MUTED, elinewidth=1.3,
                    capsize=2.5, capthick=1.3, zorder=2, alpha=0.9)
        # Marker size grows with the number of trials (confidence in the dot).
        ax.scatter(p, y, s=40 + 16 * (t["n"] - 1), color=t["colour"], zorder=3,
                   edgecolor="white", linewidth=0.7)
        ax.annotate(f"{t['k']}/{t['n']}", xy=(102, y), xytext=(4, 0),
                    textcoords="offset points", va="center", ha="left",
                    fontsize=7, color=MUTED, annotation_clip=False)

    ax.set_yticks(ys)
    ax.set_yticklabels([t["task"] for t in tasks], fontsize=7.5, color=INK)
    ax.set_xlabel("per-task success probability (%)", color=INK, fontsize=10)
    ci_pct = int(round(confidence * 100))
    ax.set_title(f"CyberGym per-task capability  ({method} {ci_pct}% CI, S1–S4 oracle)",
                 color=INK, fontsize=12, fontweight="bold", loc="left")
    ax.grid(True, axis="x", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.tick_params(colors=MUTED, labelsize=9)

    legend = [
        Line2D([0], [0], marker="o", ls="", color=SUCC, label="task ever solved", markersize=7),
        Line2D([0], [0], marker="o", ls="", color=ATT, label="attempted, never solved", markersize=7),
        Line2D([0], [0], marker="o", ls="", color=NONE, label="no capability signal", markersize=7),
        Line2D([0], [0], color=MUTED, lw=1.3, label=f"{ci_pct}% CI (right: k/n trials)"),
    ]
    ax.legend(handles=legend, frameon=False, fontsize=8.5, ncol=2,
              loc="upper center", bbox_to_anchor=(0.5, -0.12 - 0.9 / fig_h))

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    print(f"wrote {out}  ({len(tasks)} tasks, {tot_k}/{tot_n} trials solved, "
          f"pooled {pooled:.1f}%, {method} {ci_pct}% CI)")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Per-task CyberGym success-probability forest plot.")
    p.add_argument("--results-dir", action="append", default=None,
                   help="dir of trial result JSONs (repeatable; default results/modal_trials)")
    p.add_argument("--extra", action="append", default=[],
                   help="extra trial result JSON to include (repeatable)")
    p.add_argument("--out", type=Path,
                   default=Path("results/modal_trials/cybergym_task_forest.png"))
    p.add_argument("--confidence", type=float, default=0.95,
                   help="confidence level for the per-task interval (default 0.95)")
    p.add_argument("--interval", choices=("jeffreys", "clopper", "wilson"),
                   default="jeffreys",
                   help="small-sample interval estimator (default jeffreys; "
                        "jeffreys/clopper need SciPy, else fall back to wilson)")
    args = p.parse_args(argv)

    results_dirs = args.results_dir or ["results/modal_trials"]
    rows = load_trials(results_dirs, args.extra)
    if not rows:
        raise SystemExit("no trial result JSONs found")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    render(rows, args.out, args.confidence, args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
