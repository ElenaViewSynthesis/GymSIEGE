#!/usr/bin/env python3
"""CyberGym oracle stage funnel: how many trials (or tasks) clear each rung of
the find-vuln -> PoC -> patch oracle, and where capability drains away.

The capability curve collapses the whole oracle to a single success bit. This
plot opens that bit back up into the ladder it actually is:

  S1/S2        earlier oracle stages (null in patch-only mode -> auto-hidden)
  S3           the PoC reproduces the crash on the vulnerable build
  S4           the patch makes the crash go away
  S3 isolated  S3 re-confirmed under network-isolated detonation
  S4 isolated  S4 re-confirmed under isolation
  success      final confirmed success (status == "success")

Two things a reviewer reads straight off the funnel:
  * the widest single drop = the capability bottleneck (which stage the agent
    fails at most), and
  * the S3 -> S3-isolated / S4 -> S4-isolated steps = the *isolation gap*: trials
    that looked solved until the oracle was re-run without network help. That gap
    is a reward-hacking / over-claim signal, not just attrition, so it is called
    out explicitly.

Stages whose field is null for every trial (e.g. S1/S2 in patch-only runs) are
dropped unless --show-empty, so the funnel adapts to the run mode. Counting is
per trial by default; --by task counts a task as clearing a stage if ANY of its
trials did (an optimistic, pass@n-style view).

Usage:
  python3 cybergym_stage_funnel.py \
      [--results-dir results/modal_trials]... [--extra PATH.json]... \
      [--out results/modal_trials/cybergym_stage_funnel.png] \
      [--by trial|task] [--show-empty]
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional

from cybergym_capability_curve import load_trials_detailed

# (field, label).  __total__ and __success__ are synthetic endpoints; the rest
# read a stage field that is "passed" when the rung is cleared.
STAGE_ORDER: list[tuple[str, str]] = [
    ("__total__", "attempted"),
    ("stage1", "S1 reached"),
    ("stage2", "S2 reached"),
    ("stage3", "S3 PoC reproduces"),
    ("isolated_stage3", "S3 isolated-confirmed"),
    ("stage4", "S4 patch holds"),
    ("isolated_stage4", "S4 isolated-confirmed"),
    ("__success__", "confirmed success"),
]
# Steps whose drop is an isolation re-check rather than plain attrition.
_ISOLATION_STEPS = {"isolated_stage3", "isolated_stage4"}


def _passed(d: dict[str, Any], key: str) -> bool:
    if key == "__total__":
        return True
    if key == "__success__":
        return d.get("status") == "success"
    return d.get(key) == "passed"


def _has_data(rows: list[dict[str, Any]], key: str) -> bool:
    if key in ("__total__", "__success__"):
        return True
    return any(d.get(key) is not None for d in rows)


def _counts(rows: list[dict[str, Any]], keys: list[str], by: str) -> list[int]:
    if by == "task":
        by_task: "OrderedDict[str, list[dict]]" = OrderedDict()
        for d in rows:
            by_task.setdefault(d.get("task"), []).append(d)
        groups = list(by_task.values())
        return [sum(1 for g in groups if any(_passed(d, k) for d in g)) for k in keys]
    return [sum(1 for d in rows if _passed(d, k)) for k in keys]


def render(rows: list[dict[str, Any]], out: Path, by: str, show_empty: bool) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    import numpy as np

    INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"
    LIGHT = "#bfdbfe"

    stages = [(k, lbl) for (k, lbl) in STAGE_ORDER
              if show_empty or _has_data(rows, k)]
    keys = [k for k, _ in stages]
    labels = [lbl for _, lbl in stages]
    counts = _counts(rows, keys, by)
    total = counts[0] if counts else 0
    unit = "tasks" if by == "task" else "trials"
    if total == 0:
        raise SystemExit("funnel has no trials to plot")

    n = len(stages)
    # Blue gradient, deepest at the top of the funnel and fading downward.
    t = np.linspace(0.0, 1.0, n)
    c0, c1 = np.array(mcolors.to_rgb(CURVE)), np.array(mcolors.to_rgb(LIGHT))
    shades = [mcolors.to_hex((1 - ti) * c0 + ti * c1) for ti in t]

    fig_h = max(3.0, 0.78 * n + 1.3)
    fig, ax = plt.subplots(figsize=(9, fig_h), dpi=150)
    ax.set_facecolor("white")
    fig.patch.set_facecolor("white")

    half = total / 2.0
    ax.set_xlim(-half * 1.9, half * 1.9)
    ax.set_ylim(-0.6, n - 0.4)
    ys = np.arange(n)[::-1]  # first stage on top

    prev = None
    for i, (y, key, label, c, cnt) in enumerate(zip(ys, keys, labels, shades, counts)):
        w = cnt
        ax.barh(y, w, left=-w / 2.0, height=0.62, color=c, zorder=2,
                edgecolor="white", linewidth=0.8)
        pct_total = cnt / total * 100.0
        txt_colour = "white" if i < n * 0.6 else INK
        ax.text(0, y, f"{label}\n{cnt} {unit}  ·  {pct_total:.0f}% of attempted",
                ha="center", va="center", fontsize=8, fontweight="bold",
                color=txt_colour, zorder=3)

        # Step-to-step conversion, parked to the right of the funnel.
        if prev is not None:
            conv = (cnt / prev * 100.0) if prev else 0.0
            drop = prev - cnt
            is_iso = key in _ISOLATION_STEPS
            # Normally a funnel only loses trials; guard the rare non-nested
            # case (a later field passes where an earlier one did not).
            note = (f"→ {conv:.0f}%  (−{drop})" if drop >= 0
                    else f"→ {conv:.0f}%  (+{-drop})")
            colour = "#b45309" if (is_iso and drop > 0) else MUTED
            ax.annotate(note, xy=(half * 1.02, (y + prev_y) / 2.0),
                        xytext=(0, 0), textcoords="offset points",
                        ha="left", va="center", fontsize=7.5,
                        color=colour, fontweight="bold" if is_iso else "normal",
                        annotation_clip=False)
            if is_iso and drop > 0:
                ax.annotate("isolation gap", xy=(half * 1.02, (y + prev_y) / 2.0),
                            xytext=(0, -9), textcoords="offset points",
                            ha="left", va="center", fontsize=6.5,
                            color="#b45309", style="italic", annotation_clip=False)
        prev, prev_y = cnt, y

    ax.set_title(f"CyberGym oracle stage funnel  ({unit}, S1–S4)",
                 color=INK, fontsize=12, fontweight="bold", loc="left")
    ax.set_yticks([])
    ax.set_xticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)

    # Bottleneck callout: the single largest drop between consecutive stages.
    drops = [(counts[i - 1] - counts[i], labels[i - 1], labels[i])
             for i in range(1, n)]
    if drops:
        d, a, b = max(drops, key=lambda x: x[0])
        if d > 0:
            ax.annotate(f"bottleneck: {a} → {b}  (−{d} {unit})",
                        xy=(0, -0.5), ha="center", va="center",
                        fontsize=8, color=INK, fontweight="bold")

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    print(f"wrote {out}  ({total} {unit} attempted -> {counts[-1]} confirmed; "
          f"stages: {', '.join(f'{l}={c}' for l, c in zip(labels, counts))})")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="CyberGym oracle stage funnel.")
    p.add_argument("--results-dir", action="append", default=None,
                   help="dir of trial result JSONs (repeatable; default results/modal_trials)")
    p.add_argument("--extra", action="append", default=[],
                   help="extra trial result JSON to include (repeatable)")
    p.add_argument("--out", type=Path,
                   default=Path("results/modal_trials/cybergym_stage_funnel.png"))
    p.add_argument("--by", choices=("trial", "task"), default="trial",
                   help="count each trial, or each task that ANY trial cleared (default trial)")
    p.add_argument("--show-empty", action="store_true",
                   help="keep stages that are null for every trial (default: hide them)")
    args = p.parse_args(argv)

    results_dirs = args.results_dir or ["results/modal_trials"]
    rows = load_trials_detailed(results_dirs, args.extra)
    if not rows:
        raise SystemExit("no trial result JSONs found")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    render(rows, args.out, args.by, args.show_empty)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
