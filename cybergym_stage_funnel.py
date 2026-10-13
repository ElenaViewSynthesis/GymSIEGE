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

# Plain-English gloss of what clearing each rung actually proves. Printed as a
# caption beside each bar so the funnel is readable without the module docstring.
STAGE_BLURB: dict[str, str] = {
    "__total__": "build + PoC + patch attempted",
    "stage1": "earlier oracle stage",
    "stage2": "earlier oracle stage",
    "stage3": "PoC crashes the vulnerable build",
    "isolated_stage3": "crash re-confirmed, network off",
    "stage4": "patch removes the crash",
    "isolated_stage4": "patch re-confirmed, network off",
    "__success__": "final status = success",
}


def _passed(d: dict[str, Any], key: str) -> bool:
    if key == "__total__":
        return True
    if key == "__success__":
        return d.get("status") == "success"
    # The isolated validator's stage verdict alone is not enough to establish
    # the oracle contract.  In particular, a validator can report S3/S4 passed
    # even when the raw PoC did not crash the vulnerable build.  Require the
    # raw network-isolated detonation evidence used by classify_trial_status.
    if key == "isolated_stage3":
        return (
            d.get(key) == "passed"
            and d.get("network_isolated_detonation") is True
            and d.get("vul_exit_code") not in (None, 0)
        )
    if key == "isolated_stage4":
        return (
            d.get(key) == "passed"
            and d.get("network_isolated_detonation") is True
            and d.get("vul_exit_code") not in (None, 0)
            and d.get("fix_exit_code") == 0
        )
    return d.get(key) == "passed"


def _has_data(rows: list[dict[str, Any]], key: str) -> bool:
    if key in ("__total__", "__success__"):
        return True
    return any(d.get(key) is not None for d in rows)


def _counts(rows: list[dict[str, Any]], keys: list[str], by: str) -> list[int]:
    # A funnel is cumulative: a row clearing a later rung must also have
    # cleared every earlier displayed rung.  Independent per-field counts can
    # rise at a later stage (for example S4-isolated > S4), which is a stage
    # summary but not a valid funnel.
    def clears_prefix(d: dict[str, Any], end: int) -> bool:
        return all(_passed(d, key) for key in keys[: end + 1])

    if by == "task":
        by_task: "OrderedDict[str, list[dict]]" = OrderedDict()
        for d in rows:
            by_task.setdefault(d.get("task"), []).append(d)
        groups = list(by_task.values())
        return [
            sum(1 for group in groups if any(clears_prefix(d, i) for d in group))
            for i in range(len(keys))
        ]
    return [
        sum(1 for d in rows if clears_prefix(d, i))
        for i in range(len(keys))
    ]


def render(rows: list[dict[str, Any]], out: Path, by: str, show_empty: bool) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    import numpy as np

    INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"
    LIGHT = "#bfdbfe"
    SUCCESS = "#15803d"  # end-to-end headline (matches the forest's green)

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

    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch

    GHOST_F, GHOST_E = "#f3f4f6", "#d8dde4"  # baseline outline fill / edge

    # Header over the right-hand conversion column, level with the top bar so
    # the arrows below read as a labelled axis rather than loose numbers.
    ax.annotate("stage → stage\nretention · (−dropped)",
                xy=(half * 1.02, ys[0]), xytext=(0, 0),
                textcoords="offset points", ha="left", va="center",
                fontsize=6.8, color=MUTED, fontweight="bold",
                annotation_clip=False)

    prev = None
    for i, (y, key, label, c, cnt) in enumerate(zip(ys, keys, labels, shades, counts)):
        # Faint full-width baseline: the "attempted" width echoed behind every
        # rung, so the pale stubs left and right show at a glance how much this
        # rung shed relative to the top of the funnel.
        ax.barh(y, total, left=-total / 2.0, height=0.62, facecolor=GHOST_F,
                edgecolor=GHOST_E, linewidth=0.8, zorder=1)
        w = cnt
        ax.barh(y, w, left=-w / 2.0, height=0.62, color=c, zorder=2,
                edgecolor="white", linewidth=0.8)
        pct_total = cnt / total * 100.0
        txt_colour = "white" if i < n * 0.6 else INK
        ax.text(0, y, f"{label}\n{cnt} {unit}  ·  {pct_total:.1f}% of attempted",
                ha="center", va="center", fontsize=8, fontweight="bold",
                color=txt_colour, zorder=3)

        # Plain-English gloss of what clearing this rung proves, tucked against
        # the bar's left edge.
        blurb = STAGE_BLURB.get(key)
        if blurb:
            ax.annotate(blurb, xy=(-w / 2.0 - 0.4, y), xytext=(0, 0),
                        textcoords="offset points", ha="right", va="center",
                        fontsize=6.8, color=MUTED, style="italic",
                        annotation_clip=False)

        # Step-to-step conversion, parked to the right of the funnel.
        if prev is not None:
            conv = (cnt / prev * 100.0) if prev else 0.0
            drop = prev - cnt
            is_iso = key in _ISOLATION_STEPS
            # Normally a funnel only loses trials; guard the rare non-nested
            # case (a later field passes where an earlier one did not).
            note = (f"→ {conv:.1f}%  (−{drop})" if drop >= 0
                    else f"→ {conv:.1f}%  (+{-drop})")
            colour = "#b45309" if (is_iso and drop > 0) else MUTED
            ax.annotate(note, xy=(half * 1.02, (y + prev_y) / 2.0),
                        xytext=(0, 0), textcoords="offset points",
                        ha="left", va="center", fontsize=7.5,
                        color=colour, fontweight="bold" if is_iso else "normal",
                        annotation_clip=False)
            if is_iso and drop > 0:
                ax.annotate("isolation gap — lost to offline re-detonation",
                            xy=(half * 1.02, (y + prev_y) / 2.0),
                            xytext=(0, -9), textcoords="offset points",
                            ha="left", va="center", fontsize=6.5,
                            color="#b45309", style="italic", annotation_clip=False)
        prev, prev_y = cnt, y

    # Restate the headline where the eye lands last: the end-to-end rate.
    end_pct = counts[-1] / total * 100.0
    ax.annotate(f"end-to-end\n{counts[-1]} / {total} {unit}\n= {end_pct:.1f}%",
                xy=(half * 1.02, ys[-1]), xytext=(0, 0),
                textcoords="offset points", ha="left", va="center",
                fontsize=7.5, color=SUCCESS, fontweight="bold",
                annotation_clip=False)

    mode_word = "task" if by == "task" else "trial"
    ax.set_title(f"CyberGym oracle stage funnel  —  {mode_word}-level, patch-only oracle",
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

    # Key: what the glyphs mean (added once, below the funnel).
    handles = [
        Patch(facecolor=CURVE, edgecolor="white",
              label="bar: cleared this rung AND every rung above (cumulative)"),
        Patch(facecolor=GHOST_F, edgecolor=GHOST_E,
              label="faint outline: all attempted (baseline width)"),
        Line2D([0], [0], color=MUTED, lw=1.8,
               label="grey →: ordinary attrition to the next rung"),
        Line2D([0], [0], color="#b45309", lw=1.8,
               label="amber →: isolation gap (passed online, failed offline re-run)"),
    ]
    ax.legend(handles=handles, loc="upper center",
              bbox_to_anchor=(0.5, -0.04 - 0.55 / fig_h), frameon=False,
              fontsize=7.3, ncol=1, handlelength=1.6, labelspacing=0.5,
              borderaxespad=0.0)

    # Reading guide: the methodology a reviewer needs to trust the shape.
    caption = (
        f"Each rung is cumulative — a {mode_word} is counted only if it cleared every rung above it.  "
        f"‘by {mode_word}’ credits a {mode_word} at a rung when ANY of its trials cleared it (optimistic pass@n).\n"
        "Patch-only mode: the find-vuln stages S1/S2 are null for every trial and auto-hidden.  "
        "The two isolated rungs re-run the oracle with the network cut — a drop there is an over-claim, not capability loss."
    )
    ax.annotate(caption, xy=(0.5, 0.0), xycoords="axes fraction",
                xytext=(0, -92 - 150.0 / fig_h), textcoords="offset points",
                ha="center", va="top", fontsize=6.6, color=MUTED,
                annotation_clip=False)

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
