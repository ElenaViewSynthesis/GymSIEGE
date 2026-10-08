#!/usr/bin/env python3
"""Cross-run CyberGym capability chart: one point per trial over time, plus a
cumulative-successes progress curve.

CyberGym is scored on the find-vuln -> PoC -> patch oracle stages, NOT the V8
16-rung exploitation ladder (that is a different benchmark;
``exploitbench/plot_capability_progress.py`` owns the within-episode V8 plot).
So CyberGym gets its own view here.

Each trial result JSON (``common.TrialResult`` shape) maps to an ordinal
capability TIER derived from its ``status`` -- the benchmark's own outcome
category. The middle statuses (``failed``/``no_patch``/``oracle_mismatch``) are
deliberately grouped so the chart imposes no contested ordering among them; it
only separates confirmed success, an attempt that produced artifacts, and no
usable signal. Points are coloured by exact status; a step line tracks the
cumulative count of confirmed successes across trials in date order.

Usage:
  python3 cybergym_capability_curve.py \
      [--results-dir results/modal_trials]... [--extra PATH.json]... \
      [--out results/modal_trials/cybergym_capability_curve.png] \
      [--highlight curl/arvo_66012]
"""
from __future__ import annotations

import argparse
import glob
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

# status -> (tier, label, colour). Tier is a presentation ordering, not a
# benchmark-defined score: confirmed success on top, any artifact-producing
# attempt in the middle (no ordering asserted between failed/no_patch/
# oracle_mismatch), no usable signal at the floor.
_SUCCESS = ("#15803d", 2, "confirmed success")          # S3+S4 passed, isolated-confirmed
_ATTEMPT = ("#b45309", 1, "attempted / unconfirmed")    # failed | no_patch | oracle_mismatch
_NONE = ("#9ca3af", 0, "no capability signal")          # error | no_poc | timeout | oracle_unavailable
_STATUS = {
    "success": _SUCCESS,
    "oracle_mismatch": _ATTEMPT,
    "no_patch": _ATTEMPT,
    "no_poc": _NONE,
    "failed": _ATTEMPT,
    "error": _NONE,
    "timeout": _NONE,
    "oracle_unavailable": _NONE,
}
TIER_LABELS = {2: "confirmed\nsuccess", 1: "attempted", 0: "no signal"}


def _tier(status: str) -> tuple[str, int, str]:
    return _STATUS.get(status, _NONE)


def load_trials(results_dirs: list[str], extra: list[str]) -> list[dict[str, Any]]:
    """Collect trial result JSONs, de-duplicated by (task, started_at)."""
    paths: list[str] = []
    for d in results_dirs:
        paths += glob.glob(str(Path(d) / "*.json"))
    paths += list(extra)
    seen: dict[tuple, dict] = {}
    for p in paths:
        try:
            d = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        task = d.get("task")
        started = d.get("started_at")
        if not task or not started:
            continue
        key = (task, started)
        seen[key] = {
            "task": task,
            "status": d.get("status") or "error",
            "started_at": started,
            "cost": d.get("solver_cost_usd"),
        }
    rows = list(seen.values())
    rows.sort(key=lambda r: r["started_at"])
    return rows


def render(rows: list[dict[str, Any]], out: Path, highlight: Optional[str]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"

    xs = list(range(len(rows)))
    dates = [datetime.fromisoformat(r["started_at"]) for r in rows]
    cum, n_succ = [], 0
    for r in rows:
        if r["status"] == "success":
            n_succ += 1
        cum.append(n_succ)

    fig, ax = plt.subplots(figsize=(9, 4.5), dpi=150)
    ax2 = ax.twinx()
    ax.set_facecolor("white")
    fig.patch.set_facecolor("white")

    # Progress curve: cumulative confirmed successes across trials (date order).
    ax2.step(xs, cum, where="post", lw=2, color=CURVE, zorder=2)
    ax2.set_ylabel("cumulative confirmed successes", color=CURVE, fontsize=10)
    ax2.set_ylim(0, max(cum + [1]) + 1)
    ax2.tick_params(colors=CURVE, labelsize=9)

    # Per-trial tier points, coloured by exact status.
    for i, r in enumerate(rows):
        colour, tier, _ = _tier(r["status"])
        ax.scatter(i, tier, s=46, color=colour, zorder=3,
                   edgecolor="white", linewidth=0.5)

    # Highlight the requested (or newest) trial.
    hi = None
    if highlight:
        for i, r in enumerate(rows):
            if r["task"] == highlight or r["task"].replace("/", "_") == highlight:
                hi = i
    if hi is None and rows:
        hi = len(rows) - 1
    if hi is not None:
        r = rows[hi]
        _, tier, _ = _tier(r["status"])
        ax.annotate(f"{r['task']}\n{r['started_at'][:10]} — {r['status']}",
                    xy=(hi, tier), xytext=(-10, -36), textcoords="offset points",
                    ha="right", fontsize=8, fontweight="bold", color=INK,
                    arrowprops=dict(arrowstyle="->", color=MUTED, lw=1))

    ax.set_yticks([0, 1, 2])
    ax.set_yticklabels([TIER_LABELS[0], TIER_LABELS[1], TIER_LABELS[2]], fontsize=9)
    ax.set_ylim(-0.5, 2.5)
    ax.set_xlim(-0.5, len(rows) - 0.5 if rows else 0.5)
    ax.set_xlabel("trials, in run-date order", color=INK, fontsize=10)
    ax.set_title("CyberGym capability across runs (S1–S4 oracle)", color=INK,
                 fontsize=12, fontweight="bold", loc="left")
    ax.grid(True, axis="y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for spine in ("top",):
        ax.spines[spine].set_visible(False)
        ax2.spines[spine].set_visible(False)
    ax.tick_params(colors=MUTED, labelsize=9)

    legend = [
        Line2D([0], [0], marker="o", ls="", color=_SUCCESS[0], label=_SUCCESS[2], markersize=7),
        Line2D([0], [0], marker="o", ls="", color=_ATTEMPT[0], label=_ATTEMPT[2], markersize=7),
        Line2D([0], [0], marker="o", ls="", color=_NONE[0], label=_NONE[2], markersize=7),
        Line2D([0], [0], color=CURVE, lw=2, label="cumulative successes"),
    ]
    ax.legend(handles=legend, frameon=False, fontsize=8, loc="center left")

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    print(f"wrote {out}  ({len(rows)} trials, {n_succ} confirmed successes)")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Cross-run CyberGym capability chart.")
    p.add_argument("--results-dir", action="append", default=None,
                   help="dir of trial result JSONs (repeatable; default results/modal_trials)")
    p.add_argument("--extra", action="append", default=[],
                   help="extra trial result JSON to include (repeatable)")
    p.add_argument("--out", type=Path,
                   default=Path("results/modal_trials/cybergym_capability_curve.png"))
    p.add_argument("--highlight", default="curl/arvo_66012",
                   help="task to label (default: curl/arvo_66012; falls back to newest)")
    args = p.parse_args(argv)

    results_dirs = args.results_dir or ["results/modal_trials"]
    rows = load_trials(results_dirs, args.extra)
    if not rows:
        raise SystemExit("no trial result JSONs found")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    render(rows, args.out, args.highlight)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
