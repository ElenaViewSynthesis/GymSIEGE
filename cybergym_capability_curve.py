#!/usr/bin/env python3
"""Cross-run CyberGym capability curve: cumulative confirmed successes over the
trials, in run-date order.

CyberGym is scored on the find-vuln -> PoC -> patch oracle stages, not the V8
16-rung exploitation ladder (that is a different benchmark;
``exploitbench/plot_capability_progress.py`` owns the within-episode V8 plot).

The chart is a single monotonic staircase: the running total of trials whose
``status == "success"`` (S3+S4 passed, isolated-confirmed), stepping up at each
success and flat at each non-success. A green dot marks each success on the
curve; ``--highlight`` annotates one trial with an arrow.

Usage:
  python3 cybergym_capability_curve.py \
      [--results-dir results/modal_trials]... [--extra PATH.json]... \
      [--out results/modal_trials/cybergym_capability_curve.png] \
      [--band {none,wilson}] [--confidence 0.95] [--band-scale 0.5] \
      [--highlight curl/arvo_66012]
"""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path
from typing import Any, Optional


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
        seen[(task, started)] = {
            "task": task,
            "status": d.get("status") or "error",
            "started_at": started,
            "cost": d.get("solver_cost_usd"),
        }
    rows = list(seen.values())
    rows.sort(key=lambda r: r["started_at"])
    return rows


def load_trials_detailed(results_dirs: list[str], extra: list[str]) -> list[dict[str, Any]]:
    """Like ``load_trials`` but keep the whole trial JSON for each deduped run.

    ``load_trials`` projects each result down to (task, status, started_at,
    cost). The stage funnel -- and any sibling that needs the oracle stage
    fields (``stage1``..``stage4``, ``isolated_stage3/4``, ``agent_success``
    vs ``gt_success``) -- needs the full record, so this returns the raw dicts,
    deduped by (task, started_at) and start-time sorted exactly as above.
    """
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
        seen[(task, started)] = d
    rows = list(seen.values())
    rows.sort(key=lambda r: r.get("started_at") or "")
    return rows


# status -> (category colour). success steps the curve up; the rest are on the
# flat segments, coloured so the misses are still visible on the curve.
SUCC, ATT, NONE = "#15803d", "#b45309", "#9ca3af"
_ATT_STATUS = {"failed", "no_patch", "oracle_mismatch"}


def _colour(status: str) -> str:
    if status == "success":
        return SUCC
    return ATT if status in _ATT_STATUS else NONE


def cumulative_success_counts(rows: list[dict[str, Any]]) -> list[int]:
    """Return the running number of confirmed successes for each trial."""
    counts: list[int] = []
    successes = 0
    for row in rows:
        if row["status"] == "success":
            successes += 1
        counts.append(successes)
    return counts


def render(rows: list[dict[str, Any]], out: Path, highlight: Optional[str]) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    import numpy as np
    from matplotlib.lines import Line2D
    from matplotlib.patches import Polygon

    INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"

    xs = np.arange(len(rows), dtype=float)
    counts = cumulative_success_counts(rows)
    n_succ = counts[-1] if counts else 0
    cum = np.array(counts, dtype=float)
    ymax = float(cum.max()) + 1 if len(cum) else 1.0

    fig, ax = plt.subplots(figsize=(9, 4.5), dpi=150)
    ax.set_facecolor("white")
    fig.patch.set_facecolor("white")
    ax.set_xlim(-0.5, len(rows) - 0.5 if rows else 0.5)
    ax.set_ylim(0, ymax)

    # Smooth, monotone curve through the cumulative points (PCHIP keeps it
    # non-decreasing; falls back to the raw polyline without SciPy).
    if len(xs) >= 2:
        try:
            from scipy.interpolate import PchipInterpolator
            xd = np.linspace(xs.min(), xs.max(), 400)
            yd = PchipInterpolator(xs, cum)(xd)
        except Exception:
            xd, yd = xs, cum
    else:
        xd, yd = xs, cum

    # Blue shadow fading behind: a vertical gradient (opaque near the curve,
    # fading to nothing at the baseline) clipped to the area under the curve.
    grad = np.empty((256, 1, 4))
    grad[:, :, :3] = mcolors.to_rgb(CURVE)
    grad[:, :, 3] = np.linspace(0.0, 0.32, 256).reshape(-1, 1)
    im = ax.imshow(grad, aspect="auto", origin="lower", zorder=1,
                   extent=[float(xs.min()), float(xs.max()), 0.0, ymax])
    under = Polygon(np.column_stack([np.r_[xd, xd[::-1]], np.r_[yd, np.zeros_like(yd)]]),
                    closed=True, transform=ax.transData)
    im.set_clip_path(under)

    # Soft glow + crisp smooth line.
    for lw, alpha in ((7, 0.06), (4, 0.10)):
        ax.plot(xd, yd, color=CURVE, lw=lw, alpha=alpha, zorder=2, solid_capstyle="round")
    ax.plot(xd, yd, color=CURVE, lw=2, zorder=3)

    # Per-trial dots on the curve, coloured by outcome category.
    for i, r in enumerate(rows):
        ax.scatter(i, cum[i], s=44, color=_colour(r["status"]), zorder=4,
                   edgecolor="white", linewidth=0.6)

    # Highlight one trial (default: the newest) with an arrow + task label.
    hi = None
    if highlight:
        for i, r in enumerate(rows):
            if r["task"] == highlight or r["task"].replace("/", "_") == highlight:
                hi = i
    if hi is None and rows:
        hi = len(rows) - 1
    if hi is not None:
        ax.annotate(rows[hi]["task"], xy=(hi, cum[hi]), xytext=(-12, -30),
                    textcoords="offset points", ha="right", fontsize=8,
                    fontweight="bold", color=INK,
                    arrowprops=dict(arrowstyle="->", color=MUTED, lw=1))

    ax.set_xlabel("trial number (ordered by run date)", color=INK, fontsize=10)
    ax.set_ylabel("cumulative confirmed successes", color=INK, fontsize=10)
    ax.set_title("CyberGym capability across runs (S1–S4 oracle)", color=INK,
                 fontsize=12, fontweight="bold", loc="left")
    ax.grid(True, axis="y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(colors=MUTED, labelsize=9)

    legend = [
        Line2D([0], [0], marker="o", ls="", color=SUCC, label="confirmed success", markersize=7),
        Line2D([0], [0], marker="o", ls="", color=ATT, label="attempted", markersize=7),
        Line2D([0], [0], marker="o", ls="", color=NONE, label="no capability signal", markersize=7),
        Line2D([0], [0], color=CURVE, lw=2, label="cumulative confirmed successes"),
    ]
    ax.legend(handles=legend, frameon=False, fontsize=9, ncol=4,
              loc="upper center", bbox_to_anchor=(0.5, -0.16))

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    print(f"wrote {out}  ({len(rows)} trials, {n_succ} confirmed successes)")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Cross-run CyberGym cumulative-success curve.")
    p.add_argument("--results-dir", action="append", default=None,
                   help="dir of trial result JSONs (repeatable; default results/modal_trials)")
    p.add_argument("--extra", action="append", default=[],
                   help="extra trial result JSON to include (repeatable)")
    p.add_argument("--out", type=Path, default=None,
                   help="output PNG (default depends on --band)")
    p.add_argument("--band", choices=("none", "wilson"), default="none",
                   help="none: cumulative count; wilson: cumulative rate with band")
    p.add_argument("--confidence", type=float, default=0.95,
                   help="confidence level for --band wilson (default 0.95)")
    p.add_argument("--band-scale", type=float, default=0.5,
                   help="fraction of the Wilson interval used for the filled ribbon")
    p.add_argument("--top-n", type=int, default=3,
                   help="rate peaks to label in Wilson mode (default 3; 0 disables)")
    p.add_argument("--highlight", default=None,
                   help="task to label (count default: curl/arvo_66012; "
                        "Wilson default: newest)")
    args = p.parse_args(argv)

    results_dirs = args.results_dir or ["results/modal_trials"]
    rows = load_trials(results_dirs, args.extra)
    if not rows:
        raise SystemExit("no trial result JSONs found")
    default_name = (
        "cybergym_capability_curve_rate.png"
        if args.band == "wilson"
        else "cybergym_capability_curve.png"
    )
    out = args.out or Path("results/modal_trials") / default_name
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.band == "wilson":
        from cybergym_capability_curve_rate import render as render_rate

        render_rate(
            rows,
            out,
            args.confidence,
            args.band_scale,
            args.highlight,
            args.top_n,
        )
    else:
        highlight = "curl/arvo_66012" if args.highlight is None else args.highlight
        render(rows, out, highlight)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
