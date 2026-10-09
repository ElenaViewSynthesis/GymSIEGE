#!/usr/bin/env python3
"""Cross-run CyberGym capability curve, RATE variant: cumulative success rate
with a Wilson confidence band (the shadow.png look).

This is the sibling of ``cybergym_capability_curve.py`` and reads the exact same
trial JSONs. The difference is what the y-axis measures and, crucially, what the
shaded region *means*:

  * cybergym_capability_curve.py -> cumulative *count* of successes. The blue
    fill under that line is decorative only; a running count is deterministic,
    so there is no variance to shade.
  * this file -> cumulative success *rate* (%). At trial i the rate is
    (successes so far) / (trials so far), and the band is the 95% Wilson
    interval for that binomial proportion. The band is wide early (small n)
    and tightens as trials accumulate -- a real uncertainty band, like the
    shaded regions in shadow.png, not a cosmetic gradient.

Keep both and compare the PNGs before deciding which the README should carry.
A confidence band only means something on the rate version; if you keep the
count version, drop the "shadow" framing for it.

Usage:
  python3 cybergym_capability_curve_rate.py \
      [--results-dir results/modal_trials]... [--extra PATH.json]... \
      [--out results/modal_trials/cybergym_capability_curve_rate.png] \
      [--confidence 0.95] [--band-scale 0.5] [--highlight TASK]

The band is a Wilson 95% interval scaled by --band-scale (0.5 by default) into
a thin ribbon around the line; pass --band-scale 1.0 for the full interval. The
highlight arrow defaults to the final/newest trial.
"""
from __future__ import annotations

import argparse
import glob
import json
import math
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


# Same outcome palette as the count variant so the two charts read identically.
SUCC, ATT, NONE = "#15803d", "#b45309", "#9ca3af"
_ATT_STATUS = {"failed", "no_patch", "oracle_mismatch"}


def _colour(status: str) -> str:
    if status == "success":
        return SUCC
    return ATT if status in _ATT_STATUS else NONE


def _z_for(confidence: float) -> float:
    """Two-sided normal critical value; SciPy if present, else the 95% default."""
    try:
        from scipy.stats import norm
        return float(norm.ppf(0.5 + confidence / 2.0))
    except Exception:
        return 1.959963984540054  # 95%


def wilson(k: int, n: int, z: float) -> tuple[float, float, float]:
    """Wilson score interval for k successes of n trials -> (centre, lo, hi)."""
    if n == 0:
        return 0.0, 0.0, 1.0
    phat = k / n
    denom = 1.0 + z * z / n
    centre = (phat + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return phat, max(0.0, centre - half), min(1.0, centre + half)


def render(rows: list[dict[str, Any]], out: Path, confidence: float,
           band_scale: float, highlight: Optional[str], top_n: int = 3) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.lines import Line2D

    INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"
    LIGHT = "#93c5fd"  # lighter blue for the full-95% dotted outline
    z = _z_for(confidence)

    # Cumulative rate at each trial, plus a Wilson half-width. ``band_scale``
    # shrinks that half-width into a thin ribbon hugging the line (1.0 = the
    # full 95% interval; <1 = a tighter visual band around the same centre).
    xs = np.arange(len(rows), dtype=float)
    rate, half_full, k = [], [], 0
    for i, r in enumerate(rows, start=1):
        if r["status"] == "success":
            k += 1
        p, l, h = wilson(k, i, z)
        rate.append(p * 100); half_full.append((h - l) / 2 * 100)
    rate = np.array(rate)
    half_full = np.array(half_full)            # the true 95% half-width
    half = half_full * band_scale              # the scaled ribbon half-width
    lo = np.clip(rate - half, 0, 100)
    hi = np.clip(rate + half, 0, 100)
    lo_full = np.clip(rate - half_full, 0, 100)  # full 95% interval edges
    hi_full = np.clip(rate + half_full, 0, 100)

    fig, ax = plt.subplots(figsize=(9, 4.5), dpi=150)
    ax.set_facecolor("white")
    fig.patch.set_facecolor("white")
    ax.set_xlim(-0.5, len(rows) - 0.5 if rows else 0.5)
    ax.set_ylim(0, 100)

    # Smooth the centre line and both band edges (PCHIP is shape-preserving and
    # won't overshoot into <0 / >100; falls back to raw polylines without SciPy).
    def smooth(y):
        if len(xs) < 2:
            return xs, y
        try:
            from scipy.interpolate import PchipInterpolator
            xd = np.linspace(xs.min(), xs.max(), 400)
            return xd, PchipInterpolator(xs, y)(xd)
        except Exception:
            return xs, y

    xd, yd = smooth(rate)
    _, lod = smooth(lo)
    _, hid = smooth(hi)
    _, lofd = smooth(lo_full)
    _, hifd = smooth(hi_full)

    # The confidence band: shaded ribbon between the (scaled) Wilson lo/hi.
    conf_pct = int(round(confidence * 100))
    band_label = (f"{conf_pct}% Wilson interval" if band_scale >= 0.999
                  else f"{conf_pct}% Wilson band (×{band_scale:g})")
    ax.fill_between(xd, np.clip(lod, 0, 100), np.clip(hid, 0, 100),
                    color=CURVE, alpha=0.18, zorder=1, linewidth=0,
                    label=band_label)

    # Full 95% Wilson interval drawn as a lighter-blue dotted outline above the
    # filled ribbon, so the true uncertainty is visible alongside the tight band.
    full_label = f"{conf_pct}% Wilson interval"
    ax.plot(xd, np.clip(hifd, 0, 100), color=LIGHT, lw=1.2, ls=(0, (2, 2)),
            zorder=2, label=full_label)
    ax.plot(xd, np.clip(lofd, 0, 100), color=LIGHT, lw=1.2, ls=(0, (2, 2)),
            zorder=2)

    # Soft glow + crisp smooth centre line.
    for lw, alpha in ((7, 0.06), (4, 0.10)):
        ax.plot(xd, yd, color=CURVE, lw=lw, alpha=alpha, zorder=2, solid_capstyle="round")
    ax.plot(xd, yd, color=CURVE, lw=2, zorder=3)

    # Per-trial dots on the centre line, coloured by outcome category.
    # clip_on=False so a dot sitting exactly on y=0 (e.g. an opening miss at
    # 0/1) isn't sliced in half by the bottom axis.
    for i, r in enumerate(rows):
        ax.scatter(i, rate[i], s=44, color=_colour(r["status"]), zorder=5,
                   edgecolor="white", linewidth=0.6, clip_on=False)

    # Final rate label at the right end.
    if len(rows):
        ax.annotate(f"{rate[-1]:.1f}%", xy=(len(rows) - 1, rate[-1]),
                    xytext=(8, 0), textcoords="offset points", va="center",
                    fontsize=7.5, fontweight="bold", color=INK)

    # Highlight one trial (default: the newest) with an arrow + task label.
    hi_i = None
    if highlight:
        for i, r in enumerate(rows):
            if r["task"] == highlight or r["task"].replace("/", "_") == highlight:
                hi_i = i
    if hi_i is None and rows:
        hi_i = len(rows) - 1
    if hi_i is not None:
        # Orthogonal (L-shaped) leader: a horizontal run from the label, then a
        # vertical approach up into the dot -- keeps the arrow off the ribbon
        # instead of slashing diagonally through the blue band.
        # Park the label just below the lower Wilson dotted line, so it clears
        # the band and the dotted envelope instead of sitting on them.
        end_label_y = max(4.0, float(lo_full[hi_i]) - 8.0)
        ax.annotate(rows[hi_i]["task"], xy=(hi_i, rate[hi_i]),
                    xytext=(hi_i - 0.4, end_label_y), textcoords="data",
                    ha="right", va="center",
                    fontsize=8, fontweight="bold", color=INK,
                    arrowprops=dict(arrowstyle="->", color=MUTED, lw=1,
                                    connectionstyle="angle,angleA=0,angleB=90,rad=0",
                                    shrinkB=5))

    # Label the top-N highest cumulative-rate trials (the capability peaks),
    # skipping the already-labelled end dot. Labels are parked in a row across
    # the top whitespace, evenly spread so they never collide, and each uses an
    # orthogonal leader (horizontal run along the top, then a vertical drop) so
    # the arrow lands on its peak without crossing the ribbon.
    if top_n > 0 and rows:
        ranked = sorted(range(len(rows)), key=lambda i: (-rate[i], i))
        peaks = [i for i in ranked if i != hi_i][: max(0, top_n)]  # top-N by rate
        peaks.sort()  # then left-to-right for label layout
        if peaks:
            span = (len(rows) - 1) or 1
            lo_x, hi_x = 0.10 * span, 0.90 * span
            slots = (np.linspace(lo_x, hi_x, len(peaks)) if len(peaks) > 1
                     else [span / 2.0])
            label_y = 84.0  # parked below the title, above the peaks
            last = len(peaks) - 1
            for n, (slot_x, i) in enumerate(zip(slots, peaks)):
                # The rightmost peak uses a straight diagonal leader instead of
                # an L-shape: its vertical drop would otherwise run right next to
                # the neighbouring peak's arrow. The rest keep the orthogonal
                # (horizontal-then-vertical) leader.
                # Emphasis: a slightly larger dot over the peak, keeping the
                # success-green fill so the outcome colour encoding stays intact.
                ax.scatter(i, rate[i], s=90, color=_colour(rows[i]["status"]),
                           edgecolor="white", linewidth=0.8, zorder=6, clip_on=False)
                conn = ("arc3,rad=0" if n == last
                        else "angle,angleA=0,angleB=90,rad=0")
                ax.annotate(f"{rows[i]['task']}\n{rate[i]:.1f}%",
                            xy=(i, rate[i]), xytext=(float(slot_x), label_y),
                            textcoords="data", ha="center", va="bottom",
                            fontsize=7.5, fontweight="bold", color=INK,
                            arrowprops=dict(arrowstyle="->", color=MUTED, lw=1,
                                            connectionstyle=conn, shrinkB=5))

    ax.set_xlabel("trial number (ordered by run date)", color=INK, fontsize=10)
    ax.set_ylabel("cumulative success rate (%)", color=INK, fontsize=10)
    ax.set_title("CyberGym capability across runs (S1–S4 oracle)",
                 color=INK, fontsize=12, fontweight="bold", loc="left")
    ax.grid(True, axis="y", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(colors=MUTED, labelsize=9)

    legend = [
        Line2D([0], [0], marker="o", ls="", color=SUCC, label="confirmed success", markersize=7),
        Line2D([0], [0], marker="o", ls="", color=ATT, label="attempted", markersize=7),
        Line2D([0], [0], marker="o", ls="", color=NONE, label="no capability signal", markersize=7),
        Line2D([0], [0], color=CURVE, lw=2, label="cumulative success rate"),
        plt.Rectangle((0, 0), 1, 1, color=CURVE, alpha=0.18, label=band_label),
        Line2D([0], [0], color=LIGHT, lw=1.2, ls=(0, (2, 2)), label=full_label),
    ]
    ax.legend(handles=legend, frameon=False, fontsize=8.5, ncol=3,
              loc="upper center", bbox_to_anchor=(0.5, -0.16))

    fig.tight_layout()
    fig.savefig(out, bbox_inches="tight")
    final = rate[-1] if len(rows) else 0.0
    print(f"wrote {out}  ({len(rows)} trials, {k} successes, final rate {final:.1f}%, "
          f"band [{lo[-1]:.1f}, {hi[-1]:.1f}]%)" if len(rows) else f"wrote {out}")


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Cross-run CyberGym cumulative success-RATE curve with Wilson band.")
    p.add_argument("--results-dir", action="append", default=None,
                   help="dir of trial result JSONs (repeatable; default results/modal_trials)")
    p.add_argument("--extra", action="append", default=[],
                   help="extra trial result JSON to include (repeatable)")
    p.add_argument("--out", type=Path,
                   default=Path("results/modal_trials/cybergym_capability_curve_rate.png"))
    p.add_argument("--confidence", type=float, default=0.95,
                   help="confidence level for the Wilson band (default 0.95)")
    p.add_argument("--band-scale", type=float, default=0.5,
                   help="shrink the band to this fraction of the full Wilson "
                        "width -- a thinner ribbon hugging the line (default 0.5; "
                        "1.0 = the full interval)")
    p.add_argument("--highlight", default=None,
                   help="task to label (default: the final/newest trial)")
    p.add_argument("--top-n", type=int, default=3,
                   help="also label the N highest cumulative-rate peaks (default 3; 0 to disable)")
    args = p.parse_args(argv)

    results_dirs = args.results_dir or ["results/modal_trials"]
    rows = load_trials(results_dirs, args.extra)
    if not rows:
        raise SystemExit("no trial result JSONs found")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    render(rows, args.out, args.confidence, args.band_scale, args.highlight, args.top_n)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
