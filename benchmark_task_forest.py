#!/usr/bin/env python3
"""Benchmark-neutral per-task forest plot: each task's success probability with
a small-sample confidence interval, sorted best-to-worst, optionally paired with
a validity panel (valid / total attempts, infrastructure-invalid in grey).

This is the generic renderer extracted from ``cybergym_task_forest.py``; that
module is now a thin wrapper that pins the CyberGym preset so existing commands,
imports, and tests keep working.

Input records are the normalized per-trial JSONs the adapters write
(``eval_to_trials.py`` for CVE-Bench, the CyberGym result slots, the planned
``exploitgym_to_trials.py``). Each record needs ``task`` and ``started_at``, and
either ``status`` (success | failed | no_patch | oracle_mismatch | error | ...)
or ``outcome`` (success | failure | infra_invalid). Records are de-duplicated by
``(task, started_at)``; a file may hold one record, a list of records, or an
aggregate with a top-level ``trials`` list.

Validity: a trial is capability-valid when its status is ``success`` or one of
the preset's *attempted* statuses; everything else (error, oracle_unavailable,
timeout, infra_invalid, ...) is infrastructure-invalid and is excluded from the
per-task denominator. Without ``--show-validity`` the count of excluded attempts
is appended to the k/n annotation; with it, a second panel shows valid/total.

Interval estimators (``--interval``): jeffreys (default; Beta(1/2,1/2), needs
SciPy, falls back to wilson), clopper (exact, needs SciPy), wilson.

Usage:
  python3 benchmark_task_forest.py --results-dir DIR [--results-dir DIR]... \
      --benchmark {cybergym,cve-bench,exploitgym,exploitbench,generic} \
      [--title T] [--subtitle S] [--show-validity] [--task-labels JSON] \
      [--confidence 0.95] [--interval jeffreys|clopper|wilson] --out PNG
"""
from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from cybergym_capability_curve import ATT, NONE, SUCC, _ATT_STATUS
from cybergym_capability_curve_rate import _z_for, wilson

INK, MUTED, GRID, CURVE = "#111827", "#6b7280", "#e5e7eb", "#2563eb"

# ``outcome`` vocabulary (planned ExploitGym adapter) -> ``status`` vocabulary.
_OUTCOME_TO_STATUS = {
    "success": "success",
    "failure": "failed",
    "failed": "failed",
    "infra_invalid": "error",
}


@dataclass(frozen=True)
class Preset:
    """Per-benchmark labels and the statuses that count as a valid attempt."""
    name: str
    title_prefix: str
    oracle: str
    noun: str
    attempted: frozenset
    success_label: str
    failure_label: str
    invalid_label: str
    default_results_dir: Optional[str] = None
    default_out: Optional[str] = None


_FAIL_ONLY = frozenset({"failed", "failure"})

PRESETS: dict[str, Preset] = {
    "cybergym": Preset(
        "cybergym", "CyberGym per-task capability", "S1–S4 oracle", "task",
        frozenset(_ATT_STATUS),
        "task ever solved", "attempted, never solved", "no capability signal",
        "results/modal_trials", "results/modal_trials/cybergym_task_forest.png",
    ),
    "cve-bench": Preset(
        "cve-bench", "CVE-Bench per-CVE exploit success", "check_exploit oracle", "CVE",
        _FAIL_ONLY,
        "CVE ever exploited", "attempted, never exploited", "no valid evaluation",
    ),
    "exploitgym": Preset(
        "exploitgym", "ExploitGym per-task exploit success", "checks oracle", "task",
        _FAIL_ONLY,
        "task ever exploited", "attempted, never exploited", "infrastructure-invalid only",
    ),
    "exploitbench": Preset(
        "exploitbench", "ExploitBench per-task exploit success", "grader oracle", "task",
        _FAIL_ONLY,
        "task ever exploited", "attempted, never exploited", "infrastructure-invalid only",
    ),
    "generic": Preset(
        "generic", "Per-task success", "benchmark oracle", "task",
        frozenset(_ATT_STATUS) | _FAIL_ONLY | frozenset({"no_poc", "other_vuln"}),
        "task ever succeeded", "attempted, never succeeded", "no valid trial",
    ),
}


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------
def _records_in(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
    elif isinstance(payload, dict):
        trials = payload.get("trials")
        if isinstance(trials, list):
            for item in trials:
                if isinstance(item, dict):
                    yield item
        else:
            yield payload


def _normalize(d: dict[str, Any]) -> Optional[dict[str, Any]]:
    task = d.get("task")
    if not task:
        return None
    status = d.get("status")
    if not status:
        status = _OUTCOME_TO_STATUS.get(str(d.get("outcome") or "").lower(), "error")
    return {
        "task": str(task),
        "status": str(status),
        "started_at": str(d.get("started_at") or ""),
        "benchmark": d.get("benchmark"),
    }


def load_records(results_dirs: list[str], extra: list[str]) -> list[dict[str, Any]]:
    """Normalized trial records, de-duplicated by (task, started_at), start-sorted."""
    paths: list[Path] = []
    for d in results_dirs:
        paths.extend(sorted(Path(d).glob("*.json")))
    paths.extend(Path(p) for p in extra)

    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for raw in _records_in(payload):
            rec = _normalize(raw)
            if rec is None:
                continue
            key = (rec["task"], rec["started_at"])
            if key in seen:
                continue
            seen.add(key)
            rows.append(rec)
    rows.sort(key=lambda r: r["started_at"])
    return rows


# ---------------------------------------------------------------------------
# statistics
# ---------------------------------------------------------------------------
def resolve_method(method: str) -> str:
    """The interval method that will actually be computed.

    jeffreys/clopper need SciPy; without it the renderer falls back to Wilson
    and says so (warning + the resolved name goes into the title/summary), so a
    figure never carries a label for an interval it did not draw.
    """
    if method in ("jeffreys", "clopper"):
        try:
            import scipy.stats  # noqa: F401
        except Exception:
            import warnings
            warnings.warn(
                f"--interval {method} needs SciPy, which is not installed; "
                "falling back to the Wilson interval (label updated to 'wilson')",
                RuntimeWarning, stacklevel=2,
            )
            return "wilson"
    return method


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


def _task_colour(statuses: list[str], attempted: frozenset = frozenset(_ATT_STATUS)) -> str:
    """Green if the task ever succeeded; amber if genuinely attempted; else grey."""
    if any(s == "success" for s in statuses):
        return SUCC
    if any(s in attempted for s in statuses):
        return ATT
    return NONE


def _aggregate(rows: list[dict[str, Any]]) -> "OrderedDict[str, list[str]]":
    """task -> list of per-trial statuses, insertion-ordered by first sighting."""
    by_task: "OrderedDict[str, list[str]]" = OrderedDict()
    for r in rows:
        by_task.setdefault(r["task"], []).append(r["status"])
    return by_task


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------
def render(rows: list[dict[str, Any]], out: Path, confidence: float, method: str,
           title: Optional[str] = None, *,
           preset: Preset = PRESETS["generic"],
           subtitle: Optional[str] = None,
           show_validity: bool = False,
           labels: Optional[dict[str, str]] = None,
           task_labels: Optional[dict[str, str]] = None) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch

    lab = {
        "success": preset.success_label,
        "failure": preset.failure_label,
        "invalid": preset.invalid_label,
    }
    if labels:
        lab.update({k: v for k, v in labels.items() if v})

    method = resolve_method(method)
    by_task = _aggregate(rows)
    tasks = []
    for task, statuses in by_task.items():
        valid = [s for s in statuses if s == "success" or s in preset.attempted]
        n, inv = len(valid), len(statuses) - len(valid)
        k = sum(1 for s in valid if s == "success")
        phat, lo, hi = _interval(k, n, method, confidence)
        tasks.append({
            "task": task, "k": k, "n": n, "inv": inv,
            "p": phat, "lo": lo, "hi": hi,
            "colour": _task_colour(statuses, preset.attempted),
        })
    # Best first (high p-hat on top); break ties by more trials, then name.
    tasks.sort(key=lambda t: (t["p"], t["n"], t["task"]))  # low->high; invert y below

    tot_k = sum(t["k"] for t in tasks)
    tot_n = sum(t["n"] for t in tasks)
    tot_inv = sum(t["inv"] for t in tasks)
    pooled = (tot_k / tot_n * 100.0) if tot_n else 0.0

    ys = np.arange(len(tasks))
    fig_h = max(2.4, 0.34 * len(tasks) + 1.5)
    axv = None
    if show_validity:
        fig, (ax, axv) = plt.subplots(
            1, 2, figsize=(11.5, fig_h), dpi=150, sharey=True,
            gridspec_kw={"width_ratios": [4, 1.3], "wspace": 0.10},
        )
    else:
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
        # Marker size grows with the number of valid trials (confidence in the dot).
        ax.scatter(p, y, s=40 + 16 * max(0, t["n"] - 1), color=t["colour"], zorder=3,
                   edgecolor="white", linewidth=0.7)
        note = f"{t['k']}/{t['n']}"
        if t["inv"] and not show_validity:
            note += f" (+{t['inv']} inv)"
        ax.annotate(note, xy=(102, y), xytext=(4, 0),
                    textcoords="offset points", va="center", ha="left",
                    fontsize=7, color=MUTED, annotation_clip=False)

    ax.set_yticks(ys)
    task_labels = task_labels or {}
    ax.set_yticklabels([task_labels.get(t["task"], t["task"]) for t in tasks],
                       fontsize=7.5, color=INK)
    ax.set_xlabel(f"per-{preset.noun} success probability (%)", color=INK, fontsize=10)
    ci_pct = int(round(confidence * 100))
    plot_title = (title if title is not None
                  else f"{preset.title_prefix}  ({method} {ci_pct}% CI, {preset.oracle})")
    ax.set_title(plot_title, color=INK, fontsize=12, fontweight="bold", loc="left",
                 pad=16 if subtitle else 6)
    if subtitle:
        ax.text(0.0, 1.005, subtitle, transform=ax.transAxes, va="bottom", ha="left",
                fontsize=8, color=MUTED)
    ax.grid(True, axis="x", color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.tick_params(colors=MUTED, labelsize=9)

    if axv is not None:
        max_total = max((t["n"] + t["inv"] for t in tasks), default=1)
        for y, t in zip(ys, tasks):
            axv.barh(y, t["n"], color=t["colour"], alpha=0.9, height=0.6, zorder=2)
            if t["inv"]:
                axv.barh(y, t["inv"], left=t["n"], color=NONE, alpha=0.9, height=0.6, zorder=2)
            axv.annotate(f"{t['n']}/{t['n'] + t['inv']}", xy=(t["n"] + t["inv"], y),
                         xytext=(3, 0), textcoords="offset points", va="center",
                         fontsize=7, color=MUTED)
        axv.set_xlim(0, max_total * 1.25 + 0.5)
        axv.set_xlabel("valid / total attempts", color=INK, fontsize=9)
        axv.set_title("validity", color=INK, fontsize=9, loc="left")
        axv.grid(True, axis="x", color=GRID, lw=0.8)
        axv.set_axisbelow(True)
        for spine in ("top", "right", "left"):
            axv.spines[spine].set_visible(False)
        axv.tick_params(axis="y", length=0)
        axv.tick_params(colors=MUTED, labelsize=8)

    legend = [
        Line2D([0], [0], marker="o", ls="", color=SUCC, label=lab["success"], markersize=7),
        Line2D([0], [0], marker="o", ls="", color=ATT, label=lab["failure"], markersize=7),
        Line2D([0], [0], marker="o", ls="", color=NONE, label=lab["invalid"], markersize=7),
        Line2D([0], [0], color=MUTED, lw=1.3, label=f"{ci_pct}% CI (right: k/n valid trials)"),
    ]
    if axv is not None:
        legend.append(Patch(facecolor=NONE, label="infrastructure-invalid attempt"))
    # Anchor the legend a fixed ~0.6 in below the axis (just under the x-label)
    # instead of a fraction of the axes height, so tall figures don't leave a
    # band of empty space; one row for the standard four entries.
    legend_y = -(0.62 / (fig_h * 0.9))
    ax.legend(handles=legend, frameon=False, fontsize=8.5,
              ncol=4 if len(legend) <= 4 else 3, columnspacing=1.4,
              loc="upper center", bbox_to_anchor=(0.5, legend_y))

    if axv is None:
        fig.tight_layout()  # the shared-y two-panel layout is cropped by bbox_inches instead
    fig.savefig(out, bbox_inches="tight")
    extra = f", {tot_inv} infrastructure-invalid excluded" if tot_inv else ""
    print(f"wrote {out}  ({len(tasks)} {preset.noun}s, {tot_k}/{tot_n} valid trials solved, "
          f"pooled {pooled:.1f}%, {method} {ci_pct}% CI{extra})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser(default_benchmark: str = "generic") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Per-task success-probability forest plot.")
    p.add_argument("--results-dir", action="append", default=None,
                   help="dir of normalized trial JSONs (repeatable)")
    p.add_argument("--extra", action="append", default=[],
                   help="extra trial JSON to include (repeatable)")
    p.add_argument("--benchmark", choices=sorted(PRESETS), default=default_benchmark,
                   help="label preset (default %(default)s)")
    p.add_argument("--out", type=Path, default=None, help="output PNG")
    p.add_argument("--confidence", type=float, default=0.95,
                   help="confidence level for the per-task interval (default 0.95)")
    p.add_argument("--interval", choices=("jeffreys", "clopper", "wilson"),
                   default="jeffreys",
                   help="small-sample interval estimator (default jeffreys; "
                        "jeffreys/clopper need SciPy, else fall back to wilson)")
    p.add_argument("--title", default=None, help="plot title (default: the preset's)")
    p.add_argument("--subtitle", default=None,
                   help="one-line note under the title (default: an auto summary; "
                        "pass '' to suppress)")
    p.add_argument("--show-validity", action="store_true",
                   help="add the valid/total-attempts companion panel")
    p.add_argument("--success-label", default=None)
    p.add_argument("--failure-label", default=None)
    p.add_argument("--invalid-label", default=None)
    p.add_argument("--task-labels", type=Path, default=None,
                   help="JSON object mapping task id -> y-axis label (e.g. to "
                        "append a CVSS score); unmapped tasks keep their id")
    return p


def load_task_labels(path: Optional[Path]) -> dict[str, str]:
    """Read a ``{task: label}`` JSON object; reject anything else loudly."""
    if path is None:
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in payload.items()
    ):
        raise SystemExit(f"--task-labels {path}: expected a JSON object of string -> string")
    return payload


def main(argv: Optional[list[str]] = None, *, default_benchmark: str = "generic") -> int:
    args = build_parser(default_benchmark).parse_args(argv)
    preset = PRESETS[args.benchmark]

    results_dirs = args.results_dir or ([preset.default_results_dir] if preset.default_results_dir else [])
    if not results_dirs and not args.extra:
        raise SystemExit("--results-dir (or --extra) is required for this benchmark")
    out = args.out or (Path(preset.default_out) if preset.default_out else None)
    if out is None:
        raise SystemExit("--out is required for this benchmark")

    rows = load_records(results_dirs, args.extra)
    if not rows:
        raise SystemExit("no trial result JSONs found")

    subtitle = args.subtitle
    if subtitle is None:
        n_tasks = len({r["task"] for r in rows})
        n_valid = sum(1 for r in rows if r["status"] == "success" or r["status"] in preset.attempted)
        subtitle = (f"{preset.name}: {n_tasks} {preset.noun}{'s' if n_tasks != 1 else ''}, "
                    f"{n_valid} valid of {len(rows)} attempts")
    elif subtitle == "":
        subtitle = None

    out.parent.mkdir(parents=True, exist_ok=True)
    render(rows, out, args.confidence, args.interval, args.title,
           preset=preset, subtitle=subtitle, show_validity=args.show_validity,
           labels={"success": args.success_label, "failure": args.failure_label,
                   "invalid": args.invalid_label},
           task_labels=load_task_labels(args.task_labels))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
