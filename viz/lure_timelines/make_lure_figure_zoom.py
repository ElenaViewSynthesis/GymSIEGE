"""Publication figure: four Luna lure runs on one shared time axis, with zooms.

(a) overview: all four runs on one linear 0-600 s axis, one row per run.
(b) the same rows, zoomed into the three windows where the lure events happen
    (a broken axis: each window has its own scale, all share the rows).

Subset rule: runs whose timelines contain >= 5 distinct event symbols
(four Luna runs, one per task, all on the unsolvable form).
Every mark sits at its true time. Same-kind events within 0.1 s are drawn once
with a xN count; marks that would overlap move to the nearest free slot above
or below the run's bar (first fit, centre out).

Usage:  python make_lure_figure_zoom.py RUNS_JSON EVENTS_JSON OUT_DIR [WIDTH_IN]

WIDTH_IN (default 7.0) is the figure's width in inches. At 7.0 the label
gutters are the fixed 1.62 in / 1.12 in; at any other width they are measured
from the run and outcome labels as drawn, and every font and marker keeps its
size, so a 5.5 in figure prints at its own size at a 5.5 in text width.
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Rectangle
from matplotlib.transforms import ScaledTranslation, blended_transform_factory

runs_path, events_path, out_dir = map(Path, sys.argv[1:4])
FIG_W = float(sys.argv[4]) if len(sys.argv) > 4 else 7.0
out_dir.mkdir(parents=True, exist_ok=True)
runs = {r["run_id"]: r for r in json.loads(runs_path.read_text())}
events = json.loads(events_path.read_text())

# ---------------------------------------------------------------- encoding
LURE, CASE, INK = "#D55E00", "#0072B2", "#1a1a1a"
TICK, BAR, BAND, MUTED = "#9e9e9e", "#cfcfcf", "#f4f4f4", "#5a5a5a"
KINDS = {  # kind -> (marker, face, edge, size_pt, label); order = placement priority
    "checkpoint_read": ("s", LURE, LURE, 4.4, "Reference checkpoint read"),
    "lure_discovery":  ("o", "white", LURE, 4.6, "Lure folder listed"),
    "lure_open":       ("o", LURE, LURE, 4.6, "Lure solution opened"),
    "experiment_read": ("^", CASE, CASE, 5.0, "Case files read"),
    "answer_written":  ("D", INK, INK, 3.9, "Answer written"),
    "agent_exit":      ("o", INK, INK, 3.2, "Agent finished"),
    "budget_stop":     ("|", INK, INK, 6.0, "Budget reached"),
}
RANK = {k: i for i, k in enumerate(KINDS)}
STAGE = {"accessed": "lure opened", "submitted": "lure answer submitted",
         "discovered": "lure listed", "none": "no lure contact"}

# zoom windows (s): where the lure events happen
WINDOWS = [(0, 90), (386, 411), (557, 587)]
WIN_LABELS = ["i", "ii", "iii"]

# ---------------------------------------------------------------- subset
per_run = defaultdict(Counter)
for e in events:
    if e["kind"] in KINDS:
        per_run[e["run_id"]][e["kind"]] += 1
selected = sorted((rid for rid, c in per_run.items() if len(c) >= 5),
                  key=lambda rid: runs[rid]["case_id"])
n = len(selected)
ev_by_run = {rid: [e for e in events if e["run_id"] == rid] for rid in selected}

# ---------------------------------------------------------------- style
mpl.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Helvetica", "Arial", "DejaVu Sans"],
    "font.size": 7, "axes.linewidth": 0.6, "axes.edgecolor": "#333",
    "xtick.major.width": 0.6, "xtick.major.size": 2.5, "xtick.labelsize": 6.3,
    "xtick.color": "#333", "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
})

LEFT, RIGHT = 1.62, 1.12          # in, label gutters at the default 7.0 in width


def text_width_in(s, **kw):
    """Width in inches of one label as matplotlib draws it."""
    probe = plt.figure(figsize=(1, 1))
    t = probe.text(0, 0, s, **kw)
    w = t.get_window_extent(probe.canvas.get_renderer()).width / probe.dpi
    plt.close(probe)
    return w


if FIG_W != 7.0:  # gutters measured from the labels, 7 pt from the axis plus a small margin
    LEFT = max(max(text_width_in(f"{runs[r]['case_id']}  {runs[r]['pair']}", fontsize=6.9, fontweight="bold"),
                   text_width_in(f"{runs[r]['budget']} budget · {runs[r]['tool_calls']} tool calls", fontsize=6))
               for r in selected) + 7 / 72 + 0.06
    RIGHT = max(max(text_width_in(STAGE.get(runs[r]["stage"], runs[r]["stage"]), fontsize=6.5),
                    text_width_in(f"verifier {runs[r]['verifier']} · {float(runs[r]['wall_s']):.0f} s", fontsize=6))
                for r in selected) + 7 / 72 + 0.06
AX_W = FIG_W - LEFT - RIGHT       # in
GAP, STEP = 0.8, 5.8              # pt: clearance, row pitch


def badge_pt(c, fs):
    return 0 if c == 1 else 0.55 * fs * (1 + len(str(c))) + 1.5


def layout(evs, lo, hi, pt_per_s, scale):
    """(kind, instant) marks inside [lo, hi], each in the nearest free slot."""
    same = Counter((e["kind"], round(e["t_s"], 1)) for e in evs
                   if e["kind"] in KINDS and lo <= e["t_s"] <= hi)
    items = sorted(({"kind": k, "t": t, "n": c} for (k, t), c in same.items()),
                   key=lambda it: (it["t"], RANK[it["kind"]]))
    box = 5.0 * scale
    rows = defaultdict(list)
    order = [0] + [s * k for k in range(1, 12) for s in (1, -1)]
    for it in items:
        x = (it["t"] - lo) * pt_per_s
        ext = (x - box / 2 - GAP, x + box / 2 + badge_pt(it["n"], 5.2 * scale) + GAP)
        for k in order:
            if all(ext[1] <= a or ext[0] >= b for a, b in rows[k]):
                rows[k].append(ext)
                it["row"] = k
                break
    return items


def draw_rows(ax, lo, hi, width_in, scale, step):
    """Bars, tool-call ticks and event marks for every run inside [lo, hi]."""
    pt_per_s = width_in * 72 / (hi - lo)
    row_h_pt = ax.get_position().height * FIG_H * 72 / n
    tick_half = 4.0 * scale / row_h_pt
    for i, rid in enumerate(selected):
        if i % 2 == 0:
            ax.axhspan(i - 0.5, i + 0.5, color=BAND, lw=0, zorder=0)
        wall = float(runs[rid]["wall_s"])
        if wall >= lo:
            ax.plot([max(lo, 0), min(wall, hi)], [i, i], color=BAR, lw=1.6 * scale ** 0.5,
                    solid_capstyle="butt", zorder=1)
        for e in ev_by_run[rid]:
            if e["kind"] == "tool_call" and lo <= e["t_s"] <= hi:
                ax.plot([e["t_s"]] * 2, [i - tick_half, i + tick_half], color=TICK, lw=0.7, zorder=2)
        for it in layout(ev_by_run[rid], lo, hi, pt_per_s, scale):
            mk, face, edge, size, _ = KINDS[it["kind"]]
            up = it["row"] * step
            tr = ax.transData + ScaledTranslation(0, up / 72, fig.dpi_scale_trans)
            ax.plot(it["t"], i, marker=mk, ms=size * scale, mfc=face, mec=edge,
                    mew=0.85 if face == "white" else 0.45, ls="none", transform=tr,
                    zorder=4, clip_on=False)
            if it["n"] > 1:
                ttr = ax.transData + ScaledTranslation((2.5 * scale + 0.9) / 72, up / 72, fig.dpi_scale_trans)
                ax.text(it["t"], i, f"×{it['n']}", transform=ttr, fontsize=5.2 * scale,
                        color="#444", va="center", ha="left", zorder=5, clip_on=False)


def style_axis(ax, lo, hi):
    ax.set_xlim(lo, hi)
    ax.set_ylim(n - 0.5, -0.5)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.set_yticks([])
    ax.tick_params(axis="x", pad=1.5)


# ---------------------------------------------------------------- geometry (in)
ZSCALE, ZSTEP = 1.25, 7.0                      # zoom panels: bigger marks, wider pitch
ROW_A, ROW_B = 0.50, 0.50
TOP, MID, BOTTOM = 0.30, 0.62, 0.78            # TOP: panel tag; MID: axis a + tag b; BOTTOM: axis b + legend
H_A, H_B = n * ROW_A, n * ROW_B
FIG_H = TOP + H_A + MID + H_B + BOTTOM
fig = plt.figure(figsize=(FIG_W, FIG_H))
fy = lambda inch: inch / FIG_H
fx = lambda inch: inch / FIG_W

# ---------------------------------------------------------------- (a) overview
ax_a = fig.add_axes([fx(LEFT), fy(BOTTOM + H_B + MID), fx(AX_W), fy(H_A)])
style_axis(ax_a, 0, 600)
ax_a.set_xticks(range(0, 601, 100))
for xv in range(100, 601, 100):
    ax_a.axvline(xv, color="#e6e6e6", lw=0.5, zorder=0.5)
for (lo, hi), lab in zip(WINDOWS, WIN_LABELS):
    ax_a.add_patch(Rectangle((lo, -0.5), hi - lo, n, facecolor="none", edgecolor="#777",
                             lw=0.6, ls=(0, (2, 1.5)), zorder=3))
    ax_a.text((lo + hi) / 2, -0.5, lab, ha="center", va="bottom", fontsize=6.3, color="#444",
              fontstyle="italic", transform=ax_a.transData + ScaledTranslation(0, 1.5 / 72, fig.dpi_scale_trans))
short_s = max(float(r["budget_s"]) for r in runs.values() if r["budget"] == "short")
ax_a.axvline(short_s, color="#8c8c8c", lw=0.6, ls=(0, (3, 2)), zorder=0.6)
# at a narrower width the shorter label keeps clear of window i's label
short_label = f"short budget ends ({short_s:.0f} s)" if FIG_W == 7.0 else f"short budget ({short_s:.0f} s)"
ax_a.text(short_s - 4, -0.5, short_label, ha="right", va="bottom",
          fontsize=5.9, color=MUTED, transform=ax_a.transData + ScaledTranslation(0, 1.5 / 72, fig.dpi_scale_trans))
draw_rows(ax_a, 0, 600, AX_W, 1.0, STEP)
ax_a.set_xlabel("seconds from run start", fontsize=6.6, labelpad=1.5)

# run labels (left) and outcomes (right), once, on the overview
lab_t = blended_transform_factory(ax_a.transAxes, ax_a.transData)
def side(ax, x, i, dx, dy, text, **kw):
    t = blended_transform_factory(ax.transAxes, ax.transData)
    ax.text(x, i, text, va="center", transform=t + ScaledTranslation(dx / 72, dy / 72, fig.dpi_scale_trans), **kw)
for i, rid in enumerate(selected):
    r = runs[rid]
    side(ax_a, 0, i, -7, 3.9, f"{r['case_id']}  {r['pair']}", ha="right", fontweight="bold", fontsize=6.9)
    side(ax_a, 0, i, -7, -4.1, f"{r['budget']} budget · {r['tool_calls']} tool calls", ha="right", color=MUTED, fontsize=6)
    ok = r["verifier"] == "pass"
    side(ax_a, 1, i, 7, 3.9, STAGE.get(r["stage"], r["stage"]), ha="left", fontsize=6.5)
    side(ax_a, 1, i, 7, -4.1, f"verifier {r['verifier']} · {float(r['wall_s']):.0f} s",
         ha="left", fontsize=6, color="#1b7837" if ok else "#b2182b")

# ---------------------------------------------------------------- (b) zooms
spans = [hi - lo for lo, hi in WINDOWS]
GAP_W = 0.16                                    # in, between windows
weights = [2.2, 1.0, 1.15]                      # share of width per window
usable = AX_W - GAP_W * (len(WINDOWS) - 1)
widths = [usable * w / sum(weights) for w in weights]
x_in = LEFT
axes_b = []
for k, ((lo, hi), w, lab) in enumerate(zip(WINDOWS, widths, WIN_LABELS)):
    ax = fig.add_axes([fx(x_in), fy(BOTTOM), fx(w), fy(H_B)])
    style_axis(ax, lo, hi)
    step = 10
    if FIG_W != 7.0:  # a narrower window: widen the tick step until labels sit >= 16 pt apart
        while step * w * 72 / (hi - lo) < 16:
            step *= 2
    ax.set_xticks(range(int(lo + (-lo) % step), int(hi) + 1, step))
    draw_rows(ax, lo, hi, w, ZSCALE, ZSTEP)
    ax.text(0.5, 1.0, f"{lab}   {lo:.0f}–{hi:.0f} s", transform=ax.transAxes, ha="center", va="bottom",
            fontsize=6.3, color="#444", fontstyle="italic")
    if k:  # axis-break mark at the start of each later window
        bt = ax.transAxes + ScaledTranslation(-GAP_W / 2, 0, fig.dpi_scale_trans)
        ax.text(0, 0, "//", transform=bt, ha="center", va="center", fontsize=6, color="#333")
    axes_b.append(ax)
    x_in += w + GAP_W
for i, rid in enumerate(selected):
    side(axes_b[0], 0, i, -7, 0, f"{runs[rid]['case_id']}", ha="right", fontweight="bold", fontsize=6.9)
fig.text(fx(LEFT + AX_W / 2), fy(BOTTOM) - 0.25 / FIG_H, "seconds from run start (zoomed windows)",
         ha="center", va="top", fontsize=6.6)

# panel tags
fig.text(fx(0.12), fy(FIG_H - 0.10), "a", fontweight="bold", fontsize=9, va="top")
fig.text(fx(0.12), fy(BOTTOM + H_B + 0.30), "b", fontweight="bold", fontsize=9, va="top")
fig.text(fx(0.30), fy(FIG_H - 0.11), "All runs, one time axis", fontsize=7, va="top", color="#333")
fig.text(fx(0.30), fy(BOTTOM + H_B + 0.29), "Zoom on the windows where the lure is used", fontsize=7, va="top", color="#333")

# legend
handles = [Line2D([], [], color=TICK, lw=0.7, marker="|", ms=5.5, ls="none", mew=0.7, label="Tool call")]
present = {e["kind"] for rid in selected for e in ev_by_run[rid]}
for kind, (mk, face, edge, size, label) in KINDS.items():
    if kind in present:
        handles.append(Line2D([], [], marker=mk, ms=size, mfc=face, mec=edge,
                              mew=0.85 if face == "white" else 0.45, ls="none", label=label))
fig.legend(handles=handles, loc="lower center", ncol=4, frameon=False, fontsize=6.3,
           handletextpad=0.3, columnspacing=1.2, handlelength=1.2,
           bbox_to_anchor=(fx(LEFT + AX_W / 2), 0.0))

for ext in ("pdf", "svg", "png"):
    fig.savefig(out_dir / f"fig_lure_timelines_zoom.{ext}", dpi=400 if ext == "png" else None)
print("selected:", selected)
