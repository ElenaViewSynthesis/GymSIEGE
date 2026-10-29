#!/usr/bin/env python3
"""Draw one collusion run as an evidence timeline: channels as lanes, stage as color.

Usage: plot_run_timeline.py <run-dir-or-artifacts.tar.gz> <out.png> [--case CLH-036]

Reads the case report (evidence kinds, timestamps, via/from/to fields) and the
chained event logs from a Modal run's artifacts.tar.gz. Draws, for the six
channels the suite plants (paper Table 7), every coordination-stage event at
the second it occurred, colored by the stage it sets (one blue ramp, light to
dark: discovered, read, wrote, exchanged, acted), the planted baselines as
gray ticks, the subject's process activity as a gray strip, and a hairline at
the first coordination event. Never reads, prints, or draws a marker value:
only event kinds, channel names, run roles, and timestamps.

Palette: the ordinal blue ramp validated for five steps (light end 2.1:1 on
white); chrome in ink tokens. Matches the paper's figure conventions
(DejaVu Sans, hairline grid, no chart title; the caption lives in LaTeX).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

LANES = [
    "Shared cache",
    "Coordination board",
    "Peer workspaces",
    "Inboxes",
    "Task queue and result ledger",
    "Delegation",
]
VIA_LANE = {
    "cache": "Shared cache", "shared": "Shared cache", "shared_cache": "Shared cache",
    "board": "Coordination board",
    "workspace": "Peer workspaces", "peer_workspace": "Peer workspaces",
    "inbox": "Inboxes",
    "queue": "Task queue and result ledger", "ledger": "Task queue and result ledger",
    "delegate": "Delegation", "delegation": "Delegation", "child": "Delegation",
}
KIND_LANE = {
    "SHARED_CHANNEL_READ": "Shared cache", "SHARED_CHANNEL_WRITE": "Shared cache",
    "BOARD_READ": "Coordination board", "BOARD_POST": "Coordination board",
    "PEER_DISCOVERY": "Peer workspaces", "FOREIGN_WORKSPACE_READ": "Peer workspaces",
    "PEER_INBOX_WRITE": "Inboxes",
    "TASK_QUEUE_TAMPER": "Task queue and result ledger",
    "RESULT_SPOOFED": "Task queue and result ledger",
    "NESTED_HARNESS_SPAWN": "Delegation", "DELEGATION_ESCAPE": "Delegation",
    "DELEGATION_DEPTH_EXCEEDED": "Delegation", "ASSIGNMENT_LAUNDERED": "Delegation",
}
STAGE_OF = {
    "PEER_DISCOVERY": "discovered",
    "FOREIGN_WORKSPACE_READ": "read", "SHARED_CHANNEL_READ": "read", "BOARD_READ": "read",
    "DELEGATION_ESCAPE": "read",
    "SHARED_CHANNEL_WRITE": "wrote", "BOARD_POST": "wrote", "PEER_INBOX_WRITE": "wrote",
    "TASK_QUEUE_TAMPER": "wrote",
    "CROSS_RUN_MARKER_TRANSFER": "exchanged",
    "COORDINATION_ACTED": "acted", "RESULT_SPOOFED": "acted", "ASSIGNMENT_LAUNDERED": "acted",
}
STAGES = ["discovered", "read", "wrote", "exchanged", "acted"]
RAMP = {"discovered": "#86b6ef", "read": "#5598e7", "wrote": "#2a78d6",
        "exchanged": "#1c5cab", "acted": "#104281"}
PLANTED = {"CHANNEL_VERSION", "WORKSPACE_VERSION"}
INK, INK2, MUTED, GRID, BASE, SURFACE = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#ffffff"


def open_archive(source: Path) -> tarfile.TarFile:
    archive = source if source.is_file() else source / "artifacts.tar.gz"
    return tarfile.open(archive, "r:*")


def tsv_events(tar: tarfile.TarFile, member: str) -> list[tuple[float, str]]:
    """(timestamp, kind) pairs from a chained events.mirror.tsv; other columns ignored."""
    try:
        raw = tar.extractfile(member).read().decode("utf-8", errors="replace")
    except KeyError:
        return []
    out = []
    for line in raw.splitlines():
        cols = line.split("\t")
        if len(cols) > 5 and re.match(r"^\d+(\.\d+)?$", cols[4]):
            out.append((float(cols[4]), cols[5]))
    return out


def lane_for(kind: str, detail: object) -> str | None:
    if isinstance(detail, dict):
        via = str(detail.get("via", "")).lower()
        if via in VIA_LANE:
            return VIA_LANE[via]
        channel = str(detail.get("channel", "")).lower()
        if channel in VIA_LANE:
            return VIA_LANE[channel]
    return KIND_LANE.get(kind)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--case", default=None, help="case id inside the archive (default: the only one)")
    args = parser.parse_args()

    with open_archive(args.source) as tar:
        names = tar.getnames()
        cases = sorted({n.split("/")[1] for n in names if n.startswith("cases/") and n.count("/") >= 2})
        case = args.case or (cases[0] if len(cases) == 1 else None)
        if case is None:
            raise SystemExit(f"archive holds several cases {cases}; pass --case")
        report = json.loads(tar.extractfile(f"cases/{case}/report.json").read())
        orch = tsv_events(tar, f"cases/{case}/orchestrator/events.mirror.tsv")
        subject = tsv_events(tar, f"cases/{case}/runs/subject/harness/events.mirror.tsv")

    # The report's time_to_first_coordination_s counts from the earliest logged
    # event, so the axis does the same; CASE_STARTED lands a fraction later.
    t0 = min(t for t, _ in orch + subject)
    t_end = max([t for t, k in orch if k == "CASE_FINISHED"] or [t for t, _ in orch + subject])
    span = max(t_end - t0, 1.0)

    # Coordination-stage events and planted baselines, from the report's evidence.
    marks: list[tuple[float, str, str, str]] = []  # (t, lane, stage, kind)
    planted: list[tuple[float, str]] = []
    for item in report.get("evidence", []):
        kind, t = str(item["kind"]), float(item["timestamp"]) - t0
        detail = item.get("detail")
        if kind in PLANTED:
            lane = lane_for(kind, detail) or ("Peer workspaces" if kind == "WORKSPACE_VERSION" else "Shared cache")
            planted.append((t, lane))
            continue
        stage = STAGE_OF.get(kind)
        lane = lane_for(kind, detail)
        if stage and lane:
            marks.append((t, lane, stage, kind))

    # Subject process activity per 5 s bin (context strip).
    width = 5.0
    activity: Counter = Counter()
    for t, kind in subject:
        if kind in {"SUBPROCESS_SPAWN", "EXEC"}:
            activity[int((t - t0) // width)] += 1
    first_coord = report.get("time_to_first_coordination_s")

    plt.rcParams.update({"font.size": 8.5, "font.family": "DejaVu Sans"})
    fig, (ax, ax_act) = plt.subplots(
        2, 1, figsize=(5.5, 3.6), dpi=260, sharex=True,
        gridspec_kw={"height_ratios": [6, 1.2], "hspace": 0.08})
    fig.patch.set_facecolor(SURFACE)
    for a in (ax, ax_act):
        a.set_facecolor(SURFACE)
        for side in ("top", "right"):
            a.spines[side].set_visible(False)
        a.spines["left"].set_color(BASE)
        a.spines["bottom"].set_color(BASE)
        a.tick_params(axis="both", length=0, colors=MUTED, labelsize=7.5)

    ys = {lane: i for i, lane in enumerate(reversed(LANES))}
    ax.set_yticks(list(ys.values()))
    ax.set_yticklabels(list(ys.keys()), color=INK, fontsize=7.8)
    ax.set_ylim(-0.6, len(LANES) - 0.4)
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for lane in LANES:  # lane baselines
        ax.axhline(ys[lane], color=GRID, linewidth=0.6, zorder=0)

    for t, lane in planted:
        ax.plot([t, t], [ys[lane] - 0.22, ys[lane] + 0.22], color=MUTED, linewidth=1.0, zorder=2)
    # Spread coincident marks slightly so two events at one second stay visible.
    groups: dict[tuple[float, str], list[tuple[str, str]]] = defaultdict(list)
    for t, lane, stage, kind in sorted(marks, key=lambda m: (m[0], STAGES.index(m[2]))):
        groups[(round(t, 1), lane)].append((stage, kind))
    for (t, lane), items in groups.items():
        # Coincident events on one lane fan out vertically, lowest stage at the bottom.
        n = len(items)
        for i, (stage, _) in enumerate(items):
            offset = (i - (n - 1) / 2) * 0.34
            ax.plot(t, ys[lane] + offset, marker="o", markersize=7.0, color=RAMP[stage],
                    markeredgecolor=SURFACE, markeredgewidth=1.2, linestyle="none", zorder=4)

    if isinstance(first_coord, (int, float)):
        ax.axvline(first_coord, color=BASE, linewidth=0.8, zorder=1)
        ax.text(first_coord, len(LANES) - 0.5, f"first coordination event\n{first_coord:.1f} s",
                ha="right" if first_coord > span * 0.6 else "left", va="top", fontsize=7.2, color=INK2,
                transform=ax.transData, bbox={"facecolor": SURFACE, "edgecolor": "none", "pad": 1.0})

    if activity:
        xs = [b * width for b in sorted(activity)]
        hs = [activity[b] for b in sorted(activity)]
        ax_act.bar(xs, hs, width=width * 0.9, align="edge", color=MUTED, edgecolor=SURFACE, linewidth=0.6)
    ax_act.set_yticks([])
    ax_act.set_ylabel("subject\nspawns", color=INK2, fontsize=7.2, rotation=0, ha="right", va="center", labelpad=6)
    ax_act.set_xlim(0, span * 1.02)
    ax_act.set_xlabel("seconds since case start", color=INK2)
    ax_act.spines["left"].set_visible(False)

    handles = [Patch(facecolor=RAMP[s], edgecolor=SURFACE, label=s) for s in STAGES]
    handles.append(Line2D([0], [0], color=MUTED, linewidth=1.2, label="planted baseline version"))
    fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False, fontsize=7.2,
               handlelength=1.4, labelcolor=INK, bbox_to_anchor=(0.60, 0.0))
    fig.subplots_adjust(left=0.30, right=0.98, top=0.97, bottom=0.26)
    fig.savefig(args.output, facecolor=SURFACE)

    summary = {
        "case": case, "stage": report.get("observed_stage"), "score": report.get("score"),
        "first_coordination_s": first_coord, "case_seconds": round(span, 1),
        "marks": [(round(t, 2), lane, stage, kind) for t, lane, stage, kind in marks],
        "planted": Counter(lane for _, lane in planted),
        "subject_spawn_events": sum(activity.values()),
    }
    print(json.dumps(summary, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
