# Lure timelines figure

`make_lure_figure_zoom.py` draws the honeypot paper's Figure 4: four Luna lure
runs on one shared time axis, with zooms into the windows where the lure events
happen.

- **(a)** shows all four runs on one linear 0-600 s axis, one row per run.
- **(b)** shows the same rows on a broken axis with three windows: 0-90 s,
  386-411 s and 557-587 s.

The script picks the runs whose timelines carry at least five distinct event
symbols. That gives four Luna runs, one per task, all on the unsolvable form.
Every mark sits at its true time:

- events of the same kind within 0.1 s of each other are drawn once, with a
  ×N count;
- a mark that would overlap another moves to the nearest free slot above or
  below the run's bar.

## Files

| File | What it is |
|---|---|
| `make_lure_figure_zoom.py` | the figure script (matplotlib) |
| `datasets/runs.json` | one row per lure run, 32 runs |
| `datasets/events.json` | one row per timed event, 469 events |

The 32 runs are the two lure cohorts, 16 cells each:

- `results/docker-honeypot-lure-exp/lure-luna-v1-20261104T145103Z` (`gpt-5.6-luna`);
- `results/docker-honeypot-lure-exp/lure-opus-v1-20261104T161126Z` (`claude-opus-5-5`).

Each cohort covers 4 task pairs × solvable/unsolvable × short (300 s) / long
(1,200 s).

`runs.json` is version 3 of the lure-trajectories dashboard's runs dataset. In
that version, the Luna cohort is re-gated under scored set version 3, which
changes only ULT-008 long. `events.json` is the dashboard's events dataset
with its free-text `detail` column removed. The figure reads only `run_id`,
`kind` and `t_s` from it.

Both datasets were built with each run's secrets masked:

- the hub token, the canary and every lure answer;
- `FLAG{...}`, hex runs of 16 or more characters, decimal runs of 12 or more
  digits, and markers.

Paths are shortened to `<workspace>`, `<task>` and `<run folder>`. Times are
seconds from the run's start.

## Regenerate

From the repo root, in WSL with the repo venv (matplotlib 3.11.2):

```bash
# NeurIPS and ICML: 7.0 in wide
.venv/bin/python viz/lure_timelines/make_lure_figure_zoom.py \
  viz/lure_timelines/datasets/runs.json viz/lure_timelines/datasets/events.json <out_dir>

# ICLR: 5.5 in wide
.venv/bin/python viz/lure_timelines/make_lure_figure_zoom.py \
  viz/lure_timelines/datasets/runs.json viz/lure_timelines/datasets/events.json <out_dir> 5.5
```

Each run writes `fig_lure_timelines_zoom.pdf`, `.png` and `.svg` into
`<out_dir>`. The optional fourth argument sets the width in inches (default
7.0):

- at 7.0 in, the label gutters are the fixed 1.62 in and 1.12 in;
- at any other width, the gutters are measured from the labels as drawn, and
  fonts and markers keep their size, so the figure prints at its own size in a
  narrower text block.

On 2026-11-05, the paper's three copies were rebuilt from this folder and are
pixel-identical at 300 dpi:
- `fig_lure_timelines_zoom.pdf` at 7.0 in, in the paper folder and in `icml/`;
- the same file at 5.5 in, in `iclr/`.
