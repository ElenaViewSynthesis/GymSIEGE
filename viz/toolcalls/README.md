# Interactive tool-call chart

A self-contained HTML page showing, per task, how many tool calls the agent made
(every `command_execution` and `file_change` in its Codex trajectory), for three
CyberGym end-to-end cohort runs: the repeats cohort's trial 2 (22 tasks) and both
trials of the industry-critical extension cohort (25 tasks each). Bars are
coloured by the verified two-authority outcome; clicking a task expands its
command breakdown (category counts + the full command list with exit status).

Deploy `index.html` as a static page — no server, no build step, no external
dependencies except Google Fonts.

## Files

| File | What it is |
|---|---|
| `index.html` | the built, deployable page (data embedded) |
| `chart.template.html` | the page with `__DATA__` / `__DETAIL__` placeholders |
| `datasets/summary.json` | one row per task (counts, outcome, cost, time) |
| `datasets/detail.json` | per-task command list + category counts |
| `extract_summary.py` | builds `datasets/summary.json` from trajectory + result logs |
| `extract_detail.py` | builds `datasets/detail.json` from trajectory logs |
| `build.py` | injects the two datasets into the template → `index.html` |

## Regenerate

The extractors read the gitignored `artifacts/` and `results/` directories (the
paid-run outputs), so run them from a checkout that has them, or point
`GYMSIEGE_ROOT` at one:

```bash
GYMSIEGE_ROOT=/path/to/daytona-sandbox python3 viz/toolcalls/extract_summary.py viz/toolcalls/datasets/summary.json
GYMSIEGE_ROOT=/path/to/daytona-sandbox python3 viz/toolcalls/extract_detail.py  viz/toolcalls/datasets/detail.json
python3 viz/toolcalls/build.py
```

## Notes

- A tool call is one completed `command_execution` or `file_change` item; the
  expand panel shows each command's shell exit (0 = ok).
- Categories (read / search / build / run / test / edit / shell) are keyword
  heuristics in priority order; the raw command text is always shown so any
  mis-categorisation is visible.
- Commands are truncated to 180 characters in `datasets/detail.json`.
- Outcome colours are CVD-validated (green success / blue other-vuln / orange
  failed) and each bar also carries a glyph, so colour is never the only channel.
- Data generated 2026-10-25 from batches `cybergym-e2e-repeats-v1-t2`,
  `cybergym-e2e-ext25-v1-t1` and `cybergym-e2e-ext25-v1-t2` (model `gpt-5.6-luna`).
  For the two tasks shared by both cohorts (curl, binutils), the extension logs of
  both trials are read from `artifacts/_ext25-v1/` and the repeats logs from the
  restored originals.
