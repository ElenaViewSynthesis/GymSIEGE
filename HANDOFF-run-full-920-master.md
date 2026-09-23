# Codex handoff — run the full 920-task master list on Modal

**Owner:** Codex · **Priority:** medium (scale-up of an existing, working 22-task path;
not blocking) · **Type:** tooling + infra (batch runner variant + a much larger snapshot bake)
**Opened:** 2026-09-23 · **Scope:** run every task in
`reference/cybergym_tasks.master.txt` (920 tasks) end to end on Modal, the same way
`run_modal_pinned_tasks.sh` runs the pinned 22. This is **not** a drop-in — the current
snapshot only contains the 22 pinned tasks' build images, so the disk image is the real
blocker. Read the "Required sandbox disk image" section before running anything.

## Why

`run_modal_pinned_tasks.sh` already runs the pinned 22 tasks sequentially through
`modal_sandbox_runner.py --mode patch-only`, restoring each trial from the baked Modal
filesystem snapshot (`results/modal_snapshot.json`). The 920-task master list now exists
locally (`reference/cybergym_tasks.master.txt`, committed in `8fa7ac3`), so the natural next
question is "run all of them." Two things stand between here and that: the batch runner is
hardcoded to `txt/tasks.pinned.txt`, and — more importantly — the baked snapshot only holds
the 22 pinned tasks' 18 build images. The other ~900 tasks' images are **not** in it, so a
trial restored from today's snapshot would fail to build for any non-pinned task.

## Current state (verified 2026-09-23)

- `reference/cybergym_tasks.master.txt` — 920 task lines + a `# source_rev:` header. It parses
  cleanly through `common.Task.parse` / `load_tasks` (both skip the `#` header and blanks), so
  it is format-compatible with `pinned_task_paths()` and with any `--tasks-file` consumer.
- `run_modal_pinned_tasks.sh` — reads `txt/tasks.pinned.txt` **hardcoded** on its last line
  (`done < txt/tasks.pinned.txt`); no `--tasks-file` argument. Loops
  `.venv/bin/python modal_sandbox_runner.py --task "$task" --mode patch-only` sequentially,
  `set -uo pipefail` with per-task `|| true`, writing `results/modal_trials/<safe>.json` +
  `.log`. `safe="${task//\//_}"`.
- `modal_sandbox_runner.py` — `--task` (required), `--mode {patch-only,e2e}`,
  `--provisioning {snapshot,cold}` (default `snapshot`), `--manifest` (default
  `results/modal_snapshot.json`), `--litellm-secret`, `--output`, `--run-id`. No
  `--budget`/`--timeout`/`--k`. Restores each trial from `manifest["snapshot_image_id"]`.
- `modal_snapshot_build.py` — bakes the snapshot; **accepts `--tasks-file`** (default
  `txt/tasks.pinned.txt`). The current baked snapshot = 22 tasks / 18 images = **111.2 GB of
  Docker state + 4.2 GB dataset ≈ 115 GB**, and a per-trial restore reports **~119 GiB in use**.
- Modal VM Sandbox disk cap is **512 GiB** (vs Daytona's 10 GiB), which is why CyberGym runs on
  Modal at all.

## Required sandbox disk image

**The disk image is the Modal filesystem snapshot baked by `modal_snapshot_build.py`, whose
verified Image ID lives in `results/modal_snapshot.json`.** `modal_sandbox_runner.py` restores
every `--provisioning snapshot` trial from exactly that Image ID.

**Today's snapshot does not cover the 920 tasks** — it was baked from `txt/tasks.pinned.txt`
(22 tasks, 18 images). To run the full master list you must **re-bake the snapshot from the
master file**:

```
python modal_snapshot_build.py --tasks-file reference/cybergym_tasks.master.txt \
    --output results/modal_snapshot.master.json
```

(A `--limit` bake is forced to a non-canonical `--output`; a full bake to the canonical
`results/modal_snapshot.json` would overwrite the pinned snapshot — decide deliberately which
manifest you want, and point the runner at it with `--manifest`.)

**Open risk — this bake may not fit 512 GiB, and its size is unmeasured.** 22 tasks/18 images
= ~115 GB. The 920 tasks span far more projects and distinct build images; images are shared
within a project/base-builder, so the cost scales with the number of *distinct* images, not the
920 tasks. **Do not assume it fits and do not invent a figure** — measure it first:

1. Enumerate the distinct build images the 920 tasks resolve to (the per-task image mapping the
   builder already reads; see `snapshot_build.py`'s `validator_images` / `default_image` path and
   `common.py`). 
2. Sum their pulled sizes. If the total + dataset + working headroom exceeds ~512 GiB, a single
   snapshot is not viable and the plan must change (e.g. shard the master list into several
   snapshots by image set, or pull images per-trial cold instead of baking them).

Record the measured distinct-image count and total GB in `FINDINGS.md` before baking — that
number is the actual answer to "what disk image is needed," and it is currently unknown.

## Bash commands

### 0. Prereqs (same as the pinned path)
- WSL terminal at repo root, the repo `.venv` set up, `LITELLM_BASE_URL` in `.env.local`.
- Modal auth (`python -m modal setup`) and the two named Modal Secrets:
  `gymsiege-huggingface` (supplies `HF_TOKEN`, for the gated dataset during the bake) and
  `gymsiege-litellm` (supplies `LITELLM_MASTER_KEY`, sourced from `LITELLM_SECRET_KEY`). See
  README "Run all 22 pinned tasks on Modal" for the exact `modal secret create` lines. **Never
  print the tokens.**

### 1. Bake the master-list snapshot (only after the size check above)
```bash
python modal_snapshot_build.py --tasks-file reference/cybergym_tasks.master.txt \
    --output results/modal_snapshot.master.json
```
Writes the verified Image ID to `results/modal_snapshot.master.json`.

### 2. Run the 920 tasks sequentially
The pinned batch script hardcodes `txt/tasks.pinned.txt`, so make a master variant rather than
editing the pinned one in place. Copy `run_modal_pinned_tasks.sh` to
`run_modal_master_tasks.sh` and change **only** the input file and add the manifest flag:
```bash
# in the copy:
#   done < reference/cybergym_tasks.master.txt      # was txt/tasks.pinned.txt
#   ... modal_sandbox_runner.py --task "$task" --mode patch-only \
#         --manifest results/modal_snapshot.master.json \
#         --output "results/modal_trials/${safe}.json" ...
GYMSIEGE_RUN_ID="gymsiege-master-$(date -u +%Y%m%dT%H%M%SZ)" bash run_modal_master_tasks.sh
```
Or, without a script, the equivalent inline loop:
```bash
mkdir -p results/modal_trials
run_id="gymsiege-master-$(date -u +%Y%m%dT%H%M%SZ)"
grep -vE '^\s*#|^\s*$' reference/cybergym_tasks.master.txt | while IFS= read -r task; do
  task="$(echo "${task%%#*}" | xargs)"; [ -z "$task" ] && continue
  safe="${task//\//_}"
  echo "=== $task ==="
  .venv/bin/python modal_sandbox_runner.py --task "$task" --mode patch-only \
    --manifest results/modal_snapshot.master.json \
    --output "results/modal_trials/${safe}.json" --run-id "$run_id" \
    2>&1 | tee "results/modal_trials/${safe}.log" || true
done
```

### 3. One task, for a smoke test first
```bash
PYTHONUNBUFFERED=1 .venv/bin/python modal_sandbox_runner.py \
    --task arrow/arvo_41221 --mode patch-only \
    --manifest results/modal_snapshot.master.json \
    --output results/modal_trials/arrow_arvo_41221.json \
    2>&1 | tee results/modal_trials/arrow_arvo_41221.log
```

## Guardrails

- **Real cost / time.** Each task = one real Modal sandbox + real LiteLLM/LLM spend, serial.
  The pinned 22 cost ~$1.28 over ~9.0 h wall. 920 tasks is ~42x the task count — extrapolate
  **only** as a rough order of magnitude ($ tens, days of wall time), and do a small
  `--limit`/subset run to get a real per-task rate before committing to the full sweep. Don't
  quote a precise total you haven't measured.
- **Snapshot manifest.** A full-master bake to the canonical `results/modal_snapshot.json`
  overwrites the pinned snapshot the 22-task path depends on. Prefer a distinct manifest
  (`results/modal_snapshot.master.json`) and `--manifest` on the runner.
- **`results/modal_trials/` is overwritten in place.** The pinned run and a master run share the
  same output dir and `<safe>.json` naming; commit or copy anything you want to keep first, and
  note that pinned-task slots would be overwritten by the master run.
- **Known per-task caveat.** Trials are currently expected to end `oracle_unavailable` during
  isolated re-detonation (`codex-task-open-issues.md#5`) even when the agent phase succeeds —
  a separate known issue, not a sign the runner is broken.
- **`detect_leaks=0`** stays in effect (0 LeakSanitizer tasks in the 920 anyway; see FINDINGS #23).
- Cite what you measure; do not invent task counts, image sizes, or costs. Keep the test suite
  green (`python -m unittest discover -s tests`); the langfuse/CRLF-path failures already present
  are pre-existing and unrelated.

## Acceptance

- A measured distinct-image count + total GB for the 920 tasks recorded in `FINDINGS.md`, with a
  verdict on whether one 512 GiB snapshot fits or the list must be sharded.
- A master-list snapshot baked (or a documented sharding plan if it doesn't fit), Image ID in a
  non-canonical manifest.
- `run_modal_master_tasks.sh` (or the inline loop) runs the master list; results land in
  `results/modal_trials/`; the pinned snapshot/manifest is left intact.
- A short note on measured per-task rate from a subset run before any full sweep.

## Key references

- `run_modal_pinned_tasks.sh` — the pinned batch loop this scales up from.
- `modal_sandbox_runner.py` — `--task`/`--mode`/`--provisioning`/`--manifest`; restores from
  `manifest["snapshot_image_id"]`.
- `modal_snapshot_build.py` — the bake; `--tasks-file`, `--limit`, `--output`; 22-task/18-image
  = ~115 GB baseline; 512 GiB VM cap.
- `common.py:196` (`Task.parse`, skips `#`/blank), `common.py:209` (`load_tasks`),
  `snapshot_build.py:514` (`pinned_task_paths`).
- README "Run all 22 pinned tasks on Modal" + the storage-ceiling section — secret setup,
  measured pinned cost/time, and the Modal-vs-Daytona disk rationale.
- `reference/cybergym_tasks.master.txt` — the 920-task input; `FINDINGS.md` #23 — the sanitizer
  split and `detect_leaks=0` follow-up.
