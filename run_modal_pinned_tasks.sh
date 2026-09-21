#!/usr/bin/env bash
# GYMSIEGE Modal pinned-task run — invokes modal_sandbox_runner.py once per
# task in txt/tasks.pinned.txt (patch-only mode), sequentially. This is a
# standalone loop, not orchestrator.py: modal_sandbox_runner.py has no
# --tasks-file/--k/parallelism of its own yet (see README.md's Modal trial
# adapter section).
#
# Real cost warning: this creates one real Modal sandbox and spends real
# LiteLLM/LLM budget per task, sequentially, over the full pinned set (22
# tasks as of 2026-09-15) -- expect well over an hour and real money, not a
# dry run. Every task is also currently expected to end oracle_unavailable
# during the isolated re-detonation (codex-task-open-issues.md#5) even when
# the agent phase itself succeeds -- that is a known, separate issue, not a
# sign this script is broken.
#
# Requires the .venv this repo already uses (see README.md#local-setup-and-credentials)
# and a working LITELLM_BASE_URL in .env.local -- run from a WSL terminal.
set -uo pipefail  # deliberately not -e: one task's failing exit code must
                  # not abort the run for the rest (see below)

cd "$(dirname "$0")"

mkdir -p results/modal_trials
run_id="${GYMSIEGE_RUN_ID:-gymsiege-modal-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

while IFS= read -r line; do
  task="${line%%#*}"                       # strip trailing "# note"
  task="$(echo "$task" | xargs)"           # trim whitespace
  [ -z "$task" ] && continue                # skip blank/comment-only lines
  safe="${task//\//_}"
  echo "=== $task ==="
  # `|| true`: modal_sandbox_runner.py exits 1 on error/oracle_unavailable,
  # which under `pipefail` would otherwise propagate out of the pipeline --
  # every task must still get its own attempt regardless of earlier results.
  .venv/bin/python modal_sandbox_runner.py --task "$task" --mode patch-only \
    --output "results/modal_trials/${safe}.json" \
    --run-id "$run_id" \
    2>&1 | tee "results/modal_trials/${safe}.log" || true
done < txt/tasks.pinned.txt

echo
echo "=== done -- per-task results in results/modal_trials/, logs alongside ==="
