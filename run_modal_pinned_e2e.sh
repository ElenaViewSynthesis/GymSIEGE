#!/usr/bin/env bash
# Run the pinned CyberGym task set sequentially in end-to-end mode.
#
# WARNING: this creates real Modal sandboxes and spends real LLM budget.
# Each invocation creates a new run ID and an isolated results directory, so
# results from earlier runs are never silently mixed into the new batch.
set -uo pipefail

cd "$(dirname "$0")"

if [[ ! -f .venv/bin/activate || ! -x .venv/bin/python ]]; then
  echo "missing repository virtual environment: .venv" >&2
  exit 2
fi
if [[ ! -f .env.local ]]; then
  echo "missing required credentials file: .env.local" >&2
  exit 2
fi
if [[ ! -f txt/tasks.pinned.txt ]]; then
  echo "missing task list: txt/tasks.pinned.txt" >&2
  exit 2
fi

# shellcheck disable=SC1091
source .venv/bin/activate
set -a
# shellcheck disable=SC1091
source .env.local
set +a

python_bin="$PWD/.venv/bin/python"
run_id="gymsiege-e1-e2e-$(date -u +%Y%m%dT%H%M%SZ)-$$"
output_dir="results/modal_trials_e2e/$run_id"

mkdir -p "$output_dir"
printf '%s\n' "$run_id" > "$output_dir/RUN_ID"

echo "Run ID: $run_id"
echo "Python: $python_bin"
echo "Output: $output_dir"

while IFS= read -r line; do
  task="${line%%#*}"
  task="$(printf '%s' "$task" | xargs)"
  [[ -z "$task" ]] && continue

  safe="${task//\//_}"
  result="$output_dir/${safe}.json"
  log="$output_dir/${safe}.log"

  if [[ -s "$result" ]]; then
    echo "=== skip $task (already has a result)"
    continue
  fi

  echo "=== $task  $(date -u +%FT%TZ) ==="

  "$python_bin" modal_sandbox_runner.py \
    --task "$task" \
    --mode e2e \
    --trial 1 \
    --litellm-model-id gpt-5.6-luna \
    --output "$result" \
    --run-id "$run_id" \
    2>&1 | tee "$log"

  runner_status=${PIPESTATUS[0]}
  if (( runner_status != 0 )); then
    echo "=== runner failed for $task (exit $runner_status)" | tee -a "$log"
  fi
done < txt/tasks.pinned.txt 2>&1 | tee -a "$output_dir/_loop.log"

echo "=== run complete: $run_id ==="
echo "Results and logs: $output_dir"
