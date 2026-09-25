#!/usr/bin/env bash
# Run one preplanned CyberGym master shard. Set GYMSIEGE_MASTER_SHARD=01..47.
# Each shard uses its own snapshot manifest and results directory so parallel
# shard processes cannot overwrite the pinned-22 outputs or one another.
set -uo pipefail

cd "$(dirname "$0")"

shard="${GYMSIEGE_MASTER_SHARD:-}"
if [[ ! "$shard" =~ ^(0[1-9]|[1-3][0-9]|4[0-7])$ ]]; then
  echo "set GYMSIEGE_MASTER_SHARD to 01..47" >&2
  exit 2
fi

tasks_file="txt/modal_master_shards/shard-${shard}.txt"
manifest="results/modal_snapshot.master-shard-${shard}.json"
output_dir="results/modal_trials/master-shard-${shard}"
if [ ! -f "$manifest" ]; then
  echo "missing $manifest; bake this shard before running trials" >&2
  exit 2
fi

mkdir -p "$output_dir"
run_id="${GYMSIEGE_RUN_ID:-gymsiege-master-${shard}-$(date -u +%Y%m%dT%H%M%SZ)-$$}"

while IFS= read -r line; do
  task="${line%%#*}"
  task="$(echo "$task" | xargs)"
  [ -z "$task" ] && continue
  safe="${task//\//_}"
  echo "=== shard ${shard}: ${task} ==="
  .venv/bin/python modal_sandbox_runner.py --task "$task" --mode patch-only \
    --manifest "$manifest" \
    --output "${output_dir}/${safe}.json" \
    --run-id "$run_id" \
    2>&1 | tee "${output_dir}/${safe}.log" || true
done < "$tasks_file"

echo "=== shard ${shard} done; results in ${output_dir}/ ==="
