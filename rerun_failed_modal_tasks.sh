#!/usr/bin/env bash
# Rerun the Modal pinned tasks that failed on 2026-10-11 with a Modal
# control-plane TimeoutError (DNS "Temporary failure in name resolution" at
# modal.App.lookup). Those tasks never started a sandbox and wrote no result
# JSON, so they must be re-run. ghostscript/arvo_45320 is intentionally NOT in
# this list -- it connected, ran to completion, and wrote a real result
# (status=failed, a genuine model miss), so it does not need rerunning.
#
# Same contract as run_modal_pinned_tasks.sh: one real Modal sandbox + real
# LLM budget per task, patch-only, sequential, writing results/modal_trials/
# <safe>.json (and a <safe>.log beside it). Run from a WSL terminal.
set -uo pipefail  # not -e: a task's non-zero exit must not abort the rest

cd "$(dirname "$0")"

# Repo venv + local credentials (.env.local: MODAL_TOKEN_*, LITELLM_BASE_URL,
# LANGFUSE_*, ...). Without these modal_sandbox_runner.py dies at
# modal.App.lookup with AuthError: Token missing.
source .venv/bin/activate
set -a; source .env.local; set +a

mkdir -p results/modal_trials
run_id="${GYMSIEGE_RUN_ID:-gymsiege-modal-rerun-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"   # per-task attempts to ride out a network blip
RETRY_SLEEP="${RETRY_SLEEP:-20}"    # base backoff seconds (grows per attempt)

# The tasks that failed with the network TimeoutError, in original run order.
tasks=(
  "ffmpeg/oss-fuzz_385167047"
  "arrow/arvo_41221"
  "libtpms/oss-fuzz_42537128"
  "mruby/arvo_19902"
  "binutils/arvo_61822"
  "ffmpeg/oss-fuzz_436997807"
  "mruby/arvo_53183"
  "net-snmp/arvo_52465"
  "libxaac/arvo_62261"
  "wireshark/arvo_3408"
  "libdwarf/arvo_56454"
  "opensc/oss-fuzz_448717172"
  "p11-kit/arvo_31276"
  "unit/oss-fuzz_42536363"
  "upx/oss-fuzz_380327173"
)

# Preflight: the original failure was DNS, not Modal being down. If name
# resolution is still broken, every task would just burn a ~2-min timeout --
# fail fast instead of spending 15 of them.
if ! getent hosts api.modal.com >/dev/null 2>&1; then
  echo "!!! cannot resolve api.modal.com -- DNS/network still down; not starting." >&2
  echo "    (same failure class as the original run; fix WSL networking first)" >&2
  exit 1
fi

solved=0
unsolved=()
for task in "${tasks[@]}"; do
  safe="${task//\//_}"
  out="results/modal_trials/${safe}.json"
  echo "=== $task ==="
  wrote=0
  for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
    start=$(date +%s)
    # `|| true`: a real error / oracle_unavailable exits 1, which under
    # pipefail would otherwise abort the loop. We decide retry below from
    # whether a fresh result JSON was actually written, not from exit code --
    # a completed run that scored "failed" also exits 1 and must NOT be retried.
    .venv/bin/python modal_sandbox_runner.py --task "$task" --mode patch-only \
      --output "$out" \
      --run-id "$run_id" \
      2>&1 | tee "results/modal_trials/${safe}.log" || true
    # A result written at/after this attempt's start = the run reached result
    # collection (any status). No fresh file = it crashed before writing
    # (the network-timeout case) -> retry.
    if [ -f "$out" ] && [ "$(stat -c %Y "$out" 2>/dev/null || echo 0)" -ge "$start" ]; then
      wrote=1
      break
    fi
    if [ "$attempt" -lt "$MAX_ATTEMPTS" ]; then
      sleep_for=$(( RETRY_SLEEP * attempt ))
      echo "--- $task: no result written (attempt $attempt/$MAX_ATTEMPTS, likely network); retrying in ${sleep_for}s" >&2
      sleep "$sleep_for"
    fi
  done
  if [ "$wrote" -eq 1 ]; then
    solved=$(( solved + 1 ))
  else
    unsolved+=("$task")
    echo "!!! $task: still no result after $MAX_ATTEMPTS attempts" >&2
  fi
done

echo
echo "=== done -- ${solved}/${#tasks[@]} tasks produced a result in results/modal_trials/ ==="
if [ "${#unsolved[@]}" -gt 0 ]; then
  echo "=== still failed (${#unsolved[@]}): ${unsolved[*]} ===" >&2
  exit 1
fi
