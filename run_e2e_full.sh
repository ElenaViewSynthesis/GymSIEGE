#!/usr/bin/env bash
# Start the PAID CyberGym E2E full continuation (the remaining cohort cells)
# after the smoke result has been reviewed.
#
#   bash run_e2e_full.sh <approved-smoke-sha256>          # asks before the paid step
#   bash run_e2e_full.sh <approved-smoke-sha256> --yes    # no prompt
#
# The hash must be the sha256sum of the reviewed published smoke result; the
# runner refuses the full phase if it differs. Run run_e2e_smoke.sh first: it
# repairs the gymsiege-litellm secret this run also depends on.
#
# Outside tmux it relaunches itself inside a tmux session named "e2e-full"
# (detach: Ctrl+b then d; reattach: tmux attach -t e2e-full). If interrupted,
# rerun the same command: published cells are skipped.
#
# Never edit this file while it is running (bash reads scripts by byte offset).
set -eo pipefail

cd "$(dirname "$0")"
repo="$PWD"
approved="${1:-}"
assume_yes=0
[[ "${2:-}" == "--yes" ]] && assume_yes=1

if [[ ! "$approved" =~ ^[0-9a-f]{64}$ ]]; then
  echo "usage: bash run_e2e_full.sh <approved-smoke-sha256> [--yes]" >&2
  exit 2
fi

if [[ -z "${TMUX:-}" ]] && command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t e2e-full 2>/dev/null; then
    echo "tmux session 'e2e-full' already exists; attach with: tmux attach -t e2e-full" >&2
    exit 2
  fi
  exec tmux new-session -s e2e-full "bash '$repo/run_e2e_full.sh' $approved ${2:-}; exec bash"
fi

# One batch at a time: a second runner would race the smoke/full cells.
if pgrep -f 'run_modal_repeats.py' >/dev/null; then
  echo "error: a run_modal_repeats.py process is already running; wait for it to finish" >&2
  pgrep -af 'run_modal_repeats.py' >&2
  exit 2
fi

manifest="reference/cybergym_e2e_paper_cohort.v1.json"
for f in .venv/bin/activate .env.local "$manifest"; do
  [[ -f "$f" ]] || { echo "missing: $f" >&2; exit 2; }
done

# shellcheck disable=SC1091
source .venv/bin/activate
export PYDANTIC_DISABLE_PLUGINS=1
set -a
# shellcheck disable=SC1091
source .env.local
set +a
: "${LITELLM_BASE_URL:?LITELLM_BASE_URL is not set in .env.local}"
gw="${LITELLM_BASE_URL%/}"
gw="${gw%/v1}"

batch="$(python -c "import json;print(json.load(open('$manifest'))['batch_id'])")"
output_root="$(python -c "import json;print(json.load(open('$manifest'))['output_root'])")"
smoke_task="$(python -c "import json;print(json.load(open('$manifest'))['smoke_task'])")"
batch_dir="$output_root/$batch"
smoke_result="$batch_dir/published-results/${smoke_task//\//_}__trial-1.json"

echo "== 1/3 smoke result"
[[ -f "$smoke_result" ]] || { echo "error: no published smoke result at $smoke_result" >&2; exit 1; }
actual="$(sha256sum "$smoke_result" | cut -d' ' -f1)"
[[ "$actual" == "$approved" ]] || { echo "error: smoke hash is $actual, not the approved $approved" >&2; exit 1; }
echo "   $smoke_result matches the approved hash"

echo "== 2/3 gateway is up through the public URL (a dead ngrok tunnel would turn every cell into a fake no_poc)"
for candidate in LITELLM_SECRET_KEY LITELLM_MASTER_KEY; do
  [[ -n "${!candidate:-}" ]] || continue
  if code="$(printf 'Authorization: Bearer %s\n' "${!candidate}" |
      curl -sS -o /dev/null -w '%{http_code}' -H @- "$gw/v1/models")" && [[ "$code" == "200" ]]; then
    echo "   gateway OK ($candidate, HTTP 200)"
    gateway_ok=1
    break
  fi
done
[[ "${gateway_ok:-0}" == "1" ]] || { echo "error: gateway $gw/v1/models is not answering 200; start the gateway and ngrok first" >&2; exit 1; }

echo "== 3/3 read-only plan"
plan="$(bash run_modal_pinned_e2e.sh --phase full)"
grep -v '^  \(planned\|existing\)' <<<"$plan"
planned="$(grep -c '^  planned' <<<"$plan" || true)"
existing="$(grep -c '^  existing' <<<"$plan" || true)"
echo "   $existing already published, $planned to run"
[[ "$planned" -gt 0 ]] || { echo "nothing left to run"; exit 0; }

if (( ! assume_yes )); then
  read -r -p "Start the PAID full run of $planned cells now? Type yes: " answer
  [[ "$answer" == "yes" ]] || { echo "not started"; exit 0; }
fi
log="$output_root/full-$batch-$(date -u +%Y%m%dT%H%M%SZ).log"
set +e
bash run_modal_pinned_e2e.sh --phase full --execute --approved-smoke-sha256 "$approved" 2>&1 | tee "$log"
full_status=${PIPESTATUS[0]}
set -e
echo "full-run exit: $full_status   log: $log"

echo "== summary"
python - "$batch_dir" <<'PY'
import collections, json, pathlib, sys
batch = pathlib.Path(sys.argv[1])
published = sorted((batch / "published-results").glob("*.json"))
counts = collections.Counter(json.loads(p.read_text())["status"] for p in published)
cost = sum((json.loads(p.read_text()).get("solver_cost_usd") or 0) for p in published)
print(f"  published: {len(published)}  {dict(counts)}")
print(f"  solver cost (published cells): ${cost:.2f}")
ledger = batch / "_meta" / "excluded_trials.jsonl"
rows = [l for l in ledger.read_text().splitlines() if l.strip()] if ledger.exists() else []
print(f"  excluded attempts: {len(rows)}")
PY
