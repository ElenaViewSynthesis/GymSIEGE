#!/usr/bin/env bash
# Repair the gymsiege-litellm Modal secret, verify the frozen E2E plan, and
# start the PAID CyberGym E2E smoke task (the manifest's smoke_task only).
#
#   bash run_e2e_smoke.sh          # asks before the paid step
#   bash run_e2e_smoke.sh --yes    # no prompt
#
# Outside tmux it relaunches itself inside a tmux session named "e2e", so the
# run survives a closed terminal (detach: Ctrl+b then d; reattach:
# tmux attach -t e2e).
#
# Why the secret step exists: inside each sandbox CyberGym mints its own
# per-trial gateway key with LITELLM_MASTER_KEY. ExploitBench scripts rewrite
# gymsiege-litellm with only OPENAI_API_KEY/OPENAI_API_BASE, which drops it,
# and every E2E attempt then dies in ~2 s with "LITELLM_MASTER_KEY is missing".
#
# Never edit this file while it is running (bash reads scripts by byte offset).
set -eo pipefail

cd "$(dirname "$0")"
repo="$PWD"
assume_yes=0
[[ "${1:-}" == "--yes" ]] && assume_yes=1

if [[ -z "${TMUX:-}" ]] && command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t e2e 2>/dev/null; then
    echo "tmux session 'e2e' already exists; attach with: tmux attach -t e2e" >&2
    exit 2
  fi
  # Keep a shell open after the script ends so the output stays readable.
  exec tmux new-session -s e2e "bash '$repo/run_e2e_smoke.sh' ${1:-}; exec bash"
fi

manifest="reference/cybergym_e2e_paper_cohort.v1.json"
for f in .venv/bin/activate .env.local "$manifest" CVE-bench/refresh_litellm_key.sh; do
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

echo "== 1/5 mint a budgeted virtual key (kept in the secret for ExploitBench)"
# shellcheck disable=SC1091
KEY_BUDGET="${KEY_BUDGET:-10}" source CVE-bench/refresh_litellm_key.sh

echo "== 2/5 find a credential that can mint per-trial keys (what the sandbox does)"
# Keys go to curl on stdin (-H @-), never on argv where ps could show them.
can_mint() {
  local cred="$1" resp key
  resp="$(printf 'Authorization: Bearer %s\n' "$cred" |
    curl -fsS -X POST "$gw/key/generate" -H @- \
      -H 'Content-Type: application/json' \
      -d '{"max_budget":0.01,"key_alias":"gymsiege-e2e-smoke-mintcheck"}')" || return 1
  key="$(jq -er '.key' <<<"$resp")" || return 1
  printf 'Authorization: Bearer %s\n' "$cred" |
    curl -fsS -X POST "$gw/key/delete" -H @- \
      -H 'Content-Type: application/json' \
      -d "{\"keys\":[\"$key\"]}" >/dev/null || echo "warn: test key was minted but not deleted" >&2
  return 0
}
mint_var=""
for candidate in LITELLM_SECRET_KEY LITELLM_MASTER_KEY; do
  if [[ -n "${!candidate:-}" ]] && can_mint "${!candidate}"; then
    mint_var="$candidate"
    break
  fi
  echo "   $candidate cannot mint (unset or rejected)"
done
[[ -n "$mint_var" ]] || { echo "error: no credential can mint keys at $gw; stopping before any paid step" >&2; exit 1; }
echo "   mint OK with $mint_var"

echo "== 3/5 recreate Modal secret gymsiege-litellm (values never echoed)"
secret_json="$(mktemp "${HOME}/.gymsiege-secret.XXXXXX.json")"
trap 'rm -f "$secret_json"' EXIT
chmod 600 "$secret_json"
MINT_CRED="${!mint_var}" GW="$gw" python - "$secret_json" <<'PY'
import json, os, sys
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump({
        "LITELLM_MASTER_KEY": os.environ["MINT_CRED"],
        "OPENAI_API_KEY": os.environ["OPENAI_API_KEY"],
        "OPENAI_API_BASE": os.environ["GW"],
    }, fh)
PY
modal secret create gymsiege-litellm --from-json "$secret_json" --force
rm -f "$secret_json"

echo "== 4/5 read-only plan"
plan="$(bash run_modal_pinned_e2e.sh --phase plan)"
grep -v '^  planned' <<<"$plan"
expected_batch="$(python -c "import json;print(json.load(open('$manifest'))['batch_id'])")"
output_root="$(python -c "import json;print(json.load(open('$manifest'))['output_root'])")"
smoke_task="$(python -c "import json;print(json.load(open('$manifest'))['smoke_task'])")"
planned="$(grep -c '^  planned' <<<"$plan" || true)"
grep -qx "batch: $expected_batch" <<<"$plan" || { echo "error: plan batch is not $expected_batch" >&2; exit 1; }
[[ "$planned" == "22" ]] || { echo "error: expected 22 planned cells, got $planned" >&2; exit 1; }
echo "   plan OK: batch $expected_batch, $planned planned cells"

echo "== 5/5 PAID smoke run: $smoke_task"
if (( ! assume_yes )); then
  read -r -p "Start the paid smoke run now? Type yes: " answer
  [[ "$answer" == "yes" ]] || { echo "not started"; exit 0; }
fi
log="$output_root/smoke-$expected_batch-$(date -u +%Y%m%dT%H%M%SZ).log"
set +e
bash run_modal_pinned_e2e.sh --phase smoke --execute 2>&1 | tee "$log"
smoke_status=${PIPESTATUS[0]}
set -e
echo "smoke exit: $smoke_status   log: $log"

batch_dir="$output_root/$expected_batch"
result="$batch_dir/published-results/${smoke_task//\//_}__trial-1.json"
echo "== review"
if [[ -f "$result" ]]; then
  python - "$result" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for k in ("status", "batch_id", "solver_cost_usd", "stage1", "stage2", "stage3",
          "stage4", "isolated_stage3", "isolated_stage4", "error"):
    print(f"  {k}: {d.get(k)}")
PY
  sha256sum "$result"
else
  echo "  no published smoke result (all attempts excluded)"
fi
echo "excluded_trials.jsonl:"
cat "$batch_dir/_meta/excluded_trials.jsonl" 2>/dev/null || true
