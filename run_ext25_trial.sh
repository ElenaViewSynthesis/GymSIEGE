#!/usr/bin/env bash
# Run one trial of the extension cohort (cybergym-e2e-ext25-v1): the smoke cell,
# then the full trial gated on the smoke result's sha256. Paid (Modal + model).
#
#   bash run_ext25_trial.sh -k 1      # trial 1
#   bash run_ext25_trial.sh -k 2      # trial 2, after trial 1 finishes
#
# Run from WSL. Re-running the same trial is safe: published cells are skipped.
set -uo pipefail  # not -e: report and stop explicitly instead

usage() { echo "usage: bash $0 -k <1|2>" >&2; exit 2; }

K=""
while [ $# -gt 0 ]; do
  case "$1" in
    -k|--trial) K="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done
case "$K" in 1|2) ;; *) usage ;; esac

cd "$(dirname "$0")"
PY=".venv/bin/python"
MANIFEST="reference/cybergym-e2e-ext25-v1.t$K.json"
SMOKE="results/modal_trials_e2e/cybergym-e2e-ext25-v1-t$K/published-results/curl_arvo_66012__trial-$K.json"
export PYDANTIC_DISABLE_PLUGINS=1

# .env.defaults sets the EU Langfuse URL and the harness only fills *empty*
# variables from .env.local, so the US-region keys would be sent to the EU host
# (401, tracing disabled). A non-empty shell value wins, so export the local one.
LF_URL=$(grep -E '^\s*(export\s+)?LANGFUSE_BASE_URL=' .env.local 2>/dev/null | tail -1 | sed -E 's/^[^=]*=//; s/^"//; s/"$//')
[ -n "$LF_URL" ] && export LANGFUSE_BASE_URL="$LF_URL" LANGFUSE_HOST="$LF_URL"

[ -f "$MANIFEST" ] || { echo "missing $MANIFEST (run freeze_e2e_ext25.sh)" >&2; exit 1; }
echo "trial $K | HEAD $(git rev-parse --short HEAD) | manifest $MANIFEST"

# 1. smoke cell (curl/arvo_66012)
"$PY" run_modal_repeats.py --manifest "$MANIFEST" --phase smoke --execute \
  || { echo "smoke phase failed; not starting the full trial" >&2; exit 1; }
[ -f "$SMOKE" ] || { echo "smoke result not published: $SMOKE" >&2; exit 1; }

# 2. smoke outcome and its sha256, which approves the full run
python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print('smoke status',d['status'],'| agent',d.get('agent_success'),'| gt',d.get('gt_success'))" "$SMOKE"
SMOKE_SHA=$(sha256sum "$SMOKE" | cut -d' ' -f1)
echo "smoke sha256 $SMOKE_SHA"

# 3. full trial
"$PY" run_modal_repeats.py --manifest "$MANIFEST" --phase full --execute \
  --approved-smoke-sha256 "$SMOKE_SHA"
