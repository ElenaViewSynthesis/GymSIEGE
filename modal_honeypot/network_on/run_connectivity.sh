#!/usr/bin/env bash
# Network-on positive control: run the 20 network-off probes on a host WITH open
# egress and assert every one reaches its target. The mirror of the network-off
# containment suite -- same probe, same corpus, opposite expectation.
#
# "Reached" = a clean connect ("allowed") OR an HTTP response came back
# ("blocked" + error_type HTTPError, e.g. NOF-015's HTTP 421 from api.openai.com).
# Only a timeout / refused / DNS failure counts as unreachable. Exits non-zero
# unless all 20 probes reach their target. Free: no Modal, Langfuse, or secrets.
set -uo pipefail

root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel 2>/dev/null || echo .)
probe="$root/modal_honeypot/network_off/probe.py"
corpus="$root/modal_honeypot/network_off/network_off_cases_20.jsonl"

pass=0 total=0 fails=()
while IFS= read -r line; do
  line=${line%$'\r'}                       # tolerate a CRLF checkout
  [ -z "$line" ] && continue
  total=$((total+1)); id=$(jq -r .id <<<"$line")
  mapfile -t args < <(jq -r '.input.argv[2:][]' <<<"$line" | tr -d '\r')
  out=$(python3 "$probe" "${args[@]}" 2>&1)
  res=$(jq -r '.network_result // "err"' <<<"$out" 2>/dev/null || echo err)
  etype=$(jq -r '.error_type // "-"' <<<"$out" 2>/dev/null || echo -)
  if [ "$res" = allowed ] || { [ "$res" = blocked ] && [ "$etype" = HTTPError ]; }; then
    pass=$((pass+1)); echo "PASS $id ${args[*]} ($res)"
  else
    fails+=("$id"); echo "FAIL $id ${args[*]} -> $res"
  fi
done < "$corpus"

echo "== $pass/$total reached =="
if [ "$total" -ne 20 ] || [ "$pass" -ne 20 ]; then
  echo "FAILED: expected 20/20 with the network on; failures: ${fails[*]:-none}" >&2
  exit 1
fi
echo "OK: all 20 probes reached their target (network on)."
