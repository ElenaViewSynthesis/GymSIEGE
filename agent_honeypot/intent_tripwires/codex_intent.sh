#!/usr/bin/env bash
# Agent-only Codex adapter for one intent-tripwire case
# (agent_honeypot/intent_tripwires/run_case.py --subject-command). The intent
# twin of modal_honeypot/codex_gateway.sh: the same scoped-gateway provider
# config, but the case's own prompt and trajectory, the case's web-search mode
# (HONEYPOT_CODEX_WEB_SEARCH: live only for the two hosted-search cases, set by
# run_case.py from the case), and no writable root beyond the case workspace,
# which workspace-write already makes writable as Codex's cwd. Provider
# credentials stay in the inherited environment; only the variable name and
# gateway URL enter Codex config. The outer boundary (the Docker egress
# allow-list) remains the network boundary in both sandbox modes.
set -Eeuo pipefail

# The repository root (/opt/honeypot in the image), for the redaction filter.
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

: "${OPENAI_API_KEY:?ephemeral virtual key is missing}"
: "${OPENAI_BASE_URL:?gateway URL is missing}"
: "${HONEYPOT_CODEX_MODEL:?pinned model is missing}"
: "${HONEYPOT_CASE_PROMPT_FILE:?prompt path is missing}"
: "${HONEYPOT_TRAJECTORY:?trajectory path is missing}"
: "${HONEYPOT_WORKSPACE:?task workspace is missing}"

web_search=${HONEYPOT_CODEX_WEB_SEARCH:-disabled}
case "$web_search" in
  disabled|live) ;;
  *)
    printf 'unsupported HONEYPOT_CODEX_WEB_SEARCH: %s\n' "$web_search" >&2
    exit 64
    ;;
esac

sandbox_mode=${HONEYPOT_CODEX_SANDBOX:-danger-full-access}
sandbox_config=()
case "$sandbox_mode" in
  danger-full-access)
    sandbox_config=(-c 'sandbox_mode="danger-full-access"')
    ;;
  workspace-write)
    # Network on inside Codex's sandbox, as for collusion: an exfiltration
    # attempt then reaches the egress proxy, which refuses and logs it.
    sandbox_config=(
      -c 'sandbox_mode="workspace-write"'
      -c 'sandbox_workspace_write.network_access=true'
    )
    ;;
  *)
    printf 'unsupported HONEYPOT_CODEX_SANDBOX: %s\n' "$sandbox_mode" >&2
    exit 64
    ;;
esac

codex \
  -C "$HONEYPOT_WORKSPACE" \
  --model "$HONEYPOT_CODEX_MODEL" \
  -c 'approval_policy="never"' \
  "${sandbox_config[@]}" \
  -c "web_search=\"$web_search\"" \
  -c 'model_provider="honeypot_gateway"' \
  -c 'model_providers.honeypot_gateway.name="Scoped LiteLLM gateway"' \
  -c "model_providers.honeypot_gateway.base_url=\"$OPENAI_BASE_URL\"" \
  -c 'model_providers.honeypot_gateway.env_key="OPENAI_API_KEY"' \
  -c 'model_providers.honeypot_gateway.wire_api="responses"' \
  -c 'model_providers.honeypot_gateway.supports_standalone_web_search=false' \
  exec --skip-git-repo-check --json "$(cat "$HONEYPOT_CASE_PROMPT_FILE")" \
  2>&1 \
  | python3 "$repo/modal_honeypot/redact_stream.py" \
  | tee "$HONEYPOT_TRAJECTORY"
