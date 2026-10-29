#!/usr/bin/env bash
# Agent-only Codex adapter. Provider credentials stay in the inherited Secret
# environment; only the variable name and gateway URL enter Codex config.
set -Eeuo pipefail

: "${OPENAI_API_KEY:?ephemeral virtual key is missing}"
: "${OPENAI_BASE_URL:?gateway URL is missing}"
: "${HONEYPOT_CODEX_MODEL:?pinned model is missing}"
: "${HONEYPOT_COLLUSION_PROMPT_FILE:?prompt path is missing}"
: "${HONEYPOT_COLLUSION_TRANSCRIPT:?transcript path is missing}"
: "${HONEYPOT_WORKSPACE:?task workspace is missing}"

# -C: the agent works in its own task workspace. Without it Codex inherits the
# harness's cwd (/opt/honeypot) and treats the honeypot source tree as its
# project, as the first real-agent pilots did.
codex \
  -C "$HONEYPOT_WORKSPACE" \
  --model "$HONEYPOT_CODEX_MODEL" \
  -c 'approval_policy="never"' \
  -c 'sandbox_mode="danger-full-access"' \
  -c 'web_search="disabled"' \
  -c 'model_provider="honeypot_gateway"' \
  -c 'model_providers.honeypot_gateway.name="Scoped LiteLLM gateway"' \
  -c "model_providers.honeypot_gateway.base_url=\"$OPENAI_BASE_URL\"" \
  -c 'model_providers.honeypot_gateway.env_key="OPENAI_API_KEY"' \
  -c 'model_providers.honeypot_gateway.wire_api="responses"' \
  -c 'model_providers.honeypot_gateway.supports_standalone_web_search=false' \
  exec --skip-git-repo-check --json "$(cat "$HONEYPOT_COLLUSION_PROMPT_FILE")" \
  2>&1 \
  | python3 /opt/honeypot/modal_honeypot/redact_stream.py \
  | tee "$HONEYPOT_COLLUSION_TRANSCRIPT"
