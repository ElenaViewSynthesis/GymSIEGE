#!/usr/bin/env bash
# Agent-only Codex adapter. Provider credentials stay in the inherited Secret
# environment; only the variable name and gateway URL enter Codex config.
# HONEYPOT_CODEX_SANDBOX selects danger-full-access (the default and the v3
# setting) or workspace-write. The latter keeps reads unrestricted, enables
# network inside Codex's sandbox, and adds the planted channel paths supplied
# in HONEYPOT_CODEX_WRITABLE_ROOTS to the writable boundary. Modal's outbound
# allowlist remains the outer network boundary in both modes.
set -Eeuo pipefail

: "${OPENAI_API_KEY:?ephemeral virtual key is missing}"
: "${OPENAI_BASE_URL:?gateway URL is missing}"
: "${HONEYPOT_CODEX_MODEL:?pinned model is missing}"
: "${HONEYPOT_COLLUSION_PROMPT_FILE:?prompt path is missing}"
: "${HONEYPOT_COLLUSION_TRANSCRIPT:?transcript path is missing}"
: "${HONEYPOT_WORKSPACE:?task workspace is missing}"

sandbox_mode=${HONEYPOT_CODEX_SANDBOX:-danger-full-access}
sandbox_config=()
case "$sandbox_mode" in
  danger-full-access)
    sandbox_config=(-c 'sandbox_mode="danger-full-access"')
    ;;
  workspace-write)
    : "${HONEYPOT_CODEX_WRITABLE_ROOTS:?workspace-write roots are missing}"
    writable_roots=$(
      python3 - <<'PY'
import json
import os

roots = list(dict.fromkeys(os.environ["HONEYPOT_CODEX_WRITABLE_ROOTS"].split(":")))
if not roots or any(not root.startswith("/") for root in roots):
    raise SystemExit("workspace-write roots must be non-empty absolute paths")
print(json.dumps(roots, separators=(",", ":")))
PY
    )
    sandbox_config=(
      -c 'sandbox_mode="workspace-write"'
      -c 'sandbox_workspace_write.network_access=true'
      -c "sandbox_workspace_write.writable_roots=$writable_roots"
    )
    ;;
  *)
    printf 'unsupported HONEYPOT_CODEX_SANDBOX: %s\n' "$sandbox_mode" >&2
    exit 64
    ;;
esac

# -C: the agent works in its own task workspace. Without it Codex inherits the
# harness's cwd (/opt/honeypot) and treats the honeypot source tree as its
# project, as the first real-agent pilots did.
codex \
  -C "$HONEYPOT_WORKSPACE" \
  --model "$HONEYPOT_CODEX_MODEL" \
  -c 'approval_policy="never"' \
  "${sandbox_config[@]}" \
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
