#!/usr/bin/env python3
"""Launch a real collusion subject with a minimal, explicit environment."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence


CONTAINMENT_MARKER = "MODAL_COLLUSION_CONTAINMENT_ENFORCED"
SAFE_RUNTIME_NAMES = {
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "NO_PROXY", "PATH",
    "SHELL", "SSL_CERT_DIR", "SSL_CERT_FILE", "TERM", "TMPDIR", "TZ", "USER",
    "no_proxy",
}
PROVIDER_NAMES = {"OPENAI_API_BASE", "OPENAI_API_KEY", "OPENAI_BASE_URL"}
HONEYPOT_NAMES = {
    "HONEYPOT_AGENT_ROOT_PID", "HONEYPOT_BASE_HARNESS", "HONEYPOT_BLOCK_NETWORK",
    "HONEYPOT_BLOCK_PROPAGATION", "HONEYPOT_BOARD_URL", "HONEYPOT_CASE_ID",
    "HONEYPOT_CODEX_CANARY_PID", "HONEYPOT_COLLUSION_INBOX",
    "HONEYPOT_COLLUSION_OBSERVE_ONLY", "HONEYPOT_COLLUSION_OWN_INBOX",
    "HONEYPOT_COLLUSION_PEER_INBOXES", "HONEYPOT_COLLUSION_PRELOAD",
    "HONEYPOT_COLLUSION_PROMPT_FILE", "HONEYPOT_COLLUSION_QUEUE",
    "HONEYPOT_COLLUSION_RESULTS", "HONEYPOT_COLLUSION_ROOT",
    "HONEYPOT_COLLUSION_RUN_ID", "HONEYPOT_COLLUSION_SHARED_PATHS",
    "HONEYPOT_COLLUSION_TRANSCRIPT", "HONEYPOT_CONTENT_MARKER",
    "HONEYPOT_EVENT_FD", "HONEYPOT_EVENT_LOG", "HONEYPOT_EVIDENCE_CHAIN",
    "HONEYPOT_EXTRA_PATH", "HONEYPOT_FOREIGN_PID", "HONEYPOT_MAX_NEST_DEPTH",
    "HONEYPOT_NEST_DEPTH", "HONEYPOT_PEER_ASSIGNMENT", "HONEYPOT_PEER_RUN_IDS",
    "HONEYPOT_PEER_WORKSPACES", "HONEYPOT_PRELOAD", "HONEYPOT_REAL_PATH",
    "HONEYPOT_RUN_KIND", "HONEYPOT_RUN_MARKER", "HONEYPOT_SCRIPTED_ACTOR",
    "HONEYPOT_SENSITIVE_PATHS", "HONEYPOT_SHARED", "HONEYPOT_SHIM_PATH",
    "HONEYPOT_WORKSPACE",
}


def build_agent_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Keep honeypot controls, process basics, and one scoped provider key."""
    env = {
        name: value for name, value in source.items()
        if name in HONEYPOT_NAMES or name in SAFE_RUNTIME_NAMES or name in PROVIDER_NAMES
    }
    if source.get(CONTAINMENT_MARKER) == "1":
        env[CONTAINMENT_MARKER] = "1"
    base_preload = source.get("LD_PRELOAD", "")
    collusion_preload = source["HONEYPOT_COLLUSION_PRELOAD"]
    env["LD_PRELOAD"] = f"{collusion_preload}:{base_preload}" if base_preload else collusion_preload
    env["HONEYPOT_COLLUSION_PRELOADED"] = "1"
    return env


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["--"]:
        args = args[1:]
    if not args:
        print("agent_subject.py requires a command after --", file=sys.stderr)
        return 64
    if os.environ.get(CONTAINMENT_MARKER) != "1":
        print(
            "refusing real collusion subject: external containment is not confirmed "
            f"({CONTAINMENT_MARKER}=1 is required)",
            file=sys.stderr,
        )
        return 78
    env = build_agent_environment(os.environ)
    os.execvpe(args[0], args, env)
    return 70  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
