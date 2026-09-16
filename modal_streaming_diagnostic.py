#!/usr/bin/env python3
"""
Diagnose whether Modal's outbound_domain_allowlist/outbound_cidr_allowlist
networking -- used by every modal_sandbox_runner.py trial sandbox so the
later isolation-narrowing API (_experimental_set_outbound_network_policy)
can work -- is what breaks Codex's long-lived streaming LLM calls.

Why this is the leading hypothesis, not the tunnel: a real Codex trial's
streaming call to LITELLM_BASE_URL + "/responses" failed identically
("stream disconnected before completion") through two independent tunnel
technologies (a Cloudflare quick tunnel, then ngrok's free static domain).
Switching tunnel providers changed nothing. The one constant across both
failures is the Modal sandbox's own outbound networking config, since
Modal's domain-allowlist is documented as working by inspecting/filtering
TLS traffic on port 443 -- exactly the kind of layer that could plausibly
mishandle a long-lived, gappy SSE stream regardless of what's on the other
end of it.

Creates two minimal, throwaway Modal sandboxes (plain ubuntu + curl, no
toolchain snapshot needed -- this only tests networking, so it's fast and
cheap to spin up, unlike a real trial):
  A) allowlisted   -- outbound_domain_allowlist=["*"], outbound_cidr_allowlist=["0.0.0.0/0"]
                      (exactly modal_sandbox_runner.py's _create_sandbox config)
  B) unrestricted  -- no allowlist arguments at all (Modal's plain default)

From each, runs the identical real streaming call against
LITELLM_BASE_URL + "/responses" (the same endpoint Codex's own CLI hit,
not the older /v1/chat/completions), using the same model
(ModelConfig.litellm_model_id default, solver_agent.py) real trials use,
authenticated with LITELLM_SECRET_KEY (never LITELLM_MASTER_KEY, per this
repo's credential policy). If A fails and B succeeds, that is the
confirmed cause. If both fail the same way, the allowlist is cleared as a
suspect and the search moves elsewhere (LiteLLM's own streaming/timeout
config, or the model's own response latency pattern).

Real but small cost: two short streaming LLM calls, not free. Always
terminates both sandboxes in `finally`, regardless of outcome.
"""

from __future__ import annotations

import argparse
import json
import shlex
import time
from pathlib import Path
from typing import Any

import common
from common import atomic_write_json, get_logger

log = get_logger("modal_streaming_diagnostic")

DEFAULT_APP = "gymsiege-streaming-diagnostic"
DEFAULT_MODEL = "gpt-5.6-luna"  # solver_agent.ModelConfig's own default
DEFAULT_PROMPT = (
    "Write an extremely detailed, exhaustive technical explanation (aim for "
    "several thousand words) covering: how the Sieve of Eratosthenes works "
    "and why it's correct; a full walkthrough of the Sieve of Atkin as an "
    "alternative; a comparison of their time/space complexity with worked "
    "examples; then a separate, equally detailed explanation of the Miller-"
    "Rabin primality test including the mathematics behind why it works, "
    "with several fully worked numerical examples. Do not summarize -- go "
    "into full depth on every section."
)
CURL_TIMEOUT_S = 240


def _curl_script(base_url: str, model: str, prompt: str) -> str:
    # shlex.quote(), not repr(): repr() assumes Python's backslash-escape
    # rules for embedded quotes, which bash single-quoted strings don't
    # support at all -- shlex.quote() closes/reopens quotes instead
    # ('it'"'"'s'), the only form that's actually safe in a shell command
    # regardless of what --model/--prompt ever contain.
    url = shlex.quote(f"{base_url}/responses")
    payload = shlex.quote(
        json.dumps({"model": model, "input": prompt, "stream": True, "max_output_tokens": 8000})
    )
    # $LITELLM_SECRET_KEY expands inside the sandbox's own shell, from the
    # env var the Modal Secret injects -- never interpolated here.
    return f"""
set -u
START=$(date +%s.%N)
curl -N -sS -m {CURL_TIMEOUT_S} -X POST {url} \\
  -H "Authorization: Bearer $LITELLM_SECRET_KEY" \\
  -H "Content-Type: application/json" \\
  -d {payload} \\
  -w '\\nCURL_EXIT_MARKER http_code=%{{http_code}} time_total=%{{time_total}}\\n'
CURL_RC=$?
END=$(date +%s.%N)
echo "DIAGNOSTIC_RC=$CURL_RC DIAGNOSTIC_WALL_S=$(echo "$END - $START" | bc)"
"""


def _run_probe(modal_mod, app, label: str, use_allowlist: bool, secret, base_url: str, model: str, prompt: str) -> dict[str, Any]:
    image = modal_mod.Image.from_registry("ubuntu:24.04").apt_install(["curl", "bc"])
    kwargs: dict[str, Any] = {
        "app": app,
        "image": image,
        "cpu": 1,
        "memory": 1024,
        "timeout": CURL_TIMEOUT_S + 60,
        "secrets": [secret],
    }
    if use_allowlist:
        kwargs["outbound_domain_allowlist"] = ["*"]
        kwargs["outbound_cidr_allowlist"] = ["0.0.0.0/0"]

    log.info("[%s] creating sandbox (allowlisted=%s)", label, use_allowlist)
    t0 = time.monotonic()
    with modal_mod.enable_output():
        sandbox = modal_mod.Sandbox.create("sleep", "infinity", **kwargs)
    t_create = time.monotonic() - t0

    result: dict[str, Any] = {"label": label, "allowlisted": use_allowlist, "t_create_s": t_create}
    try:
        script = _curl_script(base_url, model, prompt)
        started = time.monotonic()
        process = sandbox.exec("bash", "-lc", script, timeout=CURL_TIMEOUT_S + 30)
        process.wait()
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        result.update(
            exit_code=process.returncode,
            duration_s=time.monotonic() - started,
            stdout_tail=stdout[-4000:],
            stderr_tail=stderr[-2000:],
        )
        log.info(
            "[%s] curl exit=%s duration=%.1fs stdout_tail=%s",
            label, process.returncode, result["duration_s"], stdout[-300:].replace("\n", " | "),
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        log.error("[%s] probe failed: %s", label, exc)
    finally:
        try:
            sandbox.terminate()
        except Exception as exc:
            log.warning("[%s] terminate() failed: %s", label, exc)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", default=DEFAULT_APP)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--prompt", default=DEFAULT_PROMPT)
    parser.add_argument("--output", type=Path, default=common.RESULTS_DIR / "modal_streaming_diagnostic.json")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        import modal
    except ImportError as exc:
        raise SystemExit("Modal SDK is required; install requirements.txt") from exc

    base_url = common.require_env("LITELLM_BASE_URL")
    secret_key = common.require_env("LITELLM_SECRET_KEY")
    secret = modal.Secret.from_dict({"LITELLM_SECRET_KEY": secret_key})

    app = modal.App.lookup(args.app, create_if_missing=True)

    results = {
        "base_url": base_url,
        "model": args.model,
        "observed_at_unix": time.time(),
        "probes": [
            _run_probe(modal, app, "A_allowlisted", True, secret, base_url, args.model, args.prompt),
            _run_probe(modal, app, "B_unrestricted", False, secret, base_url, args.model, args.prompt),
        ],
    }
    atomic_write_json(args.output, results)

    print(f"\nwrote {args.output}\n")
    for probe in results["probes"]:
        status = "ERROR" if "error" in probe else f"exit_code={probe.get('exit_code')}"
        print(f"{probe['label']:16s} allowlisted={probe['allowlisted']!s:5s} {status} duration={probe.get('duration_s', '?')}")

    a_ok = "error" not in results["probes"][0] and results["probes"][0].get("exit_code") == 0
    b_ok = "error" not in results["probes"][1] and results["probes"][1].get("exit_code") == 0
    print()
    if not a_ok and b_ok:
        print("CONFIRMED: the outbound_domain_allowlist config breaks the stream; unrestricted networking does not.")
    elif not a_ok and not b_ok:
        print("Both failed identically: the allowlist is NOT the cause -- look elsewhere (LiteLLM streaming/timeout config, or the model's own response latency).")
    elif a_ok and b_ok:
        print("Both succeeded: could not reproduce the disconnect with this prompt/model -- may need a longer or gappier response to trigger it.")
    else:
        print("Unexpected: allowlisted succeeded but unrestricted failed -- rerun, this result contradicts the hypothesis either way.")


if __name__ == "__main__":
    main()
