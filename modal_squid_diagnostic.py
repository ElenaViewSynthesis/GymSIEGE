#!/usr/bin/env python3
"""
Diagnose whether cybergym-e2e's own Squid firewall proxy is rejecting the
real Codex CLI's calls -- not a long-stream/Modal-networking problem, a
much more specific hypothesis: real trials never pass --domain to
`python -m firewall start` (see solver_agent.py's BuildAgent.run), so
Squid loads only its DEFAULT domain allowlist
(scripts/firewall/default_allowlist.txt upstream: api.anthropic.com,
api.openai.com, generativelanguage.googleapis.com). The real agent's
outbound calls go to LITELLM_BASE_URL (a Cloudflare/ngrok tunnel
hostname), which is on neither list. Squid's `http_access deny all` for
anything not in `allowed_domains` denies the CONNECT outright -- which can
plausibly surface to a naive streaming HTTP client as a generic "stream
disconnected"/"error sending request" failure rather than a clean,
recognizable 403, matching what Codex's own trajectory logs show.

modal_streaming_diagnostic.py already ruled out Modal's own
outbound_domain_allowlist networking and long-duration streams as causes
(both a ~13s and a ~72s real streaming call succeeded cleanly with no
Squid in the path at all). This script adds the one thing that test
didn't reproduce: cybergym-e2e's actual Squid proxy, using its real
SQUID_CONF_TEMPLATE (pulled from the upstream repo verbatim, not
guessed), in the exact "run" (domain-allowlist) mode real trials use --
not the permissive "install" mode.

One Modal sandbox, two sequential real calls through the same live Squid
instance:
  A) default allowlist   (api.anthropic.com/api.openai.com/generativelanguage.googleapis.com only)
     -- reproduces the real, current misconfiguration
  B) default allowlist + our tunnel hostname added, then `squid -k reconfigure`
     -- the fix, if this hypothesis is right

Real but small cost: at most one short-to-moderate streaming LLM call (B
only needs to succeed briefly to confirm; A is expected to fail near-
instantly, costing nothing). Always terminates the sandbox in `finally`.
"""

from __future__ import annotations

import argparse
import json
import shlex
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import common
from common import atomic_write_json, get_logger

log = get_logger("modal_squid_diagnostic")

DEFAULT_APP = "gymsiege-squid-diagnostic"
DEFAULT_MODEL = "gpt-5.6-luna"  # solver_agent.ModelConfig's own default
PROXY_PORT = 3128
CURL_TIMEOUT_S = 60

# Pulled verbatim from sunblaze-ucb/cybergym-e2e's scripts/firewall/proxy.py
# (SQUID_CONF_TEMPLATE) -- the real "run" (agent-phase) proxy config, not
# the permissive "install" one. Kept identical rather than approximated so
# this test reflects the actual denial behavior, not a guess at it.
SQUID_CONF_TEMPLATE = """\
# --- CyberGym domain-allowlist proxy ---

acl SSL_ports port 443 {extra_ports}
acl Safe_ports port 80 443 {extra_ports}
acl CONNECT method CONNECT

# Allowed destinations -- loaded from external files
acl allowed_domains dstdomain "{domain_allowlist_path}"
{ip_acl}

# Rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow CONNECT allowed_domains
{ip_connect_rule}
http_access allow allowed_domains
{ip_rule}
http_access deny all

http_port {port}

# Disable disk cache
cache deny all

# Logging (Squid runs as user 'proxy' which cannot write to /dev/stdout)
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
"""

# Pulled verbatim from scripts/firewall/default_allowlist.txt.
DEFAULT_ALLOWLIST = """\
# Default domain allowlist for the cybergym-e2e run proxy.
api.anthropic.com
api.openai.com
generativelanguage.googleapis.com
"""


def _squid_conf() -> str:
    return SQUID_CONF_TEMPLATE.format(
        extra_ports="",
        domain_allowlist_path="/etc/squid/allowed_domains.txt",
        ip_acl="",
        ip_connect_rule="",
        ip_rule="",
        port=PROXY_PORT,
    )


def _curl_through_proxy_script(label: str, base_url: str, model: str, max_output_tokens: int) -> str:
    url = shlex.quote(f"{base_url}/responses")
    payload = shlex.quote(
        json.dumps({
            "model": model,
            "input": "Say ok.",
            "stream": True,
            "max_output_tokens": max_output_tokens,
        })
    )
    # `exit "$CURL_RC"` last: without it, the trailing echo would always
    # succeed and this exec's own returncode would be 0 regardless of
    # whether curl actually failed.
    return f"""
echo '--- {label} ---'
curl -N -sS -m {CURL_TIMEOUT_S} -x http://127.0.0.1:{PROXY_PORT} -X POST {url} \\
  -H "Authorization: Bearer $LITELLM_SECRET_KEY" \\
  -H "Content-Type: application/json" \\
  -d {payload} \\
  -w '\\nCURL_EXIT_MARKER http_code=%{{http_code}} time_total=%{{time_total}}\\n' \\
  2>&1
CURL_RC=$?
echo "CURL_RC=$CURL_RC"
exit "$CURL_RC"
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", default=DEFAULT_APP)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--output", type=Path, default=common.RESULTS_DIR / "modal_squid_diagnostic.json")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        import modal
    except ImportError as exc:
        raise SystemExit("Modal SDK is required; install requirements.txt") from exc

    base_url = common.require_env("LITELLM_BASE_URL")
    secret_key = common.require_env("LITELLM_SECRET_KEY")
    tunnel_host = urlparse(base_url).hostname
    if not tunnel_host:
        raise SystemExit(f"LITELLM_BASE_URL={base_url!r} has no parseable host")

    secret = modal.Secret.from_dict({"LITELLM_SECRET_KEY": secret_key})
    app = modal.App.lookup(args.app, create_if_missing=True)

    image = modal.Image.from_registry("ubuntu:24.04").apt_install(["docker.io", "curl"])
    log.info("creating sandbox (vm_runtime for docker support)")
    with modal.enable_output():
        sandbox = modal.Sandbox.create(
            "/usr/bin/dockerd", "--host=unix:///var/run/docker.sock",
            app=app, image=image, cpu=2, memory=2048,
            timeout=CURL_TIMEOUT_S * 4 + 300,
            experimental_options={"vm_runtime": True},
            secrets=[secret],
        )

    results: dict[str, Any] = {
        "base_url": base_url, "tunnel_host": tunnel_host, "model": args.model,
        "observed_at_unix": time.time(), "steps": [],
    }
    try:
        wait_docker = sandbox.exec(
            "bash", "-lc",
            "for i in $(seq 1 60); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1",
            timeout=90,
        )
        wait_docker.wait()
        results["steps"].append({"label": "docker_ready", "returncode": wait_docker.returncode})
        if wait_docker.returncode != 0:
            raise RuntimeError("dockerd never became ready")

        # Write the real "run" config + the real default allowlist (no
        # --domain args -- reproducing exactly what solver_agent.py's
        # BuildAgent.run currently invokes).
        sandbox.filesystem.write_text(_squid_conf(), "/root/squid.conf")
        sandbox.filesystem.write_text(DEFAULT_ALLOWLIST, "/root/allowed_domains.txt")

        pull = sandbox.exec("docker", "pull", "ubuntu/squid:latest", timeout=180)
        pull.wait()
        results["steps"].append({"label": "docker_pull_squid", "returncode": pull.returncode})

        run_squid = sandbox.exec(
            "docker", "run", "-d", "--name", "squid-test",
            "--network", "host",
            "-v", "/root/squid.conf:/etc/squid/squid.conf",
            "-v", "/root/allowed_domains.txt:/etc/squid/allowed_domains.txt",
            "ubuntu/squid:latest",
            timeout=60,
        )
        run_squid.wait()
        results["steps"].append({"label": "squid_start", "returncode": run_squid.returncode})

        wait_squid = sandbox.exec(
            "bash", "-lc",
            f"for i in $(seq 1 30); do curl -sS -m 2 -x http://127.0.0.1:{PROXY_PORT} "
            "http://example.com >/dev/null 2>&1; c=$?; "
            "[ $c -eq 0 -o $c -eq 22 ] && exit 0; sleep 1; done; exit 1",
            timeout=45,
        )
        wait_squid.wait()
        results["steps"].append({"label": "squid_ready", "returncode": wait_squid.returncode})

        # --- Probe A: default allowlist only (the current real config) ---
        probe_a = sandbox.exec(
            "bash", "-lc",
            _curl_through_proxy_script("A_default_allowlist", base_url, args.model, 50),
            timeout=CURL_TIMEOUT_S + 20,
        )
        probe_a.wait()
        out_a = probe_a.stdout.read()
        results["probe_a_default_allowlist"] = {
            "returncode": probe_a.returncode,
            "output_tail": out_a[-3000:],
        }
        log.info("[A_default_allowlist] rc=%s output_tail=%s", probe_a.returncode, out_a[-500:].replace("\n", " | "))

        # --- Fix: add our tunnel host, reconfigure Squid, retest ---
        updated_allowlist = DEFAULT_ALLOWLIST + f"{tunnel_host}\n"
        sandbox.filesystem.write_text(updated_allowlist, "/root/allowed_domains.txt")
        recopy = sandbox.exec(
            "docker", "cp", "/root/allowed_domains.txt", "squid-test:/etc/squid/allowed_domains.txt",
            timeout=30,
        )
        recopy.wait()
        # A full restart, not `squid -k reconfigure`: the first run showed
        # reconfigure reporting success (returncode 0) while the ACL file
        # change silently never took effect -- external dstdomain ACL files
        # apparently aren't reliably re-read by a signal-based reconfigure
        # in this image. A restart guarantees a clean re-read of everything.
        restart = sandbox.exec("docker", "restart", "squid-test", timeout=30)
        restart.wait()
        results["steps"].append({"label": "squid_restart", "returncode": restart.returncode})
        wait_squid_2 = sandbox.exec(
            "bash", "-lc",
            f"for i in $(seq 1 30); do curl -sS -m 2 -x http://127.0.0.1:{PROXY_PORT} "
            "http://example.com >/dev/null 2>&1; c=$?; "
            "[ $c -eq 0 -o $c -eq 22 ] && exit 0; sleep 1; done; exit 1",
            timeout=45,
        )
        wait_squid_2.wait()
        results["steps"].append({"label": "squid_ready_after_restart", "returncode": wait_squid_2.returncode})

        probe_b = sandbox.exec(
            "bash", "-lc",
            _curl_through_proxy_script("B_tunnel_host_added", base_url, args.model, 50),
            timeout=CURL_TIMEOUT_S + 20,
        )
        probe_b.wait()
        out_b = probe_b.stdout.read()
        results["probe_b_with_tunnel_host"] = {
            "returncode": probe_b.returncode,
            "output_tail": out_b[-3000:],
        }
        log.info("[B_tunnel_host_added] rc=%s output_tail=%s", probe_b.returncode, out_b[-500:].replace("\n", " | "))

    finally:
        try:
            sandbox.terminate()
        except Exception as exc:
            log.warning("terminate() failed: %s", exc)

    atomic_write_json(args.output, results)
    print(f"\nwrote {args.output}\n")

    a_failed = results.get("probe_a_default_allowlist", {}).get("returncode") != 0
    b_ok = results.get("probe_b_with_tunnel_host", {}).get("returncode") == 0
    if a_failed and b_ok:
        print("CONFIRMED: Squid's default allowlist rejects the tunnel host; adding it fixes the call.")
        print(f"Fix: pass --domain {tunnel_host} to `python -m firewall start` in solver_agent.py's BuildAgent.run.")
    elif not a_failed:
        print("UNEXPECTED: probe A (default allowlist) succeeded -- this hypothesis may be wrong, or NO_PROXY/host-gateway routing bypassed Squid entirely. Inspect output_tail.")
    else:
        print("Both probes failed -- adding the tunnel host did not fix it. Inspect output_tail for both; the cause is something else.")


if __name__ == "__main__":
    main()
