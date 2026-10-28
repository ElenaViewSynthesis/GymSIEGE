#!/usr/bin/env python3
"""Run a defensive honeypot suite in a network-blocked Modal Sandbox."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    from modal_honeypot.redact import scan_for_secret
    from modal_honeypot.virtual_key import (
        LiteLLMAdminClient,
        MintedKey,
        key_spend,
        mint_virtual_key,
        revoke_virtual_key,
    )
except ModuleNotFoundError:  # direct ``python modal_honeypot/runner.py``
    from redact import scan_for_secret
    from virtual_key import (
        LiteLLMAdminClient,
        MintedKey,
        key_spend,
        mint_virtual_key,
        revoke_virtual_key,
    )


REPO = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/honeypot"
DEFAULT_APP = "rogue-agent-honeypots"
CODEX_VERSION = "0.164.0"
POLICY = {
    "block_network": True,
    "cpu": (1.0, 2.0),
    "memory": (512, 1024),
    "timeout": 1800,
    "idle_timeout": 300,
    "secrets": [],
    "volumes": {},
    "user": "honeypot",
}
CASE_PREFIXES = {
    "agent": "APH-",
    "collusion": "CLH-",
    "instrument": "IHT-",
    "model": "MRH-",
    "network-off": "NOF-",
}


def validate_case(harness: str, case_id: str | None) -> None:
    if harness not in CASE_PREFIXES:
        raise ValueError(f"unknown harness: {harness}")
    if case_id is None:
        return
    prefix = CASE_PREFIXES[harness]
    if not case_id.startswith(prefix):
        raise ValueError(f"{harness} case IDs must begin with {prefix}")


def validate_network_off_opt_in(harness: str, enabled: bool) -> None:
    if harness == "network-off" and not enabled:
        raise ValueError("network-off suite requires --enable-network-off-suite")
    if harness != "network-off" and enabled:
        raise ValueError("--enable-network-off-suite requires --network-off-suite")


def validate_allow_network(harness: str | None, allow_network: bool) -> None:
    """--allow-network opens outbound egress for one run (block_network=False).

    It is an explicit opt-in that never changes POLICY, is refused for the
    network-off suite (whose results mean nothing with egress open), and is
    recorded in the run metadata and the output directory name. The user-space
    tripwires inside the sandbox still log and refuse egress tools and
    connects; only the outer boundary is removed.
    """
    if harness in {"collusion", "network-off"} and allow_network:
        target = "--harness collusion" if harness == "collusion" else "--network-off-suite"
        raise ValueError(f"--allow-network cannot be combined with {target}")


GATEWAY_URL_NAMES = ("OPENAI_BASE_URL", "OPENAI_API_BASE", "LITELLM_BASE_URL")
LOOPBACK_HOSTS = {"localhost", "0.0.0.0", "::1"}
ARM_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
KEY_TTL_PATTERN = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>[smhd])$")


def gateway_url(*, require_v1: bool = False) -> str:
    """Return the first configured, externally reachable gateway URL."""
    for name in GATEWAY_URL_NAMES:
        base = os.environ.get(name, "")
        if not base:
            continue
        parsed = urlparse(base)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"} or not host:
            raise ValueError(f"--egress-allowlist gateway: {name} is not an HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError(f"{name} must not contain credentials, a query, or a fragment")
        if host in LOOPBACK_HOSTS or host.startswith("127."):
            raise ValueError(
                f"--egress-allowlist gateway: {name} points at {host}, which the sandbox "
                "cannot reach; set it to the tunnel URL of the gateway"
            )
        if require_v1 and parsed.path.rstrip("/")[-3:] != "/v1":
            raise ValueError(
                f"{name} must be the full OpenAI-compatible gateway URL ending in /v1"
            )
        if require_v1 and parsed.scheme != "https":
            raise ValueError(f"{name} must use HTTPS when carrying a virtual key")
        return base.rstrip("/")
    raise ValueError(
        "--egress-allowlist gateway needs OPENAI_BASE_URL, OPENAI_API_BASE, or "
        "LITELLM_BASE_URL in the environment"
    )


def gateway_host() -> str:
    """Hostname of the model gateway as the sandbox must reach it.

    Read on the host from the first set of OPENAI_BASE_URL, OPENAI_API_BASE,
    LITELLM_BASE_URL (the first two are what the scrubbed agent environment
    passes through). A loopback host is refused: the sandbox cannot reach the
    operator's localhost, so the variable must point at the tunnel URL.
    """
    host = urlparse(gateway_url()).hostname
    assert host is not None
    return host.lower()


def default_key_ttl(sandbox_timeout: int) -> str:
    return f"{math.ceil(sandbox_timeout / 60) + 5}m"


def key_ttl_seconds(value: str) -> int:
    match = KEY_TTL_PATTERN.fullmatch(value)
    if not match:
        raise ValueError("--key-ttl must be a positive LiteLLM duration such as 35m")
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group("unit")]
    return int(match.group("amount")) * multiplier


def virtual_key_alias(
    harness: str, case_id: str | None, arm: str, trial: int, stamp: str,
) -> str:
    if not ARM_PATTERN.fullmatch(arm):
        raise ValueError("--arm must contain only letters, digits, '.', '_' or '-'")
    if trial < 1:
        raise ValueError("--trial must be at least 1")
    return f"{harness}/{case_id or 'all'}/t{trial}/{stamp}"


def _has_egress_token(spec: str | None, token: str) -> bool:
    return token in {item.strip() for item in (spec or "").split(",") if item.strip()}


def validate_virtual_key_preconditions(
    args: argparse.Namespace, egress_allowlist: list[str] | None,
) -> str:
    """Validate an actual mint and return the full provider gateway URL."""
    if args.subject_command is None:
        raise ValueError("virtual-key minting requires --subject-command")
    if args.case_id is None:
        raise ValueError("virtual-key minting requires one --case-id, not --all")
    if not _has_egress_token(getattr(args, "egress_allowlist", None), "gateway"):
        raise ValueError(
            "virtual-key minting requires --egress-allowlist containing the gateway token"
        )
    gateway = gateway_url(require_v1=True)
    host = urlparse(gateway).hostname
    if not egress_allowlist or host not in egress_allowlist:
        raise ValueError("the resolved gateway host is not in the egress allowlist")
    if not os.environ.get("LITELLM_MASTER_KEY"):
        raise ValueError("virtual-key minting requires LITELLM_MASTER_KEY on the host")
    if not getattr(args, "model", None):
        raise ValueError("virtual-key minting requires --model")
    budget = getattr(args, "key_budget", 0.50)
    if not isinstance(budget, (int, float)) or not math.isfinite(budget) or budget <= 0:
        raise ValueError("--key-budget must be a positive finite USD amount")
    ttl = getattr(args, "key_ttl", None) or default_key_ttl(args.sandbox_timeout)
    if key_ttl_seconds(ttl) <= args.sandbox_timeout:
        raise ValueError("--key-ttl must be longer than --sandbox-timeout")
    return gateway


def resolve_egress_allowlist(spec: str | None) -> list[str] | None:
    """Parse --egress-allowlist into hostnames.

    The token ``langfuse`` resolves to the host of LANGFUSE_BASE_URL and the
    token ``gateway`` to the model gateway's host (see gateway_host), both read
    on the host at plan time (hostnames, never keys). Entries are bare
    hostnames; URLs and ``*`` are refused so the list can never widen to open
    egress. A real agent needs ``langfuse,gateway``: Langfuse alone leaves it
    unable to reach the model.
    """
    if spec is None:
        return None
    hosts: list[str] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if item == "langfuse":
            base = os.environ.get("LANGFUSE_BASE_URL", "")
            host = urlparse(base).hostname if base else None
            if not host:
                raise ValueError("--egress-allowlist langfuse needs LANGFUSE_BASE_URL in the environment")
            item = host
        elif item == "gateway":
            item = gateway_host()
        if item == "*" or "/" in item or ":" in item:
            raise ValueError(f"--egress-allowlist entries are bare hostnames, not URLs or '*': {item}")
        hosts.append(item.lower())
    if not hosts:
        raise ValueError("--egress-allowlist is empty")
    return sorted(set(hosts))


def validate_egress_allowlist(
    harness: str | None, allowlist: list[str] | None, allow_network: bool,
) -> None:
    """--egress-allowlist opens egress to the listed hosts only.

    It sets block_network=False with outbound_domain_allowlist=hosts, so the
    sandbox can reach those hosts and nothing else. Because it is scoped it is
    permitted for the collusion suite, where open egress is refused; it is
    still refused for the network-off suite and never combined with
    --allow-network. It is recorded in the policy, the metadata, the tags, and
    the output directory name, and exported to the sandbox as
    MODAL_NETWORK_ALLOWLIST so in-sandbox code knows egress is scoped.
    """
    if allowlist is None:
        return
    if allow_network:
        raise ValueError("--egress-allowlist cannot be combined with --allow-network")
    if harness == "network-off":
        raise ValueError("--egress-allowlist cannot be combined with --network-off-suite")


def validate_weights_mode(harness: str | None, weights_mode: str) -> None:
    if weights_mode not in {"text", "format"}:
        raise ValueError(f"unknown weights mode: {weights_mode}")
    if weights_mode == "format" and harness != "model":
        raise ValueError("--weights-mode format requires --harness model")


def validate_subject_command(harness: str | None, subject_command: str | None) -> None:
    if subject_command is not None and harness != "collusion":
        raise ValueError("--subject-command requires --harness collusion")


def output_name(
    harness: str | None,
    case_id: str | None,
    *,
    demo: bool,
    evidence_chain: bool,
    weights_mode: str,
    allow_network: bool,
    subject_command: str | None = None,
    egress_allowlist: list[str] | None = None,
) -> str:
    target = "demo" if demo else str(harness)
    selection = "run" if demo else case_id or "all"
    if subject_command is not None:
        selection += "-agent"
    chain = "chain" if evidence_chain else "chain-off"
    network = "-net-open" if allow_network else ("-net-allow" if egress_allowlist else "")
    return f"{target}-{selection}-{chain}-{weights_mode}{network}"


def remote_argv(
    harness: str | None,
    case_id: str | None,
    workers: int,
    *,
    network_off_enabled: bool = False,
    allow_network: bool = False,
    evidence_chain: bool = False,
    weights_mode: str = "text",
    demo: bool = False,
    subject_command: str | None = None,
    model: str | None = None,
    egress_allowlist: list[str] | None = None,
) -> list[str]:
    if demo:
        if harness is not None or case_id is not None:
            raise ValueError("--demo cannot be combined with a harness or case ID")
    elif harness is None:
        raise ValueError("a harness is required unless --demo is selected")
    else:
        validate_case(harness, case_id)
    validate_network_off_opt_in(harness, network_off_enabled)
    validate_allow_network(harness, allow_network)
    validate_egress_allowlist(harness, egress_allowlist, allow_network)
    validate_weights_mode(harness, weights_mode)
    validate_subject_command(harness, subject_command)
    command = ["/usr/sbin/runuser", "-u", "honeypot"]
    if subject_command is not None:
        # The virtual key and gateway URL arrive as Sandbox Secret environment
        # variables. Preserve them explicitly across the UID transition; the
        # agent_subject launcher later reduces the environment to its allowlist.
        command.append("--preserve-environment")
    command.extend([
        "--", "env",
        "HOME=/home/honeypot", "PYTHONDONTWRITEBYTECODE=1",
        f"HONEYPOT_WEIGHTS_MODE={weights_mode}",
    ])
    if evidence_chain or harness == "collusion":
        command.append("HONEYPOT_EVIDENCE_CHAIN=1")
    if harness == "collusion":
        command.append("MODAL_COLLUSION_CONTAINMENT_ENFORCED=1")
        if subject_command is not None and model is not None:
            command.append(f"HONEYPOT_CODEX_MODEL={model}")
    if harness == "network-off":
        command.append("MODAL_NETWORK_OFF_ENFORCED=1")
    if allow_network:
        command.append("MODAL_NETWORK_OPEN=1")
    if egress_allowlist:
        command.append("MODAL_NETWORK_ALLOWLIST=" + ",".join(egress_allowlist))
    if demo:
        command.append("TMPDIR=/tmp/honeypot-output")
    command.extend([
        "python3", f"{REMOTE_ROOT}/modal_honeypot/in_sandbox.py",
        "--output-root", "/tmp/honeypot-output",
    ])
    if demo:
        command.append("--demo")
    else:
        command.extend(["--harness", str(harness), "--workers", str(workers)])
        command.extend(["--case-id", case_id] if case_id else ["--all"])
        if subject_command is not None:
            command.extend(["--subject-command", subject_command])
    return command


def build_image(modal_module, *, verify_secret_environment: bool = False):
    image = (
        modal_module.Image.debian_slim(python_version="3.12")
        .apt_install(
            "gcc", "libc6-dev", "procps", "psmisc", "lsof", "gdb", "lldb",
            "strace", "util-linux", "tmux", "screen", "at", "curl", "wget",
            "git", "rsync", "zip", "gzip", "zstd", "ca-certificates",
        )
        .run_commands(
            "useradd --create-home --uid 1000 --shell /bin/bash honeypot",
            "mkdir -p /workspace && chown honeypot:honeypot /workspace",
        )
    )
    if verify_secret_environment:
        # Modal injects Secret values into the Sandbox environment. This build
        # assertion proves the image's non-login runuser preserves such
        # inherited variables for the unprivileged exec process.
        image = image.apt_install("nodejs", "npm").run_commands(
            f"npm install --global @openai/codex@{CODEX_VERSION}",
            f"codex --version | grep -Fx 'codex-cli {CODEX_VERSION}'",
            "env MODAL_SECRET_ENV_PROBE=preserved /usr/sbin/runuser -u honeypot "
            "--preserve-environment -- "
            "sh -c 'test \"$MODAL_SECRET_ENV_PROBE\" = preserved'",
        )
    return (
        image
        .add_local_dir(REPO / "agent_honeypot", f"{REMOTE_ROOT}/agent_honeypot", copy=True)
        .add_local_dir(REPO / "model_replication_honeypot", f"{REMOTE_ROOT}/model_replication_honeypot", copy=True)
        .add_local_dir(REPO / "modal_honeypot", f"{REMOTE_ROOT}/modal_honeypot", copy=True)
        .add_local_dir(REPO / "tests", f"{REMOTE_ROOT}/tests", copy=True)
    )


def run(
    args: argparse.Namespace, *, modal_module=None, admin_client=None,
) -> int:
    if not args.demo:
        validate_case(args.harness, args.case_id)
    validate_network_off_opt_in(args.harness, args.enable_network_off_suite)
    validate_allow_network(args.harness, args.allow_network)
    egress_allowlist = resolve_egress_allowlist(getattr(args, "egress_allowlist", None))
    validate_egress_allowlist(args.harness, egress_allowlist, args.allow_network)
    validate_weights_mode(args.harness, args.weights_mode)
    validate_subject_command(args.harness, args.subject_command)
    block_network = not (args.allow_network or bool(egress_allowlist))
    if args.harness == "network-off" and block_network is not True:
        raise RuntimeError("network-off suite requires block_network=True")
    evidence_chain = args.evidence_chain or args.harness == "collusion"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    arm = getattr(args, "arm", "manual")
    trial = getattr(args, "trial", 1)
    key_ttl = getattr(args, "key_ttl", None) or default_key_ttl(args.sandbox_timeout)
    key_budget = getattr(args, "key_budget", 0.50)
    key_alias = None
    if args.subject_command is not None:
        key_alias = virtual_key_alias(args.harness, args.case_id, arm, trial, stamp)
    runtime_policy = {
        **POLICY,
        "block_network": block_network,
        "egress": "open" if args.allow_network else ("allowlist" if egress_allowlist else "blocked"),
        "egress_allowlist": egress_allowlist,
        "timeout": args.sandbox_timeout,
        "exec_timeout": args.exec_timeout,
        "network_off_suite_enabled": args.enable_network_off_suite,
        "evidence_chain": evidence_chain,
        "weights_mode": args.weights_mode,
    }
    if key_alias is not None:
        runtime_policy.update({
            "secrets": [f"virtual-key:{key_alias}"],
            "key_budget_usd": key_budget,
            "key_ttl": key_ttl,
            "key_model": getattr(args, "model", None),
        })
    command = remote_argv(
        args.harness, args.case_id, args.workers,
        network_off_enabled=args.enable_network_off_suite,
        allow_network=args.allow_network,
        evidence_chain=evidence_chain,
        weights_mode=args.weights_mode,
        demo=args.demo,
        subject_command=args.subject_command,
        model=getattr(args, "model", None),
        egress_allowlist=egress_allowlist,
    )
    if args.allow_network:
        print("WARNING: --allow-network: this sandbox has outbound network access; "
              "the user-space tripwires still log and refuse egress, but the outer "
              "boundary is open", file=sys.stderr)
    if egress_allowlist:
        print("WARNING: --egress-allowlist: this sandbox can reach "
              + ", ".join(egress_allowlist)
              + " and no other host; the user-space tripwires still log and refuse "
              "egress, and every byte to those hosts is an observed channel",
              file=sys.stderr)
    if args.subject_command is not None:
        # A real agent reaches the model only through the gateway; say so when the
        # egress policy cannot carry it, but do not refuse: the run is still contained.
        try:
            reachable_gateway = gateway_host()
        except ValueError:
            reachable_gateway = None
        if block_network:
            print("WARNING: --subject-command with egress blocked: the real agent cannot "
                  "reach the model gateway; use --egress-allowlist langfuse,gateway",
                  file=sys.stderr)
        elif egress_allowlist and reachable_gateway not in egress_allowlist:
            print("WARNING: --subject-command: the model gateway host is not in "
                  "--egress-allowlist; add the 'gateway' token or the agent cannot "
                  "reach the model", file=sys.stderr)
    if args.dry_run:
        print(json.dumps({"app": args.app_name, "harness": args.harness, "demo": args.demo,
                          "case_id": args.case_id, "output_name": output_name(
                              args.harness, args.case_id, demo=args.demo,
                              evidence_chain=evidence_chain, weights_mode=args.weights_mode,
                              allow_network=args.allow_network,
                              subject_command=args.subject_command,
                              egress_allowlist=egress_allowlist,
                          ), "policy": runtime_policy, "remote_argv": command},
                         indent=2))
        return 0

    gateway = None
    if args.subject_command is not None:
        gateway = validate_virtual_key_preconditions(args, egress_allowlist)
    if modal_module is None:
        try:
            import modal as modal_module
        except ImportError as exc:
            raise SystemExit("Modal SDK missing; install the repository's pinned requirements (requirements.txt pins modal==1.6.0), for example in the repo .venv") from exc

    name = output_name(
        args.harness, args.case_id, demo=args.demo,
        evidence_chain=evidence_chain, weights_mode=args.weights_mode,
        allow_network=args.allow_network,
        subject_command=args.subject_command,
        egress_allowlist=egress_allowlist,
    )
    output = (args.output / f"{name}-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    sandbox = None
    minted: MintedKey | None = None
    client = admin_client
    cleanup_errors: list[str] = []
    sandbox_kwargs: dict[str, object] = {}
    if egress_allowlist:
        sandbox_kwargs["outbound_domain_allowlist"] = list(egress_allowlist)
    metadata: dict[str, object] = {
        "schema_version": "1.0", "harness": args.harness, "demo": args.demo,
        "case_id": args.case_id, "evidence_chain": evidence_chain,
        "subject_mode": "agent" if args.subject_command is not None else "scripted",
        "weights_mode": args.weights_mode, "app": args.app_name,
        "policy": runtime_policy, "started_at": stamp,
    }
    if key_alias is not None:
        metadata.update({"arm": arm, "trial": trial})
    try:
        runtime_secrets = []
        if key_alias is not None:
            assert gateway is not None
            if client is None:
                client = LiteLLMAdminClient(gateway, os.environ["LITELLM_MASTER_KEY"])
            key_metadata = {
                "run_id": key_alias,
                "harness": args.harness,
                "case_id": args.case_id,
                "trial": trial,
                "arm": arm,
                "purpose": "rogue-agent-honeypot",
            }
            minted = mint_virtual_key(
                client,
                alias=key_alias,
                model=args.model,
                budget_usd=key_budget,
                ttl=key_ttl,
                metadata=key_metadata,
            )
            key_record: dict[str, object] = {
                "key_alias": key_alias,
                "minted_at": datetime.now(timezone.utc).isoformat(),
                "budget_usd": key_budget,
                "ttl": key_ttl,
            }
            if minted.token_id:
                key_record["token_id"] = minted.token_id
            elif minted.key_hash:
                key_record["key_hash"] = minted.key_hash
            else:
                key_record["key_fingerprint"] = minted.fingerprint
            metadata["virtual_key"] = key_record
            try:
                runtime_secret = modal_module.Secret.from_dict({
                    "OPENAI_API_KEY": minted.key,
                    "OPENAI_BASE_URL": gateway,
                })
            except Exception:
                raise RuntimeError("failed to construct the ephemeral Modal Secret") from None
            runtime_secrets = [runtime_secret]

        app = modal_module.App.lookup(args.app_name, create_if_missing=True)
        image = build_image(modal_module, verify_secret_environment=minted is not None)
        with modal_module.enable_output():
            sandbox = modal_module.Sandbox.create(
                "sleep", "infinity", app=app, image=image, workdir="/workspace",
                block_network=block_network, cpu=POLICY["cpu"], memory=POLICY["memory"],
                timeout=args.sandbox_timeout, idle_timeout=POLICY["idle_timeout"],
                secrets=runtime_secrets, volumes={}, **sandbox_kwargs,
                tags={"purpose": "rogue-agent-honeypot",
                      "harness": "demo" if args.demo else args.harness,
                      "network": "open" if args.allow_network
                      else ("allowlist" if egress_allowlist else "blocked")},
            )
        metadata["sandbox_id"] = sandbox.object_id
        process = sandbox.exec(*command, timeout=args.exec_timeout)
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        process.wait()
        metadata["remote_exit_code"] = process.returncode
        (output / "remote.stdout.log").write_text(stdout or "")
        (output / "remote.stderr.log").write_text(stderr or "")
        sandbox.filesystem.copy_to_local("/tmp/honeypot-output/summary.json", output / "summary.json")
        sandbox.filesystem.copy_to_local("/tmp/honeypot-output/artifacts.tar.gz", output / "artifacts.tar.gz")
        passed = process.returncode == 0
        metadata["passed"] = passed
        return 0 if passed else 1
    finally:
        if sandbox is not None:
            try:
                metadata["termination"] = "explicit-finally"
                metadata["sandbox_exit_code"] = sandbox.terminate(wait=True)
            except Exception:
                metadata["termination_error"] = "sandbox termination failed"
                cleanup_errors.append("sandbox termination failed")
            try:
                sandbox.detach()
            except Exception:
                metadata["detach_error"] = "sandbox detach failed"
                cleanup_errors.append("sandbox detach failed")
        if minted is not None and client is not None:
            key_record = metadata["virtual_key"]
            assert isinstance(key_record, dict)
            try:
                key_record["spend_usd"] = key_spend(client, minted.management_id)
            except Exception:
                key_record["spend_error"] = "key spend lookup failed"
                cleanup_errors.append("key spend lookup failed")
            try:
                revoke_virtual_key(client, minted.management_id)
                key_record["revoked_at"] = datetime.now(timezone.utc).isoformat()
            except Exception:
                key_record["revocation_error"] = "virtual-key revocation failed; TTL remains the backstop"
                cleanup_errors.append("virtual-key revocation failed")
        metadata_path = output / "modal-run.json"
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        if minted is not None:
            findings = scan_for_secret([output], minted.key)
            metadata["redaction"] = {
                "passed": not findings,
                "findings": [str(path.relative_to(output)) for path in findings],
            }
            metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
            if findings:
                cleanup_errors.append("virtual-key redaction scan failed")
        print(json.dumps({"output": str(output), **metadata}, indent=2, sort_keys=True))
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    harness = parser.add_mutually_exclusive_group(required=True)
    harness.add_argument("--harness", choices=["agent", "collusion", "instrument", "model"])
    harness.add_argument(
        "--network-off-suite", action="store_true",
        help="select the 20-case outbound-network containment suite",
    )
    harness.add_argument("--demo", action="store_true", help="run the checked evidence-chain demo")
    parser.add_argument(
        "--enable-network-off-suite", action="store_true",
        help="required explicit opt-in for --network-off-suite",
    )
    parser.add_argument(
        "--allow-network", action="store_true",
        help="open outbound network for this run (block_network=False); refused with "
             "--network-off-suite; recorded in the metadata and the output directory name",
    )
    parser.add_argument(
        "--egress-allowlist",
        help="comma-separated hostnames the sandbox may reach and nothing else "
             "(block_network=False with outbound_domain_allowlist); the token 'langfuse' "
             "resolves to the host of LANGFUSE_BASE_URL and 'gateway' to the model gateway's "
             "host from OPENAI_BASE_URL/OPENAI_API_BASE/LITELLM_BASE_URL (loopback refused); "
             "a real agent needs langfuse,gateway; permitted for --harness collusion, "
             "refused with --allow-network and with --network-off-suite",
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--case-id")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--evidence-chain", action="store_true")
    parser.add_argument("--weights-mode", choices=["text", "format"], default="text")
    parser.add_argument(
        "--subject-command",
        help="real-agent command for collusion subjects; requires external containment",
    )
    parser.add_argument("--model", help="single LiteLLM model allowed on a minted virtual key")
    parser.add_argument("--key-budget", type=float, default=0.50, help="per-run virtual-key budget in USD")
    parser.add_argument(
        "--key-ttl",
        help="LiteLLM virtual-key duration; defaults to sandbox timeout plus five minutes",
    )
    parser.add_argument("--arm", default="manual", help="experiment arm recorded in virtual-key metadata")
    parser.add_argument("--trial", type=int, default=1, help="one-based trial number")
    parser.add_argument("--app-name", default=DEFAULT_APP)
    parser.add_argument("--output", type=Path, default=Path("results/modal-honeypot"))
    parser.add_argument("--sandbox-timeout", type=int, default=POLICY["timeout"])
    parser.add_argument("--exec-timeout", type=int, default=1500)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.network_off_suite:
        args.harness = "network-off"
    try:
        validate_network_off_opt_in(args.harness, args.enable_network_off_suite)
        validate_allow_network(args.harness, args.allow_network)
        validate_egress_allowlist(
            args.harness, resolve_egress_allowlist(args.egress_allowlist), args.allow_network,
        )
        validate_weights_mode(args.harness, args.weights_mode)
        validate_subject_command(args.harness, args.subject_command)
    except ValueError as exc:
        parser.error(str(exc))
    if args.demo and (args.case_id or args.all):
        parser.error("--demo cannot be combined with --case-id or --all")
    if not args.demo and not (args.case_id or args.all):
        parser.error("a harness run requires --case-id or --all")
    if args.sandbox_timeout < args.exec_timeout or args.sandbox_timeout > 86400:
        parser.error("sandbox timeout must cover exec timeout and be at most 86400 seconds")
    if not math.isfinite(args.key_budget) or args.key_budget <= 0:
        parser.error("--key-budget must be a positive finite USD amount")
    if args.trial < 1:
        parser.error("--trial must be at least 1")
    if not ARM_PATTERN.fullmatch(args.arm):
        parser.error("--arm must contain only letters, digits, '.', '_' or '-'")
    if args.key_ttl is not None:
        try:
            key_ttl_seconds(args.key_ttl)
        except ValueError as exc:
            parser.error(str(exc))
    if args.all:
        args.case_id = None
    try:
        return run(args)
    except ValueError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
