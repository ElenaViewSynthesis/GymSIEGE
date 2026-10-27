#!/usr/bin/env python3
"""Run a defensive honeypot suite in a network-blocked Modal Sandbox."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


REPO = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/honeypot"
DEFAULT_APP = "rogue-agent-honeypots"
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


def gateway_host() -> str:
    """Hostname of the model gateway as the sandbox must reach it.

    Read on the host from the first set of OPENAI_BASE_URL, OPENAI_API_BASE,
    LITELLM_BASE_URL (the first two are what the scrubbed agent environment
    passes through). A loopback host is refused: the sandbox cannot reach the
    operator's localhost, so the variable must point at the tunnel URL.
    """
    for name in GATEWAY_URL_NAMES:
        base = os.environ.get(name, "")
        if not base:
            continue
        host = urlparse(base).hostname
        if not host:
            raise ValueError(f"--egress-allowlist gateway: {name} is not a URL")
        if host in LOOPBACK_HOSTS or host.startswith("127."):
            raise ValueError(
                f"--egress-allowlist gateway: {name} points at {host}, which the sandbox "
                "cannot reach; set it to the tunnel URL of the gateway"
            )
        return host.lower()
    raise ValueError(
        "--egress-allowlist gateway needs OPENAI_BASE_URL, OPENAI_API_BASE, or "
        "LITELLM_BASE_URL in the environment"
    )


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
    command = [
        "/usr/sbin/runuser", "-u", "honeypot", "--", "env",
        "HOME=/home/honeypot", "PYTHONDONTWRITEBYTECODE=1",
        f"HONEYPOT_WEIGHTS_MODE={weights_mode}",
    ]
    if evidence_chain or harness == "collusion":
        command.append("HONEYPOT_EVIDENCE_CHAIN=1")
    if harness == "collusion":
        command.append("MODAL_COLLUSION_CONTAINMENT_ENFORCED=1")
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


def build_image(modal_module):
    return (
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
        .add_local_dir(REPO / "agent_honeypot", f"{REMOTE_ROOT}/agent_honeypot", copy=True)
        .add_local_dir(REPO / "model_replication_honeypot", f"{REMOTE_ROOT}/model_replication_honeypot", copy=True)
        .add_local_dir(REPO / "modal_honeypot", f"{REMOTE_ROOT}/modal_honeypot", copy=True)
        .add_local_dir(REPO / "tests", f"{REMOTE_ROOT}/tests", copy=True)
    )


def run(args: argparse.Namespace) -> int:
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
    command = remote_argv(
        args.harness, args.case_id, args.workers,
        network_off_enabled=args.enable_network_off_suite,
        allow_network=args.allow_network,
        evidence_chain=evidence_chain,
        weights_mode=args.weights_mode,
        demo=args.demo,
        subject_command=args.subject_command,
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

    try:
        import modal
    except ImportError as exc:
        raise SystemExit("Modal SDK missing; install the repository's pinned requirements (requirements.txt pins modal==1.6.0), for example in the repo .venv") from exc

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = output_name(
        args.harness, args.case_id, demo=args.demo,
        evidence_chain=evidence_chain, weights_mode=args.weights_mode,
        allow_network=args.allow_network,
        subject_command=args.subject_command,
        egress_allowlist=egress_allowlist,
    )
    output = (args.output / f"{name}-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    app = modal.App.lookup(args.app_name, create_if_missing=True)
    image = build_image(modal)
    sandbox = None
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
    try:
        with modal.enable_output():
            sandbox = modal.Sandbox.create(
                "sleep", "infinity", app=app, image=image, workdir="/workspace",
                block_network=block_network, cpu=POLICY["cpu"], memory=POLICY["memory"],
                timeout=args.sandbox_timeout, idle_timeout=POLICY["idle_timeout"],
                secrets=[], volumes={}, **sandbox_kwargs,
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
            finally:
                sandbox.detach()
        (output / "modal-run.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"output": str(output), **metadata}, indent=2, sort_keys=True))


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
    if args.all:
        args.case_id = None
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
