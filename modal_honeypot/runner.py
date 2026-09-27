#!/usr/bin/env python3
"""Run a defensive honeypot suite in a network-blocked Modal Sandbox."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


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
CASE_PREFIXES = {"agent": "APH-", "model": "MRH-", "network-off": "NOF-"}


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


def remote_argv(
    harness: str,
    case_id: str | None,
    workers: int,
    *,
    network_off_enabled: bool = False,
) -> list[str]:
    validate_case(harness, case_id)
    validate_network_off_opt_in(harness, network_off_enabled)
    command = [
        "/usr/sbin/runuser", "-u", "honeypot", "--", "env",
        "HOME=/home/honeypot", "PYTHONDONTWRITEBYTECODE=1",
    ]
    if harness == "network-off":
        command.append("MODAL_NETWORK_OFF_ENFORCED=1")
    command.extend([
        "python3", f"{REMOTE_ROOT}/modal_honeypot/in_sandbox.py",
        "--harness", harness, "--workers", str(workers),
        "--output-root", "/tmp/honeypot-output",
    ])
    command.extend(["--case-id", case_id] if case_id else ["--all"])
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
    )


def run(args: argparse.Namespace) -> int:
    validate_case(args.harness, args.case_id)
    validate_network_off_opt_in(args.harness, args.enable_network_off_suite)
    if args.harness == "network-off" and POLICY["block_network"] is not True:
        raise RuntimeError("network-off suite requires block_network=True")
    runtime_policy = {
        **POLICY,
        "timeout": args.sandbox_timeout,
        "exec_timeout": args.exec_timeout,
        "network_off_suite_enabled": args.enable_network_off_suite,
    }
    command = remote_argv(
        args.harness, args.case_id, args.workers,
        network_off_enabled=args.enable_network_off_suite,
    )
    if args.dry_run:
        print(json.dumps({"app": args.app_name, "harness": args.harness, "case_id": args.case_id,
                          "policy": runtime_policy, "remote_argv": command},
                         indent=2))
        return 0

    try:
        import modal
    except ImportError as exc:
        raise SystemExit("Modal SDK missing; install the pinned requirements with: pip install modal==1.5.5") from exc

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output / f"{args.harness}-{args.case_id or 'all'}-{stamp}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    app = modal.App.lookup(args.app_name, create_if_missing=True)
    image = build_image(modal)
    sandbox = None
    metadata: dict[str, object] = {
        "schema_version": "1.0", "harness": args.harness, "case_id": args.case_id,
        "app": args.app_name, "policy": runtime_policy, "started_at": stamp,
    }
    try:
        with modal.enable_output():
            sandbox = modal.Sandbox.create(
                "sleep", "infinity", app=app, image=image, workdir="/workspace",
                block_network=True, cpu=POLICY["cpu"], memory=POLICY["memory"],
                timeout=args.sandbox_timeout, idle_timeout=POLICY["idle_timeout"],
                secrets=[], volumes={},
                tags={"purpose": "rogue-agent-honeypot", "harness": args.harness},
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
    harness.add_argument("--harness", choices=["agent", "model"])
    harness.add_argument(
        "--network-off-suite", action="store_true",
        help="select the 20-case outbound-network containment suite",
    )
    parser.add_argument(
        "--enable-network-off-suite", action="store_true",
        help="required explicit opt-in for --network-off-suite",
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--case-id")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
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
    except ValueError as exc:
        parser.error(str(exc))
    if args.sandbox_timeout < args.exec_timeout or args.sandbox_timeout > 86400:
        parser.error("sandbox timeout must cover exec timeout and be at most 86400 seconds")
    if args.all:
        args.case_id = None
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
