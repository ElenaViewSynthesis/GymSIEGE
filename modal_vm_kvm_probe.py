#!/usr/bin/env python3
"""Probe KVM and nested Docker device passthrough in a Modal VM Sandbox.

This is intentionally separate from a benchmark run: it creates one short-
lived VM Sandbox, records host/TCG/KVM results, and always terminates it.
It does not attach provider secrets or invoke an agent.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any


def _process_result(process) -> dict[str, Any]:
    process.wait()
    return {
        "returncode": process.returncode,
        "stdout": process.stdout.read(),
        "stderr": process.stderr.read(),
    }


def _exec(sandbox, label: str, script: str, timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    process = sandbox.exec("bash", "-lc", script, timeout=timeout)
    result = _process_result(process)
    result.update(label=label, duration_s=round(time.monotonic() - started, 3))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", default="gymsiege-modal-vm-probe")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/modal_vm_kvm_probe.json"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        import modal
    except ImportError as exc:
        raise SystemExit(
            "Modal's Python SDK is required; install a version supporting VM "
            "Sandboxes and filesystem snapshot TTLs (v1.5 or newer)."
        ) from exc

    image = (
        modal.Image.from_registry("ubuntu:24.04")
        .env({"DEBIAN_FRONTEND": "noninteractive"})
        .apt_install(["docker.io", "qemu-system-x86"])
    )
    app = modal.App.lookup(args.app, create_if_missing=True)
    results: dict[str, Any] = {
        "observed_at_unix": time.time(),
        "app": args.app,
        "modal_version": getattr(modal, "__version__", "unknown"),
        "vm_runtime": True,
        "sandbox_id": None,
        "probes": [],
        "termination_error": None,
    }

    sandbox = None
    try:
        with modal.enable_output():
            sandbox = modal.Sandbox.create(
                "/usr/bin/dockerd",
                "--host=unix:///var/run/docker.sock",
                app=app,
                image=image,
                cpu=2,
                memory=4096,
                timeout=args.timeout,
                experimental_options={"vm_runtime": True},
            )
        results["sandbox_id"] = sandbox.object_id

        probes = results["probes"]
        probes.append(
            _exec(
                sandbox,
                "docker_ready",
                "for i in $(seq 1 120); do docker info >/dev/null 2>&1 && exit 0; "
                "sleep 1; done; exit 1",
                150,
            )
        )
        probes.append(
            _exec(
                sandbox,
                "vm_identity_and_kvm_device",
                "uname -a; id; ls -la /dev/kvm 2>&1; "
                "test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm",
                30,
            )
        )
        probes.append(
            _exec(
                sandbox,
                "qemu_version",
                "qemu-system-x86_64 --version",
                30,
            )
        )
        probes.append(
            _exec(
                sandbox,
                "vm_kvm_acceleration",
                "timeout 3 qemu-system-x86_64 -accel kvm -machine pc "
                "-nodefaults -display none -S; code=$?; test $code -eq 124",
                15,
            )
        )
        probes.append(
            _exec(
                sandbox,
                "vm_tcg_fallback",
                "timeout 3 qemu-system-x86_64 -accel tcg -machine pc "
                "-nodefaults -display none -S; code=$?; test $code -eq 124",
                15,
            )
        )
        probes.append(
            _exec(
                sandbox,
                "nested_docker_kvm",
                "docker run --rm --device /dev/kvm:/dev/kvm ubuntu:24.04 "
                "bash -lc 'test -c /dev/kvm && test -r /dev/kvm && "
                "test -w /dev/kvm && apt-get update >/dev/null && "
                "apt-get install -y qemu-system-x86 >/dev/null && "
                "timeout 3 qemu-system-x86_64 -accel kvm -machine pc "
                "-nodefaults -display none -S; code=$?; test $code -eq 124'",
                600,
            )
        )
    finally:
        if sandbox is not None:
            try:
                sandbox.terminate()
            except Exception as exc:
                results["termination_error"] = f"{type(exc).__name__}: {exc}"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    failed = [probe["label"] for probe in results["probes"] if probe["returncode"]]
    if results["termination_error"]:
        failed.append("sandbox_termination")
    print(f"wrote {args.output}")
    if failed:
        raise SystemExit("failed probes: " + ", ".join(failed))


if __name__ == "__main__":
    main()
