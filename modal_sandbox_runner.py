#!/usr/bin/env python3
"""
GYMSIEGE Modal trial adapter -- the Modal equivalent of sandbox_runner.py's
run_trial(). One call is one (task, mode, trial) unit of work:

    Sandbox.create(image=Image.from_id(<baked snapshot>), vm_runtime=True,
                    secrets=[...], outbound_domain_allowlist=["*"], ...)
      -> wait for the dockerd entrypoint to answer
      -> Solver(ModalSandboxAdapter(sandbox), model, remote_dir=...).build(...)
         (same BuildAgent as Daytona -- see ModalSandboxAdapter below)
      -> best-effort in-sandbox cgroup/df telemetry probe
      -> sandbox.filesystem.copy_to_local(...) for poc.bin/fix.patch/run_agent.log
      -> sandbox.terminate() in `finally` no matter what happened above

This mirrors sandbox_runner.py's contract (same TrialResult shape, same
status-classification cascade via common.classify_trial_status, same
BuildAgent/Solver from solver_agent.py) rather than re-implementing the
build/PoC/patch/oracle logic a second time. Per
modal-docs/modal-virtualization.md's own architecture note, Daytona and
Modal are kept behind a narrow provider boundary instead of branching
solver_agent.py inline: that boundary is ModalSandboxAdapter below, which
gives a raw modal.Sandbox the same `.process.exec()` /
`.update_network_settings()` shape BuildAgent already expects.

What is NOT ported from sandbox_runner.py, and why:
  - ResearchAgent / computer-use / screen recording: Modal Sandboxes have no
    GUI, VNC, accessibility-tree, or recording API. Every trial here records
    research_mode="skipped" the same way a Daytona research-phase *failure*
    already does -- this isn't a new status, just a new reason to reach one
    that already exists.
  - sandbox.set_ttl() / mid-life TTL re-arming: Modal has no settable
    running-sandbox TTL. `timeout=` is creation-time-only (max 24h); that is
    this adapter's only lifetime safety net, backstopped by terminate() in
    `finally`.
  - --provisioning fork: Modal has no live-sandbox fork API. "snapshot" mode
    (an independent Sandbox.create() restore from the baked Image ID) is
    already Modal's cheap-parallel-restore path, so there's no separate
    warm-parent-then-fork optimization to port.
  - get_metrics()/get_metrics_latest(): not exposed anywhere in
    modal-docs/*. `_probe_telemetry` below is a best-effort substitute that
    reads cgroup memory + `df` from inside the sandbox over exec, using the
    exact mem_used/mem_total/disk_used dict-key contract sandbox_runner.py's
    _metrics_to_dict already produces from Daytona's real SandboxMetrics --
    so orchestrator.py's OOM-threshold check works unmodified against either
    provider's TrialResult, just sampled once rather than as a real history.

Known rough edge: _reconfirm_isolated's network cut/reopen (in
solver_agent.py, unmodified) rides ModalSandboxAdapter.update_network_settings,
which itself rides Modal's `_experimental_set_outbound_network_policy` -- an
alpha, underscore-prefixed API (modal-docs/modal-networking-security.md,
"Dynamic policy limitations"). Confirmed live 2026-09-15 for the block
direction: a real trial's re-detonation container had its own `apt-get`
calls hit a genuine network wall, and the reopen call didn't raise either
-- not yet proven across every failure/success path, though. If a live run
finds it doesn't behave as documented, that surfaces as
`detonation_error` on the trial rather than a silent false pass -- it never
skips the network cut and continues.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import common
from common import (
    AGENT_TIMEOUT_S,
    ARTIFACTS_DIR,
    Mode,
    ProvisioningMode,
    SANDBOX_NAME_PREFIX,
    Task,
    TrialResult,
    append_event,
    atomic_write_json,
    get_logger,
)
from modal_snapshot_build import DEFAULT_APP, DEFAULT_MANIFEST, REMOTE_REPO_DIR
from solver_agent import ModelConfig, Solver

log = get_logger("modal_sandbox_runner")

OUT_DIR = "/root/agent_output"
DEFAULT_LITELLM_SECRET = os.environ.get("GYMSIEGE_MODAL_LITELLM_SECRET_NAME", "gymsiege-litellm")
DOCKER_READY_TIMEOUT_S = 180
# Budget: run_agent.py's own --timeout (AGENT_TIMEOUT_S) + the isolated
# re-detonation's own 7600s exec timeout (solver_agent._reconfirm_isolated)
# + headroom for docker-wait/telemetry/artifact download. Modal's own
# ceiling is 24h (86400s); this stays comfortably under it.
TRIAL_SANDBOX_TIMEOUT_S = int(
    os.environ.get("GYMSIEGE_MODAL_TRIAL_TIMEOUT_S", str(AGENT_TIMEOUT_S + 7600 + 1800))
)
TRIAL_SANDBOX_CPU = 2
TRIAL_SANDBOX_MEMORY_MIB = 8192


class _ModalExecResult:
    """Mimics the .exit_code/.result shape solver_agent.py expects from
    Daytona's ExecuteResponse, backed by a real modal.ContainerProcess."""

    __slots__ = ("exit_code", "result")

    def __init__(self, exit_code: Optional[int], result: str):
        self.exit_code = exit_code
        self.result = result


class _ModalProcessProxy:
    def __init__(self, sandbox):
        self._sandbox = sandbox

    async def exec(self, cmd: str, timeout: Optional[int] = None) -> _ModalExecResult:
        process = await self._sandbox.exec.aio("bash", "-lc", cmd, timeout=timeout)
        await process.wait.aio()
        stdout = await process.stdout.read.aio() or ""
        stderr = await process.stderr.read.aio() or ""
        # Daytona's `.result` carries combined output; concatenating keeps
        # _parse_json_marker's "scan every line for the marker" logic correct
        # regardless of which stream a given line actually landed on.
        return _ModalExecResult(process.returncode, stdout + stderr)


class ModalSandboxAdapter:
    """The provider boundary modal-docs/modal-virtualization.md calls for:
    gives a raw modal.Sandbox the two Daytona-shaped members BuildAgent
    (solver_agent.py) uses, so BuildAgent itself needs no Modal-specific
    branches.
    """

    def __init__(self, sandbox):
        self.sandbox = sandbox  # duck-typed name BuildAgent expects
        self.process = _ModalProcessProxy(sandbox)

    async def update_network_settings(self, network_block_all: bool) -> None:
        set_policy = getattr(self.sandbox, "_experimental_set_outbound_network_policy", None)
        if set_policy is None:
            raise RuntimeError(
                "installed Modal SDK exposes no "
                "_experimental_set_outbound_network_policy(); cannot enforce "
                "the network-isolated PoC re-detonation on this SDK version"
            )
        allow_domains = [] if network_block_all else ["*"]
        allow_cidrs = [] if network_block_all else ["0.0.0.0/0"]
        # Alpha/private API, documented sync-only -- run off the event loop
        # thread rather than assuming an .aio() twin exists.
        await asyncio.to_thread(
            set_policy,
            outbound_domain_allowlist=allow_domains,
            outbound_cidr_allowlist=allow_cidrs,
        )


async def _create_sandbox(
    modal_mod, app, provisioning: ProvisioningMode, snapshot_image_id: str, secrets: list
):
    t0 = time.monotonic()
    if provisioning == "snapshot":
        image = modal_mod.Image.from_id(snapshot_image_id)
    elif provisioning == "cold":
        # Bench-only baseline, same role as sandbox_runner.py's "cold" arm:
        # no toolchain, not what a real trial runs from.
        image = (
            modal_mod.Image.from_registry("ubuntu:24.04")
            .env({"DEBIAN_FRONTEND": "noninteractive"})
            .apt_install(["docker.io", "docker-buildx"])
        )
    else:
        raise ValueError(
            f"unsupported Modal provisioning mode: {provisioning!r} -- Modal "
            "has no live-sandbox fork API, so only 'snapshot' and 'cold' are "
            "supported (see module docstring)"
        )
    with modal_mod.enable_output():
        sandbox = await modal_mod.Sandbox.create.aio(
            "/usr/bin/dockerd",
            "--host=unix:///var/run/docker.sock",
            app=app,
            image=image,
            cpu=TRIAL_SANDBOX_CPU,
            memory=TRIAL_SANDBOX_MEMORY_MIB,
            timeout=TRIAL_SANDBOX_TIMEOUT_S,
            experimental_options={"vm_runtime": True},
            secrets=secrets,
            # Populated allowlists (not block_network=True) so
            # update_network_settings() can flip them shut later via the
            # alpha runtime-policy API -- block_network is create-time-only
            # and can't be reopened (modal-docs/modal-networking-security.md,
            # "Dynamic policy limitations").
            outbound_domain_allowlist=["*"],
            outbound_cidr_allowlist=["0.0.0.0/0"],
        )
    return sandbox, time.monotonic() - t0


def _trial_secrets(modal_mod, litellm_secret_name: str) -> list:
    secrets = [modal_mod.Secret.from_name(litellm_secret_name)]
    provider_env = {
        key: os.environ[key]
        for key in ("LITELLM_BASE_URL", "OPENAI_BASE_URL")
        if os.environ.get(key)
    }
    if provider_env:
        secrets.append(modal_mod.Secret.from_dict(provider_env))
    return secrets


async def _wait_for_docker(process: _ModalProcessProxy, task_path: str) -> None:
    r = await process.exec(
        "for i in $(seq 1 180); do "
        "if [ -S /var/run/docker.sock ] && docker info >/dev/null 2>&1; then echo ready; exit 0; fi; "
        "sleep 1; done; echo 'dockerd not ready after 180s' >&2; exit 1",
        timeout=DOCKER_READY_TIMEOUT_S,
    )
    if r.exit_code != 0:
        raise RuntimeError(f"Docker daemon unavailable after Modal snapshot restore: {r.result[-2000:]}")
    # Same ASAN/mmap-layout workaround sandbox_runner.py applies for Daytona;
    # harmless no-op if the real VM kernel doesn't need it.
    await process.exec("sysctl -w vm.mmap_rnd_bits=28 >/dev/null 2>&1 || true", timeout=15)


async def _probe_telemetry(process: _ModalProcessProxy, task_path: str) -> dict:
    """Best-effort mem/disk snapshot -- see module docstring."""
    script = (
        "if [ -f /sys/fs/cgroup/memory.max ]; then "
        "  MAXV=$(cat /sys/fs/cgroup/memory.max); [ \"$MAXV\" = 'max' ] && MAXV=0; "
        "  echo mem_total=$MAXV; echo mem_used=$(cat /sys/fs/cgroup/memory.current); "
        "else "
        "  free -b | awk '/Mem:/ {print \"mem_total=\" $2; print \"mem_used=\" $3}'; "
        "fi; "
        "df -B1 --output=used / | tail -1 | awk '{print \"disk_used=\" $1}'"
    )
    try:
        r = await process.exec(script, timeout=30)
    except Exception as exc:
        log.warning("[%s] telemetry probe failed: %s", task_path, exc)
        return {}
    if r.exit_code != 0:
        return {}
    parsed: dict = {}
    for line in r.result.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        try:
            parsed[key.strip()] = int(value.strip())
        except ValueError:
            continue
    if parsed:
        parsed["timestamp"] = time.time()
    return parsed


def _artifact_path(task: Task, mode: Mode, trial: int, filename: str) -> Path:
    path = ARTIFACTS_DIR / task.safe_name / mode / f"trial-{trial}" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_snapshot_manifest(path: Path = DEFAULT_MANIFEST) -> dict:
    manifest = common.load_json(path, default=None)
    if not manifest or not manifest.get("snapshot_image_id"):
        raise RuntimeError(
            f"no verified Modal snapshot manifest at {path} -- run "
            "modal_snapshot_build.py first"
        )
    return manifest


async def run_trial(
    modal_mod,
    app,
    task: Task,
    mode: Mode,
    trial: int,
    manifest: dict,
    provisioning: ProvisioningMode = "snapshot",
    model: Optional[ModelConfig] = None,
    litellm_secret_name: str = DEFAULT_LITELLM_SECRET,
    record: bool = False,
    result: TrialResult | None = None,
) -> TrialResult:
    started_at = datetime.now(timezone.utc).isoformat()
    name = f"{SANDBOX_NAME_PREFIX}-modal-{task.safe_name}-{mode}-t{trial}-{int(time.time())}"
    if result is None:
        result = TrialResult(task=task.path, mode=mode, trial=trial, provisioning=provisioning)
    result.provider = "modal"
    result.started_at = started_at
    append_event({
        "type": "trial_start", "task": task.path, "mode": mode, "trial": trial,
        "sandbox_name": name, "provider": "modal",
    })

    if record:
        log.warning(
            "[%s] record=True requested but Modal Sandboxes have no "
            "recording/computer-use API; ignoring", task.path,
        )

    t_total0 = time.monotonic()
    sandbox = None
    adapter = None
    try:
        secrets = _trial_secrets(modal_mod, litellm_secret_name)
        sandbox, t_create = await _create_sandbox(
            modal_mod, app, provisioning, manifest["snapshot_image_id"], secrets
        )
        result.sandbox_id = sandbox.object_id
        result.sandbox_name = name
        result.t_create_s = t_create
        log.info(
            "[%s] Modal sandbox %s ready in %.1fs (provisioning=%s)",
            task.path, result.sandbox_id, t_create, provisioning,
        )

        # Modal has no settable running-sandbox TTL -- the bounded `timeout=`
        # passed at creation above is the only lifetime safety net, so it's
        # "armed" the moment create() returns, unlike Daytona's separate
        # set_ttl() call.
        result.cleanup_ttl_set = True

        try:
            await sandbox.set_tags.aio({
                "siege": "1", "task": task.safe_name, "mode": mode, "trial": str(trial),
            })
        except Exception as exc:
            log.warning("[%s] set_tags failed (non-fatal): %s", task.path, exc)

        adapter = ModalSandboxAdapter(sandbox)
        await _wait_for_docker(adapter.process, task.path)

        solver = Solver(adapter, model=model, remote_dir=REMOTE_REPO_DIR)
        # No computer-use/GUI surface on Modal -- see module docstring.
        result.research_mode = "skipped"
        result.research_success = None

        t_b0 = time.monotonic()
        build = await solver.build(task, mode, OUT_DIR)
        result.t_build_s = time.monotonic() - t_b0

        result.stage1, result.stage2, result.stage3, result.stage4 = (
            build.stage1, build.stage2, build.stage3, build.stage4
        )
        result.agent_success, result.gt_success = build.agent_success, build.gt_success
        result.vul_exit_code, result.fix_exit_code = build.vul_exit_code, build.fix_exit_code
        result.network_isolated_detonation = build.network_isolated_detonation
        result.detonation_error = build.detonation_error
        result.solver_usage = build.solver_usage
        result.solver_cost_usd = build.solver_cost_usd
        result.status = common.classify_trial_status(build)

        telemetry = await _probe_telemetry(adapter.process, task.path)
        if telemetry:
            result.metrics_latest = telemetry
            result.metrics_series = [telemetry]

        # Each file downloaded independently: a failure on one (e.g. a patch
        # that was never actually written) must not skip the others -- a
        # missing run_agent.log is exactly the evidence needed to diagnose
        # why the patch is missing in the first place.
        if build.poc_path:
            try:
                local = _artifact_path(task, mode, trial, "poc.bin")
                await asyncio.to_thread(sandbox.filesystem.copy_to_local, build.poc_path, str(local))
                result.poc_local_path = str(local)
            except Exception as exc:
                log.warning("[%s] poc.bin download failed: %s", task.path, exc)
        if build.patch_path:
            try:
                local = _artifact_path(task, mode, trial, "fix.patch")
                await asyncio.to_thread(sandbox.filesystem.copy_to_local, build.patch_path, str(local))
                result.patch_local_path = str(local)
            except Exception as exc:
                log.warning("[%s] fix.patch download failed: %s", task.path, exc)
        try:
            local = _artifact_path(task, mode, trial, "run_agent.log")
            await asyncio.to_thread(sandbox.filesystem.copy_to_local, build.log_path, str(local))
            result.log_local_path = str(local)
        except Exception as exc:
            log.warning("[%s] run_agent.log download failed: %s", task.path, exc)

    except Exception as exc:
        result.status = "error"
        result.error = f"{exc}\n{traceback.format_exc(limit=5)}"
        log.error("[%s] Modal trial errored: %s", task.path, exc)

    finally:
        if sandbox is not None:
            if adapter is not None and not result.metrics_latest:
                # Mirrors sandbox_runner.py's _capture_telemetry_bounded: take
                # one bounded best-effort sample even on the error/cancelled
                # path, before the sandbox is gone.
                try:
                    telemetry = await asyncio.wait_for(
                        _probe_telemetry(adapter.process, task.path), timeout=30
                    )
                    if telemetry:
                        result.metrics_latest = telemetry
                        result.metrics_series = [telemetry]
                except Exception as exc:
                    log.warning("[%s] bounded final telemetry probe failed: %s", task.path, exc)
            try:
                await sandbox.terminate.aio()
                result.cleanup_delete_accepted = True
                result.cleanup_destroyed = True
            except Exception as exc:
                log.error(
                    "[%s] terminate() failed -- Modal sandbox %s may leak: %s",
                    task.path, result.sandbox_id, exc,
                )

        result.t_total_s = time.monotonic() - t_total0
        result.finished_at = datetime.now(timezone.utc).isoformat()
        append_event({
            "type": "trial_end", "task": task.path, "mode": mode, "trial": trial,
            "status": result.status, "t_total_s": result.t_total_s, "provider": "modal",
        })

    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one CyberGym-E2E trial against a Modal-baked snapshot."
    )
    parser.add_argument("--task", required=True, help="project/task_id, e.g. freetype2/arvo_368")
    parser.add_argument("--mode", choices=["e2e", "patch-only"], default="patch-only")
    parser.add_argument("--trial", type=int, default=1)
    parser.add_argument("--provisioning", choices=["snapshot", "cold"], default="snapshot")
    parser.add_argument("--app", default=None, help="Modal App name (default: the manifest's own app)")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--litellm-secret", default=DEFAULT_LITELLM_SECRET)
    parser.add_argument("--agent", default="codex", choices=["codex"])
    parser.add_argument("--model-provider", default="litellm", choices=["litellm"])
    parser.add_argument(
        "--litellm-model-id",
        default="gpt-5.6-luna",
        choices=["gpt-5.6-luna", "gpt-5.6-sol", "gpt-daybreak-blue-latest"],
    )
    parser.add_argument("--output", type=Path, default=None, help="write the TrialResult JSON here")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        import modal
    except ImportError as exc:
        raise SystemExit("Modal SDK is required; install requirements.txt") from exc

    task = Task.parse(args.task)
    if task is None:
        raise SystemExit("--task must be project/task_id, e.g. freetype2/arvo_368")

    if not os.environ.get("LITELLM_BASE_URL"):
        raise SystemExit(
            "LITELLM_BASE_URL is not set -- start the LiteLLM gateway first "
            "(see README.md) so it can be forwarded into the Modal sandbox"
        )

    manifest = load_snapshot_manifest(args.manifest)
    app_name = args.app or manifest.get("app", DEFAULT_APP)
    app = modal.App.lookup(app_name, create_if_missing=True)
    model = ModelConfig(
        provider=args.model_provider, litellm_model_id=args.litellm_model_id, agent=args.agent
    )

    result = asyncio.run(
        run_trial(
            modal, app, task, args.mode, args.trial,
            manifest=manifest,
            provisioning=args.provisioning,
            model=model,
            litellm_secret_name=args.litellm_secret,
        )
    )
    payload = result.to_json()
    print(json.dumps(payload, indent=2, default=str))
    if args.output:
        atomic_write_json(args.output, payload)
    if result.status in ("error", "oracle_unavailable"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
