#!/usr/bin/env python3
"""Plan or execute manifest-pinned CyberGym repeats without overwriting results.

The default is a read-only plan. Paid execution requires ``--execute``. Each
attempt is written beneath ``attempts/``; only a genuine terminal model outcome
is copied, with exclusive creation, into the batch root consumed by the paper
loaders. Infrastructure failures remain auditable but outside loader scope.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = ROOT / "reference" / "cybergym_paper_cohort.v1.json"
TERMINAL_STATUSES = {"success", "failed", "no_patch", "oracle_mismatch"}
RETRYABLE_STATUSES = {"error", "oracle_unavailable"}
_BATCH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ManifestError(ValueError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError(f"expected a JSON object in {path}")
    return payload


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = _read_json(path)
    required = {
        "schema_version", "cohort_id", "benchmark", "mode", "provider",
        "provisioning", "model_provider", "litellm_model_id", "agent",
        "snapshot_manifest", "snapshot_image_id", "baseline_trial",
        "repeat_trials", "max_attempts", "retry_sleep_s", "output_root",
        "baseline_results", "completed_repeats", "cost_estimate",
    }
    missing = sorted(required - manifest.keys())
    if missing:
        raise ManifestError(f"manifest missing fields: {', '.join(missing)}")
    if manifest["schema_version"] != 1:
        raise ManifestError("unsupported schema_version (expected 1)")
    entries = manifest["baseline_results"]
    if not isinstance(entries, list) or not entries:
        raise ManifestError("baseline_results must be a non-empty list")
    tasks = [entry.get("task") for entry in entries if isinstance(entry, dict)]
    if len(tasks) != len(entries) or any(not task or "/" not in task for task in tasks):
        raise ManifestError("every baseline result needs a project/task_id task")
    if any(not entry.get("result") or not entry.get("sha256") for entry in entries):
        raise ManifestError("every baseline result needs result and sha256 fields")
    if len(set(tasks)) != len(tasks):
        raise ManifestError("baseline_results contains duplicate tasks")
    trials = manifest["repeat_trials"]
    if (
        not isinstance(trials, list)
        or not trials
        or any(not isinstance(trial, int) or trial < 1 for trial in trials)
        or len(set(trials)) != len(trials)
    ):
        raise ManifestError("repeat_trials must contain unique positive integers")
    if manifest["baseline_trial"] in trials:
        raise ManifestError("repeat_trials must not include baseline_trial")
    completed = manifest["completed_repeats"]
    if not isinstance(completed, list):
        raise ManifestError("completed_repeats must be a list")
    completed_keys = []
    for entry in completed:
        if not isinstance(entry, dict):
            raise ManifestError("completed_repeats entries must be objects")
        if not entry.get("task") or not entry.get("result") or not entry.get("sha256"):
            raise ManifestError("every completed repeat needs task, result, and sha256")
        if entry.get("trial") not in trials:
            raise ManifestError("completed repeat trial must be declared in repeat_trials")
        completed_keys.append((entry["task"], entry["trial"]))
    if len(set(completed_keys)) != len(completed_keys):
        raise ManifestError("completed_repeats contains duplicate task/trial cells")
    if any(task not in set(tasks) for task, _ in completed_keys):
        raise ManifestError("completed_repeats contains a task outside the cohort")
    if not isinstance(manifest["max_attempts"], int) or manifest["max_attempts"] < 1:
        raise ManifestError("max_attempts must be a positive integer")
    if not isinstance(manifest["retry_sleep_s"], (int, float)) or manifest["retry_sleep_s"] < 0:
        raise ManifestError("retry_sleep_s must be non-negative")
    return manifest


def _validate_frozen_result(
    entry: dict[str, Any], expected_trial: int, root: Path
) -> None:
    result_path = root / entry["result"]
    try:
        actual_hash = hashlib.sha256(result_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ManifestError(f"cannot read frozen result {result_path}: {exc}") from exc
    if actual_hash != entry["sha256"]:
        raise ManifestError(f"frozen result SHA-256 mismatch: {result_path}")
    result = _read_json(result_path)
    if result.get("task") != entry["task"]:
        raise ManifestError(f"frozen result task mismatch in {result_path}")
    if result.get("trial") != expected_trial:
        raise ManifestError(f"frozen result trial mismatch in {result_path}")
    if result.get("status") not in TERMINAL_STATUSES:
        raise ManifestError(
            f"frozen result is not a terminal model outcome: {result_path} "
            f"status={result.get('status')!r}"
        )


def validate_frozen_inputs(manifest: dict[str, Any], root: Path = ROOT) -> None:
    snapshot_path = root / manifest["snapshot_manifest"]
    snapshot = _read_json(snapshot_path)
    if snapshot.get("snapshot_image_id") != manifest["snapshot_image_id"]:
        raise ManifestError(
            "snapshot image mismatch: cohort declares "
            f"{manifest['snapshot_image_id']!r}, {snapshot_path} has "
            f"{snapshot.get('snapshot_image_id')!r}"
        )
    snapshot_tasks = snapshot.get("tasks")
    declared_tasks = [entry["task"] for entry in manifest["baseline_results"]]
    if snapshot_tasks != declared_tasks:
        raise ManifestError("cohort task order/content does not match snapshot manifest")

    for entry in manifest["baseline_results"]:
        _validate_frozen_result(entry, manifest["baseline_trial"], root)
    for entry in manifest["completed_repeats"]:
        _validate_frozen_result(entry, entry["trial"], root)


def completed_repeat_map(manifest: dict[str, Any], root: Path = ROOT) -> dict[tuple[str, int], Path]:
    return {
        (entry["task"], entry["trial"]): root / entry["result"]
        for entry in manifest["completed_repeats"]
    }


def planned_cells(
    manifest: dict[str, Any], selected_tasks: set[str] | None = None
) -> list[tuple[str, int]]:
    tasks = [entry["task"] for entry in manifest["baseline_results"]]
    if selected_tasks:
        unknown = sorted(selected_tasks - set(tasks))
        if unknown:
            raise ManifestError(f"task(s) not in cohort: {', '.join(unknown)}")
        tasks = [task for task in tasks if task in selected_tasks]
    return [(task, trial) for task in tasks for trial in manifest["repeat_trials"]]


def _safe_task(task: str) -> str:
    return task.replace("/", "_")


def final_path(batch_dir: Path, task: str, trial: int) -> Path:
    return batch_dir / f"{_safe_task(task)}__trial-{trial}.json"


def terminal_result(path: Path, task: str, trial: int) -> bool:
    if not path.is_file():
        return False
    try:
        payload = _read_json(path)
    except ManifestError as exc:
        raise ManifestError(f"existing final result is unreadable; refusing overwrite: {exc}") from exc
    if payload.get("task") != task or payload.get("trial") != trial:
        raise ManifestError(f"existing final result has wrong identity; refusing overwrite: {path}")
    if payload.get("status") not in TERMINAL_STATUSES:
        raise ManifestError(
            f"existing final result is non-terminal; archive it before retrying: {path}"
        )
    return True


def _next_attempt_paths(batch_dir: Path, task: str, trial: int) -> tuple[Path, Path]:
    attempt_dir = batch_dir / "attempts" / f"{_safe_task(task)}__trial-{trial}"
    attempt_dir.mkdir(parents=True, exist_ok=True)
    index = 1
    while True:
        stem = f"attempt-{index:02d}"
        result_path = attempt_dir / f"{stem}.json"
        log_path = attempt_dir / f"{stem}.log"
        if not result_path.exists() and not log_path.exists():
            return result_path, log_path
        index += 1


def _publish_terminal(attempt_path: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with attempt_path.open("rb") as source, destination.open("xb") as target:
        shutil.copyfileobj(source, target)


def _load_local_env() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise ManifestError("python-dotenv is required for paid execution") from exc
    load_dotenv(ROOT / ".env.local", override=False)


def paid_preflight(manifest: dict[str, Any]) -> None:
    _load_local_env()
    for name in ("MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "LITELLM_BASE_URL"):
        if not os.environ.get(name):
            raise ManifestError(f"{name} is not set; paid execution not started")
    try:
        socket.getaddrinfo("api.modal.com", 443)
    except OSError as exc:
        raise ManifestError(f"cannot resolve api.modal.com; paid execution not started: {exc}") from exc
    subprocess.run(["modal", "profile", "current"], cwd=ROOT, check=True)
    secrets = subprocess.run(
        ["modal", "secret", "list"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    )
    secret_name = os.environ.get("GYMSIEGE_MODAL_LITELLM_SECRET_NAME", "gymsiege-litellm")
    if secret_name not in secrets.stdout:
        raise ManifestError(f"Modal secret {secret_name!r} not found; paid execution not started")


def _write_batch_metadata(
    manifest_path: Path, manifest: dict[str, Any], batch_dir: Path, batch_id: str
) -> None:
    raw = manifest_path.read_bytes()
    payload = {
        "batch_id": batch_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "cohort_manifest": str(manifest_path),
        "cohort_manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "cohort": manifest,
    }
    meta = batch_dir / "_meta" / "batch.json"
    meta.parent.mkdir(parents=True, exist_ok=True)
    with meta.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def _validate_batch_metadata(manifest_path: Path, batch_dir: Path, batch_id: str) -> None:
    meta_path = batch_dir / "_meta" / "batch.json"
    metadata = _read_json(meta_path)
    expected_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if metadata.get("batch_id") != batch_id:
        raise ManifestError(f"batch id mismatch in {meta_path}; refusing resume")
    if metadata.get("cohort_manifest_sha256") != expected_hash:
        raise ManifestError(
            f"cohort manifest changed since {batch_dir} was created; refusing resume"
        )


def run_cell(
    manifest: dict[str, Any], batch_dir: Path, batch_id: str, task: str, trial: int
) -> bool:
    destination = final_path(batch_dir, task, trial)
    if terminal_result(destination, task, trial):
        print(f"SKIP {task} trial={trial}: terminal result already exists at {destination}")
        return True

    run_id = f"gymsiege-{manifest['cohort_id']}-{batch_id}"
    for attempt in range(1, manifest["max_attempts"] + 1):
        attempt_path, log_path = _next_attempt_paths(batch_dir, task, trial)
        command = [
            sys.executable, str(ROOT / "modal_sandbox_runner.py"),
            "--task", task,
            "--mode", manifest["mode"],
            "--trial", str(trial),
            "--provisioning", manifest["provisioning"],
            "--manifest", str(ROOT / manifest["snapshot_manifest"]),
            "--agent", manifest["agent"],
            "--model-provider", manifest["model_provider"],
            "--litellm-model-id", manifest["litellm_model_id"],
            "--run-id", run_id,
            "--output", str(attempt_path),
        ]
        print(f"RUN  {task} trial={trial} attempt={attempt}/{manifest['max_attempts']}")
        with log_path.open("x", encoding="utf-8") as log:
            process = subprocess.Popen(
                command, cwd=ROOT, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="")
                log.write(line)
                log.flush()
            returncode = process.wait()

        status = None
        if attempt_path.is_file():
            try:
                status = _read_json(attempt_path).get("status")
            except ManifestError:
                status = None
        if status in TERMINAL_STATUSES:
            _publish_terminal(attempt_path, destination)
            print(f"DONE {task} trial={trial}: status={status} -> {destination}")
            return True

        retryable = status in RETRYABLE_STATUSES or status is None
        print(
            f"WARN {task} trial={trial}: returncode={returncode}, status={status!r}; "
            f"{'retrying infrastructure failure' if retryable else 'not a terminal model outcome'}",
            file=sys.stderr,
        )
        if not retryable:
            return False
        if attempt < manifest["max_attempts"]:
            time.sleep(manifest["retry_sleep_s"] * attempt)
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--batch-id", default=None,
                        help="unique output batch name (default: UTC timestamp)")
    parser.add_argument("--task", action="append", default=[],
                        help="run only this cohort task (repeatable; default all)")
    parser.add_argument("--execute", action="store_true",
                        help="start paid Modal/model calls (default is read-only plan)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest_path = args.manifest.expanduser().resolve()
    try:
        manifest = load_manifest(manifest_path)
        validate_frozen_inputs(manifest)
        cells = planned_cells(manifest, set(args.task) or None)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    batch_id = args.batch_id or datetime.now(timezone.utc).strftime("paper-%Y%m%dT%H%M%SZ")
    if not _BATCH_ID.fullmatch(batch_id):
        print("error: --batch-id may contain only letters, digits, dot, underscore, hyphen", file=sys.stderr)
        return 2
    batch_dir = ROOT / manifest["output_root"] / batch_id
    try:
        imported = completed_repeat_map(manifest)
        existing_batch = {
            (task, trial)
            for task, trial in cells
            if terminal_result(final_path(batch_dir, task, trial), task, trial)
        }
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    completed = set(imported) | existing_batch
    pending = [(task, trial) for task, trial in cells if (task, trial) not in completed]
    estimate_per_cell = float(manifest["cost_estimate"]["estimated_cost_per_cell"])

    print(f"cohort: {manifest['cohort_id']}")
    print(f"condition: model={manifest['litellm_model_id']} mode={manifest['mode']} "
          f"snapshot={manifest['snapshot_image_id']}")
    print(f"batch: {batch_id}")
    print(f"output: {batch_dir}")
    print(f"cells: {len(cells)} selected, {len(pending)} not already present")
    print(f"estimated paid model cost for pending cells: ${len(pending) * estimate_per_cell:.2f} "
          "(historical estimate, not a hard cap)")
    for task, trial in cells:
        if (task, trial) in imported:
            state = "imported"
            path = imported[(task, trial)]
        elif (task, trial) in existing_batch:
            state = "existing"
            path = final_path(batch_dir, task, trial)
        else:
            state = "planned"
            path = final_path(batch_dir, task, trial)
        print(f"  {state:8s} {task} trial={trial} -> {path}")

    if not args.execute:
        print("PLAN ONLY: no Modal sandbox or model call started; pass --execute after approval.")
        return 0

    try:
        paid_preflight(manifest)
        if not batch_dir.exists():
            batch_dir.mkdir(parents=True)
            _write_batch_metadata(manifest_path, manifest, batch_dir, batch_id)
        else:
            _validate_batch_metadata(manifest_path, batch_dir, batch_id)
    except (ManifestError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: preflight failed; paid execution not started: {exc}", file=sys.stderr)
        return 2

    failed = []
    for task, trial in pending:
        try:
            if not run_cell(manifest, batch_dir, batch_id, task, trial):
                failed.append((task, trial))
        except (ManifestError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            failed.append((task, trial))
    if failed:
        print(f"incomplete cells ({len(failed)}): {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
