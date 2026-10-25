#!/usr/bin/env python3
"""Plan or execute manifest-pinned CyberGym repeats without overwriting results.

The default is a read-only plan. Paid execution requires ``--execute``. Each
attempt is written beneath ``attempts/``; only a genuine terminal model outcome
is copied, with exclusive creation, into ``published-results/``. Infrastructure
failures remain auditable in an append-only exclusion ledger outside loader
scope. Schema-v2 E2E manifests also enforce a smoke-first gate.
"""
from __future__ import annotations

import argparse
import copy
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

from common import (
    AGENT_INFRASTRUCTURE_ERROR_REASON,
    TERMINAL_MODEL_STATUSES,
    decide_missing_artifact_infra,
    find_install_marker,
    scan_trajectory_for_gateway_kill,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = ROOT / "reference" / "cybergym_paper_cohort.v1.json"
TERMINAL_STATUSES = set(TERMINAL_MODEL_STATUSES)
RETRYABLE_STATUSES = {"error", "oracle_unavailable"}
_BATCH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
NETWORK_EGRESS_VALUES = {"blocked", "proxy_allowlist", "open"}
NETWORK_SEARCH_VALUES = {"disabled", "live", "cached"}
NETWORK_POLICY_FIELDS = {"egress", "allowlist", "search_mode", "network_access_tasks"}


class ManifestError(ValueError):
    pass


def _validate_network_policy(manifest: dict[str, Any], tasks: list[str]) -> None:
    if "network_policy" not in manifest:
        return
    policy = manifest["network_policy"]
    if not isinstance(policy, dict):
        raise ManifestError("network_policy must be an object")
    missing = sorted(NETWORK_POLICY_FIELDS - policy.keys())
    unknown = sorted(policy.keys() - NETWORK_POLICY_FIELDS)
    if missing:
        raise ManifestError(f"network_policy missing fields: {', '.join(missing)}")
    if unknown:
        raise ManifestError(f"network_policy has unknown fields: {', '.join(unknown)}")
    if policy["egress"] not in NETWORK_EGRESS_VALUES:
        raise ManifestError(f"network_policy.egress must be one of {sorted(NETWORK_EGRESS_VALUES)}")
    if policy["search_mode"] not in NETWORK_SEARCH_VALUES:
        raise ManifestError(
            f"network_policy.search_mode must be one of {sorted(NETWORK_SEARCH_VALUES)}"
        )
    allowlist = policy["allowlist"]
    if (
        not isinstance(allowlist, list)
        or any(not isinstance(host, str) or not host for host in allowlist)
        or len(set(allowlist)) != len(allowlist)
    ):
        raise ManifestError("network_policy.allowlist must contain unique non-empty strings")
    access_tasks = policy["network_access_tasks"]
    if (
        not isinstance(access_tasks, list)
        or any(not isinstance(task, str) or not task for task in access_tasks)
        or len(set(access_tasks)) != len(access_tasks)
    ):
        raise ManifestError(
            "network_policy.network_access_tasks must contain unique non-empty strings"
        )
    outside = sorted(set(access_tasks) - set(tasks))
    if outside:
        raise ManifestError(
            "network_policy.network_access_tasks contains tasks outside the manifest: "
            + ", ".join(outside)
        )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestError(f"expected a JSON object in {path}")
    return payload


def sha256_path(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ManifestError(f"cannot hash {path}: {exc}") from exc


def manifest_sha256(path: Path) -> str:
    return sha256_path(path)


def _tasks(manifest: dict[str, Any]) -> list[str]:
    if manifest["schema_version"] == 2:
        return list(manifest["ordered_tasks"])
    return [entry["task"] for entry in manifest["baseline_results"]]


def _trials(manifest: dict[str, Any]) -> list[int]:
    if manifest["schema_version"] == 2:
        return list(manifest["trial_numbers"])
    return list(manifest["repeat_trials"])


def _max_attempts(manifest: dict[str, Any]) -> int:
    if manifest["schema_version"] == 2:
        return int(manifest["retry_policy"]["max_attempts"])
    return int(manifest["max_attempts"])


def _retry_sleep_s(manifest: dict[str, Any]) -> float:
    if manifest["schema_version"] == 2:
        return float(manifest["retry_policy"]["retry_sleep_s"])
    return float(manifest["retry_sleep_s"])


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = _read_json(path)
    schema_version = manifest.get("schema_version")
    if schema_version not in (1, 2):
        raise ManifestError("unsupported schema_version (expected 1 or 2)")
    if schema_version == 2:
        required = {
            "schema_version", "cohort_id", "benchmark", "mode", "provider",
            "provisioning", "model_provider", "litellm_model_id", "agent",
            "source_revision", "snapshot_manifest", "snapshot_manifest_sha256",
            "snapshot_image_id", "ordered_tasks", "trial_numbers", "batch_id",
            "smoke_task", "retry_policy", "output_root", "exclusion_rules",
            "paper_output_root", "cost_estimate",
        }
        missing = sorted(required - manifest.keys())
        if missing:
            raise ManifestError(f"manifest missing fields: {', '.join(missing)}")
        if manifest["mode"] != "e2e":
            raise ManifestError("schema-v2 paper manifest must declare mode='e2e'")
        tasks = manifest["ordered_tasks"]
        if (
            not isinstance(tasks, list) or not tasks
            or any(not isinstance(task, str) or "/" not in task for task in tasks)
            or len(set(tasks)) != len(tasks)
        ):
            raise ManifestError("ordered_tasks must contain unique project/task_id strings")
        trials = manifest["trial_numbers"]
        if (
            not isinstance(trials, list) or not trials
            or any(not isinstance(trial, int) or trial < 1 for trial in trials)
            or len(set(trials)) != len(trials)
        ):
            raise ManifestError("trial_numbers must contain unique positive integers")
        if manifest["smoke_task"] not in tasks:
            raise ManifestError("smoke_task must be present in ordered_tasks")
        if not _BATCH_ID.fullmatch(str(manifest["batch_id"])):
            raise ManifestError("batch_id contains unsupported characters")
        for field in ("snapshot_manifest", "output_root", "paper_output_root"):
            declared_path = Path(str(manifest[field]))
            if declared_path.is_absolute() or ".." in declared_path.parts:
                raise ManifestError(f"{field} must be a repository-relative path")
        revision = manifest["source_revision"]
        if (
            not isinstance(revision, dict)
            or not revision.get("commit")
            or not isinstance(revision.get("dirty"), bool)
            or not revision.get("diff_sha256")
        ):
            raise ManifestError("source_revision must freeze commit, dirty, and diff_sha256")
        retry = manifest["retry_policy"]
        if not isinstance(retry, dict):
            raise ManifestError("retry_policy must be an object")
        if not isinstance(retry.get("max_attempts"), int) or retry["max_attempts"] < 1:
            raise ManifestError("retry_policy.max_attempts must be a positive integer")
        if not isinstance(retry.get("retry_sleep_s"), (int, float)) or retry["retry_sleep_s"] < 0:
            raise ManifestError("retry_policy.retry_sleep_s must be non-negative")
        if set(retry.get("retryable_statuses", [])) != RETRYABLE_STATUSES:
            raise ManifestError("retry_policy.retryable_statuses does not match runner policy")
        if set(manifest.get("exclusion_rules", {}).get("terminal_statuses", [])) != TERMINAL_STATUSES:
            raise ManifestError("exclusion_rules.terminal_statuses does not match runner policy")
        cost = manifest["cost_estimate"]
        planned_count = len(tasks) * len(trials)
        try:
            per_cell = float(cost["estimated_cost_per_cell"])
            total = float(cost["estimated_total"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ManifestError("cost_estimate must declare per-cell and total estimates") from exc
        if cost.get("planned_cells") != planned_count:
            raise ManifestError("cost_estimate.planned_cells does not match frozen cells")
        if abs(total - per_cell * planned_count) > 1e-9:
            raise ManifestError("cost_estimate.estimated_total does not match per-cell estimate")
        _validate_network_policy(manifest, tasks)
        return manifest

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
    _validate_network_policy(manifest, tasks)
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


def _tracked_diff_sha256(root: Path) -> tuple[bool, str]:
    process = subprocess.run(
        ["git", "diff", "--binary", "HEAD", "--", "."],
        cwd=root, check=True, capture_output=True,
    )
    return bool(process.stdout), hashlib.sha256(process.stdout).hexdigest()


def _validate_source_revision(manifest: dict[str, Any], root: Path) -> None:
    declared = manifest["source_revision"]
    actual_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    if declared.get("commit") != actual_commit:
        raise ManifestError(
            f"source revision mismatch: manifest={declared.get('commit')!r}, "
            f"checkout={actual_commit!r}"
        )
    dirty, diff_hash = _tracked_diff_sha256(root)
    if declared.get("dirty") is not dirty:
        raise ManifestError("source dirty-tree marker does not match the checkout")
    if declared.get("diff_sha256") != diff_hash:
        raise ManifestError("source tracked-diff SHA-256 does not match the checkout")


def validate_frozen_inputs(manifest: dict[str, Any], root: Path = ROOT) -> None:
    snapshot_path = root / manifest["snapshot_manifest"]
    snapshot = _read_json(snapshot_path)
    if manifest["schema_version"] == 2:
        if sha256_path(snapshot_path) != manifest["snapshot_manifest_sha256"]:
            raise ManifestError(f"snapshot manifest SHA-256 mismatch: {snapshot_path}")
        _validate_source_revision(manifest, root)
    if snapshot.get("snapshot_image_id") != manifest["snapshot_image_id"]:
        raise ManifestError(
            "snapshot image mismatch: cohort declares "
            f"{manifest['snapshot_image_id']!r}, {snapshot_path} has "
            f"{snapshot.get('snapshot_image_id')!r}"
        )
    # The manifest's tasks must all be baked into the snapshot, but need not be
    # the whole snapshot: a sub-cohort (e.g. the 2-task install-fix diagnostic
    # pooled with the 22-task paper cohort) declares a subset of the snapshot's
    # tasks. The runner only executes the manifest's ordered_tasks, so an
    # unordered subset check is the correct guarantee; a declared task absent
    # from the snapshot is still rejected.
    snapshot_tasks = set(snapshot.get("tasks") or [])
    missing = [task for task in _tasks(manifest) if task not in snapshot_tasks]
    if missing:
        raise ManifestError(
            f"cohort tasks not present in snapshot manifest: {', '.join(missing)}"
        )

    if manifest["schema_version"] == 2:
        return

    for entry in manifest["baseline_results"]:
        _validate_frozen_result(entry, manifest["baseline_trial"], root)
    for entry in manifest["completed_repeats"]:
        _validate_frozen_result(entry, entry["trial"], root)


def completed_repeat_map(manifest: dict[str, Any], root: Path = ROOT) -> dict[tuple[str, int], Path]:
    if manifest["schema_version"] == 2:
        return {}
    return {
        (entry["task"], entry["trial"]): root / entry["result"]
        for entry in manifest["completed_repeats"]
    }


def planned_cells(
    manifest: dict[str, Any], selected_tasks: set[str] | None = None
) -> list[tuple[str, int]]:
    tasks = _tasks(manifest)
    if selected_tasks:
        unknown = sorted(selected_tasks - set(tasks))
        if unknown:
            raise ManifestError(f"task(s) not in cohort: {', '.join(unknown)}")
        tasks = [task for task in tasks if task in selected_tasks]
    return [(task, trial) for task in tasks for trial in _trials(manifest)]


def _safe_task(task: str) -> str:
    return task.replace("/", "_")


def final_path(batch_dir: Path, task: str, trial: int) -> Path:
    return batch_dir / "published-results" / f"{_safe_task(task)}__trial-{trial}.json"


def _validate_result_payload(
    payload: dict[str, Any], manifest: dict[str, Any], task: str, trial: int,
    cohort_hash: str,
) -> None:
    expected = {
        "task": task,
        "trial": trial,
        "benchmark": manifest["benchmark"],
        "mode": manifest["mode"],
        "provider": manifest["provider"],
        "provisioning": manifest["provisioning"],
        "agent": manifest["agent"],
        "model_provider": manifest["model_provider"],
        "litellm_model_id": manifest["litellm_model_id"],
        "snapshot_manifest": manifest["snapshot_manifest"],
        "snapshot_manifest_sha256": manifest["snapshot_manifest_sha256"],
        "snapshot_image_id": manifest["snapshot_image_id"],
        "cohort_id": manifest["cohort_id"],
        "cohort_manifest_sha256": cohort_hash,
        "batch_id": manifest["batch_id"],
    }
    if "network_policy" in manifest:
        expected["network_policy"] = manifest["network_policy"]
    for field, value in expected.items():
        if field not in payload:
            raise ManifestError(f"result missing frozen condition field {field!r}")
        if payload[field] != value:
            raise ManifestError(
                f"result condition mismatch for {field}: expected {value!r}, "
                f"got {payload[field]!r}"
            )
    if payload.get("status") not in TERMINAL_STATUSES:
        raise ManifestError(f"result status is not terminal: {payload.get('status')!r}")


def terminal_result(
    path: Path, task: str, trial: int, *, manifest: dict[str, Any] | None = None,
    cohort_hash: str | None = None,
) -> bool:
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
    if manifest is not None and manifest["schema_version"] == 2:
        if cohort_hash is None:
            raise ManifestError("cohort hash is required for schema-v2 result validation")
        _validate_result_payload(payload, manifest, task, trial, cohort_hash)
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


def _result_for_publication(
    payload: dict[str, Any], manifest: dict[str, Any],
) -> dict[str, Any]:
    """Return a publication payload with the frozen network policy attached."""
    published = copy.deepcopy(payload)
    if "network_policy" not in manifest:
        return published
    declared = manifest["network_policy"]
    existing = published.get("network_policy")
    if existing is not None and existing != declared:
        raise ManifestError("attempt network_policy conflicts with the frozen manifest")
    published["network_policy"] = copy.deepcopy(declared)
    return published


def _publish_payload(payload: dict[str, Any], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as target:
        json.dump(payload, target, indent=2, sort_keys=True)
        target.write("\n")


def _publication_path(batch_dir: Path, task: str, trial: int) -> Path:
    return batch_dir / "_meta" / "publications" / f"{_safe_task(task)}__trial-{trial}.json"


def _publish_validated_terminal(
    attempt_path: Path, destination: Path, batch_dir: Path, task: str, trial: int,
    attempt_number: int, manifest: dict[str, Any], cohort_hash: str,
) -> None:
    payload = _read_json(attempt_path)
    published = _result_for_publication(payload, manifest)
    _validate_result_payload(published, manifest, task, trial, cohort_hash)
    if "network_policy" in manifest:
        _publish_payload(published, destination)
    else:
        _publish_terminal(attempt_path, destination)
    record = {
        "task": task,
        "trial": trial,
        "attempt": attempt_number,
        "status": payload["status"],
        "attempt_artifact": str(attempt_path.relative_to(ROOT)),
        "attempt_sha256": sha256_path(attempt_path),
        "published_result": str(destination.relative_to(ROOT)),
        "published_result_sha256": sha256_path(destination),
        "cohort_manifest_sha256": cohort_hash,
    }
    if "network_policy" in manifest:
        record["network_policy"] = copy.deepcopy(manifest["network_policy"])
    publication = _publication_path(batch_dir, task, trial)
    publication.parent.mkdir(parents=True, exist_ok=True)
    with publication.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)
        handle.write("\n")


def _write_failure_artifact(
    result_path: Path, *, task: str, trial: int, attempt: int,
    returncode: int, reason: str,
) -> Path:
    failure_path = result_path.with_suffix(".failure.json")
    payload = {
        "artifact_kind": "runner_failure",
        "task": task,
        "trial": trial,
        "attempt": attempt,
        "returncode": returncode,
        "reason": reason,
    }
    with failure_path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return failure_path


def _record_exclusion(
    batch_dir: Path, *, task: str, trial: int, attempt: int,
    artifact_path: Path, status: Any, reason: str,
) -> None:
    row = {
        "task": task,
        "trial": trial,
        "attempt": attempt,
        "artifact": str(artifact_path.relative_to(ROOT)),
        "sha256": sha256_path(artifact_path),
        "status": status,
        "reason": reason,
    }
    ledger = batch_dir / "_meta" / "excluded_trials.jsonl"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _load_local_env() -> None:
    try:
        from dotenv import dotenv_values
    except ImportError as exc:  # pragma: no cover - dependency is in requirements
        raise ManifestError("python-dotenv is required for paid execution") from exc
    # ``common`` loads .env.defaults first, where credential placeholders are
    # intentionally empty.  python-dotenv treats those empty strings as set, so
    # load_dotenv(..., override=False) would never hydrate the real local values.
    # Fill only missing/empty variables to preserve any non-empty shell override.
    for name, value in dotenv_values(ROOT / ".env.local").items():
        if value is not None and not os.environ.get(name):
            os.environ[name] = value


def _modal_command(*args: str) -> list[str]:
    venv_modal = Path(sys.executable).with_name("modal")
    if venv_modal.is_file() and os.access(venv_modal, os.X_OK):
        return [str(venv_modal), *args]
    modal = shutil.which("modal")
    if modal:
        return [modal, *args]
    raise ManifestError("Modal CLI is not installed; paid execution not started")


def paid_preflight(manifest: dict[str, Any]) -> None:
    _load_local_env()
    for name in ("MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "LITELLM_BASE_URL"):
        if not os.environ.get(name):
            raise ManifestError(f"{name} is not set; paid execution not started")
    try:
        socket.getaddrinfo("api.modal.com", 443)
    except OSError as exc:
        raise ManifestError(f"cannot resolve api.modal.com; paid execution not started: {exc}") from exc
    subprocess.run(_modal_command("profile", "current"), cwd=ROOT, check=True)
    secrets = subprocess.run(
        _modal_command("secret", "list"), cwd=ROOT, check=True,
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
    (batch_dir / "_meta" / "excluded_trials.jsonl").touch(exist_ok=False)


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


def inspect_attempt(path: Path) -> tuple[Any, str | None, bool]:
    """Return (status, exclusion reason, retryable) without mutating an attempt."""
    if not path.is_file():
        return None, "missing_result: runner produced no result JSON", True
    try:
        status = _read_json(path).get("status")
    except ManifestError as exc:
        return None, f"malformed_result: {exc}", True
    if status in TERMINAL_STATUSES:
        return status, None, False
    if status in RETRYABLE_STATUSES:
        return status, f"infrastructure_invalid_status: {status}", True
    return status, f"unrecognized_nonterminal_status: {status!r}", False


def reconcile_attempt_outcomes(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconcile preserved attempts without changing the live publish path.

    The function is intentionally pure: callers pass already-loaded attempt
    dictionaries. ``trajectory_event_lines`` may contain the bounded structured
    stream emitted by the sandbox scanner, and ``run_agent_log`` may contain the
    wrapper log used to audit a suspicious ``no_patch``/``no_poc`` result.

    A genuine success outranks every other outcome regardless of position. If
    no success exists, the first genuine terminal outcome wins. Infrastructure
    evidence invalidates an attempt before terminal selection; if every attempt
    is invalid, the reconciled status is ``infrastructure_invalid``.
    """
    audited: list[dict[str, Any]] = []
    genuine: list[dict[str, Any]] = []
    for index, attempt in enumerate(attempts, 1):
        status = attempt.get("status")
        attempt_number = attempt.get("attempt", index)
        invalid_reason: str | None = None
        if status in RETRYABLE_STATUSES or status in {"gateway_kill", "infrastructure_invalid"}:
            invalid_reason = f"infrastructure status: {status}"
        elif attempt.get("failure_reason") == AGENT_INFRASTRUCTURE_ERROR_REASON:
            invalid_reason = AGENT_INFRASTRUCTURE_ERROR_REASON

        raw_lines = attempt.get("trajectory_event_lines", [])
        if isinstance(raw_lines, str):
            event_lines = raw_lines.splitlines()
        elif isinstance(raw_lines, list) and all(isinstance(line, str) for line in raw_lines):
            event_lines = list(raw_lines)
        else:
            event_lines = []
        gateway_marker: str | None = None
        if event_lines:
            killed, marker = scan_trajectory_for_gateway_kill(event_lines)
            gateway_marker = marker if killed else None

        if invalid_reason is None and status in {"no_patch", "no_poc"}:
            run_agent_log = attempt.get("run_agent_log", "")
            if not isinstance(run_agent_log, str):
                run_agent_log = ""
            failure_reason, failure_detail = decide_missing_artifact_infra(
                gateway_marker=gateway_marker,
                install_marker=find_install_marker(run_agent_log),
                solver_cost=attempt.get("solver_cost_usd"),
                has_trajectory=bool(event_lines),
            )
            if failure_reason:
                invalid_reason = failure_detail or failure_reason
        elif invalid_reason is None and gateway_marker:
            invalid_reason = f"gateway/tunnel failure: {gateway_marker}"

        audit = {
            "attempt": attempt_number,
            "status": status,
            "infrastructure_invalid": invalid_reason is not None,
            "audit_reason": invalid_reason,
        }
        audited.append(audit)
        if invalid_reason is None and status in TERMINAL_STATUSES:
            genuine.append(audit)

    successes = [attempt for attempt in genuine if attempt["status"] == "success"]
    if successes:
        winner = successes[0]
        reason = "successful_terminal_outcome_outranks_other_attempts"
    elif genuine:
        winner = genuine[0]
        reason = "first_genuine_terminal_outcome"
    else:
        return {
            "status": "infrastructure_invalid",
            "winning_attempt": None,
            "reason": "all_attempts_infrastructure_invalid",
            "attempts": audited,
        }
    return {
        "status": winner["status"],
        "winning_attempt": winner["attempt"],
        "reason": reason,
        "attempts": audited,
    }


def run_cell(
    manifest: dict[str, Any], manifest_path: Path, batch_dir: Path,
    batch_id: str, task: str, trial: int,
) -> bool:
    cohort_hash = manifest_sha256(manifest_path)
    destination = final_path(batch_dir, task, trial)
    if terminal_result(
        destination, task, trial, manifest=manifest, cohort_hash=cohort_hash,
    ):
        print(f"SKIP {task} trial={trial}: terminal result already exists at {destination}")
        return True

    run_id = f"gymsiege-{manifest['cohort_id']}-{batch_id}"
    max_attempts = _max_attempts(manifest)
    for _ in range(max_attempts):
        attempt_path, log_path = _next_attempt_paths(batch_dir, task, trial)
        attempt = int(attempt_path.stem.removeprefix("attempt-"))
        if attempt > max_attempts:
            print(
                f"WARN {task} trial={trial}: retry policy exhausted "
                f"({max_attempts} attempts preserved)", file=sys.stderr,
            )
            return False
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
        if manifest["schema_version"] == 2:
            command.extend([
                "--snapshot-manifest-id", manifest["snapshot_manifest"],
                "--snapshot-manifest-sha256", manifest["snapshot_manifest_sha256"],
                "--cohort-id", manifest["cohort_id"],
                "--cohort-manifest-sha256", cohort_hash,
                "--batch-id", batch_id,
            ])
        print(f"RUN  {task} trial={trial} attempt={attempt}/{max_attempts}")
        with log_path.open("x", encoding="utf-8") as log:
            try:
                process = subprocess.Popen(
                    command, cwd=ROOT, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, bufsize=1,
                )
            except OSError as exc:
                returncode = 127
                log.write(f"runner launch failed: {type(exc).__name__}: {exc}\n")
                log.flush()
            else:
                assert process.stdout is not None
                for line in process.stdout:
                    print(line, end="")
                    log.write(line)
                    log.flush()
                returncode = process.wait()

        status, exclusion_reason, retryable = inspect_attempt(attempt_path)
        exclusion_artifact = attempt_path
        if not attempt_path.is_file():
            exclusion_artifact = _write_failure_artifact(
                attempt_path, task=task, trial=trial, attempt=attempt,
                returncode=returncode, reason=exclusion_reason or "missing_result",
            )
        if status in TERMINAL_STATUSES:
            try:
                if manifest["schema_version"] == 2:
                    _publish_validated_terminal(
                        attempt_path, destination, batch_dir, task, trial, attempt,
                        manifest, cohort_hash,
                    )
                else:
                    if "network_policy" in manifest:
                        _publish_payload(
                            _result_for_publication(_read_json(attempt_path), manifest),
                            destination,
                        )
                    else:
                        _publish_terminal(attempt_path, destination)
            except ManifestError as exc:
                exclusion_reason = f"condition_mismatch: {exc}"
                retryable = False
            else:
                print(f"DONE {task} trial={trial}: status={status} -> {destination}")
                return True

        if exclusion_reason is None:
            exclusion_reason = f"unrecognized_nonterminal_status: {status!r}"
        _record_exclusion(
            batch_dir, task=task, trial=trial, attempt=attempt,
            artifact_path=exclusion_artifact, status=status, reason=exclusion_reason,
        )
        print(
            f"WARN {task} trial={trial}: returncode={returncode}, status={status!r}; "
            f"{exclusion_reason}; {'retrying' if retryable else 'stopping cell'}",
            file=sys.stderr,
        )
        if not retryable:
            return False
        if attempt < max_attempts:
            time.sleep(_retry_sleep_s(manifest) * attempt)
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--batch-id", default=None,
                        help="unique output batch name (default: UTC timestamp)")
    parser.add_argument("--task", action="append", default=[],
                        help="run only this cohort task (repeatable; default all)")
    parser.add_argument(
        "--phase", choices=("plan", "smoke", "full"), default="plan",
        help="schema-v2 gate: read-only full plan, paid smoke, or paid full continuation",
    )
    parser.add_argument(
        "--approved-smoke-sha256", default=None,
        help="required for schema-v2 full execution; exact reviewed smoke result hash",
    )
    parser.add_argument("--execute", action="store_true",
                        help="start paid Modal/model calls (default is read-only plan)")
    return parser


def _validate_smoke_approval(
    manifest: dict[str, Any], batch_dir: Path, cohort_hash: str,
    approved_hash: str | None,
) -> None:
    trials = _trials(manifest)
    if len(trials) != 1:
        raise ManifestError("smoke approval currently requires exactly one trial number")
    task, trial = manifest["smoke_task"], trials[0]
    result_path = final_path(batch_dir, task, trial)
    if not terminal_result(
        result_path, task, trial, manifest=manifest, cohort_hash=cohort_hash,
    ):
        raise ManifestError("reviewed smoke result does not exist")
    actual_hash = sha256_path(result_path)
    if not approved_hash:
        raise ManifestError(
            "full execution requires --approved-smoke-sha256 after manual smoke review; "
            f"current smoke hash is {actual_hash}"
        )
    if approved_hash != actual_hash:
        raise ManifestError("approved smoke hash does not match the published smoke result")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manifest_path = args.manifest.expanduser().resolve()
    try:
        manifest = load_manifest(manifest_path)
        validate_frozen_inputs(manifest)
        all_cells = planned_cells(manifest, set(args.task) or None)
    except (ManifestError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if manifest["schema_version"] == 2:
        if args.batch_id and args.batch_id != manifest["batch_id"]:
            print("error: --batch-id must match the frozen schema-v2 batch_id", file=sys.stderr)
            return 2
        if args.execute and args.phase == "plan":
            print("error: --execute requires --phase smoke or --phase full", file=sys.stderr)
            return 2
        if args.execute and args.task:
            print("error: schema-v2 paid execution does not allow --task to bypass phase gates", file=sys.stderr)
            return 2
        batch_id = manifest["batch_id"]
        if args.phase == "smoke":
            cells = planned_cells(manifest, {manifest["smoke_task"]})
        else:
            cells = all_cells
    else:
        batch_id = args.batch_id or datetime.now(timezone.utc).strftime("paper-%Y%m%dT%H%M%SZ")
        cells = all_cells
    if not _BATCH_ID.fullmatch(batch_id):
        print("error: --batch-id may contain only letters, digits, dot, underscore, hyphen", file=sys.stderr)
        return 2
    batch_dir = ROOT / manifest["output_root"] / batch_id
    cohort_hash = manifest_sha256(manifest_path)
    try:
        imported = completed_repeat_map(manifest)
        existing_batch = {
            (task, trial)
            for task, trial in cells
            if terminal_result(
                final_path(batch_dir, task, trial), task, trial,
                manifest=manifest, cohort_hash=cohort_hash,
            )
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
    print(f"manifest sha256: {cohort_hash}")
    print(f"output: {batch_dir}")
    print(f"phase: {args.phase}")
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
        print(
            "PLAN ONLY: no Modal sandbox or model call started; use --phase smoke "
            "--execute only after explicit paid-run approval."
        )
        return 0

    try:
        if manifest["schema_version"] == 2 and args.phase == "full":
            _validate_smoke_approval(
                manifest, batch_dir, cohort_hash, args.approved_smoke_sha256,
            )
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
            if not run_cell(manifest, manifest_path, batch_dir, batch_id, task, trial):
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
