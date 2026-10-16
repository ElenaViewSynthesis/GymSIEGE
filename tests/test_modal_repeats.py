from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import run_modal_repeats as repeats


def test_local_env_fills_empty_defaults_without_overriding_shell(tmp_path, monkeypatch):
    (tmp_path / ".env.local").write_text(
        "MODAL_TOKEN_ID=local-id\nMODAL_TOKEN_SECRET=local-secret\n"
    )
    monkeypatch.setattr(repeats, "ROOT", tmp_path)
    monkeypatch.setenv("MODAL_TOKEN_ID", "")
    monkeypatch.setenv("MODAL_TOKEN_SECRET", "shell-secret")

    repeats._load_local_env()

    assert os.environ["MODAL_TOKEN_ID"] == "local-id"
    assert os.environ["MODAL_TOKEN_SECRET"] == "shell-secret"


def test_modal_command_prefers_cli_next_to_active_python(tmp_path, monkeypatch):
    python = tmp_path / "bin" / "python"
    modal = python.with_name("modal")
    modal.parent.mkdir()
    modal.write_text("#!/bin/sh\n")
    modal.chmod(0o755)
    monkeypatch.setattr(repeats.sys, "executable", str(python))

    assert repeats._modal_command("profile", "current") == [
        str(modal), "profile", "current",
    ]


def _manifest(root: Path) -> Path:
    snapshot = root / "snapshot.json"
    snapshot.write_text(json.dumps({"snapshot_image_id": "im-test", "tasks": ["a/one", "b/two"]}))
    baseline = []
    for task in ("a/one", "b/two"):
        result = root / f"{task.replace('/', '_')}.json"
        result.write_text(json.dumps({"task": task, "trial": 1, "status": "failed"}))
        baseline.append({
            "task": task,
            "result": result.name,
            "sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        })
    path = root / "cohort.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "cohort_id": "test",
        "benchmark": "cybergym-e2e",
        "mode": "patch-only",
        "provider": "modal",
        "provisioning": "snapshot",
        "model_provider": "litellm",
        "litellm_model_id": "gpt-5.6-luna",
        "agent": "codex",
        "snapshot_manifest": snapshot.name,
        "snapshot_image_id": "im-test",
        "baseline_trial": 1,
        "repeat_trials": [2, 3],
        "completed_repeats": [],
        "max_attempts": 3,
        "retry_sleep_s": 0,
        "output_root": "out",
        "cost_estimate": {"estimated_cost_per_cell": 0.1},
        "baseline_results": baseline,
    }))
    return path


def test_manifest_and_frozen_inputs_validate(tmp_path):
    path = _manifest(tmp_path)
    manifest = repeats.load_manifest(path)
    repeats.validate_frozen_inputs(manifest, tmp_path)
    assert repeats.planned_cells(manifest) == [
        ("a/one", 2), ("a/one", 3), ("b/two", 2), ("b/two", 3)
    ]


def test_task_selection_rejects_unknown(tmp_path):
    manifest = repeats.load_manifest(_manifest(tmp_path))
    assert repeats.planned_cells(manifest, {"b/two"}) == [("b/two", 2), ("b/two", 3)]
    with pytest.raises(repeats.ManifestError, match="not in cohort"):
        repeats.planned_cells(manifest, {"missing/task"})


def test_completed_repeat_is_frozen_and_mapped(tmp_path):
    path = _manifest(tmp_path)
    manifest = json.loads(path.read_text())
    completed = tmp_path / "a_one_trial_2.json"
    completed.write_text(json.dumps({"task": "a/one", "trial": 2, "status": "success"}))
    manifest["completed_repeats"] = [{
        "task": "a/one",
        "trial": 2,
        "result": completed.name,
        "sha256": hashlib.sha256(completed.read_bytes()).hexdigest(),
    }]
    path.write_text(json.dumps(manifest))
    loaded = repeats.load_manifest(path)
    repeats.validate_frozen_inputs(loaded, tmp_path)
    assert repeats.completed_repeat_map(loaded, tmp_path) == {
        ("a/one", 2): completed
    }


def test_existing_terminal_result_is_reusable_but_never_overwritten(tmp_path):
    destination = repeats.final_path(tmp_path, "a/one", 2)
    destination.parent.mkdir(parents=True)
    destination.write_text(json.dumps({"task": "a/one", "trial": 2, "status": "success"}))
    assert repeats.terminal_result(destination, "a/one", 2)
    attempt = tmp_path / "attempt.json"
    attempt.write_text(json.dumps({"task": "a/one", "trial": 2, "status": "failed"}))
    with pytest.raises(FileExistsError):
        repeats._publish_terminal(attempt, destination)
    assert json.loads(destination.read_text())["status"] == "success"


def test_nonterminal_final_requires_manual_archive(tmp_path):
    destination = repeats.final_path(tmp_path, "a/one", 2)
    destination.parent.mkdir(parents=True)
    destination.write_text(json.dumps({"task": "a/one", "trial": 2, "status": "error"}))
    with pytest.raises(repeats.ManifestError, match="archive it"):
        repeats.terminal_result(destination, "a/one", 2)


def test_attempt_paths_are_unique_and_nested(tmp_path):
    first_json, first_log = repeats._next_attempt_paths(tmp_path, "a/one", 2)
    first_log.write_text("first")
    second_json, second_log = repeats._next_attempt_paths(tmp_path, "a/one", 2)
    assert first_json.parent == tmp_path / "attempts" / "a_one__trial-2"
    assert (first_json.name, second_json.name) == ("attempt-01.json", "attempt-02.json")
    assert second_log.name == "attempt-02.log"


def test_batch_metadata_prevents_resume_with_changed_manifest(tmp_path):
    manifest_path = _manifest(tmp_path)
    manifest = repeats.load_manifest(manifest_path)
    batch = tmp_path / "batch"
    repeats._write_batch_metadata(manifest_path, manifest, batch, "batch-1")
    repeats._validate_batch_metadata(manifest_path, batch, "batch-1")
    manifest_path.write_text(manifest_path.read_text() + "\n")
    with pytest.raises(repeats.ManifestError, match="changed"):
        repeats._validate_batch_metadata(manifest_path, batch, "batch-1")


@pytest.mark.parametrize("status", ["no_poc", "other_vuln"])
def test_new_terminal_model_outcomes_are_publishable(tmp_path, status):
    destination = repeats.final_path(tmp_path, "a/one", 2)
    destination.parent.mkdir(parents=True)
    destination.write_text(json.dumps({"task": "a/one", "trial": 2, "status": status}))
    assert repeats.terminal_result(destination, "a/one", 2)


@pytest.mark.parametrize("status", ["error", "oracle_unavailable", "timeout"])
def test_infrastructure_or_unknown_outcomes_are_not_terminal(tmp_path, status):
    destination = repeats.final_path(tmp_path, "a/one", 2)
    destination.parent.mkdir(parents=True)
    destination.write_text(json.dumps({"task": "a/one", "trial": 2, "status": status}))
    with pytest.raises(repeats.ManifestError, match="non-terminal"):
        repeats.terminal_result(destination, "a/one", 2)


def test_missing_and_malformed_attempts_are_retryable(tmp_path):
    missing = tmp_path / "missing.json"
    assert repeats.inspect_attempt(missing) == (
        None, "missing_result: runner produced no result JSON", True,
    )
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{")
    status, reason, retryable = repeats.inspect_attempt(malformed)
    assert status is None
    assert reason.startswith("malformed_result:")
    assert retryable is True


@pytest.mark.parametrize("status", sorted(repeats.RETRYABLE_STATUSES))
def test_infrastructure_invalid_attempts_are_retryable(tmp_path, status):
    attempt = tmp_path / "attempt.json"
    attempt.write_text(json.dumps({"status": status}))
    actual, reason, retryable = repeats.inspect_attempt(attempt)
    assert actual == status
    assert reason == f"infrastructure_invalid_status: {status}"
    assert retryable is True
