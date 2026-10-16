from __future__ import annotations

import hashlib
import json

import pytest

import materialize_cybergym_cohort as materialize
import run_modal_repeats as repeats


STRICT_FIELDS = {
    "task": "a/one",
    "trial": 1,
    "benchmark": "cybergym-e2e",
    "mode": "e2e",
    "provider": "modal",
    "provisioning": "snapshot",
    "agent": "codex",
    "model_provider": "litellm",
    "litellm_model_id": "gpt-5.6-luna",
    "snapshot_manifest": "snapshot.json",
    "snapshot_manifest_sha256": "snapshot-hash",
    "snapshot_image_id": "im-test",
    "cohort_id": "e2e-test",
    "cohort_manifest_sha256": "manifest-hash",
    "batch_id": "batch-test",
}


def _strict_manifest():
    return {
        "schema_version": 2,
        "benchmark": STRICT_FIELDS["benchmark"],
        "mode": STRICT_FIELDS["mode"],
        "provider": STRICT_FIELDS["provider"],
        "provisioning": STRICT_FIELDS["provisioning"],
        "agent": STRICT_FIELDS["agent"],
        "model_provider": STRICT_FIELDS["model_provider"],
        "litellm_model_id": STRICT_FIELDS["litellm_model_id"],
        "snapshot_manifest": STRICT_FIELDS["snapshot_manifest"],
        "snapshot_manifest_sha256": STRICT_FIELDS["snapshot_manifest_sha256"],
        "snapshot_image_id": STRICT_FIELDS["snapshot_image_id"],
        "cohort_id": STRICT_FIELDS["cohort_id"],
        "batch_id": STRICT_FIELDS["batch_id"],
    }


def test_materializes_declared_baseline_and_repeat(tmp_path):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(json.dumps({"snapshot_image_id": "im-test", "tasks": ["a/one"]}))
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"task": "a/one", "trial": 1, "status": "failed"}))
    repeat = tmp_path / "repeat.json"
    repeat.write_text(json.dumps({"task": "a/one", "trial": 2, "status": "success"}))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "schema_version": 1, "cohort_id": "test", "benchmark": "cybergym-e2e",
        "mode": "patch-only", "provider": "modal", "provisioning": "snapshot",
        "model_provider": "litellm", "litellm_model_id": "gpt-5.6-luna",
        "agent": "codex", "snapshot_manifest": snapshot.name,
        "snapshot_image_id": "im-test", "baseline_trial": 1,
        "repeat_trials": [2], "max_attempts": 3, "retry_sleep_s": 0,
        "output_root": "repeats", "cost_estimate": {"estimated_cost_per_cell": 0.1},
        "baseline_results": [{
            "task": "a/one", "result": baseline.name,
            "sha256": hashlib.sha256(baseline.read_bytes()).hexdigest(),
        }],
        "completed_repeats": [{
            "task": "a/one", "trial": 2, "result": repeat.name,
            "sha256": hashlib.sha256(repeat.read_bytes()).hexdigest(),
        }],
    }))
    input_dir = tmp_path / "paper" / "input"
    rows = materialize.materialize(manifest, input_dir, root=tmp_path)
    assert [row["status"] for row in rows] == ["failed", "success"]
    assert len(list(input_dir.glob("*.json"))) == 2
    assert (input_dir.parent / "cohort.csv").is_file()
    assert (input_dir.parent / "cohort.json").is_file()
    materialize.materialize(manifest, input_dir, root=tmp_path)  # idempotent


@pytest.mark.parametrize("field", list(STRICT_FIELDS))
def test_strict_result_validation_rejects_each_condition_mismatch(field):
    payload = {**STRICT_FIELDS, "status": "success"}
    payload[field] = "wrong" if field != "trial" else 99
    with pytest.raises(repeats.ManifestError, match=field):
        repeats._validate_result_payload(
            payload, _strict_manifest(), "a/one", 1, "manifest-hash",
        )


@pytest.mark.parametrize("field", list(STRICT_FIELDS))
def test_strict_result_validation_rejects_each_missing_condition(field):
    payload = {**STRICT_FIELDS, "status": "success"}
    del payload[field]
    with pytest.raises(repeats.ManifestError, match=field):
        repeats._validate_result_payload(
            payload, _strict_manifest(), "a/one", 1, "manifest-hash",
        )


def test_strict_result_validation_rejects_excluded_status():
    payload = {**STRICT_FIELDS, "status": "oracle_unavailable"}
    with pytest.raises(repeats.ManifestError, match="not terminal"):
        repeats._validate_result_payload(
            payload, _strict_manifest(), "a/one", 1, "manifest-hash",
        )
