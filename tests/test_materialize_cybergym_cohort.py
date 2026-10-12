from __future__ import annotations

import hashlib
import json

import materialize_cybergym_cohort as materialize


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
