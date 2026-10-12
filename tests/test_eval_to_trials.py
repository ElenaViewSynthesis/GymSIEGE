"""Tests for eval_to_trials.py -- the CVE-bench .eval -> trial-JSON adapter.

Mirrors tests/test_cve_eval_actions.py's in-memory .eval builder (a ZIP_STORED
archive with header.json + samples/*.json, so no zstd codec is needed).
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

import eval_to_trials as e2t
from cybergym_capability_curve import load_trials

extractor = e2t._load_extractor()


# ---------------------------------------------------------------------------
# .eval fixture builder
# ---------------------------------------------------------------------------
def _sample(
    *,
    sample_id="CVE-2024-36412_one_day",
    epoch=1,
    started_at="2026-01-01T00:00:00Z",
    completed_at="2026-01-01T00:01:00Z",
    check_exploit=0,
    error=None,
    grader_error=False,
):
    sample: dict = {
        "id": sample_id,
        "epoch": epoch,
        "started_at": started_at,
        "completed_at": completed_at,
        "turn_count": 1,
        "error_retries": 0,
        "messages": [],
        "events": [],
        "scores": {"check_exploit": {"value": check_exploit}},
        "output": {"choices": [{"message": {"content": ""}}]},
    }
    if error is not None:
        sample["error"] = error
    if grader_error:
        sample["events"].append({"event": "grader_error", "detail": "grader crashed"})
    return sample


def _write_eval(path: Path, samples, *, status="success", challenges="CVE-2024-36412"):
    header = {
        "status": status,
        "eval": {
            "eval_id": "eval-1",
            "run_id": "run-1",
            "task": "cvebench",
            "model": "openai/test",
            "task_args": {"challenges": challenges},
            "revision": "abc123",
            "packages": {"inspect_ai": "0.3.268"},
        },
        "stats": {"started_at": "start", "completed_at": "end", "model_usage": {}},
        "results": {"total_samples": len(samples)},
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("header.json", json.dumps(header))
        for i, sample in enumerate(samples):
            archive.writestr(f"samples/sample_{i}.json", json.dumps(sample))


def _convert(path: Path):
    report = extractor.extract_eval(path)
    return e2t.eval_to_trials(report, benchmark="cve-bench", used=set(), warnings=[])


# ---------------------------------------------------------------------------
# suffix stripping / keying
# ---------------------------------------------------------------------------
def test_task_from_sample_id_strips_variant_suffix():
    assert e2t.task_from_sample_id("CVE-2024-36412_one_day") == "CVE-2024-36412"
    assert e2t.task_from_sample_id("CVE-2024-36412_zero_day") == "CVE-2024-36412"
    assert e2t.task_from_sample_id("CVE-2024-36412-one_day") == "CVE-2024-36412"
    assert e2t.task_from_sample_id("CVE-2024-36412-zero_day") == "CVE-2024-36412"
    # no suffix -> unchanged
    assert e2t.task_from_sample_id("CVE-2024-36412") == "CVE-2024-36412"


def test_task_is_not_the_inspect_task_name(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(path, [_sample(sample_id="CVE-2024-36412_one_day")])
    trials, _ = _convert(path)
    assert trials[0]["task"] == "CVE-2024-36412"
    # The Inspect task name "cvebench" must never become the forest key.
    assert trials[0]["task"] != "cvebench"


# ---------------------------------------------------------------------------
# status mapping
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        (1, "success"),
        (0, "failed"),
        (True, "success"),
        (False, "failed"),
        (None, "failed"),
        ("C", "success"),
        ("CORRECT", "success"),
        ("I", "failed"),
        ("INCORRECT", "failed"),
    ],
)
def test_status_from_check(value, expected):
    assert e2t.status_from_check(value) == expected


def test_status_mapping_end_to_end(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(
        path,
        [
            _sample(sample_id="CVE-A_one_day", epoch=1, check_exploit=1,
                    started_at="2026-01-01T00:00:00Z"),
            _sample(sample_id="CVE-A_one_day", epoch=2, check_exploit=0,
                    started_at="2026-01-01T00:02:00Z"),
        ],
        challenges="CVE-A",
    )
    trials, excluded = _convert(path)
    assert excluded == 0
    by_epoch = {t["epoch"]: t["status"] for t in trials}
    assert by_epoch == {1: "success", 2: "failed"}


# ---------------------------------------------------------------------------
# infra-invalid exclusion -- never recorded as "failed"
# ---------------------------------------------------------------------------
def test_sample_error_is_excluded_not_failed(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(path, [_sample(error={"message": "sandbox crashed"}, check_exploit=0)])
    trials, excluded = _convert(path)
    assert trials == []
    assert excluded == 1


def test_grader_error_is_excluded(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(path, [_sample(grader_error=True, check_exploit=0)])
    trials, excluded = _convert(path)
    assert trials == []
    assert excluded == 1


def test_run_status_not_success_excludes_all(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(
        path,
        [_sample(sample_id="CVE-A_one_day"), _sample(sample_id="CVE-B_one_day")],
        status="error",
    )
    trials, excluded = _convert(path)
    assert trials == []
    assert excluded == 2


# ---------------------------------------------------------------------------
# (task, started_at) uniqueness -- a collision must not drop an epoch
# ---------------------------------------------------------------------------
def test_duplicate_started_at_is_disambiguated(tmp_path):
    path = tmp_path / "run.eval"
    # Two epochs stamped with the SAME started_at and no completed_at to fall
    # back to, forcing the advance-by-epoch-seconds path.
    _write_eval(
        path,
        [
            _sample(sample_id="CVE-A_one_day", epoch=1,
                    started_at="2026-01-01T00:00:00Z", completed_at=None, check_exploit=1),
            _sample(sample_id="CVE-A_one_day", epoch=2,
                    started_at="2026-01-01T00:00:00Z", completed_at=None, check_exploit=0),
        ],
        challenges="CVE-A",
    )
    out = tmp_path / "trials"
    rc = e2t.main([str(path), "--out-dir", str(out)])
    assert rc == 0

    # Both epochs land as distinct files...
    assert len(list(out.glob("*.json"))) == 2
    # ...and both survive load_trials' (task, started_at) dedup.
    rows = load_trials([str(out)], [])
    assert len(rows) == 2
    assert all(r["task"] == "CVE-A" for r in rows)
    assert len({r["started_at"] for r in rows}) == 2


# ---------------------------------------------------------------------------
# end-to-end: emitted dir is consumable by the forest's loader
# ---------------------------------------------------------------------------
def test_emitted_dir_loads_via_load_trials(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(
        path,
        [
            _sample(sample_id="CVE-2024-36412_one_day", check_exploit=1,
                    started_at="2026-01-01T00:00:00Z"),
            _sample(sample_id="CVE-2024-0001_one_day", check_exploit=0,
                    started_at="2026-01-01T00:03:00Z"),
        ],
        challenges="CVE-2024-36412",
    )
    out = tmp_path / "trials"
    assert e2t.main([str(path), "--out-dir", str(out)]) == 0
    rows = load_trials([str(out)], [])
    status_by_task = {r["task"]: r["status"] for r in rows}
    assert status_by_task == {"CVE-2024-36412": "success", "CVE-2024-0001": "failed"}


def test_provenance_fields_present(tmp_path):
    path = tmp_path / "run.eval"
    _write_eval(path, [_sample(sample_id="CVE-A_one_day", check_exploit=1)], challenges="CVE-A")
    trials, _ = _convert(path)
    t = trials[0]
    assert t["benchmark"] == "cve-bench"
    assert t["epoch"] == 1
    assert t["check_exploit_value"] == 1
    assert t["source_eval"] == str(path)
    assert "solver_cost_usd" not in t  # optional + absent for CVE-bench


def test_write_is_idempotent_but_refuses_different_existing_result(tmp_path):
    trial = {
        "task": "CVE-A", "epoch": 1,
        "started_at": "2026-01-01T00:00:00Z", "status": "failed",
    }
    e2t._write_trials([trial], tmp_path)
    e2t._write_trials([trial], tmp_path)
    path = next(tmp_path.glob("*.json"))
    path.write_text("{}\n")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        e2t._write_trials([trial], tmp_path)


# ---------------------------------------------------------------------------
# forest --title: override vs. the byte-for-byte CyberGym default
# ---------------------------------------------------------------------------
def _render_title(monkeypatch, *, title):
    from unittest import mock

    pytest.importorskip("matplotlib")
    pytest.importorskip("numpy")
    import matplotlib.pyplot as plt
    import cybergym_task_forest as forest

    fig, ax = mock.MagicMock(), mock.MagicMock()
    monkeypatch.setattr(plt, "subplots", lambda *a, **k: (fig, ax))
    rows = [{"task": "CVE-A", "status": "success", "started_at": "2026-01-01T00:00:00Z"}]
    # wilson avoids the SciPy dependency of jeffreys/clopper.
    forest.render(rows, Path("/tmp/ignored.png"), 0.95, "wilson", title)
    return [c.args[0] for c in ax.set_title.call_args_list]


def test_forest_title_override(monkeypatch):
    titles = _render_title(monkeypatch, title="CVE-bench per-task exploit success")
    assert "CVE-bench per-task exploit success" in titles


def test_forest_title_default_unchanged(monkeypatch):
    titles = _render_title(monkeypatch, title=None)
    assert "CyberGym per-task capability  (wilson 95% CI, S1–S4 oracle)" in titles
