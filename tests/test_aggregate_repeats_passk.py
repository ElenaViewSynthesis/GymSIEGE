from __future__ import annotations

import hashlib
import json
import random

import pytest

import aggregate_repeats_passk as agg
import run_modal_repeats as repeats


# ---------------------------------------------------------------- estimators
@pytest.mark.parametrize(
    "n,c,k,expected",
    [
        (5, 0, 1, 0.0),
        (5, 5, 1, 1.0),
        (5, 1, 1, 0.2),
        (5, 1, 5, 1.0),           # any success guarantees pass@n
        (5, 2, 3, 1.0 - 1 / 10),  # C(3,3)/C(5,3) = 1/10
        (1, 0, 1, 0.0),
        (1, 1, 1, 1.0),
    ],
)
def test_pass_at_k_matches_closed_form(n, c, k, expected):
    assert agg.pass_at_k(n, c, k) == pytest.approx(expected)


def test_pass_at_k_rejects_bad_arguments():
    with pytest.raises(ValueError):
        agg.pass_at_k(5, 1, 6)
    with pytest.raises(ValueError):
        agg.pass_at_k(5, 6, 1)


def test_pass_at_1_is_the_plain_rate():
    for n in range(1, 8):
        for c in range(n + 1):
            assert agg.pass_at_k(n, c, 1) == pytest.approx(c / n)


def test_jeffreys_edges_are_pinned_and_bracket_the_rate():
    pytest.importorskip("scipy")
    lo, hi = agg.jeffreys(0, 5)
    assert lo == 0.0 and 0.0 < hi < 1.0
    lo, hi = agg.jeffreys(5, 5)
    assert 0.0 < lo < 1.0 and hi == 1.0
    lo, hi = agg.jeffreys(2, 5)
    assert lo < 0.4 < hi


def test_task_bootstrap_is_deterministic_and_brackets_the_mean():
    vals = [0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0, 1.0]
    a = agg.task_bootstrap(vals, 500, 0)
    b = agg.task_bootstrap(vals, 500, 0)
    assert a == b
    assert a[0] <= sum(vals) / len(vals) <= a[1]
    assert agg.task_bootstrap([1.0, 1.0, 1.0], 100, 0) == (1.0, 1.0)


# ------------------------------------------------------------------ grouping
def _trial(task, trial, status, *, agent=False, online=False, isolated=False, cost=0.1):
    return agg.Trial(
        task=task, trial=trial, status=status, agent_success=agent,
        gt_success=status == "success", online_chain=online,
        isolated_chain=online and isolated, cost_usd=cost, sha256="x", source="s",
    )


def _cohort():
    # a: fails first, then succeeds twice     -> any-later-success, c=2/5
    # b: fails every time                      -> c=0/5
    # c: success first, then never             -> grouped under success, c=1/5
    # d: other_vuln first, one later success   -> c=1/5
    seq = {
        "a/1": ["failed", "success", "failed", "success", "failed"],
        "b/2": ["failed"] * 5,
        "c/3": ["success", "failed", "failed", "failed", "failed"],
        "d/4": ["other_vuln", "failed", "success", "failed", "failed"],
    }
    trials = []
    for task, statuses in seq.items():
        for i, s in enumerate(statuses, start=1):
            trials.append(_trial(task, i, s, agent=(s != "failed"), online=(s != "failed"),
                                 isolated=(s == "success")))
    return trials


def test_first_trial_groups_use_only_later_trials():
    tasks = agg.by_task(_cohort())
    groups = agg.first_trial_groups(tasks, [1, 5], 200, 0, agg._z_for(0.95))
    by_outcome = {g["first_trial_outcome"]: g for g in groups}
    assert [g["first_trial_outcome"] for g in groups] == ["failed", "other_vuln", "success"]
    failed = by_outcome["failed"]
    assert failed["tasks"] == 2 and failed["any_later_success"] == 1
    assert (failed["later_successes"], failed["later_trials"]) == (2, 8)
    # pass@1 over the two failed-first tasks: (2/5 + 0/5) / 2
    assert failed["pass@1"] == pytest.approx(0.2)
    # pass@5: a=1.0, b=0.0
    assert failed["pass@5"] == pytest.approx(0.5)
    success = by_outcome["success"]
    assert success["any_later_success"] == 0 and success["later_successes"] == 0


def test_cohort_passk_means_over_tasks():
    tasks = agg.by_task(_cohort())
    rows = agg.passk_by_task(tasks, [1, 5])
    summary = agg.cohort_passk(rows, [1, 5], 200, 0)
    assert summary["pass@1"]["mean"] == pytest.approx((0.4 + 0.0 + 0.2 + 0.2) / 4)
    assert summary["pass@5"]["mean"] == pytest.approx((1.0 + 0.0 + 1.0 + 1.0) / 4)
    assert summary["pass@5"]["tasks"] == 4


def test_passk_skips_tasks_with_fewer_trials_than_k():
    trials = _cohort() + [_trial("e/5", 1, "success")]
    rows = agg.passk_by_task(agg.by_task(trials), [1, 5])
    e = next(r for r in rows if r["task"] == "e/5")
    assert e["pass@1"] == 1.0 and e["pass@5"] is None
    summary = agg.cohort_passk(rows, [1, 5], 100, 0)
    assert summary["pass@5"]["skipped_tasks_with_n_below_k"] == 1


# ----------------------------------------------------------------- selectors
def test_oracle_selector_equals_pass_at_n_and_random_is_seeded():
    tasks = agg.by_task(_cohort())
    rows = {r["selector"]: r for r in agg.best_of_n(tasks, 5, 200, 0)}
    passk = agg.cohort_passk(agg.passk_by_task(tasks, [5]), [5], 200, 0)
    assert rows["oracle_upper_bound"]["rate"] == pytest.approx(passk["pass@5"]["mean"])
    again = {r["selector"]: r for r in agg.best_of_n(tasks, 5, 200, 0)}
    assert rows["random"]["rate"] == again["random"]["rate"]
    assert rows["random"]["spend_usd"] == pytest.approx(20 * 0.1)


def test_isolated_chain_selector_prefers_isolated_passes():
    tasks = agg.by_task(_cohort())
    rows = {r["selector"]: r for r in agg.best_of_n(tasks, 5, 200, 0)}
    # In the fixture every isolated pass is a success, so the isolated selector
    # recovers every task with any success: a, c, d -> 3/4.
    assert rows["isolated_chain"]["rate"] == pytest.approx(0.75)
    # The agent's report also flags other_vuln attempts, so it can pick a
    # non-success on d; it may not beat the isolated selector.
    assert rows["agent_report"]["rate"] <= rows["isolated_chain"]["rate"]


def test_best_of_n_only_uses_tasks_with_n_attempts():
    trials = _cohort() + [_trial("e/5", 1, "success")]
    rows = agg.best_of_n(agg.by_task(trials), 5, 100, 0)
    assert all(r["tasks"] == 4 for r in rows)


# -------------------------------------------------------------------- loader
def _manifest(tmp_path, trial):
    m = {
        "schema_version": 2, "cohort_id": "rep-test", "benchmark": "cybergym-e2e",
        "mode": "e2e", "provider": "modal", "provisioning": "snapshot",
        "model_provider": "litellm", "litellm_model_id": "m", "agent": "codex",
        "source_revision": {"commit": "c", "dirty": False, "diff_sha256": "d"},
        "snapshot_manifest": "snap.json", "snapshot_manifest_sha256": "s",
        "snapshot_image_id": "im", "ordered_tasks": ["a/1", "b/2"],
        "trial_numbers": [trial], "batch_id": f"rep-test-t{trial}", "smoke_task": "a/1",
        "retry_policy": {"max_attempts": 3, "retry_sleep_s": 0,
                         "retryable_statuses": sorted(repeats.RETRYABLE_STATUSES)},
        "output_root": "out", "paper_output_root": "paper",
        "exclusion_rules": {"terminal_statuses": sorted(repeats.TERMINAL_STATUSES)},
        "cost_estimate": {"planned_cells": 2, "estimated_cost_per_cell": 0.1,
                          "estimated_total": 0.2},
    }
    path = tmp_path / f"rep-test.t{trial}.json"
    path.write_text(json.dumps(m), encoding="utf-8")
    return path, m


def _publish(tmp_path, manifest_path, m, task, trial, status):
    cohort_hash = repeats.manifest_sha256(manifest_path)
    payload = {
        "task": task, "trial": trial, "status": status, "agent_success": status == "success",
        "gt_success": status == "success", "stage1": "passed", "stage2": "passed",
        "stage3": "passed" if status == "success" else "failed", "solver_cost_usd": 0.05,
        "cohort_manifest_sha256": cohort_hash,
        **{k: m[k] for k in ("benchmark", "mode", "provider", "provisioning", "agent",
                             "model_provider", "litellm_model_id", "snapshot_manifest",
                             "snapshot_manifest_sha256", "snapshot_image_id", "cohort_id",
                             "batch_id")},
    }
    batch_dir = tmp_path / m["output_root"] / m["batch_id"]
    dest = repeats.final_path(batch_dir, task, trial)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload), encoding="utf-8")
    return dest


def test_partial_loader_reports_missing_cells_and_validates_payloads(tmp_path):
    p1, m1 = _manifest(tmp_path, 1)
    p2, m2 = _manifest(tmp_path, 2)
    _publish(tmp_path, p1, m1, "a/1", 1, "failed")
    _publish(tmp_path, p1, m1, "b/2", 1, "success")
    _publish(tmp_path, p2, m2, "a/1", 2, "success")
    trials, prov, missing, exclusions = agg.load_trials([p1, p2], tmp_path, allow_partial=True)
    assert {(t.task, t.trial) for t in trials} == {("a/1", 1), ("b/2", 1), ("a/1", 2)}
    assert missing == [("b/2", 2)]
    assert [p["batch_id"] for p in prov] == ["rep-test-t1", "rep-test-t2"]
    assert exclusions == []


def test_partial_loader_rejects_a_payload_from_the_wrong_manifest(tmp_path):
    p1, m1 = _manifest(tmp_path, 1)
    dest = _publish(tmp_path, p1, m1, "a/1", 1, "failed")
    payload = json.loads(dest.read_text())
    payload["cohort_manifest_sha256"] = hashlib.sha256(b"other").hexdigest()
    dest.write_text(json.dumps(payload))
    with pytest.raises(repeats.ManifestError):
        agg.load_trials([p1], tmp_path, allow_partial=True)


def test_loader_refuses_manifests_from_different_conditions(tmp_path):
    p1, m1 = _manifest(tmp_path, 1)
    p2, m2 = _manifest(tmp_path, 2)
    m2["snapshot_image_id"] = "im-other"
    p2.write_text(json.dumps(m2), encoding="utf-8")
    _publish(tmp_path, p1, m1, "a/1", 1, "failed")
    with pytest.raises(repeats.ManifestError):
        agg.load_trials([p1, p2], tmp_path, allow_partial=True)


# --------------------------------------------------------------------- table
def test_table_rows_follow_the_paper_column_order():
    tasks = agg.by_task(_cohort())
    groups = agg.first_trial_groups(tasks, [1, 5], 100, 0, agg._z_for(0.95))
    summary = agg.cohort_passk(agg.passk_by_task(tasks, [1, 5]), [1, 5], 100, 0)
    tex = agg.table_rows_tex("End-to-end", groups, summary, [1, 5], 4)
    first = tex.splitlines()[0]
    assert first.startswith("End-to-end & \\lblFailed{} & 2 & 1 & 2/8 (25.0\\%)")
    assert first.rstrip().endswith("\\\\")
    assert "All 4 valid tasks, End-to-end" in tex
    assert "---" not in first


def _cells(line):
    return line.rstrip().removesuffix("\\\\").split(" & ")


def test_table_rows_emit_one_pass_column_per_k():
    ks = [1, 2, 3]
    tasks = agg.by_task(_cohort())
    groups = agg.first_trial_groups(tasks, ks, 100, 0, agg._z_for(0.95))
    summary = agg.cohort_passk(agg.passk_by_task(tasks, ks), ks, 100, 0)
    lines = agg.table_rows_tex("End-to-end", groups, summary, ks, 4).splitlines()
    rows = [line for line in lines if line.startswith("End-to-end")]
    assert rows and all(len(_cells(r)) == 5 + len(ks) for r in rows)
    total = _cells(lines[-1])
    assert len(total) == 1 + len(ks)
    assert "---" not in lines[-1]


def test_table_rows_name_a_pass_at_k_over_fewer_tasks():
    # A task with one trial counts toward pass@1 but not pass@2, so the totals
    # label must say pass@2 covers fewer tasks than the cohort total.
    ks = [1, 2]
    tasks = agg.by_task(_cohort() + [_trial("e/5", 1, "success")])
    groups = agg.first_trial_groups(tasks, ks, 100, 0, agg._z_for(0.95))
    summary = agg.cohort_passk(agg.passk_by_task(tasks, ks), ks, 100, 0)
    last = agg.table_rows_tex("End-to-end", groups, summary, ks, len(tasks)).splitlines()[-1]
    assert "All 5 valid tasks, End-to-end" in last
    assert "(pass@2 over 4)" in last and "pass@1 over" not in last
    assert len(_cells(last)) == 1 + len(ks)


def test_table_rows_mark_an_undefined_pass_at_k():
    # One trial per task: pass@2 and pass@3 have no eligible task, so they are
    # undefined and must render as ---, never as a zero.
    ks = [1, 2, 3]
    tasks = agg.by_task([t for t in _cohort() if t.trial == 1])
    groups = agg.first_trial_groups(tasks, ks, 100, 0, agg._z_for(0.95))
    summary = agg.cohort_passk(agg.passk_by_task(tasks, ks), ks, 100, 0)
    lines = agg.table_rows_tex("End-to-end", groups, summary, ks, 4).splitlines()
    for row in (line for line in lines if line.startswith("End-to-end")):
        cells = _cells(row)
        assert cells[5].endswith("\\%")
        assert [c.strip() for c in cells[6:]] == ["---", "---"]
    total = [c.strip() for c in _cells(lines[-1])]
    assert "%" in total[1] and total[2:] == ["---", "---"]


# ------------------------------------------------------------------ defaults
def test_defaults_match_two_trials_per_task():
    args = agg.build_parser().parse_args(["--manifest", "m.json", "--out-dir", "out"])
    assert agg.TRIALS_PER_TASK == 2
    assert args.k == [1, 2]
    assert args.n == 2
