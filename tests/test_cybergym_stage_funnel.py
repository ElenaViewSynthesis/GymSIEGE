from __future__ import annotations

import pytest

from cybergym_stage_funnel import CORE_STAGE_LABELS, _counts
from cybergym_capability_curve_rate import scale_interval, wilson, _z_for


KEYS = [
    "__total__",
    "stage3",
    "isolated_stage3",
    "stage4",
    "isolated_stage4",
    "__success__",
]


def test_four_evidence_labels_match_stored_stage_semantics():
    assert CORE_STAGE_LABELS == (
        ("stage3", "S3 functionality passes"),
        ("isolated_stage3", "S3 offline functionality passes"),
        ("stage4", "S4 ground-truth PoC blocked"),
        ("isolated_stage4", "S4 offline ground-truth PoC blocked"),
    )


def _row(task: str, **updates):
    row = {
        "task": task,
        "status": "failed",
        "stage3": None,
        "isolated_stage3": None,
        "stage4": None,
        "isolated_stage4": None,
        "network_isolated_detonation": False,
        "vul_exit_code": None,
        "fix_exit_code": None,
    }
    row.update(updates)
    return row


def test_funnel_is_cumulative_and_uses_raw_isolated_oracle_evidence():
    rows = [
        _row(
            "p/success",
            status="success",
            stage3="passed",
            isolated_stage3="passed",
            stage4="passed",
            isolated_stage4="passed",
            network_isolated_detonation=True,
            vul_exit_code=1,
            fix_exit_code=0,
        ),
        # Mirrors libdwarf: validator fields pass, but the vulnerable build
        # does not crash, so it cannot clear isolated S3 or re-enter later.
        _row(
            "p/no-crash",
            status="oracle_mismatch",
            stage3="passed",
            isolated_stage3="passed",
            stage4="passed",
            isolated_stage4="passed",
            network_isolated_detonation=True,
            vul_exit_code=0,
            fix_exit_code=0,
        ),
        # A later isolated-stage pass cannot make a failed S4 rung increase.
        _row(
            "p/s4-failed",
            stage3="passed",
            isolated_stage3="passed",
            stage4="failed",
            isolated_stage4="passed",
            network_isolated_detonation=True,
            vul_exit_code=1,
            fix_exit_code=0,
        ),
        # A raw crash does not replace the agent-side S3 verdict.
        _row(
            "p/s3-error",
            stage3="error",
            isolated_stage3="error",
            network_isolated_detonation=True,
            vul_exit_code=1,
            fix_exit_code=127,
        ),
        _row("p/no-patch", status="no_patch"),
    ]

    assert _counts(rows, KEYS, "trial") == [5, 3, 2, 1, 1, 1]


def test_task_funnel_uses_one_cumulative_trial_per_rung():
    rows = [
        _row("p/task", stage3="passed"),
        _row(
            "p/task",
            status="success",
            stage3="passed",
            isolated_stage3="passed",
            stage4="passed",
            isolated_stage4="passed",
            network_isolated_detonation=True,
            vul_exit_code=1,
            fix_exit_code=0,
        ),
    ]

    assert _counts(rows, KEYS, "task") == [1, 1, 1, 1, 1, 1]


def test_scaled_wilson_band_preserves_asymmetric_bounds():
    p, lo, hi = wilson(16, 22, _z_for(0.95))
    scaled_lo, scaled_hi = scale_interval(p, lo, hi, 0.5)

    assert (p, lo, hi) == pytest.approx(
        (16 / 22, 0.518_482_659_9, 0.868_492_397_1), abs=1e-9
    )
    assert scaled_lo == pytest.approx((p + lo) / 2)
    assert scaled_hi == pytest.approx((p + hi) / 2)
