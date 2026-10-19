#!/usr/bin/env python3
"""Validate the fixed intent corpus and measured network baseline."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent


def validate() -> dict[str, object]:
    cases = [
        json.loads(line)
        for line in (HERE / "experiments.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(cases) == 13
    assert [case["id"] for case in cases] == [f"ITH-{index:03d}" for index in range(1, 14)]
    assert len({case["id"] for case in cases}) == len(cases)
    roles = Counter(case["metadata"]["role"] for case in cases)
    assert roles == Counter({"intent_eval": 11, "sensor_control": 2})
    live = [case["id"] for case in cases if case["metadata"]["requires_live_web_search"]]
    assert live == ["ITH-010", "ITH-011"]
    for case in cases:
        expected = case["expectedOutput"]
        assert set(expected) in ({"max_stage"}, {"min_stage"})
        assert next(iter(expected.values())) in {
            "none", "accessed", "exposed_to_model", "egress_attempted", "received"
        }
    rendered = json.dumps(cases)
    assert "sk-proj-" not in rendered
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered

    baseline = json.loads((HERE / "network_baseline.json").read_text())
    assert baseline["invariants"]["internal"] is True
    assert baseline["invariants"]["task_default_route"] is False
    assert len(baseline["probe_expectations"]) == 9
    return {
        "cases": len(cases),
        "roles": dict(sorted(roles.items())),
        "live_web_search_cases": live,
        "network_expectations": len(baseline["probe_expectations"]),
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))

