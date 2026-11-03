#!/usr/bin/env python3
"""Validate the fixed intent corpus and measured network baseline."""

from __future__ import annotations

import importlib.util
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

    # Corpus version 2: the derivation of version 1 (make_experiments_v2.py), the
    # untrusted text inside TASK.md; one twin per intent evaluation, nothing else.
    v2_path = HERE / "experiments-v2.jsonl"
    v2 = [json.loads(line) for line in v2_path.read_text().splitlines() if line.strip()]
    spec = importlib.util.spec_from_file_location("intent_make_v2", HERE / "make_experiments_v2.py")
    make_v2 = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(make_v2)
    assert v2_path.read_text() == make_v2.render(make_v2.derive()), "experiments-v2.jsonl is stale"
    assert [case["id"] for case in v2] == [f"ITH-{index:03d}" for index in range(101, 112)]
    by_id = {case["id"]: case for case in cases}
    for case in v2:
        source = by_id[case["metadata"]["derived_from"]]
        assert source["metadata"]["role"] == "intent_eval" and case["metadata"]["corpus_version"] == 2
        assert case["input"]["context_placement"] == "task"
        assert source["input"]["untrusted_context"] in case["input"]["issue_report"]
        assert "UNTRUSTED_CONTEXT" not in case["input"]["instruction"]
        assert case["expectedOutput"] == source["expectedOutput"]
        for key in ("category", "tripwire", "requires_live_web_search", "role"):
            assert case["metadata"][key] == source["metadata"][key]
    v2_live = [case["id"] for case in v2 if case["metadata"]["requires_live_web_search"]]
    assert v2_live == ["ITH-110", "ITH-111"]
    assert not {case["id"] for case in v2} & set(by_id)
    rendered_v2 = json.dumps(v2)
    assert "sk-proj-" not in rendered_v2 and "BEGIN OPENSSH PRIVATE KEY" not in rendered_v2

    # Probe cases outside both corpora: ITH-901 asks whether a hosted search
    # reaches the model through the gateway; it is never pooled with either corpus.
    probes = [json.loads(line) for line in (HERE / "probes.jsonl").read_text().splitlines() if line.strip()]
    assert [case["id"] for case in probes] == ["ITH-901"]
    for case in probes:
        assert case["metadata"]["role"] == "search_probe" and case["metadata"]["corpus_version"] == "probe"
        assert case["metadata"]["requires_live_web_search"] is True
        assert case["expectedOutput"] == {"max_stage": "none"}
        assert "context_placement" not in case["input"]
    assert not {case["id"] for case in probes} & (set(by_id) | {case["id"] for case in v2})
    rendered_probes = json.dumps(probes)
    assert "sk-proj-" not in rendered_probes and "BEGIN OPENSSH PRIVATE KEY" not in rendered_probes

    baseline = json.loads((HERE / "network_baseline.json").read_text())
    assert baseline["invariants"]["internal"] is True
    assert baseline["invariants"]["task_default_route"] is False
    assert len(baseline["probe_expectations"]) == 9
    return {
        "cases": len(cases),
        "roles": dict(sorted(roles.items())),
        "live_web_search_cases": live,
        "v2_cases": len(v2),
        "v2_live_web_search_cases": v2_live,
        "probe_cases": [case["id"] for case in probes],
        "network_expectations": len(baseline["probe_expectations"]),
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))

