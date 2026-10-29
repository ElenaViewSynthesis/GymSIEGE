#!/usr/bin/env python3
"""Validate the collusion corpus without executing any case."""

from __future__ import annotations

import importlib.util
import json
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
DATASET = HERE / "cases.jsonl"


def _generator():
    spec = importlib.util.spec_from_file_location("collusion_generate", HERE / "generate_cases.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def validate(path: Path = DATASET) -> dict[str, object]:
    items = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    generated = _generator().build()
    assert items == generated, "cases.jsonl differs from generate_cases.py"
    assert len(items) == 41
    assert [item["id"] for item in items] == [f"CLH-{index:03d}" for index in range(1, 42)]
    assert len({item["id"] for item in items}) == 41
    roles = Counter(item["metadata"]["role"] for item in items)
    assert roles == Counter({"behavior_eval": 25, "sensor_control": 16}), roles
    valid_stages = {"none", "discovered", "read", "wrote", "exchanged", "acted"}
    for item in items:
        expected = item["expectedOutput"]
        assert ("max_stage" in expected) ^ ("min_stage" in expected)
        assert expected.get("max_stage", expected.get("min_stage")) in valid_stages
        assert item["metadata"]["calibration_stage"] in valid_stages
        assert item["metadata"]["safe_target"] == "synthetic peer runs, markers, tasks, and loopback board only"
        assert item["input"]["runs"] and any(run["kind"] == "subject" for run in item["input"]["runs"])
        assert all(run["kind"] in {"subject", "peer"} for run in item["input"]["runs"])
        verifier = item["input"].get("verifier")
        if verifier is None:
            assert "verifier_passed" not in expected
            continue
        assert verifier["kind"] in {"sha256_of_file", "peer_content_token"}
        assert verifier["answer_path"] == "result/answer.txt"
        assert isinstance(expected.get("verifier_passed"), bool)
        if verifier["kind"] == "sha256_of_file":
            assert verifier["file"] == "src/task.txt"
        else:
            assert verifier["peer"] == "peer"
    rendered = json.dumps(items)
    for forbidden in ("sk-proj-", "BEGIN OPENSSH PRIVATE KEY", "http://", "https://", ".com", ".org", ".net"):
        assert forbidden not in rendered, forbidden
    return {
        "cases": len(items), "roles": dict(sorted(roles.items())),
        "categories": len({item["metadata"]["category"] for item in items}),
        "sensor_controls": [item["id"] for item in items if item["metadata"]["role"] == "sensor_control"],
    }


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
