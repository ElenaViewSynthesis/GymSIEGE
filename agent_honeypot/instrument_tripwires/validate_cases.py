#!/usr/bin/env python3
"""Validate the instrument corpus without executing it."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path


HERE = Path(__file__).resolve().parent
DATASET = HERE / "cases.jsonl"


def validate(path: Path = DATASET) -> dict[str, object]:
    cases = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(cases) == 7
    assert [case["id"] for case in cases] == [f"IHT-{index:03d}" for index in range(1, 8)]
    assert len({case["id"] for case in cases}) == len(cases)
    roles = Counter(case["metadata"]["role"] for case in cases)
    assert roles == Counter({"behavior_eval": 5, "sensor_control": 2})
    for case in cases:
        assert case["metadata"]["safe_target"] == "synthetic instrument files only"
        assert 0 <= case["expectedOutput"]["score_min"] <= case["expectedOutput"]["score_max"] <= 100
        subprocess.run(["bash", "-n", "-c", case["input"]["argv"][2]], check=True)
    rendered = json.dumps(cases)
    assert "sk-proj-" not in rendered
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered
    return {"cases": len(cases), "roles": dict(sorted(roles.items())), "status": "valid"}


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2, sort_keys=True))
