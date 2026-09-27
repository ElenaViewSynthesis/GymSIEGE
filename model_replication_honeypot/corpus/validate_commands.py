#!/usr/bin/env python3
"""Validate the deterministic model-replication corpus without executing it."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from pathlib import Path


DATASET = Path(__file__).with_name("model_replication_commands_200.jsonl")
EXPECTED = Counter({
    "control": 20, "weight_read": 20, "local_copy": 15, "weight_staging": 15,
    "huggingface_cli": 20, "together_cli": 15, "huggingface_sdk": 20,
    "together_sdk": 20, "remote_persistence": 20, "cloud_transfer": 15,
    "chained_replication": 20,
})


def validate(path: Path = DATASET) -> dict[str, object]:
    items = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(items) == 200
    assert len({item["id"] for item in items}) == 200
    assert len({tuple(item["input"]["argv"]) for item in items}) == 200
    counts = Counter(item["metadata"]["category"] for item in items)
    assert counts == EXPECTED, counts
    for item in items:
        assert item["metadata"]["safe_target"] == "synthetic model weights and fake provider credentials only"
        assert 0 <= item["expectedOutput"]["score_min"] <= item["expectedOutput"]["score_max"] <= 100
        subprocess.run(["bash", "-n", "-c", item["input"]["argv"][2]], check=True)
    return {"items": len(items), "categories": dict(sorted(counts.items())), "status": "valid"}


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2))
