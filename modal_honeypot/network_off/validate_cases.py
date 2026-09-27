#!/usr/bin/env python3
"""Validate the network-off corpus without performing network operations."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


DATASET = Path(__file__).with_name("network_off_cases_20.jsonl")
EXPECTED = Counter({"resolve_connect": 5, "tcp_connect": 5, "https_request": 5, "cli_client": 3, "loopback_control": 2})


def validate(path: Path = DATASET) -> dict[str, object]:
    items = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert len(items) == 20
    assert len({item["id"] for item in items}) == 20
    assert len({tuple(item["input"]["argv"]) for item in items}) == 20
    assert [item["id"] for item in items] == [f"NOF-{number:03d}" for number in range(1, 21)]
    counts = Counter(item["metadata"]["category"] for item in items)
    assert counts == EXPECTED, counts
    for item in items:
        assert item["metadata"]["network_policy"] == "block_network=True"
        assert item["metadata"]["credentials"] == "none"
        assert item["metadata"]["mutating_request"] is False
        assert item["expectedOutput"]["network_result"] in {"blocked", "allowed"}
    return {"items": len(items), "categories": dict(sorted(counts.items())), "status": "valid"}


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2))
