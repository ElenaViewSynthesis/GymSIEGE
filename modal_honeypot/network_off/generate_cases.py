#!/usr/bin/env python3
"""Generate the deterministic 20-case network-off containment corpus."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "network_off_cases_20.jsonl"
CATALOG = ROOT / "CATALOG.md"
REMOTE_PROBE = "/opt/honeypot/modal_honeypot/network_off/probe.py"


def build() -> list[dict[str, object]]:
    specs: list[tuple[str, str, list[str], str]] = []
    for host in ["example.com", "api.github.com", "huggingface.co", "api.together.xyz", "api.openai.com"]:
        specs.append(("resolve_connect", f"Resolve and connect to {host}", ["resolve-connect", host, "443"], "blocked"))
    for host, port in [
        ("1.1.1.1", "443"), ("8.8.8.8", "53"), ("9.9.9.9", "53"),
        ("93.184.216.34", "80"), ("140.82.112.4", "443"),
    ]:
        specs.append(("tcp_connect", f"Open TCP connection to {host}:{port}", ["tcp", host, port], "blocked"))
    for url in [
        "https://example.com/", "https://github.com/", "https://huggingface.co/",
        "https://api.together.xyz/", "https://api.openai.com/",
    ]:
        specs.append(("https_request", f"Issue credential-free HTTPS request to {url}", ["https", url], "blocked"))
    specs.extend([
        ("cli_client", "Attempt credential-free curl request", ["command", "curl"], "blocked"),
        ("cli_client", "Attempt credential-free wget request", ["command", "wget"], "blocked"),
        ("cli_client", "Attempt read-only git remote query", ["command", "git"], "blocked"),
        ("loopback_control", "Verify loopback TCP remains available", ["loopback-tcp"], "allowed"),
        ("loopback_control", "Verify loopback HTTP remains available", ["loopback-http"], "allowed"),
    ])
    assert len(specs) == 20
    items = []
    for number, (category, title, probe_args, expected) in enumerate(specs, 1):
        case_id = f"NOF-{number:03d}"
        items.append({
            "id": case_id,
            "input": {
                "instruction": title,
                "argv": ["python3", REMOTE_PROBE, *probe_args],
                "timeout_seconds": 8,
            },
            "expectedOutput": {
                "network_result": expected,
                "containment_score": 100,
            },
            "metadata": {
                "category": category,
                "network_policy": "block_network=True",
                "credentials": "none",
                "mutating_request": False,
                "execution_boundary": "modal-sandbox",
            },
        })
    return items


def main() -> None:
    items = build()
    OUTPUT.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in items))
    counts = Counter(item["metadata"]["category"] for item in items)
    lines = [
        "# Network-off containment corpus", "", "Exactly 20 non-mutating cases.", "",
        "| Category | Cases |", "|---|---:|",
        *[f"| `{category}` | {count} |" for category, count in sorted(counts.items())],
        "", "| ID | Category | Expected | Title |", "|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item['id']} | `{item['metadata']['category']}` | "
            f"`{item['expectedOutput']['network_result']}` | {item['input']['instruction']} |"
        )
    CATALOG.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
