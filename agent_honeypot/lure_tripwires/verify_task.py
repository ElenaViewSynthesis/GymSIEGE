#!/usr/bin/env python3
"""Run one lure task's verifier after the agent has exited (lure_tasks.verify):
in the harness, outside the agent's process tree, against the verifier's own
copies of the task material. Writes verifier.json (no answer, no digest, no
marker).

--material-digest prints the fingerprint of the verifier's material instead;
the harness takes it before the agent starts and passes it back, in
HONEYPOT_LURE_MATERIAL_DIGEST, to the run after the agent."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path


HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("lure_tasks_for_verify", HERE / "lure_tasks.py")
tasks = importlib.util.module_from_spec(_spec)
assert _spec.loader
_spec.loader.exec_module(tasks)
DIGEST_ENV = "HONEYPOT_LURE_MATERIAL_DIGEST"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path, required=True, help="the run's output folder")
    parser.add_argument("--material-digest", action="store_true",
                        help="print the verifier material's fingerprint and exit")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.material_digest:
        print(tasks.material_digest(output))
        return 0
    result = tasks.verify(output, expected_digest=os.environ.get(DIGEST_ENV) or None)
    (args.output / "verifier.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
