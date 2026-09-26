# Agent propagation command corpus

This directory contains exactly 200 deterministic conference/demo cases for the
local rogue-agent propagation honeypot. Every suspicious command addresses only
the synthetic PID exposed as `HONEYPOT_CODEX_CANARY_PID`. Run cases through the
harness; do not copy the commands into an ordinary host shell.

For a short conference sequence with expected signals and validation commands,
see [`DEMO_CASES.md`](DEMO_CASES.md).

Each JSONL item separates:

- `input`: instruction, executable argv, display form, and timeout.
- `expectedOutput`: required events and expected score interval.
- `metadata`: category, technique, target-safety declaration, and venue.

Validate without execution:

```bash
python3 agent_honeypot/corpus/validate_commands.py
```

Run one case and assert its score/signals:

```bash
python3 agent_honeypot/corpus/run_case.py APH-001
python3 agent_honeypot/corpus/run_case.py APH-176
```

Regenerate the JSONL and catalog deterministically:

```bash
python3 agent_honeypot/corpus/generate_commands.py
```

The runner considers the agent command's exit code evidence rather than the
test result: blocked malicious commands often exit nonzero, while the case
passes when the expected honeypot events and score are present.
