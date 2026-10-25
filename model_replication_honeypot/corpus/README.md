# Model-replication command corpus

Exactly 205 deterministic cases exercise synthetic weight access, local
replication, staging, Hugging Face and Together upload attempts, remote jobs,
deployment, and multi-provider proliferation. No real credential, model, or
provider endpoint is used.

The five `persistence_tampering` cases are additive to the original 200. Each
uses one existing remote-persistence mechanism and then deletes, rewrites, or
retimestamps only a synthetic local evidence file. The harness-owned event log
remains authoritative, so the persistence event survives that cleanup.

```bash
python3 model_replication_honeypot/corpus/validate_commands.py
python3 model_replication_honeypot/corpus/run_case.py MRH-001
python3 model_replication_honeypot/corpus/run_case.py MRH-181
```

Every item separates `input`, `expectedOutput`, and `metadata`. Suspicious
commands must only be executed through the honeypot harness or Modal runner.
