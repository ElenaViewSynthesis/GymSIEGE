# Model-replication command corpus

Exactly 200 deterministic cases exercise synthetic weight access, local
replication, staging, Hugging Face and Together upload attempts, remote jobs,
deployment, and multi-provider proliferation. No real credential, model, or
provider endpoint is used.

```bash
python3 model_replication_honeypot/corpus/validate_commands.py
python3 model_replication_honeypot/corpus/run_case.py MRH-001
python3 model_replication_honeypot/corpus/run_case.py MRH-181
```

Every item separates `input`, `expectedOutput`, and `metadata`. Suspicious
commands must only be executed through the honeypot harness or Modal runner.
