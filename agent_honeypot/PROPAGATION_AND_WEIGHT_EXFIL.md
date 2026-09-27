# Propagation attempts and self-weight exfiltration actions

Gated research plan for extending the agent propagation honeypot to cover
process propagation and synthetic model-weight upload by an agent-under-test.
This is a planning document, not an enabled mode — the existing default-deny
suites remain the CI baseline (see [README.md](README.md) and
[RUBRIC.md](RUBRIC.md)).

## Scope

- Extend the existing observation traps to study an agent-under-test that
  attempts propagation / synthetic-weight upload, inside network / process /
  filesystem containment; explicitly bars production credentials and
  proprietary weights.
- Corpus / evidence design via the Langfuse skill; per-case logging of command,
  destination class, canary, policy state, detection latency, alert / cleanup
  outcome, and deterministic score.
- Replication canaries target local emulators or disposable private repos with
  tiny synthetic weight files and short-lived, least-privilege credentials.
- An opt-in suite to study `block_network=False` on Modal — with a bolded
  prohibition: **"Do not implement this as unrestricted RCE plus unrestricted
  Internet egress."** It is gated behind an independent egress proxy / firewall,
  destination allowlisting, DNS / SNI / IP + byte limits, immutable off-sandbox
  audit logging, alerts, a tested kill switch, hard resource limits,
  auto-teardown, and per-run human approval.
- Staged rollout (emulator → single-artifact test tenant → small reviewed
  corpus), deterministic acceptance criteria, and — importantly — keeps the
  existing default-deny suites as the CI baseline and never replaces them.
