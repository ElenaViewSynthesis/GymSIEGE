# Daytona support prompt: long-running control calls and restored service state

We are running the public ExploitGym defensive-security benchmark inside
Daytona with the async Python SDK (`daytona==0.207.0`). Each benchmark trial is
restored from the `gymsiege-exploitgym` snapshot, receives its OpenAI key via a
Daytona organization Secret, pulls exactly one `exp.hardened` challenge image,
and runs with ExploitGym's mandatory two-network firewall and LLM proxy.

The working snapshot architecture is now:

- Daytona Debian-slim custom image with a 10 GiB disk (the organization limit);
- Debian's `docker.io` package, which supplies both `/usr/bin/docker` and
  `/usr/sbin/dockerd`—there is no `docker-cli` package in the configured
  Debian repositories and no shell `rehash` is needed because SDK `exec()`
  calls use fresh Bash processes and absolute paths;
- static `socat` and OpenBSD `nc` built in the outer sandbox, avoiding package
  downloads from nested setup containers;
- official glibc Node plus the Codex runtime installed with
  `--codex --skip-node-build`;
- only the small Squid firewall image baked into the snapshot; hardened task
  images are pulled one-per-trial because snapshotting their Docker layers
  exhausts the 10 GiB disk during capture.

The snapshot is active, captured successfully in about 144 seconds, and passed
a restore probe. A real `gpt-5.6-sol` trial then completed 20 model requests
through the restored environment, proving the core snapshot, Docker, proxy,
and model route work end to end.

## Restored controller/proxy processes can have unavailable secrets

If a snapshot contains live ExploitGym controller or LLM-proxy processes,
`pre_run.py` detects and tries to reuse them. Their per-deployment secrets are
not necessarily recoverable after restore, so upstream correctly refuses to
mint mismatched replacements. The supported upstream firewall stop command
only stops its Docker proxy containers; controller and LLM-proxy processes are
host processes with no corresponding stop subcommand.

GYMSIEGE now performs restore hygiene before every trial: it stops the upstream
firewall, terminates only listeners on both upstream default ports (`4000`,
`8666`) and GYMSIEGE's configured ports (`14000`, `18666`), verifies that all
four ports are free, and then lets `pre_run.py` start fresh services and emit a
matched secret set for that trial. A newly built snapshot does not invoke
`pre_run.py`, but this hygiene also makes older snapshots safe to restore.

## SDK control calls can remain silent far beyond their timeout argument

In a serial two-task production run, task one completed normally. Task two
then produced no local result for more than 70 minutes and had to be cancelled.
The orchestrator was awaiting the trial coroutine and surfaced only
`asyncio.CancelledError`; Daytona did not return a timeout or failure. A
subsequent read-only sandbox-list call (`reap --dry-run`) also remained silent
for several minutes and was cancelled. No overlapping sandbox run was started.

The adapter now emits explicit heartbeats around snapshot restore, Secret
attachment and restart, Docker startup, restore hygiene, challenge-image pull,
Node compatibility validation, evaluation, and cleanup. A rerun will identify
which SDK call owns the long tail instead of presenting one opaque wait.

Please clarify the supported Daytona behavior for this workload:

1. Which async SDK calls honor their `timeout=` parameter at the client versus
   the control plane, and what is the expected cancellation behavior?
2. Is there a control-plane operation/status or event endpoint for monitoring
   snapshot restore, sandbox stop/start, image-pull exec, and deletion without
   issuing another long-running sandbox-list call?
3. Does snapshot restore intentionally resume arbitrary host processes and a
   live Docker daemon? If so, is there a documented pre-snapshot or post-restore
   hook for stopping ephemeral services before user code runs?
4. Is outbound HTTPS from Docker containers nested inside Daytona officially
   supported, and how should Daytona's egress proxy, DNS, and CA certificate be
   propagated while retaining outer network controls?
5. Can a cancelled `daytona.create()` or `sandbox.process.exec()` leave an
   operation or sandbox running server-side, and what is the recommended
   idempotent cleanup sequence when `daytona.list()` is also delayed?

Every sandbox receives a 60-minute TTL immediately after creation and is
deleted in a `finally` block, with `orchestrator.py reap` as the backstop. Agent
execution remains isolated by ExploitGym's two-network firewall; Daytona's
organization-level network restriction remains active, and the adapter does
not claim per-sandbox `network_block_all` succeeded when the target rejects
that override.
