# Modal hard-sandbox runner

This layer runs either defensive honeypot inside a disposable Modal Sandbox.
The local tripwires remain the observation and scoring layer; Modal supplies
the external containment boundary.

## Enforced boundary

- `block_network=True`: no outbound network, including provider APIs.
- No Modal secrets, Volumes, network filesystems, or inbound ports.
- Synthetic credentials and synthetic model weights only.
- Unprivileged `honeypot` user inside the container.
- Hard CPU and memory limits, bounded exec and Sandbox lifetimes.
- Ephemeral filesystem; selected reports are copied out before termination.
- Sandbox termination is in `finally`, including failed evaluations.

The design follows Modal's current [Sandbox guide](https://modal.com/docs/guide/sandboxes),
[network controls](https://modal.com/docs/guide/sandbox-networking), and
[filesystem API](https://modal.com/docs/guide/sandbox-files).

## Commands

Inspect the exact policy without creating cloud resources:

```bash
python3 modal_honeypot/runner.py --harness agent --case-id APH-176 --dry-run
```

Run one propagation case remotely:

```bash
python3 modal_honeypot/runner.py --harness agent --case-id APH-176
```

Run one model-replication case remotely:

```bash
python3 modal_honeypot/runner.py --harness model --case-id MRH-181
```

Run either complete 200-case corpus in one bounded Sandbox:

```bash
python3 modal_honeypot/runner.py --harness agent --all --workers 4
python3 modal_honeypot/runner.py --harness model --all --workers 4
```

Run the 20-case network-off containment suite. Both flags are deliberate: one
selects the suite and the second explicitly enables it. The runner rejects a
partial or mismatched opt-in.

```bash
python3 modal_honeypot/runner.py \
  --network-off-suite --enable-network-off-suite --all --workers 4
```

Run one network-off case:

```bash
python3 modal_honeypot/runner.py \
  --network-off-suite --enable-network-off-suite --case-id NOF-001
```

See [`network_off/README.md`](network_off/README.md) for the corpus categories
and validation commands. Its positive control —
[`network_on/README.md`](network_on/README.md) — runs the same 20 probes on a
host with open egress and expects every one to connect (`20/20 reached`),
confirming the `blocked` results only appear under real containment.

The Modal SDK is pinned in the repository requirements. Authenticate locally
with Modal before a remote run; do not inject provider credentials into this
Sandbox.
