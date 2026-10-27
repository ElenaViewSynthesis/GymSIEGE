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

Enable parent-owned evidence chains for corpus logs, and optionally use the
format-valid synthetic checkpoint set for the model harness:

```bash
python3 modal_honeypot/runner.py --harness agent --all --evidence-chain
python3 modal_honeypot/runner.py --harness model --all --evidence-chain --weights-mode format
```

Run the seven instrument-tampering cases or the checked evidence-chain demo.
The image includes `tests/`, so the demo's unit-test step runs in the Sandbox:

```bash
python3 modal_honeypot/runner.py --harness instrument --all
python3 modal_honeypot/runner.py --demo
```

Run names and metadata record chain state and weights mode. Format-valid
weights are accepted only for the model harness.

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

`--allow-network` opens outbound egress for one run (`block_network=False`). It is an
explicit opt-in that never changes the default policy, is refused together with the
network-off suite, passes `MODAL_NETWORK_OPEN=1` into the sandbox, tags the sandbox
`network=open`, adds `-net-open` to the output directory name, and prints a warning.
The user-space tripwires inside still log and refuse egress tools and connects; only
the outer boundary is removed, so use it only for a run that needs it (for example an
agent that must reach a model API) and read its results with that in mind:

```bash
python3 modal_honeypot/runner.py --harness agent --case-id APH-176 --allow-network --dry-run
```

The Modal SDK is pinned in the repository requirements. Authenticate locally
with Modal before a remote run; do not inject provider credentials into this
Sandbox.
