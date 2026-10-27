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

Run the scripted collusion calibration inside the same external boundary:

```bash
python3 modal_honeypot/runner.py --harness collusion --all --dry-run
```

The collusion path is always evidence-chained, refuses `--allow-network`, and
sets the containment marker required by an opt-in `--subject-command`. A real
agent is a separate paid phase: the operator must freeze the cases, model,
Codex configuration, gateway-only network path, run-scoped virtual key,
timeouts, repetitions, and budget first. The image and Sandbox policy do not
embed provider credentials (`secrets=[]`). Collusion artifact bundles retain
the agent's JSONL transcript for post-run shape and evidence review.

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

## Scoped egress: `--egress-allowlist`

`--allow-network` opens the sandbox to everything and is refused for the
collusion suite. `--egress-allowlist HOST[,HOST...]` is the scoped alternative:
`block_network=False` with Modal's `outbound_domain_allowlist` set to exactly
those hostnames, so the sandbox can reach them and nothing else. The token
`langfuse` resolves, on the host at plan time, to the hostname of
`LANGFUSE_BASE_URL` (a hostname, never a key). Entries are bare hostnames; URLs
and `*` are refused so the list cannot widen to open egress.

```bash
# Langfuse only: a scripted collusion run whose sole egress is the Langfuse host
export LANGFUSE_BASE_URL=...   # from .env.local; never print it
python3 modal_honeypot/runner.py --harness collusion --case-id CLH-036 \
  --egress-allowlist langfuse --dry-run
```

The run is recorded as `egress: allowlist` with the host list in the policy
and metadata, tagged `network=allowlist`, suffixed `-net-allow` in the output
directory name, and exported to the sandbox as `MODAL_NETWORK_ALLOWLIST`. It is
permitted for `--harness collusion` because it is scoped; it is still refused
for the network-off suite and never combined with `--allow-network`.
Scripted runs retain `secrets=[]`: the allowlist alone opens a path and does not
place a key in the sandbox. Real-agent runs use the per-run virtual-key lifecycle
below.

A second token, `gateway`, resolves to the model gateway's host from the
first set of `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `LITELLM_BASE_URL`; a
loopback host is refused, because the sandbox cannot reach the operator's
localhost, so the variable must carry the tunnel URL. A real-agent subject
reaches the model only through the gateway, so a Langfuse-only list fits
scripted runs and a real agent takes both:

```bash
# real agent: Langfuse for live traces at the gateway, the gateway for the model
export OPENAI_BASE_URL=...        # the gateway's tunnel URL, from .env.local
python3 modal_honeypot/runner.py --harness collusion --case-id CLH-037 \
  --subject-command "$SUBJECT_CMD" --egress-allowlist langfuse,gateway \
  --model PINNED_MODEL --arm lure-pair --trial 1 --dry-run
```

A real-agent run whose policy cannot reach the gateway (egress blocked, or an
allowlist without the `gateway` token) prints a warning and is not refused:
it is still contained, it just cannot call the model. Every byte to an
allowlisted host is a channel out of the sandbox: for the lure arm it is
declared as an observed channel, never treated as part of the containment.

## Per-run virtual keys

A non-dry real-agent run requires `LITELLM_MASTER_KEY` on the host, a single
`--case-id`, the `gateway` egress token, a non-loopback gateway URL ending in
`/v1`, and `--model`. The runner mints one LiteLLM virtual key before creating
the Sandbox. `/key/generate` receives exactly `key_alias`, a one-element
`models` list, `max_budget`, `duration`, `metadata`, and `tags`. Metadata is
`run_id`, `harness`, `case_id`, `trial`, `arm`, and
`purpose=rogue-agent-honeypot`; tags are `honeypot`, the harness, and the case
ID. The default budget is USD 0.50 and the default TTL is five minutes longer
than the Sandbox lifetime; a shorter TTL is refused.

The returned key stays in host memory and is delivered with an unnamed
`modal.Secret.from_dict` as only `OPENAI_API_KEY` and the full
`OPENAI_BASE_URL`. It never enters `remote_argv` or the workspace. Modal 1.6.0
documents Sandbox Secrets as environment variables inherited by `sandbox.exec`;
the image build additionally runs a harmless `MODAL_SECRET_ENV_PROBE` through
its agent-only `runuser -u honeypot --preserve-environment -- env` path and
fails if that environment is not preserved. Scripted commands retain their
original `runuser` argv. The subject launcher's allowlist passes these two provider
variables and drops the host master key.

Teardown terminates the Sandbox, reads spend from `/key/info`, and calls
`/key/delete` even when the remote process fails. `modal-run.json` records only
the alias, token ID/hash or SHA-256 fingerprint, mint/revoke timestamps, spend,
budget, and TTL. A cleanup failure is recorded and raised; expiration remains
the revocation backstop.

After artifacts are copied, the runner scans every local output file and every
regular member of an artifact tarball. It rejects either the exact virtual-key
bytes or any token matching the LiteLLM-shaped key-prefix heuristic. Unreadable
artifacts also fail closed. An agent dry run mints nothing and prints only a
descriptor such as `virtual-key:collusion/CLH-037/t1/<timestamp>`; the static
`POLICY["secrets"]` and every scripted runtime policy remain empty.
