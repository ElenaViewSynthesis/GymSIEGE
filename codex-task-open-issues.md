# GYMSIEGE — four open infrastructure issues

GYMSIEGE (this repo) runs CyberGym-E2E and ExploitGym as a Daytona-sandbox
fleet benchmark. Four issues are open. Priority order below; #1 is the one
actually worth solving, #2 and #4 are investigations, #3 is a small
resilience fix.

## 1. (Primary) ExploitGym's baked Node runtime can't run on older-glibc targets

`exploitgym_snapshot_build.py:125-135` bakes the trial runtime by downloading
Node's official prebuilt glibc release and running:

    bash scripts/setup/static_build_node_and_agents.sh \
      --prefix "$PWD/data/runtime/node" --codex --skip-node-build

`--skip-node-build` is upstream ExploitGym's own script
(`sunblaze-ucb/exploitgym`, path `scripts/setup/static_build_node_and_agents.sh`
inside the cloned repo — not vendored in this repo, fetch it to read). We have
never actually inspected what dropping `--skip-node-build` does; the flag name
implies the script *can* build Node itself, possibly statically or against an
older glibc baseline, which — if true — would eliminate this whole failure
class in one shot instead of needing per-target workarounds.

`exploitgym_adapter.py:454-479`'s `node_compatibility_probe` mounts this baked
runtime read-only into each trial's own challenge image and runs
`node --version` against it, offline, before any model call. 7 of the tasks
run so far have failed this probe with the exact same signature — the target
image is missing `GLIBC_2.25`/`2.27`/`2.28`:

    /data/node/bin/node: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.27' not found

All 7 (`arvo_18224`, `arvo_1699`, `arvo_25885`, `arvo_11896`, `CVE-2022-23308`,
`CVE-2021-43848`, `CVE-2022-32234`) are "Ubuntu 16.04 family" per
`probe_arvo_glibc.py` / `results/glibc_probe.json`. 4 other tasks
(`arvo_42298`, `arvo_58295`, `arvo_62183`, `CVE-2022-39393`) already pass this
probe fine on newer-glibc targets — **any fix must not break those**.

**Task:** Investigate whether upstream's static-build path (or a musl Node
build, or bundling glibc alongside the binary, or downloading an older Node
release built against an older glibc floor) produces a `node` binary that
runs unmodified across both the old- and new-glibc target images. If one
works, wire it into `exploitgym_snapshot_build.py`'s bake step. The result
still has to pass upstream's own `validate.sh` runtime checks (this file's
lines 145-154: `gdb`, `nc`, `node --version`, `codex.sh --version`, `socat`).
Verify by re-baking `gymsiege-exploitgym`, then re-running
`probe_arvo_glibc.py` (or `orchestrator.py exploitgym-run --task
user:cybergym/arvo_1699 --k 1 --budget-usd 1`) and confirming it now clears
`node_compatibility_probe` instead of failing it — plus a spot-check that a
previously-passing task (e.g. `CVE-2022-39393`) still passes.

## 2. (Investigate) CyberGym's isolated-oracle network lockdown is now rejected outright by this Daytona account tier

`solver_agent.py:415-450`, `_reconfirm_isolated()`: after the agent's own
build/PoC/patch loop finishes, GYMSIEGE cuts the sandbox's network
(`sandbox.update_network_settings(network_block_all=True)`) and re-detonates
the frozen PoC in isolation, standalone, as the authoritative
`vul_exit_code`/`fix_exit_code` result. Confirmed live on two separate demo
runs (2026-09-11, 2026-09-12), 6/6 trials: this Daytona account tier now
rejects that call outright —

    Failed to update network settings: Network access is restricted and
    cannot be overridden at the sandbox level.

— so the re-detonation body inside the `try` never runs, and CyberGym cannot
currently produce a real scored result on this account at all (every trial
now correctly reports `status=oracle_unavailable`, after a fix already landed
in `sandbox_runner.py:349`'s `_looks_oracle_unavailable()` to classify this
message correctly instead of the misleading `"failed"`/"completed - no
exploitation" it used to get — that classification fix is already done and
merged; this task is about the underlying capability, not the labeling).

`exploitgym_adapter.py:526-542` already hit this same restriction on its own,
separate `update_network_settings(network_block_all=True)` call (its
post-run containment lockdown) and already handles it gracefully — catches
`DaytonaBadRequestError`, checks for this exact message, records
`daytona_network_policy = "target-managed-restriction"` instead of crashing.
ExploitGym is not actually blocked by this, though: its *primary* containment
is its own upstream two-network Docker firewall
(`upstream_firewall=True`, `exploitgym_adapter.py`), independent of Daytona's
API — the Daytona-level call is only defense-in-depth for ExploitGym.
CyberGym has no equivalent fallback; `sandbox_runner.py` never calls
`update_network_settings` itself, so `_reconfirm_isolated()` is the *only*
place CyberGym isolates the network, and it has no fallback when that's
blocked.

**Task:** Investigate whether the restriction is specifically on the Daytona
control-plane API call (`update_network_settings`), or on network lockdown
generally. If it's just the API call, an in-sandbox alternative executed via
`sandbox.process.exec()` (e.g. `iptables -P OUTPUT DROP` / an equivalent
firewall rule run *inside* the sandbox, not through Daytona's SDK) might
achieve the same isolation without needing the now-restricted API. If that's
not viable either, mirror `exploitgym_adapter.py`'s graceful-degradation
pattern in `solver_agent.py`'s `_reconfirm_isolated()` (currently a bare
`try/finally` with no `except`) so the failure is recorded structurally
(a `daytona_network_policy` field, say) rather than only as a generic
`detonation_error` string. Either way, document what you find as a new
numbered entry in `FINDINGS.md` (see entries 8 and 9 there for the expected
format/rigor — cite what you actually tested, not what you assume).

## 3. (Minor, optional) The post-secret-attach stop/start restart is an intermittent hang

Both `sandbox_runner.py:134-135` (CyberGym) and `exploitgym_adapter.py:341-342`
(ExploitGym) do the identical `sandbox.stop(timeout=120)` →
`sandbox.start(timeout=120)` cycle after `update_secrets()` (Daytona
documents this restart as required after a sandbox's first vault-secret
attach). This has hung past the 120s client timeout 4 times now — 3× on
`start()` (CyberGym, 2026-09-11), 1× on `stop()` (ExploitGym, 2026-09-12) —
always followed by `"Failed to remove sandbox: Sandbox state change in
progress"` on cleanup/reap for several minutes afterward, self-clearing
eventually (a manual retry, or the 60-minute safety TTL). A retry of the
exact same task/command immediately after one of these hangs succeeded
cleanly in under 10s, so this reads as transient Daytona platform flakiness,
not a deterministic bug — see `results/reap_log.json` for 4 earlier instances
of the identical `"Sandbox state change in progress"` message on unrelated
sandboxes/days.

**Task (optional, low priority):** Add a bounded retry-with-backoff around
this specific stop/start cycle in both files (e.g. 2-3 attempts, exponential
backoff) so a transient hang doesn't burn an entire trial's budget allocation
and a leaked sandbox. Do not paper over a *real* hang — still surface it as
an error after retries are exhausted.

## 4. (Investigate) A task ID can be listed in ExploitGym's `v1.txt` with no corresponding challenge-image metadata, and there's no cheap pre-flight check for it

Confirmed live 2026-09-12: `user:nofuzz/CVE-2021-21841` (GPAC MP4Box, CVSS
8.8 HIGH — chosen specifically as the highest-severity candidate from a
screening pass over ExploitGym's full upstream `v1.txt`, see `FINDINGS.md#11`
and `EXPERIMENTS.md`'s "Three new candidates..." section for the full
methodology) parses fine as a task ID and is genuinely present in upstream's
task-ID list, but fails at the `challenge_image_pull` stage:

    [warn] user task not in metadata: user:nofuzz/CVE-2021-21841
    No images resolved; nothing to pull.

Unlike the glibc/Node-runtime incompatibility in issue #1, which
`probe_arvo_glibc.py` predicts cheaply and offline *before* provisioning a
sandbox, this failure mode has no equivalent pre-flight check — the lookup
that resolves a task ID to a pullable Docker image only happens live, inside
`exploitgym_adapter.py`'s `challenge_image_pull` stage, after
`docker_start` has already succeeded (i.e. after most of a sandbox's
lifecycle cost has already been paid, even though this specific failure is
$0 in solver spend since it's caught before any model call).

**Task:** Investigate what "task not in metadata" actually means inside
upstream ExploitGym's own `cybergym` package (rebuilt fresh at trial start
from `/home/daytona/exploitgym` — read its actual task-loading code, not
just `v1.txt`, to find the real metadata source it consults and why this ID
is missing from it despite being listed as a valid task ID elsewhere).
Two possible outcomes, either is useful:
1. If there's a way to check metadata existence for a task ID *before*
   provisioning a sandbox (a local file, an API call, anything offline or
   cheap), add it as a `node_compatibility_probe`-style pre-flight check —
   this would let future candidate screening from `v1.txt` filter out dead
   task IDs before ever spending provisioning time/cost on them, the same
   way glibc incompatibility is already caught for free.
2. If no such check is possible without actually reaching
   `challenge_image_pull`, document that limitation explicitly (in
   `FINDINGS.md`, next to entry #11) so future task-selection work doesn't
   assume `v1.txt` membership implies runnability, and treat this as a
   closed, understood limitation rather than something to keep re-solving.

Do not spend solver budget "confirming" this task is broken again — it
already is, and retrying it wastes provisioning time (the trial does reach
`docker_start` before failing) for a result we already have.

## Constraints for all of the above

- `tests/` is plain `unittest` (`python -m unittest discover -s tests`, or
  `pytest tests/ -q` — both work, `pytest` is in `requirements.txt`). 59
  tests currently pass; whatever you change must not break them.
- Don't touch `.env.local` (real secrets, gitignored) or print any of its
  values.
- Follow the existing commit-message and `FINDINGS.md` documentation style —
  this repo is unusually strict about citing what was actually verified live
  vs. assumed.
