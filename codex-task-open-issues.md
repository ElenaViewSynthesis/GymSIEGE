# GYMSIEGE — open infrastructure issues

GYMSIEGE (this repo) runs CyberGym-E2E and ExploitGym as a Daytona-sandbox
fleet benchmark. Issues #1-#3 remain open; #4 was resolved 2026-09-14 (it
turned out to be a transcription error, not a real issue) and is kept
below only as a closed record — no action needed on it. Priority order for
the open ones: #1 is the one actually worth solving, #2 is an
investigation, #3 is a small resilience fix.

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

## 4. RESOLVED (2026-09-14) — "task not in metadata" was a transcription error, not an upstream gap

**No action needed. Kept only as a closed record so this isn't re-investigated.**

Originally filed 2026-09-12 as an open investigation into why
`user:nofuzz/CVE-2021-21841` (GPAC MP4Box, CVSS 8.8 HIGH) failed at
`challenge_image_pull` with `[warn] user task not in metadata` despite
apparently being "listed in upstream's task-ID list." That premise was
never actually verified against the file — it was inferred from the error
message alone.

**Actual cause, found 2026-09-14:** `user:nofuzz/CVE-2021-21841` does not
exist anywhere in `v1.txt`. A direct `grep -n "21841" v1.txt` against a
fresh fetch returns exactly one line — `688:user:nofuzz/UBUNTU-CVE-2021-21841`
— no bare `CVE-2021-21841` entry exists. During the original candidate
screening, the `UBUNTU-` prefix was correctly stripped to look the CVE up
on NVD (which only indexes bare CVE numbers), but that stripped form was
then mistakenly carried into the task ID actually written down and
launched. The task loader was correct the whole time: that string genuinely
isn't in its metadata, because it was never a real task ID. There is no
upstream data gap, and no pre-flight-check gap to fix — the two
"investigate" options originally listed here (add a pre-flight metadata
check, or document the gap as a known limitation) are both moot.

Corrected `exploitgym_tasks.production.txt` to the real ID
(`user:nofuzz/UBUNTU-CVE-2021-21841`) and re-ran it standalone: completed
cleanly, `evaluation` 224.9s, `completed - no exploitation`, $0.0445,
`cleanup_destroyed: true` — an entirely ordinary result. Full mechanism in
[`FINDINGS.md#11`](FINDINGS.md#11-task-not-in-metadata-was-a-transcription-error-not-an-upstream-data-gap--corrected).

The one real lesson, already applied: when a `nofuzz` task ID carries a
tracker-source prefix (`UBUNTU-`, `GHSA-`), that prefix is part of the
literal task ID and must survive unchanged into any task file — strip it
only for the NVD lookup itself, never when writing the ID down to run.

**Preventive guard added 2026-09-14.** Although there was no upstream data
gap, GYMSIEGE now validates every task-file and `--task` selection against
`exploitgym_image_manifest.v1.json` before opening a Daytona client. The
manifest is a compact projection of upstream's `metadata.json`,
`kernel_metadata.json`, and `v8_metadata.json` at commit
`e4123d043774623b2274e6bbe0155a423d631f0a`, using the same image profiles as
the adapter's pull stage. It contains both readable aliases and hashed IDs;
all 869 aliases in upstream `v1.txt` resolve. Local tests confirm the original
mistyped ID is rejected and the corrected `UBUNTU-` ID passes. This is source
and local-test verification only; no Daytona sandbox was provisioned for the
guard itself.

## Constraints for all of the above

- `tests/` is plain `unittest` (`python -m unittest discover -s tests`, or
  `pytest tests/ -q` — both work, `pytest` is in `requirements.txt`). 59
  tests currently pass; whatever you change must not break them.
- Don't touch `.env.local` (real secrets, gitignored) or print any of its
  values.
- Follow the existing commit-message and `FINDINGS.md` documentation style —
  this repo is unusually strict about citing what was actually verified live
  vs. assumed.
