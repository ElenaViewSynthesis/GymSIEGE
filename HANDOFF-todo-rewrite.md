# Codex handoff — rewrite TODO.md's stale "Current verified state" / continuation plan

**Owner:** Codex · **Priority:** high (operationally hazardous doc) · **Type:** docs
**Opened:** 2026-09-22 · **Scope:** `TODO.md` lines ~15–147 ("Current verified
state") and the "Next paid runs (planned 2026-09-04…)" section

## Why

`TODO.md`'s top section is a 2026-09-04 snapshot and is now dangerous as an
operational handoff: it claims `gymsiege-toolchain` is absent, that **"CyberGym
`run`/`sweep` cannot run at all right now: there is no LiteLLM deployment"**, and
cites a ~22-test baseline. All three are false today. A reader following it would
draw exactly the wrong conclusions about what runs and what's blocked.

## The accurate current state to rewrite it around (verify each before writing)

- **ExploitGym runs on Daytona** via `orchestrator.py exploitgym-run`;
  `gymsiege-exploitgym` snapshot is ACTIVE. Unchanged and still true.
- **CyberGym now runs on Modal**, not Daytona. `modal_sandbox_runner.py` /
  `run_modal_pinned_tasks.sh` restore per-trial Modal sandboxes from
  `modal_snapshot_build.py`'s image, which has **no 10 GiB ceiling**, so the full
  pinned set is usable there. Daytona's `gymsiege-toolchain` bake remains
  physically impossible (16 images ≈ 74.76 GB vs the hard 10 GiB per-sandbox
  cap) — but that is now a *worked-around* fact (Modal is the vehicle), not a
  blocker. Reframe it that way; don't present it as "CyberGym can't run."
- **The LiteLLM gateway exists and is up.** `gymsiege-litellm` secret exists,
  `LITELLM_BASE_URL` is set, and CyberGym on **both** Daytona and Modal routes
  its agent calls through it. The "no LiteLLM deployment / cannot run" claim is
  obsolete. The gateway also carries the `additional_drop_params: ["temperature"]`
  fix (FINDINGS #20) and the `langfuse_otel` callback (FINDINGS #21).
- **Langfuse observability shipped:** Layer 1 (per-trial host traces,
  `observability.py`, commit `a0a59ec`) and Layer 2 (gateway `langfuse_otel`
  callback capturing CyberGym generations, documented FINDINGS #21). ExploitGym
  is Layer 1 only (its bundled in-sandbox proxy never touches the gateway).
- **Isolated oracle is fully built:** stage1/2 re-detonation *and* independent
  stage3/4 re-verification with a false-positive guard (Issue #6 / FINDINGS #19);
  the prepare-before-network-cut two-phase fix (Issue #7); the exec-hang result
  polling + failure-artifact capture (FINDINGS #9). All shipped and tested.
- **Test baseline is 113 passing**, not 22 (`tests/test_core.py`).
- **Latest full production run — 22-task Modal set, 2026-09-21/22** (from
  `results/modal_trials/`): **14 `success`, 4 `failed`
  (ffmpeg/oss-fuzz_436997807, net-snmp/arvo_52465, libxaac/arvo_62261,
  ghostscript/arvo_45320), 2 `no_patch` (arrow/arvo_41221,
  opensc/oss-fuzz_448717172), 2 `oracle_mismatch` (mruby/arvo_53183,
  libdwarf/arvo_56454)**; total solver cost ≈ **$1.34**. 21/22 slots are fresh
  from this run; **`ffmpeg/oss-fuzz_385167047` is stale** (2026-09-16 result, its
  task-7 slot wasn't overwritten — flag it as needing a standalone re-run).

## Remaining / open work to list (the honest "what's left")

- **Issue #2 (open):** this Daytona account rejects the per-sandbox
  `update_network_settings(network_block_all=True)`, so CyberGym's isolated
  oracle can only run on **Modal**, not Daytona. This is the one genuinely open
  tracker item (`codex-task-open-issues.md#2`).
- **Re-run `ffmpeg/oss-fuzz_385167047`** standalone to replace its stale slot.
- **`CVE-2022-23308` `--k 5`** confirmation (it has one clean ExploitGym
  completion, not yet `--k`-confirmed like `arvo_1699`/`arvo_66311`).
- **Optional:** the transient-connection-reset retry (low priority; harness
  already fails safe) and ExploitGym Layer 2 in-sandbox-generation capture
  (documented gap, bake-time follow-up).

## What to do

1. **Replace** the "Current verified state" section (~15–147) with a dated
   ("updated 2026-09-22") accurate summary built from the facts above — lead with
   what runs where (ExploitGym→Daytona, CyberGym→Modal, gateway up), the shipped
   fixes, the 22-task results, and the tests=113 baseline.
2. **Rewrite the "Next paid runs (planned 2026-09-04…)"** section around the
   *remaining* work above; drop anything already done.
3. **Preserve the valuable diagnostic history** rather than deleting it: the HF
   `Content-Length`/chunked-reframing bug, the 10 GiB disk-ceiling measurements,
   the isolated-oracle design rationale. Either condense them into a "Background
   / resolved" subsection or move them below the current-state summary — do not
   lose the citation-quality detail, just stop presenting it as *current
   blocking* state.
4. Fix any remaining stale counts (22-test baseline, "20 pinned tasks" where it's
   now 22, etc.) as you touch them.

## Guardrails

- **Cite, don't invent.** Every result number comes from `results/modal_trials/`
  / `results/` or `FINDINGS.md`; keep the repo's "cite what you verified, not what
  you assumed" bar.
- **Don't destroy history.** The 2026-09-04 diagnostics have reference value;
  demote them, don't delete them.
- Docs only — no code change.
- Cross-check against `FINDINGS.md` (#9/#16/#17/#18/#19/#20/#21) and
  `codex-task-open-issues.md` so TODO.md doesn't contradict them.

## Acceptance

- `TODO.md`'s top no longer claims the toolchain/gateway are absent or that
  CyberGym can't run, and no longer cites a 22-test baseline.
- It leads with an accurate, dated current state (ExploitGym/Daytona +
  CyberGym/Modal + gateway + Langfuse L1/L2 + 113 tests + the 22-task tally) and
  an honest remaining-work list (Issue #2, ffmpeg re-run, CVE-2022-23308 --k5,
  the optionals).
- The valuable 2026-09-04 diagnostics are preserved as background, not deleted.

## Key references

- `results/modal_trials/*.json` (the 22-task tally); `observability.py` (`a0a59ec`);
  `FINDINGS.md#19/#20/#21`; `codex-task-open-issues.md#2`;
  `reference/DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md` (the HF bug to preserve).
