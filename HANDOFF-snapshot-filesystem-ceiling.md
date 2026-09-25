# Codex handoff — find Modal's `snapshot_filesystem` size ceiling

**Owner:** Codex · **Priority:** medium-high (blocks the 920-task sharded run;
FINDINGS #24's 12-shard plan is currently un-bakeable) · **Type:** infra
investigation (Modal snapshot limits) + a re-plan once the number is known
**Opened:** 2026-09-24 · **Scope:** determine the largest VM filesystem that
`modal.Sandbox.snapshot_filesystem()` can actually capture on this account, then
re-size the shard plan to it. No paid solver/LLM trials are needed.

## Why

Modal's VM Sandbox disk is capped at **512 GiB** (`modal_disk_cap_bytes =
549755813888` in `reference/cybergym_modal_capacity.json`), and the 12-shard
plan (#24) sized each shard to ~387 GB against that cap. But the cap is the
wrong limit: `snapshot_filesystem` fails **well below** it.

Confirmed live (FINDINGS #25):

| Filesystem size | `snapshot_filesystem` result |
| --- | --- |
| ~23 GB (10-task probe, `im-01M397WSAFVGMXX4Y9BKKX07ZH`) | works |
| ~115 GB (pinned-22) | works |
| ~415 GB (shard-03: 384.8 GB Docker + 30.6 GB dataset) | **fails ×2** |

Shard-03 baked through every step (toolchain, 390 crash logs, 46 images, 45
validator builds, disk-headroom gate showing 116 GB free) and only the final
`snapshot_filesystem` call failed — twice, ~15–18 s after cleanup (the timeout is
1800 s, so not a deadline), deterministically:

- `sb-Rgi9ItNRkX8NXCZcfIgPSU` → `InternalError ... (Error code: 463NTSTM)`
- `sb-KVDz6vJbs213gRLL9Qb8ye` → `InternalError ... (Error code: CR4TP30Y)`

So the ceiling sits **between 115 GB and 415 GB**. Its exact value decides the
shard count: ~12 fat shards near the limit vs. roughly ~45 small ones. Guessing
low wastes many extra bakes; guessing high fails late and expensively (~45 min of
image pull thrown away per failed bake). Pin the number first.

## What to do

### 1. Bracket the ceiling cheaply with synthetic-fill probes (primary method)
Do **not** re-bake real shards to binary-search — each real bake burns ~45 min of
image pull before it even reaches the snapshot call. Instead isolate the snapshot
operation: create a `vm_runtime=True` Sandbox, fill the filesystem to a target
size, call `snapshot_filesystem`, record pass/fail. `modal_vm_kvm_probe.py` is a
good standalone-probe template; reuse `_sandbox_create(..., vm_runtime=True)` and
the `snapshot_filesystem(SNAPSHOT_FILESYSTEM_TIMEOUT_S, ttl=None)` call shape from
`modal_snapshot_build.py:222` / `:320`.

Binary-search the byte size in [115 GB, 415 GB] — e.g. probe 265 GB, then
150/350, converging on the largest size that still captures. Immediately delete
each probe snapshot/sandbox so they don't accumulate storage.

**Disambiguate what the limit is measured in** — do not assume raw bytes. Three
hypotheses, each needs a different fill shape:
- **Total bytes:** one big file (`fallocate -l <N>G /probe.bin`). Fast, tests bytes only.
- **Inode / file count:** many small files (shard-03 had ~3.04M inodes). Fill to a
  high inode count at modest bytes and see if it fails earlier than the byte probe.
- **Docker layer count / `/var/lib/docker` shape:** if the byte and inode probes
  both pass at ~415 GB-equivalents, the trigger is Docker-specific and only a real
  large image set reproduces it — fall back to a real bake at the byte ceiling to
  confirm.

Report which dimension actually gates, with the pass/fail size for each.

### 2. Ask Modal support in parallel
File with Modal support quoting error codes **`463NTSTM`** and **`CR4TP30Y`**, the
two sandbox IDs above, and the ~415 GB filesystem (384.8 GB Docker + 30.6 GB
dataset, ~3.04M inodes). Ask for the documented/effective maximum
`snapshot_filesystem` size and whether it is bytes-, inode-, or layer-bound. Their
answer may make the probing moot or set the safe target directly.

### 3. Re-plan the shards to the confirmed ceiling
Once the safe max is known, re-run the planner with a smaller target and a safety
margin below the ceiling (leave room for the ~30 GB dataset + OS + build
scratch). `modal_master_shards.py` already balances by projected bytes and keeps
shared-image task groups intact — the change is the target, not the algorithm.
Expect the shard count to rise substantially (≈ 4,498 GB projected Docker ÷ target).
Regenerate `txt/modal_master_shards/`, keep coverage-exactly-once validated, and
note that this **rewrites the committed shard files** (feat commit `dda71ac`).

### 4. Correct the docs
Update FINDINGS #24 (its 12-shard sizing is disproven), the README
"Reproduce the full 920-task master run" capacity section, and the EXPERIMENTS
inventory/shard-mapping sections to the new shard count. FINDINGS #25 already
records the ceiling evidence — extend it with the pinned exact value and the
gating dimension once known.

## Guardrails

- **No paid LLM/solver trials** are needed for any of this — it is snapshot-sizing
  only. Synthetic probes cost Modal compute + storage, not model spend.
- **Do not re-run the ~415 GB shard-03 bake** — it fails deterministically; re-runs
  only waste ~50 min + compute each.
- **Leave the working snapshots intact:** the pinned manifest
  (`results/modal_snapshot.json`) and the 10-task probe
  (`results/modal_snapshot.master10.json`, `im-01M397WSAFVGMXX4Y9BKKX07ZH`). Probe
  bakes must use throwaway `--output`/names and be deleted after measuring.
- **Delete every probe snapshot** as soon as its pass/fail is recorded — a 300 GB
  snapshot left around is real stored cost.
- Keep the test suite green (`python -m unittest discover -s tests`); if you add a
  probe helper, add a small unit test for any reusable sizing logic.
- Cite measured pass/fail sizes; do not infer the ceiling from a single probe.

## Acceptance

- The `snapshot_filesystem` ceiling is established as a concrete size (or size +
  inode/layer bound), backed by at least one passing and one failing probe that
  bracket it, and/or an authoritative answer from Modal support.
- FINDINGS #25 updated with the exact ceiling and the gating dimension.
- `modal_master_shards.py` re-run to a safe target below the ceiling; the new
  `txt/modal_master_shards/` covers the 920 master tasks exactly once; #24, README,
  and EXPERIMENTS updated to the new shard count.
- A one-line note on the new bake economics (shard count × ~45 min pull) so a full
  sweep can be scheduled realistically.

## Key references

- `modal_snapshot_build.py:222` (`_sandbox_create`, `vm_runtime=True` →
  `experimental_options`), `:320` (`snapshot_filesystem(SNAPSHOT_FILESYSTEM_TIMEOUT_S,
  ttl=None)`), `:44` (`SNAPSHOT_FILESYSTEM_TIMEOUT_S = 1800`).
- `modal_vm_kvm_probe.py` — standalone Modal VM probe to template the fill-probe on.
- `reference/cybergym_modal_capacity.json` — `modal_disk_cap_bytes` (512 GiB),
  per-image projected bytes, task/image mapping used by the planner.
- `modal_master_shards.py` — the planner to re-run at a smaller target.
- `modal-docs/modal-virtualization.md`, `modal-docs/modal-vm-sandboxes.md` — Modal
  VM Sandbox + filesystem-snapshot semantics.
- FINDINGS #24 (the sharding plan) and #25 (the ceiling evidence: sizes, error
  codes, sandbox IDs).
