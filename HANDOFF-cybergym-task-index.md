# Codex handoff — pull the 920-task master list locally and build a task→sanitizer index

**Owner:** Codex · **Priority:** medium (unblocks task selection; not blocking any run) · **Type:** data/tooling (local dataset pull + derived index)
**Opened:** 2026-09-23 · **Scope:** fetch the full CyberGym-E2E task list and each task's
crash metadata locally, and emit a committable `task → project / sanitizer / crash-type`
index. First concrete use: identify **LeakSanitizer** candidate tasks that are **not** in
the pinned 22. No solver run, no snapshot bake.

## Why

Right now the repo only stores **task IDs** for the 22 pinned tasks
(`txt/tasks.pinned.txt`, `txt/tasks.demo.txt`) — there is **no sanitizer or bug-class
per task anywhere on disk**, and no cybergym metadata tree. The 920-task master list
(`scripts/tasks.txt`) and each task's `crash.log` (which records the sanitizer that
actually fired) live only in the gated `sunblaze-ucb/cybergym-e2e` dataset. So any
question of the form "which non-pinned tasks use sanitizer X?" (LeakSanitizer today,
but also MSan/UBSan/thread later) currently can't be answered from the repo — it needs
the dataset pulled and indexed. This handoff builds that index once, reproducibly, so
those questions become a local `grep`.

## What to do

### 1. Pull the master task list (920 IDs), pinned to a revision

- Fetch `scripts/tasks.txt` from `sunblaze-ucb/cybergym-e2e`. It exists in both the
  GitHub repo (`common.py:66`, `CYBERGYM_REPO_URL`) and the HF dataset
  (`common.py:68`, `HF_DATASET`); use whichever resolves cleanly, but **pin an exact
  revision** and record it. Prefer the commit already baked into the current Modal
  snapshot for consistency — `b46456c46838b2b090d7e6ded5bfdf1ff583dba7` (920 lines,
  blob `6344ed3`); `b861317` is the earlier revision the pinned 22 were resolved
  against, and both resolved the file identically, so note which you used.
- Save it locally as `reference/cybergym_tasks.master.txt` (verbatim, with the pinned
  rev in a header comment). Confirm it is 920 task lines.

### 2. Fetch each task's crash metadata — `crash.log` ONLY, not the big files

- For every task, fetch **only `crash.log`** from the HF dataset
  (`projects/<project>/<task>/crash.log`). Per `snapshot_build.py`'s findings,
  `crash.log` is **plain-git, served directly as a `200`** and small; `src.tgz` and
  `poc.bin` are **LFS/Xet-backed and large** — **do not fetch them**, and never pull
  the full (~160 GB) dataset. Use `snapshot_download` with `allow_patterns=["**/crash.log"]`
  (or `HfApi.hf_hub_download` per file), not a blanket clone.
- Land the raw `crash.log` files under a **gitignored** working dir (e.g.
  `results/cybergym_index/` — `results/**` is already ignored) so the raw dataset
  content is **not** committed (see Guardrails on licensing).
- Beware the documented HF `Content-Length`/chunked-reframing bug
  (`reference/DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md`, `hf_header_probe.py`) — it bit
  `src.tgz`-class LFS files **from inside Daytona sandboxes**. Pulling `crash.log`
  (plain-git, sizable) from the **local dev machine** should sidestep it; if a fetch
  still fails, fall back to the git-blob-SHA-1 direct fetch that `snapshot_build.py`
  already uses.

### 3. Parse the sanitizer + crash type, build the derived index

- Parse each `crash.log` for the sanitizer that fired and the crash type. Recognize:
  - `AddressSanitizer: <type>` (ASan) — heap/stack-buffer-overflow, use-after-free,
    double-free, SEGV, etc.
  - `MemorySanitizer: use-of-uninitialized-value` (MSan)
  - `UndefinedBehaviorSanitizer: <type>` (UBSan)
  - **`LeakSanitizer: detected memory leaks` / `Direct-leak` / `Indirect-leak`** (LSan —
    the target of this task). Note LSan is a **sub-detector of ASan**, not a standalone
    `SANITIZER=` value, so a leak task's `crash.log` is the only reliable signal.
  - If a `crash.log` also carries a `SANITIZER=` line or an OSS-Fuzz crash-type header,
    capture it too; where the log is empty/missing, mark the sanitizer `unknown` rather
    than guessing.
- Emit a committable index at `reference/cybergym_task_index.jsonl` — one JSON object
  per line: `{ "task": "<project>/<id>", "project": "...", "sanitizer": "ASan|MSan|UBSan|LSan|unknown", "crash_type": "<verbatim summary>", "source_rev": "<pinned sha>" }`.
  A parallel `.csv` is fine if easier to skim. Keep it deterministic (sorted by task).

### 4. Answer the LeakSanitizer question explicitly

- Produce the **LeakSanitizer subset**: every task whose `crash.log` shows
  `LeakSanitizer` / `detected memory leaks` / `Direct-leak` / `Indirect-leak`, with its
  `project/task_id` and the exact identifying line. List them in the index and summarize
  in the write-up (or state plainly "none found" if the dataset has none — that is a
  valid, cite-able result).
- Cross-check the 22 pinned tasks against the new index to confirm it agrees with the
  already-verified sanitizer split (16 ASan, 3 MSan, 1 UBSan, 2 not-captured;
  `EXPERIMENTS.md` completion table) — a sanity check that the parser is correct.

## Guardrails

- **Gated dataset access:** use the existing HF token path — `get_token()` (the WSL
  Hugging Face login cache) and/or `HF_TOKEN` from `.env.local` (mapped to the
  `gymsiege-huggingface` secret, `common.py:115`, `configure_secrets.py`). The dataset
  is already approved for this account. **Never print the token** or write it anywhere.
- **Storage & licensing:** fetch `crash.log` only; do not download `src.tgz`/`poc.bin`
  or the full dataset. **Commit only the derived index** (`reference/cybergym_task_index.jsonl`
  and `reference/cybergym_tasks.master.txt`), not the raw `crash.log` corpus — those are
  gated dataset content; keep them under the gitignored working dir. Confirm the gated
  terms permit local analysis before redistributing anything.
- **Reproducibility:** pin and record the exact dataset revision; the index must be
  regenerable from that rev.
- **detect_leaks caveat (note, not scope):** even once an LSan task is found, the harness
  runs ASan with **`detect_leaks=0`** (verified 20/20 across `results/modal_trials/`), so
  a leak oracle would not fire without flipping `detect_leaks=1` for that task's arms —
  a separate follow-up change, out of scope here.
- Cite what you verified; do not invent task IDs. Don't touch `.env.local`. Keep the test
  suite green (`python -m unittest discover -s tests`); add a small parser test if you add
  reusable parsing code.

## Acceptance

- `reference/cybergym_tasks.master.txt` (920 tasks, pinned rev in header) and
  `reference/cybergym_task_index.jsonl` (task → project / sanitizer / crash-type, one per
  line) exist, are deterministic, and are committed; the raw `crash.log` corpus is **not**
  committed.
- The **LeakSanitizer candidate list** is produced (task IDs + identifying crash.log line),
  or a cited "none found".
- The index reproduces the known 22-pinned sanitizer split as a correctness check.
- A short `FINDINGS.md` (or `reference/`) note records the method, the pinned rev, counts
  per sanitizer across the 920, and the `detect_leaks=0` follow-up needed before any leak
  task can actually be run.

## Key references

- `common.py:66` (`CYBERGYM_REPO_URL`, GitHub), `common.py:68` (`HF_DATASET`),
  `common.py:115` (HF secret mapping).
- `snapshot_build.py` — the `snapshot_download` + `ignore_patterns`/`allow_patterns`
  pattern, the crash.log-is-plain-git vs src.tgz-is-LFS distinction, and the git-blob-SHA-1
  direct-fetch fallback.
- `hf_header_probe.py` and `reference/DAYTONA_HUGGINGFACE_EGRESS_ISSUE.md` — the HF
  Content-Length/chunked bug and its scope (Daytona-sandbox egress, likely N/A locally).
- `configure_secrets.py` — HF token handling (`get_token()`), gated-Secret hosts.
- `txt/tasks.pinned.txt` — the 22 pinned tasks, resolved from `scripts/tasks.txt @ b861317`;
  `EXPERIMENTS.md` completion table — the verified 22-task sanitizer split to check against.
