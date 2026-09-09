# Modal sandboxes and virtualization — infrastructure plan for kernelCTF support

**Status: planned, not built.** Nothing in this file is implemented. Written
to scope what running `kernel:kernelctf/*` tasks (see
[`kernelctf-tasks.md`](kernelctf-tasks.md)) would actually require if Modal
becomes the platform for it, and to record one real, verified blocker found
while scoping this — not glossed over just because it complicates the plan.

## The blocker, found and verified before writing the rest of this plan

**Modal's own security docs state it uses gVisor** for sandboxing
("Compute jobs at Modal are containerized and virtualized using gVisor, the
sandboxing technology developed at Google and used in Google Cloud Run and
GKE" — `modal.com/docs/guide/security`).

gVisor is a **userspace reimplementation of the Linux syscall surface** —
its whole security model is intercepting syscalls in a sandboxed Go process
instead of letting them reach the real host kernel. Two consequences that
matter directly here:

1. **gVisor does not expose `/dev/kvm` or nested virtualization by
   default.** This is a well-known, widely-documented limitation — it's the
   same reason Google Cloud Run (also gVisor-based) can't run
   Docker-in-Docker or VM-based workloads without extra configuration.
   kernelCTF exploits need to boot an actual pinned kernel build (see
   `metadata.json`'s `"environment": "lts-6.1.36"` field, confirmed on a
   real challenge) via QEMU — that needs either KVM hardware acceleration
   or, at minimum, permission to run QEMU in software-emulation (TCG) mode.
2. **Even if QEMU could run, the target is gVisor's own reimplemented
   syscall surface, not upstream Linux** — irrelevant here specifically
   because the *exploit itself* boots its own kernel inside QEMU rather than
   attacking the host kernel directly, so this second point is less of a
   blocker than the first. Worth stating for completeness, not being lazily
   thorough.

**This directly contradicts the "Modal handles KVM/hardware virtualization"
premise as a plug-and-play assumption.** It doesn't mean Modal is wrong to
use — it means the plan needs an explicit verification step and a fallback,
not blind confidence it'll just work.

## Required verification spike, before any real integration work

Before committing engineering time to a Modal-based kernelCTF harness, run
this cheaply:

```bash
# Inside an actual Modal sandbox/container:
ls -la /dev/kvm 2>&1
qemu-system-x86_64 --version 2>&1
qemu-system-x86_64 -enable-kvm -nographic -kernel /dev/null 2>&1 | head -5
```

Three possible outcomes, each with a different plan:

| Outcome | Meaning | Plan |
|---|---|---|
| `/dev/kvm` present, KVM-accelerated QEMU boots | gVisor's default restriction doesn't apply to this Modal tier/config | Proceed with Modal directly, full speed |
| No `/dev/kvm`, but plain (TCG, software-only) QEMU works | No hardware acceleration, but exploits can still run — much slower | Proceed with Modal, budget for far longer `--timeout`/`--trial-timeout` per kernel-family task (QEMU TCG boot + exploit can be 10-50x slower than KVM-accelerated) |
| Neither works | gVisor blocks QEMU entirely, matching the documented limitation | Modal cannot host the actual kernel-boot step; see fallback below |

## Fallback if Modal genuinely can't run this

Split the architecture instead of assuming one platform does everything:
- **Modal** (or the existing Daytona setup) keeps orchestrating the agent
  loop, task selection, budget tracking, and results collection — none of
  that needs KVM.
- **A separate, bare-metal-or-nested-virtualization-capable provider**
  (a cloud VM with nested virt enabled, or a dedicated KVM-capable box) hosts
  only the actual kernel-boot-and-exploit step, invoked as a remote call from
  the orchestration layer.

This is a real architectural fork, not a footnote — decide which branch
before writing integration code, not after discovering the spike fails.

## Correction: ExploitGym's upstream harness already builds and runs kernel tasks

Everything in this section was written *before* actually reading
ExploitGym's own kernel-task code. Having now read it
(`src/cybergym/evaluation/kernel.py`, `src/cybergym/server/controller.py`,
`scripts/setup/pre_run.py`, `scripts/setup/pull_images.py`,
`examples/run_agent.py`), the premise of the original section below —
"needs its own bake path… needs its own compile-and-run step… needs its
own verification design" — is **wrong**. `kernel:` is not a stub family
gated off for lack of implementation; it's a fully working third evaluator
alongside `user:` and `v8:`, already exercised by ExploitGym's own test
suite (`tests/server/test_controller.py`,
`tests/evaluation/test_controller_secrets.py`). What follows replaces the
original six-point list. The gVisor/`/dev/kvm` blocker above still stands
as written — this correction is about what GYMSIEGE needs to build *once
a working KVM-capable sandbox exists*, which is now the user's side to
supply ("i will provide the modal sandbox setup").

### What ExploitGym already provides, confirmed by reading the source

- **`KernelEvaluator`** (`src/cybergym/evaluation/kernel.py`) is a complete
  evaluator, same shape as the `user:`/`v8:` evaluators GYMSIEGE already
  drives. It resolves the target image directly from
  `KERNEL_TASK_METADATA[task_id].image_name`
  (`cybergym/kernelctf-target:<release_id>` — a single image per task, no
  mode/variant concept like `exp.hardened`), computes a defense-capability
  bitmap (`capabilities_to_bitmap`) from either the task's original
  kernelCTF capabilities or a caller-supplied override, and gives the
  *agent's own container* `/dev/kvm` device access automatically
  (`_extra_container_kwargs()`) if `/dev/kvm` exists on the host the
  evaluator runs on — GYMSIEGE doesn't need to write this passthrough
  itself, only make sure the device node is real and accessible at that
  point in the stack (see the layering note below).
- **A working success oracle already exists.** `_verify_impl()` reads
  `/workspace/flag.txt` out of the agent container and compares it against
  an `expected_flag` derived the same way GYMSIEGE's existing token/salt
  flow already works for `user:` tasks (`generate_flag`/`generate_token`,
  same `CYBERGYM_SERVER_SALT`/`FLAG_SEED` GYMSIEGE already provisions).
  This directly contradicts the original point 4 below — no new
  verification design is needed, it's the same `CheckResult`-based
  pass/fail scoring GYMSIEGE already reads out of ExploitGym's evaluator
  output today.
- **A separate "challenge controller" process manages the QEMU VM.**
  `src/cybergym/server/controller.py` is a FastAPI service
  (`uv run -m cybergym.server`) that shells out to the local Docker daemon
  to launch the kernel-target image as a peer container next to the agent
  container on a shared Docker network (`cybergym-internal`), and exposes
  `/create_server`, `/delete_server`, `/restart_server`, `/health_check`.
  The agent connects to the VM's serial console over a TCP port the
  controller hands back. **GYMSIEGE's own `exploitgym_adapter.py` already
  starts this controller for every single trial today** —
  `_run_script()` (`exploitgym_adapter.py:692-694,704,715`) already calls
  `pre_run.py --controller-port {controller_port}` and passes
  `--controller-url "http://$DOCKER_BRIDGE_IP:{controller_port}"` into
  `run_agent.py` unconditionally. It's just idle for `user:`-only runs.
  Nothing new needs to be started; a `kernel:` task list would exercise a
  code path that already runs, unused, in every current trial.
- **Host KVM readiness is already checked, and already gated on kernel
  tasks being present.** `pre_run.py`'s `check_kvm(needed)` (line ~172)
  runs only `if has_kernel_tasks` (line 681-682: `has_kernel_tasks =
  any(t.startswith("kernel:") for t in task_ids)`), warns (non-fatally) if
  `/dev/kvm` is missing or not read/writable, and explicitly documents the
  TCG software-emulation fallback in that warning text. This is the exact
  check the "required verification spike" above is a manual dry-run of —
  once GYMSIEGE passes a `kernel:` task through, this check runs
  automatically on every trial.
- **`pull_images.py` already dispatches kernel images correctly.**
  `images_for_task()` branches on the `kernel:` prefix and pulls
  `KERNEL_TASK_METADATA[task_id].image_name` — no `--user-modes` flag
  needed or relevant (the CLI help text says so explicitly: `"Ignored for
  user/kernel"`), and the script already deduplicates images shared across
  kernel tasks.
- **`run_agent.py` already has a `--kernel-defense` flag** with presets
  (`original`, `strict`, `nodefense`) or a `+`-joined custom capability
  list (`nokaslr`, `nosmep`, `nosmap`, `userns`, `io_uring`,
  `kernelctf_hardening`), independent of the `--user-mode`/`--v8-mode`
  flags GYMSIEGE already passes — safe to pass alongside them
  unconditionally, since each evaluator only reads the flags for its own
  family.

### What GYMSIEGE's own code actually needs to change

Given the above, this is integration work against an already-working
upstream harness, not new-harness construction:

1. **Skip the two `user:`-only pre-flight stages for kernel tasks.**
   `exploitgym_adapter.py`'s `challenge_image_pull` stage (line ~451-465)
   hardcodes `--user-modes exp.hardened`, and `node_compatibility_probe`
   (line ~467-493) checks a Node runtime against
   `TASK_METADATA[task_id].images["exp.hardened"]` — both are meaningless
   for `kernel:` tasks (no `exp.hardened` mode exists for them, and the
   agent never touches a Node runtime inside the kernel target; it talks
   to a QEMU serial console instead). Gate both stages on
   `task.family == "user"` and skip them for `kernel:`.
2. **Add a generic kernel/v8-safe image pull step.** Replace the
   hardcoded `--user-modes exp.hardened` pull invocation with one that
   drops that flag when the trial's task isn't `user:` — `pull_images.py`
   already handles the dispatch correctly per-family, this is a call-site
   change, not new pull logic.
3. **Pass `--kernel-defense` through `_run_script()`.** Add it alongside
   the existing `--user-mode exp.hardened --v8-mode strict` flags
   (`exploitgym_adapter.py:718-719`) — confirmed safe to always pass all
   three, since `run_agent.py` only reads the flag relevant to each task's
   own inferred family.
4. **Wire `load_exploitgym_tasks(..., allow_non_userspace=True)` through
   from the orchestrator.** Already done, not new: `orchestrator.py`
   already exposes `--allow-non-userspace` (line 965) and threads it into
   `load_exploitgym_tasks()` (line 438-446), which already raises unless
   set for non-`user` families (`exploitgym_adapter.py:218-230`). This
   point is unchanged from the original plan below — restated here only
   because everything around it changed.
5. **Real due-diligence on kernel image size vs. sandbox disk budget.**
   GYMSIEGE's own Daytona `Resources(disk=10)` (10 GiB) cap forced
   `user:`-family images to be pulled fresh per-trial instead of baked
   into the snapshot (see the comment at `exploitgym_snapshot_build.py:142`
   and `exploitgym_adapter.py:447-449`: baking duplicates
   `/var/lib/docker` and blew the quota). Kernel target images
   (`cybergym/kernelctf-target:*`) bundle a full VM disk image plus a
   kernel source tree per `docs/docker_images.md` — no size numbers are
   published upstream, so this needs a real measurement (e.g. `docker
   manifest inspect` or an actual pull-and-`docker images` check on one
   kernelCTF target) before deciding bake-vs-pull-per-trial. The 10 GiB
   figure itself is a GYMSIEGE-chosen Daytona resource parameter, not a
   platform-hard limit — Modal's disk sizing is a separate, open question
   for whoever configures that sandbox.
6. **`/dev/kvm` needs to be real two layers deep, not just present on
   Modal generally.** `KernelEvaluator._extra_container_kwargs()` forwards
   `/dev/kvm` into the agent's own `docker run` automatically *if it can
   see the device node at the point the evaluator process itself runs* —
   which, in GYMSIEGE's current architecture, is inside the nested Docker
   context running inside the Modal sandbox, not on Modal's host directly.
   So the real requirement is: the Modal sandbox's own filesystem must
   expose a working `/dev/kvm`, *and* whatever container runtime GYMSIEGE
   runs ExploitGym's tooling under inside that sandbox must not itself
   strip device access before ExploitGym's own evaluator code gets to it.
   This is a sharper, more specific version of the original verification
   spike above, not a new requirement.
7. **Time/cost budget, now with real controller constants to plan
   against**, not just `stability_notes` guesswork: `controller.py`
   defines `CREATION_WAIT_TIMEOUT = 180.0`s (max wait to attach to an
   in-flight VM creation), `HEALTH_CHECK_RETRIES = 3` at
   `HEALTH_CHECK_RETRY_DELAY = 3.0`s, and `DEFAULT_SERVER_TTL = 3600`s
   (server auto-expires after an hour of no activity). Combined with
   `stability_notes` like "7~8 times success per 10 times run" implying
   multiple boot/exploit cycles per trial, `--trial-timeout` budgeting
   copied from the userspace tasks (minutes) still doesn't transfer — this
   part of the original plan holds.

### What's explicitly *not* needed, correcting the original plan below

- No new snapshot/image family or bake path needs to be *designed* — the
  existing per-trial-pull pattern GYMSIEGE already uses for `user:`
  images extends to `kernel:` images via the same `pull_images.py`, pending
  only the size due-diligence in point 5 above.
- No exploit build/run harness needs to be written — the agent compiles
  and runs its exploit *inside the QEMU VM itself*, over the serial
  console connection `KernelEvaluator`/the controller already establish.
  GYMSIEGE doesn't touch that step for `user:` tasks today either; kernel
  is symmetric, not a new category of work.
- No new success oracle needs to be designed — see the flag-file scoring
  above, already wired into the same `CheckResult` shape GYMSIEGE already
  consumes.

---

## Original plan (superseded by the correction above, kept for the record)

1. ~~**A new snapshot/image family.** `exploitgym_snapshot_build.py` and
   `exploitgym_adapter.py` both assume Docker-based userspace targets
   throughout — `node_compatibility_probe`, `challenge_image_pull`, the
   `docker run --network none` pattern. None of that applies to a
   QEMU-booted kernel target; this needs its own bake path, not a flag on
   the existing one.~~
2. ~~**Per-task kernel/environment resolution.** Each kernelCTF task pins a
   specific `environment` (e.g. `lts-6.1.36`, confirmed above) — the harness
   needs to resolve task → kernel image → boot config, mirroring what
   `TASK_METADATA[task_id].images["exp.hardened"]` does for userspace
   targets today, but for kernel builds instead of Docker images.~~
3. ~~**Exploit build/run harness.** kernelCTF submissions ship as
   `exploit/`-directory source (confirmed structure:
   `docs/`, `exploit/`, `metadata.json`, `original.tar.gz` per CVE, from
   `google/security-research`) — needs its own compile-and-run step, not
   the existing `uv run scripts/setup/pull_images.py` userspace pull path.~~
4. ~~**Success oracle.** The existing sanitizer-oracle re-detonation pattern
   (`daytona-notes.md`) doesn't translate directly — kernel exploit success
   is typically "did I get a root shell / read `/flag`", not "does a
   sanitizer-instrumented rebuild crash." Needs its own verification design.~~
5. **`--allow-non-userspace` is already the right hook point** —
   `exploitgym_adapter.py`'s `load_exploitgym_tasks()` already gates
   non-`user` families behind this flag; the new snapshot/harness plugs in
   there rather than needing a new CLI surface. (This one held up.)
6. **Cost and time budget are both much larger.** Kernel boot alone (even
   KVM-accelerated) is seconds-to-tens-of-seconds per attempt, and several
   kernelCTF submissions above have explicit `stability_notes` like "7~8
   times success per 10 times run" — meaning multiple boot/exploit cycles
   per trial are expected, not a single shot. `--trial-timeout` budgeting
   from the userspace tasks (minutes) doesn't transfer. (This one held up
   too, now with real controller constants added in point 7 above.)

## Recommended target for a first real attempt

Per the earlier discussion in this project: **`CVE-2026-23111_cos`** — in
`nf_tables` (the subsystem that dominates kernelCTF's real target
distribution, 12 of 27 tasks), and explicitly reachable from an
**unprivileged user namespace**, the cleanest, most defensible attack
surface of the set for a first real end-to-end attempt. See
`kernelctf-tasks.md` and `TODO.md`'s kernel-support scoping section for the
full reasoning.
