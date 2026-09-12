# Tradeoffs of a separate Ubuntu 16.04 runner file

Inspected: 2026-09-12. Local Git baseline: `b1fff9a`, with existing
uncommitted changes. This is a source review and review of saved evidence,
not a live compatibility test.

Adding a separate runner file would separate maintenance and release decisions,
but would not itself solve the runtime/library mismatch described in
[`codex-task-open-issues.md`](codex-task-open-issues.md). The architectural
question is whether a second execution path earns its ongoing maintenance cost.
This note covers that decision, without implementing or providing runtime
workarounds for the autonomous exploit-development workflow.

## What the current code establishes

- [`exploitgym_snapshot_build.py`](exploitgym_snapshot_build.py) prepares the
  outer toolchain snapshot using a Debian image and downloads a specific
  prebuilt Node runtime. Ubuntu 16.04 is the inner target's operating system;
  it is not the current outer snapshot's base image.
- [`exploitgym_adapter.py`](exploitgym_adapter.py) restores that snapshot,
  obtains the trial's target image, and checks the mounted runtime inside that
  target. Successful startup in the outer builder therefore does not establish
  compatibility inside the target.
- The saved `results/glibc_probe.json` reports Ubuntu 16.04.7 LTS and highest
  observed symbol `GLIBC_2.23` for the first three old-image records inspected.
  A successful metadata probe means the inspection succeeded, not that the
  agent runtime works. The issue document reports seven runtime failures and
  four previously compatible tasks; those counts were not freshly reproduced.
- [`probe_arvo_glibc.py`](probe_arvo_glibc.py) already provides a separate
  diagnostic entry point. A new file solely to inventory OS/library versions
  would overlap with an existing responsibility.
- The builder and adapter share the snapshot setting in
  [`common.py`](common.py). A different Python filename does not create a
  separate cloud artifact or rollback boundary. The current builder deletes
  an existing snapshot of the selected name before publishing its replacement.

## What “a new file” could mean

| Choice | Benefit | Cost or limitation |
| --- | --- | --- |
| Separate design/evidence document | Makes assumptions and compatibility limits reviewable without changing execution | Does not make the old image runnable |
| Separate diagnostic tool | Can isolate a substantially different inspection responsibility | Duplicates the existing probe if it only reports OS and library metadata |
| Thin entry point sharing existing infrastructure | Makes a distinct operating profile visible while limiting duplicated lifecycle code | Still adds configuration, documentation, and validation obligations; the filename cannot fix binary compatibility |
| Complete copy of the builder or runner | Gives the legacy path independent editing and release cadence | Forks cleanup, timeout, secret handling, containment, reporting, and future bug fixes |
| Separate target-image definition | Makes the chosen environment explicit and reproducible when its inputs are pinned | Changing the target's libraries or base system can change behavior and invalidate comparisons with the original benchmark image |

## Main tradeoffs

**Regression isolation versus duplicated maintenance.** A genuinely separate
artifact can reduce exposure of the working environment to experimental
changes. A copied script alone cannot guarantee this. Two execution paths
also create opportunities for fixes to land in only one. Issue #3 is a useful
local example: the same secret-attachment restart behavior already exists in
two adapters, and the issue asks for consistent handling in both.

**Explicit selection versus configuration mistakes.** A legacy entry point
can make operator intent clearer. It also introduces another thing to choose
alongside the task, snapshot, and runtime. Misaligned choices can produce
misleading failures. OS names alone are insufficient evidence of compatibility;
the actual runtime and image determine the result.

**Independent rollback versus resource cost.** Keeping distinct artifacts
can preserve an established environment while an alternative is assessed.
It increases storage, build time, provenance tracking, and cleanup work.
The current builder requests 10 GiB of disk and deliberately leaves challenge
images out of the snapshot because of the repository's recorded capture-space
constraint. A second filename creates no additional capacity. Current account
limits were not checked during this review.

**Historical fidelity versus convenience.** Preserving the original target
environment supports meaningful comparisons. Replacing its libraries or moving
the application to another base image may make ordinary software maintenance
easier, but produces a changed experimental environment. Results from that
environment should not silently stand in for the original target's results.

**One compatibility policy versus multiple supported combinations.** A shared
implementation reduces drift, but a change to it has a wider potential impact.
Separate profiles reduce that coupling while increasing the number of
runtime/image combinations whose compatibility must be established. Neither
layout supplies evidence that a candidate runtime supports both generations.

## Important qualifications in the issue document

The priority ordering is clear: the library mismatch is primary; network
isolation and restart resilience are separate issues. A new legacy runner
would not inherently resolve either of those other failures.

The document refers to upstream runtime validation, but the local builder
actually performs its own selected executable checks rather than invoking
upstream `validate.sh`. Those checks run in the outer build environment.
They should not be described as evidence of complete target-side compatibility.

The document also explicitly says upstream's source-build behavior has not
been inspected. This review did not fetch or assess that implementation, so
it cannot establish that removing a flag, changing runtime distribution, or
choosing an older release would solve the problem.

The local test `test_snapshot_installs_only_codex_runtime` in
[`tests/test_core.py`](tests/test_core.py) checks generated bootstrap text,
including the current installer flags. That is a configuration assertion,
not a runtime compatibility test. The issue document's “59 tests currently
pass” statement was not revalidated here.

## Decision

For the file-organization decision, a full duplicate runner has the weakest
case: it introduces substantial maintenance obligations without addressing
the underlying compatibility question. A separate document is useful now.
A distinct execution entry point would need a demonstrated operational
requirement beyond “this image is Ubuntu 16.04” to justify its cost.

This review added documentation only. No runtime code, target images, snapshots,
secrets, or existing working-tree changes were modified. No cloud resources,
model calls, benchmark trials, or tests were run.
