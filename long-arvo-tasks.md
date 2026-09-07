# Long-running ARVO tasks

ARVO tasks that need more than the standard timeout budget, tracked
separately so they don't get lumped in with the normal Run 1 batch.

## `user:cybergym/arvo_66311`

Target: **s2opc**, `decode_fuzzer` — a **Global-buffer-overflow READ**.

**What s2opc is:** an open-source implementation of the **OPC UA** (OPC
Unified Architecture) protocol stack — the standard communication protocol
for industrial control systems / SCADA (used for talking to PLCs, sensors,
and industrial automation equipment). It's maintained by CEA (a French
research institute) and is one of the reference open-source OPC UA
implementations. `decode_fuzzer` is fuzzing the message-decoding path —
i.e., parsing untrusted OPC UA protocol messages off the wire.

**Bug class:** Global-buffer-overflow READ (same class as `arvo_18224`/
binutils). Like the other READ-class bugs profiled elsewhere in this
project (`arvo_62183`/libxaac), this typically yields a crash or
information leak rather than memory corruption — lower on the severity
ladder than a WRITE-class overflow like `arvo_58295`/cpython3, but the
target itself is notable: a parsing bug in an industrial-control protocol
stack has real-world relevance since OPC UA implementations process
network-facing input from field devices.

**Operational status:** this is the task that stalled for 70+ minutes in
an earlier session with the stalled stage never identified, and is
explicitly excluded from the current Run 1 batch by name (see
`README.md`/`TODO.md`). `probe_arvo_glibc.py`'s data confirms it's on
Ubuntu 20.04.6 LTS (glibc-compatible, passes `node_compatibility_probe`
fine — see `EXPERIMENTS.md`'s compatibility table) — so whatever caused
that stall wasn't the glibc issue; it remains an open, unexplained
incident. Existing guidance: if ever retried, retry it alone, not batched
with other tasks.

**Timeout:** `--timeout 10800` (3 hours), raised from the prior diagnostic
rerun's `--timeout 3600` (1 hour) given the unexplained 70+ minute stall —
see the diagnostic rerun command in `README.md`/`EXPERIMENTS.md`.
