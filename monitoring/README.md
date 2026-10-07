# monitoring/

Read-only watchers for in-flight CI sweeps. These never dispatch, cancel, or
write anything — run them in a separate shell while a sweep driver runs.

## `watch_exploitbench_sweep.sh`

Watches an `exploitbench-modal.yml` seed-1 sweep (the one dispatched by
`exploitbench/run_modal_all_seed1.sh`) and prints a per-env roll-up once every
cell is terminal.

A sweep is isolated by **run recency** — the newest `EB_COUNT` `workflow_dispatch`
runs of the workflow. It is deliberately *not* keyed to a commit: the driver
dispatches `--ref main`, which resolves to main's tip at dispatch time, so if a
push lands mid-sweep the cells spread across several commits. Recency is stable;
sha is not. A false "done" inside the brief gap between serial cells is prevented
by requiring inflight==0 **and** the newest run id unchanged across two polls.

```bash
# from a separate shell, alongside run_modal_all_seed1.sh:
./monitoring/watch_exploitbench_sweep.sh                 # watch newest 14, poll 30s
EB_ONCE=1 ./monitoring/watch_exploitbench_sweep.sh       # one status snapshot + roll-up, no loop
EB_COUNT=14 EB_POLL=20 ./monitoring/watch_exploitbench_sweep.sh
```

Live line, each poll:

```
[HH:MM:SS] seen 7/14  done 6  running/queued 1  |  success 6  other 0
```

Roll-up at completion: a table of `ENV | CONCL | DUR | RUN_ID` for all 14 runs,
then per-env seed-1 `status`/`score`/`cost` pulled from the S3 aggregate DB
(`s3://cyberattackgym/exploitbench-modal/aggregate.sqlite`, override with
`EB_S3_DB`). The score section is best-effort — it needs `aws` creds; the run
table works without them.

### Env knobs

| var         | default                                                | meaning                                   |
|-------------|--------------------------------------------------------|-------------------------------------------|
| `EB_COUNT`  | `14`                                                   | how many newest dispatch runs to watch    |
| `EB_POLL`   | `30`                                                   | seconds between polls                     |
| `EB_ONCE`   | `0`                                                    | `1` = print once and exit (no loop)       |
| `EB_S3_DB`  | `s3://cyberattackgym/exploitbench-modal/aggregate.sqlite` | score DB location                      |

Requires `gh` (authenticated) on PATH; `aws` and `python3` only for the score
section. Stop the loop any time with Ctrl-C.
