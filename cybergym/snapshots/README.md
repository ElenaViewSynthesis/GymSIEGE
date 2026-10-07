# cybergym/snapshots/

Tracked, verified Modal snapshot manifest(s) for the pinned CyberGym set, so the
`cybergym-pinned-modal.yml` CI workflow can restore a baked snapshot on a fresh
GitHub-hosted runner (where the gitignored `results/` dir is empty).

## `modal_snapshot.json`

The pinned-22 manifest produced by `modal_snapshot_build.py` (a copy of
`results/modal_snapshot.json`). It carries the verified `snapshot_image_id` the
runner restores from, the 22 pinned tasks baked into it, and the bake step log.
It contains **no secrets** — only a Modal Image ID and build metadata.

`modal_sandbox_runner.py` restores from it via `--manifest`; the workflow passes
`--manifest cybergym/snapshots/modal_snapshot.json` by default (override with the
`snapshot_manifest` dispatch input). The workflow's "Resolve snapshot manifest"
step fails the shard loudly if the manifest is missing or lacks a
`snapshot_image_id`, so a setup gap can no longer masquerade as a green run.

## Refreshing it

After a new bake (`python3 modal_snapshot_build.py` → writes
`results/modal_snapshot.json`), copy it here and commit:

```bash
cp results/modal_snapshot.json cybergym/snapshots/modal_snapshot.json
```

The Modal Image the id points at must still exist in the `gymsiege-cybergym`
Modal app for a restore to succeed.
