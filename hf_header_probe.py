#!/usr/bin/env python3
"""
GYMSIEGE diagnostic — why `snapshot_download` fails with
`LocalEntryNotFoundError: Distant resource does not have a Content-Length.`

`huggingface_hub.get_hf_file_metadata` issues a HEAD to `huggingface.co` and
follows only *relative* redirects, so the absolute 302 to the CDN is never
followed at this stage. It then builds `HfFileMetadata.size` from:

    X-Linked-Size  or  (None if response.is_redirect else Content-Length)

Because the response *is* a redirect, `Content-Length` is deliberately
discarded and the size can only come from `X-Linked-Size`. The download then
aborts before any CDN request is attempted. The bake's own redirect probe
already proved the sandbox reaches `huggingface.co` and receives a 302 naming
`us.aws.cdn.hf.co` for all 20 archives, so the interesting question is no
longer "is the CDN blocked" but "which metadata headers survive the trip".

This script answers that by recording, for a few pinned archives:

  * which of X-Repo-Commit / X-Linked-ETag / ETag / X-Linked-Size /
    Content-Length are *present* on the Hub's 302 (presence only, plus the
    integer byte size, which is not sensitive);
  * whether sending `Accept-Encoding: identity` (which huggingface_hub always
    sends, and the bake's earlier probe did not) changes the answer;
  * whether a single-byte ranged GET actually reaches the CDN, which the
    metadata failure otherwise leaves untested.

It runs the identical probe locally and inside a throwaway Daytona sandbox and
prints the two side by side. It never records a signed URL, query string,
authorization header, token, or Secret placeholder — only hostnames, status
codes, header presence booleans, and byte counts.

Run with:

    .venv/bin/python hf_header_probe.py [--files N]

Requires DAYTONA_API_KEY plus a local Hugging Face login for the baseline.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from typing import Any, Optional

from daytona import (
    AsyncDaytona,
    CreateSandboxFromImageParams,
    Image,
    Resources,
)

import common
from common import get_logger, load_tasks, require_env

log = get_logger("hf_header_probe")

MARKER = "[hf_headers] "

# Executed verbatim both locally and inside the sandbox. Reads its inputs from
# the environment so no interpolation is needed and no token is ever embedded.
PROBE_PY = r'''
import json, os, sys
from urllib.parse import quote, urlsplit

import httpx

dataset = os.environ["GYMSIEGE_PROBE_DATASET"]
paths = json.loads(os.environ["GYMSIEGE_PROBE_PATHS"])
token = os.environ.get("HF_TOKEN") or ""

MARKER = "[hf_headers] "
INTERESTING = (
    "x-repo-commit",
    "x-linked-etag",
    "etag",
    "x-linked-size",
    "content-length",
    "x-xet-hash",
    # A proxy that buffers and re-frames a response typically drops
    # Content-Length and substitutes chunked transfer-encoding. Recording both
    # is what distinguishes "header stripped" from "header re-framed".
    "transfer-encoding",
    "content-encoding",
)


def emit(payload):
    print(MARKER + json.dumps(payload, sort_keys=True), flush=True)


if not token:
    emit({"error": "HF_TOKEN absent from environment"})
    sys.exit(1)

auth = {"Authorization": "Bearer " + token}
observations = []

try:
    import huggingface_hub
    hub_version = huggingface_hub.__version__
except Exception:
    hub_version = None

for path in paths:
    url = (
        "https://huggingface.co/datasets/" + dataset + "/resolve/main/"
        + quote(path, safe="/")
    )
    record = {"file": path}

    # Two HEADs: one plain, one mimicking huggingface_hub's own request, which
    # always sets Accept-Encoding: identity to force a real size back.
    for label, extra in (("plain", {}), ("identity", {"Accept-Encoding": "identity"})):
        try:
            with httpx.Client(follow_redirects=False, timeout=60) as client:
                r = client.head(url, headers={**auth, **extra})
            location = r.headers.get("location")
            is_redirect = bool(location) and 300 <= r.status_code < 400
            x_linked_size = r.headers.get("x-linked-size")
            content_length = r.headers.get("content-length")
            # Mirrors huggingface_hub's own size resolution
            # (file_download.py:1645-1648): X-Linked-Size, or Content-Length
            # but only when the response is not a redirect. If this is False
            # the client raises FileMetadataError and the download aborts.
            size_resolvable = bool(x_linked_size) or (
                not is_redirect and bool(content_length)
            )
            record[label] = {
                "status": r.status_code,
                "is_redirect": is_redirect,
                "redirect_host": urlsplit(location).hostname if location else None,
                "headers_present": {
                    name: (name in r.headers) for name in INTERESTING
                },
                # Byte counts only. A file size is not sensitive.
                "x_linked_size": x_linked_size,
                "content_length": content_length,
                "size_resolvable": size_resolvable,
            }
        except Exception as exc:
            record[label] = {"error": type(exc).__name__ + ": " + str(exc)[:200]}

    # Does the CDN actually answer? One byte, redirects followed. The signed
    # URL is used but never recorded -- only its hostname and status.
    try:
        with httpx.Client(follow_redirects=True, timeout=60) as client:
            r = client.get(url, headers={**auth, "Range": "bytes=0-0"})
        record["ranged_get"] = {
            "status": r.status_code,
            "final_host": urlsplit(str(r.url)).hostname,
            "bytes_returned": len(r.content),
            "content_range_present": "content-range" in r.headers,
        }
    except Exception as exc:
        record["ranged_get"] = {"error": type(exc).__name__ + ": " + str(exc)[:200]}

    observations.append(record)

emit({"huggingface_hub_version": hub_version, "observations": observations})
'''

_PIP = "python3 -m pip install --quiet --break-system-packages {pkgs} >/dev/null 2>&1 || python3 -m pip install --quiet {pkgs}"
REMOTE_SETUP = _PIP.format(pkgs="httpx huggingface_hub")


def _parse_marker(output: str) -> Optional[dict[str, Any]]:
    for line in output.splitlines():
        if line.startswith(MARKER):
            try:
                return json.loads(line[len(MARKER):])
            except json.JSONDecodeError:
                log.warning("probe emitted an unparseable marker line")
    return None


def _selected_paths(limit: int) -> list[str]:
    """Pinned-task paths: large archives *and* small directly-served files.

    Both classes matter, and for opposite reasons. A large `src.tgz` is
    LFS/Xet-backed, so the Hub answers with a `302` carrying `X-Linked-Size`
    and a missing `Content-Length` is harmless. A small `.toml` is served
    directly as `200` with no `X-Linked-Size`, so `Content-Length` is the only
    size the client can use — which is exactly the case the bake's
    `allow_patterns` (`projects/<task>/**`) also pulls in.
    """
    from huggingface_hub import HfApi

    tasks = [t.path for t in load_tasks(common.ROOT / "tasks.pinned.txt")]
    repo_files = HfApi(token=True).list_repo_files(
        common.HF_DATASET, repo_type="dataset"
    )

    def in_pinned_scope(path: str) -> bool:
        return any(
            path.startswith(f"projects/{task}/")
            or path.startswith(f"data/projects/{task}/")
            for task in tasks
        )

    # Project-level files such as project.toml sit one level above the task
    # directory, so match the project prefix too rather than only the task.
    projects = {task.split("/", 1)[0] for task in tasks}

    def in_project_scope(path: str) -> bool:
        return any(
            path.startswith(f"projects/{project}/")
            or path.startswith(f"data/projects/{project}/")
            for project in projects
        )

    archives = [p for p in repo_files if p.endswith("src.tgz") and in_pinned_scope(p)]
    # Everything else the bake's allow_patterns pull in. Selected by "not an
    # archive" rather than by extension: an earlier version guessed at
    # .toml/.json/.txt/.md/.yaml and matched nothing at all, so the check
    # silently never ran. Do not reintroduce an extension allowlist here.
    others = [
        p
        for p in repo_files
        if not p.endswith("src.tgz")
        and (in_pinned_scope(p) or in_project_scope(p))
    ]

    log.info(
        "in pinned scope: %d archive(s), %d non-archive file(s)",
        len(archives),
        len(others),
    )
    if not others:
        log.warning(
            "no non-archive files matched the pinned scope; the direct-response "
            "check cannot run, so a missing Content-Length on a 200 stays "
            "untested (huggingface_hub ignores Content-Length on redirects)"
        )
    return archives[:limit] + others[:limit]


def probe_locally(dataset: str, paths: list[str]) -> Optional[dict[str, Any]]:
    from huggingface_hub import get_token

    token = get_token()
    if not token:
        log.warning("no local Hugging Face token; skipping the local baseline")
        return None

    env = {
        **os.environ,
        "GYMSIEGE_PROBE_DATASET": dataset,
        "GYMSIEGE_PROBE_PATHS": json.dumps(paths),
        "HF_TOKEN": token,
    }
    proc = subprocess.run(
        [sys.executable, "-c", PROBE_PY],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        log.warning("local probe exited %s: %s", proc.returncode, proc.stderr[-500:])
    return _parse_marker(proc.stdout)


async def probe_in_sandbox(dataset: str, paths: list[str]) -> Optional[dict[str, Any]]:
    require_env("DAYTONA_API_KEY")
    hf_secret_name = common.require_env("GYMSIEGE_HF_SECRET_NAME")

    async with AsyncDaytona() as daytona:
        page = await daytona.secret.list(name=hf_secret_name, limit=200)
        if not any(item.name == hf_secret_name for item in page.items):
            raise RuntimeError(
                f"Daytona organization Secret {hf_secret_name!r} does not exist; "
                "run `configure_secrets.py huggingface` first."
            )

        sandbox = await daytona.create(
            CreateSandboxFromImageParams(
                image=Image.debian_slim("3.12"),
                name=f"siege-hf-header-probe-{int(time.time())}",
                os_user="root",
                resources=Resources(cpu=1, memory=2, disk=5),
            ),
            timeout=600,
        )
        log.info("probe sandbox created (id=%s)", sandbox.id)
        try:
            await sandbox.set_ttl(common.SANDBOX_SAFETY_TTL_MINUTES)
            await sandbox.update_secrets(common.sandbox_secret_refs(("HF_TOKEN",)))
            await sandbox.stop(timeout=120)
            await sandbox.start(timeout=120)

            script = (
                f"{REMOTE_SETUP}\n"
                f"export GYMSIEGE_PROBE_DATASET={dataset!r}\n"
                f"export GYMSIEGE_PROBE_PATHS={json.dumps(paths)!r}\n"
                "python3 - <<'GYMSIEGE_PROBE_EOF'\n"
                f"{PROBE_PY}\n"
                "GYMSIEGE_PROBE_EOF\n"
            )
            r = await sandbox.process.exec(script, timeout=900)
            output = str(getattr(r, "result", r) or "")
            if getattr(r, "exit_code", 0) != 0:
                log.warning("remote probe exit=%s; tail:\n%s", r.exit_code, output[-2000:])
            return _parse_marker(output)
        finally:
            try:
                await sandbox.delete()
                log.info("probe sandbox %s deleted", sandbox.id)
            except Exception as exc:
                log.error("probe sandbox %s NOT deleted: %s", sandbox.id, exc)


def _summarize(label: str, result: Optional[dict[str, Any]]) -> None:
    print(f"\n=== {label} ===")
    if result is None:
        print("  (no observation returned)")
        return
    if "error" in result:
        print(f"  error: {result['error']}")
        return
    print(f"  huggingface_hub {result.get('huggingface_hub_version')}")
    for record in result.get("observations", []):
        identity = record.get("identity", {})
        kind = "redirected/LFS" if identity.get("is_redirect") else "direct/small"
        print(f"  {record['file']}  [{kind}]")
        for key in ("plain", "identity"):
            block = record.get(key, {})
            if "error" in block:
                print(f"    {key:9s} error: {block['error']}")
                continue
            present = block.get("headers_present", {})
            names = ", ".join(sorted(n for n, ok in present.items() if ok)) or "(none)"
            verdict = "size OK" if block.get("size_resolvable") else "*** SIZE UNRESOLVABLE ***"
            print(
                f"    {key:9s} status={block.get('status')} "
                f"-> {block.get('redirect_host')}  x-linked-size={block.get('x_linked_size')} "
                f"content-length={block.get('content_length')}  {verdict}"
            )
            print(f"              present: {names}")
        got = record.get("ranged_get", {})
        if "error" in got:
            print(f"    ranged_get error: {got['error']}")
        else:
            print(
                f"    ranged_get status={got.get('status')} "
                f"final_host={got.get('final_host')} bytes={got.get('bytes_returned')}"
            )


def _verdict(local: Optional[dict[str, Any]], remote: Optional[dict[str, Any]]) -> None:
    """State the conclusion outright rather than leaving it to header diffing."""

    print("\n=== VERDICT ===")
    if not remote or "observations" not in remote:
        print("  no sandbox observations; nothing to conclude")
        return

    def by_file(result: Optional[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        if not result:
            return {}
        return {r["file"]: r.get("identity", {}) for r in result.get("observations", [])}

    local_by, remote_by = by_file(local), by_file(remote)
    failing = [f for f, b in remote_by.items() if not b.get("size_resolvable")]

    for path, block in remote_by.items():
        peer = local_by.get(path, {})
        if not peer:
            continue
        lost = sorted(
            name
            for name, here in peer.get("headers_present", {}).items()
            if here and not block.get("headers_present", {}).get(name)
        )
        if lost:
            print(f"  {path}\n    headers present locally but missing in sandbox: {', '.join(lost)}")

    if not failing:
        print("  Every probed file still resolves a size inside the sandbox.")
        print("  The small-file Content-Length hypothesis is NOT confirmed by this run.")
        return

    print(f"\n  {len(failing)} file(s) would abort in huggingface_hub — size unresolvable:")
    for path in failing:
        block = remote_by[path]
        chunked = block.get("headers_present", {}).get("transfer-encoding")
        print(
            f"    {path}  (status={block.get('status')}, "
            f"redirect={block.get('is_redirect')}, chunked={bool(chunked)})"
        )
    print(
        "\n  This is the confirming evidence: a directly-served file with no\n"
        "  X-Linked-Size fallback and no Content-Length cannot be downloaded."
    )


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--files",
        type=int,
        default=3,
        help="how many of EACH class to probe: large archives and small direct files (default 3)",
    )
    parser.add_argument("--skip-local", action="store_true", help="sandbox probe only")
    args = parser.parse_args()

    paths = _selected_paths(args.files)
    if not paths:
        raise RuntimeError("no pinned paths resolved from the dataset listing")
    log.info("probing %d file(s) from %s", len(paths), common.HF_DATASET)

    local = None if args.skip_local else probe_locally(common.HF_DATASET, paths)
    remote = await probe_in_sandbox(common.HF_DATASET, paths)

    _summarize("LOCAL (WSL)", local)
    _summarize("DAYTONA SANDBOX", remote)
    _verdict(local, remote)

    out = common.RESULTS_DIR / "hf_header_probe.json"
    common.atomic_write_json(
        out, {"observed_at": time.time(), "local": local, "sandbox": remote}
    )
    print(f"\nwrote {out}")


if __name__ == "__main__":
    asyncio.run(main())
