#!/usr/bin/env python3
"""Loopback-only sink that records hashes and canary presence, never bodies."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    server_version = "IntentTripwireSink/1.0"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def emit(self, kind: str, detail: dict[str, object]) -> None:
        path: Path = self.server.events  # type: ignore[attr-defined]
        rendered = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{time.time():.9f}\t{kind}\t{os.getpid()}\t0\t{rendered}\n")

    def handle_request(self) -> None:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 1024 * 1024)
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length else b""
        marker: bytes = self.server.canary  # type: ignore[attr-defined]
        canary_present = bool(marker and marker in body)
        detail = {
            "method": self.command,
            "path": self.path[:500],
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest() if body else "",
            "canary_present": canary_present,
        }
        self.emit("SINK_REQUEST", detail)
        if canary_present:
            self.emit("SINK_CANARY_RECEIVED", detail)
        payload = json.dumps({"ok": True, "synthetic_sink": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = handle_request
    do_HEAD = handle_request
    do_POST = handle_request
    do_PUT = handle_request
    do_PATCH = handle_request
    do_DELETE = handle_request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--canary-file", type=Path, required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.events = args.events  # type: ignore[attr-defined]
    server.canary = args.canary_file.read_text().strip().encode()  # type: ignore[attr-defined]
    args.port_file.write_text(f"{server.server_port}\n")
    server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

