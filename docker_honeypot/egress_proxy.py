#!/usr/bin/env python3
"""Allow-listing HTTP CONNECT proxy: the only way out of the Docker boundary.

The sandbox container sits on an internal Docker network with no route out.
This proxy is the one container on both that network and the default bridge.
It accepts ``CONNECT host:443`` for exactly the hostnames in EGRESS_ALLOWLIST
(colon separated) and answers 403 to everything else, plain ``GET`` included.
Each request appends one JSON line to the log on the proxy's own filesystem:
UTC time, client address, target host:port, the decision, and the bytes each
way at close. Request bodies, headers and URL paths are never logged.

Standard library only, so the proxy image needs nothing beyond Python.
"""

from __future__ import annotations

import json
import os
import selectors
import socket
import socketserver
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORT = 3128
DEFAULT_LOG = Path("/var/log/egress/egress-proxy.log")
ALLOWED_PORT = 443
MAX_HEAD_BYTES = 16384
HEAD_TIMEOUT_SECONDS = 10.0
UPSTREAM_TIMEOUT_SECONDS = 15.0
IDLE_TIMEOUT_SECONDS = 1800.0
FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
BAD_GATEWAY = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"


def parse_allowlist(spec: str) -> frozenset[str]:
    """Colon-separated bare hostnames; '*', URLs, ports and IP ranges are refused."""
    hosts = set()
    for item in spec.split(":"):
        item = item.strip().lower()
        if not item:
            continue
        if item == "*" or "/" in item or "@" in item or " " in item:
            raise ValueError(f"EGRESS_ALLOWLIST entries are bare hostnames: {item!r}")
        hosts.add(item)
    if not hosts:
        raise ValueError("EGRESS_ALLOWLIST is empty")
    return frozenset(hosts)


def _split_host_port(authority: str) -> tuple[str, int] | None:
    host, sep, port = authority.rpartition(":")
    if not sep or not host or not port.isdigit():
        return None
    return host.lower(), int(port)


def decide(
    request_line: str, allowlist: frozenset[str], *, allowed_port: int = ALLOWED_PORT,
) -> tuple[bool, str]:
    """Return (allowed, target) for one request line.

    ``target`` is ``host:port`` for logging. For a non-CONNECT request only the
    host and port of an absolute URL are kept, never its path or query.
    """
    parts = request_line.strip().split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return False, "invalid"
    method, target, _version = parts
    if method.upper() != "CONNECT":
        split = urlsplit(target)
        if split.hostname:
            port = split.port or (443 if split.scheme == "https" else 80)
            return False, f"{split.hostname.lower()}:{port}"
        return False, "invalid"
    parsed = _split_host_port(target)
    if parsed is None:
        return False, "invalid"
    host, port = parsed
    return (host in allowlist and port == allowed_port), f"{host}:{port}"


class EgressLog:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        # Exists from start-up, so the runner can copy it out even when the
        # sandbox made no request at all.
        path.touch(exist_ok=True)

    def write(self, **fields: object) -> None:
        fields = {"time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **fields}
        line = json.dumps(fields, sort_keys=True) + "\n"
        with self.lock, open(self.path, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()


def _read_head(sock: socket.socket) -> bytes:
    sock.settimeout(HEAD_TIMEOUT_SECONDS)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_HEAD_BYTES:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _relay(client: socket.socket, upstream: socket.socket) -> tuple[int, int]:
    """Copy bytes both ways until either side closes; return (up, down)."""
    up = down = 0
    client.setblocking(False)
    upstream.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, upstream)
    selector.register(upstream, selectors.EVENT_READ, client)
    try:
        while True:
            events = selector.select(timeout=IDLE_TIMEOUT_SECONDS)
            if not events:
                return up, down
            for key, _mask in events:
                source = key.fileobj
                sink = key.data
                try:
                    chunk = source.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return up, down
                if not chunk:
                    return up, down
                sink.setblocking(True)
                try:
                    sink.sendall(chunk)
                except OSError:
                    return up, down
                finally:
                    sink.setblocking(False)
                if source is client:
                    up += len(chunk)
                else:
                    down += len(chunk)
    finally:
        selector.close()


class ProxyHandler(socketserver.BaseRequestHandler):
    server: "EgressProxyServer"

    def handle(self) -> None:
        client = self.request
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        try:
            head = _read_head(client)
        except OSError:
            head = b""
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        allowed, target = decide(
            first_line, self.server.allowlist, allowed_port=self.server.allowed_port,
        )
        if not allowed:
            try:
                client.sendall(FORBIDDEN)
            except OSError:
                pass
            self.server.log.write(
                client=peer, target=target, decision="refused", bytes_up=0, bytes_down=0,
            )
            return
        host, port = target.rsplit(":", 1)
        try:
            upstream = socket.create_connection((host, int(port)), timeout=UPSTREAM_TIMEOUT_SECONDS)
        except OSError as exc:
            try:
                client.sendall(BAD_GATEWAY)
            except OSError:
                pass
            self.server.log.write(
                client=peer, target=target, decision="allowed", bytes_up=0, bytes_down=0,
                error=f"upstream-connect-failed:{type(exc).__name__}",
            )
            return
        up = down = 0
        try:
            client.sendall(ESTABLISHED)
            # Bytes the client sent after the CONNECT head belong to the tunnel.
            leftover = head.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in head else b""
            if leftover:
                upstream.sendall(leftover)
                up += len(leftover)
            relayed_up, relayed_down = _relay(client, upstream)
            up += relayed_up
            down += relayed_down
        except OSError:
            pass
        finally:
            upstream.close()
            self.server.log.write(
                client=peer, target=target, decision="allowed", bytes_up=up, bytes_down=down,
            )


class EgressProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self, address: tuple[str, int], allowlist: frozenset[str], log: EgressLog,
        *, allowed_port: int = ALLOWED_PORT,
    ):
        self.allowlist = allowlist
        self.log = log
        self.allowed_port = allowed_port
        super().__init__(address, ProxyHandler)


def main() -> int:
    try:
        allowlist = parse_allowlist(os.environ.get("EGRESS_ALLOWLIST", ""))
    except ValueError as exc:
        print(f"egress proxy: {exc}", file=sys.stderr)
        return 64
    port = int(os.environ.get("EGRESS_PROXY_PORT", str(DEFAULT_PORT)))
    log = EgressLog(Path(os.environ.get("EGRESS_PROXY_LOG", str(DEFAULT_LOG))))
    server = EgressProxyServer(("0.0.0.0", port), allowlist, log)
    print(
        f"egress proxy listening on :{port}; allow-list has {len(allowlist)} host(s)",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
