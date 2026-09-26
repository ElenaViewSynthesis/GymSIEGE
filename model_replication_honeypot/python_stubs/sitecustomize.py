"""Python-only canary file and socket instrumentation."""

from __future__ import annotations

import builtins
import os
import socket

from honeypot_events import emit, is_canary


_open = builtins.open
_connect = socket.socket.connect


def monitored_open(file, mode="r", *args, **kwargs):
    if is_canary(file):
        emit("WEIGHT_READ", "local", str(file), f"python open mode={mode}")
    return _open(file, mode, *args, **kwargs)


def monitored_connect(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        host = str(address[0])
        if host not in {"127.0.0.1", "::1", "localhost"}:
            emit("NETWORK_CONNECT_ATTEMPT", "unknown", str(address), "python socket.connect")
            if os.environ.get("HONEYPOT_BLOCK_CLOUD", "1") == "1":
                raise PermissionError("model-replication-honeypot blocked external network")
    return _connect(sock, address)


builtins.open = monitored_open
socket.socket.connect = monitored_connect
