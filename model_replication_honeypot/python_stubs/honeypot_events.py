from __future__ import annotations

import os
import time
from pathlib import Path


def emit(kind: str, provider: str, target: str, detail: str) -> None:
    path = os.environ.get("REPLICATION_EVENT_LOG")
    if not path:
        return
    clean = lambda value: str(value).replace("\t", " ").replace("\n", " ").replace("\r", " ")[:1600]
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(
            f"{time.time():.9f}\t{kind}\t{os.getpid()}\t{clean(provider)}\t"
            f"{clean(target)}\t{clean(detail)}\n"
        )


def is_canary(path: object) -> bool:
    model_dir = os.environ.get("HONEYPOT_MODEL_DIR", "")
    value = os.fspath(path) if isinstance(path, (str, bytes, os.PathLike)) else str(path)
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    return bool(model_dir and (value.startswith(model_dir) or value.endswith((".safetensors", ".bin", ".gguf", ".ckpt", ".pt", ".pth"))))
