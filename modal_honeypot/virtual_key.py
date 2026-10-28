#!/usr/bin/env python3
"""Minimal LiteLLM virtual-key administration without secret-bearing logs."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


class VirtualKeyError(RuntimeError):
    """A key-management request failed without exposing request credentials."""


class AdminClient(Protocol):
    def generate(self, payload: Mapping[str, object]) -> Mapping[str, object]: ...

    def info(self, key_id: str) -> Mapping[str, object]: ...

    def delete(self, key_id: str) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class MintedKey:
    key: str = field(repr=False)
    management_id: str = field(repr=False)
    key_alias: str
    fingerprint: str
    token_id: str | None = None
    key_hash: str | None = None

    @property
    def recorded_id(self) -> str:
        return self.token_id or self.key_hash or self.fingerprint


def admin_base_url(provider_base_url: str) -> str:
    """Turn an OpenAI-compatible ``.../v1`` URL into the proxy admin root."""
    parsed = urllib.parse.urlsplit(provider_base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("the gateway URL must be an absolute HTTP(S) URL")
    path = parsed.path.rstrip("/")
    if path.endswith("/v1"):
        path = path[:-3]
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", "")).rstrip("/")


class LiteLLMAdminClient:
    """Thin JSON client for the three LiteLLM key-management operations used here."""

    def __init__(self, gateway_url: str, master_key: str, *, timeout: float = 30.0):
        if not master_key:
            raise ValueError("LITELLM_MASTER_KEY is required")
        self._base_url = admin_base_url(gateway_url)
        self._master_key = master_key
        self._timeout = timeout

    def _request(
        self, method: str, path: str, *, payload: Mapping[str, object] | None = None,
        query: Mapping[str, str] | None = None,
    ) -> Mapping[str, object]:
        url = self._base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._master_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise VirtualKeyError(
                f"LiteLLM key administration failed for {path} with HTTP {exc.code}"
            ) from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError):
            raise VirtualKeyError(f"LiteLLM key administration failed for {path}") from None
        if not isinstance(decoded, dict):
            raise VirtualKeyError(f"LiteLLM returned a non-object response for {path}")
        return decoded

    def generate(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        return self._request("POST", "/key/generate", payload=payload)

    def info(self, key_id: str) -> Mapping[str, object]:
        return self._request("GET", "/key/info", query={"key": key_id})

    def delete(self, key_id: str) -> Mapping[str, object]:
        return self._request("POST", "/key/delete", payload={"keys": [key_id]})


def mint_virtual_key(
    client: AdminClient, *, alias: str, model: str, budget_usd: float, ttl: str,
    metadata: Mapping[str, object],
) -> MintedKey:
    # No "tags": LiteLLM gates key tags behind an Enterprise license
    # (HTTP 403 from _premium_user_check on an unlicensed gateway). The
    # alias and metadata already carry the run identity Langfuse joins on.
    payload: dict[str, object] = {
        "key_alias": alias,
        "models": [model],
        "max_budget": budget_usd,
        "duration": ttl,
        "metadata": dict(metadata),
    }
    response = client.generate(payload)
    key = response.get("key")
    if not isinstance(key, str) or not key:
        raise VirtualKeyError("LiteLLM /key/generate did not return a virtual key")
    token_id = response.get("token_id")
    key_hash = response.get("key_hash")
    token_id = token_id if isinstance(token_id, str) and token_id else None
    key_hash = key_hash if isinstance(key_hash, str) and key_hash else None
    fingerprint = "sha256:" + hashlib.sha256(key.encode()).hexdigest()
    return MintedKey(
        key=key,
        # LiteLLM documents /key/info and /key/delete in terms of the returned
        # virtual key. Keep it only in memory for those lifecycle calls; the
        # token/hash is the non-secret identifier recorded in metadata.
        management_id=key,
        key_alias=alias,
        fingerprint=fingerprint,
        token_id=token_id,
        key_hash=key_hash,
    )


def key_spend(client: AdminClient, key_id: str) -> float:
    response = client.info(key_id)
    info: Any = response.get("info", response)
    spend = info.get("spend") if isinstance(info, dict) else None
    if not isinstance(spend, (int, float)) or isinstance(spend, bool):
        raise VirtualKeyError("LiteLLM /key/info did not return numeric spend")
    return float(spend)


def revoke_virtual_key(client: AdminClient, key_id: str) -> None:
    client.delete(key_id)
