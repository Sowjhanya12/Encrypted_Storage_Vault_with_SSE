"""
client/cloud_client.py -- thin HTTP wrapper around the untrusted
cloud's API (cloud/cloud_app.py), used only by client/client_app.py.

Deliberately contains NO cryptography and makes NO decisions about
what any byte means -- it only shuttles already-encrypted bytes
(base64-encoded for JSON transport) to and from the cloud's HTTP API,
and decodes the JSON envelope back into plain bytes/dicts for the
caller. Keeping "make an HTTP call" and "decide what plaintext means"
in separate modules mirrors the same separation cloud/storage.py
(dumb persistence) and cloud/cloud_app.py (routes) already keep on the
other side of the trust boundary -- this module is the client-side
analogue of that discipline.

Every function here can raise CloudUnavailableError if the cloud
process cannot be reached at all (connection refused, DNS failure,
timeout). client_app.py's routes catch that and return a clear 502 to
the browser rather than letting a raw connection traceback leak
through -- the cloud being offline is an ordinary, expected failure
mode for a two-process demo, not a bug.
"""

from __future__ import annotations

import base64
import os
import threading
from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional, Tuple

import requests

CLOUD_BASE_URL = os.environ.get("CLOUD_BASE_URL", "http://127.0.0.1:5001")
_TIMEOUT_SECONDS = 10

# Which cloud vault namespace calls on THIS thread address. client_app.py
# sets it per request from the logged-in user's account record, so no
# route can accidentally reach another user's vault: the credentials
# come from the server-side session, never from the browser. Unset
# (the default) means the legacy single-vault namespace, which keeps
# every pre-multi-user caller -- and its tests -- working unchanged.
_scope = threading.local()

# Sentinel scope for a request that must not touch any vault at all
# (e.g. an administrator, or an anonymous request).
NO_VAULT = object()


class VaultScopeError(Exception):
    """A cloud call was attempted from a context that has no vault."""


def set_vault_scope(scope) -> None:
    """scope: None (legacy namespace), NO_VAULT, or (vault_id, token)."""
    _scope.value = scope


def get_vault_scope():
    return getattr(_scope, "value", None)


@contextmanager
def vault_scope(vault_id: str, token: bytes):
    previous = get_vault_scope()
    set_vault_scope((vault_id, token))
    try:
        yield
    finally:
        set_vault_scope(previous)


def _scope_headers() -> dict:
    scope = get_vault_scope()
    if scope is None:
        return {}
    if scope is NO_VAULT:
        raise VaultScopeError("this request has no vault to address")
    vault_id, token = scope
    return {"X-Vault-Id": vault_id, "Authorization": "Bearer " + _b64(token)}


class CloudUnavailableError(Exception):
    """The cloud process could not be reached at all (connection
    refused, DNS failure, timeout) -- distinct from CloudError, which
    means the cloud responded but with an error."""


class CloudError(Exception):
    """The cloud responded with a 4xx/5xx status."""

    def __init__(self, status_code: int, message: str):
        super().__init__(f"cloud returned {status_code}: {message}")
        self.status_code = status_code


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data)


def _request(method: str, path: str, **kwargs) -> "requests.Response":
    headers = _scope_headers()
    if headers:
        kwargs["headers"] = {**kwargs.get("headers", {}), **headers}
    try:
        resp = requests.request(method, f"{CLOUD_BASE_URL}{path}", timeout=_TIMEOUT_SECONDS, **kwargs)
    except requests.exceptions.RequestException as exc:
        raise CloudUnavailableError(
            f"could not reach the cloud service at {CLOUD_BASE_URL}: {exc}"
        ) from exc
    if resp.status_code >= 400:
        try:
            message = resp.json().get("error", resp.text)
        except ValueError:
            message = resp.text
        raise CloudError(resp.status_code, message)
    return resp


def health() -> dict:
    return _request("GET", "/health").json()


# ---------------------------------------------------------------------------
# vaults (multi-user extension)
# ---------------------------------------------------------------------------

def register_vault(vault_id: str, token: bytes) -> None:
    """Create a vault namespace. Sends the access token once so the
    cloud can store its hash; no key or password is involved."""
    _request("POST", "/vaults", json={"vault_id": vault_id, "token": _b64(token)})


def vault_stats() -> dict:
    return _request("GET", "/stats").json()


def list_index_entries(limit: int = 100, offset: int = 0) -> dict:
    data = _request("GET", "/index", params={"limit": limit, "offset": offset}).json()
    for e in data["entries"]:
        e["value"] = _unb64(e["value"])
    return data


def legacy_kdf() -> dict:
    data = _request("GET", "/legacy/kdf").json()
    for k in ("kdf_salt", "kdf_verifier"):
        data[k] = _unb64(data[k]) if data[k] is not None else None
    return data


def adopt_legacy_vault() -> dict:
    return _request("POST", "/vaults/adopt-legacy").json()


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def push_document(doc_id: str, enc_name: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> None:
    _request(
        "POST",
        "/documents",
        json={
            "doc_id": doc_id,
            "enc_name": _b64(enc_name),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
            "tag": _b64(tag),
        },
    )


def list_documents() -> "List[dict]":
    """Metadata only (doc_id, enc_name -- still encrypted bytes, just
    like fetch_document() -- size, uploaded_at). Decodes enc_name back
    to raw bytes here so every function in this module hands the
    caller plain bytes/dicts, never a base64 string it would have to
    know to decode itself."""
    docs = _request("GET", "/documents").json()
    for d in docs:
        d["enc_name"] = _unb64(d["enc_name"])
    return docs


def fetch_document(doc_id: str) -> "Optional[dict]":
    """Returns the full record with byte fields already base64-decoded
    back to raw bytes, or None if doc_id does not exist."""
    try:
        resp = _request("GET", f"/documents/{doc_id}")
    except CloudError as exc:
        if exc.status_code == 404:
            return None
        raise
    data = resp.json()
    return {
        "doc_id": data["doc_id"],
        "enc_name": _unb64(data["enc_name"]),
        "nonce": _unb64(data["nonce"]),
        "ciphertext": _unb64(data["ciphertext"]),
        "tag": _unb64(data["tag"]),
        "size": data["size"],
        "uploaded_at": data["uploaded_at"],
    }


def fetch_document_raw(doc_id: str) -> "Optional[dict]":
    """The cloud's JSON response for one record exactly as received
    (byte fields still base64) -- for the transparency views, which
    show what the cloud API literally returned."""
    try:
        return _request("GET", f"/documents/{doc_id}").json()
    except CloudError as exc:
        if exc.status_code == 404:
            return None
        raise


def replace_document(doc_id: str, enc_name: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bool:
    """In-place overwrite of an existing document's encrypted fields --
    used by password/key rotation to re-encrypt a document under a new
    K_file without changing its doc_id. Returns True if doc_id existed
    and was updated, False if it did not (not CloudError, same "404 is
    a normal, checkable outcome" shape as fetch_document/delete_document
    above)."""
    try:
        _request(
            "PUT",
            f"/documents/{doc_id}",
            json={
                "enc_name": _b64(enc_name),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
                "tag": _b64(tag),
            },
        )
    except CloudError as exc:
        if exc.status_code == 404:
            return False
        raise
    return True


def delete_document(doc_id: str) -> bool:
    """Returns True if doc_id existed and was deleted, False if it was
    already gone -- same "404 is a normal outcome, not an error" shape
    as fetch_document() above, not CloudError."""
    try:
        _request("DELETE", f"/documents/{doc_id}")
    except CloudError as exc:
        if exc.status_code == 404:
            return False
        raise
    return True


# ---------------------------------------------------------------------------
# sse_index
# ---------------------------------------------------------------------------

def replace_index(entries: "Iterable[Tuple[str, bytes]]") -> dict:
    """Atomically clear and repopulate the cloud's sse_index. Used
    after every upload: this project's static index model rebuilds
    from scratch rather than patching (Section 10), and a rebuild can
    shift which counter an existing document receives for a shared
    keyword -- so the old set must be replaced, not merged into. See
    cloud/storage.py's clear_index() docstring for the full reasoning.
    """
    payload = [{"label": label, "value": _b64(value)} for label, value in entries]
    return _request("POST", "/index/replace", json={"entries": payload}).json()


def run_remote_search(k1: bytes) -> "List[bytes]":
    """Sends ONLY k1 -- see client/search.py's module docstring for
    why K2 never travels to the cloud."""
    resp = _request("POST", "/search", json={"k1": _b64(k1)}).json()
    return [_unb64(v) for v in resp["results"]]


# ---------------------------------------------------------------------------
# meta
# ---------------------------------------------------------------------------

def get_meta(key: str) -> "Optional[bytes]":
    try:
        resp = _request("GET", f"/meta/{key}")
    except CloudError as exc:
        if exc.status_code == 404:
            return None
        raise
    return _unb64(resp.json()["value"])


def set_meta(key: str, value: bytes) -> None:
    _request("POST", f"/meta/{key}", json={"value": _b64(value)})
