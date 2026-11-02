"""
benchmarks/harness/vault.py -- the throwaway key material every suite
measures against.

Suites B2 and B3 need a real KeySet (K_file, K_index) to derive tokens and
build an index with. They must not invent one: the keys have to come from
the same `client/keymgmt.py` path a real unlock takes, or the benchmark
would be measuring bytes that the application never produces.

The salt is a fixed constant rather than `generate_salt()`, so the derived
keys -- and therefore every label, token and ciphertext key in a run -- are
identical on every machine and in every run. That is a benchmarking
requirement (reproducibility), and it costs nothing in security terms
because this key material never touches a real vault: every benchmark
vault lives in a temporary directory and holds only generated
pseudo-text. Using a random salt here would make runs less comparable and
protect nothing.

Deriving keys costs one full production-parameter Argon2id hash, so the
result is cached for the process. Suite B1, which measures that cost, does
its own uncached derivations and never uses this helper's cache.
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from typing import Dict, Sequence

from .. import config

from client import cloud_client
from client.crypto import NONCE_SIZE, TAG_SIZE, aes_gcm_encrypt
from client.indexer import build_index
from client.keymgmt import SALT_SIZE, KeySet, unlock
from client.tokenizer import tokenize

BENCHMARK_SALT = hashlib.sha256(b"encrypted-cloud-vault:benchmark-salt:v1").digest()[:SALT_SIZE]
"""Fixed 16-byte salt for benchmark vaults. Derived from a constant string
so it is reproducible and obviously not a secret."""


@lru_cache(maxsize=1)
def benchmark_keyset() -> KeySet:
    """(K_file, K_index) from the real unlock path, at the application's
    production Argon2id parameters. Cached: this is setup for other
    measurements, not itself a measurement."""
    return unlock(config.VAULT_PASSWORD, BENCHMARK_SALT)


def benchmark_doc_id(index: int) -> str:
    """A deterministic stand-in for `os.urandom(16).hex()`.

    Production assigns a random 16-byte hex doc_id (client_app.py's upload
    route). Benchmarks need the same *shape* -- 32 hex characters, because
    doc_id length is what the index's AES-GCM value length depends on --
    without the randomness, so that a rebuilt index is byte-comparable
    across runs. Derived from the document index by hashing.
    """
    return hashlib.sha256(f"benchmark-doc:{index}".encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# populating a live vault
# ---------------------------------------------------------------------------

def _split_blob(blob: bytes):
    """The nonce / ciphertext / tag split the cloud schema stores, identical
    to client_app._split_blob. Duplicated here rather than imported because
    it is three slice expressions defined by the schema, and importing a
    private helper to save three characters would couple the harness to an
    implementation detail it does not otherwise touch."""
    return blob[:NONCE_SIZE], blob[NONCE_SIZE:-TAG_SIZE], blob[-TAG_SIZE:]


def populate_vault(keys: KeySet, documents: "Sequence") -> "Dict[str, str]":
    """Bring a live vault to the state N uploads would leave it in, and
    return the {filename: doc_id} map.

    Suites B5 and B6 need a *populated vault*; they do not need to pay for
    N sequential rebuilds to get one. Uploading through
    `POST /api/documents` N times would trigger N full static rebuilds --
    O(n^2) work whose cost is exactly what suite B4 exists to measure, and
    which would otherwise be spent again as mere setup here.

    Every step below is the application's own code -- `aes_gcm_encrypt`,
    `tokenize`, `build_index`, `cloud_client.push_document`,
    `cloud_client.replace_index` -- performed in the same order the upload
    path performs them, with the rebuild done ONCE at the end instead of
    once per document. The resulting cloud state is what the final upload
    would have produced: the same encrypted documents, and an index built
    from the same complete corpus. B5 verifies that claim rather than
    asserting it, by checking that a probe keyword planted in exactly k
    documents returns exactly k search results from the live system.

    doc_ids are deterministic (harness.vault.benchmark_doc_id) rather than
    the random ones production assigns, so a run is reproducible. They have
    the same 32-hex-character shape, which is what the index's encrypted
    value length depends on.
    """
    doc_ids: "Dict[str, str]" = {}
    tokenized: "Dict[str, set]" = {}
    for doc in documents:
        doc_id = benchmark_doc_id(doc.index)
        blob = aes_gcm_encrypt(keys.k_file, doc.data)
        name_blob = aes_gcm_encrypt(keys.k_file, doc.filename.encode("utf-8"))
        nonce, ciphertext, tag = _split_blob(blob)
        cloud_client.push_document(doc_id, name_blob, nonce, ciphertext, tag)
        doc_ids[doc.filename] = doc_id
        tokenized[doc_id] = tokenize(doc.text)

    entries = build_index(keys.k_index, tokenized)
    cloud_client.replace_index([(e.label, e.value) for e in entries])
    return doc_ids


def benchmark_client_config() -> dict:
    """create_app() config for a benchmark run: a throwaway accounts DB in
    a temporary directory, never client_accounts.sqlite3 in the CWD."""
    import tempfile

    return {"ACCOUNTS_DB_PATH": os.path.join(tempfile.mkdtemp(prefix="vault-bench-accounts-"), "accounts.sqlite3")}


def unlock_client_app(client, password: str = config.VAULT_PASSWORD):
    """Unlock a trusted-client Flask test client against a fresh vault and
    return its KeySet.

    Uses the real `POST /api/unlock` route, so the vault gets the same
    bootstrap (random salt + kdf_verifier) any real first unlock produces --
    including the F1 guard that refuses to bootstrap over existing
    documents. A benchmark that skipped this and injected keys directly
    would not be measuring the shipped system.

    Multi-user extension: the trusted client now requires a logged-in
    account (and a CSRF header) before any vault route, so this registers
    and logs in a benchmark user first. It then pins this thread's
    cloud_client scope to that user's vault, so the suites' direct
    cloud_client calls address the same vault the app's routes do.
    """
    creds = {"username": "benchmark-user", "password": "benchmark-account-password"}
    response = client.post("/api/auth/register", json=creds)
    if response.status_code not in (201, 409):
        raise RuntimeError(f"benchmark account registration failed: {response.status_code} {response.data!r}")
    response = client.post("/api/auth/login", json=creds)
    if response.status_code != 200:
        raise RuntimeError(f"benchmark login failed: {response.status_code} {response.data!r}")
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]

    response = client.post("/api/unlock", json={"password": password})
    if response.status_code != 200:
        raise RuntimeError(f"benchmark vault unlock failed: {response.status_code} {response.data!r}")

    app = client.application
    unlocked = app.extensions["vault_sessions"].unlocked_sessions()
    if len(unlocked) != 1:
        raise RuntimeError("unlock returned 200 but the client app is still locked")
    user = app.extensions["vault_accounts"].get_user_by_username(creds["username"])
    cloud_client.set_vault_scope((user.vault_id, user.cloud_token))
    return unlocked[0].keys
