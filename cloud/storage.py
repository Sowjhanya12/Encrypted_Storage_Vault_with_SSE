"""
cloud/storage.py -- SQLite access layer for the untrusted cloud store.

Everything in this file runs on the UNTRUSTED side of the trust
boundary (Section 02 of docs/architecture.html). It holds zero keys
and never imports anything from client/ -- nothing here needs a key or
a tokenizer to store and retrieve bytes.

This module treats every value it is given as an opaque byte string.
It has no idea whether "ciphertext" is really AES-GCM output, whether
"label" is really an HMAC digest, or what any of it decrypts to -- and
it must never need to know. That is exactly what makes the
"honest-but-curious cloud" argument (Section 09) hold: even a fully
inspected copy of vault.sqlite3 has nothing in it for the cloud
operator to read.

Schema (Section 08) -- three tables, all untrusted, plus `vaults`:

  documents   doc_id (PK), enc_name, nonce, ciphertext, tag,
              size, uploaded_at, vault_id
  sse_index   (vault_id, label) PK, value
  meta        (vault_id, key) PK, value
  vaults      vault_id (PK), token_hash, created_at

Multi-vault extension (schema version 2): every row carries a
`vault_id`, an opaque random identifier chosen by the trusted client
for one user's vault. The cloud never learns who that user is -- no
username, no password, no key -- only that rows belong to the same
namespace. `vaults` holds SHA-256(access token) per vault so the cloud
can refuse a request for one vault made with another vault's token
(cloud_app.py enforces this). The original single-vault data lives
under the LEGACY_VAULT namespace (the empty string), which is exactly
where pre-v2 rows land after migrate_schema() runs -- nothing is
deleted or rewritten, only re-labelled with a default column value.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Optional

# Namespace of the original single-vault deployment (pre schema v2).
LEGACY_VAULT = ""

SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    doc_id      TEXT PRIMARY KEY,
    enc_name    BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,
    tag         BLOB NOT NULL,
    size        INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    vault_id    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sse_index (
    vault_id TEXT NOT NULL DEFAULT '',
    label    TEXT NOT NULL,
    value    BLOB NOT NULL,
    PRIMARY KEY (vault_id, label)
);

CREATE TABLE IF NOT EXISTS meta (
    vault_id TEXT NOT NULL DEFAULT '',
    key      TEXT NOT NULL,
    value    BLOB NOT NULL,
    PRIMARY KEY (vault_id, key)
);

CREATE TABLE IF NOT EXISTS vaults (
    vault_id   TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""

# Created only after migrate_schema(): on a pre-v2 database the
# `vault_id` column these reference does not exist yet.
_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_documents_vault ON documents (vault_id);
"""


def _columns(conn: sqlite3.Connection, table: str) -> "list[str]":
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def migrate_schema(conn: sqlite3.Connection) -> bool:
    """Upgrade a pre-v2 (single-vault) database in place. Returns True
    if anything was migrated.

    Non-destructive by construction: `documents` gains a `vault_id`
    column via ALTER TABLE (existing rows take the LEGACY_VAULT
    default); `sse_index` and `meta` must change their PRIMARY KEY to
    include vault_id, which SQLite can only do by copying every row
    into a new table inside one transaction and swapping it in. Every
    row is copied byte-for-byte -- no value is decrypted, re-encoded,
    or dropped -- and a failure part-way rolls the whole thing back.
    """
    migrated = False
    conn.execute("BEGIN")
    try:
        if "vault_id" not in _columns(conn, "documents"):
            conn.execute("ALTER TABLE documents ADD COLUMN vault_id TEXT NOT NULL DEFAULT ''")
            migrated = True
        for table, key_col in (("sse_index", "label"), ("meta", "key")):
            if "vault_id" in _columns(conn, table):
                continue
            conn.execute(
                f"""
                CREATE TABLE {table}_v2 (
                    vault_id TEXT NOT NULL DEFAULT '',
                    {key_col} TEXT NOT NULL,
                    value    BLOB NOT NULL,
                    PRIMARY KEY (vault_id, {key_col})
                )
                """
            )
            conn.execute(
                f"INSERT INTO {table}_v2 (vault_id, {key_col}, value) "
                f"SELECT '', {key_col}, value FROM {table}"
            )
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {table}_v2 RENAME TO {table}")
            migrated = True
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return migrated


def connect(db_path: "str | Path") -> sqlite3.Connection:
    """Open (creating if needed) the cloud's SQLite store and make sure
    the schema exists. One connection per request/test is fine --
    SQLite handles that cheaply and it keeps this module stateless."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    if conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
        migrate_schema(conn)
    conn.executescript(_INDEXES)
    conn.commit()
    return conn


@contextmanager
def open_db(db_path: "str | Path") -> Iterator[sqlite3.Connection]:
    """Context-manager convenience: `with open_db(path) as conn: ...`
    commits on clean exit and always closes the connection, even if
    the caller raises."""
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


class DuplicateDocumentError(Exception):
    """Raised when a doc_id already exists. IDs are assigned by the
    trusted client (Section 07, flow B: "Assign a random doc_id") --
    a collision here means a client bug or a bad-faith re-upload, not
    routine data storage.py should silently overwrite."""


class DocumentNotFoundError(Exception):
    pass


class DuplicateVaultError(Exception):
    pass


# ---------------------------------------------------------------------------
# vaults
# ---------------------------------------------------------------------------

def create_vault(conn: sqlite3.Connection, vault_id: str, token_hash: bytes) -> None:
    """Register a new vault namespace. Only a hash of the access token
    is stored -- a copy of this database is not enough to impersonate
    the vault's owner to this service."""
    try:
        conn.execute(
            "INSERT INTO vaults (vault_id, token_hash) VALUES (?, ?)",
            (vault_id, token_hash),
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateVaultError(f"vault {vault_id!r} already exists") from exc


def get_vault_token_hash(conn: sqlite3.Connection, vault_id: str) -> "Optional[bytes]":
    row = conn.execute("SELECT token_hash FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
    return row["token_hash"] if row is not None else None


def get_vault_created_at(conn: sqlite3.Connection, vault_id: str) -> "Optional[str]":
    row = conn.execute("SELECT created_at FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
    return row["created_at"] if row is not None else None


def vault_stats(conn: sqlite3.Connection, vault_id: str = LEGACY_VAULT) -> dict:
    """Aggregate, non-secret facts about one namespace -- exactly what
    the cloud operator can compute from the rows it stores anyway."""
    doc_row = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS c, "
        "COALESCE(SUM(LENGTH(enc_name)), 0) AS e, MAX(uploaded_at) AS last "
        "FROM documents WHERE vault_id = ?",
        (vault_id,),
    ).fetchone()
    meta_keys = [
        r["key"] for r in conn.execute(
            "SELECT key FROM meta WHERE vault_id = ? ORDER BY key", (vault_id,)
        ).fetchall()
    ]
    return {
        "documents": doc_row["n"],
        "ciphertext_bytes": doc_row["c"],
        "enc_name_bytes": doc_row["e"],
        "last_upload_at": doc_row["last"],
        "index_entries": index_entry_count(conn, vault_id=vault_id),
        "meta_keys": meta_keys,
    }


def adopt_legacy_vault(conn: sqlite3.Connection, vault_id: str) -> dict:
    """Move every LEGACY_VAULT row into `vault_id` (migration path for
    a pre-multi-user deployment). Refuses unless the target namespace
    is completely empty, so it can never merge two vault identities.
    Rows are re-labelled in place, never copied or rewritten."""
    for table in ("documents", "sse_index", "meta"):
        n = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE vault_id = ?", (vault_id,)).fetchone()[0]
        if n:
            raise ValueError("target vault is not empty")
    moved = {}
    for table in ("documents", "sse_index", "meta"):
        cur = conn.execute(f"UPDATE {table} SET vault_id = ? WHERE vault_id = ?", (vault_id, LEGACY_VAULT))
        moved[table] = cur.rowcount
    return moved


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def save_document(
    conn: sqlite3.Connection,
    doc_id: str,
    enc_name: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    vault_id: str = LEGACY_VAULT,
) -> None:
    """Store one encrypted document.

    `size` is deliberately NOT a parameter: it is always computed here
    as len(ciphertext) rather than trusted from a caller-supplied
    value, so it can never drift from the bytes actually stored.
    """
    try:
        conn.execute(
            """
            INSERT INTO documents (doc_id, enc_name, nonce, ciphertext, tag, size, vault_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (doc_id, enc_name, nonce, ciphertext, tag, len(ciphertext), vault_id),
        )
    except sqlite3.IntegrityError as exc:
        raise DuplicateDocumentError(f"doc_id {doc_id!r} already exists") from exc


def get_document(conn: sqlite3.Connection, doc_id: str, vault_id: str = LEGACY_VAULT) -> dict:
    """Scoped by vault_id: a doc_id belonging to another vault is
    reported exactly like one that does not exist at all."""
    row = conn.execute(
        "SELECT doc_id, enc_name, nonce, ciphertext, tag, size, uploaded_at "
        "FROM documents WHERE doc_id = ? AND vault_id = ?",
        (doc_id, vault_id),
    ).fetchone()
    if row is None:
        raise DocumentNotFoundError(f"no document with doc_id {doc_id!r}")
    return dict(row)


def list_documents(conn: sqlite3.Connection, vault_id: str = LEGACY_VAULT) -> "list[dict]":
    """Metadata only -- no ciphertext body. This is what a future
    'vault list' screen pages through. enc_name is still the encrypted
    bytes; nothing returned here is plaintext."""
    rows = conn.execute(
        "SELECT doc_id, enc_name, size, uploaded_at FROM documents "
        "WHERE vault_id = ? ORDER BY uploaded_at",
        (vault_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def document_count(conn: sqlite3.Connection, vault_id: str = LEGACY_VAULT) -> int:
    return conn.execute("SELECT COUNT(*) FROM documents WHERE vault_id = ?", (vault_id,)).fetchone()[0]


def replace_document(
    conn: sqlite3.Connection,
    doc_id: str,
    enc_name: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    vault_id: str = LEGACY_VAULT,
) -> bool:
    """Overwrite an EXISTING document's encrypted fields in place,
    under the same doc_id -- added for password/key rotation
    (client_app.py's api_change_password), which must re-encrypt every
    document under a new K_file without changing which doc_id it is
    stored under (search-index labels/values reference doc_id, not the
    ciphertext, so the doc_id itself must be stable across a rotation).

    Deliberately a separate function from save_document(), not a
    save_document() that upserts: save_document()'s INSERT-only
    behaviour (raising DuplicateDocumentError on a collision) is a
    correctness property Phase 2 relies on -- a doc_id collision on
    ordinary upload is assign a random doc_id gone catastrophically
    wrong, not routine data storage.py should silently allow. Rotation
    needs the opposite guarantee (the row must already exist), so it
    gets its own explicit primitive rather than blurring that one.

    `size` is recomputed from the new ciphertext, exactly like
    save_document() -- it must reflect what is actually stored, not a
    stale value from before rotation.

    Returns True if a row existed and was updated, False if doc_id was
    not found (the caller decides whether that is an error -- rotation
    treats it as one, since every doc_id it processes came from its own
    fresh list_documents() call moments earlier).
    """
    cur = conn.execute(
        """
        UPDATE documents
        SET enc_name = ?, nonce = ?, ciphertext = ?, tag = ?, size = ?
        WHERE doc_id = ? AND vault_id = ?
        """,
        (enc_name, nonce, ciphertext, tag, len(ciphertext), doc_id, vault_id),
    )
    return cur.rowcount > 0


def delete_document(conn: sqlite3.Connection, doc_id: str, vault_id: str = LEGACY_VAULT) -> bool:
    """Delete one document row. Returns True if a row existed and was
    removed, False if doc_id was not found -- an ordinary, expected
    outcome (not every delete follows a successful lookup, e.g. a
    concurrent request), so this layer reports it as a plain bool
    rather than raising DocumentNotFoundError; the caller (cloud_app.py)
    decides whether "not found" becomes a 404."""
    cur = conn.execute("DELETE FROM documents WHERE doc_id = ? AND vault_id = ?", (doc_id, vault_id))
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# sse_index
# ---------------------------------------------------------------------------

def save_index_entries(
    conn: sqlite3.Connection,
    entries: "Iterable[tuple[str, bytes]]",
    vault_id: str = LEGACY_VAULT,
) -> int:
    """Bulk-insert (label, value) rows into the flat Pi_bas dictionary D
    (Section 05). Takes an iterable so a later indexer.py can push an
    entire keyword's postings list in one call. Returns the row count
    inserted.

    A label collision is a genuine anomaly (labels are HMAC outputs --
    a real collision means a serious bug upstream), so it is left to
    propagate as sqlite3.IntegrityError rather than silently
    overwritten or swallowed here.
    """
    entries = list(entries)
    conn.executemany(
        "INSERT INTO sse_index (vault_id, label, value) VALUES (?, ?, ?)",
        [(vault_id, label, value) for label, value in entries],
    )
    return len(entries)


def get_index_entry(conn: sqlite3.Connection, label: str, vault_id: str = LEGACY_VAULT) -> "Optional[bytes]":
    """Single-label lookup: does D contain this label, and if so what
    opaque value sits under it?

    This is a raw storage primitive only -- it does NOT iterate
    counters or implement the Pi_bas search loop from Section 06. That
    loop (repeatedly deriving F(K1, counter) and calling this once per
    counter until a miss) is Phase 4's job; this function is the one
    building block it will call.
    """
    row = conn.execute(
        "SELECT value FROM sse_index WHERE label = ? AND vault_id = ?", (label, vault_id)
    ).fetchone()
    return row["value"] if row is not None else None


def index_entry_count(conn: sqlite3.Connection, vault_id: str = LEGACY_VAULT) -> int:
    """Total (keyword, document) pairs currently indexed -- exactly the
    'setup size' leakage the architecture doc names in Section 09."""
    return conn.execute("SELECT COUNT(*) FROM sse_index WHERE vault_id = ?", (vault_id,)).fetchone()[0]


def list_index_entries(
    conn: sqlite3.Connection, vault_id: str = LEGACY_VAULT, limit: int = 100, offset: int = 0
) -> "list[dict]":
    """A page of raw (label, value) rows, for the inspector views.
    Ordered by label, i.e. by HMAC output -- which carries no keyword
    or counter ordering a reader could exploit."""
    rows = conn.execute(
        "SELECT label, value FROM sse_index WHERE vault_id = ? ORDER BY label LIMIT ? OFFSET ?",
        (vault_id, limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]


def clear_index(conn: sqlite3.Connection, vault_id: str = LEGACY_VAULT) -> int:
    """Delete every row from sse_index. Returns the number removed.

    Added in Phase 5 for a concrete reason, not speculatively: this
    project's index is a static, from-scratch rebuild (Section 10 --
    adding a document means rebuilding the whole index, not patching
    it). build_index() assigns postings counters in doc_id-sorted
    order, so adding a new document can shift which counter an
    EXISTING document receives for a keyword they both share, which
    changes that document's label. Re-pushing a rebuilt index
    additively (via save_index_entries alone) would therefore leave
    the old, now-orphaned rows from the previous counter assignment
    sitting in the table alongside the new ones. Rebuilding correctly
    means replacing the whole table atomically -- clear_index() is
    that clear step; cloud_app.py's POST /index/replace calls it
    immediately before save_index_entries() within the same
    transaction.
    """
    cur = conn.execute("DELETE FROM sse_index WHERE vault_id = ?", (vault_id,))
    return cur.rowcount


# ---------------------------------------------------------------------------
# meta
# ---------------------------------------------------------------------------

def set_meta(conn: sqlite3.Connection, key: str, value: bytes, vault_id: str = LEGACY_VAULT) -> None:
    """Upsert one non-secret setup parameter (KDF salt, Argon2 cost
    params, scheme version -- Section 08). Stored in plaintext by
    design: these values are not secret, only the password that
    combines with the salt is."""
    conn.execute(
        "INSERT INTO meta (vault_id, key, value) VALUES (?, ?, ?) "
        "ON CONFLICT(vault_id, key) DO UPDATE SET value = excluded.value",
        (vault_id, key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str, vault_id: str = LEGACY_VAULT) -> "Optional[bytes]":
    row = conn.execute("SELECT value FROM meta WHERE key = ? AND vault_id = ?", (key, vault_id)).fetchone()
    return row["value"] if row is not None else None
