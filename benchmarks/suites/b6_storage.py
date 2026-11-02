"""
Suite B6 -- storage overhead: the price of security, in bytes.

Architecture Section 14 asks for "ciphertext vs. plaintext; index vs.
corpus". Every number here is read from the actual SQLite file the cloud
process wrote, after a real vault has been populated and indexed -- not
computed from a formula. Where SQLite can report its own page accounting,
that is preferred over summing column lengths, because the file on disk is
what a cloud provider would charge for and it includes per-row, per-page
and B-tree overhead that a column-length sum cannot see.

Three levels of measurement, all recorded
-----------------------------------------
1. **File bytes** -- `os.path.getsize` on the database (plus any `-wal` /
   `-shm` companions, if present), and `PRAGMA page_size`, `page_count`,
   `freelist_count`. This is the honest "what does this vault occupy"
   figure.

2. **Per-table bytes** -- via the `dbstat` virtual table, which reports
   real page usage per B-tree, so the documents table, the encrypted index
   and their implicit primary-key indexes are separated rather than
   estimated. `dbstat` is a compile-time option; when it is unavailable
   the suite records that fact and falls back to level 3 instead of
   silently reporting a worse number as if it were the same one.

3. **Logical column bytes** -- `SUM(LENGTH(...))` per column group. This is
   the payload proper: ciphertext, nonces, tags, encrypted filenames,
   index labels and index values. Comparing level 3 with level 2 is what
   shows how much of the vault is data and how much is database structure.

Nothing here is a ratio: the suite records measured quantities and the
analysis step derives overhead from them, so every percentage in the
report can be traced back to two numbers that were actually observed.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Dict, List

from ..config import Profile
from ..harness.cloud_process import LiveCloud
from ..harness.corpus import corpus_fingerprint, generate_corpus, keyword_stats
from ..harness.recorder import Recorder
from ..harness.timing import timer_resolution
from ..harness.vault import populate_vault, unlock_client_app, benchmark_client_config

from client import client_app

SUITE_ID = "b6_storage"
TITLE = "Storage overhead of ciphertext and the encrypted index"


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"B6 correctness gate failed: {message}")


def _read_only_connection(db_path: str) -> sqlite3.Connection:
    """Open the cloud's database read-only. A benchmark must never be able
    to alter the thing it is measuring -- and this is the untrusted side's
    file, which the client has no business writing to anyway."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _dbstat_pages(conn: sqlite3.Connection) -> "Dict[str, int]":
    """Real page bytes per B-tree, or {} if this SQLite lacks dbstat."""
    try:
        rows = conn.execute("SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name").fetchall()
    except sqlite3.OperationalError:
        return {}
    return {row["name"]: int(row["bytes"]) for row in rows}


def run(recorder: Recorder, profile: Profile) -> dict:
    resolution = timer_resolution()
    size = profile.storage_corpus_size
    documents = generate_corpus(size)
    stats = keyword_stats(documents)
    fingerprint = corpus_fingerprint(documents)
    checks: "List[str]" = []

    with LiveCloud() as cloud:
        app = client_app.create_app(benchmark_client_config())
        client = app.test_client()
        try:
            keys = unlock_client_app(client)
            populate_vault(keys, documents)

            listed = client.get("/api/documents").get_json()
            _check(len(listed) == size, f"vault holds {len(listed)} documents, expected {size}")
            checks.append(f"vault verified to hold all {size} documents before measuring")

            conn = _read_only_connection(cloud.db_path)
            try:
                page_size = conn.execute("PRAGMA page_size").fetchone()[0]
                page_count = conn.execute("PRAGMA page_count").fetchone()[0]
                freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]

                doc_rows = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
                index_rows = conn.execute("SELECT COUNT(*) FROM sse_index").fetchone()[0]
                meta_rows = conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0]
                _check(doc_rows == size, f"documents table holds {doc_rows} rows, expected {size}")
                _check(index_rows == stats["total_postings"],
                       f"sse_index holds {index_rows} rows, expected {stats['total_postings']} postings")
                checks.append(
                    "row counts in the cloud's own tables match the corpus: one document row "
                    "per file and one index row per (keyword, document) posting"
                )

                logical = conn.execute(
                    """
                    SELECT
                      SUM(LENGTH(ciphertext))                       AS ciphertext_bytes,
                      SUM(LENGTH(nonce) + LENGTH(tag))              AS nonce_and_tag_bytes,
                      SUM(LENGTH(enc_name))                         AS encrypted_filename_bytes,
                      SUM(LENGTH(doc_id))                           AS doc_id_bytes
                    FROM documents
                    """
                ).fetchone()
                index_logical = conn.execute(
                    "SELECT SUM(LENGTH(label)) AS label_bytes, SUM(LENGTH(value)) AS value_bytes "
                    "FROM sse_index"
                ).fetchone()
                meta_logical = conn.execute(
                    "SELECT SUM(LENGTH(key) + LENGTH(value)) AS bytes FROM meta"
                ).fetchone()

                dbstat = _dbstat_pages(conn)
            finally:
                conn.close()

            db_file_bytes = cloud.database_bytes()
            companions = {
                suffix: os.path.getsize(cloud.db_path + suffix)
                for suffix in ("-wal", "-shm")
                if os.path.exists(cloud.db_path + suffix)
            }
        finally:
            client.post("/api/lock")

    # -- corpus side (plaintext) -------------------------------------------
    for name, value, unit, note in (
        ("plaintext_corpus_bytes", stats["total_text_bytes"], "bytes",
         "UTF-8 bytes of the documents before encryption"),
        ("plaintext_filename_bytes", sum(len(d.filename.encode()) for d in documents), "bytes",
         "filenames before encryption"),
        ("documents", stats["documents"], "count", None),
        ("total_postings", stats["total_postings"], "count",
         "(keyword, document) pairs -- the cloud's setup-size leakage"),
        ("distinct_keywords", stats["distinct_keywords"], "count", None),
    ):
        recorder.add_scalar(SUITE_ID, name, {"documents": size}, value, unit, notes=note)

    # -- database file ------------------------------------------------------
    for name, value, unit, note in (
        ("database_file_bytes", db_file_bytes, "bytes",
         "os.path.getsize on the cloud's SQLite file -- what a provider would bill for"),
        ("database_page_size", page_size, "bytes", None),
        ("database_page_count", page_count, "count", None),
        ("database_pages_bytes", page_size * page_count, "bytes",
         "page_size x page_count, recorded next to the file size so any difference is visible"),
        ("database_freelist_pages", freelist, "count",
         "pages allocated but unused -- the index is replaced wholesale on every rebuild"),
    ):
        recorder.add_scalar(SUITE_ID, name, {"documents": size}, value, unit, notes=note)
    for suffix, value in companions.items():
        recorder.add_scalar(SUITE_ID, f"database{suffix}_bytes", {"documents": size},
                            value, "bytes", notes="SQLite companion file present at measurement time")

    # -- per-table page accounting (dbstat) --------------------------------
    if dbstat:
        for table_name, page_bytes in sorted(dbstat.items()):
            recorder.add_scalar(
                SUITE_ID, "table_page_bytes", {"documents": size, "btree": table_name},
                page_bytes, "bytes",
                notes="real page usage from SQLite's dbstat virtual table, per B-tree "
                      "(tables and their implicit primary-key indexes counted separately)",
            )
    recorder.add_scalar(
        SUITE_ID, "dbstat_available", {"documents": size}, 1 if dbstat else 0, "boolean",
        notes="whether per-table page accounting was measurable on this SQLite build; "
              "when 0, only logical column sums are available and the report says so",
    )

    # -- logical payload bytes ---------------------------------------------
    for name, value, note in (
        ("documents_ciphertext_bytes", logical["ciphertext_bytes"],
         "AES-GCM ciphertext of file contents"),
        ("documents_nonce_and_tag_bytes", logical["nonce_and_tag_bytes"],
         "12-byte nonce + 16-byte tag per document, as actually stored"),
        ("documents_encrypted_filename_bytes", logical["encrypted_filename_bytes"],
         "encrypted filenames -- the metadata protection Section 10 requires"),
        ("documents_doc_id_bytes", logical["doc_id_bytes"], "document identifiers"),
        ("index_label_bytes", index_logical["label_bytes"],
         "64-character hex HMAC labels"),
        ("index_value_bytes", index_logical["value_bytes"],
         "AES-GCM encrypted doc_id per posting"),
        ("meta_bytes", meta_logical["bytes"], "kdf_salt and kdf_verifier"),
    ):
        recorder.add_scalar(SUITE_ID, name, {"documents": size}, int(value or 0), "bytes", notes=note)

    for name, value in (("documents_rows", doc_rows), ("sse_index_rows", index_rows),
                        ("meta_rows", meta_rows)):
        recorder.add_scalar(SUITE_ID, name, {"documents": size}, value, "count")

    # A suite may only declare measures it actually produced. `dbstat` is a
    # SQLite compile-time option and is absent on some builds (notably the
    # python.org Windows distribution). When it is missing, per-table page
    # accounting is genuinely unmeasurable -- so `table_page_bytes` is left
    # OUT of the declared measures and recorded as unavailable, with the
    # reason. The logical column sums are NOT promoted into its place: they
    # answer a different question (payload bytes, not page bytes), and
    # relabelling one as the other would be a fabricated measurement.
    measures = [
        "plaintext_corpus_bytes", "database_file_bytes", "database_pages_bytes",
        "documents_ciphertext_bytes", "index_label_bytes", "index_value_bytes",
        "meta_bytes",
    ]
    unavailable_measures = {}
    if dbstat:
        measures.insert(3, "table_page_bytes")
    else:
        unavailable_measures["table_page_bytes"] = (
            "this SQLite build has no dbstat virtual table, so per-B-tree page usage "
            "cannot be measured; the logical column sums below are reported instead "
            "and are not a substitute for it"
        )

    return {
        "measures": measures,
        "unavailable_measures": unavailable_measures,
        "capabilities": {"dbstat": bool(dbstat)},
        "implementations_under_test": [
            "client.client_app (POST /api/unlock, GET /api/documents)",
            "client.crypto.aes_gcm_encrypt", "client.indexer.build_index",
            "client.cloud_client.push_document", "client.cloud_client.replace_index",
        ],
        "measurement_method": {
            "file_bytes": "os.path.getsize on the live cloud's SQLite file",
            "per_table_bytes": (
                "SQLite dbstat virtual table (real per-B-tree page usage)" if dbstat
                else "UNAVAILABLE -- this SQLite build has no dbstat; no per-table page "
                     "figure is reported and none is estimated"
            ),
            "logical_bytes": "SUM(LENGTH(column)) per column group, read-only connection",
            "estimates_used": False,
        },
        "corpus": {"documents": size, "fingerprint_sha256": fingerprint,
                   "total_postings": stats["total_postings"]},
        "correctness_gates": checks,
        "clock_resolution_seconds": resolution,
    }
