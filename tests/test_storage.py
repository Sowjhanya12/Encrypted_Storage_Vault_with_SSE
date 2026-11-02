"""
tests/test_storage.py -- Unit tests for cloud/storage.py.

Deliberately uses plain os.urandom() bytes instead of real AES-GCM
ciphertext throughout. That is the point of this file: the storage
layer must not care what the bytes mean, so the tests prove its
correctness without involving client/crypto.py at all. The one place
real crypto and storage meet is tests/test_integration.py.
"""

import ast
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloud import storage  # noqa: E402


@pytest.fixture
def conn(tmp_path):
    db_path = tmp_path / "vault.sqlite3"
    with storage.open_db(db_path) as c:
        yield c


def _doc_id() -> str:
    return os.urandom(16).hex()


# ---------------------------------------------------------------------------
# schema / connection
# ---------------------------------------------------------------------------

class TestSchema:
    def test_connect_creates_all_three_tables(self, tmp_path):
        db_path = tmp_path / "vault.sqlite3"
        conn = storage.connect(db_path)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            conn.close()
        assert {"documents", "sse_index", "meta"} <= tables

    def test_connect_is_idempotent(self, tmp_path):
        db_path = tmp_path / "vault.sqlite3"
        storage.connect(db_path).close()
        # Second connect must not fail or wipe existing data.
        conn = storage.connect(db_path)
        storage.save_document(conn, _doc_id(), b"a", b"b" * 12, b"c", b"d" * 16)
        conn.commit()
        conn.close()

        conn2 = storage.connect(db_path)
        assert storage.document_count(conn2) == 1
        conn2.close()


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

class TestDocuments:
    def test_save_and_get_round_trip_is_byte_identical(self, conn):
        doc_id = _doc_id()
        enc_name = os.urandom(24)
        nonce = os.urandom(12)
        ciphertext = os.urandom(137)
        tag = os.urandom(16)

        storage.save_document(conn, doc_id, enc_name, nonce, ciphertext, tag)
        got = storage.get_document(conn, doc_id)

        assert got["doc_id"] == doc_id
        assert got["enc_name"] == enc_name
        assert got["nonce"] == nonce
        assert got["ciphertext"] == ciphertext
        assert got["tag"] == tag

    def test_size_is_computed_from_ciphertext_length(self, conn):
        doc_id = _doc_id()
        ciphertext = os.urandom(999)
        storage.save_document(conn, doc_id, b"name", b"n" * 12, ciphertext, b"t" * 16)
        got = storage.get_document(conn, doc_id)
        assert got["size"] == 999 == len(ciphertext)

    def test_empty_ciphertext_is_allowed(self, conn):
        # The empty-plaintext AES-GCM case (Phase 1) produces a
        # zero-length "ciphertext" once the tag is split off -- make
        # sure storage doesn't special-case that away.
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"name", b"n" * 12, b"", b"t" * 16)
        got = storage.get_document(conn, doc_id)
        assert got["ciphertext"] == b""
        assert got["size"] == 0

    def test_duplicate_doc_id_raises(self, conn):
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"a", b"n" * 12, b"c", b"t" * 16)
        with pytest.raises(storage.DuplicateDocumentError):
            storage.save_document(conn, doc_id, b"a2", b"n" * 12, b"c2", b"t" * 16)

    def test_get_missing_document_raises(self, conn):
        with pytest.raises(storage.DocumentNotFoundError):
            storage.get_document(conn, "does-not-exist")

    def test_uploaded_at_is_set_automatically(self, conn):
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"a", b"n" * 12, b"c", b"t" * 16)
        got = storage.get_document(conn, doc_id)
        assert got["uploaded_at"]  # non-empty, server-assigned

    def test_list_documents_omits_ciphertext_and_key_columns(self, conn):
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"name", b"n" * 12, b"secretish", b"t" * 16)
        [row] = storage.list_documents(conn)
        assert set(row.keys()) == {"doc_id", "enc_name", "size", "uploaded_at"}
        assert "ciphertext" not in row
        assert "nonce" not in row
        assert "tag" not in row

    def test_list_documents_orders_by_upload_time(self, conn):
        ids = [_doc_id() for _ in range(3)]
        for did in ids:
            storage.save_document(conn, did, b"n", b"x" * 12, b"c", b"t" * 16)
        listed_ids = [row["doc_id"] for row in storage.list_documents(conn)]
        assert listed_ids == ids

    def test_document_count(self, conn):
        assert storage.document_count(conn) == 0
        for _ in range(5):
            storage.save_document(conn, _doc_id(), b"n", b"x" * 12, b"c", b"t" * 16)
        assert storage.document_count(conn) == 5

    def test_replace_document_overwrites_fields_in_place_same_doc_id(self, conn):
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"old-name", b"n" * 12, b"old-cipher", b"t" * 16)
        new_enc_name, new_nonce, new_ciphertext, new_tag = (
            os.urandom(24), os.urandom(12), os.urandom(200), os.urandom(16)
        )
        replaced = storage.replace_document(conn, doc_id, new_enc_name, new_nonce, new_ciphertext, new_tag)
        assert replaced is True

        got = storage.get_document(conn, doc_id)
        assert got["doc_id"] == doc_id  # unchanged
        assert got["enc_name"] == new_enc_name
        assert got["nonce"] == new_nonce
        assert got["ciphertext"] == new_ciphertext
        assert got["tag"] == new_tag
        assert got["size"] == len(new_ciphertext)

    def test_replace_missing_document_returns_false_and_writes_nothing(self, conn):
        replaced = storage.replace_document(conn, "does-not-exist", b"n", b"x" * 12, b"c", b"t" * 16)
        assert replaced is False
        assert storage.document_count(conn) == 0

    def test_replace_document_does_not_change_document_count(self, conn):
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"a", b"n" * 12, b"c", b"t" * 16)
        storage.replace_document(conn, doc_id, b"a2", b"n" * 12, b"c2", b"t" * 16)
        assert storage.document_count(conn) == 1

    def test_replace_document_only_touches_the_targeted_row(self, conn):
        keep_id, target_id = _doc_id(), _doc_id()
        storage.save_document(conn, keep_id, b"keep", b"n" * 12, b"keep-cipher", b"t" * 16)
        storage.save_document(conn, target_id, b"old", b"n" * 12, b"old-cipher", b"t" * 16)
        storage.replace_document(conn, target_id, b"new", b"n" * 12, b"new-cipher", b"t" * 16)
        untouched = storage.get_document(conn, keep_id)
        assert untouched["enc_name"] == b"keep" and untouched["ciphertext"] == b"keep-cipher"

    def test_delete_document_removes_it_and_returns_true(self, conn):
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"n", b"x" * 12, b"c", b"t" * 16)
        assert storage.delete_document(conn, doc_id) is True
        with pytest.raises(storage.DocumentNotFoundError):
            storage.get_document(conn, doc_id)

    def test_delete_missing_document_returns_false_not_raises(self, conn):
        assert storage.delete_document(conn, "does-not-exist") is False

    def test_delete_document_only_removes_the_targeted_row(self, conn):
        keep_id, drop_id = _doc_id(), _doc_id()
        storage.save_document(conn, keep_id, b"n1", b"x" * 12, b"c1", b"t" * 16)
        storage.save_document(conn, drop_id, b"n2", b"x" * 12, b"c2", b"t" * 16)
        storage.delete_document(conn, drop_id)
        assert storage.document_count(conn) == 1
        assert storage.get_document(conn, keep_id)["doc_id"] == keep_id

    def test_delete_document_does_not_touch_sse_index_or_meta(self, conn):
        # storage.delete_document only ever touches the documents table --
        # removing a document's index entries is the CALLER's job
        # (client_app.py rebuilds the whole index before calling this),
        # matching how save_index_entries()/clear_index() are separate
        # primitives this layer never invokes on its own.
        doc_id = _doc_id()
        storage.save_document(conn, doc_id, b"n", b"x" * 12, b"c", b"t" * 16)
        storage.save_index_entries(conn, [(os.urandom(32).hex(), b"v")])
        storage.set_meta(conn, "kdf_salt", b"\x01" * 16)
        storage.delete_document(conn, doc_id)
        assert storage.index_entry_count(conn) == 1
        assert storage.get_meta(conn, "kdf_salt") == b"\x01" * 16


# ---------------------------------------------------------------------------
# sse_index
# ---------------------------------------------------------------------------

class TestSseIndex:
    def test_save_and_get_single_entry_round_trip(self, conn):
        label = os.urandom(32).hex()
        value = os.urandom(48)
        inserted = storage.save_index_entries(conn, [(label, value)])
        assert inserted == 1
        assert storage.get_index_entry(conn, label) == value

    def test_bulk_insert_multiple_entries(self, conn):
        entries = [(os.urandom(32).hex(), os.urandom(20)) for _ in range(10)]
        inserted = storage.save_index_entries(conn, entries)
        assert inserted == 10
        for label, value in entries:
            assert storage.get_index_entry(conn, label) == value

    def test_missing_label_returns_none(self, conn):
        assert storage.get_index_entry(conn, "no-such-label") is None

    def test_duplicate_label_raises_integrity_error(self, conn):
        label = os.urandom(32).hex()
        storage.save_index_entries(conn, [(label, b"v1")])
        with pytest.raises(sqlite3.IntegrityError):
            storage.save_index_entries(conn, [(label, b"v2")])

    def test_index_entry_count(self, conn):
        assert storage.index_entry_count(conn) == 0
        storage.save_index_entries(conn, [(os.urandom(32).hex(), b"v") for _ in range(7)])
        assert storage.index_entry_count(conn) == 7

    def test_entries_for_different_keywords_are_indistinguishable_rows(self, conn):
        # Mirrors Section 05's point: once inserted, there is no column
        # or flag that says which keyword a row belongs to.
        storage.save_index_entries(
            conn,
            [
                (os.urandom(32).hex(), os.urandom(32)),
                (os.urandom(32).hex(), os.urandom(32)),
            ],
        )
        cols = {
            d[0]
            for d in conn.execute("SELECT * FROM sse_index LIMIT 1").description
        }
        # Schema v2 adds `vault_id` (which opaque user namespace owns the
        # row) -- still nothing that says which KEYWORD a row belongs to.
        assert cols == {"vault_id", "label", "value"}

    def test_clear_index_removes_everything_and_returns_count(self, conn):
        storage.save_index_entries(conn, [(os.urandom(32).hex(), b"v") for _ in range(5)])
        removed = storage.clear_index(conn)
        assert removed == 5
        assert storage.index_entry_count(conn) == 0

    def test_clear_index_on_an_empty_table_returns_zero(self, conn):
        assert storage.clear_index(conn) == 0

    def test_clear_index_then_reinsert_works(self, conn):
        old_label = os.urandom(32).hex()
        storage.save_index_entries(conn, [(old_label, b"old")])
        storage.clear_index(conn)
        new_label = os.urandom(32).hex()
        storage.save_index_entries(conn, [(new_label, b"new")])
        assert storage.get_index_entry(conn, old_label) is None
        assert storage.get_index_entry(conn, new_label) == b"new"


# ---------------------------------------------------------------------------
# meta
# ---------------------------------------------------------------------------

class TestMeta:
    def test_set_and_get_round_trip(self, conn):
        storage.set_meta(conn, "kdf_salt", b"\x01" * 16)
        assert storage.get_meta(conn, "kdf_salt") == b"\x01" * 16

    def test_get_missing_key_returns_none(self, conn):
        assert storage.get_meta(conn, "no-such-key") is None

    def test_set_meta_upserts_overwrites_previous_value(self, conn):
        storage.set_meta(conn, "scheme_version", b"v1")
        storage.set_meta(conn, "scheme_version", b"v2")
        assert storage.get_meta(conn, "scheme_version") == b"v2"
        # And it must not have created a second row.
        count = conn.execute("SELECT COUNT(*) FROM meta WHERE key = ?", ("scheme_version",)).fetchone()[0]
        assert count == 1


# ---------------------------------------------------------------------------
# trust-boundary guard: storage.py must never import client/
# ---------------------------------------------------------------------------

class TestTrustBoundary:
    def test_storage_module_does_not_import_client_package(self):
        source = open(
            os.path.join(os.path.dirname(__file__), "..", "cloud", "storage.py")
        ).read()
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        assert "client" not in imported_roots, (
            "cloud/storage.py imports from client/ -- this crosses the trust "
            "boundary from Section 02 and must not happen."
        )
