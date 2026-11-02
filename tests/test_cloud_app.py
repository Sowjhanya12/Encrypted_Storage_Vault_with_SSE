"""
tests/test_cloud_app.py -- HTTP-level tests for cloud/cloud_app.py.

Uses Flask's test client, which drives the real route/view functions
without needing an actual TCP port. Payload bytes travel as base64
inside JSON, matching how the real HTTP API works.
"""

import ast
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloud import storage  # noqa: E402
from cloud.cloud_app import (  # noqa: E402
    _counter_to_bytes,
    _cloud_prf,
    create_app,
    run_search_loop,
)


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "vault.sqlite3"))
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _doc_id() -> str:
    return os.urandom(16).hex()


def _upload(client, doc_id=None, **overrides):
    body = {
        "doc_id": _doc_id() if doc_id is None else doc_id,
        "enc_name": _b64(os.urandom(20)),
        "nonce": _b64(os.urandom(12)),
        "ciphertext": _b64(os.urandom(64)),
        "tag": _b64(os.urandom(16)),
    }
    body.update(overrides)
    return client.post("/documents", json=body), body


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

class TestDocumentsApi:
    def test_upload_then_fetch_is_byte_identical(self, client):
        resp, body = _upload(client)
        assert resp.status_code == 201
        doc_id = resp.get_json()["doc_id"]

        got = client.get(f"/documents/{doc_id}")
        assert got.status_code == 200
        data = got.get_json()
        assert data["enc_name"] == body["enc_name"]
        assert data["nonce"] == body["nonce"]
        assert data["ciphertext"] == body["ciphertext"]
        assert data["tag"] == body["tag"]
        assert data["size"] == len(base64.b64decode(body["ciphertext"]))

    def test_upload_missing_field_returns_400(self, client):
        body = {
            "doc_id": _doc_id(),
            "enc_name": _b64(b"n"),
            "nonce": _b64(b"n" * 12),
            # "ciphertext" and "tag" omitted
        }
        resp = client.post("/documents", json=body)
        assert resp.status_code == 400

    def test_upload_missing_doc_id_returns_400(self, client):
        resp, _ = _upload(client, doc_id="")
        assert resp.status_code == 400

    def test_upload_invalid_base64_returns_400(self, client):
        resp, _ = _upload(client, ciphertext="not-valid-base64!!")
        assert resp.status_code == 400

    def test_upload_duplicate_doc_id_returns_409(self, client):
        doc_id = _doc_id()
        first, _ = _upload(client, doc_id=doc_id)
        assert first.status_code == 201
        second, _ = _upload(client, doc_id=doc_id)
        assert second.status_code == 409

    def test_get_missing_document_returns_404(self, client):
        resp = client.get("/documents/does-not-exist")
        assert resp.status_code == 404

    def test_list_returns_metadata_without_ciphertext(self, client):
        _upload(client)
        _upload(client)
        resp = client.get("/documents")
        assert resp.status_code == 200
        docs = resp.get_json()
        assert len(docs) == 2
        for d in docs:
            assert set(d.keys()) == {"doc_id", "enc_name", "size", "uploaded_at"}

    def test_replace_existing_document_returns_200_and_overwrites_it(self, client):
        resp, _ = _upload(client)
        doc_id = resp.get_json()["doc_id"]

        new_body = {
            "enc_name": _b64(os.urandom(20)),
            "nonce": _b64(os.urandom(12)),
            "ciphertext": _b64(os.urandom(80)),
            "tag": _b64(os.urandom(16)),
        }
        replaced = client.put(f"/documents/{doc_id}", json=new_body)
        assert replaced.status_code == 200
        assert replaced.get_json() == {"doc_id": doc_id, "status": "replaced"}

        got = client.get(f"/documents/{doc_id}").get_json()
        assert got["enc_name"] == new_body["enc_name"]
        assert got["nonce"] == new_body["nonce"]
        assert got["ciphertext"] == new_body["ciphertext"]
        assert got["tag"] == new_body["tag"]

    def test_replace_missing_document_returns_404(self, client):
        resp = client.put(
            "/documents/does-not-exist",
            json={
                "enc_name": _b64(b"n"), "nonce": _b64(b"n" * 12),
                "ciphertext": _b64(b"c"), "tag": _b64(b"t" * 16),
            },
        )
        assert resp.status_code == 404

    def test_replace_missing_field_returns_400(self, client):
        resp, _ = _upload(client)
        doc_id = resp.get_json()["doc_id"]
        incomplete = {"enc_name": _b64(b"n"), "nonce": _b64(b"n" * 12)}  # no ciphertext/tag
        replaced = client.put(f"/documents/{doc_id}", json=incomplete)
        assert replaced.status_code == 400

    def test_replace_invalid_base64_returns_400(self, client):
        resp, _ = _upload(client)
        doc_id = resp.get_json()["doc_id"]
        replaced = client.put(
            f"/documents/{doc_id}",
            json={
                "enc_name": "not-valid-base64!!", "nonce": _b64(b"n" * 12),
                "ciphertext": _b64(b"c"), "tag": _b64(b"t" * 16),
            },
        )
        assert replaced.status_code == 400

    def test_delete_existing_document_returns_200_and_removes_it(self, client):
        resp, _ = _upload(client)
        doc_id = resp.get_json()["doc_id"]

        deleted = client.delete(f"/documents/{doc_id}")
        assert deleted.status_code == 200
        assert deleted.get_json() == {"doc_id": doc_id, "status": "deleted"}

        got = client.get(f"/documents/{doc_id}")
        assert got.status_code == 404

    def test_delete_missing_document_returns_404(self, client):
        resp = client.delete("/documents/does-not-exist")
        assert resp.status_code == 404

    def test_delete_only_removes_the_targeted_document(self, client):
        keep, _ = _upload(client)
        drop, _ = _upload(client)
        keep_id = keep.get_json()["doc_id"]
        drop_id = drop.get_json()["doc_id"]

        client.delete(f"/documents/{drop_id}")

        assert client.get(f"/documents/{keep_id}").status_code == 200
        assert client.get(f"/documents/{drop_id}").status_code == 404
        assert len(client.get("/documents").get_json()) == 1


# ---------------------------------------------------------------------------
# sse_index
# ---------------------------------------------------------------------------

class TestIndexApi:
    def test_push_then_lookup_round_trip(self, client):
        label = os.urandom(32).hex()
        value = os.urandom(48)
        resp = client.post("/index", json={"entries": [{"label": label, "value": _b64(value)}]})
        assert resp.status_code == 201
        assert resp.get_json()["inserted"] == 1

        got = client.get(f"/index/{label}")
        assert got.status_code == 200
        assert base64.b64decode(got.get_json()["value"]) == value

    def test_push_multiple_entries_at_once(self, client):
        entries = [{"label": os.urandom(32).hex(), "value": _b64(os.urandom(16))} for _ in range(5)]
        resp = client.post("/index", json={"entries": entries})
        assert resp.status_code == 201
        assert resp.get_json()["inserted"] == 5

    def test_lookup_miss_returns_404(self, client):
        resp = client.get("/index/no-such-label")
        assert resp.status_code == 404

    def test_push_empty_entries_returns_400(self, client):
        resp = client.post("/index", json={"entries": []})
        assert resp.status_code == 400

    def test_push_entry_missing_value_returns_400(self, client):
        resp = client.post("/index", json={"entries": [{"label": "x"}]})
        assert resp.status_code == 400

    def test_push_duplicate_label_returns_409(self, client):
        label = os.urandom(32).hex()
        client.post("/index", json={"entries": [{"label": label, "value": _b64(b"v1")}]})
        resp = client.post("/index", json={"entries": [{"label": label, "value": _b64(b"v2")}]})
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# meta
# ---------------------------------------------------------------------------

class TestMetaApi:
    def test_set_then_get_round_trip(self, client):
        salt = os.urandom(16)
        resp = client.post("/meta/kdf_salt", json={"value": _b64(salt)})
        assert resp.status_code == 200

        got = client.get("/meta/kdf_salt")
        assert got.status_code == 200
        assert base64.b64decode(got.get_json()["value"]) == salt

    def test_get_missing_key_returns_404(self, client):
        resp = client.get("/meta/does-not-exist")
        assert resp.status_code == 404

    def test_set_overwrites_previous_value(self, client):
        client.post("/meta/scheme_version", json={"value": _b64(b"v1")})
        client.post("/meta/scheme_version", json={"value": _b64(b"v2")})
        got = client.get("/meta/scheme_version")
        assert base64.b64decode(got.get_json()["value"]) == b"v2"


# ---------------------------------------------------------------------------
# trust-boundary guard: cloud_app.py must never import client/
# ---------------------------------------------------------------------------

def test_cloud_app_module_does_not_import_client_package():
    source = open(
        os.path.join(os.path.dirname(__file__), "..", "cloud", "cloud_app.py")
    ).read()
    tree = ast.parse(source)
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert "client" not in imported_roots

# ---------------------------------------------------------------------------
# run_search_loop -- direct, storage-level tests (no HTTP)
# ---------------------------------------------------------------------------

def _seed_index(conn, k1: bytes, values: list) -> None:
    """Insert entries at consecutive counters 0..len(values)-1 under
    k1, exactly like a real client's build_index() would for one
    keyword -- but built by hand here so tests can control gaps."""
    entries = [
        (_cloud_prf(k1, _counter_to_bytes(i)).hex(), v) for i, v in enumerate(values)
    ]
    storage.save_index_entries(conn, entries)


class TestRunSearchLoop:
    def test_no_matching_entries_returns_empty_list(self, tmp_path):
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            assert run_search_loop(conn, os.urandom(32)) == []

    def test_single_match(self, tmp_path):
        k1 = os.urandom(32)
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            _seed_index(conn, k1, [b"value-0"])
            assert run_search_loop(conn, k1) == [b"value-0"]

    def test_multiple_matches_returned_in_counter_order(self, tmp_path):
        k1 = os.urandom(32)
        values = [f"value-{i}".encode() for i in range(7)]
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            _seed_index(conn, k1, values)
            assert run_search_loop(conn, k1) == values

    def test_stops_at_first_gap_even_if_a_later_counter_exists(self, tmp_path):
        # Simulates a corrupted/adversarial index: counter 0 exists,
        # counter 1 is missing, counter 2 exists. The loop must stop
        # at the first miss (counter 1) and never see counter 2's
        # entry -- Section 06's "contiguous counters -> clean stop".
        k1 = os.urandom(32)
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            entries = [
                (_cloud_prf(k1, _counter_to_bytes(0)).hex(), b"value-0"),
                (_cloud_prf(k1, _counter_to_bytes(2)).hex(), b"value-2"),  # gap at 1
            ]
            storage.save_index_entries(conn, entries)
            assert run_search_loop(conn, k1) == [b"value-0"]

    def test_unrelated_entries_in_the_table_do_not_interfere(self, tmp_path):
        k1_target = os.urandom(32)
        k1_other = os.urandom(32)
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            _seed_index(conn, k1_other, [b"other-value"])
            _seed_index(conn, k1_target, [b"target-value"])
            assert run_search_loop(conn, k1_target) == [b"target-value"]

    def test_empty_k1_does_not_crash(self, tmp_path):
        # HMAC accepts an empty key (RFC 2104); the cloud must not
        # crash on a garbage token, just find nothing.
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            assert run_search_loop(conn, b"") == []

    def test_defensive_bound_raises_instead_of_looping_forever(self, tmp_path, monkeypatch):
        # Simulate a pathological/corrupted state where every lookup
        # "hits" -- exercises the safety net directly, since honest
        # data can never actually trigger it (see run_search_loop's
        # docstring for the proof).
        with storage.open_db(tmp_path / "vault.sqlite3") as conn:
            _seed_index(conn, os.urandom(32), [b"x", b"y"])  # total_entries == 2
            monkeypatch.setattr(storage, "get_index_entry", lambda conn, label, vault_id="": b"always-hits")
            with pytest.raises(RuntimeError):
                run_search_loop(conn, os.urandom(32))


# ---------------------------------------------------------------------------
# /search -- HTTP level
# ---------------------------------------------------------------------------

class TestSearchApi:
    def test_search_missing_k1_returns_400(self, client):
        resp = client.post("/search", json={})
        assert resp.status_code == 400

    def test_search_invalid_base64_returns_400(self, client):
        resp = client.post("/search", json={"k1": "not-valid-base64!!"})
        assert resp.status_code == 400

    def test_search_no_matches_returns_empty_results(self, client):
        resp = client.post("/search", json={"k1": _b64(os.urandom(32))})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["results"] == []
        assert body["count"] == 0

    def test_search_finds_pushed_entries(self, client):
        k1 = os.urandom(32)
        value = os.urandom(16)
        label = _cloud_prf(k1, _counter_to_bytes(0)).hex()
        client.post("/index", json={"entries": [{"label": label, "value": _b64(value)}]})

        resp = client.post("/search", json={"k1": _b64(k1)})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["count"] == 1
        assert base64.b64decode(body["results"][0]) == value

    def test_search_finds_multiple_entries_for_the_same_token(self, client):
        k1 = os.urandom(32)
        values = [os.urandom(16) for _ in range(4)]
        entries = [
            {"label": _cloud_prf(k1, _counter_to_bytes(i)).hex(), "value": _b64(v)}
            for i, v in enumerate(values)
        ]
        client.post("/index", json={"entries": entries})

        resp = client.post("/search", json={"k1": _b64(k1)})
        body = resp.get_json()
        assert body["count"] == 4
        assert [base64.b64decode(r) for r in body["results"]] == values


# ---------------------------------------------------------------------------
# /index/replace -- HTTP level (Phase 5's atomic index-rebuild route)
# ---------------------------------------------------------------------------

class TestIndexReplaceApi:
    def test_replace_on_empty_index_with_empty_entries_is_a_no_op(self, client):
        resp = client.post("/index/replace", json={"entries": []})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body == {"removed": 0, "inserted": 0}

    def test_replace_clears_previous_entries_not_present_in_the_new_set(self, client):
        old_label = os.urandom(32).hex()
        client.post("/index", json={"entries": [{"label": old_label, "value": _b64(b"old")}]})

        new_label = os.urandom(32).hex()
        resp = client.post(
            "/index/replace", json={"entries": [{"label": new_label, "value": _b64(b"new")}]}
        )
        assert resp.status_code == 200
        assert resp.get_json() == {"removed": 1, "inserted": 1}

        assert client.get(f"/index/{old_label}").status_code == 404
        got = client.get(f"/index/{new_label}")
        assert got.status_code == 200
        assert base64.b64decode(got.get_json()["value"]) == b"new"

    def test_replace_with_empty_entries_clears_the_whole_index(self, client):
        client.post(
            "/index",
            json={"entries": [{"label": os.urandom(32).hex(), "value": _b64(b"x")}]},
        )
        resp = client.post("/index/replace", json={"entries": []})
        assert resp.status_code == 200
        assert resp.get_json()["removed"] == 1
        assert resp.get_json()["inserted"] == 0

    def test_replace_missing_entries_field_returns_400(self, client):
        resp = client.post("/index/replace", json={})
        assert resp.status_code == 400

    def test_replace_malformed_entry_returns_400_and_does_not_clear(self, client):
        label = os.urandom(32).hex()
        client.post("/index", json={"entries": [{"label": label, "value": _b64(b"keep-me")}]})

        resp = client.post("/index/replace", json={"entries": [{"label": "no-value"}]})
        assert resp.status_code == 400

        # Validation must happen BEFORE clearing -- a rejected request
        # should never wipe existing data.
        got = client.get(f"/index/{label}")
        assert got.status_code == 200
        assert base64.b64decode(got.get_json()["value"]) == b"keep-me"

    def test_does_not_touch_documents_or_meta_tables(self, client):
        client.post(
            "/documents",
            json={
                "doc_id": "doc-1",
                "enc_name": _b64(b"name"),
                "nonce": _b64(b"n" * 12),
                "ciphertext": _b64(b"c"),
                "tag": _b64(b"t" * 16),
            },
        )
        client.post("/meta/kdf_salt", json={"value": _b64(b"s" * 16)})

        client.post("/index/replace", json={"entries": []})

        assert client.get("/documents/doc-1").status_code == 200
        assert client.get("/meta/kdf_salt").status_code == 200
