"""
tests/test_client_app.py -- end-to-end tests for client/client_app.py,
the trusted client's Flask app.

Uses the SAME live_cloud fixture as test_cloud_client.py: a real
cloud/cloud_app.py running on its own port. client_app.py itself is
driven through its own Flask test client, so a full test here
genuinely exercises both legs of the real topology -- browser-style
requests hit client_app.py, which makes real HTTP calls out to the
live cloud process, exactly as the real deployed system would.

This is the file that proves the complete workflow the phase asked
for: unlock -> upload -> index -> search -> retrieve -> decrypt, plus
the failure modes (locked, wrong password, tampering) that make that
workflow trustworthy rather than just happy-path.
"""

import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.client_app import create_app  # noqa: E402


@pytest.fixture
def app_client(user_app_client):
    # Multi-user extension: a logged-in regular user with a fresh vault
    # (see conftest.user_app_client) -- previously the single global vault.
    yield user_app_client


def _upload(app_client, filename: str, content: str):
    data = {"file": (io.BytesIO(content.encode("utf-8")), filename)}
    return app_client.post("/api/documents", data=data, content_type="multipart/form-data")


def _unlock(app_client, password="correct horse battery staple"):
    return app_client.post("/api/unlock", json={"password": password})


def _upload_bytes(app_client, filename: str, raw_bytes: bytes):
    data = {"file": (io.BytesIO(raw_bytes), filename)}
    return app_client.post("/api/documents", data=data, content_type="multipart/form-data")


def _make_minimal_pdf(text: str = "") -> bytes:
    """Same hand-built minimal-PDF fixture as test_textextract.py --
    duplicated locally rather than imported, matching this file's own
    convention of each test class defining the small helpers it needs
    (see the sqlite helpers on TestH2.../TestF1... below) rather than
    threading shared fixtures across unrelated test modules."""
    content = f"BT /F1 18 Tf 10 100 Td ({text}) Tj ET".encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 300 200] /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"\nendstream",
    ]
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode("ascii"))
        out.write(obj)
        out.write(b"\nendobj\n")
    xref_offset = out.tell()
    n = len(objects) + 1
    out.write(f"xref\n0 {n}\n".encode("ascii"))
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(f"{off:010d} 00000 n \n".encode("ascii"))
    out.write(f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii"))
    return out.getvalue()


def _make_zip(files: "dict[str, bytes]") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# static UI + status
# ---------------------------------------------------------------------------

class TestStaticAndStatus:
    def test_index_page_served(self, app_client):
        resp = app_client.get("/")
        assert resp.status_code == 200
        assert b"Encrypted Cloud Vault" in resp.data

    def test_status_starts_locked(self, app_client):
        assert app_client.get("/api/status").get_json() == {"unlocked": False}


# ---------------------------------------------------------------------------
# unlock / lock
# ---------------------------------------------------------------------------

class TestUnlockLock:
    def test_unlock_with_empty_password_returns_400(self, app_client):
        resp = app_client.post("/api/unlock", json={"password": ""})
        assert resp.status_code == 400

    def test_unlock_succeeds_and_status_reflects_it(self, app_client):
        resp = _unlock(app_client)
        assert resp.status_code == 200
        assert app_client.get("/api/status").get_json() == {"unlocked": True}

    def test_lock_clears_state(self, app_client):
        _unlock(app_client)
        resp = app_client.post("/api/lock")
        assert resp.status_code == 200
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

    def test_protected_routes_require_unlock(self, app_client):
        assert app_client.get("/api/documents").status_code == 401
        assert app_client.post("/api/search", json={"query": "x"}).status_code == 401
        assert _upload(app_client, "a.txt", "hello").status_code == 401

    def test_unlock_when_cloud_unreachable_returns_502(self, app_client, monkeypatch):
        import client.client_app as client_app_module

        def _boom(key):
            from client.cloud_client import CloudUnavailableError
            raise CloudUnavailableError("simulated outage")

        monkeypatch.setattr(client_app_module.cloud_client, "get_meta", _boom)
        resp = _unlock(app_client)
        assert resp.status_code == 502


# ---------------------------------------------------------------------------
# password / key rotation
# ---------------------------------------------------------------------------

def _change_password(app_client, current_password, new_password):
    return app_client.post(
        "/api/change-password",
        json={"current_password": current_password, "new_password": new_password},
    )


class TestChangePassword:
    def test_requires_unlock(self, app_client):
        app_client.post("/api/lock")
        resp = _change_password(app_client, "whatever", "new-password")
        assert resp.status_code == 401

    def test_missing_current_password_returns_400(self, app_client):
        _unlock(app_client, password="the real password")
        resp = app_client.post("/api/change-password", json={"new_password": "new-password"})
        assert resp.status_code == 400

    def test_missing_new_password_returns_400(self, app_client):
        _unlock(app_client, password="the real password")
        resp = app_client.post("/api/change-password", json={"current_password": "the real password"})
        assert resp.status_code == 400

    def test_empty_new_password_returns_400(self, app_client):
        _unlock(app_client, password="the real password")
        resp = _change_password(app_client, "the real password", "")
        assert resp.status_code == 400

    def test_wrong_current_password_is_rejected_and_changes_nothing(self, app_client):
        assert _unlock(app_client, password="the real password").status_code == 200
        upload_resp = _upload(app_client, "a.txt", "shared keyword alpha")
        doc_id = upload_resp.get_json()["doc_id"]

        resp = _change_password(app_client, "an attacker's guess", "new-password")
        assert resp.status_code == 401

        # Nothing was touched: the old password still unlocks fresh
        # sessions and the document/index are exactly as they were.
        app_client.post("/api/lock")
        assert _unlock(app_client, password="the real password").status_code == 200
        listed = app_client.get("/api/documents").get_json()
        assert len(listed) == 1
        assert listed[0]["doc_id"] == doc_id
        assert listed[0]["filename"] == "a.txt"
        results = app_client.post("/api/search", json={"query": "alpha"}).get_json()["results"]
        assert [r["doc_id"] for r in results] == [doc_id]

    def test_rotation_updates_status_and_migrated_count(self, app_client):
        _unlock(app_client, password="old-password")
        _upload(app_client, "a.txt", "hello")
        _upload(app_client, "b.txt", "world")
        resp = _change_password(app_client, "old-password", "new-password")
        assert resp.status_code == 200
        assert resp.get_json() == {"status": "password changed", "documents_migrated": 2}

    def test_old_password_no_longer_unlocks_after_rotation(self, app_client):
        _unlock(app_client, password="old-password")
        _upload(app_client, "a.txt", "hello")
        assert _change_password(app_client, "old-password", "new-password").status_code == 200

        app_client.post("/api/lock")
        old_attempt = _unlock(app_client, password="old-password")
        assert old_attempt.status_code == 401

    def test_new_password_unlocks_after_rotation_with_documents_and_search_intact(self, app_client):
        _unlock(app_client, password="old-password")
        r1 = _upload(app_client, "a.txt", "quarterly financial report")
        doc_id = r1.get_json()["doc_id"]
        assert _change_password(app_client, "old-password", "new-password").status_code == 200

        app_client.post("/api/lock")
        assert _unlock(app_client, password="new-password").status_code == 200

        view = app_client.get(f"/api/documents/{doc_id}").get_json()
        assert view["filename"] == "a.txt"
        assert view["content"] == "quarterly financial report"

        results = app_client.post("/api/search", json={"query": "financial"}).get_json()["results"]
        assert [r["doc_id"] for r in results] == [doc_id]

    def test_vault_stays_unlocked_under_new_password_without_re_unlocking(self, app_client):
        # The in-memory session is updated to the new keys as part of
        # the same request -- no forced re-unlock needed to keep using
        # the vault right after rotation.
        _unlock(app_client, password="old-password")
        r1 = _upload(app_client, "a.txt", "hello world")
        doc_id = r1.get_json()["doc_id"]
        assert _change_password(app_client, "old-password", "new-password").status_code == 200

        assert app_client.get("/api/status").get_json() == {"unlocked": True}
        view = app_client.get(f"/api/documents/{doc_id}").get_json()
        assert view["content"] == "hello world"

    def test_multiple_documents_all_migrate_and_stay_searchable(self, app_client):
        _unlock(app_client, password="old-password")
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        r2 = _upload(app_client, "b.txt", "shared keyword beta")
        r3 = _upload(app_client, "c.txt", "shared keyword gamma")
        doc_ids = {r.get_json()["doc_id"] for r in (r1, r2, r3)}

        assert _change_password(app_client, "old-password", "new-password").status_code == 200

        listed = app_client.get("/api/documents").get_json()
        assert {d["doc_id"] for d in listed} == doc_ids

        shared = app_client.post("/api/search", json={"query": "shared"}).get_json()["results"]
        assert {r["doc_id"] for r in shared} == doc_ids
        alpha = app_client.post("/api/search", json={"query": "alpha"}).get_json()["results"]
        assert [r["doc_id"] for r in alpha] == [r1.get_json()["doc_id"]]

    def test_validation_failure_on_a_corrupted_document_changes_nothing(
        self, app_client, live_cloud, tmp_path
    ):
        # Mirrors TestH1DestructiveIndexRebuildRegression's technique:
        # a document corrupted on the cloud side must make phase-one
        # validation fail BEFORE any re-encryption or metadata update
        # happens -- the old password must still work afterwards, on
        # an otherwise-untouched vault.
        import sqlite3

        assert _unlock(app_client, password="old-password").status_code == 200
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        doc_id_a = r1.get_json()["doc_id"]
        r2 = _upload(app_client, "b.txt", "shared keyword beta")
        doc_id_b = r2.get_json()["doc_id"]

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        conn = sqlite3.connect(str(db_candidates[0]))
        row = conn.execute(
            "SELECT ciphertext FROM documents WHERE doc_id = ?", (doc_id_a,)
        ).fetchone()
        conn.execute(
            "UPDATE documents SET ciphertext = ? WHERE doc_id = ?",
            (row[0] + b"x", doc_id_a),
        )
        conn.commit()
        conn.close()

        resp = _change_password(app_client, "old-password", "new-password")
        assert resp.status_code == 500
        assert "not" in resp.get_json()["error"].lower()

        # Old password still works; b.txt (never corrupted) is exactly
        # as it was; the vault was never touched by phase two.
        app_client.post("/api/lock")
        assert _unlock(app_client, password="old-password").status_code == 200
        view_b = app_client.get(f"/api/documents/{doc_id_b}").get_json()
        assert view_b["content"] == "shared keyword beta"
        results = app_client.post("/api/search", json={"query": "beta"}).get_json()["results"]
        assert [r["doc_id"] for r in results] == [doc_id_b]


# ---------------------------------------------------------------------------
# upload
# ---------------------------------------------------------------------------

class TestUpload:
    def test_upload_requires_utf8_text(self, app_client):
        _unlock(app_client)
        data = {"file": (io.BytesIO(b"\xff\xfe\x00\x01binary garbage"), "bad.bin")}
        resp = app_client.post("/api/documents", data=data, content_type="multipart/form-data")
        assert resp.status_code == 400

    def test_upload_succeeds_and_appears_in_vault_list(self, app_client):
        _unlock(app_client)
        resp = _upload(app_client, "notes.txt", "quarterly financial report")
        assert resp.status_code == 201
        assert resp.get_json()["filename"] == "notes.txt"

        listed = app_client.get("/api/documents").get_json()
        assert len(listed) == 1
        assert listed[0]["filename"] == "notes.txt"

    def test_upload_no_file_returns_400(self, app_client):
        _unlock(app_client)
        resp = app_client.post("/api/documents", data={}, content_type="multipart/form-data")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# the complete workflow: unlock -> upload -> search -> retrieve -> decrypt
# ---------------------------------------------------------------------------

class TestCompleteWorkflow:
    def test_full_workflow_single_document(self, app_client):
        assert _unlock(app_client).status_code == 200

        upload_resp = _upload(app_client, "report.txt", "Quarterly financial report, confidential.")
        assert upload_resp.status_code == 201
        doc_id = upload_resp.get_json()["doc_id"]

        search_resp = app_client.post("/api/search", json={"query": "financial"})
        assert search_resp.status_code == 200
        results = search_resp.get_json()["results"]
        assert len(results) == 1
        assert results[0]["doc_id"] == doc_id
        assert results[0]["filename"] == "report.txt"

        view_resp = app_client.get(f"/api/documents/{doc_id}")
        assert view_resp.status_code == 200
        body = view_resp.get_json()
        assert body["filename"] == "report.txt"
        assert body["content"] == "Quarterly financial report, confidential."

    def test_multiple_uploads_rebuild_index_correctly(self, app_client):
        # This is the specific correctness property the Phase 5 design
        # discussion flagged: adding documents whose doc_ids sort
        # BEFORE existing ones shifts postings counters, so a naive
        # additive re-push would leave stale entries. Uploading three
        # documents sharing a keyword, in sequence, and confirming a
        # search after each one returns exactly the right growing set
        # is the end-to-end proof that /index/replace's atomic
        # clear-then-insert actually works through the real app.
        _unlock(app_client)

        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        r2 = _upload(app_client, "b.txt", "shared keyword beta")
        r3 = _upload(app_client, "c.txt", "shared keyword gamma")
        doc_ids = {r1.get_json()["doc_id"], r2.get_json()["doc_id"], r3.get_json()["doc_id"]}
        assert len(doc_ids) == 3

        search_resp = app_client.post("/api/search", json={"query": "shared"})
        results = search_resp.get_json()["results"]
        assert {r["doc_id"] for r in results} == doc_ids
        assert {r["filename"] for r in results} == {"a.txt", "b.txt", "c.txt"}

        # And the unique keywords are each still findable individually.
        for keyword, expected_doc in (("alpha", "a.txt"), ("beta", "b.txt"), ("gamma", "c.txt")):
            resp = app_client.post("/api/search", json={"query": keyword})
            names = [r["filename"] for r in resp.get_json()["results"]]
            assert names == [expected_doc]

    def test_search_for_missing_keyword_returns_empty_results(self, app_client):
        _unlock(app_client)
        _upload(app_client, "a.txt", "hello world")
        resp = app_client.post("/api/search", json={"query": "nonexistentword"})
        assert resp.status_code == 200
        assert resp.get_json()["results"] == []

    def test_multi_word_query_is_now_a_conjunctive_and_search(self, app_client):
        # Historically 400 (multi-keyword search was out of scope --
        # see the now-superseded assertion this replaced). Scope
        # decision reversed: see TestConjunctiveSearch below for the
        # full behaviour this now has.
        _unlock(app_client)
        _upload(app_client, "a.txt", "hello world")
        resp = app_client.post("/api/search", json={"query": "hello world"})
        assert resp.status_code == 200
        assert [r["filename"] for r in resp.get_json()["results"]] == ["a.txt"]

    def test_view_nonexistent_document_returns_404(self, app_client):
        _unlock(app_client)
        resp = app_client.get("/api/documents/does-not-exist")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# conjunctive (multi-keyword AND) search
# ---------------------------------------------------------------------------

class TestConjunctiveSearch:
    def test_two_keyword_query_returns_only_documents_matching_both(self, app_client):
        _unlock(app_client)
        _upload(app_client, "a.txt", "quarterly financial report")  # has both
        _upload(app_client, "b.txt", "quarterly board minutes")  # only one
        _upload(app_client, "c.txt", "unrelated financial memo")  # only the other

        resp = app_client.post("/api/search", json={"query": "quarterly financial"})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["keywords"] == ["financial", "quarterly"]
        assert [r["filename"] for r in body["results"]] == ["a.txt"]

    def test_three_keyword_query(self, app_client):
        _unlock(app_client)
        _upload(app_client, "a.txt", "alpha beta gamma")  # has all three
        _upload(app_client, "b.txt", "alpha beta only")  # missing gamma
        resp = app_client.post("/api/search", json={"query": "alpha beta gamma"})
        assert [r["filename"] for r in resp.get_json()["results"]] == ["a.txt"]

    def test_keyword_order_in_the_query_does_not_matter(self, app_client):
        _unlock(app_client)
        _upload(app_client, "a.txt", "alpha beta gamma")
        forward = app_client.post("/api/search", json={"query": "alpha gamma"}).get_json()
        backward = app_client.post("/api/search", json={"query": "gamma alpha"}).get_json()
        assert forward["keywords"] == backward["keywords"] == ["alpha", "gamma"]
        assert forward["results"] == backward["results"]

    def test_no_document_matches_all_keywords_returns_empty(self, app_client):
        _unlock(app_client)
        _upload(app_client, "a.txt", "alpha beta")
        _upload(app_client, "b.txt", "gamma delta")
        resp = app_client.post("/api/search", json={"query": "alpha delta"})
        assert resp.get_json()["results"] == []

    def test_one_keyword_present_one_entirely_unindexed(self, app_client):
        # "alpha" is real and indexed; "zzznotindexed" matches nothing
        # at all -- the intersection must still come back empty, not
        # error, and the search for the unindexed term must short
        # circuit rather than needing "alpha" to be searched too.
        _unlock(app_client)
        _upload(app_client, "a.txt", "alpha beta")
        resp = app_client.post("/api/search", json={"query": "alpha zzznotindexed"})
        assert resp.status_code == 200
        assert resp.get_json()["results"] == []

    def test_single_keyword_query_is_unchanged(self, app_client):
        # The original single-keyword path is a strict special case of
        # the new one, not a different code path -- confirm it still
        # behaves exactly as before.
        _unlock(app_client)
        _upload(app_client, "a.txt", "quarterly report")
        resp = app_client.post("/api/search", json={"query": "quarterly"})
        body = resp.get_json()
        assert body["keywords"] == ["quarterly"]
        assert [r["filename"] for r in body["results"]] == ["a.txt"]

    def test_empty_query_still_returns_400(self, app_client):
        _unlock(app_client)
        resp = app_client.post("/api/search", json={"query": "   "})
        assert resp.status_code == 400

    def test_only_stopwords_still_returns_400(self, app_client):
        _unlock(app_client)
        resp = app_client.post("/api/search", json={"query": "the a is"})
        assert resp.status_code == 400

    def test_requires_unlock(self, app_client):
        app_client.post("/api/lock")
        resp = app_client.post("/api/search", json={"query": "alpha beta"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

class TestDeleteDocument:
    def test_delete_requires_unlock(self, app_client):
        # Explicitly locked rather than relying on app_client's fresh
        # process-wide state: _current_keys is a module-level global
        # (see client_app.py's module docstring), not reset between
        # tests, so an earlier test class in the same pytest run that
        # unlocked and never re-locked would otherwise leave this test
        # order-dependent instead of a genuine "locked" precondition.
        app_client.post("/api/lock")
        resp = app_client.delete("/api/documents/does-not-exist")
        assert resp.status_code == 401

    def test_delete_nonexistent_document_returns_404(self, app_client):
        _unlock(app_client)
        resp = app_client.delete("/api/documents/does-not-exist")
        assert resp.status_code == 404

    def test_delete_removes_document_from_vault_list_and_storage(self, app_client):
        _unlock(app_client)
        upload_resp = _upload(app_client, "notes.txt", "quarterly report")
        doc_id = upload_resp.get_json()["doc_id"]

        delete_resp = app_client.delete(f"/api/documents/{doc_id}")
        assert delete_resp.status_code == 200
        assert delete_resp.get_json() == {"doc_id": doc_id, "status": "deleted"}

        assert app_client.get("/api/documents").get_json() == []
        assert app_client.get(f"/api/documents/{doc_id}").status_code == 404

    def test_delete_removes_document_from_the_search_index_too(self, app_client):
        # The point of this feature, not just the document row: deleting
        # must not leave a keyword still resolving to a doc_id that no
        # longer exists (the exact phantom-result problem the route's
        # docstring explains why it rebuilds BEFORE deleting).
        _unlock(app_client)
        upload_resp = _upload(app_client, "notes.txt", "uniquesearchableterm")
        doc_id = upload_resp.get_json()["doc_id"]

        pre = app_client.post("/api/search", json={"query": "uniquesearchableterm"}).get_json()
        assert [r["doc_id"] for r in pre["results"]] == [doc_id]

        app_client.delete(f"/api/documents/{doc_id}")

        post = app_client.post("/api/search", json={"query": "uniquesearchableterm"}).get_json()
        assert post["results"] == []

    def test_delete_one_of_several_documents_sharing_a_keyword_keeps_the_others_searchable(
        self, app_client
    ):
        _unlock(app_client)
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        r2 = _upload(app_client, "b.txt", "shared keyword beta")
        r3 = _upload(app_client, "c.txt", "shared keyword gamma")
        doc_a, doc_b, doc_c = (r.get_json()["doc_id"] for r in (r1, r2, r3))

        app_client.delete(f"/api/documents/{doc_b}")

        remaining = app_client.get("/api/documents").get_json()
        assert {d["doc_id"] for d in remaining} == {doc_a, doc_c}

        shared = app_client.post("/api/search", json={"query": "shared"}).get_json()
        assert {r["doc_id"] for r in shared["results"]} == {doc_a, doc_c}

        assert app_client.post("/api/search", json={"query": "beta"}).get_json()["results"] == []
        alpha_results = app_client.post("/api/search", json={"query": "alpha"}).get_json()["results"]
        assert [r["doc_id"] for r in alpha_results] == [doc_a]
        gamma_results = app_client.post("/api/search", json={"query": "gamma"}).get_json()["results"]
        assert [r["doc_id"] for r in gamma_results] == [doc_c]

    def test_delete_then_upload_still_works_and_index_stays_correct(self, app_client):
        _unlock(app_client)
        r1 = _upload(app_client, "a.txt", "keeper keyword")
        doc_a = r1.get_json()["doc_id"]
        r2 = _upload(app_client, "b.txt", "removable keyword")
        doc_b = r2.get_json()["doc_id"]

        app_client.delete(f"/api/documents/{doc_b}")

        r3 = _upload(app_client, "c.txt", "fresh keyword")
        assert r3.status_code == 201
        doc_c = r3.get_json()["doc_id"]

        assert {d["doc_id"] for d in app_client.get("/api/documents").get_json()} == {doc_a, doc_c}
        keeper_results = app_client.post("/api/search", json={"query": "keeper"}).get_json()["results"]
        assert [r["doc_id"] for r in keeper_results] == [doc_a]
        fresh_results = app_client.post("/api/search", json={"query": "fresh"}).get_json()["results"]
        assert [r["doc_id"] for r in fresh_results] == [doc_c]
        assert app_client.post("/api/search", json={"query": "removable"}).get_json()["results"] == []

    def test_failed_index_rebuild_leaves_the_document_undeleted(
        self, app_client, live_cloud, tmp_path
    ):
        # Mirrors TestH1DestructiveIndexRebuildRegression's corruption
        # technique below. If some OTHER document still in the vault is
        # corrupted on the cloud side, the rebuild that must run BEFORE
        # this document is actually deleted will fail -- and per this
        # route's own documented ordering, that must mean the document
        # being "deleted" is left exactly where it was, not removed out
        # from under a search index that could no longer be safely
        # rebuilt without it.
        import sqlite3

        assert _unlock(app_client, password="the real password").status_code == 200
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        doc_id_a = r1.get_json()["doc_id"]
        r2 = _upload(app_client, "b.txt", "shared keyword beta")
        doc_id_b = r2.get_json()["doc_id"]

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        conn = sqlite3.connect(str(db_candidates[0]))
        row = conn.execute(
            "SELECT ciphertext FROM documents WHERE doc_id = ?", (doc_id_a,)
        ).fetchone()
        corrupted = row[0] + b"x"
        conn.execute(
            "UPDATE documents SET ciphertext = ? WHERE doc_id = ?",
            (corrupted, doc_id_a),
        )
        conn.commit()
        conn.close()

        # Deleting doc_id_b requires rebuilding the index over the
        # REMAINING corpus, which still includes the now-corrupted
        # doc_id_a -- so the rebuild must fail, and doc_id_b must be
        # left in place rather than deleted out from under it.
        delete_resp = app_client.delete(f"/api/documents/{doc_id_b}")
        assert delete_resp.status_code == 500
        assert "not deleted" in delete_resp.get_json()["error"].lower()

        listed = app_client.get("/api/documents").get_json()
        assert {d["doc_id"] for d in listed} == {doc_id_a, doc_id_b}


# ---------------------------------------------------------------------------
# wrong password -- security fix H1/H2: unlock now fails CLOSED, before
# any key can reach an upload or index rebuild. The three tests below
# used to unlock "successfully" with a wrong password and only observe
# graceful degradation afterwards (undecryptable filenames, empty
# search, a 422 on view) -- that was the exact "no verifier" design
# note the old class name referenced, and it is exactly what let H1
# happen. They are replaced here with tests of the fixed behaviour:
# unlock itself refuses a wrong password outright, so those degraded-
# but-not-crashing states are never reached in the first place.
# ---------------------------------------------------------------------------

class TestWrongPasswordFailsClosedAtUnlock:
    def test_wrong_password_unlock_is_rejected_clearly(self, app_client):
        _unlock(app_client, password="the real password")
        _upload(app_client, "secret.txt", "top secret contents")
        app_client.post("/api/lock")

        resp = _unlock(app_client, password="a completely different guess")
        assert resp.status_code == 401
        assert "incorrect password" in resp.get_json()["error"].lower()
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

    def test_wrong_password_leaves_documents_and_search_inaccessible(self, app_client):
        _unlock(app_client, password="the real password")
        _upload(app_client, "secret.txt", "confidential keyword")
        app_client.post("/api/lock")

        resp = _unlock(app_client, password="a completely different guess")
        assert resp.status_code == 401

        # Vault stayed locked -- nothing about the old degraded-but-200
        # behaviour (undecryptable filenames, empty search results) is
        # reachable, because unlock itself already refused.
        assert app_client.get("/api/documents").status_code == 401
        assert app_client.post("/api/search", json={"query": "confidential"}).status_code == 401

    def test_wrong_password_then_correct_password_still_unlocks(self, app_client):
        # The verifier must not falsely reject the real password after
        # a failed attempt -- a wrong guess must not corrupt state.
        _unlock(app_client, password="the real password")
        upload_resp = _upload(app_client, "secret.txt", "top secret contents")
        doc_id = upload_resp.get_json()["doc_id"]
        app_client.post("/api/lock")

        assert _unlock(app_client, password="a completely different guess").status_code == 401
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

        resp = _unlock(app_client, password="the real password")
        assert resp.status_code == 200
        view = app_client.get(f"/api/documents/{doc_id}")
        assert view.status_code == 200
        assert view.get_json()["content"] == "top secret contents"


# ---------------------------------------------------------------------------
# H1 regression -- adversarial sequence from the Opus audit's Probe P1:
# wrong-password unlock -> upload -> the encrypted index must survive.
# ---------------------------------------------------------------------------

class TestH1DestructiveIndexRebuildRegression:
    def test_adversarial_sequence_wrong_password_then_upload_cannot_destroy_index(self, app_client):
        # Ground truth: a real document, correctly indexed.
        assert _unlock(app_client, password="the real password").status_code == 200
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        assert r1.status_code == 201
        doc_id_a = r1.get_json()["doc_id"]
        app_client.post("/api/lock")

        # PROBE P1, step 1: unlock with a wrong password. Pre-fix this
        # returned 200 {'status': 'unlocked'}. Now it must be rejected
        # outright, and _current_keys must never be set.
        wrong_unlock = _unlock(app_client, password="an attacker's guess")
        assert wrong_unlock.status_code == 401

        # PROBE P1, step 2: attempt the upload that used to trigger the
        # destructive rebuild under the wrong K_file. Since unlock never
        # succeeded, this must be rejected as locked, not accepted as
        # 201 -- the destructive path is structurally unreachable now.
        upload_attempt = _upload(app_client, "evil.txt", "whatever the attacker wants")
        assert upload_attempt.status_code == 401

        # PROBE P1's regression check: search hits before=1, after=0 in
        # the original bug. With the fix, the real index must be fully
        # intact after this whole adversarial sequence.
        assert _unlock(app_client, password="the real password").status_code == 200
        search_resp = app_client.post("/api/search", json={"query": "shared"})
        assert search_resp.status_code == 200
        results = search_resp.get_json()["results"]
        assert [r["doc_id"] for r in results] == [doc_id_a]

        listed = app_client.get("/api/documents").get_json()
        assert len(listed) == 1
        assert listed[0]["filename"] == "a.txt"

    def test_rebuild_aborts_and_leaves_index_untouched_when_a_document_is_corrupted(
        self, app_client, live_cloud, tmp_path
    ):
        # Defence-in-depth check for the OTHER half of H1's fix: even
        # with a correct password throughout (no wrong-password entry
        # point at all here), a single corrupted document must not
        # cause the whole index to be silently replaced with one that
        # is missing that document's keywords.
        import sqlite3

        assert _unlock(app_client, password="the real password").status_code == 200
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        assert r1.status_code == 201
        doc_id_a = r1.get_json()["doc_id"]

        # Sanity: the keyword is findable before any corruption.
        pre_check = app_client.post("/api/search", json={"query": "shared"}).get_json()
        assert len(pre_check["results"]) == 1

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        conn = sqlite3.connect(str(db_candidates[0]))
        row = conn.execute(
            "SELECT ciphertext FROM documents WHERE doc_id = ?", (doc_id_a,)
        ).fetchone()
        corrupted = row[0] + b"x"  # append raw bytes -- keeps BLOB storage
        # affinity, unlike SQL '||' with a text literal, which would
        # coerce the column to TEXT and break unrelated reads.
        conn.execute(
            "UPDATE documents SET ciphertext = ? WHERE doc_id = ?",
            (corrupted, doc_id_a),
        )
        conn.commit()
        conn.close()

        # A second upload triggers _rebuild_and_push_index(), which will
        # now fail to decrypt doc_id_a. It must abort, not push a
        # smaller index -- so the upload as a whole reports failure...
        r2 = _upload(app_client, "b.txt", "shared keyword beta")
        assert r2.status_code == 500
        assert "index" in r2.get_json()["error"].lower()

        # ...but the SECOND document was still safely stored (only the
        # index rebuild was aborted, per the fix's "document stored,
        # but index rebuild refused" contract).
        listed = app_client.get("/api/documents").get_json()
        assert {d["doc_id"] for d in listed} == {doc_id_a, r2.get_json()["doc_id"]}

        # And the index from BEFORE the corruption is exactly as it
        # was -- doc_id_a is still found by its original keyword, which
        # would be impossible if the index had been replaced by a
        # rebuild that excluded it.
        search_resp = app_client.post("/api/search", json={"query": "alpha"})
        assert [r["doc_id"] for r in search_resp.get_json()["results"]] == [doc_id_a]


# ---------------------------------------------------------------------------
# trust boundary: what actually crosses the wire to the cloud
# ---------------------------------------------------------------------------

class TestTrustBoundaryThroughTheRealApp:
    def test_cloud_database_never_contains_plaintext_or_keys_after_a_full_workflow(
        self, app_client, live_cloud, tmp_path
    ):
        _unlock(app_client, password="vault owner's password")
        _upload(app_client, "plan.txt", "confidential strategic plan for Q4")
        app_client.post("/api/search", json={"query": "confidential"})

        # Find the live cloud's actual db file: the live_cloud fixture
        # created it under this test's own tmp_path.
        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        raw = db_candidates[0].read_bytes()

        assert b"confidential" not in raw
        assert b"strategic" not in raw
        assert b"plan.txt" not in raw

    def test_browser_facing_responses_never_include_key_material_field_names(self, app_client):
        # A structural sanity check: nothing this app ever returns to
        # the browser is named like a key. (Actual key-byte-absence is
        # proven at the crypto/integration layers already -- this
        # checks the API contract doesn't even have a field to leak
        # one through.)
        _unlock(app_client)
        _upload(app_client, "a.txt", "hello world")
        for path, method, body in [
            ("/api/status", "get", None),
            ("/api/documents", "get", None),
            ("/api/search", "post", {"query": "hello"}),
        ]:
            resp = app_client.get(path) if method == "get" else app_client.post(path, json=body)
            payload = resp.get_json()
            text = str(payload).lower()
            for forbidden in ("k_file", "k_index", "master_key", "kfile", "kindex"):
                assert forbidden not in text


# ---------------------------------------------------------------------------
# H2 regression -- Opus audit Probe P5: unauthenticated KDF metadata.
# Directly manipulates the cloud's raw meta table (as an operator
# deleting a row, or a bug/tamper would) to reproduce the exact
# missing/corrupt-salt scenarios the fix must fail closed on.
# ---------------------------------------------------------------------------

class TestH2MissingOrCorruptKdfMetadataRegression:
    @staticmethod
    def _meta_row_count(tmp_path, key=None):
        import sqlite3

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        conn = sqlite3.connect(str(db_candidates[0]))
        if key is None:
            row = conn.execute("SELECT COUNT(*) FROM meta").fetchone()
        else:
            row = conn.execute("SELECT COUNT(*) FROM meta WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row[0]

    @staticmethod
    def _delete_meta_row(tmp_path, key):
        import sqlite3

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        conn = sqlite3.connect(str(db_candidates[0]))
        conn.execute("DELETE FROM meta WHERE key = ?", (key,))
        conn.commit()
        conn.close()

    @staticmethod
    def _corrupt_meta_row(tmp_path, key, transform):
        import sqlite3

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        conn = sqlite3.connect(str(db_candidates[0]))
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        assert row is not None
        conn.execute("UPDATE meta SET value = ? WHERE key = ?", (transform(row[0]), key))
        conn.commit()
        conn.close()

    def test_first_ever_unlock_creates_both_salt_and_verifier_rows(self, app_client, tmp_path):
        assert self._meta_row_count(tmp_path) == 0
        resp = _unlock(app_client, password="a brand new vault password")
        assert resp.status_code == 200
        assert self._meta_row_count(tmp_path, "kdf_salt") == 1
        assert self._meta_row_count(tmp_path, "kdf_verifier") == 1

    def test_missing_salt_on_an_existing_vault_fails_closed(self, app_client, tmp_path):
        # PROBE P5: unlock once to create a real vault (both rows
        # present), upload a document, lock, then delete the single
        # kdf_salt row exactly as an operator `DELETE FROM meta` or a
        # restored partial backup would.
        assert _unlock(app_client, password="the real password").status_code == 200
        _upload(app_client, "secret.txt", "top secret contents")
        app_client.post("/api/lock")

        self._delete_meta_row(tmp_path, "kdf_salt")

        # Pre-fix: this returned 200 {'status': 'unlocked'} and quietly
        # minted a brand-new vault identity over the old one. Post-fix:
        # it must refuse outright, with both the real password...
        resp = _unlock(app_client, password="the real password")
        assert resp.status_code == 409
        assert "kdf_salt" in resp.get_json()["error"]
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

        # ...and any other password: this is not "wrong password", it
        # is "vault cannot be safely unlocked at all" -- no new salt
        # may be minted regardless of what password is supplied.
        resp2 = _unlock(app_client, password="literally anything else")
        assert resp2.status_code == 409
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

    def test_missing_verifier_on_an_existing_vault_fails_closed(self, app_client, tmp_path):
        # The mirror image of the above: kdf_salt survives, but
        # kdf_verifier is the one that's gone (e.g. a partial write
        # during vault creation, or a targeted deletion). Must also
        # fail closed, never fall back to unauthenticated trust of the
        # surviving salt.
        assert _unlock(app_client, password="the real password").status_code == 200
        app_client.post("/api/lock")

        self._delete_meta_row(tmp_path, "kdf_verifier")

        resp = _unlock(app_client, password="the real password")
        assert resp.status_code == 409
        assert "kdf_verifier" in resp.get_json()["error"]
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

    def test_corrupted_salt_bytes_never_unlock(self, app_client, tmp_path):
        # Salt row still present (not deleted), but its bytes have been
        # altered -- e.g. a substituted salt (Probe P5's other half:
        # "a cloud returning one fixed salt to every vault"), or plain
        # bit-rot. Must never reach an unlocked state.
        assert _unlock(app_client, password="the real password").status_code == 200
        _upload(app_client, "secret.txt", "top secret contents")
        app_client.post("/api/lock")

        self._corrupt_meta_row(
            tmp_path, "kdf_salt", lambda old: bytes((old[0] ^ 0xFF,)) + old[1:]
        )

        resp = _unlock(app_client, password="the real password")
        assert resp.status_code != 200
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

    def test_correct_password_on_an_untampered_vault_still_unlocks_across_cycles(
        self, app_client, tmp_path
    ):
        # The regression the whole verifier mechanism must not break:
        # ordinary repeated lock/unlock with the correct password, on
        # an untouched vault, keeps working exactly as before.
        assert _unlock(app_client, password="the real password").status_code == 200
        r1 = _upload(app_client, "notes.txt", "quarterly findings")
        assert r1.status_code == 201
        app_client.post("/api/lock")

        for _ in range(3):
            resp = _unlock(app_client, password="the real password")
            assert resp.status_code == 200
            assert app_client.get("/api/status").get_json() == {"unlocked": True}
            view = app_client.get(f"/api/documents/{r1.get_json()['doc_id']}")
            assert view.status_code == 200
            assert view.get_json()["content"] == "quarterly findings"
            app_client.post("/api/lock")


# ---------------------------------------------------------------------------
# F1 regression -- Opus follow-up review: the H2 fix's "both rows
# absent -> genuinely fresh vault" branch did not check whether the
# vault already had documents. Deleting BOTH kdf_salt AND kdf_verifier
# from an EXISTING vault used to still be treated as "fresh" and would
# happily mint a brand-new identity, letting literally any password
# report "unlocked" -- while the vault's real encrypted documents sit
# there, permanently unreadable under the old (now orphaned) keys.
# This class reproduces that exact attack and confirms the fix: such a
# vault must fail closed for every password, and the existing
# encrypted documents must be provably untouched (byte-identical)
# throughout.
# ---------------------------------------------------------------------------

class TestF1BothKdfRowsMissingRegression:
    @staticmethod
    def _db_path(tmp_path):
        import sqlite3  # noqa: F401  (imported for side effect symmetry with helpers below)

        db_candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
        assert len(db_candidates) == 1
        return db_candidates[0]

    @classmethod
    def _delete_both_kdf_rows(cls, tmp_path):
        import sqlite3

        conn = sqlite3.connect(str(cls._db_path(tmp_path)))
        conn.execute("DELETE FROM meta WHERE key IN ('kdf_salt', 'kdf_verifier')")
        conn.commit()
        conn.close()

    @classmethod
    def _meta_row_count(cls, tmp_path):
        import sqlite3

        conn = sqlite3.connect(str(cls._db_path(tmp_path)))
        row = conn.execute("SELECT COUNT(*) FROM meta").fetchone()
        conn.close()
        return row[0]

    @classmethod
    def _snapshot_document_row(cls, tmp_path, doc_id):
        """Raw bytes of one document row exactly as SQLite stores
        them -- the ground truth for "the encrypted document was not
        touched", independent of anything client_app.py's own API
        reports (which is locked and can't even be asked, by design,
        once the attack has landed)."""
        import sqlite3

        conn = sqlite3.connect(str(cls._db_path(tmp_path)))
        row = conn.execute(
            "SELECT enc_name, nonce, ciphertext, tag, size, uploaded_at "
            "FROM documents WHERE doc_id = ?",
            (doc_id,),
        ).fetchone()
        conn.close()
        assert row is not None, "document disappeared entirely -- far worse than untouched-but-unreadable"
        return tuple(row)

    def test_both_rows_missing_on_a_vault_with_documents_fails_closed_for_any_password(
        self, app_client, tmp_path
    ):
        # Ground truth: a real vault, unlocked once, with a real
        # document -- so kdf_salt and kdf_verifier both legitimately
        # exist (created by the H2 bootstrap branch on first unlock).
        assert _unlock(app_client, password="the real password").status_code == 200
        _upload(app_client, "secret.txt", "top secret contents")
        app_client.post("/api/lock")
        assert self._meta_row_count(tmp_path) == 2

        # THE ATTACK: both mandatory KDF rows deleted at once (a wipe
        # of the `meta` table, a bad restore, or a targeted deletion --
        # indistinguishable from the cloud's side of the trust
        # boundary). Pre-F1-fix, api_unlock's `salt is None and
        # verifier is None` branch could not tell this apart from a
        # genuinely fresh vault and would mint a new identity here.
        self._delete_both_kdf_rows(tmp_path)
        assert self._meta_row_count(tmp_path) == 0

        # The real password must NOT be accepted -- the fix must not
        # silently bootstrap a new identity that happens to reuse the
        # real password, because that would still be minting a NEW
        # salt/verifier pair (not restoring the old, now-lost one),
        # permanently orphaning the already-encrypted document under
        # keys derived from a salt that no longer exists anywhere.
        resp_real = _unlock(app_client, password="the real password")
        assert resp_real.status_code == 409
        assert "already contains documents" in resp_real.get_json()["error"]
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

        # ...and no other password may be accepted either -- this is
        # "vault cannot be safely unlocked at all", not "wrong
        # password", exactly like the single-row-missing (H2) case.
        resp_other = _unlock(app_client, password="an attacker's random guess")
        assert resp_other.status_code == 409
        assert app_client.get("/api/status").get_json() == {"unlocked": False}

        # And the attack must not have silently re-minted metadata as
        # a side effect of the refused attempts.
        assert self._meta_row_count(tmp_path) == 0

    def test_both_rows_missing_attack_leaves_encrypted_documents_untouched(
        self, app_client, tmp_path
    ):
        assert _unlock(app_client, password="the real password").status_code == 200
        r1 = _upload(app_client, "secret.txt", "top secret contents")
        assert r1.status_code == 201
        doc_id = r1.get_json()["doc_id"]
        before = self._snapshot_document_row(tmp_path, doc_id)
        app_client.post("/api/lock")

        self._delete_both_kdf_rows(tmp_path)

        # Fire several unlock attempts -- the real password, a wrong
        # one, and an empty-ish edge case -- all of which must be
        # refused, before checking the document underneath.
        for pw in ("the real password", "an attacker's random guess", "x"):
            resp = _unlock(app_client, password=pw)
            assert resp.status_code == 409

        after = self._snapshot_document_row(tmp_path, doc_id)
        assert after == before, (
            "the encrypted document row changed after a both-KDF-rows-missing "
            "attack sequence -- it must be left byte-for-byte untouched"
        )

    def test_both_rows_missing_on_a_genuinely_empty_vault_still_bootstraps(
        self, app_client, tmp_path
    ):
        # Regression guard for the fix itself: a TRUE fresh vault (no
        # documents ever uploaded, no KDF metadata ever written) must
        # still be allowed to bootstrap on first unlock -- the F1 fix
        # must not turn every legitimate first-run into a 409.
        assert self._meta_row_count(tmp_path) == 0
        resp = _unlock(app_client, password="a brand new vault password")
        assert resp.status_code == 200
        assert self._meta_row_count(tmp_path) == 2
        assert app_client.get("/api/status").get_json() == {"unlocked": True}


# ---------------------------------------------------------------------------
# PDF upload support -- extends the original UTF-8-only upload path
# (client/textextract.py). Real bytes stored and returned exactly as
# uploaded; extracted text is searchable exactly like a .txt file's
# content always was; a new /download route hands back the original
# bytes as a real file response instead of JSON.
# ---------------------------------------------------------------------------

class TestPdfUpload:
    def test_upload_valid_pdf_succeeds(self, app_client):
        _unlock(app_client)
        pdf_bytes = _make_minimal_pdf("quarterly board minutes")
        resp = _upload_bytes(app_client, "minutes.pdf", pdf_bytes)
        assert resp.status_code == 201
        assert resp.get_json()["filename"] == "minutes.pdf"

    def test_uploaded_pdf_text_is_searchable(self, app_client):
        _unlock(app_client)
        pdf_bytes = _make_minimal_pdf("boardroomkeyword tokentwo")
        upload_resp = _upload_bytes(app_client, "minutes.pdf", pdf_bytes)
        doc_id = upload_resp.get_json()["doc_id"]

        search_resp = app_client.post("/api/search", json={"query": "boardroomkeyword"})
        assert search_resp.status_code == 200
        results = search_resp.get_json()["results"]
        assert [r["doc_id"] for r in results] == [doc_id]
        assert results[0]["filename"] == "minutes.pdf"

    def test_pdf_and_txt_documents_coexist_and_are_both_searchable(self, app_client):
        # Regression guard: adding PDF support must not disturb the
        # existing plain-text path, and a rebuild must correctly
        # tokenize a mixed corpus of both kinds in one pass.
        _unlock(app_client)
        txt_resp = _upload_bytes(app_client, "notes.txt", b"shared keyword from text")
        pdf_resp = _upload_bytes(app_client, "report.pdf", _make_minimal_pdf("shared keyword from pdf"))

        search_resp = app_client.post("/api/search", json={"query": "shared"})
        doc_ids = {r["doc_id"] for r in search_resp.get_json()["results"]}
        assert doc_ids == {txt_resp.get_json()["doc_id"], pdf_resp.get_json()["doc_id"]}

    def test_get_document_json_hides_pdf_content_but_flags_is_pdf(self, app_client):
        _unlock(app_client)
        upload_resp = _upload_bytes(app_client, "minutes.pdf", _make_minimal_pdf("board minutes"))
        doc_id = upload_resp.get_json()["doc_id"]

        view = app_client.get(f"/api/documents/{doc_id}")
        assert view.status_code == 200
        body = view.get_json()
        assert body["content"] is None
        assert body["is_pdf"] is True

    def test_get_document_json_still_returns_text_content_for_txt(self, app_client):
        # Regression guard on the response shape itself: existing .txt
        # behaviour (content present, is_pdf false) must be unchanged.
        _unlock(app_client)
        upload_resp = _upload(app_client, "notes.txt", "hello world")
        doc_id = upload_resp.get_json()["doc_id"]

        view = app_client.get(f"/api/documents/{doc_id}")
        body = view.get_json()
        assert body["content"] == "hello world"
        assert body["is_pdf"] is False

    def test_download_route_returns_original_pdf_bytes_exactly(self, app_client):
        _unlock(app_client)
        pdf_bytes = _make_minimal_pdf("byte-for-byte round trip")
        upload_resp = _upload_bytes(app_client, "minutes.pdf", pdf_bytes)
        doc_id = upload_resp.get_json()["doc_id"]

        resp = app_client.get(f"/api/documents/{doc_id}/download")
        assert resp.status_code == 200
        assert resp.data == pdf_bytes
        assert resp.mimetype == "application/pdf"
        assert "minutes.pdf" in resp.headers["Content-Disposition"]

    def test_download_route_works_for_txt_too(self, app_client):
        _unlock(app_client)
        upload_resp = _upload(app_client, "notes.txt", "hello world")
        doc_id = upload_resp.get_json()["doc_id"]

        resp = app_client.get(f"/api/documents/{doc_id}/download")
        assert resp.status_code == 200
        assert resp.data == b"hello world"
        assert resp.mimetype == "text/plain"

    def test_download_route_requires_unlock(self, app_client):
        # Explicit lock rather than relying on a fresh-locked default:
        # _current_keys is a module-wide global (by design -- see
        # client_app.py's module docstring), so it can carry over from
        # whatever the previous test in this same run left unlocked.
        app_client.post("/api/lock")
        assert app_client.get("/api/documents/whatever/download").status_code == 401

    def test_download_route_nonexistent_document_returns_404(self, app_client):
        _unlock(app_client)
        resp = app_client.get("/api/documents/does-not-exist/download")
        assert resp.status_code == 404

    def test_upload_corrupted_pdf_bytes_is_rejected_not_silently_indexed(self, app_client):
        # Starts with the real PDF magic bytes but is not a parseable
        # PDF body -- must be rejected with 400, exactly like any other
        # unsupported binary, never silently stored with zero keywords.
        _unlock(app_client)
        resp = _upload_bytes(app_client, "broken.pdf", b"%PDF-1.4\nnot actually a valid pdf body")
        assert resp.status_code == 400
        assert "unsupported file type" in resp.get_json()["error"].lower()

    def test_upload_pdf_with_no_text_layer_succeeds_but_is_not_searchable(self, app_client):
        # A scanned-image PDF with no OCR text layer is a legitimate
        # upload (like an empty .txt file), just findable by nothing.
        _unlock(app_client)
        resp = _upload_bytes(app_client, "scanned.pdf", _make_minimal_pdf(""))
        assert resp.status_code == 201

        search_resp = app_client.post("/api/search", json={"query": "anything"})
        assert search_resp.get_json()["results"] == []

    def test_non_pdf_binary_upload_is_still_rejected(self, app_client):
        # Original UTF-8-only behaviour, preserved: arbitrary binary
        # that is neither valid UTF-8 nor a PDF is still a 400.
        _unlock(app_client)
        resp = _upload_bytes(app_client, "bad.bin", b"\xff\xfe\x00\x01binary garbage")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Zip upload support -- another extension of client/textextract.py's
# single entry point. A zip stays ONE vault document (not one document
# per file inside it); every file inside it that is UTF-8 or PDF gets
# folded into that one document's searchable text.
# ---------------------------------------------------------------------------

class TestZipUpload:
    def test_upload_valid_zip_succeeds(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({"notes.txt": b"quarterly board minutes"})
        resp = _upload_bytes(app_client, "archive.zip", zip_bytes)
        assert resp.status_code == 201
        assert resp.get_json()["filename"] == "archive.zip"

    def test_zip_content_is_searchable(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({"notes.txt": b"ziparchivekeyword inside"})
        upload_resp = _upload_bytes(app_client, "archive.zip", zip_bytes)
        doc_id = upload_resp.get_json()["doc_id"]

        search_resp = app_client.post("/api/search", json={"query": "ziparchivekeyword"})
        results = search_resp.get_json()["results"]
        assert [r["doc_id"] for r in results] == [doc_id]
        assert results[0]["filename"] == "archive.zip"

    def test_zip_stays_one_document_even_with_multiple_files_inside(self, app_client):
        # The chosen model: one vault document per zip, not one per
        # file inside it -- confirmed by checking the vault list has
        # exactly one entry after uploading a multi-file zip.
        _unlock(app_client)
        zip_bytes = _make_zip({"a.txt": b"alpha", "b.txt": b"beta", "c.txt": b"gamma"})
        _upload_bytes(app_client, "archive.zip", zip_bytes)

        listed = app_client.get("/api/documents").get_json()
        assert len(listed) == 1
        assert listed[0]["filename"] == "archive.zip"

    def test_pdf_inside_zip_is_also_searchable(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({"report.pdf": _make_minimal_pdf("pdfinsidezipkeyword")})
        upload_resp = _upload_bytes(app_client, "archive.zip", zip_bytes)
        doc_id = upload_resp.get_json()["doc_id"]

        search_resp = app_client.post("/api/search", json={"query": "pdfinsidezipkeyword"})
        assert [r["doc_id"] for r in search_resp.get_json()["results"]] == [doc_id]

    def test_unreadable_member_does_not_block_upload_or_the_readable_ones(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({
            "photo.png": b"\xff\xfe\x00\x01not really an image but binary-ish",
            "notes.txt": b"stillfindablekeyword",
        })
        resp = _upload_bytes(app_client, "mixed.zip", zip_bytes)
        assert resp.status_code == 201

        search_resp = app_client.post("/api/search", json={"query": "stillfindablekeyword"})
        assert len(search_resp.get_json()["results"]) == 1

    def test_get_document_json_hides_zip_content_but_flags_is_zip(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({"notes.txt": b"hello"})
        upload_resp = _upload_bytes(app_client, "archive.zip", zip_bytes)
        doc_id = upload_resp.get_json()["doc_id"]

        view = app_client.get(f"/api/documents/{doc_id}")
        body = view.get_json()
        assert body["content"] is None
        assert body["is_zip"] is True
        assert body["is_pdf"] is False

    def test_download_route_returns_original_zip_bytes_exactly(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({"notes.txt": b"byte for byte round trip"})
        upload_resp = _upload_bytes(app_client, "archive.zip", zip_bytes)
        doc_id = upload_resp.get_json()["doc_id"]

        resp = app_client.get(f"/api/documents/{doc_id}/download")
        assert resp.status_code == 200
        assert resp.data == zip_bytes
        assert resp.mimetype == "application/zip"
        assert "archive.zip" in resp.headers["Content-Disposition"]

    def test_office_document_disguised_as_zip_is_rejected(self, app_client):
        _unlock(app_client)
        fake_docx = _make_zip({
            "[Content_Types].xml": b"<Types xmlns='http://example/content-types'/>",
            "word/document.xml": b"<w:document>hello</w:document>",
        })
        resp = _upload_bytes(app_client, "report.docx", fake_docx)
        assert resp.status_code == 400

    def test_nested_zip_is_uploaded_but_its_contents_are_not_searchable(self, app_client):
        # Deliberate, documented limit (zip-bomb defence): exactly one
        # level of archive expansion. The outer zip still uploads
        # (it's a valid zip with at least the inner zip as a member,
        # which itself just isn't readable) -- it just doesn't index
        # whatever text is inside the nested archive.
        _unlock(app_client)
        inner_zip = _make_zip({"secret.txt": b"nestedzipkeyword"})
        outer_zip = _make_zip({"inner.zip": inner_zip, "outer.txt": b"outerzipkeyword"})
        resp = _upload_bytes(app_client, "nested.zip", outer_zip)
        assert resp.status_code == 201

        outer_hit = app_client.post("/api/search", json={"query": "outerzipkeyword"})
        assert len(outer_hit.get_json()["results"]) == 1

        inner_hit = app_client.post("/api/search", json={"query": "nestedzipkeyword"})
        assert inner_hit.get_json()["results"] == []

    def test_zip_of_only_unreadable_members_still_uploads_but_is_not_searchable(self, app_client):
        _unlock(app_client)
        zip_bytes = _make_zip({"photo.png": b"\xff\xfe\x00\x01binary garbage"})
        resp = _upload_bytes(app_client, "photos.zip", zip_bytes)
        assert resp.status_code == 201

        search_resp = app_client.post("/api/search", json={"query": "anything"})
        assert search_resp.get_json()["results"] == []

    def test_zip_shaped_but_invalid_bytes_are_rejected(self, app_client):
        # Starts with the real zip local-file-header magic but has no
        # valid end-of-central-directory record, so is_zip() correctly
        # says False (see test_textextract.py's own test of that same
        # case) -- and these particular bytes also aren't valid UTF-8,
        # so the upload falls through every supported format and is
        # rejected, exactly like any other unsupported binary would be.
        _unlock(app_client)
        resp = _upload_bytes(app_client, "broken.zip", b"PK\x03\x04\xff\xfe\x00\x01not a real zip body")
        assert resp.status_code == 400
