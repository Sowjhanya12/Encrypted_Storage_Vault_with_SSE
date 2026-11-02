"""
tests/test_multiuser_security.py -- the multi-user extension: accounts,
sessions, CSRF, role-based access control, cross-user isolation, the
administrator's no-plaintext guarantee, and the demonstration features
(transparency lab, cloud inspector, search trace, tamper test).

Runs against the same live two-process topology as test_client_app.py:
a real cloud_app.py on its own port, driven by client_app.py making real
HTTP calls. Raw-database checks read the cloud's actual SQLite file.
"""

import base64
import io
import os
import sqlite3
import sys
import time
from contextlib import contextmanager

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from conftest import login_test_client, make_client_app  # noqa: E402

VAULT_PW = "alice vault passphrase"
SECRET_TEXT = "quarterly zephyrion merger plan confidential"
SECRET_NAME = "merger-plan.txt"


@contextmanager
def _client(app):
    # Several users are active at once in these tests, so clients must
    # not preserve request contexts (`with app.test_client()` does).
    yield app.test_client()


def _db(tmp_path):
    (path,) = list(tmp_path.glob("**/cloud_vault.sqlite3"))
    return str(path)


def _upload(c, filename=SECRET_NAME, content=SECRET_TEXT):
    data = {"file": (io.BytesIO(content.encode("utf-8")), filename)}
    return c.post("/api/documents", data=data, content_type="multipart/form-data")


@pytest.fixture
def app(live_cloud, tmp_path):
    return make_client_app(tmp_path)


@pytest.fixture
def alice(app):
    with _client(app) as c:
        login_test_client(c, "alice", "alice-account-pw")
        yield c


@pytest.fixture
def bob(app):
    with _client(app) as c:
        login_test_client(c, "bob", "bob-account-pw")
        yield c


@pytest.fixture
def admin(app):
    with _client(app) as c:
        resp = c.post("/api/setup/admin", json={
            "setup_token": "test-setup-token", "username": "root-admin", "password": "admin-account-pw",
        })
        assert resp.status_code == 201
        login_test_client(c, "root-admin", "admin-account-pw", register=False)
        yield c


@pytest.fixture
def alice_with_doc(alice):
    assert alice.post("/api/unlock", json={"password": VAULT_PW}).status_code == 200
    resp = _upload(alice)
    assert resp.status_code == 201
    return alice, resp.get_json()["doc_id"]


# ---------------------------------------------------------------------------
# registration, login, logout
# ---------------------------------------------------------------------------

class TestRegistrationAndLogin:
    def test_register_login_and_session_info(self, app):
        with _client(app) as c:
            data = login_test_client(c, "carol", "carol-account-pw")
            assert data["authenticated"] is True
            assert data["user"]["username"] == "carol"
            assert data["user"]["role"] == "user"
            assert data["unlocked"] is False
            assert c.get("/api/session").get_json()["user"]["username"] == "carol"

    def test_account_password_is_stored_only_as_argon2id_hash(self, app, tmp_path):
        with _client(app) as c:
            login_test_client(c, "carol", "very-distinctive-pw-123")
        raw = (tmp_path / "client_accounts.sqlite3").read_bytes()
        assert b"very-distinctive-pw-123" not in raw
        conn = sqlite3.connect(str(tmp_path / "client_accounts.sqlite3"))
        (hash_,) = conn.execute("SELECT password_hash FROM users WHERE username='carol'").fetchone()
        conn.close()
        assert hash_.startswith("$argon2id$")

    @pytest.mark.parametrize("body,status", [
        ({"username": "ab", "password": "long-enough-pw"}, 400),
        ({"username": "bad name!", "password": "long-enough-pw"}, 400),
        ({"username": "dave", "password": "short"}, 400),
        ({"username": "dave"}, 400),
        ({"username": 123, "password": "long-enough-pw"}, 400),
    ])
    def test_register_rejects_invalid_input(self, app, body, status):
        with _client(app) as c:
            assert c.post("/api/auth/register", json=body).status_code == status

    def test_duplicate_username_rejected_case_insensitively(self, app):
        with _client(app) as c:
            assert c.post("/api/auth/register", json={"username": "erin", "password": "erin-account-pw"}).status_code == 201
            assert c.post("/api/auth/register", json={"username": "ERIN", "password": "other-account-pw"}).status_code == 409

    def test_wrong_password_and_unknown_user_give_the_same_401(self, app):
        with _client(app) as c:
            c.post("/api/auth/register", json={"username": "frank", "password": "frank-account-pw"})
            wrong = c.post("/api/auth/login", json={"username": "frank", "password": "nope-nope-nope"})
            unknown = c.post("/api/auth/login", json={"username": "nobody", "password": "nope-nope-nope"})
            assert wrong.status_code == unknown.status_code == 401
            assert wrong.get_json() == unknown.get_json()

    def test_repeated_failures_are_throttled(self, app):
        with _client(app) as c:
            c.post("/api/auth/register", json={"username": "gina", "password": "gina-account-pw"})
            for _ in range(5):
                assert c.post("/api/auth/login", json={"username": "gina", "password": "wrong-password"}).status_code == 401
            # even the CORRECT password is refused while throttled
            assert c.post("/api/auth/login", json={"username": "gina", "password": "gina-account-pw"}).status_code == 429

    def test_logout_ends_session_and_wipes_vault_keys(self, alice, app):
        alice.post("/api/unlock", json={"password": VAULT_PW})
        assert len(app.extensions["vault_sessions"].unlocked_sessions()) == 1
        assert alice.post("/api/auth/logout").status_code == 200
        assert app.extensions["vault_sessions"].unlocked_sessions() == []
        assert alice.get("/api/documents").status_code == 401
        assert alice.get("/api/session").get_json()["authenticated"] is False

    def test_login_issues_a_fresh_session_id(self, app):
        with _client(app) as c:
            login_test_client(c, "hank", "hank-account-pw")
            first = c.get_cookie("vault_sid").value
            login_test_client(c, "hank", "hank-account-pw", register=False)
            second = c.get_cookie("vault_sid").value
            assert first != second
            assert app.extensions["vault_sessions"].active_count() == 1

    def test_session_cookie_flags(self, app):
        with _client(app) as c:
            c.post("/api/auth/register", json={"username": "ivan", "password": "ivan-account-pw"})
            resp = c.post("/api/auth/login", json={"username": "ivan", "password": "ivan-account-pw"})
            cookie = resp.headers["Set-Cookie"]
            assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
            # the cookie is only an opaque id -- no user data or keys
            assert "ivan" not in cookie


class TestSessionExpiry:
    def test_idle_session_expires_and_locks_the_vault(self, live_cloud, tmp_path):
        app = make_client_app(tmp_path, SESSION_IDLE_SECONDS=1)
        with _client(app) as c:
            login_test_client(c, "judy", "judy-account-pw")
            assert c.post("/api/unlock", json={"password": VAULT_PW}).status_code == 200
            time.sleep(1.3)
            assert c.get("/api/documents").status_code == 401
            assert app.extensions["vault_sessions"].unlocked_sessions() == []
        events = app.extensions["vault_accounts"].list_events(event_type="session_expired")
        assert events and events[0]["actor_username"] == "judy"

    def test_absolute_lifetime_is_enforced(self, live_cloud, tmp_path):
        app = make_client_app(tmp_path, SESSION_ABSOLUTE_SECONDS=1)
        with _client(app) as c:
            login_test_client(c, "kim", "kim-account-pw")
            time.sleep(1.3)
            assert c.get("/api/session").get_json()["authenticated"] is False


class TestCsrf:
    def test_state_change_without_csrf_header_is_refused(self, alice):
        del alice.environ_base["HTTP_X_CSRF_TOKEN"]
        assert alice.post("/api/unlock", json={"password": VAULT_PW}).status_code == 403
        assert _upload(alice).status_code == 403

    def test_wrong_csrf_token_is_refused(self, alice):
        alice.environ_base["HTTP_X_CSRF_TOKEN"] = "forged"
        assert alice.post("/api/unlock", json={"password": VAULT_PW}).status_code == 403

    def test_login_requires_json_and_same_origin(self, app):
        with _client(app) as c:
            c.post("/api/auth/register", json={"username": "leo", "password": "leo-account-pw"})
            form = c.post("/api/auth/login", data={"username": "leo", "password": "leo-account-pw"})
            assert form.status_code == 415
            foreign = c.post(
                "/api/auth/login", json={"username": "leo", "password": "leo-account-pw"},
                headers={"Origin": "http://evil.example"},
            )
            assert foreign.status_code == 403

    def test_anonymous_state_change_is_refused(self, app):
        with _client(app) as c:
            assert c.post("/api/unlock", json={"password": VAULT_PW}).status_code == 401
            assert c.post("/api/auth/logout").status_code == 401


# ---------------------------------------------------------------------------
# role-based access control
# ---------------------------------------------------------------------------

ADMIN_GETS = ["/api/admin/overview", "/api/admin/users", "/api/admin/audit", "/api/admin/inspector"]


class TestRoleBasedAccess:
    @pytest.mark.parametrize("path", ADMIN_GETS)
    def test_regular_user_cannot_reach_admin_endpoints(self, alice, path):
        assert alice.get(path).status_code == 403

    def test_regular_user_cannot_change_account_status(self, alice, bob, app):
        bob_id = app.extensions["vault_accounts"].get_user_by_username("bob").id
        assert alice.post(f"/api/admin/users/{bob_id}/status", json={"active": False}).status_code == 403
        assert app.extensions["vault_accounts"].get_user(bob_id).is_active

    @pytest.mark.parametrize("path", ADMIN_GETS)
    def test_anonymous_cannot_reach_admin_endpoints(self, app, path):
        with _client(app) as c:
            assert c.get(path).status_code == 401

    def test_denied_admin_access_is_audited(self, alice, app):
        alice.get("/api/admin/users")
        events = app.extensions["vault_accounts"].list_events(event_type="access_denied")
        assert events and events[0]["actor_username"] == "alice"

    def test_admin_has_no_vault_operations(self, admin):
        assert admin.post("/api/unlock", json={"password": "anything-at-all"}).status_code == 403
        assert admin.get("/api/documents").status_code == 403
        assert _upload(admin).status_code == 403
        assert admin.post("/api/search", json={"query": "merger"}).status_code == 403
        assert admin.get("/api/inspector").status_code == 403

    def test_admin_endpoints_work_for_admin(self, admin):
        for path in ADMIN_GETS:
            assert admin.get(path).status_code == 200, path


class TestAdminBootstrap:
    def test_wrong_setup_token_is_refused(self, app):
        with _client(app) as c:
            resp = c.post("/api/setup/admin", json={"setup_token": "guess", "username": "x-admin", "password": "admin-account-pw"})
            assert resp.status_code == 403
        assert not app.extensions["vault_accounts"].admin_exists()

    def test_setup_is_one_time_only(self, admin, app):
        with _client(app) as c:
            resp = c.post("/api/setup/admin", json={
                "setup_token": "test-setup-token", "username": "second-admin", "password": "admin-account-pw",
            })
            assert resp.status_code == 409

    def test_no_admin_exists_by_default(self, app):
        assert not app.extensions["vault_accounts"].admin_exists()
        with _client(app) as c:
            assert c.get("/api/setup/status").get_json() == {"admin_exists": False}

    def test_registration_never_grants_admin(self, app):
        with _client(app) as c:
            c.post("/api/auth/register", json={"username": "mallory", "password": "mallory-pw-123", "role": "admin"})
            data = login_test_client(c, "mallory", "mallory-pw-123", register=False)
            assert data["user"]["role"] == "user"


class TestAccountAdministration:
    def test_deactivation_blocks_login_and_ends_live_sessions(self, admin, alice, app):
        alice.post("/api/unlock", json={"password": VAULT_PW})
        alice_id = app.extensions["vault_accounts"].get_user_by_username("alice").id
        resp = admin.post(f"/api/admin/users/{alice_id}/status", json={"active": False})
        assert resp.status_code == 200 and resp.get_json()["sessions_ended"] == 1
        assert alice.get("/api/documents").status_code == 401
        assert app.extensions["vault_sessions"].unlocked_sessions() == []
        with _client(app) as c:
            assert c.post("/api/auth/login", json={"username": "alice", "password": "alice-account-pw"}).status_code == 403
        assert admin.post(f"/api/admin/users/{alice_id}/status", json={"active": True}).status_code == 200
        with _client(app) as c:
            assert c.post("/api/auth/login", json={"username": "alice", "password": "alice-account-pw"}).status_code == 200

    def test_admin_cannot_deactivate_self(self, admin, app):
        me = app.extensions["vault_accounts"].get_user_by_username("root-admin").id
        assert admin.post(f"/api/admin/users/{me}/status", json={"active": False}).status_code == 400

    def test_status_change_validates_input(self, admin, app):
        assert admin.post("/api/admin/users/99999/status", json={"active": False}).status_code == 404
        assert admin.post("/api/admin/users/1/status", json={"active": "no"}).status_code == 400


# ---------------------------------------------------------------------------
# cross-user isolation
# ---------------------------------------------------------------------------

class TestCrossUserIsolation:
    def test_other_user_cannot_list_read_download_or_delete(self, alice_with_doc, bob):
        _, doc_id = alice_with_doc
        assert bob.post("/api/unlock", json={"password": "bob vault passphrase"}).status_code == 200
        assert bob.get("/api/documents").get_json() == []
        assert bob.get(f"/api/documents/{doc_id}").status_code == 404
        assert bob.get(f"/api/documents/{doc_id}/download").status_code == 404
        assert bob.get(f"/api/transparency/{doc_id}").status_code == 404
        assert bob.post("/api/tamper-demo", json={"doc_id": doc_id}).status_code == 404
        assert bob.delete(f"/api/documents/{doc_id}").status_code == 404
        search = bob.post("/api/search", json={"query": "zephyrion"}).get_json()
        assert search["results"] == []

    def test_owner_still_has_the_document_after_attempted_cross_user_delete(self, alice_with_doc, bob):
        alice, doc_id = alice_with_doc
        bob.post("/api/unlock", json={"password": "bob vault passphrase"})
        bob.delete(f"/api/documents/{doc_id}")
        assert alice.get(f"/api/documents/{doc_id}").get_json()["content"] == SECRET_TEXT

    def test_same_passphrase_still_yields_independent_vault_keys(self, alice, bob, app, tmp_path):
        alice.post("/api/unlock", json={"password": "shared passphrase"})
        bob.post("/api/unlock", json={"password": "shared passphrase"})
        keysets = [s.keys for s in app.extensions["vault_sessions"].unlocked_sessions()]
        assert len(keysets) == 2
        assert keysets[0].k_file != keysets[1].k_file
        assert keysets[0].k_index != keysets[1].k_index
        conn = sqlite3.connect(_db(tmp_path))
        salts = [r[0] for r in conn.execute("SELECT value FROM meta WHERE key='kdf_salt'")]
        conn.close()
        assert len(salts) == 2 and salts[0] != salts[1]

    def test_cloud_rejects_wrong_vault_token(self, alice_with_doc, bob, app, live_cloud):
        import requests

        accounts = app.extensions["vault_accounts"]
        a, b = accounts.get_user_by_username("alice"), accounts.get_user_by_username("bob")
        _, doc_id = alice_with_doc
        hdr = lambda vid, tok: {"X-Vault-Id": vid, "Authorization": "Bearer " + base64.b64encode(tok).decode()}
        assert requests.get(f"{live_cloud}/documents", headers=hdr(a.vault_id, b.cloud_token), timeout=5).status_code == 401
        assert requests.get(f"{live_cloud}/documents", headers={"X-Vault-Id": a.vault_id}, timeout=5).status_code == 401
        # Bob's own valid credentials cannot see Alice's document id
        assert requests.get(f"{live_cloud}/documents/{doc_id}", headers=hdr(b.vault_id, b.cloud_token), timeout=5).status_code == 404
        # nor can an unauthenticated (legacy-namespace) request
        assert requests.get(f"{live_cloud}/documents/{doc_id}", timeout=5).status_code == 404
        ok = requests.get(f"{live_cloud}/documents/{doc_id}", headers=hdr(a.vault_id, a.cloud_token), timeout=5)
        assert ok.status_code == 200

    def test_cloud_vault_cannot_be_re_registered(self, alice, app, live_cloud):
        import requests

        a = app.extensions["vault_accounts"].get_user_by_username("alice")
        resp = requests.post(f"{live_cloud}/vaults", json={
            "vault_id": a.vault_id, "token": base64.b64encode(os.urandom(32)).decode(),
        }, timeout=5)
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# administrator sees metadata, never plaintext or keys
# ---------------------------------------------------------------------------

class TestAdminNeverSeesPlaintext:
    def test_admin_views_contain_no_plaintext_filenames_keywords_or_keys(self, alice_with_doc, admin, app):
        alice, doc_id = alice_with_doc
        alice.post("/api/search", json={"query": "zephyrion merger"})
        keys = app.extensions["vault_sessions"].unlocked_sessions()[0].keys
        alice_id = app.extensions["vault_accounts"].get_user_by_username("alice").id

        bodies = [admin.get(p).get_data(as_text=True) for p in ADMIN_GETS]
        bodies.append(admin.get(f"/api/admin/inspector?user_id={alice_id}").get_data(as_text=True))
        inspected = admin.get(f"/api/admin/inspector?user_id={alice_id}").get_json()
        assert inspected["documents"][0]["doc_id"] == doc_id  # it really sees the record...
        for body in bodies:
            for secret in ("zephyrion", "merger", SECRET_NAME, VAULT_PW, "alice-account-pw"):
                assert secret not in body
            for key in (keys.k_file, keys.k_index):
                assert key.hex() not in body
                assert base64.b64encode(key).decode() not in body

    def test_admin_storage_totals_match_the_cloud_database(self, alice_with_doc, admin, tmp_path):
        overview = admin.get("/api/admin/overview").get_json()
        conn = sqlite3.connect(_db(tmp_path))
        docs, size = conn.execute("SELECT COUNT(*), SUM(size) FROM documents").fetchone()
        idx = conn.execute("SELECT COUNT(*) FROM sse_index").fetchone()[0]
        conn.close()
        assert overview["storage"]["documents"] == docs == 1
        assert overview["storage"]["ciphertext_bytes"] == size
        assert overview["storage"]["index_entries"] == idx

    def test_audit_log_records_events_without_sensitive_values(self, alice_with_doc, admin, app, tmp_path):
        alice, doc_id = alice_with_doc
        alice.post("/api/search", json={"query": "zephyrion"})
        alice.get(f"/api/documents/{doc_id}/download")
        with _client(app) as c:
            c.post("/api/auth/login", json={"username": "alice", "password": "wrong-password"})
        types = {e["event_type"] for e in admin.get("/api/admin/audit").get_json()["events"]}
        assert {"register", "login", "vault_initialized", "vault_unlock", "upload", "search",
                "download", "login_failed"} <= types
        raw = (tmp_path / "client_accounts.sqlite3").read_bytes()
        for secret in (b"zephyrion", SECRET_NAME.encode(), VAULT_PW.encode(), b"wrong-password", b"alice-account-pw"):
            assert secret not in raw


# ---------------------------------------------------------------------------
# encryption transparency, inspector, search trace, tamper demo
# ---------------------------------------------------------------------------

class TestTransparencyLab:
    def test_both_sides_are_real_and_match_the_cloud_database(self, alice_with_doc, tmp_path):
        alice, doc_id = alice_with_doc
        data = alice.get(f"/api/transparency/{doc_id}").get_json()
        assert data["client"]["filename"] == SECRET_NAME
        assert data["client"]["text_preview"] == SECRET_TEXT
        assert data["client"]["size_bytes"] == len(SECRET_TEXT.encode())

        conn = sqlite3.connect(_db(tmp_path))
        enc_name, nonce, ct, tag, size = conn.execute(
            "SELECT enc_name, nonce, ciphertext, tag, size FROM documents WHERE doc_id = ?", (doc_id,)
        ).fetchone()
        conn.close()
        cloud = data["cloud"]
        assert cloud["content"]["nonce_hex"] == nonce.hex()
        assert cloud["content"]["tag_hex"] == tag.hex()
        assert cloud["content"]["ciphertext_hex"] == ct[:512].hex()
        assert cloud["content"]["ciphertext_bytes"] == len(ct) == size
        assert cloud["enc_name"]["nonce_hex"] == enc_name[:12].hex()
        assert cloud["enc_name"]["tag_hex"] == enc_name[-16:].hex()
        # GCM: ciphertext length == plaintext length; +28 bytes overhead
        assert data["comparison"]["ciphertext_bytes"] == data["comparison"]["plaintext_bytes"]
        assert data["comparison"]["overhead_bytes"] == 28
        assert data["comparison"]["plaintext_prefix_found_in_ciphertext"] is False
        assert SECRET_TEXT.encode().hex() not in cloud["content"]["ciphertext_hex"]

    def test_requires_unlock(self, alice_with_doc):
        alice, doc_id = alice_with_doc
        alice.post("/api/lock")
        assert alice.get(f"/api/transparency/{doc_id}").status_code == 401

    def test_tampered_record_reports_decryption_failure(self, alice_with_doc, tmp_path, app):
        alice, doc_id = alice_with_doc
        conn = sqlite3.connect(_db(tmp_path))
        (ct,) = conn.execute("SELECT ciphertext FROM documents WHERE doc_id=?", (doc_id,)).fetchone()
        conn.execute("UPDATE documents SET ciphertext=? WHERE doc_id=?", (bytes([ct[0] ^ 1]) + ct[1:], doc_id))
        conn.commit()
        conn.close()
        assert alice.get(f"/api/transparency/{doc_id}").status_code == 422
        assert app.extensions["vault_accounts"].list_events(event_type="decryption_failed")


class TestCloudInspector:
    def test_shows_ciphertext_but_never_plaintext(self, alice_with_doc, tmp_path):
        alice, doc_id = alice_with_doc
        alice.post("/api/lock")  # works while locked: no key needed
        resp = alice.get("/api/inspector")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert SECRET_NAME not in body and "zephyrion" not in body
        data = resp.get_json()
        assert [d["doc_id"] for d in data["documents"]] == [doc_id]
        conn = sqlite3.connect(_db(tmp_path))
        idx = conn.execute("SELECT COUNT(*) FROM sse_index").fetchone()[0]
        conn.close()
        assert data["index"]["total"] == idx == data["stats"]["index_entries"]
        assert set(data["stats"]["meta_keys"]) == {"kdf_salt", "kdf_verifier"}


class TestSearchTrace:
    def test_trace_token_is_exactly_what_the_cloud_received(self, alice_with_doc, wire_log):
        alice, doc_id = alice_with_doc
        data = alice.post("/api/search", json={"query": "zephyrion merger"}).get_json()
        assert [r["doc_id"] for r in data["results"]] == [doc_id]
        sent = [e["request_json"]["k1"] for e in wire_log if e["path"] == "/search"]
        traced = [s["cloud_request"]["body"]["k1"] for s in data["trace"]["steps"]]
        assert traced == sent and len(sent) == 2
        for e in wire_log:
            if e["path"] == "/search":
                assert "zephyrion" not in str(e["request_json"]) and "merger" not in str(e["request_json"])
        assert all(s["decrypted_doc_ids"] == [doc_id] for s in data["trace"]["steps"])


class TestTamperDemo:
    @pytest.mark.parametrize("region", ["nonce", "ciphertext", "tag"])
    def test_flipped_bit_is_rejected_and_stored_record_is_untouched(self, alice_with_doc, tmp_path, region):
        alice, doc_id = alice_with_doc
        conn = sqlite3.connect(_db(tmp_path))
        before = conn.execute("SELECT enc_name, nonce, ciphertext, tag FROM documents WHERE doc_id=?", (doc_id,)).fetchone()
        conn.close()
        data = alice.post("/api/tamper-demo", json={"doc_id": doc_id, "region": region}).get_json()
        assert data["baseline_decrypt"]["ok"] is True
        assert data["tampered_decrypt"]["rejected"] is True
        assert data["tampered_decrypt"]["underlying"] == "InvalidTag"
        assert data["original_byte"] != data["modified_byte"]
        assert data["original_unchanged_in_cloud"] is True
        conn = sqlite3.connect(_db(tmp_path))
        after = conn.execute("SELECT enc_name, nonce, ciphertext, tag FROM documents WHERE doc_id=?", (doc_id,)).fetchone()
        conn.close()
        assert before == after
        assert alice.get(f"/api/documents/{doc_id}").get_json()["content"] == SECRET_TEXT

    def test_sample_mode_needs_no_stored_document(self, alice):
        alice.post("/api/unlock", json={"password": VAULT_PW})
        data = alice.post("/api/tamper-demo", json={"region": "tag", "offset": 0, "bit": 7}).get_json()
        assert data["tampered_decrypt"]["rejected"] is True
        assert data["original_unchanged_in_cloud"] is None
        assert data["offset_in_region"] == 0 and data["bit"] == 7

    def test_is_logged_as_a_demo_event(self, alice_with_doc, app):
        alice, doc_id = alice_with_doc
        alice.post("/api/tamper-demo", json={"doc_id": doc_id})
        (event,) = app.extensions["vault_accounts"].list_events(event_type="tamper_demo")
        assert event["is_demo"] is True and event["outcome"] == "rejected"

    @pytest.mark.parametrize("body", [
        {"region": "header"}, {"region": "tag", "offset": 16}, {"region": "tag", "bit": 8}, {"doc_id": 5},
    ])
    def test_invalid_input_is_rejected(self, alice, body):
        alice.post("/api/unlock", json={"password": VAULT_PW})
        assert alice.post("/api/tamper-demo", json=body).status_code == 400


class TestDashboardAndActivity:
    def test_counts_come_from_real_events(self, alice_with_doc):
        alice, doc_id = alice_with_doc
        alice.post("/api/search", json={"query": "zephyrion"})
        alice.post("/api/search", json={"query": "merger"})
        alice.get(f"/api/documents/{doc_id}/download")
        d = alice.get("/api/dashboard").get_json()
        assert d["counts"]["uploads"] == 1
        assert d["counts"]["searches"] == 2
        assert d["counts"]["downloads"] == 1
        assert d["storage"]["documents"] == 1
        assert d["recent_uploads"][0]["filename"] == SECRET_NAME

    def test_activity_is_only_the_users_own(self, alice_with_doc, bob):
        bob_events = bob.get("/api/activity").get_json()["events"]
        assert bob_events and all(e["actor_username"] == "bob" for e in bob_events)


# ---------------------------------------------------------------------------
# legacy data migration
# ---------------------------------------------------------------------------

_OLD_SCHEMA = """
CREATE TABLE documents (doc_id TEXT PRIMARY KEY, enc_name BLOB NOT NULL, nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL, tag BLOB NOT NULL, size INTEGER NOT NULL,
  uploaded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));
CREATE TABLE sse_index (label TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
"""


class TestSchemaMigration:
    def test_pre_multiuser_database_is_migrated_without_data_loss(self, tmp_path):
        from cloud import storage

        path = tmp_path / "old.sqlite3"
        conn = sqlite3.connect(str(path))
        conn.executescript(_OLD_SCHEMA)
        conn.execute("INSERT INTO documents (doc_id, enc_name, nonce, ciphertext, tag, size) VALUES (?,?,?,?,?,?)",
                     ("d1", b"N" * 40, b"n" * 12, b"c" * 50, b"t" * 16, 50))
        conn.execute("INSERT INTO sse_index VALUES (?, ?)", ("aa" * 32, b"v" * 40))
        conn.execute("INSERT INTO meta VALUES (?, ?)", ("kdf_salt", b"s" * 16))
        conn.commit()
        conn.close()

        conn = storage.connect(path)
        try:
            assert storage.get_document(conn, "d1")["ciphertext"] == b"c" * 50
            assert storage.get_index_entry(conn, "aa" * 32) == b"v" * 40
            assert storage.get_meta(conn, "kdf_salt") == b"s" * 16
            assert conn.execute("PRAGMA user_version").fetchone()[0] == storage.SCHEMA_VERSION
            # a second vault can now hold the same meta key independently
            storage.set_meta(conn, "kdf_salt", b"x" * 16, vault_id="ab")
            assert storage.get_meta(conn, "kdf_salt") == b"s" * 16
        finally:
            conn.close()
        storage.connect(path).close()  # idempotent

    def test_legacy_vault_can_be_adopted_by_a_new_account(self, alice, live_cloud):
        import client.cloud_client as cc
        from client.client_app import _split_blob
        from client.crypto import aes_gcm_encrypt
        from client.keymgmt import generate_salt, unlock as derive_keys

        # Build a legacy (unscoped) vault exactly as the original app did.
        salt = generate_salt()
        keys = derive_keys("legacy passphrase", salt)
        cc.set_vault_scope(None)
        cc.set_meta("kdf_salt", salt)
        cc.set_meta("kdf_verifier", aes_gcm_encrypt(keys.k_index, b"vault-verifier:v1"))
        n, c, t = _split_blob(aes_gcm_encrypt(keys.k_file, b"legacy file body"))
        cc.push_document("0" * 32, aes_gcm_encrypt(keys.k_file, b"legacy.txt"), n, c, t)

        assert alice.get("/api/vault/legacy").get_json() == {"available": True, "documents": 1}
        assert alice.post("/api/vault/adopt-legacy", json={"password": "wrong"}).status_code == 401
        resp = alice.post("/api/vault/adopt-legacy", json={"password": "legacy passphrase"})
        assert resp.status_code == 200 and resp.get_json()["moved"]["documents"] == 1
        assert alice.post("/api/unlock", json={"password": "legacy passphrase"}).status_code == 200
        assert [d["filename"] for d in alice.get("/api/documents").get_json()] == ["legacy.txt"]
        # legacy namespace is now empty; a second adoption has nothing to take
        assert alice.get("/api/vault/legacy").get_json() == {"available": False}


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_unknown_api_route_returns_json_404(self, alice):
        resp = alice.get("/api/does-not-exist")
        assert resp.status_code == 404 and "error" in resp.get_json()

    def test_cloud_outage_is_a_clean_502(self, alice, monkeypatch):
        import client.cloud_client as cc

        monkeypatch.setattr(cc, "CLOUD_BASE_URL", "http://127.0.0.1:1")
        resp = alice.get("/api/inspector")
        assert resp.status_code == 502
        assert "Traceback" not in resp.get_data(as_text=True)

    def test_oversized_upload_is_rejected(self, live_cloud, tmp_path):
        app = make_client_app(tmp_path, MAX_CONTENT_LENGTH=1024)
        with _client(app) as c:
            login_test_client(c, "nina", "nina-account-pw")
            c.post("/api/unlock", json={"password": VAULT_PW})
            assert _upload(c, "big.txt", "x" * 5000).status_code == 413

    def test_download_filename_cannot_inject_headers(self, alice):
        alice.post("/api/unlock", json={"password": VAULT_PW})
        doc_id = _upload(alice, 'evil"\r\nX-Injected: 1.txt', "header injection test").get_json()["doc_id"]
        resp = alice.get(f"/api/documents/{doc_id}/download")
        assert resp.status_code == 200
        assert "X-Injected" not in resp.headers
        assert "\n" not in resp.headers["Content-Disposition"]

    def test_api_responses_are_not_cacheable(self, alice):
        assert alice.get("/api/session").headers["Cache-Control"] == "no-store"
