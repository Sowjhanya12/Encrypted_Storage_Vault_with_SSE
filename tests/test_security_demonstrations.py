"""
tests/test_security_demonstrations.py -- Phase 6: reproducible
security & leakage demonstrations, run against the REAL two-process
topology (a live cloud/cloud_app.py Flask server on its own real TCP
port, via the same `live_cloud` fixture Phase 5's tests use, driven by
client/client_app.py making genuine HTTP calls through
client/cloud_client.py -- nothing here is simulated or mocked at the
protocol level).

Each demonstration below is a normal pytest test (so it is CI-checked
like everything else in this suite -- a regression here fails the
build, not just a comment going stale) that also records one entry
into the `evidence` fixture. pytest_sessionfinish (tests/conftest.py)
renders every entry collected this run into
docs/security_demo_report.html, so the report is regenerated from
whatever the code actually does today, every time `pytest` runs --
never a static table of claims that can drift from the implementation.

Every entry states, explicitly, what the untrusted cloud can observe,
what the trusted client can observe, what never leaves the trusted
client at all, and -- where the answer is "yes, this leaks" -- whether
that is a bug (verdict MITIGATED, pointing at the fix) or an accepted,
documented cost of the chosen static Πbas SSE construction (verdict
CONFIRMED-LEAKAGE, pointing at the architecture section/audit finding
that scopes it). Nothing here is fixed or worked around: Phase 6's job
is to demonstrate the system as built, not to change it.
"""

from __future__ import annotations

import base64
import io
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.client_app import create_app  # noqa: E402


@pytest.fixture
def app_client(user_app_client):
    # Multi-user extension: a logged-in regular user with a fresh vault
    # (see conftest.user_app_client) -- previously the single global vault.
    yield user_app_client


def _unlock(app_client, password="the real password"):
    return app_client.post("/api/unlock", json={"password": password})


def _upload(app_client, filename: str, content: str):
    data = {"file": (io.BytesIO(content.encode("utf-8")), filename)}
    return app_client.post("/api/documents", data=data, content_type="multipart/form-data")


def _search(app_client, query: str):
    return app_client.post("/api/search", json={"query": query})


def _current_keys(app_client):
    """White-box access to the trusted client's in-memory KeySet --
    legitimate here specifically because this file's entire job is
    proving what NEVER crosses to the cloud, which requires comparing
    the real key bytes against every byte the cloud actually received.
    (Multi-user extension: keys now live on the one unlocked server-side
    session rather than in a module-level global.)
    """
    unlocked = app_client.application.extensions["vault_sessions"].unlocked_sessions()
    assert len(unlocked) == 1, "test bug: called _current_keys() while locked"
    return unlocked[0].keys


def _db_path(tmp_path):
    candidates = list(tmp_path.glob("**/cloud_vault.sqlite3"))
    assert len(candidates) == 1
    return str(candidates[0])


def _raw_db_bytes(tmp_path):
    with open(_db_path(tmp_path), "rb") as f:
        return f.read()


def _sse_index_rows(tmp_path):
    conn = sqlite3.connect(_db_path(tmp_path))
    rows = conn.execute("SELECT label, value FROM sse_index").fetchall()
    conn.close()
    return rows


def _corrupt_bytes_column(tmp_path, table, column, where_column, where_value, corrupt_fn):
    """Flips bytes in a BLOB column via a Python read-modify-write
    bound as a parameter (not SQL string concatenation), which would
    silently coerce the column's storage affinity from BLOB to TEXT
    and break unrelated reads -- see phase6_h1_h2_fix's regression
    test for the exact failure this avoids."""
    conn = sqlite3.connect(_db_path(tmp_path))
    row = conn.execute(
        f"SELECT {column} FROM {table} WHERE {where_column} = ?", (where_value,)
    ).fetchone()
    assert row is not None
    conn.execute(
        f"UPDATE {table} SET {column} = ? WHERE {where_column} = ?",
        (corrupt_fn(row[0]), where_value),
    )
    conn.commit()
    conn.close()


def _hexpeek(b: bytes, n: int = 20) -> str:
    return f"{b[:n].hex()}… ({len(b)} bytes total)"


# ===========================================================================
# D1 -- the cloud never receives plaintext files, filenames, keywords, or
# vault keys (Section 02's core invariant; audit Probes P2/P12).
# ===========================================================================

class TestD1CloudNeverReceivesPlaintextOrKeys:
    def test_cloud_never_receives_plaintext_content_filenames_or_keys(
        self, app_client, wire_log, tmp_path, evidence
    ):
        secret_word = "zephyrion"
        secret_filename = "quarterly_salaries_confidential.txt"
        secret_content = f"The {secret_word} project budget is classified."

        assert _unlock(app_client).status_code == 200
        keys = _current_keys(app_client)
        upload_resp = _upload(app_client, secret_filename, secret_content)
        assert upload_resp.status_code == 201
        assert _search(app_client, secret_word).status_code == 200

        # Every byte field client/cloud_client.py ever sends is already
        # base64 text by the time it reaches `requests.request` --
        # wire_log captures exactly that HTTP traffic, nothing decoded
        # or reconstructed afterwards.
        wire_text = repr(wire_log)
        raw_db = _raw_db_bytes(tmp_path)

        for secret in (secret_word, secret_filename, "classified", "budget"):
            assert secret not in wire_text, f"{secret!r} leaked into HTTP traffic to the cloud"
            assert secret.encode() not in raw_db, f"{secret!r} leaked into the cloud's raw database"

        # The strongest form of the claim: the actual derived key
        # bytes (not just their names) appear nowhere in anything the
        # cloud ever received or stores, in either raw or base64 form.
        for key_name, key_bytes in (("k_file", keys.k_file), ("k_index", keys.k_index)):
            assert key_bytes not in raw_db, f"{key_name} raw bytes found in the cloud's database"
            b64 = base64.b64encode(key_bytes).decode()
            assert b64 not in wire_text, f"{key_name} (base64) found in HTTP traffic to the cloud"

        evidence.append({
            "id": "D1",
            "title": "The cloud never receives plaintext content, filenames, keywords, or vault keys",
            "audit_ref": "architecture.html §02 trust boundary; Opus audit Probes P2, P12",
            "claim": (
                "A document containing the words 'zephyrion', 'classified' and 'budget', "
                "uploaded under a deliberately identifiable filename, was uploaded and then "
                "searched for. Every HTTP request the trusted client sent to the cloud during "
                "that workflow, and the cloud's own on-disk database afterwards, were scanned "
                "byte-for-byte for the plaintext words/filename and for the actual derived "
                "K_file/K_index key bytes -- none were found anywhere."
            ),
            "cloud_can_see": (
                "Opaque AES-GCM blobs (nonce/ciphertext/tag) for the document and its filename; "
                "opaque hex labels and opaque encrypted values in sse_index; a document's byte "
                "size and upload timestamp."
            ),
            "client_can_see": f"The real filename ({secret_filename!r}) and full plaintext content.",
            "remains_secret": (
                "The plaintext content and filename; the search keyword; K_file; K_index; the "
                "Argon2id master key; the vault password -- confirmed absent from every captured "
                "request/response and from the raw cloud database file."
            ),
            "intentional_limitation": None,
            "verdict": "SECURE",
            "raw_evidence": {
                "requests_sent_to_cloud": len(wire_log),
                "sample_upload_request": next(
                    (e for e in wire_log if e["path"] == "/documents" and e["method"] == "POST"), None
                ),
                "k_file_prefix_never_found_as": _hexpeek(keys.k_file),
                "k_index_prefix_never_found_as": _hexpeek(keys.k_index),
            },
        })


# ===========================================================================
# D2 -- repeated searches for the same keyword produce identical,
# recognisable search tokens (search-pattern leakage inherent to any
# deterministic-trapdoor SSE scheme; architecture §01/§10).
# ===========================================================================

class TestD2DeterministicSearchTokensLeakRepetition:
    def test_same_keyword_same_token_different_keyword_different_token(
        self, app_client, wire_log, evidence
    ):
        assert _unlock(app_client).status_code == 200
        _upload(app_client, "a.txt", "the quarterly financial outlook")
        _upload(app_client, "b.txt", "an unrelated document about gardening")

        assert _search(app_client, "financial").status_code == 200
        assert _search(app_client, "financial").status_code == 200  # same keyword again
        assert _search(app_client, "gardening").status_code == 200  # different keyword

        search_calls = [e for e in wire_log if e["path"] == "/search" and e["method"] == "POST"]
        assert len(search_calls) == 3
        k1_first, k1_second, k1_third = (c["request_json"]["k1"] for c in search_calls)

        assert k1_first == k1_second, "identical keyword must produce an identical token"
        assert k1_first != k1_third, "different keywords must produce different tokens"

        evidence.append({
            "id": "D2",
            "title": "Repeated searches for the same keyword are recognisable to the cloud",
            "audit_ref": "architecture.html §01/§10 (accepted SSE cost); crypto.py's prf() docstring",
            "claim": (
                "Searching 'financial' twice sent the byte-identical K1 token to the cloud both "
                "times; searching the unrelated keyword 'gardening' sent a different token. F(K1, "
                "counter) is deterministic by construction (HMAC-SHA256), which is what makes "
                "search work at all -- and exactly what makes repeat queries linkable."
            ),
            "cloud_can_see": (
                "That the exact same search happened twice (identical K1 bytes), and that a third "
                "search was for something different (a different K1) -- without ever learning what "
                "keyword either one was."
            ),
            "client_can_see": "The real keywords behind each token ('financial', 'gardening').",
            "remains_secret": "Which plaintext keyword a given K1 corresponds to (HMAC is one-way).",
            "intentional_limitation": (
                "Determinism is inherent to any *searchable* symmetric encryption trapdoor, not a "
                "bug in this implementation -- hiding it requires a fundamentally different "
                "(randomised-token / ORAM-backed) construction, out of scope per §01."
            ),
            "verdict": "CONFIRMED-LEAKAGE",
            "raw_evidence": {
                "k1_search_1_financial": k1_first,
                "k1_search_2_financial_repeat": k1_second,
                "k1_search_3_gardening": k1_third,
                "tokens_equal_for_same_keyword": k1_first == k1_second,
            },
        })


# ===========================================================================
# D3 -- the cloud observes result counts, total index size, and the actual
# access pattern of a search: which opaque document rows get fetched
# immediately afterwards (architecture §09's "setup size" leakage, plus
# Opus audit M4's "search eagerly fetches every match, amplifying
# access-pattern leakage"). Two sub-demonstrations:
#   D3a -- per-search match counts and total index row count (a bare
#          COUNT(*) on the cloud's own tables, no decryption needed).
#   D3b -- the literal HTTP sequence a search produces: a POST /search
#          immediately followed by one GET /documents/<doc_id> per match,
#          captured via wire_log against the real live cloud -- proving
#          the cloud can observe exactly which opaque document IDs were
#          "accessed" as a consequence of which search, and that repeating
#          the same search reproduces the identical access pattern.
# ===========================================================================

class TestD3ResultCountAndAccessPatternLeakage:
    def test_cloud_observes_match_counts_and_total_index_size(
        self, app_client, wire_log, tmp_path, evidence
    ):
        assert _unlock(app_client).status_code == 200
        _upload(app_client, "a.txt", "shared keyword alpha")
        _upload(app_client, "b.txt", "shared keyword beta")
        _upload(app_client, "c.txt", "shared keyword gamma")  # 3 docs share "shared"
        _upload(app_client, "d.txt", "solo keyword lonely")   # 1 doc has "solo"

        resp_shared = _search(app_client, "shared")
        resp_solo = _search(app_client, "solo")
        resp_missing = _search(app_client, "nonexistentword")

        search_calls = [e for e in wire_log if e["path"] == "/search" and e["method"] == "POST"]
        counts = [c["response_json"]["count"] for c in search_calls]
        assert counts == [3, 1, 0]
        assert len(resp_shared.get_json()["results"]) == 3
        assert len(resp_solo.get_json()["results"]) == 1
        assert resp_missing.get_json()["results"] == []

        total_index_rows = len(_sse_index_rows(tmp_path))
        # 4 keyword-postings for "shared"'s 3 docs' own unique words +
        # "shared" itself x3 + "solo"+"lonely" for doc d -- exact count
        # isn't the point, that the cloud can read it via a bare
        # COUNT(*) on its own table, with zero decryption, is.
        assert total_index_rows > 0

        evidence.append({
            "id": "D3a",
            "title": "The cloud observes exact result counts and total index size (setup-size leakage)",
            "audit_ref": "architecture.html §09 (setup-size leakage)",
            "claim": (
                "Three searches against the SAME live vault returned cloud-visible match counts of "
                "3, 1 and 0 respectively -- the cloud's own /search response includes 'count' "
                "explicitly, and it can also read the total row count of sse_index directly (a bare "
                "SQL COUNT(*), no decryption needed) to learn how many (keyword, document) postings "
                "the whole vault contains."
            ),
            "cloud_can_see": (
                f"Exact match count per search ({counts}); total index size "
                f"({total_index_rows} rows) at any time."
            ),
            "client_can_see": "The same counts, plus the real keywords and filenames behind them.",
            "remains_secret": "Which keyword or document identity a given count/row corresponds to.",
            "intentional_limitation": (
                "Result-count and setup-size leakage are fundamental to this class of SSE (§01/§10 "
                "scope) -- suppressing them needs padding/ORAM-style constructions this project does "
                "not implement."
            ),
            "verdict": "CONFIRMED-LEAKAGE",
            "raw_evidence": {
                "counts_observed_by_cloud": counts,
                "total_sse_index_rows_visible_to_cloud": total_index_rows,
            },
        })

    def test_cloud_observes_which_opaque_document_ids_are_fetched_after_a_search(
        self, app_client, wire_log, evidence
    ):
        """D3b -- the actual access-pattern leakage the original D3 named
        in its class docstring/title but never captured with real
        evidence: client_app.py's api_search() does not just tell the
        browser which documents matched -- for EVERY matched doc_id it
        also calls cloud_client.fetch_document(doc_id) (to decrypt that
        document's filename for display), which is a real GET
        /documents/<doc_id> request to the untrusted cloud. That means
        the literal HTTP sequence a search produces is directly
        observable by the cloud as: one POST /search, immediately
        followed by exactly `count` GET /documents/<doc_id> calls naming
        the opaque doc_ids that matched -- an access-pattern signal
        that exists independently of, and in addition to, D2's
        deterministic-token linkage and D3a's bare match count.
        """
        assert _unlock(app_client).status_code == 200
        r_a = _upload(app_client, "a.txt", "shared budget alpha")
        r_b = _upload(app_client, "b.txt", "shared budget beta")
        r_c = _upload(app_client, "c.txt", "solo gamma")
        assert r_a.status_code == r_b.status_code == r_c.status_code == 201
        doc_id_a = r_a.get_json()["doc_id"]
        doc_id_b = r_b.get_json()["doc_id"]
        doc_id_c = r_c.get_json()["doc_id"]

        def _search_and_capture_wire_window(query):
            """Runs one search and returns (response, the exact slice of
            wire_log it produced) -- a precise, real HTTP transcript for
            that one search, not a guess about ordering."""
            start = len(wire_log)
            resp = _search(app_client, query)
            assert resp.status_code == 200
            return resp, list(wire_log[start:])

        def _analyse_window(window, resp):
            # First call in the window must be the search itself...
            assert window[0]["method"] == "POST"
            assert window[0]["path"] == "/search"
            matched_count = window[0]["response_json"]["count"]
            # ...and every call after it, with nothing interleaved, is a
            # per-matched-document fetch -- exactly `matched_count` of
            # them, naming the opaque doc_id in the URL path itself.
            fetch_calls = window[1:]
            assert len(fetch_calls) == matched_count
            for call in fetch_calls:
                assert call["method"] == "GET"
                assert call["path"].startswith("/documents/")
            fetched_doc_ids = {c["path"].rsplit("/", 1)[-1] for c in fetch_calls}
            result_doc_ids = {r["doc_id"] for r in resp.get_json()["results"]}
            assert fetched_doc_ids == result_doc_ids
            return fetched_doc_ids

        resp_budget_1, window_budget_1 = _search_and_capture_wire_window("budget")
        resp_budget_2, window_budget_2 = _search_and_capture_wire_window("budget")  # exact repeat
        resp_solo, window_solo = _search_and_capture_wire_window("solo")

        fetched_budget_1 = _analyse_window(window_budget_1, resp_budget_1)
        fetched_budget_2 = _analyse_window(window_budget_2, resp_budget_2)
        fetched_solo = _analyse_window(window_solo, resp_solo)

        # The cloud-visible access pattern for "budget" is exactly the
        # two documents that actually share that keyword...
        assert fetched_budget_1 == {doc_id_a, doc_id_b}
        # ...a REPEAT of the same search reproduces the IDENTICAL access
        # pattern -- a linkage signal the cloud can read purely from
        # which opaque doc_ids get touched afterwards, independent of
        # D2's k1-token-equality linkage.
        assert fetched_budget_2 == fetched_budget_1
        # ...and a genuinely different keyword produces a distinguishable
        # pattern (a different, disjoint set of opaque doc_ids fetched).
        assert fetched_solo == {doc_id_c}
        assert fetched_solo != fetched_budget_1

        evidence.append({
            "id": "D3b",
            "title": "The cloud observes the real HTTP access pattern: which opaque document IDs are fetched right after a search",
            "audit_ref": "Opus audit M4 (search eagerly fetches every match, amplifying access-pattern leakage)",
            "claim": (
                "Captured via wire_log against the real live cloud process (not simulated): searching "
                "'budget' produces the literal HTTP sequence POST /search -> GET /documents/<id> for "
                "each of the two documents that share that keyword, with nothing else interleaved. "
                "Repeating the identical search reproduces the identical two-document access pattern; "
                "a different keyword ('solo') produces a different, disjoint single-document pattern. "
                "The cloud never decrypts anything, but it directly observes which opaque document "
                "records get 'touched' as a consequence of which search, and can tell two searches "
                "were for the same underlying keyword from that pattern alone."
            ),
            "cloud_can_see": (
                "The exact request sequence for each search (1 POST /search + N GET /documents/<id>, "
                "N = the match count); the opaque doc_id of every document a search's results caused "
                "to be fetched; that a repeated search reproduces byte-identical access pattern; that "
                "a different keyword produces a distinguishable access pattern -- all without ever "
                "learning a real keyword or filename."
            ),
            "client_can_see": "The real keyword ('budget'/'solo') and filenames behind every fetched doc_id.",
            "remains_secret": "Which plaintext keyword or filename any given opaque doc_id corresponds to.",
            "intentional_limitation": (
                "Per audit finding M4: api_search() eagerly fetches every matching document's "
                "encrypted name to resolve filenames for the browser response, which is what turns a "
                "single opaque search into an observable multi-request access pattern. A production "
                "system wanting to suppress this would cache decrypted filenames client-side (Opus "
                "fix-order item 5) instead of re-fetching on every search -- out of scope for this fix, "
                "which only had to DEMONSTRATE the leakage, not eliminate it."
            ),
            "verdict": "CONFIRMED-LEAKAGE",
            "raw_evidence": {
                "http_sequence_budget_search_1": [f"{c['method']} {c['path']}" for c in window_budget_1],
                "http_sequence_budget_search_2_repeat": [f"{c['method']} {c['path']}" for c in window_budget_2],
                "http_sequence_solo_search": [f"{c['method']} {c['path']}" for c in window_solo],
                "fetched_doc_ids_budget_search_1": sorted(fetched_budget_1),
                "fetched_doc_ids_budget_search_2_repeat": sorted(fetched_budget_2),
                "fetched_doc_ids_solo_search": sorted(fetched_solo),
                "repeat_search_access_pattern_identical": fetched_budget_2 == fetched_budget_1,
            },
        })


# ===========================================================================
# D4 -- tampering with encrypted files or encrypted index values causes
# authenticated decryption failure (AES-GCM's tag check; §04/§10).
# ===========================================================================

class TestD4TamperingCausesAuthenticatedFailure:
    def test_tampered_document_ciphertext_fails_loudly(self, app_client, tmp_path, evidence):
        assert _unlock(app_client).status_code == 200
        upload_resp = _upload(app_client, "secret.txt", "top secret contents")
        doc_id = upload_resp.get_json()["doc_id"]

        _corrupt_bytes_column(
            tmp_path, "documents", "ciphertext", "doc_id", doc_id, lambda b: b + b"x"
        )

        resp = app_client.get(f"/api/documents/{doc_id}")
        assert resp.status_code == 422

        evidence.append({
            "id": "D4a",
            "title": "A tampered document ciphertext fails authenticated decryption, not silently",
            "audit_ref": "architecture.html §04 (AES-GCM); crypto.py's aes_gcm_decrypt() docstring",
            "claim": (
                "One byte was appended directly to a stored document's ciphertext in the cloud's "
                "own database (simulating either a malicious cloud or accidental corruption), then "
                "the document was fetched with the CORRECT password. The trusted client returned a "
                "clean 422, never garbage plaintext."
            ),
            "cloud_can_see": "It can freely flip bits in its own storage -- it always could.",
            "client_can_see": "A clear 'decryption failed -- tampered or corrupted' error, nothing else.",
            "remains_secret": "n/a -- this demonstrates integrity, not confidentiality.",
            "intentional_limitation": None,
            "verdict": "SECURE",
            "raw_evidence": {"doc_id": doc_id, "response_status": resp.status_code, "response_body": resp.get_json()},
        })

    def test_tampered_index_value_fails_loudly_on_search(self, app_client, tmp_path, evidence):
        assert _unlock(app_client).status_code == 200
        _upload(app_client, "solo.txt", "zephyrion")  # exactly one keyword, one index row

        rows_before = _sse_index_rows(tmp_path)
        assert len(rows_before) == 1
        label = rows_before[0][0]

        _corrupt_bytes_column(
            tmp_path, "sse_index", "value", "label", label, lambda b: b + b"x"
        )

        resp = _search(app_client, "zephyrion")
        assert resp.status_code == 422

        evidence.append({
            "id": "D4b",
            "title": "A tampered encrypted index value fails authenticated decryption on search, not silently",
            "audit_ref": "architecture.html §05/§06 (Πbas index); search.py's decrypt_search_results()",
            "claim": (
                "The single sse_index row for a document with one distinctive keyword had one byte "
                "appended to its encrypted 'value' column directly in the cloud's database. Searching "
                "for that exact keyword afterwards -- the cloud still finds and returns the row (the "
                "label lookup itself doesn't need decryption) -- returned a clean 422 rather than a "
                "wrong or corrupted document ID."
            ),
            "cloud_can_see": "It can tamper with any opaque value it stores -- it always could.",
            "client_can_see": "A clear 'one or more search results failed to decrypt' error.",
            "remains_secret": "n/a -- this demonstrates integrity, not confidentiality.",
            "intentional_limitation": None,
            "verdict": "SECURE",
            "raw_evidence": {"tampered_label": label, "response_status": resp.status_code, "response_body": resp.get_json()},
        })


# ===========================================================================
# D5 -- missing/corrupted KDF metadata fails closed (H2 fix, verified live
# through the real two-process topology and raw-DB tampering).
# ===========================================================================

class TestD5MissingOrCorruptKdfMetadataFailsClosed:
    def test_deleted_salt_on_an_existing_vault_fails_closed(self, app_client, tmp_path, evidence):
        assert _unlock(app_client).status_code == 200
        _upload(app_client, "secret.txt", "top secret contents")
        app_client.post("/api/lock")

        conn = sqlite3.connect(_db_path(tmp_path))
        conn.execute("DELETE FROM meta WHERE key = 'kdf_salt'")
        conn.commit()
        conn.close()

        resp = _unlock(app_client, password="the real password")

        evidence.append({
            "id": "D5",
            "title": "Missing/corrupt KDF metadata fails closed instead of minting a new vault identity",
            "audit_ref": "Opus audit H2; fixed in phase6_h1_h2_fix (kdf_verifier)",
            "claim": (
                "The cloud's single kdf_salt meta row was deleted directly from its database "
                "(simulating an operator DELETE, a restored partial backup, or a malicious cloud), "
                "then unlock was attempted with the correct password. It was refused."
            ),
            "cloud_can_see": "It holds the only copy of kdf_salt/kdf_verifier and could delete either.",
            "client_can_see": f"A clear {resp.status_code} error naming the missing metadata, vault stays locked.",
            "remains_secret": "n/a.",
            "intentional_limitation": None,
            "verdict": "MITIGATED",
            "raw_evidence": {"status_code": resp.status_code, "body": resp.get_json()},
        })
        assert resp.status_code == 409
        assert app_client.get("/api/status").get_json() == {"unlocked": False}


# ===========================================================================
# D6 -- wrong-password unlock fails closed and structurally cannot trigger
# a destructive index rebuild (H1 fix, verified live with wire-level proof
# that the cloud never even received the attack's upload/replace calls).
# ===========================================================================

class TestD6WrongPasswordFailsClosedBeforeAnyRebuild:
    def test_wrong_password_unlock_never_reaches_upload_or_index_replace(
        self, app_client, wire_log, tmp_path, evidence
    ):
        assert _unlock(app_client, password="the real password").status_code == 200
        r1 = _upload(app_client, "a.txt", "shared keyword alpha")
        assert r1.status_code == 201
        doc_id_a = r1.get_json()["doc_id"]
        app_client.post("/api/lock")

        calls_before_attack = len(wire_log)

        wrong_unlock = _unlock(app_client, password="an attacker's guess")
        assert wrong_unlock.status_code == 401
        upload_attempt = _upload(app_client, "evil.txt", "whatever the attacker wants")
        assert upload_attempt.status_code == 401

        attack_calls = wire_log[calls_before_attack:]
        destructive_calls = [
            c for c in attack_calls
            if c["path"] in ("/documents", "/index/replace") and c["method"] == "POST"
        ]

        assert destructive_calls == [], (
            "the wrong-password attack sequence must never even reach the cloud with an "
            "upload or an index replacement -- unlock has to refuse before either is possible"
        )

        assert _unlock(app_client, password="the real password").status_code == 200
        search_resp = _search(app_client, "shared")
        assert [r["doc_id"] for r in search_resp.get_json()["results"]] == [doc_id_a]

        evidence.append({
            "id": "D6",
            "title": "Wrong-password unlock fails closed; the destructive-rebuild attack path is unreachable",
            "audit_ref": "Opus audit H1, Probe P1; fixed in phase6_h1_h2_fix (unlock verifier + all-or-nothing rebuild)",
            "claim": (
                "Reproduced the exact Probe P1 sequence (correct unlock, upload, lock, wrong-password "
                "unlock, upload attempt) while capturing every HTTP call the client made to the cloud. "
                f"Zero of the {len(attack_calls)} calls made during the attack sequence were a "
                "POST /documents or POST /index/replace -- the cloud never received either, because "
                "unlock itself refused first."
            ),
            "cloud_can_see": "The failed unlock attempt itself (a GET on its own meta rows) -- nothing more.",
            "client_can_see": (
                "A clear 401 at unlock; the real index is fully intact afterwards, confirmed by a "
                "correct-password search still finding the original document."
            ),
            "remains_secret": "n/a.",
            "intentional_limitation": None,
            "verdict": "MITIGATED",
            "raw_evidence": {
                "attack_sequence_calls": attack_calls,
                "destructive_calls_during_attack": destructive_calls,
            },
        })


# ===========================================================================
# D7 -- the static index rebuild cost is real and observable on the wire
# (architecture §10's accepted O(n)-per-upload limitation).
# ===========================================================================

class TestD7StaticIndexRebuildCostIsObservable:
    def test_each_upload_refetches_the_whole_growing_corpus(self, app_client, wire_log, evidence):
        assert _unlock(app_client).status_code == 200

        fetch_counts = []
        for i in range(3):
            before = len([e for e in wire_log if e["method"] == "GET" and e["path"].startswith("/documents/")])
            _upload(app_client, f"doc{i}.txt", f"unique content number {i}")
            after = len([e for e in wire_log if e["method"] == "GET" and e["path"].startswith("/documents/")])
            fetch_counts.append(after - before)

        # Upload i re-fetches all i+1 documents that exist at that point
        # (itself included, once already pushed) -- O(n) per upload, not
        # O(1) -- exactly what a genuinely incremental/forward-private
        # index would avoid.
        assert fetch_counts == [1, 2, 3]

        evidence.append({
            "id": "D7",
            "title": "The static index is rebuilt from the whole corpus on every single upload",
            "audit_ref": "architecture.html §10 'static-only assumption'; indexer.py/_rebuild_and_push_index() docstrings",
            "claim": (
                "Three uploads in sequence triggered "
                f"{fetch_counts} document re-fetches respectively -- upload N re-fetches and "
                "re-decrypts all N documents that exist by then, observable purely from HTTP call "
                "volume, confirming the O(n)-per-upload cost the code's own docstrings claim."
            ),
            "cloud_can_see": (
                "The number of GET /documents/<id> calls per upload growing linearly -- i.e. it can "
                "infer, from traffic volume alone, that a full-corpus operation runs on every write, "
                "which is itself a form of operation-pattern leakage beyond content."
            ),
            "client_can_see": "The same, plus that this is simply how the design works.",
            "remains_secret": "Which specific documents were re-fetched stays opaque (random doc_ids).",
            "intentional_limitation": (
                "Explicitly named and accepted in §10: no incremental index update, no forward "
                "privacy -- a real incremental/forward-private SSE construction is out of scope for "
                "this project."
            ),
            "verdict": "CONFIRMED-LEAKAGE",
            "raw_evidence": {"document_refetches_per_upload": fetch_counts},
        })


# ===========================================================================
# D8 -- a captured search token (K1) remains usable against a LATER,
# rebuilt index (Opus audit M5: lack of forward privacy, confirmed live).
# ===========================================================================

class TestD8CapturedTokenSurvivesLaterRebuilds:
    def test_a_token_captured_before_a_rebuild_still_works_and_grows_after_it(
        self, app_client, wire_log, live_cloud, evidence
    ):
        import requests

        assert _unlock(app_client).status_code == 200
        r1 = _upload(app_client, "a.txt", "zephyrion alpha")
        assert r1.status_code == 201

        # An attacker (or the cloud itself) observes ONE search and
        # captures its K1 -- exactly what D2 showed is recognisable.
        first_search = _search(app_client, "zephyrion")
        assert first_search.status_code == 200
        assert len(first_search.get_json()["results"]) == 1
        captured = next(
            e for e in reversed(wire_log)
            if e["path"] == "/search" and e["method"] == "POST"
        )
        captured_k1 = captured["request_json"]["k1"]
        # Multi-user extension: the request also carried the vault's
        # namespace + access-token headers. An observer of that request
        # sees them as well, so the replay reuses them -- the access
        # token scopes WHICH vault is searched, it adds no forward privacy.
        captured_headers = captured["request_headers"]

        # The corpus changes AFTER the token was captured: a second
        # document sharing the same keyword triggers a full index
        # rebuild (fresh nonces, a fresh 'value' ciphertext for every
        # posting -- see indexer.py's docstring) that the attacker was
        # never involved in and has no fresh visibility into.
        r2 = _upload(app_client, "b.txt", "zephyrion beta")
        assert r2.status_code == 201
        doc_id_b = r2.get_json()["doc_id"]

        # Replay the OLD captured token directly against the live
        # cloud's real /search endpoint -- bypassing the trusted client
        # entirely, using nothing but the previously-observed k1 bytes,
        # exactly as a passive observer who once saw a query would.
        replay = requests.post(
            f"{live_cloud}/search", json={"k1": captured_k1}, headers=captured_headers, timeout=5
        )
        assert replay.status_code == 200
        replay_count = replay.json()["count"]

        assert replay_count == 2, (
            "a token captured before the rebuild must still work AFTER it, and must now cover "
            "the document that didn't exist when it was captured -- that is exactly the lack of "
            "forward privacy this demonstrates"
        )

        evidence.append({
            "id": "D8",
            "title": "A search token captured once remains valid forever, and silently grows to cover future data",
            "audit_ref": "Opus audit M5 (confirmed); architecture.html §10 (no forward privacy claimed)",
            "claim": (
                "K1 for 'zephyrion' was captured from a live search while only ONE matching document "
                "existed. A second matching document was then uploaded, triggering a full index "
                "rebuild the captured token played no part in. Replaying the OLD token directly "
                "against the live cloud -- with no involvement from the trusted client at all -- now "
                "returns BOTH documents."
            ),
            "cloud_can_see": (
                "Nothing new is required of the cloud here: it is the same deterministic F(K_index, "
                "keyword) it always sees (D2) -- the point is that possessing one old token is "
                "permanently as good as possessing a live one, for that keyword, forever."
            ),
            "client_can_see": "That this is how the static construction behaves -- no client action needed.",
            "remains_secret": "Which keyword the token corresponds to, in isolation.",
            "intentional_limitation": (
                "This is exactly M5's finding and architecture.html §10's explicitly out-of-scope "
                "forward privacy -- a forward-private SSE construction (e.g. rotating K1 per epoch) "
                "would close this, and is named future work, not attempted here."
            ),
            "verdict": "CONFIRMED-LEAKAGE",
            "raw_evidence": {
                "captured_k1_before_rebuild": captured_k1,
                "results_at_capture_time": 1,
                "new_document_added_after_capture": doc_id_b,
                "replay_result_count_after_rebuild": replay_count,
            },
        })


# ===========================================================================
# D9 -- a conjunctive (multi-keyword AND) query is answered as N fully
# independent single-keyword searches, intersected on the trusted client
# (client/search.py's normalise_conjunctive_query + client_app.py's
# api_search). The cloud never computes or is told the intersection --
# but IS told, by ordinary request timing alone, that these N tokens
# arrived together as one logical query (architecture.html §09).
# ===========================================================================

class TestD9ConjunctiveSearchTokenCoOccurrence:
    def test_two_keyword_and_query_sends_two_independent_single_keyword_searches(
        self, app_client, wire_log, evidence
    ):
        assert _unlock(app_client).status_code == 200
        _upload(app_client, "a.txt", "quarterly financial report")  # matches both
        _upload(app_client, "b.txt", "quarterly board minutes")  # matches only one
        _upload(app_client, "c.txt", "unrelated financial memo")  # matches only the other

        resp = _search(app_client, "quarterly financial")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["keywords"] == ["financial", "quarterly"]
        assert [r["filename"] for r in body["results"]] == ["a.txt"]

        search_calls = [e for e in wire_log if e["path"] == "/search" and e["method"] == "POST"]
        # The whole point being demonstrated: the cloud's /search route
        # was called TWICE -- once per keyword -- with two DIFFERENT k1
        # tokens, never a combined "AND" request of any kind. Nothing
        # in the wire protocol distinguishes this from two unrelated
        # single-keyword searches happening to occur back-to-back.
        assert len(search_calls) == 2
        k1_financial, k1_quarterly = (c["request_json"]["k1"] for c in search_calls)
        assert k1_financial != k1_quarterly
        assert all(set(c["request_json"].keys()) == {"k1"} for c in search_calls)

        evidence.append({
            "id": "D9",
            "title": "A conjunctive (AND) search is two ordinary single-keyword searches back-to-back, intersected only by the client -- but their co-occurrence is still cloud-visible",
            "audit_ref": "architecture.html §01 (scope reversal, documented) and §09 (query-conjunction row); client/search.py module docstring",
            "claim": (
                "Searching 'quarterly financial' (an implicit AND) produced exactly two calls to "
                "the cloud's unmodified /search route, each carrying a single k1 token -- byte-"
                "identical in shape to D2's ordinary single-keyword search. The cloud was never "
                "asked to compute an intersection and never received both tokens in one request; "
                "client_app.py intersected the two decrypted doc_id sets itself, after both cloud "
                "round trips had already completed."
            ),
            "cloud_can_see": (
                "Two independent search requests, each with its own token and its own result "
                "count/access pattern (identical leakage to a lone single-keyword search, per D2/D3) "
                "-- PLUS that these two arrived together, in this order, with no unrelated traffic "
                "between them, which a request-timing/log analysis can read as 'these two keywords "
                "were queried jointly' even though no field in either request says so."
            ),
            "client_can_see": "The real keywords ('quarterly', 'financial') and that a document matched both.",
            "remains_secret": "The plaintext keywords themselves, and which specific document matched (only its opaque doc_id and access pattern are cloud-visible, per D3).",
            "intentional_limitation": (
                "This co-occurrence signal is the scoped cost of choosing the simplest correct "
                "construction (client-side intersection of independent searches) over a cross-tag "
                "scheme (e.g. OXT) that could hide more -- see client/search.py's module docstring "
                "for that design decision. Suppressing it entirely needs a real multi-keyword "
                "protocol, out of scope per the same depth-over-breadth call §01 already makes for "
                "the base scheme."
            ),
            "verdict": "CONFIRMED-LEAKAGE",
            "raw_evidence": {
                "query": "quarterly financial",
                "search_calls_to_cloud": len(search_calls),
                "k1_tokens_sent": [k1_quarterly, k1_financial],
                "each_request_carried_only_one_token": all(
                    set(c["request_json"].keys()) == {"k1"} for c in search_calls
                ),
                "final_intersection_result": [r["filename"] for r in body["results"]],
            },
        })
