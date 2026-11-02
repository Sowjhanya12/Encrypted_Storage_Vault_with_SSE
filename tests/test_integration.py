"""
tests/test_integration.py -- where client/ (trusted) and cloud/
(untrusted) actually meet.

This is the only test file in the project allowed to import from both
client/ and cloud/ at once -- it plays the role client_app.py will
play once it exists in Phase 5: deriving keys, encrypting, splitting
the AES-GCM blob into the columns the cloud schema expects, pushing it
over HTTP, fetching it back, and decrypting.

It carries the checks explicitly required so far:
  * Phase 2: a full document round trip is byte-identical / decrypts
    correctly, and the cloud never receives or stores key material.
  * Phase 3: a tokenized corpus can be indexed and pushed into the
    cloud's sse_index table with the expected entry count, and no
    plaintext keyword or doc_id appears in the stored index either.
  * Phase 4: a real /search HTTP round trip against the real cloud
    returns the correct doc_id set for successful searches, missing
    keywords, and multiple matches; wrong keys and tampered results
    are rejected; and cloud/cloud_app.py's independently-implemented
    HMAC/counter encoding is checked byte-for-byte against
    client/crypto.py and client/indexer.py's, so the two
    implementations required by the trust boundary (Section 02) can't
    silently drift apart.
"""

import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.crypto import (  # noqa: E402
    NONCE_SIZE,
    TAG_SIZE,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
)
from client.indexer import build_index  # noqa: E402
from client.keymgmt import derive_master_key, generate_salt, unlock, Argon2Params  # noqa: E402
from client.search import (  # noqa: E402
    AmbiguousQueryError,
    build_search_token,
    decrypt_search_results,
    normalise_query,
)
from client.tokenizer import tokenize  # noqa: E402
from cloud import storage  # noqa: E402
from cloud.cloud_app import _counter_to_bytes, _cloud_prf, create_app  # noqa: E402

FAST_PARAMS = Argon2Params(time_cost=1, memory_cost_kib=8, parallelism=1)


@pytest.fixture
def cloud(tmp_path):
    """Returns (flask_test_client, db_path) so tests can both call the
    HTTP API and, when needed, inspect the raw SQLite file on disk."""
    db_path = tmp_path / "vault.sqlite3"
    app = create_app(db_path=str(db_path))
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, db_path


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _split_blob(blob: bytes):
    """The one place this project slices an AES-GCM blob into the
    cloud schema's three columns. crypto.py's own public size
    constants (NONCE_SIZE, TAG_SIZE) do the slicing -- the cloud side
    never needs to know these numbers exist."""
    nonce = blob[:NONCE_SIZE]
    tag = blob[-TAG_SIZE:]
    ciphertext = blob[NONCE_SIZE:-TAG_SIZE]
    return nonce, ciphertext, tag


# ---------------------------------------------------------------------------
# functional: full upload -> download -> decrypt round trip
# ---------------------------------------------------------------------------

class TestUploadDownloadDecryptRoundTrip:
    def test_file_survives_the_full_trip_unchanged(self, cloud):
        client_http, _db_path = cloud
        keys = unlock("correct horse battery staple", generate_salt(), FAST_PARAMS)

        plaintext = b"Q3 financial report -- confidential draft, do not distribute."
        filename = "q3-report.txt"

        file_blob = aes_gcm_encrypt(keys.k_file, plaintext)
        name_blob = aes_gcm_encrypt(keys.k_file, filename.encode("utf-8"))
        nonce, ciphertext, tag = _split_blob(file_blob)
        doc_id = os.urandom(16).hex()

        resp = client_http.post(
            "/documents",
            json={
                "doc_id": doc_id,
                "enc_name": _b64(name_blob),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
                "tag": _b64(tag),
            },
        )
        assert resp.status_code == 201

        fetched = client_http.get(f"/documents/{doc_id}").get_json()
        rebuilt_blob = (
            base64.b64decode(fetched["nonce"])
            + base64.b64decode(fetched["ciphertext"])
            + base64.b64decode(fetched["tag"])
        )
        assert rebuilt_blob == file_blob  # storage round trip was byte-identical

        recovered_plaintext = aes_gcm_decrypt(keys.k_file, rebuilt_blob)
        recovered_name = aes_gcm_decrypt(keys.k_file, base64.b64decode(fetched["enc_name"]))
        assert recovered_plaintext == plaintext
        assert recovered_name.decode("utf-8") == filename

    def test_wrong_key_cannot_decrypt_what_the_cloud_returns(self, cloud):
        # Sanity check the other direction: even a byte-perfect fetch
        # from the cloud is useless without the right K_file.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        attacker_keys = unlock("attacker's guess", generate_salt(), FAST_PARAMS)

        blob = aes_gcm_encrypt(keys.k_file, b"top secret contents")
        nonce, ciphertext, tag = _split_blob(blob)
        doc_id = os.urandom(16).hex()
        client_http.post(
            "/documents",
            json={
                "doc_id": doc_id,
                "enc_name": _b64(aes_gcm_encrypt(keys.k_file, b"name.txt")),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
                "tag": _b64(tag),
            },
        )
        fetched = client_http.get(f"/documents/{doc_id}").get_json()
        rebuilt_blob = (
            base64.b64decode(fetched["nonce"])
            + base64.b64decode(fetched["ciphertext"])
            + base64.b64decode(fetched["tag"])
        )
        from client.crypto import DecryptionError

        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(attacker_keys.k_file, rebuilt_blob)


# ---------------------------------------------------------------------------
# how Phase 1's unlock() gets its salt from Phase 2's meta storage
# ---------------------------------------------------------------------------

class TestSaltRoundTripThroughMeta:
    def test_salt_stored_in_meta_reproduces_the_same_master_key(self, cloud):
        # Mirrors Section 07 flow A: the client fetches the (non-secret)
        # salt from the cloud, then derives locally. The password
        # itself never appears in this test's HTTP calls at all.
        client_http, _db_path = cloud
        salt = generate_salt()
        client_http.post("/meta/kdf_salt", json={"value": _b64(salt)})

        fetched_salt = base64.b64decode(client_http.get("/meta/kdf_salt").get_json()["value"])
        assert fetched_salt == salt

        original = derive_master_key("vault owner's password", salt, FAST_PARAMS)
        rederived = derive_master_key("vault owner's password", fetched_salt, FAST_PARAMS)
        assert original == rederived


# ---------------------------------------------------------------------------
# security: the cloud never receives or stores key material or plaintext
# ---------------------------------------------------------------------------

class TestCloudNeverSeesKeysOrPlaintext:
    def test_sqlite_file_on_disk_contains_no_key_material(self, cloud):
        client_http, db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)

        plaintext = b"contents that must never appear in cleartext on the cloud"
        filename = "sensitive-plan.txt"
        file_blob = aes_gcm_encrypt(keys.k_file, plaintext)
        name_blob = aes_gcm_encrypt(keys.k_file, filename.encode("utf-8"))
        nonce, ciphertext, tag = _split_blob(file_blob)

        client_http.post(
            "/documents",
            json={
                "doc_id": os.urandom(16).hex(),
                "enc_name": _b64(name_blob),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
                "tag": _b64(tag),
            },
        )

        raw_db_bytes = db_path.read_bytes()

        # The two things this phase's requirement is literally about:
        # K_file and K_index must not be sitting in the stored file.
        assert keys.k_file not in raw_db_bytes
        assert keys.k_index not in raw_db_bytes

        # And the honest-but-curious promise from Section 09: no
        # plaintext file content or filename either.
        assert plaintext not in raw_db_bytes
        assert filename.encode("utf-8") not in raw_db_bytes

    def test_http_request_bodies_never_carry_key_material(self, cloud):
        # Same idea, checked at the transport boundary instead of the
        # disk file: nothing sent to the cloud's HTTP API -- not even
        # transiently -- contains the raw key bytes.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        blob = aes_gcm_encrypt(keys.k_file, b"payload")
        nonce, ciphertext, tag = _split_blob(blob)

        body = {
            "doc_id": os.urandom(16).hex(),
            "enc_name": _b64(aes_gcm_encrypt(keys.k_file, b"name.txt")),
            "nonce": _b64(nonce),
            "ciphertext": _b64(ciphertext),
            "tag": _b64(tag),
        }
        # Every string value the client is about to send, concatenated,
        # must not contain a base64 rendering of either key.
        sent = " ".join(v for v in body.values() if isinstance(v, str))
        assert _b64(keys.k_file) not in sent
        assert _b64(keys.k_index) not in sent

        client_http.post("/documents", json=body)


# ---------------------------------------------------------------------------
# Phase 3: tokenized corpus -> encrypted index -> pushed into the cloud
# ---------------------------------------------------------------------------

class TestCorpusIndexingIntoCloud:
    """Section 15 P3's own "done" criterion: 'a test asserts the
    dictionary has the expected entry count and no plaintext'. This
    class does exactly that, against the real cloud storage layer --
    not a mock -- via the same /index HTTP route Phase 4's search will
    read from.
    """

    CORPUS = {
        "doc-quarterly": "Quarterly financial report, Q3 2024. Confidential.",
        "doc-invoice": "Invoice report attached -- please review and approve.",
        "doc-summary": "Executive summary of the Q3 report for the board.",
    }

    def test_indexed_corpus_has_expected_entry_count_in_cloud_storage(self, cloud):
        client_http, db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)

        documents = {doc_id: tokenize(text) for doc_id, text in self.CORPUS.items()}
        entries = build_index(keys.k_index, documents)
        expected_pairs = sum(len(kws) for kws in documents.values())
        assert len(entries) == expected_pairs > 0

        resp = client_http.post(
            "/index",
            json={
                "entries": [
                    {"label": e.label, "value": base64.b64encode(e.value).decode("ascii")}
                    for e in entries
                ]
            },
        )
        assert resp.status_code == 201
        assert resp.get_json()["inserted"] == expected_pairs

        # Confirm directly against storage.py (Section 09's "setup
        # size" leakage is exactly this row count, and it's the doc's
        # explicit done-criterion for this phase).
        with storage.open_db(db_path) as conn:
            assert storage.index_entry_count(conn) == expected_pairs

    def test_indexed_corpus_leaks_no_plaintext_keyword_or_doc_id(self, cloud):
        client_http, db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)

        documents = {doc_id: tokenize(text) for doc_id, text in self.CORPUS.items()}
        entries = build_index(keys.k_index, documents)

        client_http.post(
            "/index",
            json={
                "entries": [
                    {"label": e.label, "value": base64.b64encode(e.value).decode("ascii")}
                    for e in entries
                ]
            },
        )

        raw_db_bytes = db_path.read_bytes()

        # Every stored row must have the shape of the scheme's output and
        # nothing else: a label is a 64-hex-char HMAC-SHA256 digest, and a
        # value is exactly nonce(12) + AES-GCM(doc_id) + tag(16) -- room
        # for an encrypted doc_id, no room for anything smuggled in.
        doc_id_lengths = {len(d.encode("utf-8")) for d in self.CORPUS}
        for e in entries:
            assert len(e.label) == 64 and all(c in "0123456789abcdef" for c in e.label)
            assert len(e.value) - 12 - 16 in doc_id_lengths

        # None of the actual words in the corpus, and none of the
        # doc_ids, may appear anywhere in the stored index.
        #
        # The labels and values written above are random-looking by
        # construction (HMAC output as hex, AES-GCM ciphertext). A short
        # keyword can occur inside them purely by chance -- measured at
        # ~1.7% of runs, e.g. the 2 bytes "q3" inside a random GCM value,
        # or the all-hex-digit "2024" inside a hex label -- which made
        # this test flaky without indicating any leak. So those known
        # random bytes are zeroed in place before scanning; any keyword
        # stored anywhere ELSE in the file (as plaintext) is still caught,
        # and the shape checks above rule out plaintext inside them.
        scrubbed = raw_db_bytes
        for e in entries:
            scrubbed = scrubbed.replace(e.label.encode("ascii"), b"\0" * len(e.label))
            scrubbed = scrubbed.replace(e.value, b"\0" * len(e.value))
        for text in self.CORPUS.values():
            for keyword in tokenize(text):
                assert keyword.encode("utf-8") not in scrubbed
        for doc_id in self.CORPUS:
            assert doc_id.encode("utf-8") not in raw_db_bytes

        # Nor the keys used to build the index.
        assert keys.k_index not in raw_db_bytes
        assert keys.k_file not in raw_db_bytes

    def test_search_side_can_recompute_the_same_labels_index_side_wrote(self, cloud):
        # This is the concrete guarantee Phase 4 depends on: given the
        # same K_index and the same tokenized keyword, recomputing K1
        # and F(K1, 0) reproduces a label that is actually present in
        # the cloud's sse_index -- proving index-build and (future)
        # search-token generation are using one consistent contract,
        # without implementing the search loop itself.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)

        documents = {"doc1": tokenize("annual report and financial summary")}
        entries = build_index(keys.k_index, documents)
        client_http.post(
            "/index",
            json={
                "entries": [
                    {"label": e.label, "value": base64.b64encode(e.value).decode("ascii")}
                    for e in entries
                ]
            },
        )

        from client.crypto import prf
        from client.indexer import counter_to_bytes, keyword_label_key

        k1 = keyword_label_key(keys.k_index, "report")
        recomputed_label = prf(k1, counter_to_bytes(0)).hex()

        got = client_http.get(f"/index/{recomputed_label}")
        assert got.status_code == 200

# ---------------------------------------------------------------------------
# Phase 4: real /search over the real cloud -- keyword to decrypted doc_ids
# ---------------------------------------------------------------------------

def _push_corpus(client_http, keys, corpus_text):
    """Tokenize + index + push a corpus into the real cloud, exactly
    as tests/test_integration.py's TestCorpusIndexingIntoCloud
    (Phase 3) already does. Returns the tokenized documents dict for
    callers that need to compute expected results."""
    documents = {doc_id: tokenize(text) for doc_id, text in corpus_text.items()}
    entries = build_index(keys.k_index, documents)
    resp = client_http.post(
        "/index",
        json={
            "entries": [
                {"label": e.label, "value": base64.b64encode(e.value).decode("ascii")}
                for e in entries
            ]
        },
    )
    assert resp.status_code == 201
    return documents


def _search(client_http, keys, query: str):
    """The full client-side search flow a future client_app.py will
    perform: normalise -> token -> real HTTP /search -> decrypt."""
    keyword = normalise_query(query)
    token = build_search_token(keys.k_index, keyword)
    resp = client_http.post("/search", json={"k1": base64.b64encode(token).decode("ascii")})
    assert resp.status_code == 200
    encrypted_values = [base64.b64decode(v) for v in resp.get_json()["results"]]
    return decrypt_search_results(keys.k_index, keyword, encrypted_values)


CORPUS = {
    "doc-quarterly": "Quarterly financial report, Q3 2024. Confidential.",
    "doc-invoice": "Invoice report attached -- please review and approve.",
    "doc-summary": "Executive summary of the Q3 report for the board.",
    "doc-unrelated": "Office lunch menu for Friday.",
}


class TestSearchEndToEnd:
    def test_successful_search_single_match(self, cloud):
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        assert _search(client_http, keys, "invoice") == {"doc-invoice"}

    def test_successful_search_multiple_matching_documents(self, cloud):
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        # "report" appears in doc-quarterly, doc-invoice, and doc-summary.
        assert _search(client_http, keys, "report") == {
            "doc-quarterly",
            "doc-invoice",
            "doc-summary",
        }

    def test_missing_keyword_returns_empty_set_not_an_error(self, cloud):
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        assert _search(client_http, keys, "nonexistentword") == set()

    def test_search_on_a_completely_empty_index_returns_empty_set(self, cloud):
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        # Nothing pushed at all.
        assert _search(client_http, keys, "anything") == set()

    def test_query_phrasing_does_not_affect_the_match(self, cloud):
        # Case/punctuation-insensitivity: the query normaliser and the
        # indexer's tokenizer are the same function, so this must
        # match regardless of how the query is phrased.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        assert _search(client_http, keys, "INVOICE!!!") == {"doc-invoice"}
        assert _search(client_http, keys, "  invoice  ") == {"doc-invoice"}

    def test_multi_word_query_is_rejected_not_silently_narrowed(self, cloud):
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        with pytest.raises(AmbiguousQueryError):
            _search(client_http, keys, "quarterly report")

    def test_wrong_vault_password_finds_nothing(self, cloud):
        # A different password derives a different K_index and thus a
        # different, unrelated K1 -- the real-world "wrong keys" case.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        attacker_keys = unlock("attacker's guess", generate_salt(), FAST_PARAMS)
        assert _search(client_http, attacker_keys, "invoice") == set()

    def test_decrypting_with_the_wrong_keyword_fails_loudly(self, cloud):
        # A more targeted "wrong key" case: correct k_index, but
        # decrypting results found under one keyword's token with a
        # different keyword's K2 must fail, not return garbage.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        keyword = normalise_query("invoice")
        token = build_search_token(keys.k_index, keyword)
        resp = client_http.post("/search", json={"k1": base64.b64encode(token).decode("ascii")})
        encrypted_values = [base64.b64decode(v) for v in resp.get_json()["results"]]

        from client.crypto import DecryptionError

        with pytest.raises(DecryptionError):
            decrypt_search_results(keys.k_index, "summary", encrypted_values)

    def test_tampered_result_from_the_cloud_fails_loudly(self, cloud):
        # Simulates a corrupted/tampered value coming back from the
        # cloud -- AES-GCM's tag check must catch it here too, in the
        # real HTTP path, not just in isolated crypto unit tests.
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        _push_corpus(client_http, keys, CORPUS)

        keyword = normalise_query("invoice")
        token = build_search_token(keys.k_index, keyword)
        resp = client_http.post("/search", json={"k1": base64.b64encode(token).decode("ascii")})
        encrypted_values = [bytearray(base64.b64decode(v)) for v in resp.get_json()["results"]]
        encrypted_values[0][-1] ^= 0x01  # flip a bit as if tampered in transit

        from client.crypto import DecryptionError

        with pytest.raises(DecryptionError):
            decrypt_search_results(keys.k_index, keyword, [bytes(v) for v in encrypted_values])

    def test_search_result_count_matches_documents_pushed_for_that_keyword(self, cloud):
        # A slightly larger corpus to exercise more than a handful of
        # postings for one keyword, still well within a normal corpus
        # size (not a performance/stress test -- that's Phase 7).
        client_http, _db_path = cloud
        keys = unlock("vault owner's password", generate_salt(), FAST_PARAMS)
        big_corpus = {f"doc-{i}": "shared keyword plus unique{} text".format(i) for i in range(25)}
        _push_corpus(client_http, keys, big_corpus)

        result = _search(client_http, keys, "shared")
        assert result == set(big_corpus.keys())
        assert len(result) == 25


class TestCloudSearchLoopMatchesClientImplementation:
    """The drift-detector this phase's design explicitly calls for:
    cloud/cloud_app.py's _cloud_prf/_counter_to_bytes are a deliberate
    duplication of client/crypto.py's prf() and client/indexer.py's
    counter_to_bytes() (to keep the client/cloud import boundary
    sharp). This test is what actually keeps them from silently
    drifting apart, since nothing else enforces it structurally.
    """

    def test_hmac_implementations_agree_on_many_inputs(self):
        from client.crypto import prf

        for _ in range(20):
            key = os.urandom(32)
            data = os.urandom(16)
            assert _cloud_prf(key, data) == prf(key, data)

    def test_counter_encodings_agree(self):
        from client.indexer import counter_to_bytes

        for counter in (0, 1, 2, 255, 256, 65535, 1_000_000):
            assert _counter_to_bytes(counter) == counter_to_bytes(counter)

    def test_a_label_computed_client_side_matches_one_computed_cloud_side(self):
        from client.crypto import prf
        from client.indexer import counter_to_bytes

        k1 = os.urandom(32)
        for counter in range(10):
            client_label = prf(k1, counter_to_bytes(counter)).hex()
            cloud_label = _cloud_prf(k1, _counter_to_bytes(counter)).hex()
            assert client_label == cloud_label
