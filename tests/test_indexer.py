"""
tests/test_indexer.py -- Unit tests for client/indexer.py.

Uses client/crypto.py directly to verify entries decrypt correctly
(that's testing indexer.py's own correctness, not crossing into
cloud/ -- the cloud-integration version of this lives in
tests/test_integration.py).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.crypto import KEY_SIZE, aes_gcm_decrypt, prf  # noqa: E402
from client.indexer import (  # noqa: E402
    IndexEntry,
    build_index,
    counter_to_bytes,
    keyword_label_key,
    keyword_value_key,
)
from client.tokenizer import tokenize  # noqa: E402


def _k_index() -> bytes:
    return os.urandom(KEY_SIZE)


# ---------------------------------------------------------------------------
# key derivation primitives
# ---------------------------------------------------------------------------

class TestKeyDerivation:
    def test_label_key_and_value_key_differ(self):
        k_index = _k_index()
        assert keyword_label_key(k_index, "report") != keyword_value_key(k_index, "report")

    def test_deterministic_for_same_inputs(self):
        k_index = _k_index()
        assert keyword_label_key(k_index, "report") == keyword_label_key(k_index, "report")
        assert keyword_value_key(k_index, "report") == keyword_value_key(k_index, "report")

    def test_different_keywords_produce_different_keys(self):
        k_index = _k_index()
        assert keyword_label_key(k_index, "report") != keyword_label_key(k_index, "invoice")
        assert keyword_value_key(k_index, "report") != keyword_value_key(k_index, "invoice")

    def test_different_k_index_produces_different_keys(self):
        assert keyword_label_key(_k_index(), "report") != keyword_label_key(_k_index(), "report")

    def test_no_two_keywords_share_label_and_value_keys_across_domains(self):
        # A K1 for one keyword should never equal a K2 for any keyword
        # -- the domain markers keep the two derivation streams apart.
        k_index = _k_index()
        k1 = keyword_label_key(k_index, "alpha")
        k2 = keyword_value_key(k_index, "alpha")
        assert k1 != k2


class TestCounterEncoding:
    def test_deterministic(self):
        assert counter_to_bytes(5) == counter_to_bytes(5)

    def test_different_counters_differ(self):
        seen = {counter_to_bytes(i) for i in range(1000)}
        assert len(seen) == 1000

    def test_rejects_negative_counter(self):
        with pytest.raises(ValueError):
            counter_to_bytes(-1)

    def test_fixed_width(self):
        assert len(counter_to_bytes(0)) == len(counter_to_bytes(999999))


# ---------------------------------------------------------------------------
# build_index
# ---------------------------------------------------------------------------

class TestBuildIndex:
    def test_empty_corpus_produces_empty_index(self):
        assert build_index(_k_index(), {}) == []

    def test_document_with_no_keywords_contributes_nothing(self):
        assert build_index(_k_index(), {"doc1": set()}) == []

    def test_single_document_single_keyword_produces_one_entry(self):
        entries = build_index(_k_index(), {"doc1": {"report"}})
        assert len(entries) == 1
        assert isinstance(entries[0], IndexEntry)

    def test_entry_count_matches_sum_of_keyword_document_pairs(self):
        documents = {
            "doc1": {"report", "invoice"},
            "doc2": {"report"},
            "doc3": {"report", "invoice", "summary"},
        }
        expected_pairs = sum(len(kws) for kws in documents.values())  # 2 + 1 + 3 = 6
        entries = build_index(_k_index(), documents)
        assert len(entries) == expected_pairs == 6

    def test_labels_are_hex_strings_of_expected_length(self):
        entries = build_index(_k_index(), {"doc1": {"report"}})
        label = entries[0].label
        assert isinstance(label, str)
        assert len(label) == 64  # 32-byte HMAC-SHA256 digest, hex-encoded
        int(label, 16)  # raises ValueError if not valid hex

    def test_values_decrypt_to_the_correct_doc_id(self):
        k_index = _k_index()
        documents = {"doc-A": {"report"}, "doc-B": {"report"}}
        entries = build_index(k_index, documents)
        k2 = keyword_value_key(k_index, "report")

        recovered = {aes_gcm_decrypt(k2, e.value).decode("utf-8") for e in entries}
        assert recovered == {"doc-A", "doc-B"}

    def test_labels_are_deterministic_across_rebuilds(self):
        # HMAC has no randomness: the same (k_index, documents) always
        # assigns the same label to the same (keyword, counter) pair.
        # This is what lets a rebuilt index still be found by label.
        k_index = _k_index()
        documents = {"doc1": {"report", "invoice"}, "doc2": {"report"}}
        a = build_index(k_index, documents)
        b = build_index(k_index, documents)
        assert sorted(e.label for e in a) == sorted(e.label for e in b)

    def test_values_are_NOT_deterministic_across_rebuilds(self):
        # The other half of the same property, stated explicitly: each
        # value is AES-GCM(K2, doc_id) with a fresh random nonce (the
        # Phase 1 design -- aes_gcm_encrypt never accepts a caller
        # nonce), so re-encrypting the identical doc_id under the
        # identical K2 produces different ciphertext bytes every time.
        # This is deliberate, not a bug: if rebuilds produced identical
        # ciphertext for an unchanged posting, a curious cloud could
        # diff two rebuilds' sse_index snapshots and learn *which*
        # (keyword, document) pairs persisted unchanged, without ever
        # decrypting anything. Fresh nonces deny it that comparison.
        k_index = _k_index()
        documents = {"doc1": {"report"}}
        a = build_index(k_index, documents)
        b = build_index(k_index, documents)
        assert a[0].label == b[0].label       # same lookup key
        assert a[0].value != b[0].value       # but unrecognisable ciphertext

    def test_rebuild_label_set_is_order_independent(self):
        # Dict insertion order must not affect which labels appear --
        # only doc_id sort order does (build_index sorts internally).
        # Values are excluded from the comparison for the same reason
        # as above: fresh nonces make them differ regardless.
        k_index = _k_index()
        docs_a = {"doc1": {"x"}, "doc2": {"x"}}
        docs_b = {"doc2": {"x"}, "doc1": {"x"}}
        labels_a = sorted(e.label for e in build_index(k_index, docs_a))
        labels_b = sorted(e.label for e in build_index(k_index, docs_b))
        assert labels_a == labels_b

    def test_different_k_index_produces_a_completely_different_index(self):
        documents = {"doc1": {"report"}}
        a = build_index(_k_index(), documents)
        b = build_index(_k_index(), documents)
        assert a[0].label != b[0].label
        assert a[0].value != b[0].value

    def test_shared_keyword_gets_sequential_counters_in_doc_id_order(self):
        # doc_id sort order determines which document gets counter 0.
        k_index = _k_index()
        entries = build_index(k_index, {"doc-b": {"x"}, "doc-a": {"x"}})
        k1 = keyword_label_key(k_index, "x")
        k2 = keyword_value_key(k_index, "x")
        import hmac
        from client.crypto import prf

        label_counter_0 = prf(k1, counter_to_bytes(0)).hex()
        label_counter_1 = prf(k1, counter_to_bytes(1)).hex()

        by_label = {e.label: e.value for e in entries}
        assert aes_gcm_decrypt(k2, by_label[label_counter_0]).decode() == "doc-a"
        assert aes_gcm_decrypt(k2, by_label[label_counter_1]).decode() == "doc-b"

    def test_no_label_collisions_across_many_keywords(self):
        k_index = _k_index()
        documents = {f"doc{i}": {f"keyword{i}", "shared"} for i in range(50)}
        entries = build_index(k_index, documents)
        labels = [e.label for e in entries]
        assert len(labels) == len(set(labels))

    def test_no_plaintext_keyword_or_doc_id_in_entries(self):
        k_index = _k_index()
        documents = {"secret-doc-id-123": {"confidential", "classified"}}
        entries = build_index(k_index, documents)
        for e in entries:
            assert b"confidential" not in e.value
            assert b"classified" not in e.value
            assert b"secret-doc-id-123" not in e.value
            assert "confidential" not in e.label
            assert "secret-doc-id-123" not in e.label


# ---------------------------------------------------------------------------
# integration with tokenizer.py (still client-side only, no cloud)
# ---------------------------------------------------------------------------

class TestWithRealTokenizer:
    def test_tokenized_documents_index_correctly(self):
        k_index = _k_index()
        corpus_text = {
            "doc1": "Quarterly financial report for Q3.",
            "doc2": "Invoice report attached, please review.",
        }
        documents = {doc_id: tokenize(text) for doc_id, text in corpus_text.items()}
        entries = build_index(k_index, documents)

        # "report" is a shared keyword -> 2 entries; "quarterly",
        # "financial", "invoice", "attached", "please", "review" are
        # each in exactly one doc -> 1 entry each ("q3" too, "for" is
        # a stopword and dropped).
        expected_pairs = sum(len(kws) for kws in documents.values())
        assert len(entries) == expected_pairs

        # Recover the two entries belonging to "report" by recomputing
        # its label key and the labels for counters 0 and 1 -- this is
        # exactly the lookup Phase 4's search will perform later.
        k1_report = keyword_label_key(k_index, "report")
        k2_report = keyword_value_key(k_index, "report")
        report_labels = {prf(k1_report, counter_to_bytes(i)).hex() for i in range(2)}

        recovered = {
            aes_gcm_decrypt(k2_report, e.value).decode()
            for e in entries
            if e.label in report_labels
        }
        assert recovered == {"doc1", "doc2"}
