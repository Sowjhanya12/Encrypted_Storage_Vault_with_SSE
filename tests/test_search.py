"""
tests/test_search.py -- Unit tests for client/search.py.

Pure client-side: no network, no cloud/. Uses client/indexer.py's
build_index() directly to produce real entries to search against, so
these tests exercise the actual index-then-search contract, not a
hand-rolled fixture that might not match what indexer.py really does.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.crypto import KEY_SIZE, DecryptionError, aes_gcm_encrypt  # noqa: E402
from client.indexer import build_index, keyword_label_key, keyword_value_key  # noqa: E402
from client.search import (  # noqa: E402
    AmbiguousQueryError,
    build_search_token,
    decrypt_search_results,
    normalise_conjunctive_query,
    normalise_query,
)
from client.tokenizer import tokenize  # noqa: E402


def _k_index() -> bytes:
    return os.urandom(KEY_SIZE)


# ---------------------------------------------------------------------------
# normalise_query -- the single-keyword scope boundary
# ---------------------------------------------------------------------------

class TestNormaliseQuery:
    def test_single_word_query_normalises_like_the_tokenizer(self):
        assert normalise_query("Report!") == "report"

    def test_empty_query_is_ambiguous(self):
        with pytest.raises(AmbiguousQueryError):
            normalise_query("")

    def test_only_stopwords_is_ambiguous(self):
        with pytest.raises(AmbiguousQueryError):
            normalise_query("the a is")

    def test_only_punctuation_is_ambiguous(self):
        with pytest.raises(AmbiguousQueryError):
            normalise_query("!!! ...")

    def test_multi_word_query_is_ambiguous(self):
        # normalise_query() itself is UNCHANGED and still strictly
        # single-keyword -- rejected, not silently narrowed to one
        # word. Multi-keyword search is now supported, but through the
        # separate normalise_conjunctive_query() below, not by relaxing
        # this function's contract.
        with pytest.raises(AmbiguousQueryError):
            normalise_query("annual report")

    def test_ambiguous_query_error_is_a_value_error(self):
        assert issubclass(AmbiguousQueryError, ValueError)

    def test_case_and_punctuation_do_not_affect_the_result(self):
        assert normalise_query("REPORT") == normalise_query("report,") == normalise_query("  report  ")


# ---------------------------------------------------------------------------
# normalise_conjunctive_query -- multi-keyword AND, additive to the above
# ---------------------------------------------------------------------------

class TestNormaliseConjunctiveQuery:
    def test_single_word_query_matches_normalise_query(self):
        assert normalise_conjunctive_query("Report!") == {"report"}

    def test_two_word_query_returns_both_keywords(self):
        assert normalise_conjunctive_query("annual report") == {"annual", "report"}

    def test_result_is_a_set_word_order_is_discarded(self):
        assert normalise_conjunctive_query("annual report") == normalise_conjunctive_query("report annual")

    def test_duplicate_words_collapse_to_one_keyword(self):
        assert normalise_conjunctive_query("report report report") == {"report"}

    def test_stopwords_are_dropped_leaving_only_real_keywords(self):
        assert normalise_conjunctive_query("the annual report") == {"annual", "report"}

    def test_empty_query_is_still_ambiguous(self):
        with pytest.raises(AmbiguousQueryError):
            normalise_conjunctive_query("")

    def test_only_stopwords_is_still_ambiguous(self):
        with pytest.raises(AmbiguousQueryError):
            normalise_conjunctive_query("the a is")

    def test_only_punctuation_is_still_ambiguous(self):
        with pytest.raises(AmbiguousQueryError):
            normalise_conjunctive_query("!!! ...")

    def test_returns_a_frozenset(self):
        assert isinstance(normalise_conjunctive_query("report"), frozenset)


# ---------------------------------------------------------------------------
# build_search_token
# ---------------------------------------------------------------------------

class TestBuildSearchToken:
    def test_matches_indexer_keyword_label_key(self):
        # Not a coincidence -- build_search_token literally calls the
        # same function indexer.py uses to build the index.
        k_index = _k_index()
        assert build_search_token(k_index, "report") == keyword_label_key(k_index, "report")

    def test_deterministic(self):
        k_index = _k_index()
        assert build_search_token(k_index, "report") == build_search_token(k_index, "report")

    def test_different_keywords_different_tokens(self):
        k_index = _k_index()
        assert build_search_token(k_index, "report") != build_search_token(k_index, "invoice")

    def test_is_32_bytes(self):
        assert len(build_search_token(_k_index(), "report")) == 32


# ---------------------------------------------------------------------------
# decrypt_search_results
# ---------------------------------------------------------------------------

class TestDecryptSearchResults:
    def test_empty_results_decrypt_to_empty_set(self):
        assert decrypt_search_results(_k_index(), "report", []) == set()

    def test_single_result_decrypts_correctly(self):
        k_index = _k_index()
        k2 = keyword_value_key(k_index, "report")
        value = aes_gcm_encrypt(k2, b"doc-42")
        assert decrypt_search_results(k_index, "report", [value]) == {"doc-42"}

    def test_multiple_results_decrypt_correctly(self):
        k_index = _k_index()
        k2 = keyword_value_key(k_index, "report")
        values = [aes_gcm_encrypt(k2, doc_id.encode()) for doc_id in ("doc-a", "doc-b", "doc-c")]
        assert decrypt_search_results(k_index, "report", values) == {"doc-a", "doc-b", "doc-c"}

    def test_wrong_keyword_fails_to_decrypt(self):
        # Values encrypted under K2 for "report" cannot be decrypted
        # using the K2 derived for a different keyword.
        k_index = _k_index()
        k2_report = keyword_value_key(k_index, "report")
        value = aes_gcm_encrypt(k2_report, b"doc-1")
        with pytest.raises(DecryptionError):
            decrypt_search_results(k_index, "invoice", [value])

    def test_wrong_k_index_fails_to_decrypt(self):
        k_index_a = _k_index()
        k_index_b = _k_index()
        k2_a = keyword_value_key(k_index_a, "report")
        value = aes_gcm_encrypt(k2_a, b"doc-1")
        with pytest.raises(DecryptionError):
            decrypt_search_results(k_index_b, "report", [value])

    def test_tampered_value_fails_to_decrypt(self):
        k_index = _k_index()
        k2 = keyword_value_key(k_index, "report")
        value = bytearray(aes_gcm_encrypt(k2, b"doc-1"))
        value[-1] ^= 0x01  # flip a bit in the authentication tag
        with pytest.raises(DecryptionError):
            decrypt_search_results(k_index, "report", [bytes(value)])

    def test_one_bad_value_aborts_the_whole_batch(self):
        # Fail loud, not silent-partial: one tampered entry among
        # otherwise-good ones must raise, not quietly return the rest.
        k_index = _k_index()
        k2 = keyword_value_key(k_index, "report")
        good = aes_gcm_encrypt(k2, b"doc-good")
        bad = bytearray(aes_gcm_encrypt(k2, b"doc-bad"))
        bad[-1] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt_search_results(k_index, "report", [good, bytes(bad)])


# ---------------------------------------------------------------------------
# end-to-end against a real build_index() output (still no network)
# ---------------------------------------------------------------------------

class TestEndToEndAgainstRealIndex:
    def test_search_recovers_the_correct_doc_ids(self):
        k_index = _k_index()
        documents = {
            "doc1": tokenize("quarterly financial report"),
            "doc2": tokenize("invoice report attached"),
            "doc3": tokenize("unrelated memo"),
        }
        entries = build_index(k_index, documents)
        by_label = {e.label: e.value for e in entries}

        keyword = normalise_query("Report")
        token = build_search_token(k_index, keyword)

        # Simulate the cloud's loop locally (no Flask/network needed
        # for this test -- that integration is covered separately).
        from client.crypto import prf
        from client.indexer import counter_to_bytes

        matched_values = []
        counter = 0
        while True:
            label = prf(token, counter_to_bytes(counter)).hex()
            if label not in by_label:
                break
            matched_values.append(by_label[label])
            counter += 1

        result = decrypt_search_results(k_index, keyword, matched_values)
        assert result == {"doc1", "doc2"}

    def test_search_for_unindexed_keyword_returns_empty_set(self):
        k_index = _k_index()
        documents = {"doc1": tokenize("quarterly financial report")}
        build_index(k_index, documents)  # built, but "nonexistentword" is not in it

        keyword = normalise_query("nonexistentword")
        # No entries at all match this token -- decrypt_search_results
        # on an empty list must not error.
        assert decrypt_search_results(k_index, keyword, []) == set()
