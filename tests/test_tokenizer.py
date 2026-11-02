"""
tests/test_tokenizer.py -- Unit tests for client/tokenizer.py.

The property that matters most here isn't any individual rule -- it's
determinism: the same effective content must tokenize identically no
matter how it's phrased, because index-time and search-time
normalisation have to agree exactly (Section 05).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.tokenizer import STOPWORDS, tokenize  # noqa: E402


class TestBasicNormalisation:
    def test_lowercases(self):
        assert tokenize("REPORT") == {"report"}

    def test_strips_punctuation(self):
        assert tokenize("report, please!") == {"report", "please"}

    def test_splits_on_whitespace_variants(self):
        assert tokenize("report\tplease\nnow") == {"report", "please", "now"}

    def test_numbers_are_kept_as_tokens(self):
        assert "2024" in tokenize("Q3 2024 financial report")

    def test_mixed_alphanumeric_token_is_kept_whole(self):
        assert "invoice42" in tokenize("invoice42 pending")


class TestFiltering:
    def test_drops_single_character_tokens(self):
        result = tokenize("a b report c")
        assert "a" not in result
        assert "b" not in result
        assert "c" not in result
        assert "report" in result

    def test_removes_stopwords(self):
        result = tokenize("the report is on the table")
        assert "the" not in result
        assert "is" not in result
        assert "on" not in result
        assert "report" in result
        assert "table" in result

    def test_stopword_list_is_lowercase_only(self):
        # A sanity check on the fixture itself: if a stopword were
        # accidentally stored with mixed case, it would silently stop
        # filtering anything (tokenize() only ever produces lowercase
        # tokens to compare against it).
        assert all(w == w.lower() for w in STOPWORDS)


class TestDeduplication:
    def test_dedups_within_document(self):
        result = tokenize("report report report the report")
        assert result == {"report"}

    def test_returns_a_set(self):
        assert isinstance(tokenize("report file"), set)


class TestEdgeCases:
    def test_empty_string_returns_empty_set(self):
        assert tokenize("") == set()

    def test_only_stopwords_and_punctuation_returns_empty_set(self):
        assert tokenize("the a is, on!") == set()

    def test_only_punctuation_returns_empty_set(self):
        assert tokenize("!!! ... ---") == set()

    def test_non_string_input_raises_type_error(self):
        with pytest.raises(TypeError):
            tokenize(b"not a str")
        with pytest.raises(TypeError):
            tokenize(None)
        with pytest.raises(TypeError):
            tokenize(12345)

    def test_hyphens_and_apostrophes_act_as_delimiters(self):
        # Documented simplification: "don't" -> "don" + "t" (dropped
        # by the length filter), "well-known" -> "well" + "known".
        result = tokenize("don't miss the well-known report")
        assert "don" in result
        assert "t" not in result  # filtered by MIN_TOKEN_LENGTH
        assert "well" in result
        assert "known" in result


class TestDeterminismAcrossPhrasing:
    """This is the property Section 05 actually cares about: index
    time and search time must agree. We can't test search yet (Phase
    4), so we test the thing search will rely on -- that differently
    phrased but semantically-equivalent text normalises identically.
    """

    def test_same_words_different_case_and_punctuation_agree(self):
        a = tokenize("Quarterly Report: Confidential!")
        b = tokenize("quarterly report confidential")
        assert a == b

    def test_repeated_calls_are_identical(self):
        text = "The quick brown fox jumps over the lazy dog 2024"
        assert tokenize(text) == tokenize(text)

    def test_word_order_does_not_matter_for_the_resulting_set(self):
        a = tokenize("alpha beta gamma")
        b = tokenize("gamma alpha beta")
        assert a == b
