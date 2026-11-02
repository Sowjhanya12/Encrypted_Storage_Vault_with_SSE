"""
Self-tests for benchmarks/harness/corpus.py.

Everything Phase 7 claims about comparability rests on this generator, so
these tests attack the properties the claims depend on:

  * byte-for-byte determinism, including across separate OS processes;
  * prefix stability, so a scaling curve varies the corpus SIZE and
    nothing else;
  * exact probe-keyword document frequencies under the vault's real
    tokenizer, so suite B5's x-axis means what it says;
  * that the generated text is actually work for the tokenizer, rather
    than a pre-cleaned word list that would understate indexing cost.
"""

import subprocess
import sys

import pytest

from benchmarks import config
from benchmarks.harness import corpus
from benchmarks.harness.corpus import (
    PROBE_PREFIX,
    build_vocabulary,
    corpus_fingerprint,
    documents_containing,
    generate_corpus,
    keyword_stats,
    probe_keyword,
    write_corpus_to_disk,
)
from client.tokenizer import MIN_TOKEN_LENGTH, STOPWORDS, tokenize

# Fingerprints recorded on 2026-08-27 (CPython 3.10, Linux x86_64). They pin
# the generator's output for all time: a change here means the corpus
# changed, and every previously recorded measurement stopped being
# comparable with every future one. If this test fails after a Python
# upgrade or on a different platform, that is a finding to report, not a
# constant to update quietly.
GOLDEN_FINGERPRINT_10_NO_PROBES = "53c8f2057add36d8bce07c61ed6e09698639fe9224f8df06ace431837117d8ee"
GOLDEN_FINGERPRINT_10_PROBES_1_5_10 = "717611e965868cdb6611ca361020356bd29cf318f50d0f2af58411a1825805f1"


class TestDeterminism:
    def test_two_calls_produce_identical_documents(self):
        a, b = generate_corpus(20), generate_corpus(20)
        assert [d.text for d in a] == [d.text for d in b]
        assert [d.filename for d in a] == [d.filename for d in b]

    def test_fingerprint_matches_the_recorded_golden_value(self):
        assert corpus_fingerprint(generate_corpus(10)) == GOLDEN_FINGERPRINT_10_NO_PROBES

    def test_fingerprint_with_probes_matches_the_recorded_golden_value(self):
        got = corpus_fingerprint(generate_corpus(10, probe_frequencies=(1, 5, 10)))
        assert got == GOLDEN_FINGERPRINT_10_PROBES_1_5_10

    def test_determinism_survives_a_separate_process(self):
        """In-process equality could come from caching. A fresh
        interpreter, with its own module import and its own RNG state, is
        the check that actually matters for 'the same corpus on your
        machine and mine'."""
        code = (
            "import sys; sys.path.insert(0, '.');"
            "from benchmarks.harness.corpus import generate_corpus, corpus_fingerprint;"
            "print(corpus_fingerprint(generate_corpus(10)))"
        )
        out = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=True
        )
        assert out.stdout.strip() == GOLDEN_FINGERPRINT_10_NO_PROBES

    def test_fingerprint_changes_when_the_corpus_changes(self):
        """A fingerprint that never moves would prove nothing."""
        assert corpus_fingerprint(generate_corpus(10)) != corpus_fingerprint(generate_corpus(11))
        assert corpus_fingerprint(generate_corpus(10)) != corpus_fingerprint(
            generate_corpus(10, probe_frequencies=(3,))
        )


class TestPrefixStability:
    def test_a_larger_corpus_extends_a_smaller_one(self):
        """Suite B3/B4/B5 scaling curves depend on this: at each size the
        corpus is 'the same documents plus more', so a bend in a curve is
        the system's behaviour and not the input changing shape."""
        small, large = generate_corpus(10), generate_corpus(200)
        assert [d.text for d in small] == [d.text for d in large[:10]]

    def test_prefix_stability_holds_with_a_fixed_probe_set(self):
        probes = (1, 5, 10)
        small = generate_corpus(10, probe_frequencies=probes)
        large = generate_corpus(50, probe_frequencies=probes)
        assert [d.text for d in small] == [d.text for d in large[:10]]

    def test_planting_probes_does_not_alter_document_bodies(self):
        """Probe tags are appended after the body, so a corpus with probes
        and one without differ only by the trailing tag line -- which is
        what lets suite B3 (no probes) and suite B5 (probes) be discussed
        as the same corpus."""
        plain = generate_corpus(5)
        tagged = generate_corpus(5, probe_frequencies=(2,))
        for p, t in zip(plain, tagged):
            assert t.text.startswith(p.text.rstrip("\n"))
            assert p.filename == t.filename


PROBE_FREQUENCIES = (1, 2, 5, 10, 25)


@pytest.fixture(scope="module")
def probe_docs():
    return generate_corpus(30, probe_frequencies=PROBE_FREQUENCIES)


@pytest.fixture(scope="module")
def realism_docs():
    return generate_corpus(25)


class TestProbeKeywords:
    PROBES = PROBE_FREQUENCIES

    @pytest.mark.parametrize("k", PROBES)
    def test_each_probe_appears_in_exactly_k_documents(self, probe_docs, k):
        """Measured through the vault's real tokenizer, not by string
        search -- a tag that the tokenizer dropped would silently make
        suite B5 measure a zero-result search."""
        assert len(documents_containing(probe_docs, probe_keyword(k))) == k

    def test_probe_tags_survive_tokenization_unchanged(self, probe_docs):
        assert probe_keyword(5) in probe_docs[0].keywords
        assert len(probe_keyword(5)) >= MIN_TOKEN_LENGTH
        assert probe_keyword(5) not in STOPWORDS

    def test_probes_land_in_the_lowest_indexed_documents(self, probe_docs):
        assert documents_containing(probe_docs, probe_keyword(5)) == [0, 1, 2, 3, 4]

    def test_generated_vocabulary_can_never_collide_with_a_probe(self):
        vocab = build_vocabulary()
        assert not any(w.startswith(PROBE_PREFIX) for w in vocab)
        assert not any(any(ch.isdigit() for ch in w) for w in vocab)

    def test_a_probe_larger_than_the_corpus_is_refused(self):
        """Silently planting a k=50 probe in a 10-document corpus would
        make the search-latency x-axis a lie."""
        with pytest.raises(ValueError, match="exceeds the corpus size"):
            generate_corpus(10, probe_frequencies=(50,))

    def test_invalid_probe_frequency_is_refused(self):
        with pytest.raises(ValueError):
            generate_corpus(10, probe_frequencies=(0,))


class TestVocabulary:
    def test_size_and_uniqueness(self):
        vocab = build_vocabulary()
        assert len(vocab) == config.CORPUS_VOCABULARY_SIZE
        assert len(set(vocab)) == len(vocab)

    def test_every_word_survives_the_vaults_tokenizer(self):
        """A vocabulary word that the tokenizer discards would inflate the
        corpus text without contributing an index posting, quietly
        decoupling 'words generated' from 'keywords indexed'."""
        for word in build_vocabulary()[:200]:
            assert tokenize(word) == {word}

    def test_no_vocabulary_word_is_a_stopword(self):
        assert not (set(build_vocabulary()) & STOPWORDS)


class TestCorpusRealism:
    def test_documents_are_the_intended_size(self, realism_docs):
        low, high = config.CORPUS_WORDS_PER_DOCUMENT
        for d in realism_docs:
            words = len(d.text.split())
            assert low * 0.6 <= words <= high * 1.4, f"doc {d.index}: {words} words"
            assert 1500 < d.size_bytes < 12000

    def test_text_contains_stopwords_and_punctuation_so_the_tokenizer_works(self, realism_docs):
        """If the corpus were a clean word list, indexing cost would be
        understated: no lower-casing, no splitting, no stop-word removal."""
        text = realism_docs[0].text
        assert any(f" {sw} " in text.lower() for sw in ("the", "and", "with", "for", "into"))
        assert "." in text and "-" in text
        assert any(ch.isupper() for ch in text)

    def test_deduplication_actually_bites(self, realism_docs):
        """Zipf-distributed draws repeat words heavily, so the keyword set
        must be much smaller than the word count -- otherwise the index
        would be measuring a corpus with no repetition, which no real
        document set has."""
        d = realism_docs[0]
        assert len(d.keywords) < len(d.text.split()) * 0.7

    def test_keyword_counts_vary_between_documents(self, realism_docs):
        counts = [len(d.keywords) for d in realism_docs]
        assert len(set(counts)) > len(counts) // 2, "a uniform corpus would flatter the results"

    def test_documents_are_valid_utf8_text_the_vault_would_accept(self, realism_docs):
        """client_app rejects non-UTF-8 uploads; a corpus it would refuse
        could never be benchmarked end to end."""
        for d in realism_docs:
            assert d.data.decode("utf-8") == d.text
            assert d.size_bytes == len(d.text)  # pure ASCII: bytes == characters

    def test_filenames_are_unique(self, realism_docs):
        names = [d.filename for d in realism_docs]
        assert len(set(names)) == len(names)


class TestKeywordStats:
    def test_totals_agree_with_the_tokenizer(self):
        docs = generate_corpus(20)
        stats = keyword_stats(docs)
        assert stats["documents"] == 20
        assert stats["total_postings"] == sum(len(d.keywords) for d in docs)
        assert stats["distinct_keywords"] == len(set().union(*(d.keywords for d in docs)))
        assert stats["total_text_bytes"] == sum(d.size_bytes for d in docs)

    def test_postings_is_the_index_row_count_not_the_distinct_word_count(self):
        """`total_postings` is the (keyword, document) pair count -- the
        quantity that becomes sse_index's row count and the cloud's
        'setup size' leakage."""
        stats = keyword_stats(generate_corpus(20))
        assert stats["total_postings"] > stats["distinct_keywords"]

    def test_empty_corpus_is_handled(self):
        assert keyword_stats([])["total_postings"] == 0
        assert generate_corpus(0) == []


class TestWriteCorpusToDisk:
    def test_round_trips_byte_identically(self, tmp_path):
        docs = generate_corpus(3)
        paths = write_corpus_to_disk(docs, str(tmp_path))
        assert len(paths) == 3
        for doc, path in zip(docs, paths):
            with open(path, "rb") as f:
                assert f.read() == doc.data
