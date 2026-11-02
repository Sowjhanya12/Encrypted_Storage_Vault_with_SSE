"""
Self-tests for benchmarks/config.py.

The point of these is that `quick` and `full` must differ ONLY in how
much work they do. If a profile could change what is measured or how a
document is generated, a quick run would stop being evidence that the
full run is sound, and two runs could not be compared.
"""

import pytest

from benchmarks import config
from benchmarks.config import FULL, PROFILES, QUICK, SUITE_IDS, get_profile


class TestProfilesDifferOnlyInSize:
    @pytest.mark.parametrize(
        "attribute",
        [
            "kdf_repeats", "kdf_sweep_repeats", "aead_repeats", "micro_repeats",
            "index_repeats", "upload_max_documents", "rebuild_repeats", "search_repeats",
            "storage_corpus_size",
        ],
    )
    def test_full_is_at_least_as_large_as_quick(self, attribute):
        assert getattr(FULL, attribute) >= getattr(QUICK, attribute)

    def test_full_uses_the_agreed_200_document_maximum(self):
        assert FULL.upload_max_documents == 200
        assert FULL.rebuild_checkpoints[-1] == 200

    def test_corpus_generation_parameters_are_not_per_profile(self):
        """Seed, vocabulary and document length are module constants, so
        document n is byte-identical under either profile."""
        for name in ("CORPUS_SEED", "CORPUS_VOCABULARY_SIZE", "CORPUS_ZIPF_EXPONENT", "CORPUS_WORDS_PER_DOCUMENT"):
            assert hasattr(config, name)
        assert not any(hasattr(p, "corpus_seed") for p in PROFILES.values())


class TestSizingIsStatisticallyUsable:
    def test_full_repeat_counts_support_a_confidence_interval(self):
        """n >= 2 everywhere (a CI needs dispersion), and n >= 10 for the
        cheap operations that carry the headline figures."""
        assert FULL.kdf_repeats >= 10
        assert FULL.aead_repeats >= 10
        assert FULL.index_repeats >= 10
        assert FULL.search_repeats >= 10
        assert FULL.rebuild_repeats >= 2

    def test_aead_sizes_span_small_and_large_files(self):
        """Small sizes expose per-call fixed cost, large sizes expose
        steady-state throughput; a range covering only one of the two
        would support only half the conclusion."""
        assert min(FULL.aead_sizes_bytes) <= 4096
        assert max(FULL.aead_sizes_bytes) >= 8 * 1024 * 1024

    def test_kdf_sweep_brackets_the_shipped_parameters(self):
        from client import keymgmt

        assert keymgmt.ARGON2_MEMORY_COST_KIB in FULL.kdf_sweep_memory_kib
        assert keymgmt.ARGON2_TIME_COST in FULL.kdf_sweep_time_cost
        assert min(FULL.kdf_sweep_memory_kib) < keymgmt.ARGON2_MEMORY_COST_KIB
        assert max(FULL.kdf_sweep_memory_kib) > keymgmt.ARGON2_MEMORY_COST_KIB

    def test_search_match_counts_are_increasing_and_start_at_one(self):
        assert FULL.search_match_counts[0] == 1
        assert list(FULL.search_match_counts) == sorted(set(FULL.search_match_counts))

    def test_rebuild_checkpoints_fit_within_the_corpus_that_gets_uploaded(self):
        assert max(FULL.rebuild_checkpoints) <= FULL.upload_max_documents
        assert max(QUICK.rebuild_checkpoints) <= QUICK.upload_max_documents

    def test_search_scaling_experiment_holds_k_fixed(self):
        """The 'latency vs index size' experiment is only interpretable
        if the result count does not move with the corpus."""
        assert FULL.search_scaling_fixed_k in FULL.search_match_counts
        assert len(FULL.search_scaling_corpus_sizes) >= 3


class TestProfileLookupAndSummary:
    def test_get_profile_returns_the_named_profile(self):
        assert get_profile("full") is FULL
        assert get_profile("quick") is QUICK

    def test_unknown_profile_fails_loudly(self):
        with pytest.raises(SystemExit):
            get_profile("medium")

    def test_profiles_are_frozen(self):
        with pytest.raises(Exception):
            FULL.upload_max_documents = 5

    def test_summary_covers_the_sizing_of_every_implemented_suite(self):
        summary = FULL.summary()
        for suite in ("b1_primitives", "b2_token_generation", "b3_indexing"):
            assert suite in summary, f"{suite} sizing is missing from the manifest summary"
        assert summary["corpus"]["seed"] == config.CORPUS_SEED
