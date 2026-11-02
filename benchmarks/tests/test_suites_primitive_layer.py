"""
Self-tests for suites B1-B3 and for benchmarks/run_all.py.

These do not check that the vault is fast -- that is what the benchmarks
themselves report, and a self-test asserting a performance threshold would
fail on a slower machine for no good reason. They check that the suites
MEASURE WHAT THEY CLAIM TO: that every declared benchmark actually produced
samples, that warm-ups are recorded and excluded, that Argon2id is never
batched, that the two scaling axes agree, that the correctness gates are
real, and that a suite which fails cannot be presented as one that
succeeded.

Every suite runs here at a deliberately tiny sizing, into a temporary
results directory, so the test suite stays fast and never touches the
recorded benchmark data.
"""

import dataclasses

import pytest

from benchmarks import config, run_all
from benchmarks.config import QUICK
from benchmarks.harness.recorder import (
    PHASE_MEASURE,
    PHASE_WARMUP,
    STATUS_FAILED,
    STATUS_NOT_RUN,
    STATUS_OK,
    Recorder,
    load_manifest,
    load_raw,
    measured_values,
    scalar_values,
    verify,
)
from benchmarks.suites import b1_primitives, b2_token_generation, b3_indexing

TINY = dataclasses.replace(
    QUICK,
    name="tiny",
    description="self-test sizing -- not a measurement",
    kdf_repeats=1,
    kdf_warmup=0,
    kdf_sweep_memory_kib=(8192,),
    kdf_sweep_time_cost=(1,),
    kdf_sweep_repeats=1,
    aead_sizes_bytes=(1024, 4096),
    aead_repeats=2,
    micro_batch=50,
    micro_repeats=2,
    index_corpus_sizes=(3, 5),
    index_repeats=2,
    default_warmup=1,
)


def _run_suite(module, tmp_path):
    recorder = Recorder(str(tmp_path), TINY.name, {"self_test": True}, config.SUITE_IDS)
    recorder.begin_suite(module.SUITE_ID)
    metadata = module.run(recorder, TINY)
    recorder.end_suite(module.SUITE_ID)
    recorder.finalize(extra={"suite_metadata": {module.SUITE_ID: metadata}})
    return metadata, load_raw(str(tmp_path), module.SUITE_ID)


# ---------------------------------------------------------------------------
# properties every suite must have
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def b1_result(tmp_path_factory):
    return _run_suite(b1_primitives, tmp_path_factory.mktemp("b1"))


@pytest.fixture(scope="module")
def b2_result(tmp_path_factory):
    return _run_suite(b2_token_generation, tmp_path_factory.mktemp("b2"))


@pytest.fixture(scope="module")
def b3_result(tmp_path_factory):
    return _run_suite(b3_indexing, tmp_path_factory.mktemp("b3"))


class TestCommonSuiteContract:
    @pytest.mark.parametrize("fixture_name", ["b1_result", "b2_result", "b3_result"])
    def test_every_declared_measure_produced_samples(self, fixture_name, request):
        metadata, rows = request.getfixturevalue(fixture_name)
        for name in metadata["measures"]:
            values = measured_values(rows, name) or scalar_values(rows, name)
            assert values, f"{name} is declared but produced no recorded samples"

    @pytest.mark.parametrize("fixture_name", ["b1_result", "b2_result", "b3_result"])
    def test_warmups_are_recorded_and_excluded_from_statistics(self, fixture_name, request):
        _, rows = request.getfixturevalue(fixture_name)
        phases = {r["phase"] for r in rows}
        assert PHASE_WARMUP in phases and PHASE_MEASURE in phases
        warm = [r for r in rows if r["phase"] == PHASE_WARMUP]
        assert warm, "no warm-up samples were recorded"
        # The discard is an aggregation rule: a warm-up row is on disk, and
        # measured_values() must not return it.
        for benchmark in {r["benchmark"] for r in warm}:
            n_measure = len([r for r in rows if r["benchmark"] == benchmark
                             and r["phase"] == PHASE_MEASURE])
            assert len(measured_values(rows, benchmark)) == n_measure

    @pytest.mark.parametrize("fixture_name", ["b1_result", "b2_result", "b3_result"])
    def test_metadata_names_the_real_implementations_under_test(self, fixture_name, request):
        metadata, _ = request.getfixturevalue(fixture_name)
        assert metadata["implementations_under_test"]
        for dotted in metadata["implementations_under_test"]:
            assert dotted.startswith("client."), (
                f"{dotted} is not a client/ implementation -- a benchmark must measure "
                f"the shipped code, not a reimplementation"
            )

    @pytest.mark.parametrize("fixture_name", ["b1_result", "b2_result", "b3_result"])
    def test_correctness_gates_were_performed(self, fixture_name, request):
        metadata, _ = request.getfixturevalue(fixture_name)
        assert metadata["correctness_gates"], "a suite recorded no correctness gates"

    @pytest.mark.parametrize("fixture_name", ["b1_result", "b2_result", "b3_result"])
    def test_all_timings_are_positive_and_finite(self, fixture_name, request):
        _, rows = request.getfixturevalue(fixture_name)
        for row in rows:
            if row["unit"] == "s":
                assert 0 < row["value"] < 3600, f"implausible duration in {row['benchmark']}"


# ---------------------------------------------------------------------------
# B1
# ---------------------------------------------------------------------------

class TestB1Primitives:
    def test_argon2id_is_never_batched(self, b1_result):
        """Batching a memory-hard KDF would be meaningless -- it is already
        five orders of magnitude above the clock floor."""
        _, rows = b1_result
        for row in rows:
            if row["benchmark"].startswith("argon2id") or row["benchmark"] == "vault_unlock":
                assert row["batch"] == 1

    def test_argon2id_and_the_micro_primitives_are_reported_separately(self, b1_result):
        _, rows = b1_result
        assert measured_values(rows, "argon2id_derive_master_key")
        assert measured_values(rows, "hmac_prf_keyword_input")
        argon = min(measured_values(rows, "argon2id_derive_master_key"))
        hmac_prf = max(measured_values(rows, "hmac_prf_keyword_input"))
        assert argon > hmac_prf * 100, (
            "Argon2id should be orders of magnitude slower than HMAC -- if it is not, "
            "the KDF is not doing the work its parameters ask for"
        )

    def test_shipped_argon2_parameters_are_recorded_with_the_timing(self, b1_result):
        from client import keymgmt

        _, rows = b1_result
        params = [r["params"] for r in rows if r["benchmark"] == "argon2id_derive_master_key"][0]
        assert params["time_cost"] == keymgmt.ARGON2_TIME_COST
        assert params["memory_cost_kib"] == keymgmt.ARGON2_MEMORY_COST_KIB
        assert params["parallelism"] == keymgmt.ARGON2_PARALLELISM
        assert params["shipped_parameters"] is True

    def test_the_sweep_marks_which_point_is_the_shipped_setting(self, b1_result):
        _, rows = b1_result
        sweep = [r for r in rows if r["benchmark"] == "argon2id_parameter_sweep"]
        assert sweep
        assert all("shipped_parameters" in r["params"] for r in sweep)

    def test_sweep_notes_state_it_is_not_a_tuning_recommendation(self, b1_result):
        _, rows = b1_result
        note = [r for r in rows if r["benchmark"] == "argon2id_parameter_sweep"][0]["notes"]
        assert "M1" in note and "NOT a recommendation" in note

    def test_aes_gcm_measured_at_every_configured_size(self, b1_result):
        _, rows = b1_result
        for size in TINY.aead_sizes_bytes:
            assert measured_values(rows, "aes_gcm_encrypt", {"payload_bytes": size})
            assert measured_values(rows, "aes_gcm_decrypt", {"payload_bytes": size})

    def test_ciphertext_expansion_is_a_measured_length_not_a_formula(self, b1_result):
        from client.crypto import NONCE_SIZE, TAG_SIZE

        _, rows = b1_result
        for size in TINY.aead_sizes_bytes:
            observed = scalar_values(rows, "aes_gcm_ciphertext_bytes", {"payload_bytes": size})
            assert observed == [float(size + NONCE_SIZE + TAG_SIZE)]

    def test_both_prf_call_sites_are_measured(self, b1_result):
        """F is called with a keyword at index/search time and with an
        8-byte counter per posting -- different input lengths, both worth
        measuring."""
        _, rows = b1_result
        assert measured_values(rows, "hmac_prf_keyword_input")
        assert measured_values(rows, "hmac_prf_counter_input")
        counter_params = [r["params"] for r in rows if r["benchmark"] == "hmac_prf_counter_input"][0]
        assert counter_params["input_bytes"] == 8

    def test_batched_micro_measurements_declare_that_they_are_batched(self, b1_result):
        _, rows = b1_result
        batched = [r for r in rows if r["batch"] > 1]
        assert batched
        for row in batched:
            assert "per-call mean" in row["params"]["batched_reason"]

    def test_a_broken_round_trip_would_stop_the_suite(self, monkeypatch, tmp_path):
        """The correctness gate is real: if AES-GCM stopped round-tripping,
        the suite raises instead of recording fast, meaningless numbers."""
        monkeypatch.setattr(b1_primitives, "aes_gcm_decrypt", lambda *a, **k: b"wrong")
        with pytest.raises(AssertionError, match="round trip failed"):
            _run_suite(b1_primitives, tmp_path)


# ---------------------------------------------------------------------------
# B2
# ---------------------------------------------------------------------------

class TestB2TokenGeneration:
    def test_corpus_fingerprint_is_recorded(self, b2_result):
        metadata, _ = b2_result
        assert len(metadata["corpus"]["fingerprint_sha256"]) == 64

    def test_keywords_come_from_the_corpus_and_vary_in_length(self, b2_result):
        metadata, _ = b2_result
        lengths = {c["keyword_chars"] for c in metadata["query_cases"]}
        assert len(lengths) >= 2, "token cost vs keyword length cannot be assessed"

    def test_every_query_case_is_measured_on_all_three_steps(self, b2_result):
        metadata, rows = b2_result
        for case in metadata["query_cases"]:
            for benchmark in ("normalise_query", "build_search_token",
                              "derive_value_key", "full_client_token_path"):
                assert measured_values(rows, benchmark, {"case": case["case"]}), (
                    f"{benchmark} missing for case {case['case']}"
                )

    def test_rejection_paths_are_measured(self, b2_result):
        _, rows = b2_result
        assert measured_values(rows, "rejected_multi_word_query")
        assert measured_values(rows, "rejected_stopword_only_query")

    def test_workload_parameters_are_recorded_per_sample(self, b2_result):
        _, rows = b2_result
        row = [r for r in rows if r["benchmark"] == "build_search_token"][0]
        for key in ("case", "keyword", "keyword_chars", "hmac_blocks", "batch"):
            assert key in row["params"]

    def test_token_determinism_gate_is_real(self, monkeypatch, tmp_path):
        import itertools

        counter = itertools.count()
        monkeypatch.setattr(
            b2_token_generation, "build_search_token",
            lambda k, w: bytes([next(counter) % 256]) * 32,
        )
        with pytest.raises(AssertionError, match="two different search tokens"):
            _run_suite(b2_token_generation, tmp_path)


# ---------------------------------------------------------------------------
# B3
# ---------------------------------------------------------------------------

class TestB3Indexing:
    def test_both_scaling_axes_are_recorded_at_every_size(self, b3_result):
        metadata, rows = b3_result
        assert set(metadata["scaling_axes"]) == {"documents", "total_postings"}
        for size in TINY.index_corpus_sizes:
            assert scalar_values(rows, "corpus_documents", {"documents": size}) == [float(size)]
            assert scalar_values(rows, "corpus_total_postings", {"documents": size})
            for benchmark in ("tokenize_corpus", "build_index", "tokenize_and_build"):
                params = [r["params"] for r in rows
                          if r["benchmark"] == benchmark and r["params"]["documents"] == size][0]
                assert params["total_postings"] > 0
                assert params["corpus_fingerprint_sha256"]

    def test_index_entry_count_equals_total_postings(self, b3_result):
        """The postings axis is only honest if build_index really emits one
        entry per (keyword, document) pair."""
        _, rows = b3_result
        for size in TINY.index_corpus_sizes:
            built = scalar_values(rows, "index_entries_built", {"documents": size})
            postings = scalar_values(rows, "corpus_total_postings", {"documents": size})
            assert built == postings

    def test_a_larger_corpus_has_more_postings(self, b3_result):
        _, rows = b3_result
        sizes = sorted(TINY.index_corpus_sizes)
        postings = [scalar_values(rows, "corpus_total_postings", {"documents": s})[0] for s in sizes]
        assert postings == sorted(postings) and postings[0] < postings[-1]

    def test_measurement_boundaries_are_structural_not_incidental(self, monkeypatch, tmp_path):
        """The three B3 benchmarks must differ in WHAT THEY DO, not merely in
        what they happened to measure on one machine.

        An earlier version of this test asserted
        `median(build_index) < median(tokenize_and_build)`. That is not a
        boundary check, it is a performance expectation wearing one: the two
        differ by the tokenize step, which on a fast machine with a small
        corpus is a few hundred microseconds, so ordinary scheduling noise can
        legitimately flip it -- as it did on Windows (8.5598 ms vs 8.3353 ms).
        A benchmark suite that fails because two close measurements landed in
        an unexpected order teaches you to ignore your own tests.

        What actually needs protecting is the instrumentation boundary:

          * `build_index` must be timed on ALREADY-tokenized input, so no
            tokenization happens inside its timed region;
          * `tokenize_and_build` must tokenize AND build inside its timed
            region;
          * `tokenize_corpus` must tokenize and NOT build.

        So this test captures the exact callables the suite hands to the
        timer, then runs each one with `client.tokenizer.tokenize` and
        `client.indexer.build_index` instrumented, and counts the calls. It
        proves the boundary directly and involves no clock at all, so it
        cannot flake -- and it would fail immediately if someone moved
        tokenization inside the build_index timing.
        """
        profile = dataclasses.replace(TINY, index_corpus_sizes=(3,), index_repeats=1)

        # Pair each timed callable with the benchmark name it is recorded under.
        # run() calls measure(fn, ...) and then add_measurement(name, ..., m)
        # immediately afterwards, so the most recently captured callable is the
        # one belonging to the benchmark being recorded.
        captured = []
        real_measure = b3_indexing.measure

        def capturing_measure(fn, **kwargs):
            captured.append(fn)
            return real_measure(fn, **kwargs)

        monkeypatch.setattr(b3_indexing, "measure", capturing_measure)

        timed_callable = {}

        class PairingRecorder(Recorder):
            def add_measurement(self, suite, benchmark, params, measurement, unit="s", notes=None):
                timed_callable[benchmark] = captured[-1]
                return super().add_measurement(suite, benchmark, params, measurement, unit, notes)

        recorder = PairingRecorder(str(tmp_path), profile.name, {"self_test": True}, config.SUITE_IDS)
        recorder.begin_suite(b3_indexing.SUITE_ID)
        b3_indexing.run(recorder, profile)
        recorder.end_suite(b3_indexing.SUITE_ID)

        assert set(timed_callable) == {"tokenize_corpus", "build_index", "tokenize_and_build"}

        # Instrument the two shipped functions the suite calls.
        calls = {"tokenize": 0, "build_index": 0}
        build_index_inputs = []
        real_tokenize = b3_indexing.tokenize
        real_build_index = b3_indexing.build_index

        def counting_tokenize(text):
            calls["tokenize"] += 1
            return real_tokenize(text)

        def counting_build_index(k_index, documents):
            calls["build_index"] += 1
            build_index_inputs.append(documents)
            return real_build_index(k_index, documents)

        monkeypatch.setattr(b3_indexing, "tokenize", counting_tokenize)
        monkeypatch.setattr(b3_indexing, "build_index", counting_build_index)

        def run_and_count(benchmark):
            calls["tokenize"] = calls["build_index"] = 0
            timed_callable[benchmark]()
            return dict(calls)

        n_documents = profile.index_corpus_sizes[0]

        assert run_and_count("tokenize_corpus") == {"tokenize": n_documents, "build_index": 0}, (
            "the tokenize_corpus timing must cover tokenization only"
        )
        assert run_and_count("build_index") == {"tokenize": 0, "build_index": 1}, (
            "the build_index timing must NOT include tokenization -- its input is "
            "prepared in the untimed setup phase"
        )
        assert run_and_count("tokenize_and_build") == {"tokenize": n_documents, "build_index": 1}, (
            "the tokenize_and_build timing must cover both steps"
        )

        # ...and the input build_index was timed on really is tokenized output:
        # doc_id -> set of keywords, not raw document text.
        timed_input = build_index_inputs[1]  # the build_index-only invocation
        assert isinstance(timed_input, dict) and timed_input
        for doc_id, keywords in timed_input.items():
            assert isinstance(doc_id, str) and len(doc_id) == 32
            assert isinstance(keywords, set) and keywords
            assert all(isinstance(word, str) for word in keywords)

    def test_the_combined_benchmark_is_not_a_duplicate_of_the_build_benchmark(self, b3_result):
        """`tokenize_and_build` exists to be checked against the sum of its
        parts, so it must be recorded as its own benchmark at every corpus
        size rather than aliasing one of them."""
        _, rows = b3_result
        for size in TINY.index_corpus_sizes:
            for benchmark in ("tokenize_corpus", "build_index", "tokenize_and_build"):
                assert measured_values(rows, benchmark, {"documents": size})

    def test_index_entry_shape_is_recorded(self, b3_result):
        _, rows = b3_result
        size = TINY.index_corpus_sizes[0]
        assert scalar_values(rows, "index_entry_label_chars", {"documents": size}) == [64.0]
        assert scalar_values(rows, "index_entry_value_bytes", {"documents": size})[0] > 32

    def test_label_stability_gate_is_real(self, monkeypatch, tmp_path):
        """If build_index stopped assigning deterministic labels, rebuilds
        would orphan index rows -- the suite must refuse to measure that."""
        import itertools

        from client.indexer import IndexEntry

        real_build = b3_indexing.build_index
        counter = itertools.count()

        def unstable(k_index, documents):
            entries = real_build(k_index, documents)
            return [IndexEntry(label=f"{next(counter):064x}", value=e.value) for e in entries]

        monkeypatch.setattr(b3_indexing, "build_index", unstable)
        with pytest.raises(AssertionError, match="different labels"):
            _run_suite(b3_indexing, tmp_path)


# ---------------------------------------------------------------------------
# run_all
# ---------------------------------------------------------------------------

class TestRunAll:
    def test_a_failing_suite_is_recorded_as_failed_and_the_run_reports_it(self, monkeypatch, tmp_path):
        class Exploding:
            SUITE_ID = "b1_primitives"
            TITLE = "deliberately failing suite"

            @staticmethod
            def run(recorder, profile):
                raise RuntimeError("simulated measurement failure")

        monkeypatch.setitem(run_all.SUITES, "b1_primitives", Exploding)
        exit_code = run_all.main([
            "--profile", "quick", "--suites", "b1_primitives",
            "--results-dir", str(tmp_path),
        ])
        assert exit_code == 1
        entry = load_manifest(str(tmp_path))["suites"]["b1_primitives"]
        assert entry["status"] == STATUS_FAILED
        assert "simulated measurement failure" in entry["error"]

    def test_unrun_suites_stay_not_run(self, monkeypatch, tmp_path):
        class Trivial:
            SUITE_ID = "b1_primitives"
            TITLE = "trivial"

            @staticmethod
            def run(recorder, profile):
                from benchmarks.harness.timing import measure
                recorder.add_measurement("b1_primitives", "noop", {}, measure(lambda: None, repeats=2, warmup=1))
                return {"measures": ["noop"], "implementations_under_test": ["client.crypto.prf"],
                        "correctness_gates": ["none needed"]}

        monkeypatch.setitem(run_all.SUITES, "b1_primitives", Trivial)
        assert run_all.main([
            "--profile", "quick", "--suites", "b1_primitives", "--results-dir", str(tmp_path),
        ]) == 0
        suites = load_manifest(str(tmp_path))["suites"]
        assert suites["b1_primitives"]["status"] == STATUS_OK
        for other in ("b2_token_generation", "b3_indexing", "b4_upload_rebuild",
                      "b5_search", "b6_storage"):
            assert suites[other]["status"] == STATUS_NOT_RUN
        assert verify(str(tmp_path)) == []

    def test_dataset_role_and_profile_sizing_are_recorded(self, monkeypatch, tmp_path):
        class Trivial:
            SUITE_ID = "b1_primitives"
            TITLE = "trivial"

            @staticmethod
            def run(recorder, profile):
                from benchmarks.harness.timing import measure
                recorder.add_measurement("b1_primitives", "noop", {}, measure(lambda: None, repeats=1, warmup=0))
                return {"measures": ["noop"], "implementations_under_test": ["client.crypto.prf"],
                        "correctness_gates": []}

        monkeypatch.setitem(run_all.SUITES, "b1_primitives", Trivial)
        run_all.main([
            "--profile", "quick", "--suites", "b1_primitives",
            "--results-dir", str(tmp_path), "--dataset-role", "development",
            "--label", "unit test",
        ])
        manifest = load_manifest(str(tmp_path))
        assert manifest["dataset_role"] == "development"
        assert manifest["label"] == "unit test"
        assert manifest["profile_sizing"]["name"] == "quick"
        assert manifest["command"]

    def test_default_results_directory_separates_profiles(self):
        quick = run_all.parse_args(["--profile", "quick"])
        full = run_all.parse_args(["--profile", "full"])
        assert quick.results_dir is None and full.results_dir is None
        assert quick.profile != full.profile

    def test_unknown_suite_is_refused(self):
        with pytest.raises(SystemExit):
            run_all.main(["--suites", "b9_imaginary", "--results-dir", "/tmp/never"])
