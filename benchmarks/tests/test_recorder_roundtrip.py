"""
Self-tests for benchmarks/harness/recorder.py -- the evidence trail.

These check the three guarantees the report depends on:

  1. every sample written, warm-ups included and labelled;
  2. a suite that did not run cannot be mistaken for one that did;
  3. a raw file edited after the run breaks verification loudly.

Guarantee 3 is the one worth arguing about, so it is tested by
actually tampering with a results directory and asserting the harness
notices -- the same style of evidence-driven check Phase 6 used
against the vault itself.
"""

import json
import os

import pytest

from benchmarks.harness.recorder import (
    PHASE_MEASURE,
    PHASE_SCALAR,
    PHASE_WARMUP,
    STATUS_FAILED,
    STATUS_NOT_RUN,
    STATUS_OK,
    Recorder,
    aggregate,
    load_manifest,
    load_raw,
    measured_values,
    scalar_values,
    verify,
)
from benchmarks.harness.timing import Measurement, summarize


def _measurement(samples, warmups=(), batch=1):
    m = Measurement(batch=batch)
    m.samples = list(samples)
    m.warmup_samples = list(warmups)
    return m


@pytest.fixture
def recorder(tmp_path):
    return Recorder(
        results_dir=str(tmp_path),
        profile_name="unit-test",
        environment={"platform": "test-platform"},
        declared_suites=["suite_a", "suite_b"],
    )


class TestEverySampleIsWritten:
    def test_warmups_and_measurements_are_both_recorded_and_labelled(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.add_measurement(
            "suite_a", "op", {"size": 1024}, _measurement([0.1, 0.2, 0.3], warmups=[9.9, 8.8])
        )
        recorder.end_suite("suite_a")

        rows = load_raw(str(tmp_path), "suite_a")
        assert len(rows) == 5, "no sample may be dropped at write time"
        assert [r["phase"] for r in rows] == [PHASE_WARMUP] * 2 + [PHASE_MEASURE] * 3
        assert [r["value"] for r in rows if r["phase"] == PHASE_WARMUP] == [9.9, 8.8]

    def test_aggregation_excludes_warmups_but_the_data_survives(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "op", {}, _measurement([1.0, 2.0, 3.0], warmups=[100.0]))
        recorder.end_suite("suite_a")

        rows = load_raw(str(tmp_path), "suite_a")
        assert 100.0 in [r["value"] for r in rows]
        assert measured_values(rows, "op") == [1.0, 2.0, 3.0]
        assert aggregate(str(tmp_path), "suite_a", "op").mean == pytest.approx(2.0)

    def test_recomputed_statistics_match_the_in_memory_ones(self, recorder, tmp_path):
        samples = [0.011, 0.009, 0.0105, 0.0098, 0.0301]
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "op", {}, _measurement(samples))
        recorder.end_suite("suite_a")
        recorder.finalize()

        from_disk = aggregate(str(tmp_path), "suite_a", "op")
        in_memory = summarize(samples)
        assert from_disk == in_memory, "the report must be a view over the raw file"

    def test_parameters_separate_configurations_of_one_benchmark(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "enc", {"size": 1024}, _measurement([1.0, 1.1]))
        recorder.add_measurement("suite_a", "enc", {"size": 4096}, _measurement([4.0, 4.1]))
        recorder.end_suite("suite_a")

        rows = load_raw(str(tmp_path), "suite_a")
        assert measured_values(rows, "enc", {"size": 1024}) == [1.0, 1.1]
        assert measured_values(rows, "enc", {"size": 4096}) == [4.0, 4.1]
        assert len(measured_values(rows, "enc")) == 4

    def test_scalars_are_recorded_and_kept_apart_from_timings(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "enc", {}, _measurement([1.0]))
        recorder.add_scalar("suite_a", "ciphertext_size", {"doc": 3}, 4124, "bytes")
        recorder.end_suite("suite_a")

        rows = load_raw(str(tmp_path), "suite_a")
        assert scalar_values(rows, "ciphertext_size") == [4124.0]
        assert measured_values(rows, "ciphertext_size") == [], "a scalar is not a timing sample"
        assert [r["phase"] for r in rows if r["benchmark"] == "ciphertext_size"] == [PHASE_SCALAR]

    def test_recording_without_begin_suite_is_refused(self, recorder):
        with pytest.raises(RuntimeError):
            recorder.add_measurement("suite_a", "op", {}, _measurement([1.0]))

    def test_batch_size_travels_with_the_sample(self, recorder, tmp_path):
        """A batched sample is a per-call mean, and the report has to be
        able to say so -- which it can only do if `batch` is recorded."""
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "prf", {}, _measurement([1e-6], batch=5000))
        recorder.end_suite("suite_a")
        assert load_raw(str(tmp_path), "suite_a")[0]["batch"] == 5000


class TestASuiteThatDidNotRunCannotLookLikeOneThatDid:
    def test_undeclared_execution_leaves_not_run_in_the_manifest(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "op", {}, _measurement([1.0]))
        recorder.end_suite("suite_a")
        recorder.finalize()

        suites = load_manifest(str(tmp_path))["suites"]
        assert suites["suite_a"]["status"] == STATUS_OK
        assert suites["suite_a"]["ran_in_this_run"] is True
        assert suites["suite_b"]["status"] == STATUS_NOT_RUN
        assert suites["suite_b"]["ran_in_this_run"] is False

    def test_a_failed_suite_is_recorded_as_failed_with_its_error(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.end_suite("suite_a", status=STATUS_FAILED, error="cloud process died")
        recorder.finalize()

        entry = load_manifest(str(tmp_path))["suites"]["suite_a"]
        assert entry["status"] == STATUS_FAILED
        assert "cloud process died" in entry["error"]

    def test_finalize_closes_an_abandoned_suite_as_failed(self, recorder, tmp_path):
        """An interrupted run must not leave a half-written suite
        looking complete."""
        recorder.begin_suite("suite_a")
        recorder.add_measurement("suite_a", "op", {}, _measurement([1.0]))
        recorder.finalize()  # end_suite never called

        entry = load_manifest(str(tmp_path))["suites"]["suite_a"]
        assert entry["status"] == STATUS_FAILED
        assert "end_suite" in entry["error"]

    def test_manifest_carries_profile_and_environment(self, recorder, tmp_path):
        recorder.begin_suite("suite_a")
        recorder.end_suite("suite_a")
        recorder.finalize()
        manifest = load_manifest(str(tmp_path))
        assert manifest["profile"] == "unit-test"
        assert manifest["environment"]["platform"] == "test-platform"
        assert manifest["run_id"] and manifest["started_at"] and manifest["finished_at"]
        assert manifest["wall_clock_seconds"] >= 0


class TestIntegrityVerification:
    def _one_good_run(self, tmp_path):
        rec = Recorder(str(tmp_path), "unit-test", {}, ["suite_a"])
        rec.begin_suite("suite_a")
        rec.add_measurement("suite_a", "op", {}, _measurement([1.0, 2.0]))
        rec.end_suite("suite_a")
        rec.finalize()
        return rec

    def test_an_untouched_run_verifies_clean(self, tmp_path):
        self._one_good_run(tmp_path)
        assert verify(str(tmp_path)) == []

    def test_an_edited_raw_file_is_detected(self, tmp_path):
        """Hand-editing a measurement is exactly the failure mode this
        phase must make impossible to do quietly."""
        self._one_good_run(tmp_path)
        raw = tmp_path / "raw" / "suite_a.jsonl"
        rows = [json.loads(line) for line in raw.read_text().splitlines()]
        rows[0]["value"] = 0.0000001  # a flattering number
        raw.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")

        problems = verify(str(tmp_path))
        assert problems and "has changed since the run" in problems[0]

    def test_an_appended_row_is_detected(self, tmp_path):
        self._one_good_run(tmp_path)
        raw = tmp_path / "raw" / "suite_a.jsonl"
        with open(raw, "a", encoding="utf-8") as f:
            f.write(json.dumps({"benchmark": "op", "phase": PHASE_MEASURE, "value": 0.0}) + "\n")
        assert verify(str(tmp_path))

    def test_a_deleted_raw_file_is_detected(self, tmp_path):
        self._one_good_run(tmp_path)
        os.remove(tmp_path / "raw" / "suite_a.jsonl")
        problems = verify(str(tmp_path))
        assert problems and "missing" in problems[0]

    def test_a_results_directory_with_no_run_is_reported_not_assumed_empty(self, tmp_path):
        problems = verify(str(tmp_path))
        assert problems and "no run has completed here" in problems[0]

    def test_stale_data_from_a_previous_run_does_not_pass_as_current(self, tmp_path):
        """Re-running one suite must not let another suite's older raw
        file be presented as part of the new run."""
        first = Recorder(str(tmp_path), "unit-test", {}, ["suite_a", "suite_b"])
        for suite in ("suite_a", "suite_b"):
            first.begin_suite(suite)
            first.add_measurement(suite, "op", {}, _measurement([1.0]))
            first.end_suite(suite)
        first.finalize()

        second = Recorder(str(tmp_path), "unit-test", {}, ["suite_a", "suite_b"])
        second.begin_suite("suite_a")
        second.add_measurement("suite_a", "op", {}, _measurement([2.0]))
        second.end_suite("suite_a")
        second.finalize()

        suites = load_manifest(str(tmp_path))["suites"]
        assert suites["suite_a"]["ran_in_this_run"] is True
        assert suites["suite_b"]["ran_in_this_run"] is False, (
            "suite_b's raw file still exists on disk from the earlier run; the "
            "manifest is what stops the report treating it as current"
        )
        assert verify(str(tmp_path)) == []
