"""
Self-tests for benchmarks/harness/timing.py.

The statistics here are checked against values computed by hand (or by
an independent formula written out longhand in the test), never against
what the implementation happens to return -- a test that asserts
`summarize(x).mean == statistics.fmean(x)` would pass even if both were
wrong for the reporting purpose. Where a hand value is used, the
arithmetic is shown in the test so a reader can verify it without
running anything.
"""

import math
import time

import pytest

from benchmarks.harness.timing import (
    RESOLUTION_SAFETY_FACTOR,
    Stats,
    is_resolution_limited,
    measure,
    percentile_nearest_rank,
    summarize,
    throughput_mib_s,
    timer_resolution,
)


class TestSummarizeAgainstHandComputedValues:
    """Sample set: 1, 2, 3, 4, 100 (n = 5).

    sum = 110 -> mean = 22.0
    median (middle of the sorted five) = 3.0
    variance (sample, /(n-1)):
        deviations from 22: -21, -20, -19, -18, 78
        squares: 441, 400, 361, 324, 6084 = 7610
        7610 / 4 = 1902.5 -> stdev = sqrt(1902.5) = 43.6176...
    """

    SAMPLES = [1.0, 2.0, 3.0, 4.0, 100.0]

    def test_mean_and_median(self):
        s = summarize(self.SAMPLES)
        assert s.n == 5
        assert s.mean == pytest.approx(22.0)
        assert s.median == pytest.approx(3.0)

    def test_stdev_matches_hand_computation(self):
        s = summarize(self.SAMPLES)
        assert s.stdev == pytest.approx(math.sqrt(1902.5), rel=1e-12)

    def test_min_max(self):
        s = summarize(self.SAMPLES)
        assert s.minimum == 1.0
        assert s.maximum == 100.0

    def test_coefficient_of_variation_is_stdev_over_mean(self):
        s = summarize(self.SAMPLES)
        assert s.cv == pytest.approx(math.sqrt(1902.5) / 22.0)

    def test_median_is_robust_where_the_mean_is_not(self):
        """The whole reason the report leads with the median: one
        outlier moves the mean by 19.4 and the median not at all."""
        without_outlier = summarize([1.0, 2.0, 3.0, 4.0, 5.0])
        with_outlier = summarize(self.SAMPLES)
        assert with_outlier.median == without_outlier.median
        assert with_outlier.mean - without_outlier.mean == pytest.approx(19.0)

    def test_confidence_interval_uses_students_t_not_normal(self):
        """n = 5 -> df = 4 -> t = 2.776, not 1.96. Using the normal
        critical value here would understate the interval by ~30%."""
        s = summarize(self.SAMPLES)
        expected_half = 2.776 * math.sqrt(1902.5) / math.sqrt(5)
        assert s.ci95_half_width == pytest.approx(expected_half, rel=1e-9)
        assert s.ci95_low == pytest.approx(22.0 - expected_half)
        assert s.ci95_high == pytest.approx(22.0 + expected_half)

    def test_large_n_falls_back_to_the_normal_approximation(self):
        samples = [float(i) for i in range(100)]
        s = summarize(samples)
        expected_half = 1.96 * s.stdev / math.sqrt(100)
        assert s.ci95_half_width == pytest.approx(expected_half, rel=1e-9)


class TestDispersionOfASingleSample:
    def test_single_sample_reports_none_not_zero(self):
        """One observation has no measurable spread. Reporting 0.0
        would read as 'perfectly repeatable', which is a claim the data
        cannot support."""
        s = summarize([0.5])
        assert s.n == 1
        assert s.mean == s.median == s.minimum == s.maximum == 0.5
        assert s.stdev is None
        assert s.cv is None
        assert s.ci95_low is None and s.ci95_high is None and s.ci95_half_width is None

    def test_empty_sample_set_is_an_error_not_a_zero(self):
        with pytest.raises(ValueError):
            summarize([])


class TestPercentileNearestRank:
    def test_returns_an_actually_observed_value(self):
        samples = [10.0, 20.0, 30.0, 40.0]
        assert percentile_nearest_rank(samples, 95) in samples

    def test_nearest_rank_definition(self):
        """n = 20, ceil(0.95 * 20) = 19 -> the 19th smallest."""
        samples = [float(i) for i in range(1, 21)]
        assert percentile_nearest_rank(samples, 95) == 19.0

    def test_p100_is_the_maximum_and_p50_is_a_lower_median(self):
        samples = [1.0, 2.0, 3.0, 4.0]
        assert percentile_nearest_rank(samples, 100) == 4.0
        assert percentile_nearest_rank(samples, 50) == 2.0

    def test_unsorted_input_is_handled(self):
        assert percentile_nearest_rank([5.0, 1.0, 3.0], 100) == 5.0

    def test_rejects_out_of_range_and_empty(self):
        with pytest.raises(ValueError):
            percentile_nearest_rank([1.0], 0)
        with pytest.raises(ValueError):
            percentile_nearest_rank([1.0], 101)
        with pytest.raises(ValueError):
            percentile_nearest_rank([], 95)

    def test_summarize_p95_agrees_with_the_standalone_function(self):
        samples = [float(i) for i in range(1, 21)]
        assert summarize(samples).p95 == percentile_nearest_rank(samples, 95)


class TestMeasureLoop:
    def test_returns_exactly_the_requested_sample_counts(self):
        calls = []
        m = measure(lambda: calls.append(1), repeats=7, warmup=3)
        assert len(m.samples) == 7
        assert len(m.warmup_samples) == 3
        assert len(calls) == 10, "warm-up calls must actually run, not be skipped"

    def test_warmup_samples_are_kept_not_discarded(self):
        """The discard is an aggregation rule, not a deletion: the
        warm-up numbers must survive so the exclusion can be audited."""
        m = measure(lambda: None, repeats=2, warmup=2)
        assert all(v >= 0 for v in m.warmup_samples)
        assert m.warmup_samples  # present, and separate from m.samples

    def test_batching_divides_by_batch_size(self):
        """A batched sample is a per-call mean. With batch = 50 the
        reported per-call cost must be about 1/50th of the batch."""
        counter = {"n": 0}

        def work():
            counter["n"] += 1
            for _ in range(200):
                pass

        single = measure(work, repeats=5, warmup=1, batch=1)
        batched = measure(work, repeats=5, warmup=1, batch=50)
        assert counter["n"] == (5 + 1) + (5 + 1) * 50
        assert batched.batch == 50
        # Per-call cost should be the same order of magnitude, not 50x.
        assert batched.stats.median < single.stats.median * 10

    def test_setup_runs_before_each_repetition(self):
        order = []
        measure(lambda: order.append("run"), repeats=3, warmup=0, setup=lambda: order.append("setup"))
        assert order == ["setup", "run"] * 3

    def test_rejects_nonsensical_parameters(self):
        with pytest.raises(ValueError):
            measure(lambda: None, repeats=0)
        with pytest.raises(ValueError):
            measure(lambda: None, repeats=1, warmup=-1)
        with pytest.raises(ValueError):
            measure(lambda: None, repeats=1, batch=0)

    def test_measurement_stats_property_matches_summarize(self):
        m = measure(lambda: None, repeats=5, warmup=0)
        assert m.stats == summarize(m.samples)
        assert isinstance(m.stats, Stats)


class TestClockResolution:
    def test_resolution_is_positive_and_plausible(self):
        r = timer_resolution()
        assert 0 < r < 1e-3, f"implausible clock granularity: {r} s"

    def test_resolution_limited_flags_operations_near_the_clock_floor(self):
        r = 1e-7
        assert is_resolution_limited(r * (RESOLUTION_SAFETY_FACTOR - 1), r)
        assert not is_resolution_limited(r * (RESOLUTION_SAFETY_FACTOR + 1), r)


class TestThroughput:
    def test_mib_per_second_uses_binary_megabytes(self):
        """1048576 bytes in exactly 1 second is 1.0 MiB/s. If this ever
        returns 1.048576 the unit silently became MB/s."""
        assert throughput_mib_s(1048576, 1.0) == pytest.approx(1.0)

    def test_scales_with_time(self):
        assert throughput_mib_s(1048576, 0.5) == pytest.approx(2.0)

    def test_zero_or_negative_duration_is_an_error(self):
        with pytest.raises(ValueError):
            throughput_mib_s(1024, 0.0)


class TestAdaptiveBatching:
    """`adaptive_measure` decides whether one call can be timed on its own
    from a measured pilot and the machine's measured clock granularity --
    not from a hard-coded list of 'fast' operations."""

    def test_slow_operation_is_not_batched(self):
        from benchmarks.harness.timing import adaptive_measure

        def slow():
            time.sleep(0.002)

        m, prov = adaptive_measure(slow, repeats=3, warmup=0, pilot_repeats=1)
        assert m.batch == 1
        assert prov["batch"] == 1
        assert "one observed call" in prov["batched_reason"]

    def test_sub_microsecond_operation_is_batched(self):
        from benchmarks.harness.timing import adaptive_measure

        m, prov = adaptive_measure(lambda: None, repeats=3, warmup=0, max_batch=5000, pilot_repeats=3)
        assert m.batch > 1
        assert prov["batch"] == m.batch
        assert "per-call mean" in prov["batched_reason"]

    def test_provenance_records_what_the_decision_was_based_on(self):
        from benchmarks.harness.timing import adaptive_measure

        _, prov = adaptive_measure(lambda: None, repeats=2, warmup=0, pilot_repeats=1)
        assert prov["pilot_median_seconds"] >= 0
        assert prov["clock_resolution_seconds"] > 0

    def test_choose_batch_size_boundaries(self):
        from benchmarks.harness.timing import BATCH_TARGET_SECONDS, choose_batch_size

        resolution = 1e-7
        # Comfortably above the floor -> one call is worth timing alone.
        assert choose_batch_size(1e-3, resolution, 10000) == 1
        # Far below the floor -> batch up towards the target duration.
        assert choose_batch_size(1e-8, resolution, 10000) == 10000
        # Batch is sized to reach the target duration, and capped.
        assert choose_batch_size(1e-6, resolution, 10000) == math.ceil(BATCH_TARGET_SECONDS / 1e-6)
        assert choose_batch_size(1e-9, resolution, 50) == 50

    def test_choose_batch_size_rejects_a_nonsense_cap(self):
        from benchmarks.harness.timing import choose_batch_size

        with pytest.raises(ValueError):
            choose_batch_size(1e-6, 1e-7, 0)
