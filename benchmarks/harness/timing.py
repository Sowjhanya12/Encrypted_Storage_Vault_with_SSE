"""
benchmarks/harness/timing.py -- the one place this project measures
elapsed time and reduces samples to statistics.

Every number that reaches the Phase 7 report passes through this
module, so the methodology is defined once and is identical across
suites rather than re-decided per benchmark. Standard library only.

Method, and why each choice was made
------------------------------------
* `time.perf_counter_ns()` is the clock. It is the highest-resolution
  monotonic timer Python exposes, it is not affected by the system
  clock being adjusted mid-run, and the _ns variant avoids the float
  rounding that `perf_counter()` accumulates for very short intervals.

* **Warm-up iterations are run and discarded from the statistics, but
  still written to the raw record** (recorder.py tags them
  `phase="warmup"`). The first call into a code path pays for import
  side effects, lazily-built C state inside `cryptography`, cold
  SQLite pages and a cold CPU cache; including it inflates the mean
  and tells you nothing about steady-state cost. Deleting the evidence
  of that decision would be worse than making it, so the samples
  survive in the raw file and the aggregation rule is stated.

* **Batched timing for sub-microsecond operations.** `prf()` and
  `build_search_token()` run in a few microseconds. `timer_resolution()`
  below measures the clock's actual granularity on the machine doing
  the run; when one call is not comfortably above it, timing a single
  call measures the clock, not the code. Those benchmarks instead run
  `batch` calls inside one timed region and divide, which is reported
  honestly: the raw record carries `batch`, and a batched sample is
  labelled as a per-call mean, not as an observed single call. The
  cost of that trade is that batching hides per-call variance, so it
  is used only where the alternative is meaningless.

* **Median leads, mean and standard deviation accompany it.** A
  benchmark process competes with the operating system for two CPUs;
  the resulting spikes are one-sided and drag the mean up. The median
  is the robust estimate of typical cost. The mean, standard deviation
  and the coefficient of variation are reported next to it because a
  large spread is itself a result worth seeing rather than smoothing
  away.

* **The 95% confidence interval uses Student's t**, with the critical
  value looked up from `_T_CRITICAL_95` by degrees of freedom, falling
  back to the normal approximation (1.96) above df=30. It is a CI on
  the *mean of the samples collected on this machine during this run*,
  and nothing more: it does not model machine-to-machine variation and
  must not be read as one. That caveat is repeated in the report.
"""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, List, Optional, Sequence

# Two-sided 95% critical values of Student's t by degrees of freedom
# (n - 1). Above df = 30 the normal approximation is within ~1%, which
# is far below the run-to-run noise these intervals describe.
_T_CRITICAL_95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
    7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179,
    13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101,
    19: 2.093, 20: 2.086, 21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064,
    25: 2.060, 26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}
_NORMAL_CRITICAL_95 = 1.96

# A single measured call is treated as resolution-limited unless it is
# at least this many times the clock's own granularity.
RESOLUTION_SAFETY_FACTOR = 100


def timer_resolution(probes: int = 200) -> float:
    """Smallest non-zero interval `perf_counter_ns` actually reports,
    in seconds -- measured on the machine doing the run, not assumed.

    Two consecutive reads are taken repeatedly; the smallest non-zero
    difference is the effective granularity. Recorded in the run
    manifest and used by `is_resolution_limited()` to decide whether a
    benchmark needs batching.
    """
    smallest = None
    for _ in range(probes):
        a = time.perf_counter_ns()
        b = time.perf_counter_ns()
        delta = b - a
        if delta > 0 and (smallest is None or delta < smallest):
            smallest = delta
    # A clock that never reported a non-zero delta is not plausible on
    # any supported platform; fall back to 1 ns rather than crash, and
    # let the manifest show the implausible value.
    return (smallest if smallest is not None else 1) / 1e9


def is_resolution_limited(duration_s: float, resolution_s: float) -> bool:
    """True when one timed call is too close to the clock's own
    granularity for a single-call measurement to be meaningful."""
    return duration_s < resolution_s * RESOLUTION_SAFETY_FACTOR


@dataclass(frozen=True)
class Stats:
    """Reduction of one benchmark's samples. Every field the Phase 7
    report prints comes from here, so the report cannot quote a
    statistic this module did not compute."""

    n: int
    mean: float
    median: float
    stdev: Optional[float]
    minimum: float
    maximum: float
    p95: float
    cv: Optional[float]                 # stdev / mean -- relative spread
    ci95_low: Optional[float]
    ci95_high: Optional[float]
    ci95_half_width: Optional[float]

    def as_dict(self) -> dict:
        return asdict(self)


def percentile_nearest_rank(samples: "Sequence[float]", pct: float) -> float:
    """Nearest-rank percentile: sort, take ceil(pct/100 * n) as a
    1-based rank.

    Chosen over an interpolating percentile because it always returns
    a value that was actually observed -- for a latency figure quoted
    in a report, "this measurement happened" is a stronger claim than
    a weighted average of two neighbours.
    """
    if not samples:
        raise ValueError("percentile of an empty sample set is undefined")
    if not 0 < pct <= 100:
        raise ValueError("pct must be in (0, 100]")
    ordered = sorted(samples)
    rank = math.ceil(pct / 100.0 * len(ordered))
    return ordered[max(1, rank) - 1]


def summarize(samples: "Sequence[float]") -> Stats:
    """Reduce raw per-call durations (or any scalar samples) to Stats.

    With n = 1 the dispersion fields are None rather than 0.0 -- a
    single observation has no measurable spread, and reporting 0.0
    would read as "perfectly repeatable", which is the opposite of
    what one sample means.
    """
    if not samples:
        raise ValueError("cannot summarize an empty sample set")
    n = len(samples)
    mean = statistics.fmean(samples)
    median = statistics.median(samples)
    if n >= 2:
        stdev = statistics.stdev(samples)
        t = _T_CRITICAL_95.get(n - 1, _NORMAL_CRITICAL_95)
        half = t * stdev / math.sqrt(n)
        ci_low, ci_high = mean - half, mean + half
        cv = stdev / mean if mean else None
    else:
        stdev = half = ci_low = ci_high = cv = None
    return Stats(
        n=n,
        mean=mean,
        median=median,
        stdev=stdev,
        minimum=min(samples),
        maximum=max(samples),
        p95=percentile_nearest_rank(samples, 95),
        cv=cv,
        ci95_low=ci_low,
        ci95_high=ci_high,
        ci95_half_width=half,
    )


@dataclass
class Measurement:
    """One benchmark configuration's complete measurement record.

    `samples` are the per-call durations in seconds that statistics are
    computed from; `warmup_samples` are the discarded-from-statistics
    warm-up calls, kept so the raw record shows what was excluded and
    the exclusion can be audited rather than trusted.
    """

    samples: List[float] = field(default_factory=list)
    warmup_samples: List[float] = field(default_factory=list)
    batch: int = 1
    unit: str = "s"

    @property
    def stats(self) -> Stats:
        return summarize(self.samples)


def measure(
    fn: "Callable[[], object]",
    *,
    repeats: int,
    warmup: int = 2,
    batch: int = 1,
    setup: "Optional[Callable[[], None]]" = None,
) -> Measurement:
    """Time `fn` `repeats` times (after `warmup` discarded runs) and
    return every sample.

    `setup`, if given, runs before each timed repetition and is NOT
    included in the timing -- for benchmarks that need fresh input per
    repetition (a new plaintext, a re-seeded state) without paying for
    that preparation inside the measurement.

    With `batch > 1`, one repetition times `batch` back-to-back calls
    and divides: each returned sample is a per-call mean over that
    batch. See the module docstring for when that is legitimate.
    """
    if repeats < 1:
        raise ValueError("repeats must be >= 1")
    if warmup < 0:
        raise ValueError("warmup must be >= 0")
    if batch < 1:
        raise ValueError("batch must be >= 1")

    m = Measurement(batch=batch)

    def _one_timed_repetition() -> float:
        if setup is not None:
            setup()
        start = time.perf_counter_ns()
        for _ in range(batch):
            fn()
        elapsed_ns = time.perf_counter_ns() - start
        return elapsed_ns / 1e9 / batch

    for _ in range(warmup):
        m.warmup_samples.append(_one_timed_repetition())
    for _ in range(repeats):
        m.samples.append(_one_timed_repetition())
    return m


# Target duration for one batched repetition. 2 ms is ~33,000x this
# machine class's clock granularity, so quantisation error is negligible,
# while the batch stays short enough that OS scheduling noise still shows
# up as variance between repetitions instead of being averaged away inside
# one long batch.
BATCH_TARGET_SECONDS = 0.002


def choose_batch_size(single_call_seconds: float, resolution_s: float, max_batch: int) -> int:
    """How many calls to time together, or 1 if timing one call is already
    meaningful.

    The decision is made from a measured pilot duration and the machine's
    measured clock granularity, never from a hard-coded assumption about
    which operations are "fast" -- the same code therefore batches on a
    slow machine and stops batching on a fast one, and records which it
    did.
    """
    if max_batch < 1:
        raise ValueError("max_batch must be >= 1")
    if single_call_seconds <= 0:
        return max_batch
    if not is_resolution_limited(single_call_seconds, resolution_s):
        return 1
    needed = math.ceil(BATCH_TARGET_SECONDS / single_call_seconds)
    return max(1, min(max_batch, needed))


def adaptive_measure(
    fn: "Callable[[], object]",
    *,
    repeats: int,
    warmup: int = 2,
    resolution_s: "Optional[float]" = None,
    max_batch: int = 10000,
    pilot_repeats: int = 3,
    setup: "Optional[Callable[[], None]]" = None,
) -> "tuple[Measurement, dict]":
    """`measure()` with the batch size chosen from a pilot run.

    Returns the Measurement and a small provenance dict -- the pilot
    duration, the machine's clock resolution, the batch chosen and why --
    which the caller records as `notes`/params so the report can state
    "per-call mean over N calls" wherever that is what a number is, rather
    than presenting a batched figure as a single observed call.

    The pilot itself is thrown away rather than reported: it runs before
    the warm-up, so it is the coldest and least representative sample
    available, and including it would bias the very statistics it exists
    to make measurable.
    """
    if resolution_s is None:
        resolution_s = timer_resolution()
    pilot = measure(fn, repeats=pilot_repeats, warmup=0, batch=1, setup=setup)
    pilot_median = statistics.median(pilot.samples)
    batch = choose_batch_size(pilot_median, resolution_s, max_batch)
    measurement = measure(fn, repeats=repeats, warmup=warmup, batch=batch, setup=setup)
    provenance = {
        "pilot_median_seconds": pilot_median,
        "clock_resolution_seconds": resolution_s,
        "batch": batch,
        "batched_reason": (
            "single call is within %dx the clock resolution -- each sample is a "
            "per-call mean over %d calls" % (RESOLUTION_SAFETY_FACTOR, batch)
            if batch > 1
            else "single call is comfortably above the clock resolution -- each "
                 "sample is one observed call"
        ),
    }
    return measurement, provenance


def throughput_mib_s(byte_count: int, seconds: float) -> float:
    """Bytes processed per second, in MiB/s (1 MiB = 1048576 bytes).

    Stated explicitly because MB/s is ambiguous between 10^6 and 2^20
    and a throughput table that does not say which is not reproducible.
    """
    if seconds <= 0:
        raise ValueError("seconds must be positive to compute throughput")
    return (byte_count / 1048576.0) / seconds
