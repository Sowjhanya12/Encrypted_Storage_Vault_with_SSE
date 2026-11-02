"""
benchmarks/harness/recorder.py -- the run's evidence trail.

This module exists to make one guarantee enforceable rather than
promised: **no number reaches the Phase 7 report that was not measured
in the run the report describes.**

How it is enforced
------------------
1. **Every sample is written, including the discarded ones.** Each
   warm-up call, each timed call and each scalar observation becomes
   one line of JSON in `results/raw/<suite>.jsonl`. Aggregates are
   never the primary record -- they are recomputed downstream from
   these lines, so any table or chart in the report can be rebuilt,
   or contradicted, from the shipped raw data.

2. **A suite that did not run cannot look like one that did.** The
   full list of suites is declared when the run starts; any suite not
   executed is written to the manifest as `not_run`, and the report
   renders it as "not run" rather than leaving a gap a reader would
   fill in charitably.

3. **Stale data cannot be silently re-reported.** Re-running a single
   suite truncates only that suite's raw file, which would otherwise
   leave last week's file for every other suite sitting in the same
   directory looking current. So the manifest records, per suite, the
   SHA-256 and line count of the raw file *as written by this run*,
   and `verify(results_dir)` re-hashes them. The report generator
   refuses to render a suite whose file no longer matches, or whose
   manifest entry is missing. Editing a raw file by hand to "fix" a
   number breaks the hash and stops the report -- which is the point.

The format is JSON Lines rather than one big JSON document so a run
that is interrupted after ninety minutes still leaves every sample it
had already collected on disk, intact and parseable.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from .timing import Measurement, Stats, summarize

MANIFEST_FILENAME = "manifest.json"
RAW_DIRNAME = "raw"

# Phase tags used on every raw line.
PHASE_WARMUP = "warmup"      # timed, then excluded from statistics
PHASE_MEASURE = "measure"    # timed, included in statistics
PHASE_SCALAR = "scalar"      # a directly observed quantity (bytes, counts)

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_NOT_RUN = "not_run"


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_lines(path: str) -> int:
    with open(path, "r", encoding="utf-8") as f:
        return sum(1 for _ in f)


class Recorder:
    """Writes one run's raw samples and its manifest.

    Usage mirrors the shape of a run:

        rec = Recorder(results_dir, profile_name, env, declared_suites=[...])
        rec.begin_suite("b2_aead")
        rec.add_measurement("b2_aead", "aes_gcm_encrypt", {...}, measurement)
        rec.end_suite("b2_aead")
        ...
        rec.finalize()
    """

    def __init__(
        self,
        results_dir: str,
        profile_name: str,
        environment: dict,
        declared_suites: "Iterable[str]",
        run_id: "Optional[str]" = None,
    ) -> None:
        self.results_dir = os.path.abspath(results_dir)
        self.raw_dir = os.path.join(self.results_dir, RAW_DIRNAME)
        os.makedirs(self.raw_dir, exist_ok=True)
        self.profile_name = profile_name
        self.environment = environment
        self.declared_suites = list(declared_suites)
        self.run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._monotonic_start = time.monotonic()
        self._suites: "Dict[str, dict]" = {
            name: {"status": STATUS_NOT_RUN, "ran_in_this_run": False}
            for name in self.declared_suites
        }
        self._open_handles: "Dict[str, object]" = {}

    # -- suite lifecycle ---------------------------------------------------

    def raw_path(self, suite: str) -> str:
        return os.path.join(self.raw_dir, f"{suite}.jsonl")

    def begin_suite(self, suite: str) -> None:
        """Open (truncating) this suite's raw file for the current run.

        Truncation is why the manifest hash exists: it keeps one run's
        file authoritative, and the hash keeps a *previous* run's file
        for some other suite from passing as part of this one.
        """
        if suite not in self._suites:
            self._suites[suite] = {"status": STATUS_NOT_RUN, "ran_in_this_run": False}
        self._suites[suite].update(
            {
                "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "_monotonic_start": time.monotonic(),
                "ran_in_this_run": True,
                "status": STATUS_FAILED,  # pessimistic until end_suite says otherwise
                "sample_lines": 0,
            }
        )
        self._open_handles[suite] = open(self.raw_path(suite), "w", encoding="utf-8")

    def end_suite(self, suite: str, status: str = STATUS_OK, error: "Optional[str]" = None) -> None:
        handle = self._open_handles.pop(suite, None)
        if handle is not None:
            handle.close()
        entry = self._suites[suite]
        entry["status"] = status
        entry["error"] = error
        entry["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry["duration_seconds"] = round(time.monotonic() - entry.pop("_monotonic_start", time.monotonic()), 3)
        path = self.raw_path(suite)
        if os.path.exists(path):
            entry["raw_file"] = os.path.relpath(path, self.results_dir).replace(os.sep, "/")
            entry["raw_sha256"] = _sha256_of_file(path)
            entry["raw_line_count"] = _count_lines(path)
        else:
            entry["raw_file"] = None
            entry["raw_sha256"] = None
            entry["raw_line_count"] = 0

    def suite_status(self, suite: str) -> dict:
        """Read-only view of one suite's manifest entry, for callers that
        want to report progress without reaching into internals."""
        return {k: v for k, v in self._suites.get(suite, {}).items() if not k.startswith("_")}

    # -- writing samples ---------------------------------------------------

    def _write(self, suite: str, row: dict) -> None:
        handle = self._open_handles.get(suite)
        if handle is None:
            raise RuntimeError(
                f"begin_suite({suite!r}) must be called before recording samples for it"
            )
        # Wall-clock provenance on every row. Added after three authoritative B4
        # runs stalled: reconstructing WHEN a run stopped making progress
        # required arithmetic against the manifest's start time and the suite
        # duration, which works but is inference. With these two fields the gap
        # is directly readable from the raw file -- the difference between two
        # consecutive rows IS the time the run spent between them.
        #
        # Honest about what the value means: it is the moment the row was
        # WRITTEN, which for a timed measurement is just after its final
        # repetition finished, not when the first one started. It is
        # provenance, never an input to any statistic.
        row = dict(row)
        row["ts_utc"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        row["elapsed_since_run_start_s"] = round(time.monotonic() - self._monotonic_start, 6)
        handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        handle.flush()  # an interrupted run keeps everything already collected
        self._suites[suite]["sample_lines"] = self._suites[suite].get("sample_lines", 0) + 1

    def add_measurement(
        self,
        suite: str,
        benchmark: str,
        params: dict,
        measurement: Measurement,
        unit: str = "s",
        notes: "Optional[str]" = None,
    ) -> None:
        """Write every sample of one benchmark configuration: warm-ups
        tagged `warmup`, timed repetitions tagged `measure`."""
        common = {
            "run_id": self.run_id,
            "suite": suite,
            "benchmark": benchmark,
            "params": params,
            "unit": unit,
            "batch": measurement.batch,
        }
        if notes:
            common["notes"] = notes
        for i, value in enumerate(measurement.warmup_samples):
            self._write(suite, {**common, "phase": PHASE_WARMUP, "rep": i, "value": value})
        for i, value in enumerate(measurement.samples):
            self._write(suite, {**common, "phase": PHASE_MEASURE, "rep": i, "value": value})

    def add_scalar(
        self,
        suite: str,
        benchmark: str,
        params: dict,
        value: float,
        unit: str,
        notes: "Optional[str]" = None,
    ) -> None:
        """Record a directly observed quantity that is not a duration --
        a ciphertext length, an index row count, an on-disk file size,
        the number of HTTP requests one upload caused."""
        row = {
            "run_id": self.run_id,
            "suite": suite,
            "benchmark": benchmark,
            "params": params,
            "unit": unit,
            "batch": 1,
            "phase": PHASE_SCALAR,
            "rep": 0,
            "value": value,
        }
        if notes:
            row["notes"] = notes
        self._write(suite, row)

    # -- manifest ----------------------------------------------------------

    def finalize(self, extra: "Optional[dict]" = None) -> str:
        """Close anything still open and write manifest.json. Returns
        the manifest path."""
        for suite in list(self._open_handles):
            self.end_suite(suite, status=STATUS_FAILED, error="suite never called end_suite")
        manifest = {
            "run_id": self.run_id,
            "profile": self.profile_name,
            "started_at": self.started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "wall_clock_seconds": round(time.monotonic() - self._monotonic_start, 3),
            "environment": self.environment,
            "suites": {
                name: {k: v for k, v in entry.items() if not k.startswith("_")}
                for name, entry in self._suites.items()
            },
            "integrity_note": (
                "Each suite entry carries the SHA-256 and line count of the raw "
                "sample file as written by this run. benchmarks/harness/recorder.py's "
                "verify() re-checks them; the report generator refuses to render a "
                "suite whose raw file does not match, or that this run did not execute."
            ),
        }
        if extra:
            manifest.update(extra)
        path = os.path.join(self.results_dir, MANIFEST_FILENAME)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True, default=str)
        return path


# ---------------------------------------------------------------------------
# reading back -- used by benchmarks/analysis/ and by the harness self-tests
# ---------------------------------------------------------------------------

def load_manifest(results_dir: str) -> dict:
    with open(os.path.join(results_dir, MANIFEST_FILENAME), "r", encoding="utf-8") as f:
        return json.load(f)


def load_raw(results_dir: str, suite: str) -> "List[dict]":
    """Every recorded line for one suite, in write order."""
    path = os.path.join(results_dir, RAW_DIRNAME, f"{suite}.jsonl")
    rows: "List[dict]" = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def measured_values(rows: "Iterable[dict]", benchmark: str, params_match: "Optional[dict]" = None) -> "List[float]":
    """Pull the statistics-eligible samples (`phase == "measure"`) for
    one benchmark, optionally narrowed to one parameter combination.

    Warm-ups are excluded HERE, at aggregation time, rather than at
    collection time -- the single place the discard rule is applied,
    and it is applied to data that remains on disk either way.
    """
    out: "List[float]" = []
    for row in rows:
        if row.get("benchmark") != benchmark or row.get("phase") != PHASE_MEASURE:
            continue
        if params_match and any(row.get("params", {}).get(k) != v for k, v in params_match.items()):
            continue
        out.append(float(row["value"]))
    return out


def scalar_values(rows: "Iterable[dict]", benchmark: str, params_match: "Optional[dict]" = None) -> "List[float]":
    out: "List[float]" = []
    for row in rows:
        if row.get("benchmark") != benchmark or row.get("phase") != PHASE_SCALAR:
            continue
        if params_match and any(row.get("params", {}).get(k) != v for k, v in params_match.items()):
            continue
        out.append(float(row["value"]))
    return out


def aggregate(results_dir: str, suite: str, benchmark: str, params_match: "Optional[dict]" = None) -> Stats:
    """Recompute a benchmark's statistics from the raw file on disk --
    the operation the report performs, so the report is by
    construction a view over the raw data rather than a parallel
    record of it."""
    return summarize(measured_values(load_raw(results_dir, suite), benchmark, params_match))


def verify(results_dir: str) -> "List[str]":
    """Re-check every manifest integrity claim. Returns a list of
    human-readable problems; an empty list means the raw files on disk
    are exactly the ones this manifest's run wrote.

    Called by the report generator before rendering anything.
    """
    problems: "List[str]" = []
    try:
        manifest = load_manifest(results_dir)
    except FileNotFoundError:
        return [f"no {MANIFEST_FILENAME} in {results_dir} -- no run has completed here"]
    except json.JSONDecodeError as exc:
        return [f"{MANIFEST_FILENAME} is not valid JSON: {exc}"]

    for suite, entry in manifest.get("suites", {}).items():
        if not entry.get("ran_in_this_run"):
            continue
        raw_rel = entry.get("raw_file")
        if not raw_rel:
            problems.append(f"{suite}: manifest says it ran but records no raw file")
            continue
        path = os.path.join(results_dir, raw_rel)
        if not os.path.exists(path):
            problems.append(f"{suite}: raw file {raw_rel} is missing")
            continue
        actual_hash = _sha256_of_file(path)
        if actual_hash != entry.get("raw_sha256"):
            problems.append(
                f"{suite}: raw file {raw_rel} has changed since the run "
                f"(sha256 {actual_hash[:12]}... != manifest {str(entry.get('raw_sha256'))[:12]}...)"
            )
        actual_lines = _count_lines(path)
        if actual_lines != entry.get("raw_line_count"):
            problems.append(
                f"{suite}: raw file {raw_rel} has {actual_lines} lines, "
                f"manifest recorded {entry.get('raw_line_count')}"
            )
    return problems
