"""
benchmarks/run_all.py -- the single command that runs Phase 7.

    python -m benchmarks.run_all --profile quick
    python -m benchmarks.run_all --profile full --dataset-role authoritative

Results are written to `benchmarks/results/<profile>/` by default, so a
quick calibration run can never overwrite a full run's data.

Dataset role
------------
Every run records whether it is `development` (the default: calibration,
harness debugging, a laptop doing three other things) or `authoritative`
(the run whose numbers go in the report). The distinction is a deliberate
flag rather than an inference from the profile name, because a full-profile
run is not automatically the reportable one -- it might have been a
rehearsal on different hardware. The report prints the role, and
development data is labelled as such wherever it appears.

Failure handling
----------------
A suite that raises is recorded as `failed` with its error text and the run
continues to the next suite. It can never be rendered as successful: the
manifest's per-suite status is what the report reads, and a suite that
never ran at all stays `not_run`. Ctrl-C is caught so that everything
already measured is finalised and verifiable rather than lost.
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from typing import Dict, List

# Make the repository root importable when run as `python benchmarks/run_all.py`
# as well as `python -m benchmarks.run_all`.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from benchmarks import config  # noqa: E402
from benchmarks.harness import environment  # noqa: E402
from benchmarks.harness.recorder import (  # noqa: E402
    STATUS_FAILED,
    STATUS_OK,
    Recorder,
    verify,
)
from benchmarks.suites import (  # noqa: E402
    b1_primitives,
    b2_token_generation,
    b3_indexing,
    b4_upload_rebuild,
    b5_search,
    b6_storage,
)

# Suites implemented so far. Later steps append to this map; suites declared
# in config.SUITE_IDS but absent here are recorded as `not_run`.
SUITES = {
    b1_primitives.SUITE_ID: b1_primitives,
    b2_token_generation.SUITE_ID: b2_token_generation,
    b3_indexing.SUITE_ID: b3_indexing,
    b4_upload_rebuild.SUITE_ID: b4_upload_rebuild,
    b5_search.SUITE_ID: b5_search,
    b6_storage.SUITE_ID: b6_storage,
}

DEFAULT_RESULTS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Run the Encrypted Cloud Vault Phase 7 benchmarks.")
    p.add_argument("--profile", default="quick", choices=sorted(config.PROFILES),
                   help="workload sizing (default: quick)")
    p.add_argument("--suites", default="all",
                   help="comma-separated suite ids to run, or 'all' (default: all implemented)")
    p.add_argument("--results-dir", default=None,
                   help="output directory (default: benchmarks/results/<profile>)")
    p.add_argument("--dataset-role", default="development", choices=("development", "authoritative"),
                   help="whether this run's numbers are reportable (default: development)")
    p.add_argument("--label", default="",
                   help="free-text note recorded in the manifest, e.g. which machine this ran on")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    profile = config.get_profile(args.profile)
    results_dir = args.results_dir or os.path.join(DEFAULT_RESULTS_ROOT, profile.name)

    requested: "List[str]"
    if args.suites == "all":
        requested = [s for s in config.SUITE_IDS if s in SUITES]
    else:
        requested = [s.strip() for s in args.suites.split(",") if s.strip()]
        unknown = [s for s in requested if s not in SUITES]
        if unknown:
            raise SystemExit(f"unknown or not-yet-implemented suite(s): {unknown}. "
                             f"Implemented: {sorted(SUITES)}")

    env = environment.capture()
    recorder = Recorder(
        results_dir=results_dir,
        profile_name=profile.name,
        environment=env,
        declared_suites=config.SUITE_IDS,
    )

    print(f"Phase 7 benchmarks -- profile '{profile.name}', role '{args.dataset_role}'")
    print(f"  {environment.one_line_summary(env)}")
    print(f"  results -> {results_dir}")
    print(f"  running: {', '.join(requested)}")
    if args.dataset_role == "development":
        print("  NOTE: development data -- not for the report unless re-run as authoritative")

    metadata: "Dict[str, dict]" = {}
    failures = 0
    interrupted = False

    for suite_id in requested:
        module = SUITES[suite_id]
        print(f"\n[{suite_id}] {module.TITLE} ...", flush=True)
        recorder.begin_suite(suite_id)
        try:
            metadata[suite_id] = module.run(recorder, profile)
        except KeyboardInterrupt:
            recorder.end_suite(suite_id, status=STATUS_FAILED, error="interrupted by user")
            interrupted = True
            print(f"[{suite_id}] INTERRUPTED -- recorded as failed", flush=True)
            break
        except Exception as exc:
            recorder.end_suite(suite_id, status=STATUS_FAILED,
                               error=f"{type(exc).__name__}: {exc}")
            failures += 1
            print(f"[{suite_id}] FAILED: {type(exc).__name__}: {exc}", flush=True)
            traceback.print_exc()
            continue
        recorder.end_suite(suite_id, status=STATUS_OK)
        entry = recorder.suite_status(suite_id)
        print(f"[{suite_id}] ok -- {entry['sample_lines']} raw rows in "
              f"{entry['duration_seconds']}s", flush=True)

    manifest_path = recorder.finalize(extra={
        "dataset_role": args.dataset_role,
        "label": args.label,
        "profile_sizing": profile.summary(),
        "suite_metadata": metadata,
        "command": " ".join(sys.argv),
        "interrupted": interrupted,
    })

    problems = verify(results_dir)
    print(f"\nmanifest: {manifest_path}")
    print("integrity: " + ("OK -- raw files match the manifest" if not problems
                           else "PROBLEMS: " + "; ".join(problems)))
    if failures:
        print(f"{failures} suite(s) failed -- see the manifest for the recorded errors")
    return 1 if (problems or failures or interrupted) else 0


if __name__ == "__main__":
    raise SystemExit(main())
