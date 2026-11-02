"""
benchmarks/suites/ -- one module per benchmark suite.

Every module exposes the same three names so benchmarks/run_all.py can
drive them uniformly:

    SUITE_ID     the id declared in benchmarks/config.SUITE_IDS
    TITLE        one line, used as the report's section heading
    run(recorder, profile) -> dict

`run` records its samples through the recorder it is given and returns a
JSON-serialisable metadata dict (corpus fingerprint, workload description,
correctness checks performed) that run_all.py folds into the manifest.

A suite NEVER catches its own exceptions to keep a run going. If a
measurement cannot be taken, the suite raises: run_all.py records the
suite as `failed` with the error text, and the report renders it as
failed. A suite that swallowed an error and returned partial data would
be indistinguishable from one that succeeded, which is the failure mode
this phase is built to prevent.
"""
