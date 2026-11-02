# benchmarks/results/

One directory per run profile. `benchmarks/run_all.py` writes here.

```
results/<profile>/manifest.json   environment, profile sizing, per-suite status + raw-file hashes
results/<profile>/raw/*.jsonl     every sample, one JSON object per line (warm-ups included)
```

## Which data is which

Every manifest records a `dataset_role`:

- **`development`** — calibration, harness debugging, or a machine that was doing
  other things at the time. Real measurements, but not reportable.
- **`authoritative`** — the run whose numbers go in the Phase 7 report.

The role is a deliberate flag on the command line, not something inferred from the
profile name: a full-profile run is not automatically the reportable one.

## Current contents

- `quick/` — complete calibration run of the primitive suites (B1-B3), `development`
  role, taken on the Cowork Linux sandbox (2 logical cores). Verified.
- `smoke/` — complete run of the system suites (B4-B6) at the `smoke` profile,
  `development` role, same machine. B4 is capped at **50 documents**, not the full
  profile's 200: the sandbox kills any command running longer than 45 seconds, and
  a 200-document B4 needs minutes because every upload rebuilds the whole index.
  These are real measurements of the real two-process system and are usable as a
  scaling smoke test, but they are **not** the authoritative dataset.
- `full-partial/` — B2 only, at full sizing, `development` role. Exists to prove the
  full-profile code path runs; the other suites at full sizing exceed the sandbox
  limit.
- `raw/`, `tables/`, `plots/` — empty directories left over from the Step 1 scaffold.
  This environment cannot delete files in the mounted folder, and git does not track
  empty directories, so they are harmless. Each contains no manifest, so `verify()`
  correctly reports that no run has completed there.
- `full/` — **no completed run.** `raw/ABORTED_b1_primitives_no_manifest.jsonl.txt`
  is the partial output of a full-profile run that was killed part-way through the
  Argon2id parameter sweep by the sandbox's process limits. It was renamed out of
  the way rather than deleted (this environment cannot delete files in the mounted
  folder) so it can never be read as a current raw file. Because the run never
  reached `finalize()`, no manifest was written, and
  `benchmarks.harness.recorder.verify()` reports
  `"no manifest.json ... no run has completed here"` — the interrupted run cannot
  present itself as a completed one.

The authoritative full-profile dataset is to be produced on the project owner's
Windows machine with:

```
python -m benchmarks.run_all --profile full --dataset-role authoritative --label "..."
```
