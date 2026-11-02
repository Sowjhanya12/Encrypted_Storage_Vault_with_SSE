# Phase 7 Benchmark Figures — Source and Provenance

Generated: 2026-09-04
Generation method: single Python script (`matplotlib`, `Agg` backend), reading only the
three authoritative Windows benchmark result directories listed below. No benchmark was
re-run and no source file was modified to produce these figures (see integrity note at
the end of this file).

All figures are PNG, 300 DPI, `tight`/`bbox_inches="tight"` layout.

---

## figure_1_aes_gcm.png
- **Source:** `benchmarks/results/full/raw/b1_primitives.jsonl` (benchmarks `aead_encrypt`,
  `aead_decrypt`; phase = `measure`)
- **X-axis:** payload size in bytes, 1 KiB – 16 MiB (log scale)
- **Y-axis:** time in seconds (log scale)
- **Error bars:** observed min–max range across n = 15 measured repetitions per point
- **Shows:** AES-256-GCM encrypt/decrypt throughput scaling is linear in payload size
  across three decades, with encrypt and decrypt tracking each other closely.

## figure_2_index_construction.png
- **Source:** `benchmarks/results/full/raw/b3_indexing.jsonl` (benchmarks `tokenize_corpus`,
  `build_index`; phase = `measure`)
- **X-axis:** document count — 10, 25, 50, 100, 200 (log scale)
- **Y-axis:** time in seconds (log scale)
- **Error bars:** observed min–max range, n = 10 per point
- **Shows:** B3 (tokenize + index build, no cloud round-trip) is the one suite that
  completed a full run at 200 documents — this is not a B4 result and does not imply B4
  completed at 200. Growth is driven by total (keyword, document) postings, not raw
  document count alone, so it is not perfectly linear.

## figure_3_b4_rebuild_scaling.png
- **Sources:** `benchmarks/results/full/raw/b4_upload_rebuild.jsonl` (Run 1),
  `benchmarks/results/full-b4/raw/b4_upload_rebuild.jsonl` (Run 2),
  `benchmarks/results/full-b4-run3/raw/b4_upload_rebuild.jsonl` (Run 3) —
  benchmark `rebuild_index_total`, phase = `measure`
- **X-axis:** checkpoint size in documents — 10, 25, 50, (100)
- **Y-axis:** median rebuild time in seconds
- **Error bars:** observed min–max range
- **Shows:** all three independent authoritative attempts at the B4 suite, each of which
  failed before reaching a 200-document checkpoint. Run 1 has no 100-document point (it
  failed earlier). A vertical marker and annotation at x = 200 makes explicit that the
  200-document checkpoint was never reached in any authoritative run — no value is
  plotted, extrapolated, or implied there.

## figure_4_b4_rebuild_decomposition.png
- **Source:** `benchmarks/results/full-b4/raw/b4_upload_rebuild.jsonl` (Run 2 only — the
  only authoritative run with a complete 4-step decomposition at the 100-document
  checkpoint) — benchmarks `rebuild_step_fetch_all_documents`,
  `rebuild_step_decrypt_and_tokenize`, `rebuild_step_build_index`,
  `rebuild_step_replace_index`, and `rebuild_index_total` (overlaid marker), phase =
  `measure`
- **X-axis:** checkpoint size — 10, 25, 50, 100 (no 200-document decomposition exists)
- **Y-axis:** median time in seconds (stacked bar = sum of the 4 steps; diamond marker =
  independently measured whole-rebuild time)
- **Shows:** `fetch_all_documents` (client ↔ cloud document retrieval) dominates rebuild
  cost at every checkpoint and grows fastest, while local cryptographic/index steps
  (decrypt+tokenize, build_index, replace_index) stay comparatively small.

## figure_5_b5_cloud_search.png
- **Source:** `benchmarks/results/full/raw/b5_search.jsonl` (benchmark
  `cloud_search_loop`, phase = `measure`)
- **X-axis:** number of matching documents — 1, 2, 5, 10, 25, 50, 100 (log scale, vault
  fixed at 100 documents)
- **Y-axis:** time in seconds
- **Error bars:** observed min–max range, n = 30 per point
- **Shows:** cloud-side search time is approximately flat (15–31 ms band) across the
  tested match-count range — explicitly not claimed to be perfectly constant (CV ≈
  23–38% at this scale, noted on the figure).

## figure_6_b5_client_latency.png
- **Source:** `benchmarks/results/full/raw/b5_search.jsonl` (benchmark
  `client_search_end_to_end`, phase = `measure`)
- **X-axis:** number of matching documents — same as Figure 5 (log scale)
- **Y-axis:** time in seconds
- **Error bars:** observed min–max range, n = 30 per point
- **Shows:** client end-to-end latency grows near-linearly with match count (0.049 s →
  1.683 s), because the client issues one `GET /documents/<id>` per matching result
  (eager per-result fetch). Contrasts directly with Figure 5's flat cloud-side curve —
  the bottleneck is the per-result fetch pattern, not cloud-side search cost.

## figure_7_b6_storage_footprint.png
- **Source:** `benchmarks/results/full/raw/b6_storage.jsonl` (phase = `scalar`,
  single 200-document snapshot — B6 was measured at only this one corpus size)
- **Shows:** two bars — (1) plaintext content + filename bytes, and (2) the actual
  encrypted SQLite database file size, decomposed into its named ciphertext/index/
  metadata components plus a derived "unattributed structural overhead" segment
  (`db_file_bytes − sum(named logical columns)`, i.e. not itself a directly measured
  field). Annotated with the resulting ≈10.63× database-file expansion vs. plaintext.
  Labeled explicitly as n = 1 / a single snapshot, not a scaling measurement.

---

## Integrity note

Before and after figure generation, SHA-256 hashes and modification timestamps were
recorded for all 10 source files (3 manifests + 7 raw JSONL files spanning `full/`,
`full-b4/`, `full-b4-run3/`) and confirmed byte-for-byte and timestamp-for-timestamp
identical. No benchmark suite was re-run. No application, harness, or benchmark-suite
code was modified. Only this directory (`benchmarks/figures/`) was newly created.
