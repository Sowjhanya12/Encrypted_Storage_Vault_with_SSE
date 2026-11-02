"""
Suite B3 -- encrypted index construction.

Times the two client-side steps that turn a corpus into the flat Pi_bas
dictionary the cloud stores: tokenizing every document, and building the
index from the resulting keyword sets. Both are the shipped
implementations -- `client.tokenizer.tokenize` and
`client.indexer.build_index` -- called exactly as `client_app.py`'s
rebuild path calls them. Nothing here is optimised, patched or shadowed
for the benchmark; the point is to measure the system that exists.

What is measured, and against which implementation
--------------------------------------------------
  tokenize_corpus        client.tokenizer.tokenize over every document
  build_index            client.indexer.build_index (labels + encrypted ids)
  tokenize_and_build     both, as the rebuild path performs them

Why the scaling analysis needs both axes
----------------------------------------
Document count is the axis a reader expects; **total postings** -- the
number of (keyword, document) pairs -- is the axis the work is actually
proportional to. `build_index` performs one HMAC and one AES-GCM
encryption per posting, and postings per document vary with document
length and vocabulary overlap. Plotting against documents alone would
hide that, and would silently attribute to "more documents" a cost that
is really "more postings per document". Both are recorded for every
corpus size, as scalars alongside the timings, so the analysis step can
fit and plot either and the report can show they tell the same story --
or, if they do not, say so.

Postings is also the quantity architecture Section 09 names as the
cloud's `setup size` leakage, so this suite's x-axis is the same number
the security analysis already discusses.

Separation of setup from measurement
------------------------------------
`build_index` takes already-tokenized keyword sets, so tokenization is
performed in the untimed `setup` callback for the build_index benchmark
and timed on its own in `tokenize_corpus`. The combined
`tokenize_and_build` figure exists so the two can be checked against
their sum rather than assumed additive.
"""

from __future__ import annotations

from typing import Dict, List

from ..config import Profile
from ..harness.corpus import corpus_fingerprint, generate_corpus, keyword_stats
from ..harness.recorder import Recorder
from ..harness.timing import measure, timer_resolution
from ..harness.vault import benchmark_doc_id, benchmark_keyset

from client.indexer import build_index
from client.tokenizer import tokenize

SUITE_ID = "b3_indexing"
TITLE = "Encrypted index construction"


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"B3 correctness gate failed: {message}")


def _tokenize_corpus(documents) -> "Dict[str, set]":
    """Exactly what client_app._rebuild_and_push_index does to build its
    `documents` mapping: tokenize each document's text and key it by
    doc_id."""
    return {benchmark_doc_id(d.index): tokenize(d.text) for d in documents}


def run(recorder: Recorder, profile: Profile) -> dict:
    resolution = timer_resolution()
    keys = benchmark_keyset()
    checks: "List[str]" = []
    corpora: "List[dict]" = []

    for size in profile.index_corpus_sizes:
        documents = generate_corpus(size)
        stats = keyword_stats(documents)
        fingerprint = corpus_fingerprint(documents)

        tokenized = _tokenize_corpus(documents)
        entries = build_index(keys.k_index, tokenized)

        # -- correctness gates -------------------------------------------
        _check(len(entries) == stats["total_postings"],
               f"build_index emitted {len(entries)} entries for {stats['total_postings']} "
               f"postings at {size} documents -- the postings axis would be wrong")
        _check(len({e.label for e in entries}) == len(entries),
               "build_index produced duplicate labels -- the cloud's sse_index primary "
               "key would reject them")
        _check(len(tokenized) == size, "tokenization lost or duplicated a document")
        rebuilt = build_index(keys.k_index, tokenized)
        _check({e.label for e in rebuilt} == {e.label for e in entries},
               "two builds of the same corpus produced different labels -- rebuilds "
               "would orphan index rows")
        _check({e.value for e in rebuilt} != {e.value for e in entries},
               "two builds produced identical ciphertext values -- fresh AES-GCM nonces "
               "are what stop the cloud diffing two index snapshots")

        # -- corpus shape, recorded as measured scalars -------------------
        for name, value, unit in (
            ("corpus_documents", stats["documents"], "count"),
            ("corpus_total_postings", stats["total_postings"], "count"),
            ("corpus_distinct_keywords", stats["distinct_keywords"], "count"),
            ("corpus_text_bytes", stats["total_text_bytes"], "bytes"),
            ("index_entries_built", len(entries), "count"),
            ("index_entry_value_bytes", len(entries[0].value), "bytes"),
            ("index_entry_label_chars", len(entries[0].label), "count"),
        ):
            recorder.add_scalar(SUITE_ID, name, {"documents": size}, value, unit)

        # -- timings -------------------------------------------------------
        m = measure(
            lambda docs=documents: _tokenize_corpus(docs),
            repeats=profile.index_repeats,
            warmup=profile.default_warmup,
            batch=1,
        )
        recorder.add_measurement(
            SUITE_ID, "tokenize_corpus",
            {
                "documents": size,
                "total_postings": stats["total_postings"],
                "distinct_keywords": stats["distinct_keywords"],
                "corpus_text_bytes": stats["total_text_bytes"],
                "corpus_fingerprint_sha256": fingerprint,
            },
            m,
            notes="client.tokenizer.tokenize over every document, keyed by doc_id -- "
                  "the mapping client_app's rebuild path feeds to build_index.",
        )

        m = measure(
            lambda t=tokenized: build_index(keys.k_index, t),
            repeats=profile.index_repeats,
            warmup=profile.default_warmup,
            batch=1,
        )
        recorder.add_measurement(
            SUITE_ID, "build_index",
            {
                "documents": size,
                "total_postings": stats["total_postings"],
                "distinct_keywords": stats["distinct_keywords"],
                "corpus_text_bytes": stats["total_text_bytes"],
                "corpus_fingerprint_sha256": fingerprint,
            },
            m,
            notes="client.indexer.build_index on already-tokenized input: one HMAC "
                  "label and one AES-GCM encrypted doc_id per posting. Tokenization "
                  "is excluded and timed separately.",
        )

        m = measure(
            lambda docs=documents: build_index(keys.k_index, _tokenize_corpus(docs)),
            repeats=profile.index_repeats,
            warmup=profile.default_warmup,
            batch=1,
        )
        recorder.add_measurement(
            SUITE_ID, "tokenize_and_build",
            {
                "documents": size,
                "total_postings": stats["total_postings"],
                "distinct_keywords": stats["distinct_keywords"],
                "corpus_text_bytes": stats["total_text_bytes"],
                "corpus_fingerprint_sha256": fingerprint,
            },
            m,
            notes="Both steps together -- the whole client-side index construction "
                  "cost, recorded so the two separate figures can be checked against "
                  "it rather than assumed additive.",
        )

        corpora.append({
            "documents": size,
            "fingerprint_sha256": fingerprint,
            "total_postings": stats["total_postings"],
            "distinct_keywords": stats["distinct_keywords"],
            "total_text_bytes": stats["total_text_bytes"],
            "keywords_per_document_mean": round(stats["keywords_per_document_mean"], 2),
        })

    checks.append(
        "at every corpus size: entry count equals total postings, labels are unique, "
        "labels are stable across rebuilds, and values are not (fresh nonces)"
    )

    return {
        "measures": ["tokenize_corpus", "build_index", "tokenize_and_build"],
        "implementations_under_test": ["client.tokenizer.tokenize", "client.indexer.build_index"],
        "scaling_axes": ["documents", "total_postings"],
        "corpora": corpora,
        "probe_keywords_planted": False,
        "correctness_gates": checks,
        "clock_resolution_seconds": resolution,
    }
