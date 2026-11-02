"""
Suite B5 -- search latency.

Architecture Section 14 predicts search cost "should scale with result
size, not total corpus". This suite tests that prediction against the
implementation instead of repeating it, and it separates two boundaries
the project's own security analysis already treats as distinct.

Two measurement boundaries, deliberately kept apart
---------------------------------------------------
`cloud_search_loop` -- one `POST /search` to the untrusted cloud carrying
only K1, timed around `cloud_client.run_remote_search`. This is the Pi_bas
loop itself: regenerate F(K1, counter) labels, look each up, stop at the
first miss. It is the cost the *scheme* implies.

`client_search_end_to_end` -- one `POST /api/search` on the trusted
client: normalise the query, derive K1, the same cloud search, then one
`GET /documents/<doc_id>` per result so the filename can be decrypted, then
decrypting every returned id. This is the latency a user actually waits
for.

The difference between the two is not overhead in general -- it is
specifically the eager per-result fetch that audit finding M4 names and
demonstration D3b shows the cloud can read. B5 turns that finding into a
number: how many milliseconds, per matching document, the current design
spends handing the cloud its own access pattern.

Exact match counts, not approximate ones
----------------------------------------
The x-axis comes from the Step-2 probe keywords: `probekw0025` is planted
in exactly 25 documents. Before any timing is recorded, the live system is
asked for that keyword and the returned document set is compared against
the corpus ground truth -- so a search that silently returned the wrong
number of results can never contribute a fast, meaningless sample.

Second experiment: is the cost really independent of corpus size?
-----------------------------------------------------------------
Holding the result count fixed at `search_scaling_fixed_k` and growing the
vault tests Section 14's claim directly. There is a specific reason to
doubt it: `cloud/cloud_app.py`'s `run_search_loop` calls
`storage.index_entry_count(conn)` -- a `COUNT(*)` over the whole
`sse_index` table -- once per search, as a defensive loop bound, and
SQLite primary-key lookups are O(log n) in table size. Whether that is
measurable at this scale is exactly what the experiment reports; the
outcome is not assumed in either direction.
"""

from __future__ import annotations

from typing import Dict, List

from ..config import Profile
from ..harness.cloud_process import LiveCloud
from ..harness.corpus import (
    corpus_fingerprint,
    documents_containing,
    generate_corpus,
    keyword_stats,
    probe_keyword,
)
from ..harness.recorder import Recorder
from ..harness.timing import measure, timer_resolution
from ..harness.vault import populate_vault, unlock_client_app, benchmark_client_config
from ..harness.wire import record_wire

from client import client_app, cloud_client
from client.search import build_search_token

SUITE_ID = "b5_search"
TITLE = "Search latency vs. matching documents"

# Access-pattern sequences are recorded in full up to this many calls; beyond
# it the manifest keeps a shape summary plus the first few calls, because a
# 200-line verbatim sequence adds bulk without adding evidence.
_FULL_SEQUENCE_LIMIT = 12


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"B5 correctness gate failed: {message}")


def _expected_doc_ids(documents, doc_ids: "Dict[str, str]", keyword: str) -> "set":
    """Ground truth for a probe keyword: which uploaded documents contain
    it, mapped to the doc_ids the vault stored them under."""
    indices = documents_containing(documents, keyword)
    by_index = {d.index: d.filename for d in documents}
    return {doc_ids[by_index[i]] for i in indices}


def _measure_one_vault(recorder, profile, documents, match_counts, benchmark_suffix, extra_params):
    """Populate a live vault with `documents` and time both search
    boundaries for every keyword in `match_counts`."""
    stats = keyword_stats(documents)
    fingerprint = corpus_fingerprint(documents)
    results = []

    with LiveCloud() as cloud:
        app = client_app.create_app(benchmark_client_config())
        client = app.test_client()
        try:
            keys = unlock_client_app(client)
            doc_ids = populate_vault(keys, documents)

            for k in match_counts:
                keyword = probe_keyword(k)
                expected = _expected_doc_ids(documents, doc_ids, keyword)
                _check(len(expected) == k,
                       f"corpus ground truth says {keyword} is in {len(expected)} documents, not {k}")

                # -- correctness gate against the LIVE system ---------------
                response = client.post("/api/search", json={"query": keyword})
                _check(response.status_code == 200,
                       f"search for {keyword} returned {response.status_code}")
                body = response.get_json()
                returned = {r["doc_id"] for r in body["results"]}
                _check(returned == expected,
                       f"search for {keyword} returned {len(returned)} documents, "
                       f"expected exactly {k} and the same ids")

                # -- access pattern, captured untimed -----------------------
                with record_wire(cloud.base_url) as wire:
                    client.post("/api/search", json={"query": keyword})
                sequence = wire.sequence
                fetches = wire.count("GET", r"/documents/[0-9a-f]+")
                _check(fetches == k,
                       f"expected {k} document fetches for a {k}-result search, saw {fetches}")

                token = build_search_token(keys.k_index, keyword)

                m = measure(
                    lambda t=token: cloud_client.run_remote_search(t),
                    repeats=profile.search_repeats,
                    warmup=profile.default_warmup,
                    batch=1,
                )
                recorder.add_measurement(
                    SUITE_ID, f"cloud_search_loop{benchmark_suffix}",
                    {
                        "matching_documents": k,
                        "vault_documents": len(documents),
                        "total_postings": stats["total_postings"],
                        "corpus_fingerprint_sha256": fingerprint,
                        **extra_params,
                    },
                    m,
                    notes="POST /search carrying only K1 -- the Pi_bas loop on the "
                          "untrusted cloud, no document fetches, no decryption.",
                )
                cloud_median = m.stats.median

                m = measure(
                    lambda w=keyword: client.post("/api/search", json={"query": w}),
                    repeats=profile.search_repeats,
                    warmup=profile.default_warmup,
                    batch=1,
                )
                recorder.add_measurement(
                    SUITE_ID, f"client_search_end_to_end{benchmark_suffix}",
                    {
                        "matching_documents": k,
                        "vault_documents": len(documents),
                        "total_postings": stats["total_postings"],
                        "corpus_fingerprint_sha256": fingerprint,
                        **extra_params,
                    },
                    m,
                    notes="POST /api/search -- token generation, the cloud search, one "
                          "GET /documents/<doc_id> per result for the filename, and "
                          "result decryption.",
                )
                client_median = m.stats.median

                recorder.add_scalar(
                    SUITE_ID, f"search_result_count{benchmark_suffix}",
                    {"matching_documents": k, "vault_documents": len(documents)},
                    len(returned), "count",
                    notes="documents the live system returned, verified against corpus ground truth",
                )
                recorder.add_scalar(
                    SUITE_ID, f"search_document_fetches{benchmark_suffix}",
                    {"matching_documents": k, "vault_documents": len(documents)},
                    fetches, "count",
                    notes="observed GET /documents/<doc_id> calls -- audit M4 / demonstration "
                          "D3b, counted from real traffic",
                )
                recorder.add_scalar(
                    SUITE_ID, f"eager_fetch_cost_seconds{benchmark_suffix}",
                    {"matching_documents": k, "vault_documents": len(documents)},
                    max(client_median - cloud_median, 0.0), "s",
                    notes="client end-to-end median minus cloud search median -- the measured "
                          "price of the eager per-result fetch",
                )

                results.append({
                    "matching_documents": k,
                    "vault_documents": len(documents),
                    "cloud_median_seconds": cloud_median,
                    "client_median_seconds": client_median,
                    "document_fetches": fetches,
                    "access_pattern": (
                        sequence if len(sequence) <= _FULL_SEQUENCE_LIMIT
                        else sequence[:5] + [f"... {len(sequence) - 5} further calls omitted"]
                    ),
                    "access_pattern_shape": wire.summary(),
                })
        finally:
            client.post("/api/lock")

    return results, stats, fingerprint


def run(recorder: Recorder, profile: Profile) -> dict:
    resolution = timer_resolution()
    match_counts = list(profile.search_match_counts)
    checks: "List[str]" = []

    # -- experiment 1: latency vs number of matching documents -------------
    main_size = max(match_counts)
    documents = generate_corpus(main_size, probe_frequencies=match_counts)
    by_k, stats, fingerprint = _measure_one_vault(
        recorder, profile, documents, match_counts, "", {"experiment": "match_count_scaling"}
    )
    checks.append(
        f"every probe keyword returned exactly its planted document set from the live "
        f"system ({', '.join(str(k) for k in match_counts)} matches), and the observed "
        f"GET /documents count equalled the result count each time"
    )

    # -- experiment 2: latency vs index size, result count held fixed ------
    fixed_k = profile.search_scaling_fixed_k
    scaling: "List[dict]" = []
    for size in profile.search_scaling_corpus_sizes:
        if fixed_k > size:
            continue
        docs = generate_corpus(size, probe_frequencies=(fixed_k,))
        rows, size_stats, size_fingerprint = _measure_one_vault(
            recorder, profile, docs, [fixed_k], "_fixed_k",
            {"experiment": "index_size_scaling"},
        )
        for row in rows:
            row["total_postings"] = size_stats["total_postings"]
            row["corpus_fingerprint_sha256"] = size_fingerprint
        scaling.extend(rows)
    checks.append(
        f"index-size experiment held the result count fixed at {fixed_k} across "
        f"{len(scaling)} vault sizes"
    )

    return {
        "measures": [
            "cloud_search_loop", "client_search_end_to_end", "search_result_count",
            "search_document_fetches", "eager_fetch_cost_seconds",
            "cloud_search_loop_fixed_k", "client_search_end_to_end_fixed_k",
        ],
        "implementations_under_test": [
            "client.client_app (POST /api/search)", "client.search.build_search_token",
            "client.search.decrypt_search_results", "client.cloud_client.run_remote_search",
            "client.tokenizer.tokenize",
        ],
        "topology": "trusted client in-process (Flask test client) -> real HTTP -> cloud_app.py subprocess",
        "experiment_match_count_scaling": {
            "vault_documents": main_size,
            "corpus_fingerprint_sha256": fingerprint,
            "total_postings": stats["total_postings"],
            "match_counts": match_counts,
            "results": by_k,
        },
        "experiment_index_size_scaling": {
            "fixed_result_count": fixed_k,
            "vault_sizes": list(profile.search_scaling_corpus_sizes),
            "results": scaling,
        },
        "correctness_gates": checks,
        "clock_resolution_seconds": resolution,
    }
