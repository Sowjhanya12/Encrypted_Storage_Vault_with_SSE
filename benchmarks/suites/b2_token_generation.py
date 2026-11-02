"""
Suite B2 -- search-token generation.

The client-side half of a search, before a single byte reaches the
network: normalise the query with the shared tokenizer, derive K1 (the
only thing sent to the cloud), and derive K2 (which never leaves the
client and is used to decrypt the results). Architecture Section 14 lists
"token generation time" as a metric and predicts it is "effectively
constant; shows client cost is trivial" -- this suite is what turns that
prediction into a measurement, and it is measured against the real
`client/search.py` and `client/indexer.py`, not a reimplementation.

What is measured, and against which implementation
--------------------------------------------------
  normalise_query              client.search.normalise_query   (tokenizer + arity check)
  build_search_token           client.search.build_search_token (K1 = F(K_index, "1"||w))
  derive_value_key             client.indexer.keyword_value_key (K2, client-side only)
  full_client_token_path       both of the above, as api_search calls them
  rejected_multi_word_query    the AmbiguousQueryError path
  rejected_stopword_only_query the AmbiguousQueryError path

Why the rejection paths are timed too
-------------------------------------
`normalise_query` refuses any query that does not reduce to exactly one
keyword (multi-keyword search is out of scope by design, architecture
Section 01). A rejection is a real user-facing outcome, and timing it
shows the refusal is cheap -- it costs a tokenize and a length check, with
no key derivation and no network call. It also documents that an
out-of-scope query is rejected rather than silently reinterpreted.

Query cases come from the corpus
--------------------------------
The keywords benchmarked are drawn from the deterministic corpus rather
than invented here, so the measured input is exactly the kind of token the
index actually holds, and the corpus fingerprint is recorded with the
results. Keyword length is varied deliberately: HMAC-SHA256 processes its
input in 64-byte blocks, so a keyword short enough to fit one block and a
keyword long enough to need two are the honest way to ask whether token
cost depends on the keyword at all.
"""

from __future__ import annotations

from typing import List

from ..config import Profile
from ..harness.corpus import generate_corpus, corpus_fingerprint
from ..harness.recorder import Recorder
from ..harness.timing import adaptive_measure, timer_resolution
from ..harness.vault import benchmark_keyset

from client.indexer import keyword_value_key
from client.search import AmbiguousQueryError, build_search_token, normalise_query
from client.tokenizer import tokenize

SUITE_ID = "b2_token_generation"
TITLE = "Search-token generation (client side)"

# Corpus size used purely as a source of realistic keywords -- this suite
# does not index anything, so the size only needs to be large enough to
# offer a spread of keyword lengths.
_KEYWORD_SOURCE_DOCUMENTS = 25


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"B2 correctness gate failed: {message}")


def _keyword_cases(documents) -> "List[tuple]":
    """(case_name, query_string, expected_keyword) drawn deterministically
    from the corpus: the shortest keyword, a typical one, and the longest.

    Sorted before selecting so the choice does not depend on set iteration
    order, which is not stable across processes.
    """
    keywords = sorted(set().union(*(d.keywords for d in documents)))
    alphabetic = [w for w in keywords if w.isalpha()]
    shortest = min(alphabetic, key=lambda w: (len(w), w))
    longest = max(alphabetic, key=lambda w: (len(w), w))
    typical = sorted(alphabetic, key=lambda w: (len(w), w))[len(alphabetic) // 2]
    return [
        ("shortest_keyword", shortest, shortest),
        ("typical_keyword", typical, typical),
        ("longest_keyword", longest, longest),
        # The same keyword reached through the normalisation the tokenizer
        # actually performs: upper case, surrounding punctuation, whitespace.
        ("mixed_case_and_punctuation", f"  {typical.upper()}!  ", typical),
    ]


def run(recorder: Recorder, profile: Profile) -> dict:
    resolution = timer_resolution()
    keys = benchmark_keyset()
    documents = generate_corpus(_KEYWORD_SOURCE_DOCUMENTS)
    fingerprint = corpus_fingerprint(documents)
    checks = []

    cases = _keyword_cases(documents)

    # -- correctness gates, before any timing -----------------------------
    for name, query, expected in cases:
        _check(normalise_query(query) == expected,
               f"{name}: normalise_query({query!r}) did not yield {expected!r}")
    checks.append("every query case normalises to its expected keyword")

    sample_keyword = cases[1][2]
    token_a = build_search_token(keys.k_index, sample_keyword)
    token_b = build_search_token(keys.k_index, sample_keyword)
    _check(token_a == token_b, "the same keyword produced two different search tokens")
    _check(len(token_a) == 32, "search token is not a 32-byte HMAC-SHA256 output")
    _check(build_search_token(keys.k_index, cases[0][2]) != token_a,
           "two different keywords produced the same search token")
    _check(keyword_value_key(keys.k_index, sample_keyword) != token_a,
           "K1 and K2 collided for the same keyword -- domain separation is broken")
    checks.append(
        "token determinism, 32-byte length, keyword distinctness and K1/K2 "
        "domain separation verified before timing"
    )

    # -- the three steps, separately ---------------------------------------
    for name, query, expected in cases:
        m, prov = adaptive_measure(
            lambda q=query: normalise_query(q),
            repeats=profile.micro_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, "normalise_query",
            {"case": name, "query_chars": len(query), "keyword": expected,
             "keyword_chars": len(expected), **prov},
            m,
            notes="client.search.normalise_query -- the shared tokenizer plus the "
                  "single-keyword arity check. " + prov["batched_reason"],
        )

        m, prov = adaptive_measure(
            lambda w=expected: build_search_token(keys.k_index, w),
            repeats=profile.micro_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, "build_search_token",
            {"case": name, "keyword": expected, "keyword_chars": len(expected),
             "hmac_blocks": 1 + (len(expected) + 1) // 64, **prov},
            m,
            notes="client.search.build_search_token -- K1 = F(K_index, '1'||w), the "
                  "only key material that ever crosses to the cloud. " + prov["batched_reason"],
        )

        m, prov = adaptive_measure(
            lambda w=expected: keyword_value_key(keys.k_index, w),
            repeats=profile.micro_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, "derive_value_key",
            {"case": name, "keyword": expected, "keyword_chars": len(expected), **prov},
            m,
            notes="client.indexer.keyword_value_key -- K2, derived locally at result "
                  "decryption time and never transmitted. " + prov["batched_reason"],
        )

        def full_path(q=query):
            keyword = normalise_query(q)
            build_search_token(keys.k_index, keyword)

        m, prov = adaptive_measure(
            full_path,
            repeats=profile.micro_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, "full_client_token_path",
            {"case": name, "query_chars": len(query), "keyword_chars": len(expected), **prov},
            m,
            notes="Everything client_app.api_search does between receiving a query and "
                  "making the HTTP call: normalise, then derive K1. " + prov["batched_reason"],
        )

    # -- rejection paths ----------------------------------------------------
    rejected = [
        ("multi_word_query", "annual report summary"),
        ("stopword_only_query", "the and of"),
    ]
    for name, query in rejected:
        try:
            normalise_query(query)
        except AmbiguousQueryError:
            pass
        else:
            raise AssertionError(f"B2 correctness gate failed: {query!r} was not rejected")

        def rejected_path(q=query):
            try:
                normalise_query(q)
            except AmbiguousQueryError:
                return None

        m, prov = adaptive_measure(
            rejected_path,
            repeats=profile.micro_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, f"rejected_{name}",
            {"query_chars": len(query), "tokens": len(tokenize(query)), **prov},
            m,
            notes="Out-of-scope query refused by client.search.normalise_query: no key "
                  "derivation, no network call. " + prov["batched_reason"],
        )
    checks.append("both out-of-scope query shapes verified to raise AmbiguousQueryError")

    return {
        "measures": [
            "normalise_query", "build_search_token", "derive_value_key",
            "full_client_token_path", "rejected_multi_word_query",
            "rejected_stopword_only_query",
        ],
        "implementations_under_test": [
            "client.search.normalise_query", "client.search.build_search_token",
            "client.indexer.keyword_value_key", "client.tokenizer.tokenize",
        ],
        "corpus": {
            "documents": _KEYWORD_SOURCE_DOCUMENTS,
            "fingerprint_sha256": fingerprint,
            "role": "source of realistic keywords only -- nothing is indexed in this suite",
        },
        "query_cases": [
            {"case": name, "query": query, "keyword": expected, "keyword_chars": len(expected)}
            for name, query, expected in cases
        ],
        "rejected_cases": [{"case": n, "query": q} for n, q in rejected],
        "correctness_gates": checks,
        "clock_resolution_seconds": resolution,
    }
