"""
client/search.py -- Section 06's search-token generation + result
decryption. The other half of Phase 3's contract: indexer.build_index()
wrote labels with F(K1, counter) and values with AES-GCM(K2, doc_id);
this module derives the SAME K1/K2 for a queried keyword -- via
indexer.py's own functions, never a reimplementation -- and decrypts
whatever the cloud's search loop found.

Design note -- one deliberate, explained deviation from Section 06
----------------------------------------------------------------------
Section 06's pseudocode writes `token = (K1, K2)  # send to cloud`.
build_search_token() below returns ONLY K1. Reasoning:

  * cloud/cloud_app.py's search loop only ever uses K1, to regenerate
    labels and look them up. It never decrypts anything -- Section 02
    states "never decrypts, never sees a keyword, filename, or
    plaintext" as a hard invariant, tested since Phase 2.
  * K2 is used exclusively by decrypt_search_results() below, on the
    trusted client, on a value the client derives locally from
    (k_index, keyword) -- the exact computation that produced K1 a
    moment earlier. There is no reason for K2 to round-trip through
    the untrusted cloud to reach code that never lost it.
  * Section 07 flow C lists "Cloud looks up" (K1 only) and "Decrypt
    IDs" (client, K2) as separate steps -- consistent with this, not
    with sending K2 anywhere.
  * Sending K2 to the cloud has zero functional benefit and only
    widens, for no reason, how much key material ever reaches the
    untrusted side -- directly against this project's standing "zero
    keys ever cross to the cloud" invariant (Phase 2's explicit
    requirement, verified there by inspecting the raw database and
    HTTP payloads for key bytes).

Flagged rather than silently changed, per instruction: this is a
one-line revert (add k2 to the token) if strict literal fidelity to
Section 06's pseudocode is preferred over this tightening.

Conjunctive (multi-keyword AND) search -- a scoped reversal of
Section 01's "multi-keyword/boolean search: Out" line
----------------------------------------------------------------------
normalise_conjunctive_query() below is the ONE relaxation of that
scope decision, and it is deliberately additive, not a rewrite of
normalise_query(): every single-keyword query still goes through the
exact unchanged Pi_bas path above, one K1 token, one cloud lookup.

The construction chosen is the simplest correct one, not the
strongest: N keywords -> N fully independent single-keyword Pi_bas
searches (this module's own build_search_token/decrypt_search_results,
called once per keyword, completely unchanged) -- and the AND is
computed by intersecting the N resulting doc_id sets, entirely on the
TRUSTED CLIENT (client_app.py's api_search route), never on the cloud.
A cross-tag construction (e.g. Cash et al.'s OXT) can hide more from
the cloud -- which term is rarest, for instance -- at the cost of a
substantially more complex token/index design; deliberately not
attempted here, the same "depth over breadth" call Section 01 already
makes for the base scheme.

This is NOT free: the cloud still runs each keyword's search
independently and still learns each one's own individual result count
and access pattern, exactly as Section 09 already documents for a
single-keyword query -- and it additionally learns that these specific
N tokens arrived together as one logical request, i.e. that these N
keywords are being searched jointly. That is new, and is exactly the
kind of leakage Section 01 was originally naming as a reason to keep
this out of scope. Naming it precisely, the way D1-D8 already do for
every other leak in this project, is what keeps adding it defensible
rather than a silent scope-creep. See architecture.html Section 09's
"Query conjunction" row and tests/test_security_demonstrations.py's D9
for the live, captured proof of exactly what the cloud receives.
"""

from __future__ import annotations

from typing import FrozenSet, Iterable, Set

from .crypto import aes_gcm_decrypt
from .indexer import keyword_label_key, keyword_value_key
from .tokenizer import tokenize


class AmbiguousQueryError(ValueError):
    """Raised when a query does not tokenize to exactly one keyword.

    This project scopes search to single exact-keyword queries only
    (Section 01: multi-keyword/boolean search is explicitly out of
    scope). Rather than silently picking one word out of several, or
    silently treating multiple words as an implicit multi-keyword
    search, an ambiguous query is rejected outright -- a scope
    boundary enforced in code, not just in the docs.
    """


def normalise_query(query: str) -> str:
    """tokenize() the raw query with the SAME tokenizer indexer.py
    used to build the index, and require it to reduce to exactly one
    keyword.

    Raises AmbiguousQueryError for zero keywords (an empty string, or
    a query made only of stopwords/punctuation) or more than one
    (a multi-word query).
    """
    keywords = tokenize(query)
    if len(keywords) != 1:
        raise AmbiguousQueryError(
            f"query {query!r} must tokenize to exactly one keyword, "
            f"got {sorted(keywords)!r} -- multi-keyword search is out of scope"
        )
    return next(iter(keywords))


def normalise_conjunctive_query(query: str) -> "FrozenSet[str]":
    """tokenize() the raw query into EVERY keyword it reduces to -- one
    or more terms, with an implicit AND: a matching document must
    contain every keyword in the returned set, not just one of them.

    Deliberately the only difference from normalise_query() above: this
    accepts more than one keyword instead of rejecting it. Still
    rejects a query that tokenizes to ZERO keywords (an empty string,
    or one made only of stopwords/punctuation) with the same
    AmbiguousQueryError -- an empty AND is not a meaningful query
    either way, and there is no reasonable default to silently fall
    back to.

    Term ORDER carries no meaning here (AND is commutative) and is
    deliberately discarded: the caller gets back a set, not the
    original word order, so nothing downstream can accidentally treat
    query phrasing as significant when this scheme has no concept of
    phrase or proximity search.
    """
    keywords = tokenize(query)
    if not keywords:
        raise AmbiguousQueryError(
            f"query {query!r} does not contain any indexable keyword"
        )
    return frozenset(keywords)


def build_search_token(k_index: bytes, keyword: str) -> bytes:
    """K1 = F(K_index, '1' || w) for an already-normalised keyword.

    Reuses indexer.keyword_label_key() rather than re-deriving the
    formula, so index-time and search-time can never silently drift
    apart on it. This is the only thing sent to the cloud for a search
    -- see the module docstring for why K2 does not travel with it.
    """
    return keyword_label_key(k_index, keyword)


def decrypt_search_results(
    k_index: bytes, keyword: str, encrypted_values: "Iterable[bytes]"
) -> "Set[str]":
    """Decrypt every value the cloud's search loop returned for
    `keyword` into the plaintext doc_id set. K2 is derived locally --
    it was never sent anywhere and never needs to be.

    Raises client.crypto.DecryptionError (propagated, not caught) if
    ANY returned value fails to decrypt -- a tampered/corrupted value
    from the cloud, or a keyword/key mismatch. This aborts the whole
    batch rather than silently dropping the bad entry and returning a
    partial result: a search result that quietly lost documents is a
    worse failure mode than one that fails loudly.
    """
    k2 = keyword_value_key(k_index, keyword)
    return {aes_gcm_decrypt(k2, value).decode("utf-8") for value in encrypted_values}
