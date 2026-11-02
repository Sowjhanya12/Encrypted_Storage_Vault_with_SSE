"""
client/indexer.py -- builds the flat Pi_bas encrypted index (Section 05).

Given a corpus (doc_id -> the keyword set tokenizer.tokenize() already
extracted for that document), this module derives per-keyword label
and value keys from K_index and emits the complete flat dictionary D
that the cloud stores in its `sse_index` table: label -> value pairs,
indistinguishable from each other, with no visible grouping by
keyword (Section 05's central point).

    # For every keyword w and its matching documents id[0..c-1]:
    K1 = F(K_index, 1 || w)        # label key
    K2 = F(K_index, 2 || w)        # value key
    for counter, id in enumerate(matching_docs):
        label = F(K1, counter)
        value = AES_GCM_Enc(K2, id)
        D[label] = value

This module does index construction ONLY:

  * It does not tokenize -- callers must pass already-tokenized
    keyword sets, so the "one shared tokenizer" rule (Section 05) is
    enforced by construction: whichever code path calls tokenize() for
    indexing must be the exact same function search will call later,
    and this module has no opportunity to quietly diverge from that.
  * It does not talk to the network -- callers push the returned
    entries to cloud/cloud_app.py's /index route themselves (a later
    phase's client_app.py; today, tests play that role).
  * It does not implement search or result decryption. Section 11
    explicitly assigns "token generation + result decryption" to
    search.py in Phase 4 -- not duplicated here, even though the
    decrypt step is a one-line inverse of this module's encrypt step.

Static-index limitation (Section 10, "Static-only assumption"): this
is a batch, from-scratch build. There is no incremental "add one file
to an existing index" operation -- adding a file means re-running
build_index() over the whole corpus (including the new file) and
re-uploading the result. This project does not claim forward privacy;
patching a live index safely requires a forward-private construction,
named as future work in Section 01/10, not implemented here.

Shared derivation contract with Phase 4
----------------------------------------
keyword_label_key(), keyword_value_key(), and counter_to_bytes() are
exported (not module-private) on purpose: Section 06's search-token
generation recomputes the *identical* K1, K2, and per-counter label
for a queried keyword. If indexer.py and the future search.py each
reimplemented that formula separately, the slightest encoding drift
(e.g. counter-as-decimal-string here vs counter-as-raw-int there)
would make every search silently return nothing. Phase 4 must import
these three functions rather than rederive the formula.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

from .crypto import aes_gcm_encrypt, prf

# Domain-separation markers matching the architecture doc's own
# notation ("1 || w", "2 || w") literally -- K1 and K2 can never
# collide because they diverge at the very first byte fed to F.
_LABEL_KEY_DOMAIN = b"1"
_VALUE_KEY_DOMAIN = b"2"

# Fixed-width counter encoding shared by index build (here) and search
# (Phase 4). 8 bytes big-endian: simple, unambiguous, and large enough
# that no realistic corpus will ever approach overflow.
_COUNTER_BYTE_LENGTH = 8


@dataclass(frozen=True)
class IndexEntry:
    """One row of the flat dictionary D. `label` is a hex string (the
    sse_index.label TEXT column); `value` is the AES-GCM blob (the
    sse_index.value BLOB column) -- convert with `(e.label, e.value)`
    when handing entries to cloud.storage.save_index_entries or the
    /index HTTP route, both of which already expect that shape."""

    label: str
    value: bytes


def counter_to_bytes(counter: int) -> bytes:
    """Encode a postings counter for F(K1, counter). Fixed-width
    big-endian so two different counters can never encode to the same
    bytes -- Phase 4 MUST use this exact function, not reimplement it,
    or index/search will disagree on labels."""
    if counter < 0:
        raise ValueError("counter must be non-negative")
    return counter.to_bytes(_COUNTER_BYTE_LENGTH, "big")


def keyword_label_key(k_index: bytes, keyword: str) -> bytes:
    """K1 = F(K_index, "1" || w) -- the per-keyword label key."""
    return prf(k_index, _LABEL_KEY_DOMAIN + keyword.encode("utf-8"))


def keyword_value_key(k_index: bytes, keyword: str) -> bytes:
    """K2 = F(K_index, "2" || w) -- the per-keyword value key."""
    return prf(k_index, _VALUE_KEY_DOMAIN + keyword.encode("utf-8"))


def build_index(k_index: bytes, documents: "Dict[str, Iterable[str]]") -> "List[IndexEntry]":
    """Build the complete flat dictionary D for a corpus.

    `documents` maps doc_id -> that document's tokenized keyword set
    (as produced by tokenizer.tokenize() -- this function does not
    tokenize anything itself).

    Documents are processed in doc_id-sorted order, so the LABEL each
    (keyword, counter) pair receives is deterministic: the same
    (k_index, documents) always assigns the same labels, regardless of
    dict insertion order. That is what makes "rebuild the whole index"
    (Section 10) a coherent operation rather than one that silently
    reshuffles postings counters every time it runs.

    The VALUES are deliberately NOT deterministic across rebuilds:
    each is AES-GCM(K2, doc_id) with a fresh random nonce (Phase 1's
    aes_gcm_encrypt never accepts a caller-supplied one), so
    re-encrypting the same doc_id under the same K2 twice produces
    different ciphertext bytes both times. This is a security property,
    not an inconsistency -- if an unchanged posting re-encrypted to
    identical bytes on every rebuild, a curious cloud could diff two
    sse_index snapshots and learn which (keyword, document) pairs
    persisted unchanged across an update, without decrypting anything.
    Fresh nonces deny it that comparison.

    Returns a flat list -- Section 05's point that there is no visible
    grouping by keyword once inserted into one table; this function
    doesn't group its own output either.
    """
    postings: "Dict[str, List[str]]" = {}
    for doc_id in sorted(documents.keys()):
        for keyword in documents[doc_id]:
            postings.setdefault(keyword, []).append(doc_id)

    entries: List[IndexEntry] = []
    for keyword, doc_ids in postings.items():
        k1 = keyword_label_key(k_index, keyword)
        k2 = keyword_value_key(k_index, keyword)
        for counter, doc_id in enumerate(doc_ids):
            label = prf(k1, counter_to_bytes(counter)).hex()
            value = aes_gcm_encrypt(k2, doc_id.encode("utf-8"))
            entries.append(IndexEntry(label=label, value=value))
    return entries
