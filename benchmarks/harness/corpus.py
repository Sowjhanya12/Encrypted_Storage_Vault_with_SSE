"""
benchmarks/harness/corpus.py -- the deterministic synthetic corpus every
Phase 7 measurement runs against.

A benchmark is only reproducible if its input is. This module generates
document number *n* from a seed derived from *n* alone, so:

  * the same corpus appears on every machine, in every run, forever --
    your Windows run and any run made here index byte-identical text,
    which is what makes the two sets of numbers comparable at all;
  * a 200-document corpus **contains the 10-document corpus as its exact
    prefix** (per-document seeding, not one shared random stream), so the
    scaling curves in suites B3/B4/B5 measure "the same documents plus
    more", never "a differently-shaped corpus at each size". Without this,
    a bend in a scaling curve could be the corpus changing rather than the
    system behaving differently, and the curve would prove nothing.

Honesty about what this corpus is
---------------------------------
It is **synthetic pseudo-text**, not natural language, and the report says
so. What it deliberately reproduces is the property the SSE index is
sensitive to -- the *shape* of the keyword distribution:

  * Word frequencies follow a Zipf-like power law (config.CORPUS_ZIPF_EXPONENT),
    the distribution English actually exhibits. Drawing words uniformly
    instead would give nearly every document the same keyword count and
    make index size a straight line by construction -- a flattering result
    that measures the generator, not the indexer.
  * Roughly 40% of emitted words are real English stop words taken from
    client/tokenizer.py's own list, and the text carries capitalisation,
    punctuation, hyphenated forms and digits. The tokenizer therefore does
    its real work (lower-casing, splitting, length filtering, stop-word
    removal, per-document dedup) rather than being handed a pre-cleaned
    word list, which would understate indexing cost.

What it does NOT reproduce is genuine semantics: no topical clustering, no
phrases, no correlation between documents. That limitation is stated in
the report's threats-to-validity section rather than glossed over.

Probe keywords
--------------
Suite B5 needs to ask "how does search latency scale with the number of
matching documents?", which requires keywords whose document frequency is
known *exactly*, not approximately. `plant_probes` inserts synthetic tags
of the form `probekw0025` into exactly the first k documents. They cannot
collide with generated vocabulary (which never contains digits) and they
survive tokenization unchanged, both asserted by the self-tests.

Determinism discipline
----------------------
Only `random.Random.random()` is used -- never `choice`, `choices`,
`randrange` or `shuffle`. Python guarantees the Mersenne Twister stream
itself is stable across versions, but the *consumer* helpers are
implementation details that could in principle change how many values
they draw. Every integer and every word here is derived from raw
`random()` floats by arithmetic written out in this file, so the corpus
depends on nothing that could quietly shift under a Python upgrade.
"""

from __future__ import annotations

import bisect
import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from random import Random
from typing import Dict, Iterable, List, Sequence, Tuple

from .. import config

# Imported read-only, so the corpus is filtered by the SAME stop-word list
# the vault's tokenizer applies. Re-typing the list here would let the two
# drift, and the whole project's "one shared tokenizer" rule (architecture
# Section 05) exists precisely to prevent that class of mistake.
from client.tokenizer import MIN_TOKEN_LENGTH, STOPWORDS, tokenize

_CONSONANTS = "bcdfghjklmnpqrstvwxz"
_VOWELS = "aeiou"

PROBE_PREFIX = "probekw"
"""Prefix of the planted, exactly-known-frequency search keywords. Contains
no digits itself, and generated vocabulary contains no digits at all, so a
probe tag can never be produced by chance."""

_STOPWORD_RATIO = 0.40
"""Share of emitted words drawn from the stop-word list. English function
words run roughly 40-50% of running text; matching that keeps the ratio of
'words the tokenizer discards' to 'keywords it keeps' realistic."""

_SENTENCE_WORDS = (8, 18)
_PARAGRAPH_SENTENCES = (4, 8)

_STOPWORD_TUPLE = tuple(sorted(STOPWORDS))  # sorted -> stable ordering to index into


# ---------------------------------------------------------------------------
# deterministic primitives
# ---------------------------------------------------------------------------

def _uniform_int(rng: Random, low: int, high: int) -> int:
    """Uniform integer in [low, high], derived from a single random()
    draw. See the module docstring on why `randint` is not used."""
    return low + int(rng.random() * (high - low + 1))


def _document_seed(index: int) -> int:
    """Seed for document `index`, derived from the corpus seed and the
    index alone -- the mechanism behind prefix stability."""
    return config.CORPUS_SEED * 1_000_003 + index


@lru_cache(maxsize=4)
def build_vocabulary(size: int = config.CORPUS_VOCABULARY_SIZE, seed: int = config.CORPUS_SEED) -> "Tuple[str, ...]":
    """`size` distinct pronounceable pseudo-words, ordered by intended
    frequency rank (index 0 is the most common word).

    Pseudo-words rather than a real word list on purpose: an external
    word list is a dependency that has to be downloaded, versioned and
    shipped for the corpus to be reproducible, and it buys nothing --
    the index cares about the *distribution* of tokens, not their
    meaning. Words are letters-only, at least MIN_TOKEN_LENGTH long,
    and never a stop word, so every one of them survives tokenization
    and counts as a real keyword.
    """
    rng = Random(seed)
    words: "List[str]" = []
    seen = set()
    while len(words) < size:
        syllables = _uniform_int(rng, 2, 4)
        word = ""
        for _ in range(syllables):
            word += _CONSONANTS[int(rng.random() * len(_CONSONANTS))]
            word += _VOWELS[int(rng.random() * len(_VOWELS))]
            if rng.random() < 0.30:
                word += _CONSONANTS[int(rng.random() * len(_CONSONANTS))]
        if len(word) < MIN_TOKEN_LENGTH or word in STOPWORDS or word in seen:
            continue
        if word.startswith(PROBE_PREFIX):
            continue  # cannot happen (no digits) -- excluded anyway, cheaply
        seen.add(word)
        words.append(word)
    return tuple(words)


@lru_cache(maxsize=4)
def _zipf_cumulative(size: int, exponent: float) -> "Tuple[float, ...]":
    """Cumulative distribution over ranks 1..size with P(r) proportional
    to 1 / r**exponent, normalised to 1.0.

    Built once and cached: a 200-document corpus draws ~140,000 words,
    and rebuilding a 4000-entry table per word would make corpus
    generation, rather than the vault, the thing being timed.
    """
    weights = [1.0 / ((r + 1) ** exponent) for r in range(size)]
    total = sum(weights)
    cumulative: "List[float]" = []
    running = 0.0
    for w in weights:
        running += w / total
        cumulative.append(running)
    cumulative[-1] = 1.0  # guard the float tail so bisect can never overrun
    return tuple(cumulative)


def _draw_content_word(rng: Random, vocabulary: "Sequence[str]", cumulative: "Sequence[float]") -> str:
    return vocabulary[bisect.bisect_left(cumulative, rng.random())]


def _draw_stopword(rng: Random) -> str:
    return _STOPWORD_TUPLE[int(rng.random() * len(_STOPWORD_TUPLE))]


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Document:
    """One generated plaintext document, exactly as it will be uploaded."""

    index: int
    filename: str
    text: str

    @property
    def data(self) -> bytes:
        """UTF-8 bytes -- what actually gets encrypted. Generated text is
        pure ASCII, so byte length equals character length, which keeps
        the storage-overhead arithmetic in suite B6 unambiguous."""
        return self.text.encode("utf-8")

    @property
    def size_bytes(self) -> int:
        return len(self.data)

    @property
    def keywords(self) -> "set[str]":
        """The document's keyword set under the vault's own tokenizer --
        not a re-implementation of it."""
        return tokenize(self.text)


def probe_keyword(frequency: int) -> str:
    """The probe tag planted in exactly `frequency` documents."""
    return f"{PROBE_PREFIX}{frequency:04d}"


def _generate_sentence(rng: Random, vocabulary, cumulative) -> str:
    words: "List[str]" = []
    for _ in range(_uniform_int(rng, *_SENTENCE_WORDS)):
        roll = rng.random()
        if roll < _STOPWORD_RATIO:
            words.append(_draw_stopword(rng))
        elif roll < _STOPWORD_RATIO + 0.04:
            # Digits and hyphenated compounds: the tokenizer treats '-' as a
            # delimiter and keeps digit runs, and both paths should be
            # exercised by the corpus rather than assumed.
            style = rng.random()
            if style < 0.5:
                words.append(str(_uniform_int(rng, 1000, 9999)))
            else:
                a = _draw_content_word(rng, vocabulary, cumulative)
                b = _draw_content_word(rng, vocabulary, cumulative)
                words.append(f"{a}-{b}")
        else:
            words.append(_draw_content_word(rng, vocabulary, cumulative))
    sentence = " ".join(words)
    sentence = sentence[0].upper() + sentence[1:]
    terminator = "." if rng.random() < 0.88 else ("?" if rng.random() < 0.5 else "!")
    return sentence + terminator


def _generate_document_text(rng: Random, vocabulary, cumulative, target_words: int) -> str:
    """Title line, then paragraphs, until roughly `target_words` words
    have been emitted."""
    title_words = [_draw_content_word(rng, vocabulary, cumulative) for _ in range(_uniform_int(rng, 2, 5))]
    parts = [" ".join(w.capitalize() for w in title_words), ""]
    emitted = len(title_words)
    while emitted < target_words:
        sentences = []
        for _ in range(_uniform_int(rng, *_PARAGRAPH_SENTENCES)):
            sentence = _generate_sentence(rng, vocabulary, cumulative)
            emitted += sentence.count(" ") + 1
            sentences.append(sentence)
        parts.append(" ".join(sentences))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def generate_corpus(
    n_documents: int,
    probe_frequencies: "Iterable[int]" = (),
) -> "List[Document]":
    """`n_documents` deterministic documents, with probe tags planted at
    the requested exact document frequencies.

    Prefix stability holds for a FIXED `probe_frequencies` set: with the
    same probes, `generate_corpus(10, p) == generate_corpus(200, p)[:10]`
    byte for byte. Changing the probe set changes the documents that
    carry probe tags, which is why every suite in one run uses one probe
    set (benchmarks/run_all.py passes the profile's).
    """
    if n_documents < 0:
        raise ValueError("n_documents must be non-negative")
    probes = sorted(set(int(k) for k in probe_frequencies))
    for k in probes:
        if k < 1:
            raise ValueError(f"probe frequency {k} must be >= 1")
        if k > n_documents:
            raise ValueError(
                f"probe frequency {k} exceeds the corpus size ({n_documents}): a "
                f"keyword cannot appear in more documents than exist, and silently "
                f"planting it in fewer would make suite B5's x-axis a lie"
            )

    vocabulary = build_vocabulary()
    cumulative = _zipf_cumulative(len(vocabulary), config.CORPUS_ZIPF_EXPONENT)

    documents: "List[Document]" = []
    for index in range(n_documents):
        rng = Random(_document_seed(index))
        target_words = _uniform_int(rng, *config.CORPUS_WORDS_PER_DOCUMENT)
        text = _generate_document_text(rng, vocabulary, cumulative, target_words)

        # Probes are appended AFTER the body, from the same per-document
        # seed's stream position, so a document's body never changes when
        # the probe set does -- only the trailing tag line.
        planted = [probe_keyword(k) for k in probes if index < k]
        if planted:
            text += "\nReference tags: " + " ".join(planted) + "\n"

        slug_a = _draw_content_word(rng, vocabulary, cumulative)
        slug_b = _draw_content_word(rng, vocabulary, cumulative)
        documents.append(
            Document(index=index, filename=f"doc_{index:04d}_{slug_a}_{slug_b}.txt", text=text)
        )
    return documents


# ---------------------------------------------------------------------------
# provenance and statistics
# ---------------------------------------------------------------------------

def corpus_fingerprint(documents: "Sequence[Document]") -> str:
    """SHA-256 over every filename and byte of the corpus.

    Recorded in the run manifest so two result sets can be shown to have
    measured identical input, rather than being assumed to have done so
    because they used the same seed.
    """
    h = hashlib.sha256()
    for doc in documents:
        h.update(doc.filename.encode("utf-8"))
        h.update(b"\x00")
        h.update(doc.data)
        h.update(b"\x00")
    return h.hexdigest()


def keyword_stats(documents: "Sequence[Document]") -> dict:
    """Corpus shape under the vault's own tokenizer.

    `total_postings` is the number of (keyword, document) pairs, which is
    exactly the row count the encrypted index will hold -- the quantity
    architecture Section 09 names as the cloud's `setup size` leakage, and
    the honest x-axis for index-build cost (suite B3).
    """
    per_document: "List[int]" = []
    distinct: "set[str]" = set()
    total_bytes = 0
    for doc in documents:
        kws = doc.keywords
        per_document.append(len(kws))
        distinct |= kws
        total_bytes += doc.size_bytes
    return {
        "documents": len(documents),
        "total_text_bytes": total_bytes,
        "distinct_keywords": len(distinct),
        "total_postings": sum(per_document),
        "keywords_per_document_min": min(per_document) if per_document else 0,
        "keywords_per_document_max": max(per_document) if per_document else 0,
        "keywords_per_document_mean": (sum(per_document) / len(per_document)) if per_document else 0.0,
    }


def documents_containing(documents: "Sequence[Document]", keyword: str) -> "List[int]":
    """Indices of documents whose tokenized keyword set contains
    `keyword` -- ground truth for asserting a search returned the right
    documents before its timing is recorded."""
    return [doc.index for doc in documents if keyword in doc.keywords]


def write_corpus_to_disk(documents: "Sequence[Document]", directory: str) -> "List[str]":
    """Materialise a corpus as .txt files. Not needed by the benchmark
    suites (they hold documents in memory and upload the bytes directly);
    used to produce an inspectable copy when a result needs explaining."""
    os.makedirs(directory, exist_ok=True)
    written = []
    for doc in documents:
        path = os.path.join(directory, doc.filename)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(doc.text)
        written.append(path)
    return written
