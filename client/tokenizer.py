"""
client/tokenizer.py -- the ONE shared keyword normaliser (Section 05).

    "Keyword extraction must be identical at index time and search
    time or searches silently miss. Fix one tokenizer ... Write it
    once in tokenizer.py and call it from both paths."

This is that file. client/indexer.py (Phase 3) calls tokenize() to
build the encrypted index; client/search.py (Phase 4, not built yet)
will call the exact same function to normalise a search query before
deriving a token. Nothing else in this project is allowed to
re-implement keyword extraction -- if it needs keywords, it imports
this.

Normalisation rules, deliberately simple and dependency-free:

  1. Lowercase.
  2. Extract maximal runs of ASCII letters/digits as tokens --
     everything else (punctuation, whitespace, hyphens, apostrophes)
     is a delimiter. "don't" therefore splits into "don" + "t", and
     "t" is then dropped by the length filter below. This is a known,
     deliberate simplification: linguistically imperfect, but fully
     deterministic and trivial to reason about and test -- which
     matters far more than modest recall gains, since a tokenizer bug
     causes *silent* search misses, not a crash.
  3. Drop tokens shorter than 2 characters (single letters left over
     from splitting are noise, not searchable keywords).
  4. Drop a fixed English stop-word list (common function words carry
     no useful search signal and would otherwise bloat the index with
     postings that match almost every document).
  5. Deduplicate within one document -- a word appearing five times in
     a file should contribute exactly one index entry for it, not
     five identical ones.

Stemming ("running" -> "run") is explicitly marked optional in the
architecture doc; it is NOT implemented here. Adding it later is safe
precisely because there is one call site to change -- but it also adds
a dependency (a stemming library) and a new way for index-time and
search-time normalisation to drift, so it stays out until there's a
concrete reason to want it.
"""

from __future__ import annotations

import re

# A deliberately small, uncontroversial set of English stop words --
# large enough to strip the obvious noise, small enough to stay
# predictable and easy to defend in a viva ("why isn't X on the
# list?" should always have an easy answer: it wasn't common/ambiguous
# enough to bother with).
STOPWORDS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "been", "being",
        "but", "by", "for", "from", "has", "have", "had", "he", "her",
        "hers", "him", "his", "how", "if", "in", "into", "is", "it",
        "its", "of", "on", "or", "our", "she", "so", "than", "that",
        "the", "their", "them", "then", "there", "these", "they",
        "this", "those", "to", "too", "was", "we", "were", "what",
        "when", "where", "which", "who", "why", "will", "with", "you",
        "your",
    }
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")

MIN_TOKEN_LENGTH = 2


def tokenize(text: str) -> "set[str]":
    """Normalise `text` into a deduplicated set of searchable keywords.

    Same input -> same output, always (no randomness, no external
    state, no locale dependence) -- this determinism is what the
    whole SSE scheme's correctness rests on.
    """
    if not isinstance(text, str):
        raise TypeError(f"tokenize() expects str, got {type(text).__name__}")

    keywords: "set[str]" = set()
    for raw in _TOKEN_RE.findall(text.lower()):
        if len(raw) < MIN_TOKEN_LENGTH:
            continue
        if raw in STOPWORDS:
            continue
        keywords.add(raw)
    return keywords
