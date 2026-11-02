"""
benchmarks/config.py -- workload profiles: every knob that decides how
much work Phase 7 does, in one file.

Two profiles exist, and the difference between them is ONLY how many
documents, sizes and repetitions are used -- never *what* is measured
and never how a document is generated. `quick` is for developing the
harness and for a reviewer who wants to confirm the pipeline runs;
`full` is the profile whose output is reportable. Both drive identical
code paths, so a `quick` run that works is real evidence the `full`
run will produce the same tables, only with more samples.

Why the corpus parameters are NOT part of a profile
---------------------------------------------------
Document length, vocabulary size and the Zipf exponent are fixed
module-level constants, shared by both profiles. If `quick` generated
shorter documents than `full`, the two runs would not be measuring the
same system and could not be compared or cross-checked against each
other. A profile may only choose how MANY of the same documents to
use. The generator is seeded (CORPUS_SEED) so document number 37 is
byte-identical in every run on every machine -- which is what makes a
number from your Windows machine comparable with a number from any
other.

Statistical sizing
------------------
`full` uses n = 30 repetitions where a repetition is cheap and n = 10
where one repetition costs seconds (a 200-document index rebuild). The
report prints the actual n beside every figure rather than implying a
uniform one, and small-n configurations get a Student's t interval
(benchmarks/harness/timing.py) rather than a normal approximation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

# ---------------------------------------------------------------------------
# Fixed across profiles -- see the module docstring.
# ---------------------------------------------------------------------------

CORPUS_SEED = 20260827
"""Fixed RNG seed for the synthetic corpus. Changing it invalidates
comparison with every previously recorded run, so it is a constant,
not an option."""

CORPUS_VOCABULARY_SIZE = 4000
"""Distinct content words available to the generator. Realistic order
of magnitude for the working vocabulary of a personal document set,
and large enough that the index is dominated by genuine keyword
variety rather than by a handful of words repeated everywhere."""

CORPUS_ZIPF_EXPONENT = 1.1
"""Natural-language word frequency follows a Zipf-like power law. A
uniformly random word choice would give almost every document the same
keyword count and make the index size a straight line by construction
-- which would flatter the results rather than test them. s = 1.1 is
in the range usually fitted to English prose."""

CORPUS_WORDS_PER_DOCUMENT = (400, 900)
"""Uniform range of words per generated document -- roughly 2.5-6 KiB
of text, the size of a note, an email or a short report, which is the
kind of file this vault is built for."""

SUITE_IDS: "Tuple[str, ...]" = (
    "b1_primitives",
    "b2_token_generation",
    "b3_indexing",
    "b4_upload_rebuild",
    "b5_search",
    "b6_storage",
)
"""Declared to the recorder at the start of every run so that a suite
which does not execute is written to the manifest as `not_run` and
renders that way in the report."""

VAULT_PASSWORD = "benchmark-vault-password"
"""The password used to unlock the throwaway benchmark vault. Not a
secret: every benchmark vault lives in a temporary directory that is
deleted at the end of the run, and no real data is ever placed in one.
Written here, in the open, rather than looking security-conscious
while being pointless."""


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Profile:
    """One complete workload sizing. Frozen: a run must not be able to
    modify the profile it is recording as its own provenance."""

    name: str
    description: str

    # -- B1: cryptographic primitives (Argon2id, AES-GCM, PRF, HKDF) -------
    kdf_repeats: int
    kdf_warmup: int
    kdf_sweep_memory_kib: "Tuple[int, ...]"
    kdf_sweep_time_cost: "Tuple[int, ...]"
    kdf_sweep_repeats: int

    # -- B1 cont. / B2: payload sizes and micro-operation batching ---------
    aead_sizes_bytes: "Tuple[int, ...]"
    aead_repeats: int
    micro_batch: int
    micro_repeats: int

    # -- B3: tokenize + build_index ----------------------------------------
    index_corpus_sizes: "Tuple[int, ...]"
    index_repeats: int

    # -- B4: upload + static index rebuild ---------------------------------
    upload_max_documents: int
    rebuild_checkpoints: "Tuple[int, ...]"
    rebuild_repeats: int

    # -- B5: search ---------------------------------------------------------
    search_match_counts: "Tuple[int, ...]"
    search_repeats: int
    search_scaling_corpus_sizes: "Tuple[int, ...]"
    search_scaling_fixed_k: int

    # -- B6: storage overhead ----------------------------------------------
    storage_corpus_size: int

    # -- shared -------------------------------------------------------------
    default_warmup: int = 2

    def summary(self) -> dict:
        """Profile as plain data, embedded in the run manifest so the
        report states the sizing it is describing."""
        return {
            "name": self.name,
            "description": self.description,
            "b1_primitives": {
                "repeats": self.kdf_repeats,
                "warmup": self.kdf_warmup,
                "sweep_memory_kib": list(self.kdf_sweep_memory_kib),
                "sweep_time_cost": list(self.kdf_sweep_time_cost),
                "sweep_repeats": self.kdf_sweep_repeats,
            },
            "b2_token_generation": {
                "sizes_bytes": list(self.aead_sizes_bytes),
                "repeats": self.aead_repeats,
                "micro_batch": self.micro_batch,
                "micro_repeats": self.micro_repeats,
            },
            "b3_indexing": {
                "corpus_sizes": list(self.index_corpus_sizes),
                "repeats": self.index_repeats,
            },
            "b4_upload_rebuild": {
                "max_documents": self.upload_max_documents,
                "rebuild_checkpoints": list(self.rebuild_checkpoints),
                "rebuild_repeats": self.rebuild_repeats,
            },
            "b5_search": {
                "match_counts": list(self.search_match_counts),
                "repeats": self.search_repeats,
                "scaling_corpus_sizes": list(self.search_scaling_corpus_sizes),
                "scaling_fixed_k": self.search_scaling_fixed_k,
            },
            "b6_storage": {"corpus_size": self.storage_corpus_size},
            "corpus": {
                "seed": CORPUS_SEED,
                "vocabulary_size": CORPUS_VOCABULARY_SIZE,
                "zipf_exponent": CORPUS_ZIPF_EXPONENT,
                "words_per_document": list(CORPUS_WORDS_PER_DOCUMENT),
            },
        }


QUICK = Profile(
    name="quick",
    description=(
        "Development and smoke-test sizing. Same code paths and same corpus "
        "as `full`, with far fewer documents and repetitions. Its numbers are "
        "real measurements but are NOT reportable: the sample counts are too "
        "small and the corpus too short to say anything about scaling."
    ),
    kdf_repeats=5,
    kdf_warmup=1,
    kdf_sweep_memory_kib=(16384, 65536),
    kdf_sweep_time_cost=(1, 3),
    kdf_sweep_repeats=2,
    aead_sizes_bytes=(1024, 65536, 1048576),
    aead_repeats=5,
    micro_batch=1000,
    micro_repeats=10,
    index_corpus_sizes=(10, 25, 50),
    index_repeats=3,
    upload_max_documents=25,
    rebuild_checkpoints=(5, 10, 25),
    rebuild_repeats=3,
    search_match_counts=(1, 5, 10),
    search_repeats=10,
    search_scaling_corpus_sizes=(25, 50),
    search_scaling_fixed_k=5,
    storage_corpus_size=25,
)

FULL = Profile(
    name="full",
    description=(
        "Reportable sizing. 200-document corpus (the agreed Phase 7 maximum), "
        "AES-GCM measured from 1 KiB to 16 MiB, and repetition counts chosen so "
        "every reported figure carries a usable confidence interval."
    ),
    kdf_repeats=30,
    kdf_warmup=2,
    # 64 MiB is the shipped setting; the sweep brackets it by two steps in
    # each direction so the curve shows both what relaxing and what
    # tightening the parameters would cost.
    kdf_sweep_memory_kib=(16384, 32768, 65536, 131072, 262144),
    kdf_sweep_time_cost=(1, 2, 3, 4),
    kdf_sweep_repeats=5,
    # Log-spaced by factors of 4: small sizes expose the per-call fixed cost
    # (nonce generation, AESGCM object construction), large sizes expose the
    # steady-state throughput of the underlying OpenSSL implementation.
    aead_sizes_bytes=(1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216),
    aead_repeats=15,
    micro_batch=5000,
    micro_repeats=20,
    index_corpus_sizes=(10, 25, 50, 100, 200),
    index_repeats=10,
    upload_max_documents=200,
    rebuild_checkpoints=(10, 25, 50, 100, 200),
    rebuild_repeats=10,
    search_match_counts=(1, 2, 5, 10, 25, 50, 100),
    search_repeats=30,
    search_scaling_corpus_sizes=(25, 50, 100, 200),
    search_scaling_fixed_k=5,
    storage_corpus_size=200,
)

SMOKE = Profile(
    name="smoke",
    description=(
        "System-layer smoke sizing: the largest end-to-end workload that fits inside "
        "the development sandbox's per-command time limit. Real measurements of the "
        "real two-process system, but capped at 50 documents rather than the full "
        "profile's 200 -- reportable as a scaling smoke test only, never as the "
        "authoritative dataset."
    ),
    # B1-B3 sizing copied from QUICK: this profile exists for the system-layer
    # suites, and the primitive suites should stay cheap under it.
    kdf_repeats=QUICK.kdf_repeats,
    kdf_warmup=QUICK.kdf_warmup,
    kdf_sweep_memory_kib=QUICK.kdf_sweep_memory_kib,
    kdf_sweep_time_cost=QUICK.kdf_sweep_time_cost,
    kdf_sweep_repeats=QUICK.kdf_sweep_repeats,
    aead_sizes_bytes=QUICK.aead_sizes_bytes,
    aead_repeats=QUICK.aead_repeats,
    micro_batch=QUICK.micro_batch,
    micro_repeats=QUICK.micro_repeats,
    index_corpus_sizes=QUICK.index_corpus_sizes,
    index_repeats=QUICK.index_repeats,
    # B4: 50 documents -- every upload rebuilds the whole index, so the total
    # work here is already quadratic (about 1,275 document fetch-and-decrypt
    # operations across the run).
    upload_max_documents=50,
    rebuild_checkpoints=(10, 25, 50),
    rebuild_repeats=3,
    # B5: probe keywords up to 25 matches, in a 25-document vault.
    search_match_counts=(1, 2, 5, 10, 25),
    search_repeats=10,
    search_scaling_corpus_sizes=(10, 25),
    search_scaling_fixed_k=5,
    # B6: measured on a 50-document vault.
    storage_corpus_size=50,
)

PROFILES: "Dict[str, Profile]" = {p.name: p for p in (QUICK, SMOKE, FULL)}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise SystemExit(
            f"unknown profile {name!r} -- available profiles: {sorted(PROFILES)}"
        ) from None
