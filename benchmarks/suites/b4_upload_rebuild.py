"""
Suite B4 -- end-to-end upload cost and the static index rebuild.

This is the suite the architecture's own design decision is on trial in.
Section 07-B rebuilds the WHOLE index on every upload rather than patching
it, and Section 10 accepts that as the price of not claiming forward
privacy. The cost of that decision has been stated in prose since Phase 1
("O(n) in corpus size ... fine at course-project scale") and never
measured. B4 measures it.

Measurement boundaries
----------------------
Outer boundary -- `POST /api/documents` on the trusted client, driven
through its Flask test client while the untrusted cloud runs as a separate
OS process reached over real HTTP. One sample includes: UTF-8 validation,
AES-GCM encryption of the file and its name, a random doc_id, the document
push, and then the entire static rebuild (list, one GET per stored
document, one decrypt and tokenize each, build_index, replace_index). The
only thing excluded is the browser-to-client hop, which carries no
cryptography and is not part of the scheme.

An upload is a state transition, so document i can be uploaded exactly
once: each point on the per-upload timeline is n = 1 and is reported that
way, with no dispersion statistics implied. Repeatable statistics come
from the inner boundary.

Inner boundary -- `client_app._rebuild_and_push_index(keys)`, the real
function the upload route calls, invoked directly at checkpoint corpus
sizes with `rebuild_repeats` repetitions. This is white-box instrumentation
of the shipped function, not a reimplementation of it: nothing in
`client/` is modified, patched or shadowed.

Decomposition -- at each checkpoint the rebuild's constituent steps are
timed separately using the same functions the rebuild itself calls
(cloud_client.list_documents / fetch_document, aes_gcm_decrypt, tokenize,
build_index, cloud_client.replace_index), so the report can say WHICH part
of the rebuild owns the cost. The sum of the parts is recorded next to the
measured whole rather than substituted for it -- if they disagree, that is
visible.

Observed traffic -- the number of HTTP requests each upload causes is
counted from the real calls (harness/wire.py), never inferred. That count
growing 2, 3, 4 ... with vault size is demonstration D7 expressed as a
measurement.
"""

from __future__ import annotations

import io
import json
import time
from contextlib import contextmanager
from typing import Dict, List

from ..config import Profile
from ..harness.cloud_process import LiveCloud
from ..harness.corpus import corpus_fingerprint, generate_corpus, keyword_stats
from ..harness.recorder import Recorder
from ..harness.timing import Measurement, measure, timer_resolution
from ..harness.vault import unlock_client_app, benchmark_client_config
from ..harness.wire import record_wire

from client import client_app, cloud_client
from client.crypto import aes_gcm_decrypt
from client.indexer import build_index
from client.tokenizer import tokenize

SUITE_ID = "b4_upload_rebuild"
TITLE = "End-to-end upload and static index rebuild"


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(f"B4 correctness gate failed: {message}")


class B4OperationError(RuntimeError):
    """A B4 operation failed for a reason that is not a correctness gate --
    a stalled or unreachable cloud, a transport error, an OS-level failure.

    Carries the live subprocess's state at the moment of failure. Run 3 of the
    authoritative benchmark (2026-09-01) died inside the checkpoint block with
    a bare CloudUnavailableError and NO diagnostics, because only the upload
    path was instrumented: 100 healthy uploads, then 92 minutes unaccounted,
    and nothing in the record to say whether the server was alive, how much it
    had logged, or what timeout was in force. This exception type exists so
    that cannot happen twice.
    """


@contextmanager
def _diagnostic_guard(cloud, phase: str):
    """Attach cloud-subprocess diagnostics to any non-correctness failure in
    `phase`, then re-raise.

    Three deliberate properties:

      * It NEVER retries and never swallows. The original exception is chained
        (`raise ... from exc`) so the traceback still names the real cause; the
        operation is attempted exactly once, which is what an n=1 benchmark
        requires.
      * AssertionError passes through untouched. Those are this suite's
        correctness gates -- they already carry a precise message, they mean
        the measurement was wrong rather than the environment failed, and the
        self-tests assert on their text.
      * Diagnostics are collected only on the failure path, after the timed
        region has ended, so they can never enter a measurement.
    """
    try:
        yield
    except AssertionError:
        raise
    except Exception as exc:
        try:
            diagnostics = cloud.diagnostics()
        except Exception as diag_exc:  # diagnostics must never mask the real failure
            diagnostics = {"diagnostics_failed": f"{type(diag_exc).__name__}: {diag_exc}"}
        raise B4OperationError(
            f"B4 failed during {phase}: {type(exc).__name__}: {exc}\n"
            f"  attempted once, not retried\n"
            f"  cloud subprocess diagnostics: {json.dumps(diagnostics, default=str)}"
        ) from exc


def _single_sample(seconds: float) -> Measurement:
    """One observation, recorded as such. `summarize` reports None for
    dispersion at n = 1 rather than 0.0, so a single-sample point can never
    read as a perfectly repeatable one."""
    m = Measurement(batch=1)
    m.samples = [seconds]
    return m


def _upload(client, document, cloud=None) -> "tuple":
    """One real upload through POST /api/documents. Returns (seconds, doc_id).

    The upload is attempted exactly ONCE. There is deliberately no retry: an
    upload is an n=1 state transition, and re-issuing a failed one would
    silently turn a single observation into an average over an unknown number
    of attempts. A failure raises, the suite stops, and the run is recorded as
    failed.

    On failure the live cloud subprocess's state is attached to the error --
    is it alive, what did it print -- because the investigation of the
    2026-08-29 B4 abort could not tell a stalled server from a crashed one
    from the recorded evidence alone. Diagnostics are collected AFTER the
    elapsed time is taken and only on the failure path, so they cannot enter
    a measurement.
    """
    payload = {"file": (io.BytesIO(document.data), document.filename)}
    start = time.perf_counter_ns()
    response = client.post("/api/documents", data=payload, content_type="multipart/form-data")
    elapsed = (time.perf_counter_ns() - start) / 1e9
    if response.status_code != 201:
        # Diagnostics must never be able to replace the failure they describe:
        # if collecting them raises, that is recorded and the original error
        # still reaches the caller.
        try:
            diagnostics = cloud.diagnostics() if cloud is not None else {"note": "no live cloud handle"}
        except Exception as diag_exc:
            diagnostics = {"diagnostics_failed": f"{type(diag_exc).__name__}: {diag_exc}"}
        _check(False, (
            f"upload of {document.filename} returned {response.status_code}: "
            f"{response.data[:400]!r}\n"
            f"  elapsed before failure: {elapsed:.3f} s (one attempt, no retry)\n"
            f"  cloud subprocess diagnostics: {json.dumps(diagnostics, default=str)}"
        ))
    return elapsed, response.get_json()["doc_id"]


def _fetch_all_documents() -> "List[dict]":
    """The rebuild's read phase, using the same client functions it uses."""
    return [
        doc for doc in (
            cloud_client.fetch_document(meta["doc_id"])
            for meta in cloud_client.list_documents()
        ) if doc is not None
    ]


def _decrypt_and_tokenize(keys, documents) -> "Dict[str, set]":
    out = {}
    for doc in documents:
        blob = doc["nonce"] + doc["ciphertext"] + doc["tag"]
        out[doc["doc_id"]] = tokenize(aes_gcm_decrypt(keys.k_file, blob).decode("utf-8"))
    return out


def run(recorder: Recorder, profile: Profile) -> dict:
    resolution = timer_resolution()
    max_documents = profile.upload_max_documents
    checkpoints = [c for c in profile.rebuild_checkpoints if c <= max_documents]
    documents = generate_corpus(max_documents)
    fingerprint = corpus_fingerprint(documents)
    checks: "List[str]" = []
    checkpoint_details: "List[dict]" = []

    with LiveCloud() as cloud:
        timeout_metadata = cloud.timeout_metadata()
        app = client_app.create_app(benchmark_client_config())
        client = app.test_client()
        try:
            with _diagnostic_guard(cloud, "vault unlock"):
                keys = unlock_client_app(client)
            checks.append("vault unlocked through the real POST /api/unlock bootstrap path")

            for position, document in enumerate(documents, start=1):
                # Traffic is counted on the real upload; the wrapper adds one
                # list append per request, far below a loopback round trip.
                with record_wire(cloud.base_url) as wire:
                    elapsed, doc_id = _upload(client, document, cloud)

                vault_size = position
                recorder.add_measurement(
                    SUITE_ID, "upload_document_end_to_end",
                    {
                        "vault_documents_after": vault_size,
                        "document_bytes": document.size_bytes,
                        "corpus_fingerprint_sha256": fingerprint,
                    },
                    _single_sample(elapsed),
                    notes=(
                        "POST /api/documents: encrypt, push, then the full static "
                        "index rebuild over the whole vault. n=1 -- an upload is a "
                        "state transition and cannot be repeated."
                    ),
                )
                recorder.add_scalar(
                    SUITE_ID, "http_requests_per_upload", {"vault_documents_after": vault_size},
                    len(wire), "count",
                    notes="observed calls to the untrusted cloud: " + "; ".join(
                        f"{k} x{v}" for k, v in sorted(wire.summary().items())),
                )
                recorder.add_scalar(
                    SUITE_ID, "http_document_fetches_per_upload",
                    {"vault_documents_after": vault_size},
                    wire.count("GET", r"/documents/[0-9a-f]+"), "count",
                    notes="GET /documents/<doc_id> calls the rebuild made -- architecture "
                          "Section 09's static-rebuild leakage (demonstration D7), counted.",
                )

                if vault_size in checkpoints:
                    corpus_so_far = documents[:vault_size]
                    stats = keyword_stats(corpus_so_far)

                    # -- the real rebuild function, repeated -----------------
                    with _diagnostic_guard(
                        cloud, f"rebuild_index_total at the {vault_size}-document checkpoint"
                    ):
                        m = measure(
                            lambda: client_app._rebuild_and_push_index(keys),
                            repeats=profile.rebuild_repeats,
                            warmup=1,
                            batch=1,
                        )
                    recorder.add_measurement(
                        SUITE_ID, "rebuild_index_total",
                        {
                            "vault_documents": vault_size,
                            "total_postings": stats["total_postings"],
                            "corpus_text_bytes": stats["total_text_bytes"],
                            "corpus_fingerprint_sha256": fingerprint,
                        },
                        m,
                        notes="client_app._rebuild_and_push_index -- the shipped function, "
                              "called directly so it can be repeated for statistics.",
                    )
                    rebuild_median = m.stats.median

                    # -- decomposition, same functions, same order -----------
                    with _diagnostic_guard(
                        cloud, f"corpus re-fetch gate at the {vault_size}-document checkpoint"
                    ):
                        fetched = _fetch_all_documents()
                    _check(len(fetched) == vault_size,
                           f"expected {vault_size} documents from the cloud, got {len(fetched)}")

                    with _diagnostic_guard(
                        cloud, f"rebuild_step_fetch_all_documents at the {vault_size}-document checkpoint"
                    ):
                        m_fetch = measure(_fetch_all_documents,
                                          repeats=profile.rebuild_repeats, warmup=1, batch=1)
                    recorder.add_measurement(
                        SUITE_ID, "rebuild_step_fetch_all_documents",
                        {"vault_documents": vault_size, "total_postings": stats["total_postings"]},
                        m_fetch,
                        notes="cloud_client.list_documents + one fetch_document per stored "
                              "document -- the rebuild's HTTP read phase.",
                    )

                    with _diagnostic_guard(
                        cloud, f"rebuild_step_decrypt_and_tokenize at the {vault_size}-document checkpoint"
                    ):
                        m_decrypt = measure(
                            lambda: _decrypt_and_tokenize(keys, fetched),
                            repeats=profile.rebuild_repeats, warmup=1, batch=1,
                        )
                    recorder.add_measurement(
                        SUITE_ID, "rebuild_step_decrypt_and_tokenize",
                        {"vault_documents": vault_size, "total_postings": stats["total_postings"]},
                        m_decrypt,
                        notes="aes_gcm_decrypt + tokenize for every document in the vault.",
                    )

                    tokenized = _decrypt_and_tokenize(keys, fetched)
                    with _diagnostic_guard(
                        cloud, f"rebuild_step_build_index at the {vault_size}-document checkpoint"
                    ):
                        m_build = measure(
                            lambda: build_index(keys.k_index, tokenized),
                            repeats=profile.rebuild_repeats, warmup=1, batch=1,
                        )
                    recorder.add_measurement(
                        SUITE_ID, "rebuild_step_build_index",
                        {"vault_documents": vault_size, "total_postings": stats["total_postings"]},
                        m_build,
                        notes="client.indexer.build_index on the decrypted corpus.",
                    )

                    entries = build_index(keys.k_index, tokenized)
                    _check(len(entries) == stats["total_postings"],
                           "rebuilt index entry count does not match the corpus postings")
                    with _diagnostic_guard(
                        cloud, f"rebuild_step_replace_index at the {vault_size}-document checkpoint"
                    ):
                        m_push = measure(
                            lambda: cloud_client.replace_index([(e.label, e.value) for e in entries]),
                            repeats=profile.rebuild_repeats, warmup=1, batch=1,
                        )
                    recorder.add_measurement(
                        SUITE_ID, "rebuild_step_replace_index",
                        {"vault_documents": vault_size, "total_postings": stats["total_postings"]},
                        m_push,
                        notes="cloud_client.replace_index -- one POST /index/replace carrying "
                              "every posting as base64 JSON.",
                    )

                    parts = (m_fetch.stats.median + m_decrypt.stats.median
                             + m_build.stats.median + m_push.stats.median)
                    recorder.add_scalar(
                        SUITE_ID, "rebuild_decomposition_sum_seconds",
                        {"vault_documents": vault_size}, parts, "s",
                        notes="sum of the four step medians, recorded beside the measured "
                              "whole rather than substituted for it",
                    )
                    recorder.add_scalar(
                        SUITE_ID, "rebuild_decomposition_ratio",
                        {"vault_documents": vault_size},
                        parts / rebuild_median if rebuild_median else 0.0, "ratio",
                        notes="decomposition sum / measured total rebuild -- a value far from "
                              "1.0 would mean the decomposition misses a real cost",
                    )
                    for name, value, unit in (
                        ("corpus_total_postings", stats["total_postings"], "count"),
                        ("corpus_text_bytes", stats["total_text_bytes"], "bytes"),
                        ("index_entries", len(entries), "count"),
                    ):
                        recorder.add_scalar(SUITE_ID, name, {"vault_documents": vault_size}, value, unit)

                    checkpoint_details.append({
                        "vault_documents": vault_size,
                        "total_postings": stats["total_postings"],
                        "rebuild_median_seconds": rebuild_median,
                        "decomposition_ratio": parts / rebuild_median if rebuild_median else None,
                    })

            # -- final state gate -------------------------------------------
            with _diagnostic_guard(cloud, "final vault listing"):
                listed = client.get("/api/documents").get_json()
            _check(len(listed) == max_documents,
                   f"vault holds {len(listed)} documents after {max_documents} uploads")
            _check(all(d["filename"] == doc.filename for d, doc in zip(
                sorted(listed, key=lambda d: d["filename"]),
                sorted(documents, key=lambda d: d.filename))),
                "a stored filename did not decrypt back to the uploaded name")
            checks.append(
                f"all {max_documents} uploads returned 201 and every filename decrypted "
                f"back to the name it was uploaded under"
            )
        finally:
            client.post("/api/lock")

    return {
        "measures": [
            "upload_document_end_to_end", "rebuild_index_total",
            "rebuild_step_fetch_all_documents", "rebuild_step_decrypt_and_tokenize",
            "rebuild_step_build_index", "rebuild_step_replace_index",
            "http_requests_per_upload", "http_document_fetches_per_upload",
        ],
        "implementations_under_test": [
            "client.client_app (POST /api/documents, POST /api/unlock)",
            "client.client_app._rebuild_and_push_index",
            "client.cloud_client.push_document", "client.cloud_client.fetch_document",
            "client.cloud_client.replace_index", "client.indexer.build_index",
            "client.crypto.aes_gcm_decrypt", "client.tokenizer.tokenize",
        ],
        "topology": "trusted client in-process (Flask test client) -> real HTTP -> cloud_app.py subprocess",
        # The single documented deviation from the shipped client. Read from the
        # live LiveCloud context rather than restated, so the manifest cannot
        # claim a value that was not actually in effect. See
        # benchmarks/harness/cloud_process.py for the full rationale.
        "http_timeout": timeout_metadata,
        "retry_policy": "none -- an upload is an n=1 state transition and is attempted exactly once",
        "failure_instrumentation": {
            "upload_path": "cloud subprocess diagnostics attached to the failing upload",
            "checkpoint_path": (
                "every rebuild measurement and its four decomposition steps, the "
                "corpus re-fetch gate, the vault unlock and the final listing are "
                "wrapped in a diagnostic guard (added after run 3 stalled inside "
                "the checkpoint block with no diagnostics recorded)"
            ),
            "captured": [
                "process_alive", "returncode", "http_timeout_in_effect_seconds",
                "database_exists", "captured_output_bytes", "captured_output_lines",
                "captured_output_tail",
            ],
            "retries_added": False,
            "correctness_gates_unchanged": True,
        },
        "corpus": {"documents": max_documents, "fingerprint_sha256": fingerprint},
        "checkpoints": checkpoint_details,
        "per_upload_sample_size": 1,
        "correctness_gates": checks,
        "clock_resolution_seconds": resolution,
    }
