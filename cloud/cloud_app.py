"""
cloud/cloud_app.py -- Flask app for the untrusted cloud service.

This is a separate process from the (future) trusted client app,
listening on its own port, so the client/cloud split described in
Section 02 is a genuine process boundary -- not just two functions in
one script. That separation is what lets the demo open this app's
routes directly and show they hold only ciphertext and opaque tokens.

Every route here speaks bytes and opaque labels only. Byte fields
travel as base64 inside JSON (HTTP/JSON is text-first; base64 is just
a transport encoding, not a cryptographic step -- it adds no
confidentiality). No route parses, tokenizes, or interprets what any
of those bytes mean, and none of them import client.crypto or
client.keymgmt.

Scope history: Phase 2 added storage only -- /index stored and
returned individual label -> value rows (a raw dictionary primitive)
with no search loop. Phase 4 adds that loop: POST /search runs
Section 06's "regenerate labels from a client-supplied K1, stop at
the first miss" algorithm via run_search_loop() below, using
storage.get_index_entry() for each step -- the exact primitive Phase 2
built and earmarked for this.

run_search_loop() and its two small helpers (_cloud_prf,
_counter_to_bytes) reimplement HMAC-SHA256 and the counter encoding
locally with the stdlib, rather than importing client.crypto /
client.indexer. That import boundary stays intentionally sharp even
though HMAC-SHA256 itself is public, standard cryptography -- what
must never cross it is the trusted client's actual key-management
code and vault secrets, not the mere ability to compute a hash. See
tests/test_integration.py's cross-implementation check for how the
two independent implementations are kept from silently drifting apart
instead of relying on a shared import.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_module
import os

from flask import Flask, g, jsonify, request

from . import storage

DEFAULT_DB_PATH = os.environ.get("VAULT_DB_PATH", "vault.sqlite3")

# Multi-vault access control (schema v2). A request that names a vault
# (X-Vault-Id) must prove possession of that vault's access token
# (Authorization: Bearer <base64 token>); the cloud compares
# SHA-256(token) against vaults.token_hash in constant time. The token
# is a random credential minted by the trusted client per user vault --
# it is NOT derived from, and reveals nothing about, any vault key or
# password. A request with no X-Vault-Id addresses the legacy
# single-vault namespace, which keeps its original unauthenticated
# behaviour unless CLOUD_ALLOW_LEGACY_VAULT=0.
VAULT_HEADER = "X-Vault-Id"
_VAULT_ID_MAX_LEN = 64
_INDEX_PAGE_MAX = 500


def _token_hash(token: bytes) -> bytes:
    return hashlib.sha256(token).digest()


def _valid_vault_id(vault_id: str) -> bool:
    return (
        isinstance(vault_id, str)
        and 0 < len(vault_id) <= _VAULT_ID_MAX_LEN
        and all(c in "0123456789abcdef" for c in vault_id)
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"field {field!r} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:  # malformed base64 -> a 400, not a 500 crash
        raise ValueError(f"field {field!r} is not valid base64") from exc


def _cloud_prf(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256(key, data) -- Section 06's F, recomputed here with
    the stdlib rather than imported from client.crypto.prf(). This is
    a deliberate duplication, not an oversight: cloud/ must never
    import client/ (the AST-based tests in tests/test_storage.py and
    tests/test_cloud_app.py enforce this), and HMAC-SHA256 is public,
    standard cryptography -- computing it here needs no secret this
    module doesn't already have from the caller. `key` is always a
    client-supplied, single-search, single-keyword token (K1), never a
    vault secret; this function has no way to obtain K_index, K_file,
    or the master key, and never receives them.

    Consistency with client/crypto.py's prf() is enforced by a test
    (tests/test_integration.py) that computes labels both ways for the
    same inputs and asserts they match byte-for-byte, rather than by
    sharing code -- see the module docstring for why.
    """
    return _hmac_module.new(key, data, hashlib.sha256).digest()


def _counter_to_bytes(counter: int) -> bytes:
    """Must exactly match client/indexer.py's counter_to_bytes(): an
    8-byte big-endian encoding. See _cloud_prf's docstring."""
    return counter.to_bytes(8, "big")


def run_search_loop(conn, k1: bytes, vault_id: str = storage.LEGACY_VAULT) -> "list[bytes]":
    """Section 06's cloud-side search loop: regenerate labels with the
    caller-supplied K1 and stop at the first counter whose label is
    not in the index ("contiguous counters -> clean stop").

    Touches only `conn` and `k1` -- no other key, no plaintext, no
    state beyond what the caller explicitly handed it. Never decrypts
    anything; it only recognises which opaque rows exist.

    Defensive bound (not part of the documented protocol, added for
    robustness): a keyword can never legitimately have more postings
    than there are total rows in the whole sse_index table, because
    each hit consumes one distinct row and rows aren't shared between
    keywords. So looping more than (total row count + 1) times without
    a miss is structurally impossible for honest data -- reaching it
    means a corrupted index or a bug, not a real search result, and is
    reported as such rather than looping forever.
    """
    total_entries = storage.index_entry_count(conn, vault_id=vault_id)
    results: "list[bytes]" = []
    counter = 0
    while True:
        if counter > total_entries:
            raise RuntimeError(
                f"search loop exceeded the total indexed entry count "
                f"({total_entries}) without a miss -- this should be "
                f"structurally impossible and indicates a corrupted "
                f"index or a bug, not a legitimate search result"
            )
        label = _cloud_prf(k1, _counter_to_bytes(counter)).hex()
        value = storage.get_index_entry(conn, label, vault_id=vault_id)
        if value is None:
            return results
        results.append(value)
        counter += 1


def create_app(db_path: str = DEFAULT_DB_PATH, allow_legacy: "bool | None" = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path
    if allow_legacy is None:
        allow_legacy = os.environ.get("CLOUD_ALLOW_LEGACY_VAULT", "1") != "0"
    app.config["ALLOW_LEGACY_VAULT"] = allow_legacy
    # Touch the DB once at startup so the schema exists (and a pre-v2
    # database is migrated) before the first request, rather than
    # failing (or racing) on it.
    storage.connect(db_path).close()

    # Routes that never touch a vault namespace.
    _UNSCOPED = {"health", "create_vault_route"}

    @app.before_request
    def _resolve_vault():
        """Authenticate the vault a request addresses, once, before any
        route runs -- so no individual route can forget to check."""
        if request.endpoint in _UNSCOPED:
            return None
        vault_id = request.headers.get(VAULT_HEADER)
        if vault_id is None:
            if not app.config["ALLOW_LEGACY_VAULT"]:
                return jsonify({"error": "vault credentials required"}), 401
            g.vault_id = storage.LEGACY_VAULT
            return None
        auth = request.headers.get("Authorization", "")
        if not _valid_vault_id(vault_id) or not auth.startswith("Bearer "):
            return jsonify({"error": "invalid vault credentials"}), 401
        try:
            token = base64.b64decode(auth[len("Bearer "):], validate=True)
        except Exception:
            return jsonify({"error": "invalid vault credentials"}), 401
        with storage.open_db(app.config["DB_PATH"]) as conn:
            stored = storage.get_vault_token_hash(conn, vault_id)
        # Same response for "no such vault" and "wrong token", and the
        # comparison runs either way, so neither case is distinguishable.
        expected = stored if stored is not None else b"\x00" * 32
        if not _hmac_module.compare_digest(_token_hash(token), expected) or stored is None:
            return jsonify({"error": "invalid vault credentials"}), 401
        g.vault_id = vault_id
        return None

    # -- health --------------------------------------------------------

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "role": "untrusted-cloud"})

    # -- vaults ----------------------------------------------------------

    @app.post("/vaults")
    def create_vault_route():
        """Register a new vault namespace. The caller supplies the
        opaque vault_id and its access token; only SHA-256(token) is
        stored. First registration wins -- an existing vault_id can
        never be re-registered with a different token."""
        body = request.get_json(silent=True) or {}
        vault_id = body.get("vault_id")
        if not _valid_vault_id(vault_id):
            return jsonify({"error": "vault_id must be 1-64 lowercase hex characters"}), 400
        try:
            token = _unb64(body.get("token"), "token")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if len(token) < 16:
            return jsonify({"error": "token must be at least 16 bytes"}), 400
        try:
            with storage.open_db(app.config["DB_PATH"]) as conn:
                storage.create_vault(conn, vault_id, _token_hash(token))
        except storage.DuplicateVaultError:
            return jsonify({"error": "vault already exists"}), 409
        return jsonify({"vault_id": vault_id}), 201

    @app.get("/stats")
    def stats_route():
        """Aggregate, non-secret facts about the caller's namespace:
        exactly what this service could count from its own rows."""
        with storage.open_db(app.config["DB_PATH"]) as conn:
            result = storage.vault_stats(conn, vault_id=g.vault_id)
            result["vault_created_at"] = storage.get_vault_created_at(conn, g.vault_id)
        result["vault_id"] = g.vault_id
        return jsonify(result)

    @app.post("/vaults/adopt-legacy")
    def adopt_legacy_route():
        """Migration path: re-label every legacy (pre-multi-user) row as
        belonging to the caller's vault. Only allowed into an empty,
        authenticated vault. The cloud cannot check that the caller
        knows the legacy vault password -- the trusted client verifies
        that against the legacy kdf_verifier before calling this."""
        if g.vault_id == storage.LEGACY_VAULT:
            return jsonify({"error": "vault credentials required"}), 401
        try:
            with storage.open_db(app.config["DB_PATH"]) as conn:
                moved = storage.adopt_legacy_vault(conn, g.vault_id)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 409
        return jsonify({"moved": moved}), 200

    @app.get("/legacy/kdf")
    def legacy_kdf_route():
        """The legacy vault's non-secret KDF rows, readable by any
        authenticated vault (so a migration can verify the legacy
        password even when the unauthenticated legacy API is off)."""
        if g.vault_id == storage.LEGACY_VAULT:
            return jsonify({"error": "vault credentials required"}), 401
        with storage.open_db(app.config["DB_PATH"]) as conn:
            salt = storage.get_meta(conn, "kdf_salt")
            verifier = storage.get_meta(conn, "kdf_verifier")
            docs = storage.document_count(conn)
        return jsonify({
            "kdf_salt": _b64(salt) if salt is not None else None,
            "kdf_verifier": _b64(verifier) if verifier is not None else None,
            "documents": docs,
        })

    # -- documents -------------------------------------------------------

    @app.post("/documents")
    def upload_document():
        body = request.get_json(silent=True) or {}
        doc_id = body.get("doc_id")
        if not isinstance(doc_id, str) or doc_id == "":
            return jsonify({"error": "doc_id must be a non-empty string"}), 400

        required = ("enc_name", "nonce", "ciphertext", "tag")
        missing = [f for f in required if f not in body]
        if missing:
            return jsonify({"error": f"missing fields: {missing}"}), 400

        try:
            fields = {f: _unb64(body[f], f) for f in required}
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            with storage.open_db(app.config["DB_PATH"]) as conn:
                storage.save_document(conn, doc_id=doc_id, vault_id=g.vault_id, **fields)
        except storage.DuplicateDocumentError as exc:
            return jsonify({"error": str(exc)}), 409

        return jsonify({"doc_id": doc_id}), 201

    @app.get("/documents")
    def list_documents_route():
        with storage.open_db(app.config["DB_PATH"]) as conn:
            docs = storage.list_documents(conn, vault_id=g.vault_id)
        return jsonify(
            [
                {
                    "doc_id": d["doc_id"],
                    "enc_name": _b64(d["enc_name"]),
                    "size": d["size"],
                    "uploaded_at": d["uploaded_at"],
                }
                for d in docs
            ]
        )

    @app.get("/documents/<doc_id>")
    def get_document_route(doc_id: str):
        try:
            with storage.open_db(app.config["DB_PATH"]) as conn:
                doc = storage.get_document(conn, doc_id, vault_id=g.vault_id)
        except storage.DocumentNotFoundError:
            return jsonify({"error": "not found"}), 404
        return jsonify(
            {
                "doc_id": doc["doc_id"],
                "enc_name": _b64(doc["enc_name"]),
                "nonce": _b64(doc["nonce"]),
                "ciphertext": _b64(doc["ciphertext"]),
                "tag": _b64(doc["tag"]),
                "size": doc["size"],
                "uploaded_at": doc["uploaded_at"],
            }
        )

    @app.put("/documents/<doc_id>")
    def replace_document_route(doc_id: str):
        """In-place overwrite of an EXISTING document's encrypted
        fields, added for password/key rotation -- see
        cloud/storage.py's replace_document() docstring for why this is
        deliberately a separate route from POST /documents rather than
        that route upserting."""
        body = request.get_json(silent=True) or {}
        required = ("enc_name", "nonce", "ciphertext", "tag")
        missing = [f for f in required if f not in body]
        if missing:
            return jsonify({"error": f"missing fields: {missing}"}), 400

        try:
            fields = {f: _unb64(body[f], f) for f in required}
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        with storage.open_db(app.config["DB_PATH"]) as conn:
            replaced = storage.replace_document(conn, doc_id=doc_id, vault_id=g.vault_id, **fields)
        if not replaced:
            return jsonify({"error": "not found"}), 404
        return jsonify({"doc_id": doc_id, "status": "replaced"}), 200

    @app.delete("/documents/<doc_id>")
    def delete_document_route(doc_id: str):
        with storage.open_db(app.config["DB_PATH"]) as conn:
            deleted = storage.delete_document(conn, doc_id, vault_id=g.vault_id)
        if not deleted:
            return jsonify({"error": "not found"}), 404
        return jsonify({"doc_id": doc_id, "status": "deleted"}), 200

    # -- sse_index ---------------------------------------------------------

    @app.post("/index")
    def push_index_entries():
        body = request.get_json(silent=True) or {}
        entries = body.get("entries")
        if not isinstance(entries, list) or not entries:
            return jsonify({"error": "'entries' must be a non-empty list"}), 400

        parsed = []
        for e in entries:
            if not isinstance(e, dict) or "label" not in e or "value" not in e:
                return jsonify({"error": "each entry needs 'label' and 'value'"}), 400
            label = e["label"]
            if not isinstance(label, str) or label == "":
                return jsonify({"error": "'label' must be a non-empty string"}), 400
            try:
                parsed.append((label, _unb64(e["value"], "value")))
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400

        try:
            with storage.open_db(app.config["DB_PATH"]) as conn:
                inserted = storage.save_index_entries(conn, parsed, vault_id=g.vault_id)
        except Exception as exc:  # sqlite3.IntegrityError on a label collision
            return jsonify({"error": str(exc)}), 409

        return jsonify({"inserted": inserted}), 201

    @app.get("/index/<label>")
    def get_index_entry_route(label: str):
        with storage.open_db(app.config["DB_PATH"]) as conn:
            value = storage.get_index_entry(conn, label, vault_id=g.vault_id)
        if value is None:
            return jsonify({"error": "not found"}), 404
        return jsonify({"label": label, "value": _b64(value)})

    @app.get("/index")
    def list_index_route():
        """A page of raw index rows for the inspector views: opaque
        HMAC labels and AES-GCM values, nothing the cloud could read."""
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), _INDEX_PAGE_MAX))
            offset = max(0, int(request.args.get("offset", 0)))
        except ValueError:
            return jsonify({"error": "limit and offset must be integers"}), 400
        with storage.open_db(app.config["DB_PATH"]) as conn:
            total = storage.index_entry_count(conn, vault_id=g.vault_id)
            rows = storage.list_index_entries(conn, vault_id=g.vault_id, limit=limit, offset=offset)
        return jsonify({
            "total": total,
            "entries": [{"label": r["label"], "value": _b64(r["value"])} for r in rows],
        })

    @app.post("/index/replace")
    def replace_index_route():
        # Distinct from POST /index (Phase 2, unchanged): that route
        # is additive-insert-only and requires a non-empty list.
        # Rebuilding the whole index (Phase 5's upload flow) needs to
        # atomically REPLACE the table's contents -- including
        # correctly ending up empty if the corpus currently has zero
        # keywords -- so it gets its own route rather than changing
        # /index's established semantics.
        body = request.get_json(silent=True) or {}
        entries = body.get("entries")
        if not isinstance(entries, list):
            return jsonify({"error": "'entries' must be a list (may be empty)"}), 400

        parsed = []
        for e in entries:
            if not isinstance(e, dict) or "label" not in e or "value" not in e:
                return jsonify({"error": "each entry needs 'label' and 'value'"}), 400
            label = e["label"]
            if not isinstance(label, str) or label == "":
                return jsonify({"error": "'label' must be a non-empty string"}), 400
            try:
                parsed.append((label, _unb64(e["value"], "value")))
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400

        with storage.open_db(app.config["DB_PATH"]) as conn:
            removed = storage.clear_index(conn, vault_id=g.vault_id)
            inserted = storage.save_index_entries(conn, parsed, vault_id=g.vault_id) if parsed else 0

        return jsonify({"removed": removed, "inserted": inserted}), 200

    @app.post("/search")
    def search_route():
        body = request.get_json(silent=True) or {}
        if "k1" not in body:
            return jsonify({"error": "missing field: k1"}), 400
        try:
            k1 = _unb64(body["k1"], "k1")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        with storage.open_db(app.config["DB_PATH"]) as conn:
            results = run_search_loop(conn, k1, vault_id=g.vault_id)

        return jsonify({"results": [_b64(v) for v in results], "count": len(results)}), 200

    # -- meta ----------------------------------------------------------------

    @app.post("/meta/<key>")
    def set_meta_route(key: str):
        body = request.get_json(silent=True) or {}
        if "value" not in body:
            return jsonify({"error": "missing field: value"}), 400
        try:
            value = _unb64(body["value"], "value")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        with storage.open_db(app.config["DB_PATH"]) as conn:
            storage.set_meta(conn, key, value, vault_id=g.vault_id)
        return jsonify({"key": key}), 200

    @app.get("/meta/<key>")
    def get_meta_route(key: str):
        with storage.open_db(app.config["DB_PATH"]) as conn:
            value = storage.get_meta(conn, key, vault_id=g.vault_id)
        if value is None:
            return jsonify({"error": "not found"}), 404
        return jsonify({"key": key, "value": _b64(value)})

    @app.errorhandler(500)
    def internal_error(_exc):
        # Never leak a traceback, filesystem path, or SQL to a caller.
        return jsonify({"error": "internal cloud error"}), 500

    return app


if __name__ == "__main__":
    # Runs the untrusted cloud on its own port, deliberately different
    # from the (future) trusted client app -- Section 02's "why two
    # processes matters for marks".
    create_app().run(port=int(os.environ.get("CLOUD_PORT", "5001")), debug=False)
