"""
client/client_app.py -- the trusted client's own Flask process
(Section 11: "Flask: serves web/, relays ciphertext to cloud").

Section 02's trust boundary made concrete: this process is the ONLY
place in the whole system that ever holds a derived key or sees
plaintext. It serves the browser UI (web/) and orchestrates every
operation by calling:

  - client/keymgmt.py, client/crypto.py                    -- all cryptography
  - client/tokenizer.py, client/indexer.py, client/search.py -- the SSE scheme
  - client/cloud_client.py                                  -- the ONLY way
    this process ever talks to the untrusted cloud, and only in
    ciphertext and opaque tokens

The browser (web/main.js) never calls the cloud directly and never
receives a key. It only ever talks to THIS process's /api/* routes,
which return plaintext (decrypted filenames, document content, search
results) because all the cryptography happens here, in this Python
process -- never in JavaScript, matching Section 03's "Browser UI:
thin shell, no crypto".

Session model (multi-user extension -- replaces the original
single-operator design, in which ONE process-wide KeySet served
whoever could reach the port). Now:

  * Users log in with an ACCOUNT password (client/accounts.py: Argon2id
    password hash, roles `user` / `admin`). Login creates a server-side
    session; the browser cookie carries only a random session id
    (HttpOnly, SameSite=Strict). Sessions expire on idle and absolute
    timeouts, and every state-changing /api request must echo the
    session's CSRF token in an X-CSRF-Token header.
  * Each regular user owns ONE vault: an opaque random vault_id in the
    cloud, with its own salt, verifier, documents and index. "Unlock"
    still runs the original keymgmt.unlock() on that user's own vault
    passphrase, so every user has independent K_file / K_index -- there
    is no global key. The unlocked KeySet is attached to that one
    session only and wiped on lock, logout or expiry.
  * Ownership is enforced twice: this process only ever addresses the
    logged-in user's own vault (credentials come from the server-side
    account record, never from the browser), and the cloud refuses a
    vault request without that vault's access token. A doc_id from
    another vault is simply "not found".
  * Administrators have no vault and no keys. Their routes read the
    audit log, account metadata, and cloud-side ciphertext records --
    nothing that could decrypt anything.

Password verifier (added post-Phase-5, security fix H1/H2): the
paragraph above described Phases 1-5 as shipped, and is exactly why an
incorrect password used to be discovered only much later -- by which
point a follow-up upload's index rebuild had already silently
destroyed the real encrypted index (H1), and a missing `kdf_salt` row
had already silently minted a brand-new vault identity (H2). An
independent security audit (docs/security_audit_opus_phase6_readiness.md)
found both were reachable with nothing more than a typo or a deleted
row -- see project memory phase6_security_audit_opus.md. This module
now stores one extra, non-secret meta row -- `kdf_verifier`, an
AES-GCM encryption of a fixed constant under K_index -- created ONLY
the very first time a vault is ever unlocked (when BOTH `kdf_salt` and
`kdf_verifier` are absent). Every later unlock must decrypt it:
failure means the password is wrong and unlock is refused outright
(401) before any key ever reaches an upload or index rebuild; if only
ONE of the two rows is present, the vault's KDF metadata is incomplete
or corrupted, and unlock refuses to proceed rather than minting a new
identity over it (409). This is a deliberate, minimal addition to the
approved design -- not scope creep -- scoped narrowly to closing H1
and H2. (Accounts and sessions arrived later, in the multi-user
extension described above; the verifier logic is unchanged by it and
now simply runs per vault.)

Fix F1 (post-audit follow-up, closes a gap the H2 fix above left
open): the "both rows absent" branch is not automatically a fresh
vault. An attacker (or an operator's mistake) can delete BOTH
`kdf_salt` and `kdf_verifier` from an existing vault that already has
documents, which the original H2 fix would still treat as "genuinely
new" and happily bootstrap a brand-new identity over -- any password
would then "unlock" a vault whose real documents are permanently
unreadable. Unlock now checks whether the cloud already holds any
documents before it is willing to bootstrap: if it does, both-absent
is treated exactly like the single-row-missing case (409, fail
closed, no password accepted) instead of as a fresh vault. Only a
cloud with BOTH rows absent AND zero documents may bootstrap.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
from functools import wraps
from urllib.parse import quote, urlparse

from flask import Flask, Response, g, jsonify, request
from werkzeug.exceptions import HTTPException

from . import cloud_client
from .accounts import (
    LOGIN_FAILURE_LIMIT,
    validate_password,
    validate_username,
    ROLE_ADMIN,
    ROLE_USER,
    AccountError,
    AccountStore,
    DuplicateUserError,
    SessionStore,
    USERNAME_RE,
    new_vault_credentials,
)
from .crypto import (
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    DecryptionError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
)
from .cloud_client import CloudError, CloudUnavailableError, VaultScopeError
from .indexer import build_index
from .keymgmt import (
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    generate_salt,
    unlock as derive_keys,
)
from .search import (
    AmbiguousQueryError,
    build_search_token,
    decrypt_search_results,
    normalise_conjunctive_query,
)
from .textextract import extract_indexable_text, is_pdf, is_zip
from .tokenizer import tokenize

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

# -- KDF metadata verifier (security fix H1/H2) -----------------------------
# See the module docstring's "Password verifier" section above. Kept
# entirely within this file because H1 and H2 are both Phase-5
# "operational layer" bugs per the audit -- Phase 1's crypto core and
# Phase 3/4's K1/K2 index/search contract are untouched by this fix.
_VERIFIER_META_KEY = "kdf_verifier"
_VERIFIER_PLAINTEXT = b"vault-verifier:v1"


class VaultMetadataError(Exception):
    """Raised when the cloud's KDF metadata (`kdf_salt` / `kdf_verifier`)
    is in a state that must never be unlocked from: exactly one of the
    two mandatory rows present, OR both rows absent while the vault
    already holds documents. Either state can only mean a deleted/
    corrupted row, a partial write, or a both-rows-deletion attack --
    never a genuinely fresh vault (a genuinely fresh vault has BOTH
    rows absent AND zero documents) -- so unlock refuses to either
    guess or silently mint a new identity over the old one (H2/F1)."""


class IndexRebuildError(Exception):
    """Raised by _rebuild_and_push_index when at least one existing
    document in the corpus failed to decrypt during a rebuild. Pushing
    a smaller index in that case would silently destroy index coverage
    for every document that failed (H1) -- so the whole rebuild is
    aborted instead and the cloud's current index is left untouched."""


log = logging.getLogger("vault.client")


class _Anon:
    username = None

SESSION_COOKIE = "vault_sid"
CSRF_HEADER = "X-CSRF-Token"
_MAX_UPLOAD_BYTES = 16 * 1024 * 1024
_PREVIEW_TEXT_CHARS = 20000
_HEX_PREVIEW_BYTES = 512
_INSPECTOR_DOC_LIMIT = 50
_INSPECTOR_INDEX_LIMIT = 50


def _require_unlocked():
    """Returns the current session's KeySet, or None if this session's
    vault is locked (or there is no session). Every route that touches
    keys or plaintext calls this first."""
    session = g.get("session")
    return session.keys if session is not None else None


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _parts_view(blob: bytes) -> dict:
    """Split one stored AES-GCM blob (nonce || ciphertext || tag) into a
    display-safe hex view. Only ever called on bytes the cloud returned."""
    nonce, ciphertext, tag = _split_blob(blob)
    return {
        "total_bytes": len(blob),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext[:_HEX_PREVIEW_BYTES].hex(),
        "ciphertext_bytes": len(ciphertext),
        "ciphertext_truncated": len(ciphertext) > _HEX_PREVIEW_BYTES,
        "tag_hex": tag.hex(),
    }


def _cloud_record_view(raw: dict) -> dict:
    """What the cloud's GET /documents/<id> returned, re-presented for
    the inspector/transparency views: separate nonce / ciphertext / tag
    columns exactly as the cloud schema stores them, plus the encrypted
    filename blob (stored as one combined nonce||ct||tag column)."""
    enc_name = base64.b64decode(raw["enc_name"])
    nonce = base64.b64decode(raw["nonce"])
    ciphertext = base64.b64decode(raw["ciphertext"])
    tag = base64.b64decode(raw["tag"])
    return {
        "doc_id": raw["doc_id"],
        "uploaded_at": raw["uploaded_at"],
        "size": raw["size"],
        "enc_name": {**_parts_view(enc_name), "b64": raw["enc_name"]},
        "content": {
            "nonce_hex": nonce.hex(),
            "nonce_bytes": len(nonce),
            "ciphertext_hex": ciphertext[:_HEX_PREVIEW_BYTES].hex(),
            "ciphertext_b64_preview": raw["ciphertext"][:384],
            "ciphertext_bytes": len(ciphertext),
            "ciphertext_truncated": len(ciphertext) > _HEX_PREVIEW_BYTES,
            "tag_hex": tag.hex(),
            "tag_bytes": len(tag),
            "blob_bytes": len(nonce) + len(ciphertext) + len(tag),
        },
    }


def _raw_response_preview(raw: dict) -> dict:
    """The cloud JSON response with long base64 fields shortened, so the
    UI can show the literal wire format without shipping megabytes."""
    out = {}
    for k, v in raw.items():
        if isinstance(v, str) and len(v) > 160:
            out[k] = f"{v[:160]}… ({len(v)} base64 chars)"
        else:
            out[k] = v
    return out


def _content_kind(content: bytes) -> str:
    if is_pdf(content):
        return "pdf"
    if is_zip(content):
        return "zip"
    try:
        content.decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "binary"


def _safe_download_name(filename: str) -> str:
    """Header-safe Content-Disposition value: no quotes, CR/LF or path
    separators can break out of the header, and non-ASCII names survive
    via RFC 5987 filename*."""
    cleaned = "".join("_" if c in '"\\/\r\n' or ord(c) < 32 else c for c in filename) or "download"
    ascii_name = cleaned.encode("ascii", "replace").decode("ascii").replace("?", "_")
    return f"filename=\"{ascii_name}\"; filename*=UTF-8''{quote(cleaned)}"


def _split_blob(blob: bytes):
    """The one place this process slices an AES-GCM blob into the
    cloud schema's three columns -- identical to what
    tests/test_integration.py has done by hand since Phase 2."""
    return blob[:NONCE_SIZE], blob[NONCE_SIZE:-TAG_SIZE], blob[-TAG_SIZE:]


def _decrypt_filename(keys, enc_name: bytes) -> str:
    """Best-effort filename decrypt: returns a clearly-marked
    placeholder instead of raising, so ONE bad/wrong-key entry does
    not take down an entire vault-list or search-result response --
    the caller can still show the rest and let the user notice
    something is wrong with that one row."""
    try:
        return aes_gcm_decrypt(keys.k_file, enc_name).decode("utf-8")
    except (DecryptionError, UnicodeDecodeError):
        return "<undecryptable -- wrong password, or corrupted/tampered data>"


def _rebuild_and_push_index(keys, exclude_doc_id: "str | None" = None) -> None:
    """Re-derives the WHOLE index from the current corpus and pushes
    it as an atomic replacement. Called after every successful upload,
    and by api_delete_document (see that route's docstring for why it
    calls this BEFORE removing the document from cloud storage, not
    after).

    Static-index cost, stated plainly: this re-fetches and
    re-decrypts every document in the vault on every upload (O(n) in
    corpus size). Fine at course-project scale; a production system
    wanting to avoid this would need either a persisted plaintext-
    keyword cache or a genuinely incremental (forward-private) index --
    both out of scope per Section 10's static-index decision.

    `exclude_doc_id`: when given, that document is treated as already
    gone for this rebuild even though it may still physically exist in
    cloud storage at call time -- this is what lets api_delete_document
    remove a document's keywords from the searchable index as a
    separate, safely-ordered step from deleting its ciphertext.
    """
    docs_meta = cloud_client.list_documents()
    documents = {}
    failed_doc_ids = []
    for meta in docs_meta:
        if meta["doc_id"] == exclude_doc_id:
            continue
        doc = cloud_client.fetch_document(meta["doc_id"])
        if doc is None:
            continue  # deleted between listing and fetching -- skip, not fatal
        blob = doc["nonce"] + doc["ciphertext"] + doc["tag"]
        try:
            plaintext = aes_gcm_decrypt(keys.k_file, blob)
        except DecryptionError:
            # Security fix H1: this USED to `continue` here, silently
            # contributing zero keywords for this document and letting
            # the rebuild finish "successfully" with a smaller index
            # that then destructively replaced the real one. With the
            # api_unlock verifier (H2) in place this should now be
            # unreachable via a wrong password -- keys are checked
            # before any upload ever happens -- but it can still happen
            # from a genuinely corrupted/tampered document, so the
            # rebuild itself stays defensive: record the failure and
            # keep scanning (so the error below can report every
            # affected doc_id at once), but never build or push a
            # partial index.
            failed_doc_ids.append(meta["doc_id"])
            continue

        # PDF-support addition: same idea as the DecryptionError case
        # above -- decryption succeeding but extraction failing should
        # not happen for anything uploaded through api_upload_document
        # (which validates with this exact function first), but a
        # rebuild stays defensive rather than assuming that can never
        # change; treat it as a failed document, not a silent zero-
        # keyword contribution.
        text = extract_indexable_text(plaintext)
        if text is None:
            failed_doc_ids.append(meta["doc_id"])
            continue
        documents[meta["doc_id"]] = tokenize(text)

    if failed_doc_ids:
        # Abort the whole rebuild rather than replacing the cloud's
        # current (complete, correct) index with an incomplete one.
        # cloud_client.replace_index() is never called on this path --
        # the existing sse_index table is left exactly as it was.
        raise IndexRebuildError(
            f"{len(failed_doc_ids)} of {len(docs_meta)} document(s) in the "
            f"vault failed to decrypt during index rebuild and were "
            f"excluded: {failed_doc_ids}. Refusing to replace the "
            f"encrypted index with an incomplete one -- the existing "
            f"index was left unchanged."
        )

    entries = build_index(keys.k_index, documents)
    cloud_client.replace_index([(e.label, e.value) for e in entries])


def create_app(config: "dict | None" = None) -> Flask:
    app = Flask(__name__, static_folder=WEB_DIR, static_url_path="")
    app.config.update(
        ACCOUNTS_DB_PATH=os.environ.get("ACCOUNTS_DB_PATH", "client_accounts.sqlite3"),
        SESSION_IDLE_SECONDS=int(os.environ.get("SESSION_IDLE_SECONDS", "1800")),
        SESSION_ABSOLUTE_SECONDS=int(os.environ.get("SESSION_ABSOLUTE_SECONDS", str(8 * 3600))),
        SESSION_COOKIE_SECURE_FLAG=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
        ALLOW_REGISTRATION=os.environ.get("ALLOW_REGISTRATION", "1") != "0",
        # One-time administrator bootstrap secret. Configurable via the
        # environment; otherwise random per process and printed to the
        # client's terminal at startup (see __main__) -- never a fixed,
        # hard-coded credential. Useless once an administrator exists.
        ADMIN_SETUP_TOKEN=os.environ.get("ADMIN_SETUP_TOKEN") or secrets.token_urlsafe(18),
        MAX_CONTENT_LENGTH=_MAX_UPLOAD_BYTES,
    )
    if config:
        app.config.update(config)

    accounts = AccountStore(app.config["ACCOUNTS_DB_PATH"])
    sessions = SessionStore(app.config["SESSION_IDLE_SECONDS"], app.config["SESSION_ABSOLUTE_SECONDS"])
    app.extensions["vault_accounts"] = accounts
    app.extensions["vault_sessions"] = sessions

    # Unsafe-method routes reachable without a session. They are still
    # CSRF-resistant: they accept only a JSON body (a cross-site HTML
    # form cannot send application/json without a CORS preflight this
    # app never grants) and reject a foreign Origin header.
    _SESSIONLESS_POST = {"api_register", "api_login", "api_setup_admin"}

    def audit(event_type, outcome="success", target=None, detail=None, is_demo=False, user=None, **kw):
        accounts.log_event(
            event_type,
            outcome=outcome,
            actor=user if user is not None else g.get("user"),
            target=target,
            detail=detail,
            is_demo=is_demo,
            ip=request.remote_addr,
            **kw,
        )

    def _session_payload():
        user, session = g.get("user"), g.get("session")
        if user is None:
            return {
                "authenticated": False,
                "admin_exists": accounts.admin_exists(),
                "registration_open": app.config["ALLOW_REGISTRATION"],
            }
        return {
            "authenticated": True,
            "user": {**user.public(), "vault_id": user.vault_id},
            "unlocked": session.keys is not None,
            "csrf_token": session.csrf_token,
            "idle_timeout_seconds": app.config["SESSION_IDLE_SECONDS"],
        }

    @app.before_request
    def _load_session():
        g.session, g.user = None, None
        # Restored after the request, so an in-process caller's own scope
        # (e.g. the benchmark harness) is never silently clobbered.
        g.previous_vault_scope = cloud_client.get_vault_scope()
        cloud_client.set_vault_scope(cloud_client.NO_VAULT)
        sid = request.cookies.get(SESSION_COOKIE)
        session, expired = sessions.get(sid)
        if expired is not None:
            reason, old = expired
            accounts.log_event(
                "session_expired", outcome="expired", actor_id=old.user_id,
                actor_username=(accounts.get_user(old.user_id) or _Anon).username,
                detail=reason, ip=request.remote_addr,
            )
        if session is not None:
            user = accounts.get_user(session.user_id)
            if user is None or not user.is_active:
                sessions.destroy(sid)
            else:
                g.session, g.user = session, user
                if user.role == ROLE_USER and user.vault_id and user.cloud_token:
                    cloud_client.set_vault_scope((user.vault_id, user.cloud_token))

        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/"):
            if request.endpoint in _SESSIONLESS_POST:
                if not request.is_json:
                    return jsonify({"error": "expected an application/json request body"}), 415
                origin = request.headers.get("Origin")
                if origin and urlparse(origin).netloc != request.host:
                    return jsonify({"error": "cross-origin request refused"}), 403
                return None
            if g.session is None:
                return jsonify({"error": "authentication required -- please log in"}), 401
            supplied = request.headers.get(CSRF_HEADER, "")
            if not hmac.compare_digest(supplied, g.session.csrf_token):
                return jsonify({"error": "missing or invalid CSRF token -- reload the page"}), 403
        return None

    @app.teardown_request
    def _clear_scope(_exc):
        cloud_client.set_vault_scope(g.get("previous_vault_scope"))

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'none'; form-action 'self'",
        )
        if request.path.startswith("/api/"):
            # Decrypted content must never sit in a shared/browser cache.
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def _set_session_cookie(resp, sid):
        resp.set_cookie(
            SESSION_COOKIE, sid, httponly=True, samesite="Strict",
            secure=app.config["SESSION_COOKIE_SECURE_FLAG"], path="/",
            max_age=app.config["SESSION_ABSOLUTE_SECONDS"],
        )

    # -- authorization decorators ------------------------------------------

    def login_required(role=None):
        def deco(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                if g.user is None:
                    return jsonify({"error": "authentication required -- please log in"}), 401
                if role is not None and g.user.role != role:
                    audit("access_denied", outcome="denied", detail=f"{request.method} {request.path}")
                    if role == ROLE_USER:
                        msg = "administrator accounts have no vault -- vault operations require a regular user account"
                    else:
                        msg = "administrator role required"
                    return jsonify({"error": msg}), 403
                return fn(*args, **kwargs)
            return wrapper
        return deco

    vault_user = login_required(ROLE_USER)
    admin_only = login_required(ROLE_ADMIN)

    # -- error handling: never leak tracebacks, paths, or SQL ------------------

    @app.errorhandler(CloudUnavailableError)
    def _cloud_down(exc):
        return jsonify({"error": "the cloud storage service is unreachable -- is cloud_app running?"}), 502

    @app.errorhandler(CloudError)
    def _cloud_error(exc):
        return jsonify({"error": f"cloud service error ({exc.status_code})"}), 502

    @app.errorhandler(VaultScopeError)
    def _no_vault(exc):
        return jsonify({"error": "this account has no vault"}), 403

    @app.errorhandler(413)
    def _too_large(exc):
        return jsonify({"error": f"file too large (limit {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"}), 413

    @app.errorhandler(Exception)
    def _unexpected(exc):
        if isinstance(exc, HTTPException):
            if request.path.startswith("/api/"):
                return jsonify({"error": exc.description or exc.name}), exc.code
            return exc
        log.exception("unhandled error in %s %s", request.method, request.path)
        return jsonify({"error": "internal error -- see the trusted client's console log"}), 500

    @app.get("/")
    def index_page():
        return app.send_static_file("index.html")

    # -- accounts / sessions -------------------------------------------------

    @app.get("/api/session")
    def api_session():
        return jsonify(_session_payload())

    @app.post("/api/auth/register")
    def api_register():
        if not app.config["ALLOW_REGISTRATION"]:
            return jsonify({"error": "self-registration is disabled"}), 403
        body = request.get_json(silent=True) or {}
        username, password = body.get("username"), body.get("password")
        try:
            validate_username(username)
            validate_password(password)
        except AccountError as exc:
            return jsonify({"error": str(exc)}), 400
        if accounts.username_exists(username):
            return jsonify({"error": "that username is already taken"}), 409

        # Each user gets their own opaque cloud namespace + access token.
        vault_id, token = new_vault_credentials()
        with cloud_client.vault_scope(vault_id, token):
            cloud_client.register_vault(vault_id, token)
        try:
            user = accounts.create_user(username, password, ROLE_USER, vault_id=vault_id, cloud_token=token)
        except DuplicateUserError as exc:
            return jsonify({"error": str(exc)}), 409
        audit("register", user=user, target=user.username)
        return jsonify({"user": user.public()}), 201

    @app.post("/api/auth/login")
    def api_login():
        body = request.get_json(silent=True) or {}
        username, password = body.get("username"), body.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
            return jsonify({"error": "username and password are required"}), 400
        # Never log a value that might be a mistyped password.
        logged_name = username if USERNAME_RE.match(username) else None

        if logged_name and accounts.recent_failed_logins(logged_name) >= LOGIN_FAILURE_LIMIT:
            accounts.log_event("login_throttled", outcome="denied", actor_username=logged_name, ip=request.remote_addr)
            return jsonify({"error": "too many failed attempts -- try again in 15 minutes"}), 429

        user = accounts.verify_password(username, password)
        if user is None:
            existing = accounts.get_user_by_username(logged_name) if logged_name else None
            accounts.log_event(
                "login_failed", outcome="failure",
                actor_id=existing.id if existing else None, actor_username=logged_name,
                detail="invalid credentials", ip=request.remote_addr,
            )
            return jsonify({"error": "invalid username or password"}), 401
        if not user.is_active:
            audit("login_failed", outcome="failure", user=user, detail="account deactivated")
            return jsonify({"error": "this account has been deactivated by an administrator"}), 403

        # Fresh session id on every login (no session fixation); any
        # session this browser already had is ended and its keys wiped.
        sessions.destroy(request.cookies.get(SESSION_COOKIE))
        session = sessions.create(user.id, user.role)
        accounts.record_login(user.id)
        g.session, g.user = session, user
        audit("login", user=user)
        resp = jsonify(_session_payload())
        _set_session_cookie(resp, session.sid)
        return resp

    @app.post("/api/auth/logout")
    def api_logout():
        was_unlocked = g.session.keys is not None
        sessions.destroy(g.session.sid)  # wipes the KeySet, if any
        if was_unlocked:
            audit("vault_lock", detail="locked by logout")
        audit("logout")
        resp = jsonify({"status": "logged out"})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.get("/api/setup/status")
    def api_setup_status():
        return jsonify({"admin_exists": accounts.admin_exists()})

    @app.post("/api/setup/admin")
    def api_setup_admin():
        """One-time administrator bootstrap. Works only while NO admin
        account exists, and only with the setup token printed in the
        trusted client's terminal (or set via ADMIN_SETUP_TOKEN). The
        operator chooses the admin's username and password here -- there
        is no default administrator credential anywhere."""
        if accounts.admin_exists():
            return jsonify({"error": "setup already completed -- an administrator exists"}), 409
        body = request.get_json(silent=True) or {}
        supplied = body.get("setup_token")
        if not isinstance(supplied, str) or not hmac.compare_digest(supplied, app.config["ADMIN_SETUP_TOKEN"]):
            accounts.log_event("admin_bootstrap", outcome="denied", detail="wrong setup token", ip=request.remote_addr)
            return jsonify({"error": "invalid setup token"}), 403
        try:
            user = accounts.create_user(body.get("username"), body.get("password"), ROLE_ADMIN)
        except AccountError as exc:
            return jsonify({"error": str(exc)}), 400 if not isinstance(exc, DuplicateUserError) else 409
        audit("admin_bootstrap", user=user, target=user.username)
        return jsonify({"user": user.public()}), 201

    # -- vault lifecycle -----------------------------------------------

    @app.get("/api/status")
    def api_status():
        return jsonify({"unlocked": _require_unlocked() is not None})

    @app.post("/api/unlock")
    @vault_user
    def api_unlock():
        body = request.get_json(silent=True) or {}
        password = body.get("password")
        if not isinstance(password, str) or password == "":
            return jsonify({"error": "password must be a non-empty string"}), 400

        try:
            salt = cloud_client.get_meta("kdf_salt")
            verifier = cloud_client.get_meta(_VERIFIER_META_KEY)
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        if salt is None and verifier is None:
            # Security fix F1/H2 (both-rows-missing case): both
            # mandatory KDF rows are absent. That is legitimate ONLY
            # for a genuinely fresh vault that has never stored
            # anything -- a document can only exist if some earlier
            # unlock already succeeded, and the ONLY way to reach a
            # successful unlock is through this same branch (fresh) or
            # the "both present" branch below, both of which require
            # kdf_salt/kdf_verifier to exist afterward. So if the cloud
            # already holds documents, both rows being absent here can
            # only mean they were deleted/lost from an EXISTING vault
            # (the audit's exact both-missing attack) -- minting a new
            # identity over that state would let ANY password "unlock"
            # a vault whose real documents are now unreadable forever.
            # Check for that BEFORE bootstrapping anything.
            try:
                existing_docs = cloud_client.list_documents()
            except CloudUnavailableError as exc:
                return jsonify({"error": str(exc)}), 502
            except CloudError as exc:
                return jsonify({"error": str(exc)}), 502

            if existing_docs:
                audit("vault_unlock", outcome="failure", detail="KDF metadata missing on a non-empty vault")
                return jsonify({
                    "error": (
                        "vault key-derivation metadata is missing entirely "
                        "('kdf_salt' and 'kdf_verifier' are both absent) but "
                        "the vault already contains documents. This is not "
                        "a fresh vault -- refusing to mint a new vault "
                        "identity over existing encrypted data. No password "
                        "will unlock this vault until its KDF metadata is "
                        "restored."
                    )
                }), 409

            # Genuinely fresh vault confirmed: no documents AND no KDF
            # metadata at all. This is the ONLY branch in the entire
            # app allowed to mint a new vault identity. Not part of
            # Section 07 flow A (which assumes a salt already exists)
            # but required to make that flow possible the very first
            # time.
            salt = generate_salt()
            try:
                keys = derive_keys(password, salt)
            except ValueError as exc:
                return jsonify({"error": f"could not derive vault keys: {exc}"}), 500
            verifier = aes_gcm_encrypt(keys.k_index, _VERIFIER_PLAINTEXT)
            try:
                cloud_client.set_meta("kdf_salt", salt)
                cloud_client.set_meta(_VERIFIER_META_KEY, verifier)
            except CloudUnavailableError as exc:
                return jsonify({"error": str(exc)}), 502
            except CloudError as exc:
                return jsonify({"error": str(exc)}), 502
            audit("vault_initialized", detail="new vault salt + verifier created")
        elif salt is None or verifier is None:
            # Security fix H2: exactly one of the two mandatory rows is
            # missing -- a deleted row, a partial write, tampering. This
            # is NOT a fresh vault (a fresh vault has both absent), so
            # unlock must not guess, and must not bootstrap a new salt
            # over an existing vault's real identity. Fail closed.
            missing = "kdf_salt" if salt is None else _VERIFIER_META_KEY
            audit("vault_unlock", outcome="failure", detail=f"KDF metadata incomplete ({missing} missing)")
            return jsonify({
                "error": (
                    f"vault key-derivation metadata is incomplete: "
                    f"'{missing}' is missing while the other KDF row is "
                    f"present. Refusing to unlock or create a new vault "
                    f"identity over the existing one."
                )
            }), 409
        else:
            try:
                keys = derive_keys(password, salt)
            except ValueError as exc:
                # e.g. a corrupted salt whose length no longer matches
                # SALT_SIZE -- fail closed rather than crashing (500).
                return jsonify({
                    "error": f"vault key-derivation metadata is corrupt: {exc}"
                }), 409
            try:
                aes_gcm_decrypt(keys.k_index, verifier)
            except DecryptionError:
                # Security fix H1/H2: this is the check that used not to
                # exist. A wrong password (or a corrupted/substituted
                # salt or verifier) is now caught HERE, before any key
                # ever reaches an upload or index rebuild -- closing the
                # entry condition for H1's destructive rebuild.
                audit("vault_unlock_failed", outcome="failure", detail="incorrect vault passphrase")
                return jsonify({"error": "incorrect password"}), 401

        # Keys belong to THIS session only (see module docstring).
        g.session.lock()
        g.session.keys = keys
        audit("vault_unlock")
        return jsonify({"status": "unlocked"}), 200

    @app.post("/api/lock")
    @vault_user
    def api_lock():
        was_unlocked = g.session.keys is not None
        g.session.lock()
        if was_unlocked:
            audit("vault_lock")
        return jsonify({"status": "locked"}), 200

    @app.post("/api/change-password")
    @vault_user
    def api_change_password():
        """Rotates the vault's password: a fresh salt, a freshly
        derived KeySet, every document re-encrypted under the new
        K_file, the whole search index rebuilt under the new K_index,
        and finally the KDF metadata (kdf_salt/kdf_verifier) updated to
        match. Requires the CURRENT password even though the vault is
        already unlocked -- a deliberate re-authentication step for a
        security-sensitive action, independent of (and not simply
        trusting) the process-wide unlocked session.

        Two-phase, fail-fast-before-writing (the H1 abort philosophy
        applied one step earlier): phase one decrypts and tokenizes
        EVERY document under the OLD keys, entirely in memory, writing
        nothing anywhere. Only if that whole pass succeeds does phase
        two begin re-encrypting and pushing. This guarantees a
        validation failure (a corrupted/tampered document, found before
        phase two starts) can NEVER itself leave the vault
        half-migrated -- but it does not, and structurally cannot,
        make phase two itself atomic.

        Documented limitation, honestly, not hidden: unlike a single
        AES-GCM call, this is O(n) HTTP round-trips to the cloud (one
        PUT per document, same rebuild-cost philosophy as
        _rebuild_and_push_index -- see that function's docstring and
        architecture.html Section 07). If the cloud connection drops
        DURING phase two, after some documents have already been
        overwritten with new-key ciphertext but before kdf_salt/
        kdf_verifier are updated (the LAST step, deliberately), the
        vault is left in a genuinely split state: unlocking with the
        OLD password still succeeds (the verifier hasn't changed yet)
        but shows the already-migrated documents as
        "<undecryptable...>"; unlocking with the NEW password fails
        outright (the verifier still names the old identity). There is
        no way to make an O(n) multi-request migration atomic without
        either a distributed transaction the cloud side does not
        implement, or the envelope-encryption redesign named as future
        work in Section 04 (wrap a random per-document key with the
        master key, so rotation only ever re-wraps small key blobs
        instead of re-encrypting every document). Accepted, scoped
        trade-off for this project, not an oversight.
        """
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        body = request.get_json(silent=True) or {}
        current_password = body.get("current_password")
        new_password = body.get("new_password")
        if not isinstance(current_password, str) or current_password == "":
            return jsonify({"error": "current_password must be a non-empty string"}), 400
        if not isinstance(new_password, str) or new_password == "":
            return jsonify({"error": "new_password must be a non-empty string"}), 400

        try:
            salt = cloud_client.get_meta("kdf_salt")
            verifier = cloud_client.get_meta(_VERIFIER_META_KEY)
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502
        if salt is None or verifier is None:
            # Same fail-closed posture as unlock's H2/F1 branches: the
            # vault was unlocked a moment ago, so these rows existing
            # is the expected state -- one or both missing now means a
            # deleted row or corruption happened concurrently, not a
            # normal condition this route should paper over.
            return jsonify({
                "error": "vault KDF metadata is missing or incomplete -- refusing to rotate the password"
            }), 409

        # Independent re-authentication: derive fresh keys from the
        # SUPPLIED current_password and check them against the stored
        # verifier, rather than trusting this session's unlocked keys
        # to still correspond to whatever the caller claims. This also
        # means the crypto below never depends on the session keys being
        # in sync with reality -- only on what was just verified.
        try:
            old_keys = derive_keys(current_password, salt)
        except ValueError as exc:
            return jsonify({"error": f"could not derive vault keys: {exc}"}), 500
        try:
            aes_gcm_decrypt(old_keys.k_index, verifier)
        except DecryptionError:
            audit("vault_passphrase_change", outcome="failure", detail="current passphrase incorrect")
            return jsonify({"error": "current password is incorrect"}), 401

        # Phase one: decrypt + tokenize the WHOLE corpus under the OLD
        # keys, in memory only. Nothing is written in this phase.
        try:
            docs_meta = cloud_client.list_documents()
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        migrated = {}  # doc_id -> {"filename": bytes, "content": bytes, "keywords": set[str]}
        failed_doc_ids = []
        for meta in docs_meta:
            try:
                doc = cloud_client.fetch_document(meta["doc_id"])
            except CloudUnavailableError as exc:
                return jsonify({"error": str(exc)}), 502
            except CloudError as exc:
                return jsonify({"error": str(exc)}), 502
            if doc is None:
                continue  # deleted between listing and fetching -- skip, not fatal

            blob = doc["nonce"] + doc["ciphertext"] + doc["tag"]
            try:
                filename_bytes = aes_gcm_decrypt(old_keys.k_file, doc["enc_name"])
                content_bytes = aes_gcm_decrypt(old_keys.k_file, blob)
            except DecryptionError:
                failed_doc_ids.append(meta["doc_id"])
                continue

            text = extract_indexable_text(content_bytes)
            if text is None:
                failed_doc_ids.append(meta["doc_id"])
                continue

            migrated[meta["doc_id"]] = {
                "filename": filename_bytes,
                "content": content_bytes,
                "keywords": tokenize(text),
            }

        if failed_doc_ids:
            raise_msg = (
                f"{len(failed_doc_ids)} of {len(docs_meta)} document(s) failed to "
                f"decrypt under the current password during validation and were "
                f"excluded: {failed_doc_ids}. Password was NOT changed -- refusing "
                f"to migrate a corpus it could not fully validate first."
            )
            return jsonify({"error": raise_msg}), 500

        # Phase two: only now, having confirmed every document decrypts
        # cleanly, generate the new identity and start writing.
        new_salt = generate_salt()
        try:
            new_keys = derive_keys(new_password, new_salt)
        except ValueError as exc:
            return jsonify({"error": f"could not derive vault keys: {exc}"}), 500

        for doc_id, plain in migrated.items():
            name_blob = aes_gcm_encrypt(new_keys.k_file, plain["filename"])
            file_blob = aes_gcm_encrypt(new_keys.k_file, plain["content"])
            nonce, ciphertext, tag = _split_blob(file_blob)
            try:
                cloud_client.replace_document(doc_id, name_blob, nonce, ciphertext, tag)
            except CloudUnavailableError as exc:
                return jsonify({
                    "error": (
                        f"password rotation interrupted while re-encrypting documents: "
                        f"{exc}. The vault may now be in a MIXED state -- some documents "
                        f"re-encrypted under the new password, others still under the old "
                        f"one -- and kdf_salt/kdf_verifier were NOT yet updated, so the OLD "
                        f"password still unlocks the vault (already-migrated documents will "
                        f"show as undecryptable until this is retried and completes)."
                    )
                }), 502
            except CloudError as exc:
                return jsonify({"error": str(exc)}), 502

        entries = build_index(new_keys.k_index, {doc_id: plain["keywords"] for doc_id, plain in migrated.items()})
        try:
            cloud_client.replace_index([(e.label, e.value) for e in entries])
        except CloudUnavailableError as exc:
            return jsonify({
                "error": (
                    f"password rotation interrupted while rebuilding the index: {exc}. "
                    f"Documents were re-encrypted under the new password, but "
                    f"kdf_salt/kdf_verifier were NOT yet updated -- retry this request "
                    f"with the SAME new password to finish (the old password's verifier "
                    f"is still in place, but its documents are already unreadable under "
                    f"it; do not attempt to unlock with the old password in this state)."
                )
            }), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        # LAST step, deliberately: the point of no return. Everything
        # above this line is retriable; this line is what actually
        # flips the vault's identity to the new password.
        new_verifier = aes_gcm_encrypt(new_keys.k_index, _VERIFIER_PLAINTEXT)
        try:
            cloud_client.set_meta("kdf_salt", new_salt)
            cloud_client.set_meta(_VERIFIER_META_KEY, new_verifier)
        except CloudUnavailableError as exc:
            return jsonify({
                "error": (
                    f"password rotation interrupted at the final step (updating KDF "
                    f"metadata): {exc}. Documents and the index were already migrated "
                    f"to the new password -- retry this request with the SAME new "
                    f"password to finish; do not attempt to unlock with the old "
                    f"password."
                )
            }), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        g.session.lock()
        g.session.keys = new_keys
        audit("vault_passphrase_change", detail=f"{len(migrated)} document(s) re-encrypted")
        return jsonify({"status": "password changed", "documents_migrated": len(migrated)}), 200

    # -- documents -------------------------------------------------------

    @app.post("/api/documents")
    @vault_user
    def api_upload_document():
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        if "file" not in request.files:
            return jsonify({"error": "no file provided (multipart field name must be 'file')"}), 400
        file = request.files["file"]
        if not file.filename:
            return jsonify({"error": "uploaded file has no filename"}), 400

        raw_bytes = file.read()
        if extract_indexable_text(raw_bytes) is None:
            audit("upload", outcome="rejected", detail="unsupported file type")
            return jsonify(
                {
                    "error": "unsupported file type -- only UTF-8 text files, PDFs "
                    "(with a readable text layer; not one encrypted with its own "
                    "password), and zip archives (of files this project can read; "
                    "not a Word/Excel/PowerPoint file, which is a zip internally but "
                    "not one this project indexes) can be uploaded. This project's "
                    "SSE index is built over readable keyword content."
                }
            ), 400

        doc_id = os.urandom(16).hex()
        file_blob = aes_gcm_encrypt(keys.k_file, raw_bytes)
        name_blob = aes_gcm_encrypt(keys.k_file, file.filename.encode("utf-8"))
        nonce, ciphertext, tag = _split_blob(file_blob)

        try:
            cloud_client.push_document(doc_id, name_blob, nonce, ciphertext, tag)
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        try:
            _rebuild_and_push_index(keys)
        except IndexRebuildError as exc:
            audit("upload", outcome="failure", target=doc_id, detail="stored, but index rebuild aborted")
            # Security fix H1: the document itself is safely stored
            # (the push above already succeeded), but the encrypted
            # search index could not be safely rebuilt and was left
            # exactly as it was -- never replaced with an incomplete
            # one. Reported loudly rather than silently, unlike before.
            return jsonify({
                "doc_id": doc_id,
                "error": (
                    f"document stored, but the encrypted search index "
                    f"could not be safely rebuilt and was left unchanged: {exc}"
                )
            }), 500
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        audit("upload", target=doc_id, detail=f"{len(raw_bytes)} plaintext bytes -> {len(ciphertext)} ciphertext bytes")
        return jsonify({"doc_id": doc_id, "filename": file.filename}), 201

    @app.get("/api/documents")
    @vault_user
    def api_list_documents():
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        try:
            docs = cloud_client.list_documents()
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502

        return jsonify(
            [
                {
                    "doc_id": d["doc_id"],
                    "filename": _decrypt_filename(keys, d["enc_name"]),
                    "size": d["size"],
                    "uploaded_at": d["uploaded_at"],
                }
                for d in docs
            ]
        ), 200

    @app.get("/api/documents/<doc_id>")
    @vault_user
    def api_get_document(doc_id: str):
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        try:
            doc = cloud_client.fetch_document(doc_id)
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        if doc is None:
            return jsonify({"error": "not found"}), 404

        blob = doc["nonce"] + doc["ciphertext"] + doc["tag"]
        try:
            filename = aes_gcm_decrypt(keys.k_file, doc["enc_name"]).decode("utf-8")
            content_bytes = aes_gcm_decrypt(keys.k_file, blob)
        except DecryptionError:
            audit("decryption_failed", outcome="failure", target=doc_id, detail="view: AES-GCM tag check failed")
            return jsonify(
                {
                    "error": "decryption failed -- wrong vault password, or this "
                    "file's stored ciphertext was corrupted or tampered with"
                }
            ), 422

        audit("view", target=doc_id)
        pdf_file = is_pdf(content_bytes)
        zip_file = is_zip(content_bytes)
        content = None
        if not pdf_file and not zip_file:
            try:
                content = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                pass  # some other binary that slipped past upload validation

        return jsonify({
            "doc_id": doc_id,
            "filename": filename,
            "content": content,
            "is_pdf": pdf_file,
            "is_zip": zip_file,
        }), 200

    @app.get("/api/documents/<doc_id>/download")
    @vault_user
    def api_download_document(doc_id: str):
        """Returns a document's decrypted bytes as a real file download,
        instead of JSON -- the only sane way to hand back binary content
        such as a PDF (base64-in-JSON would work but adds ~33% overhead
        and no browser can just open it). Same trust boundary as every
        other route: decryption happens here, in the trusted client,
        never in the browser; this is just a different response
        encoding for the same already-unlocked-only plaintext access
        api_get_document already grants.
        """
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        try:
            doc = cloud_client.fetch_document(doc_id)
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        if doc is None:
            return jsonify({"error": "not found"}), 404

        blob = doc["nonce"] + doc["ciphertext"] + doc["tag"]
        try:
            filename = aes_gcm_decrypt(keys.k_file, doc["enc_name"]).decode("utf-8")
            content_bytes = aes_gcm_decrypt(keys.k_file, blob)
        except DecryptionError:
            audit("decryption_failed", outcome="failure", target=doc_id, detail="download: AES-GCM tag check failed")
            return jsonify(
                {
                    "error": "decryption failed -- wrong vault password, or this "
                    "file's stored ciphertext was corrupted or tampered with"
                }
            ), 422

        if is_pdf(content_bytes):
            mimetype = "application/pdf"
        elif is_zip(content_bytes):
            mimetype = "application/zip"
        else:
            mimetype = "text/plain; charset=utf-8"
        # ?inline=1 lets the in-app preview pane render a PDF; anything
        # else is always served as an attachment.
        inline = request.args.get("inline") == "1" and mimetype == "application/pdf"
        if not inline:
            audit("download", target=doc_id)
        response = Response(content_bytes, mimetype=mimetype)
        response.headers["Content-Disposition"] = (
            ("inline; " if inline else "attachment; ") + _safe_download_name(filename)
        )
        return response

    @app.delete("/api/documents/<doc_id>")
    @vault_user
    def api_delete_document(doc_id: str):
        """Removes a document and every trace of it from the encrypted
        search index.

        Ordering here is deliberately the REVERSE of api_upload_document's
        (rebuild the index first, delete the document second) -- not an
        inconsistency, a chosen tradeoff. Deleting the document first and
        rebuilding the index second would leave a window (permanent, if
        the rebuild then failed) where sse_index still holds labels
        pointing at a doc_id that no longer exists: api_search's
        not-found fallback (`filename = doc_id` when fetch_document
        returns None) would then surface that as a phantom search result
        forever, with no way to clear it short of a manual re-upload of
        some other document to trigger a fresh rebuild. Rebuilding first
        instead means the worst-case failure is a document that still
        exists but is temporarily unsearchable -- fully recoverable by
        simply retrying this same request.
        """
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        try:
            existing = cloud_client.fetch_document(doc_id)
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502
        if existing is None:
            return jsonify({"error": "not found"}), 404

        try:
            _rebuild_and_push_index(keys, exclude_doc_id=doc_id)
        except IndexRebuildError as exc:
            return jsonify({
                "error": (
                    f"document was NOT deleted: the encrypted search index "
                    f"could not be safely rebuilt without it, and was left "
                    f"unchanged, so the document itself was left in place "
                    f"too rather than deleting it out from under a stale "
                    f"index: {exc}"
                )
            }), 500
        except CloudUnavailableError as exc:
            return jsonify({"error": str(exc)}), 502
        except CloudError as exc:
            return jsonify({"error": str(exc)}), 502

        try:
            cloud_client.delete_document(doc_id)
        except CloudUnavailableError as exc:
            return jsonify({
                "error": (
                    f"the encrypted index no longer references this "
                    f"document, but deleting its stored ciphertext failed: "
                    f"{exc}. It is no longer searchable; retry this "
                    f"request to finish removing it."
                )
            }), 502
        except CloudError as exc:
            return jsonify({
                "error": (
                    f"the encrypted index no longer references this "
                    f"document, but deleting its stored ciphertext failed: "
                    f"{exc}. It is no longer searchable; retry this "
                    f"request to finish removing it."
                )
            }), 502

        audit("delete", target=doc_id)
        return jsonify({"doc_id": doc_id, "status": "deleted"}), 200

    # -- search --------------------------------------------------------------

    @app.post("/api/search")
    @vault_user
    def api_search():
        """Conjunctive (AND) search: a query normalises to one or more
        keywords (client/search.py's normalise_conjunctive_query), and
        a matching document must contain every one of them.

        Each keyword is answered as its own completely independent,
        unchanged Pi_bas search -- its own K1 token, its own cloud
        round trip, its own decrypt -- and the N resulting doc_id sets
        are intersected HERE, on the trusted client, after every one of
        them has already been decrypted. The cloud is never asked to
        compute, or told about, the intersection itself.

        Queried in sorted order purely for determinism (AND has no
        inherent order). A keyword whose own result set is already
        empty stops the loop immediately -- the intersection can only
        be empty from that point on -- which is a pure efficiency
        choice, not an extra leak: the cloud already learns that
        keyword's own (zero) result count from its own search
        regardless of whether the remaining keywords are ever sent.
        See client/search.py's module docstring for what this DOES add
        to the leakage profile: the cloud learns that these N tokens
        were submitted together as one logical request.
        """
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401

        body = request.get_json(silent=True) or {}
        query = body.get("query")
        if not isinstance(query, str):
            return jsonify({"error": "query must be a string"}), 400

        try:
            keywords = normalise_conjunctive_query(query)
        except AmbiguousQueryError as exc:
            return jsonify({"error": str(exc)}), 400

        # `steps` records, per keyword, exactly what crossed the trust
        # boundary -- for the search demonstration view. The keyword
        # itself is only ever shown to its own (trusted) user's browser;
        # the cloud request body is literally {"k1": <token>}.
        steps = []
        doc_ids = None
        for keyword in sorted(keywords):
            token = build_search_token(keys.k_index, keyword)
            try:
                encrypted_values = cloud_client.run_remote_search(token)
            except CloudUnavailableError as exc:
                return jsonify({"error": str(exc)}), 502

            try:
                keyword_doc_ids = decrypt_search_results(keys.k_index, keyword, encrypted_values)
            except DecryptionError:
                audit("decryption_failed", outcome="failure", detail="search: index value failed AES-GCM check")
                return jsonify(
                    {"error": "one or more search results failed to decrypt -- possible tampering or corruption"}
                ), 422

            steps.append({
                "keyword": keyword,
                "token_hex": token.hex(),
                "cloud_request": {"method": "POST", "path": "/search", "body": {"k1": _b64(token)}},
                "cloud_result_count": len(encrypted_values),
                "encrypted_results": [
                    {"hex": v.hex()[:96], "bytes": len(v)} for v in encrypted_values[:10]
                ],
                "decrypted_doc_ids": sorted(keyword_doc_ids),
            })

            doc_ids = keyword_doc_ids if doc_ids is None else (doc_ids & keyword_doc_ids)
            if not doc_ids:
                break  # intersection with anything else is still empty

        results = []
        for doc_id in sorted(doc_ids or ()):
            doc = cloud_client.fetch_document(doc_id)
            filename = doc_id
            if doc is not None:
                filename = _decrypt_filename(keys, doc["enc_name"])
            results.append({"doc_id": doc_id, "filename": filename})

        # Logged without the query: only its shape and outcome.
        audit("search", detail=f"{len(keywords)} keyword(s), {len(results)} result(s)")
        return jsonify({
            "query": query,
            "keywords": sorted(keywords),
            "results": results,
            "trace": {
                "steps": steps,
                "keywords_not_sent": len(keywords) - len(steps),
                "intersection": sorted(doc_ids or ()),
            },
        }), 200

    # -- dashboard / activity ------------------------------------------------

    @app.get("/api/dashboard")
    @vault_user
    def api_dashboard():
        """Real numbers only: storage figures come from the cloud's own
        /stats for this vault; activity figures from the audit log. File
        names need the vault unlocked (they are decrypted here)."""
        keys = _require_unlocked()
        stats = cloud_client.vault_stats()
        recent = []
        if keys is not None:
            docs = sorted(cloud_client.list_documents(), key=lambda d: d["uploaded_at"], reverse=True)
            recent = [
                {
                    "doc_id": d["doc_id"],
                    "filename": _decrypt_filename(keys, d["enc_name"]),
                    "size": d["size"],
                    "uploaded_at": d["uploaded_at"],
                }
                for d in docs[:5]
            ]
        counts = accounts.event_counts(actor_id=g.user.id)
        return jsonify({
            "unlocked": keys is not None,
            "vault_initialized": "kdf_salt" in stats["meta_keys"],
            "storage": stats,
            "recent_uploads": recent,
            "counts": {
                "uploads": counts.get("upload:success", 0),
                "downloads": counts.get("download:success", 0),
                "views": counts.get("view:success", 0),
                "searches": counts.get("search:success", 0),
                "deletes": counts.get("delete:success", 0),
                "tamper_demos": counts.get("tamper_demo", 0),
                "decryption_failures": counts.get("decryption_failed", 0),
                "unlock_failures": counts.get("vault_unlock_failed", 0),
                "login_failures": counts.get("login_failed", 0),
            },
            "recent_activity": accounts.list_events(actor_id=g.user.id, limit=8),
            "security_events": accounts.list_events(actor_id=g.user.id, security_only=True, limit=5),
        })

    @app.get("/api/activity")
    @login_required()
    def api_activity():
        try:
            limit = int(request.args.get("limit", 100))
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400
        return jsonify({"events": accounts.list_events(actor_id=g.user.id, limit=limit)})

    # -- encryption transparency -----------------------------------------------

    @app.get("/api/transparency/<doc_id>")
    @vault_user
    def api_transparency(doc_id: str):
        """Side-by-side view of ONE document: what the authorized user
        sees after decryption here, next to the exact record the cloud
        API returns for it. The right-hand side is built only from the
        cloud's own GET /documents/<id> response -- nothing is
        re-encrypted or synthesised for display."""
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401
        raw = cloud_client.fetch_document_raw(doc_id)
        if raw is None:
            return jsonify({"error": "not found"}), 404

        cloud_view = _cloud_record_view(raw)
        enc_name = base64.b64decode(raw["enc_name"])
        nonce = base64.b64decode(raw["nonce"])
        ciphertext = base64.b64decode(raw["ciphertext"])
        tag = base64.b64decode(raw["tag"])
        try:
            filename_bytes = aes_gcm_decrypt(keys.k_file, enc_name)
            content = aes_gcm_decrypt(keys.k_file, nonce + ciphertext + tag)
        except DecryptionError:
            audit("decryption_failed", outcome="failure", target=doc_id, detail="transparency: AES-GCM tag check failed")
            return jsonify({"error": "decryption failed -- the stored ciphertext or tag does not verify"}), 422

        kind = _content_kind(content)
        text_preview = None
        if kind == "text":
            decoded = content.decode("utf-8")
            text_preview = decoded[:_PREVIEW_TEXT_CHARS]
        probe = content[:32]
        audit("transparency_view", target=doc_id)
        return jsonify({
            "doc_id": doc_id,
            "client": {
                "filename": filename_bytes.decode("utf-8", "replace"),
                "filename_bytes": len(filename_bytes),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "kind": kind,
                "text_preview": text_preview,
                "text_truncated": kind == "text" and len(text_preview) < len(content.decode("utf-8")),
                "plaintext_hex": content[:64].hex(),
            },
            "cloud": cloud_view,
            "cloud_raw_response": _raw_response_preview(raw),
            "comparison": {
                "plaintext_bytes": len(content),
                "ciphertext_bytes": len(ciphertext),
                "stored_blob_bytes": len(nonce) + len(ciphertext) + len(tag),
                "overhead_bytes": len(nonce) + len(tag),
                "filename_plaintext_bytes": len(filename_bytes),
                "filename_blob_bytes": len(enc_name),
                "plaintext_prefix_found_in_ciphertext": bool(probe) and probe in ciphertext,
                "tag_verified": True,
            },
        })

    # -- cloud storage inspector -------------------------------------------------

    def _inspect_current_vault(doc_limit=_INSPECTOR_DOC_LIMIT, index_limit=_INSPECTOR_INDEX_LIMIT):
        """Everything here comes from the cloud API for the vault in
        scope -- the same bytes a curious cloud operator holds. No
        decryption happens anywhere in this function."""
        stats = cloud_client.vault_stats()
        listing = cloud_client.list_documents()
        records = []
        for meta in listing[:doc_limit]:
            raw = cloud_client.fetch_document_raw(meta["doc_id"])
            if raw is not None:
                records.append(_cloud_record_view(raw))
        index_page = cloud_client.list_index_entries(limit=index_limit)
        return {
            "stats": stats,
            "documents": records,
            "documents_total": len(listing),
            "index": {
                "total": index_page["total"],
                "entries": [
                    {"label": e["label"], "value_hex": e["value"].hex(), "value_bytes": len(e["value"])}
                    for e in index_page["entries"]
                ],
            },
        }

    @app.get("/api/inspector")
    @vault_user
    def api_inspector():
        """The user's own vault as the CLOUD sees it. Works while the
        vault is locked -- that is the point: none of it needs a key."""
        audit("cloud_inspector_view")
        return jsonify(_inspect_current_vault())

    # -- tamper-detection demonstration --------------------------------------------

    @app.post("/api/tamper-demo")
    @vault_user
    def api_tamper_demo():
        """Flip ONE bit in an in-memory COPY of an encrypted blob and try
        to decrypt it with the real AES-GCM code path. Nothing is ever
        written back: the stored record is re-fetched afterwards and its
        hash compared, to prove the original is untouched."""
        keys = _require_unlocked()
        if keys is None:
            return jsonify({"error": "vault is locked"}), 401
        body = request.get_json(silent=True) or {}
        doc_id = body.get("doc_id")
        region = body.get("region", "ciphertext")
        if region not in ("nonce", "ciphertext", "tag"):
            return jsonify({"error": "region must be one of: nonce, ciphertext, tag"}), 400

        if doc_id:
            if not isinstance(doc_id, str):
                return jsonify({"error": "doc_id must be a string"}), 400
            doc = cloud_client.fetch_document(doc_id)
            if doc is None:
                return jsonify({"error": "not found"}), 404
            blob = doc["nonce"] + doc["ciphertext"] + doc["tag"]
            source = "stored document (a disposable in-memory copy of its cloud record)"
        else:
            sample = b"Tamper-detection sample: this text was encrypted in memory and is never stored."
            blob = aes_gcm_encrypt(keys.k_file, sample)
            source = "temporary sample encrypted in memory (never stored)"

        bounds = {
            "nonce": (0, NONCE_SIZE),
            "ciphertext": (NONCE_SIZE, len(blob) - TAG_SIZE),
            "tag": (len(blob) - TAG_SIZE, len(blob)),
        }
        start, end = bounds[region]
        if end <= start:
            return jsonify({"error": "this file has an empty ciphertext body -- choose the nonce or tag region"}), 400
        offset = body.get("offset")
        if offset is None:
            offset = secrets.randbelow(end - start)
        if not isinstance(offset, int) or not 0 <= offset < end - start:
            return jsonify({"error": f"offset must be an integer in [0, {end - start - 1}] for this region"}), 400
        bit = body.get("bit")
        if bit is None:
            bit = secrets.randbelow(8)
        if not isinstance(bit, int) or not 0 <= bit <= 7:
            return jsonify({"error": "bit must be an integer 0-7"}), 400

        original_sha = hashlib.sha256(blob).hexdigest()
        try:
            baseline = aes_gcm_decrypt(keys.k_file, blob)
            baseline_result = {"ok": True, "plaintext_bytes": len(baseline)}
        except DecryptionError as exc:
            baseline_result = {"ok": False, "error": str(exc)}

        position = start + offset
        modified = bytearray(blob)  # the disposable copy
        modified[position] ^= 1 << bit
        try:
            aes_gcm_decrypt(keys.k_file, bytes(modified))
            tampered_result = {"rejected": False}
        except DecryptionError as exc:
            tampered_result = {
                "rejected": True,
                "exception": type(exc).__name__,
                "underlying": type(exc.__cause__).__name__ if exc.__cause__ else None,
                "message": str(exc),
            }

        lo, hi = max(0, position - 8), min(len(blob), position + 8)
        original_still_stored = None
        if doc_id:
            after = cloud_client.fetch_document(doc_id)
            after_blob = after["nonce"] + after["ciphertext"] + after["tag"] if after else b""
            original_still_stored = hashlib.sha256(after_blob).hexdigest() == original_sha

        audit(
            "tamper_demo",
            outcome="rejected" if tampered_result["rejected"] else "ACCEPTED",
            target=doc_id or "sample",
            detail=f"bit {bit} flipped in {region} byte {offset}",
            is_demo=True,
        )
        return jsonify({
            "source": source,
            "doc_id": doc_id,
            "region": region,
            "region_bounds": [start, end],
            "blob_bytes": len(blob),
            "position": position,
            "offset_in_region": offset,
            "bit": bit,
            "window_start": lo,
            "original_window_hex": blob[lo:hi].hex(),
            "modified_window_hex": bytes(modified[lo:hi]).hex(),
            "original_byte": f"{blob[position]:08b}",
            "modified_byte": f"{modified[position]:08b}",
            "original_sha256": original_sha,
            "modified_sha256": hashlib.sha256(bytes(modified)).hexdigest(),
            "baseline_decrypt": baseline_result,
            "tampered_decrypt": tampered_result,
            "original_unchanged_in_cloud": original_still_stored,
        })

    # -- legacy single-vault migration -----------------------------------------------

    @app.get("/api/vault/legacy")
    @vault_user
    def api_legacy_status():
        """Whether a pre-multi-user vault exists that this (still empty,
        never-initialised) vault could adopt."""
        stats = cloud_client.vault_stats()
        eligible = stats["documents"] == 0 and not stats["meta_keys"] and stats["index_entries"] == 0
        if not eligible:
            return jsonify({"available": False})
        legacy = cloud_client.legacy_kdf()
        available = legacy["kdf_salt"] is not None and legacy["kdf_verifier"] is not None
        return jsonify({"available": available, "documents": legacy["documents"] if available else 0})

    @app.post("/api/vault/adopt-legacy")
    @vault_user
    def api_adopt_legacy():
        """Moves the legacy single-user vault into this user's namespace,
        after proving knowledge of its passphrase against the legacy
        verifier. Nothing is decrypted or re-encrypted: rows are only
        re-labelled, so the legacy passphrase becomes this vault's."""
        body = request.get_json(silent=True) or {}
        password = body.get("password")
        if not isinstance(password, str) or password == "":
            return jsonify({"error": "password must be a non-empty string"}), 400
        legacy = cloud_client.legacy_kdf()
        if legacy["kdf_salt"] is None or legacy["kdf_verifier"] is None:
            return jsonify({"error": "no legacy vault is available to migrate"}), 404
        try:
            candidate = derive_keys(password, legacy["kdf_salt"])
            aes_gcm_decrypt(candidate.k_index, legacy["kdf_verifier"])
        except (ValueError, DecryptionError):
            audit("legacy_vault_adopted", outcome="failure", detail="incorrect legacy passphrase")
            return jsonify({"error": "incorrect legacy vault passphrase"}), 401
        candidate.wipe()
        try:
            moved = cloud_client.adopt_legacy_vault()["moved"]
        except CloudError as exc:
            if exc.status_code == 409:
                return jsonify({"error": "your vault is not empty -- legacy data can only move into a new vault"}), 409
            raise
        audit("legacy_vault_adopted", detail=f"{moved.get('documents', 0)} document(s) moved")
        return jsonify({"status": "adopted", "moved": moved}), 200

    # -- administration (no keys, no plaintext) ----------------------------------------

    def _vault_users():
        return [u for u in accounts.list_users() if u.role == ROLE_USER and u.vault_id and u.cloud_token]

    @app.get("/api/admin/overview")
    @admin_only
    def api_admin_overview():
        users = accounts.list_users()
        totals = {"documents": 0, "ciphertext_bytes": 0, "enc_name_bytes": 0, "index_entries": 0}
        cloud_ok = True
        try:
            for u in _vault_users():
                with cloud_client.vault_scope(u.vault_id, u.cloud_token):
                    st = cloud_client.vault_stats()
                for k in totals:
                    totals[k] += st[k]
        except CloudUnavailableError:
            cloud_ok = False
        counts = accounts.event_counts()
        return jsonify({
            "cloud_reachable": cloud_ok,
            "accounts": {
                "total": len(users),
                "users": sum(1 for u in users if u.role == ROLE_USER),
                "admins": sum(1 for u in users if u.role == ROLE_ADMIN),
                "inactive": sum(1 for u in users if not u.is_active),
            },
            "sessions": {"active": sessions.active_count(), "unlocked_vaults": len(sessions.unlocked_sessions())},
            "storage": totals,
            "events": {
                "uploads": counts.get("upload:success", 0),
                "downloads": counts.get("download:success", 0),
                "searches": counts.get("search:success", 0),
                "deletes": counts.get("delete:success", 0),
                "logins": counts.get("login:success", 0),
                "login_failures": counts.get("login_failed", 0),
                "throttled_logins": counts.get("login_throttled", 0),
                "unlock_failures": counts.get("vault_unlock_failed", 0),
                "decryption_failures": counts.get("decryption_failed", 0),
                "tamper_rejected": counts.get("tamper_demo:rejected", 0),
                "tamper_accepted": counts.get("tamper_demo:ACCEPTED", 0),
                "access_denied": counts.get("access_denied", 0),
            },
            "recent_security_events": accounts.list_events(security_only=True, limit=10),
        })

    @app.get("/api/admin/users")
    @admin_only
    def api_admin_users():
        out = []
        for u in accounts.list_users():
            entry = {**u.public(), "has_vault": bool(u.vault_id)}
            if u.role == ROLE_USER and u.vault_id and u.cloud_token:
                entry["vault_id"] = u.vault_id
                try:
                    with cloud_client.vault_scope(u.vault_id, u.cloud_token):
                        st = cloud_client.vault_stats()
                    entry["storage"] = {k: st[k] for k in ("documents", "ciphertext_bytes", "index_entries", "last_upload_at")}
                    entry["vault_initialized"] = "kdf_salt" in st["meta_keys"]
                except CloudUnavailableError:
                    entry["storage"] = None
            out.append(entry)
        return jsonify({"users": out})

    @app.post("/api/admin/users/<int:user_id>/status")
    @admin_only
    def api_admin_set_status(user_id: int):
        body = request.get_json(silent=True) or {}
        active = body.get("active")
        if not isinstance(active, bool):
            return jsonify({"error": "'active' must be true or false"}), 400
        target = accounts.get_user(user_id)
        if target is None:
            return jsonify({"error": "no such user"}), 404
        if target.id == g.user.id:
            return jsonify({"error": "you cannot change the status of your own account"}), 400
        if not active and target.role == ROLE_ADMIN and target.is_active and accounts.active_admin_count() <= 1:
            return jsonify({"error": "cannot deactivate the last active administrator"}), 400
        accounts.set_active(user_id, active)
        ended = 0 if active else sessions.revoke_user(user_id)  # locks their vault too
        audit(
            "account_status_changed", target=target.username,
            detail=f"{'activated' if active else 'deactivated'}; {ended} session(s) ended",
        )
        return jsonify({"user": accounts.get_user(user_id).public(), "sessions_ended": ended})

    @app.get("/api/admin/audit")
    @admin_only
    def api_admin_audit():
        try:
            limit = int(request.args.get("limit", 200))
        except ValueError:
            return jsonify({"error": "limit must be an integer"}), 400
        event_type = request.args.get("event_type") or None
        security_only = request.args.get("security_only") == "1"
        return jsonify({"events": accounts.list_events(event_type=event_type, security_only=security_only, limit=limit)})

    @app.get("/api/admin/inspector")
    @admin_only
    def api_admin_inspector():
        """Cloud-side records of one user's vault, fetched through the
        cloud API with that vault's access token. The administrator gets
        ciphertext and non-secret metadata only: this process holds no
        key for any vault it is not unlocked into, and admins never are."""
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"vaults": [
                {"user_id": u.id, "username": u.username, "vault_id": u.vault_id} for u in _vault_users()
            ]})
        try:
            target = accounts.get_user(int(user_id))
        except ValueError:
            return jsonify({"error": "user_id must be an integer"}), 400
        if target is None or target.role != ROLE_USER or not target.vault_id:
            return jsonify({"error": "no such user vault"}), 404
        with cloud_client.vault_scope(target.vault_id, target.cloud_token):
            view = _inspect_current_vault()
        audit("cloud_inspector_view", target=target.username, detail="admin inspection (ciphertext only)")
        return jsonify({"user_id": target.id, "username": target.username, "vault_id": target.vault_id, **view})

    # -- system information ---------------------------------------------------------------

    @app.get("/api/system")
    @login_required()
    def api_system():
        try:
            cloud_client.set_vault_scope(None)
            cloud = cloud_client.health()
            cloud_ok = cloud.get("status") == "ok"
        except (CloudUnavailableError, CloudError):
            cloud_ok = False
        return jsonify({
            "cloud_reachable": cloud_ok,
            "crypto": {
                "aead": "AES-256-GCM",
                "key_bytes": KEY_SIZE,
                "nonce_bytes": NONCE_SIZE,
                "tag_bytes": TAG_SIZE,
                "vault_kdf": "Argon2id",
                "vault_kdf_params": {
                    "time_cost": ARGON2_TIME_COST,
                    "memory_kib": ARGON2_MEMORY_COST_KIB,
                    "parallelism": ARGON2_PARALLELISM,
                },
                "subkey_kdf": "HKDF-SHA256",
                "prf": "HMAC-SHA256",
                "account_password_hash": "Argon2id (argon2-cffi PasswordHasher)",
            },
            "session": {
                "idle_timeout_seconds": app.config["SESSION_IDLE_SECONDS"],
                "absolute_timeout_seconds": app.config["SESSION_ABSOLUTE_SECONDS"],
                "cookie": "HttpOnly; SameSite=Strict" + ("; Secure" if app.config["SESSION_COOKIE_SECURE_FLAG"] else ""),
                "csrf": f"per-session token in the {CSRF_HEADER} header",
            },
        })

    return app


def _print_admin_setup_banner(app: Flask) -> None:
    accounts = app.extensions["vault_accounts"]
    if accounts.admin_exists():
        return
    print(
        "\n" + "=" * 70 + "\n"
        "  No administrator account exists yet.\n"
        "  Open the web UI, choose 'First-time admin setup', and enter this\n"
        f"  one-time setup token:   {app.config['ADMIN_SETUP_TOKEN']}\n"
        "  (Set ADMIN_SETUP_TOKEN to choose it yourself. It stops working\n"
        "  as soon as the first administrator has been created.)\n"
        + "=" * 70 + "\n",
        flush=True,
    )


if __name__ == "__main__":
    # Runs the trusted client on its own port, deliberately different
    # from the cloud (Section 02's "why two processes matters for
    # marks" -- start cloud/cloud_app.py separately, on its own port,
    # to keep the process boundary genuine for the demo).
    # CLIENT_PORT override: on macOS 12+, port 5000 is taken by the
    # AirPlay Receiver, so run with e.g. CLIENT_PORT=5050 there.
    logging.basicConfig(level=logging.INFO)
    application = create_app()
    _print_admin_setup_banner(application)
    application.run(port=int(os.environ.get("CLIENT_PORT", "5000")), debug=False)
