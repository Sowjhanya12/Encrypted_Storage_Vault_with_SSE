"""
client/accounts.py -- user accounts, roles, sessions, and the audit log
for the trusted client (multi-user extension).

Two credentials, deliberately kept apart:

  * ACCOUNT password -- proves who you are to THIS trusted client. Stored
    only as an Argon2id password hash (argon2-cffi's PasswordHasher, which
    embeds its own random salt and cost parameters in the hash string).
    It never derives a key and never reaches the cloud.
  * VAULT passphrase -- unchanged from the original design (keymgmt.py):
    Argon2id(passphrase, per-vault salt) -> master key -> HKDF -> K_file,
    K_index. Entered on "Unlock vault", after login. The resulting KeySet
    lives only in this process's memory, attached to one server-side
    session, and is wiped on lock, logout, or session expiry.

So a stolen accounts database yields password hashes and cloud access
tokens (enough to read *ciphertext*), but no vault key: those depend on
a passphrase that is never stored anywhere.

Everything here lives in a local SQLite file on the TRUSTED side
(ACCOUNTS_DB_PATH, default client_accounts.sqlite3). The cloud never sees
usernames, roles, account passwords, or the audit log -- it only knows
each user's opaque vault_id.

Audit log rules: events record WHO did WHAT to WHICH opaque id, and the
outcome. They never record a password, key, plaintext content, plaintext
filename, or search keyword (a search event records only how many
keywords and results there were).
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

ROLE_USER = "user"
ROLE_ADMIN = "admin"
ROLES = (ROLE_USER, ROLE_ADMIN)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 1024

# Brute-force throttle: this many failed logins for one username inside
# the window locks further attempts for that username until it passes.
LOGIN_FAILURE_LIMIT = 5
LOGIN_FAILURE_WINDOW_SECONDS = 15 * 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    is_active     INTEGER NOT NULL DEFAULT 1,
    vault_id      TEXT UNIQUE,
    cloud_token   BLOB,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    actor_id       INTEGER,
    actor_username TEXT,
    event_type     TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    target         TEXT,
    detail         TEXT,
    is_demo        INTEGER NOT NULL DEFAULT 0,
    ip             TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events (actor_id, id);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events (event_type, id);
"""

# Event types that count as security-relevant for dashboards.
SECURITY_EVENT_TYPES = (
    "login_failed",
    "login_throttled",
    "vault_unlock_failed",
    "decryption_failed",
    "tamper_demo",
    "access_denied",
    "account_status_changed",
    "session_expired",
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AccountError(ValueError):
    """Invalid input for an account operation (shown to the caller)."""


class DuplicateUserError(AccountError):
    pass


@dataclass
class User:
    id: int
    username: str
    role: str
    is_active: bool
    vault_id: Optional[str]
    cloud_token: Optional[bytes]
    created_at: str
    last_login_at: Optional[str]

    def public(self) -> dict:
        """Fields safe to show in the UI (no hash, no token)."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
        }


def _row_to_user(row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        role=row["role"],
        is_active=bool(row["is_active"]),
        vault_id=row["vault_id"],
        cloud_token=row["cloud_token"],
        created_at=row["created_at"],
        last_login_at=row["last_login_at"],
    )


def validate_username(username) -> str:
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        raise AccountError("username must be 3-32 characters: letters, digits, '.', '_' or '-'")
    return username


def validate_password(password) -> str:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AccountError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    return password


class AccountStore:
    """All account + audit persistence. Every query is parameterised."""

    def __init__(self, db_path: str, hasher: Optional[PasswordHasher] = None):
        self.db_path = db_path
        self.hasher = hasher or PasswordHasher()  # Argon2id, library defaults
        # A real hash to verify against when the username does not exist,
        # so "no such user" and "wrong password" take comparable time.
        self._dummy_hash = self.hasher.hash(secrets.token_hex(16))
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # -- users ---------------------------------------------------------------

    def create_user(
        self,
        username: str,
        password: str,
        role: str = ROLE_USER,
        vault_id: Optional[str] = None,
        cloud_token: Optional[bytes] = None,
    ) -> User:
        validate_username(username)
        validate_password(password)
        if role not in ROLES:
            raise AccountError("invalid role")
        password_hash = self.hasher.hash(password)
        try:
            with self._conn() as conn:
                cur = conn.execute(
                    "INSERT INTO users (username, password_hash, role, vault_id, cloud_token, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (username, password_hash, role, vault_id, cloud_token, _now()),
                )
                user_id = cur.lastrowid
        except sqlite3.IntegrityError as exc:
            raise DuplicateUserError("that username is already taken") from exc
        return self.get_user(user_id)

    def username_exists(self, username: str) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        return row is not None

    def get_user(self, user_id: int) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> Optional[User]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return _row_to_user(row) if row else None

    def list_users(self) -> List[User]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        return [_row_to_user(r) for r in rows]

    def admin_exists(self) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").fetchone()
        return row is not None

    def active_admin_count(self) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()[0]

    def set_active(self, user_id: int, active: bool) -> bool:
        with self._conn() as conn:
            cur = conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))
        return cur.rowcount > 0

    def verify_password(self, username: str, password: str) -> Optional[User]:
        """Returns the user if (username, password) is correct, else
        None. Does NOT check is_active -- the caller reports a disabled
        account separately, and only after the password was right, so a
        guesser cannot use that message to probe which accounts exist."""
        user = self.get_user_by_username(username) if isinstance(username, str) else None
        stored_hash = None
        if user is not None:
            with self._conn() as conn:
                stored_hash = conn.execute(
                    "SELECT password_hash FROM users WHERE id = ?", (user.id,)
                ).fetchone()[0]
        try:
            self.hasher.verify(stored_hash or self._dummy_hash, password if isinstance(password, str) else "")
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return None
        if user is None:
            return None
        if self.hasher.check_needs_rehash(stored_hash):
            with self._conn() as conn:
                conn.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?", (self.hasher.hash(password), user.id)
                )
        return user

    def record_login(self, user_id: int) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (_now(), user_id))

    # -- audit -----------------------------------------------------------------

    def log_event(
        self,
        event_type: str,
        outcome: str = "success",
        actor: Optional[User] = None,
        actor_id: Optional[int] = None,
        actor_username: Optional[str] = None,
        target: Optional[str] = None,
        detail: Optional[str] = None,
        is_demo: bool = False,
        ip: Optional[str] = None,
    ) -> None:
        if actor is not None:
            actor_id, actor_username = actor.id, actor.username
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO audit_events (ts, actor_id, actor_username, event_type, outcome, target, detail, is_demo, ip) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_now(), actor_id, actor_username, event_type, outcome, target, detail, 1 if is_demo else 0, ip),
            )

    def list_events(
        self,
        actor_id: Optional[int] = None,
        event_type: Optional[str] = None,
        security_only: bool = False,
        limit: int = 100,
    ) -> List[dict]:
        clauses, params = [], []
        if actor_id is not None:
            clauses.append("actor_id = ?")
            params.append(actor_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if security_only:
            clauses.append(f"event_type IN ({','.join('?' * len(SECURITY_EVENT_TYPES))})")
            params.extend(SECURITY_EVENT_TYPES)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 1000)))
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events {where} ORDER BY id DESC LIMIT ?", params
            ).fetchall()
        return [
            {**dict(r), "is_demo": bool(r["is_demo"])}
            for r in rows
        ]

    def event_counts(self, actor_id: Optional[int] = None) -> Dict[str, int]:
        """{event_type:outcome -> count} plus {event_type -> count}."""
        where, params = ("WHERE actor_id = ?", [actor_id]) if actor_id is not None else ("", [])
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT event_type, outcome, COUNT(*) AS n FROM audit_events {where} "
                f"GROUP BY event_type, outcome",
                params,
            ).fetchall()
        counts: Dict[str, int] = {}
        for r in rows:
            counts[f"{r['event_type']}:{r['outcome']}"] = r["n"]
            counts[r["event_type"]] = counts.get(r["event_type"], 0) + r["n"]
        return counts

    def recent_failed_logins(self, username: str, window_seconds: int = LOGIN_FAILURE_WINDOW_SECONDS) -> int:
        since = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'login_failed' "
                "AND actor_username = ? COLLATE NOCASE AND ts >= ?",
                (username, since),
            ).fetchone()[0]


# ---------------------------------------------------------------------------
# server-side sessions
# ---------------------------------------------------------------------------

@dataclass
class Session:
    sid: str
    user_id: int
    role: str
    csrf_token: str
    created_at: float
    last_seen: float
    keys: object = None  # keymgmt.KeySet while the vault is unlocked
    expired_reason: Optional[str] = field(default=None)

    def lock(self) -> None:
        if self.keys is not None:
            self.keys.wipe()
        self.keys = None


class SessionStore:
    """In-memory, server-side session table. The browser's cookie holds
    only a random session id; the user id, role, CSRF token and -- while
    unlocked -- the vault KeySet stay in this process. Nothing secret is
    ever serialised into a cookie (Flask's default session would be a
    client-readable signed cookie, which is why it is not used here)."""

    def __init__(self, idle_timeout: int, absolute_timeout: int):
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, user_id: int, role: str) -> Session:
        now = time.monotonic()
        session = Session(
            sid=secrets.token_urlsafe(32),
            user_id=user_id,
            role=role,
            csrf_token=secrets.token_urlsafe(32),
            created_at=now,
            last_seen=now,
        )
        with self._lock:
            self._sessions[session.sid] = session
        return session

    def get(self, sid: Optional[str]):
        """Returns (session, None) for a live session, (None, reason) if
        it just expired, (None, None) if unknown. Touches last_seen."""
        if not sid:
            return None, None
        now = time.monotonic()
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None, None
            reason = None
            if now - session.last_seen > self.idle_timeout:
                reason = "idle timeout"
            elif now - session.created_at > self.absolute_timeout:
                reason = "maximum session lifetime reached"
            if reason:
                session.lock()
                del self._sessions[sid]
                session.expired_reason = reason
                return None, (reason, session)
            session.last_seen = now
            return session, None

    def destroy(self, sid: Optional[str]) -> None:
        with self._lock:
            session = self._sessions.pop(sid, None) if sid else None
        if session is not None:
            session.lock()

    def revoke_user(self, user_id: int) -> int:
        """End every session of one user (e.g. account deactivated)."""
        with self._lock:
            doomed = [s for s in self._sessions.values() if s.user_id == user_id]
            for s in doomed:
                del self._sessions[s.sid]
        for s in doomed:
            s.lock()
        return len(doomed)

    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def unlocked_sessions(self) -> List[Session]:
        with self._lock:
            return [s for s in self._sessions.values() if s.keys is not None]


def new_vault_credentials():
    """A fresh opaque vault id + cloud access token for a new user.
    Both random; neither is derived from any password or key."""
    return os.urandom(16).hex(), os.urandom(32)
