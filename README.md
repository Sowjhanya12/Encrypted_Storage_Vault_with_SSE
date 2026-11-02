# Encrypted Cloud Vault — Searchable Symmetric Encryption

A two-process encrypted cloud storage system: a **trusted client** that encrypts everything, and an **untrusted cloud** that stores only ciphertext and runs encrypted keyword search.

| Process | Command | Port | Role |
|---|---|---|---|
| Untrusted cloud | `python3 -m cloud.cloud_app` | **5001** | Stores ciphertext, encrypted index, non-secret metadata. Never sees a key, filename, keyword or plaintext. |
| Trusted client + web UI | `python3 -m client.client_app` | **5000** (use **5050** on macOS) | Accounts, sessions, all cryptography, serves the browser UI. |

Crypto: AES-256-GCM (files + filenames + index values), Argon2id (vault passphrase → master key), HKDF-SHA256 (→ `K_file`, `K_index`), HMAC-SHA256 (search tokens / index labels).

---

## 1. Setup (once)

Requires Python 3.9+.

```bash
cd "Encrypted Vault SSE"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # cryptography, argon2-cffi, flask, requests, pypdf, pytest
```

## 2. Start the two services (two terminals, venv active in both)

**Terminal 1 — cloud (port 5001):**
```bash
python3 -m cloud.cloud_app
```

**Terminal 2 — trusted client:**
```bash
CLIENT_PORT=5050 python3 -m client.client_app      # macOS (port 5000 is taken by AirPlay Receiver)
# python3 -m client.client_app                     # elsewhere: port 5000
```

Open **http://127.0.0.1:5050** (or :5000). The same URL serves both the user and the administrator interface; the role you log in with decides which navigation you get, and the server enforces it.

On first start the client terminal prints a box like:

```
  No administrator account exists yet.
  ...one-time setup token:   ocv7zSRKUAOupCrT196EMizU
```

Data files (all git-ignored): `vault.sqlite3` (cloud), `client_accounts.sqlite3` (accounts + audit log, trusted side).

## 3. First-time setup

1. **Administrator (one-time):** on the login page open **Admin setup**, paste the setup token from the client terminal, and choose the admin username and password. The tab disappears once an admin exists; there is no default admin account. To choose the token yourself, start the client with `ADMIN_SETUP_TOKEN=...`.
2. **Users:** **Create account** → username + account password (min. 8 characters). Each user gets a private, empty cloud vault.
3. **Vault unlock:** after login, the first unlock asks you to **choose a vault passphrase**. It is separate from the account password and is never stored. Later logins require *Unlock vault* with the same passphrase.
4. **Existing pre-multi-user data:** your old single-user vault is preserved as the "legacy" vault. A new user whose vault is still empty sees **Migrate the pre-multi-user vault** on the unlock screen. Entering the old vault password moves it into that account (rows are re-labelled, not re-encrypted). After that, unlock with the old password.

## 4. Demonstration script (≈10 minutes)

Prepare a small `.txt` file containing, e.g., `Quarterly zephyrion budget review. The merger plan is confidential.`

1. **Two processes.** Show both terminals. Cloud = port 5001, client = 5050. Optionally `curl http://127.0.0.1:5001/health`.
2. **Register `alice`**, choose a vault passphrase (note the deliberate Argon2id delay), land on the **Dashboard**. It shows identity, access scope and real counts.
3. **Upload** the text file: the progress stages show *browser → trusted client → AES-GCM → cloud + index rebuild*.
4. **Encryption Transparency Lab** (or *Lab* on the file row): left = filename + plaintext in the trusted client; right = the exact `nonce` / `ciphertext` / `tag` columns and encrypted-filename blob the cloud API returned, plus the raw JSON. Point out: ciphertext bytes = plaintext bytes, +28 bytes overhead (12 nonce + 16 tag), and no plaintext prefix in the ciphertext. Key names are shown, never key bytes.
5. **Cloud Storage Inspector:** the vault exactly as the cloud stores it (random doc ids, encrypted names, HMAC index labels). Click **Lock vault** and reopen it: it still works, because no key is involved.
6. **Unlock → Search** `zephyrion merger`: walk the 7 steps (keywords → HMAC token → literal `POST /search {"k1": …}` → cloud loop → encrypted results → client decryption → filenames). Read the *honest leakage* box.
7. **Tamper detection test** (Lab → second tab): pick the file, region *ciphertext*, click **Flip one bit**. Expected: unmodified copy ✓ decrypts, modified copy ⛔ rejected (`DecryptionError ← InvalidTag`), stored original ✓ unchanged (SHA-256 re-checked from the cloud).
8. **Isolation:** log out, register `bob`, unlock. Bob's files, search and inspector show nothing of Alice's (her doc ids return 404 for him; the cloud also refuses his token for her vault).
9. **Administrator:** log out, log in as the admin. **Admin Dashboard** (real counts, tamper tests, failed logins), **Accounts** (deactivate Bob → his session ends immediately), **Audit Log** (filter *security events only*; demo events are tagged), **Cloud Storage Inspector** (Alice's vault: ciphertext only — the admin has no key and cannot open her files).
10. **Security & System:** key hierarchy, parameters, and the "who can see what" table.

## 5. Tests

```bash
python3 -m pytest                    # main suite: tests/
python3 -m pytest benchmarks/tests   # benchmark-harness tests
```

`tests/test_multiuser_security.py` covers registration and login, invalid credentials, throttling, session expiry, logout, CSRF, RBAC, admin bootstrap, cross-user isolation (app and cloud level), the admin no-plaintext guarantee, transparency, inspector, search trace, tamper demo, schema migration, legacy adoption, and error handling. `pytest` also regenerates `docs/security_demo_report.html`.

## 6. Security model (what is and is not claimed)

- **Account auth ≠ vault keys.** Account passwords are stored only as Argon2id password hashes. Vault keys come from a separate passphrase via Argon2id + HKDF, are held in memory for one server-side session, and are wiped on lock, logout, session expiry or account deactivation.
- **Per-user keys.** Every vault has its own salt, verifier and keys. There is no shared global key.
- **Ownership enforced twice.**
  - The trusted client addresses only the logged-in user's vault, using credentials from the server-side account record.
  - The cloud requires that vault's bearer token; it stores only SHA-256(token).
- **Sessions.** HttpOnly + SameSite=Strict cookie holding a random id only. 30-minute idle and 8-hour absolute timeouts (`SESSION_IDLE_SECONDS`, `SESSION_ABSOLUTE_SECONDS`). A CSRF token is required in the `X-CSRF-Token` header for every state-changing request. Login is throttled after 5 failures in 15 minutes.
- **Admins** have no vault and no keys. Admin routes return audit events, account metadata and cloud ciphertext statistics/records only.
- **Audit log** never stores passwords, keys, file contents, filenames or search keywords.

## 7. Known limitations

- **Trusted-client assumption.** Whoever controls the client host could capture passphrases; protection is against the cloud operator, other users and app administrators. The client DB stores each vault's cloud access token (sufficient to read *ciphertext*, not to decrypt).
- **SSE leakage (by design of Πbas):**
  - search pattern (repeated tokens), access pattern and result counts
  - file sizes, counts and timestamps
  - for multi-keyword queries, that the tokens arrived together
  - **no forward privacy**: a captured token keeps matching future uploads
- **Static index:** every upload and delete rebuilds the vault's whole index (O(n)).
- **Passphrase change** re-encrypts every document with many requests; an interruption can leave a mixed state (the error message explains recovery).
- **Legacy namespace.** Requests without vault headers still reach the legacy single-user namespace unauthenticated, for backward compatibility. After migrating legacy data, start the cloud with `CLOUD_ALLOW_LEGACY_VAULT=0` to disable it.
- **Deployment.** Sessions are in memory (a client restart logs everyone out). It runs on Flask's development server over plain HTTP on localhost. For anything beyond a local demo, use HTTPS and set `SESSION_COOKIE_SECURE=1`.
- **Supported uploads:** UTF-8 text, PDFs with a text layer, and ZIPs of those (max 16 MB). Search is exact-keyword only (no stemming or substrings).

## 8. Configuration reference

| Variable | Default | Process |
|---|---|---|
| `VAULT_DB_PATH` | `vault.sqlite3` | cloud |
| `CLOUD_PORT` | `5001` | cloud |
| `CLOUD_ALLOW_LEGACY_VAULT` | `1` | cloud |
| `CLIENT_PORT` | `5000` | client |
| `CLOUD_BASE_URL` | `http://127.0.0.1:5001` | client |
| `ACCOUNTS_DB_PATH` | `client_accounts.sqlite3` | client |
| `ADMIN_SETUP_TOKEN` | random, printed at start | client |
| `ALLOW_REGISTRATION` | `1` | client |
| `SESSION_IDLE_SECONDS` / `SESSION_ABSOLUTE_SECONDS` | `1800` / `28800` | client |
| `SESSION_COOKIE_SECURE` | `0` | client |

A pre-change copy of the original database is kept at `backups/vault.sqlite3.pre-multiuser-20261025`. The cloud's schema migration (v1 → v2) runs automatically on startup and preserves every existing row.
