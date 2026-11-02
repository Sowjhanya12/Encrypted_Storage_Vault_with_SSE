# Security Audit (Opus, independent) — Encrypted Cloud Vault (SSE), Phases 1–5

**Reviewer role:** senior cryptography / security reviewer, not the implementer
**Reviewed against:** `docs/architecture.html` (Stage 1, approved) and the actual source in `client/`, `cloud/`, `web/`, `tests/`
**Date:** 26 August 2026
**Method:** full read of all 12 production modules, the architecture document rendered to text and read end-to-end, and all 9 test files; the suite run by the auditor (`210 passed in 13.32s`); **12 independently written adversarial probes**, all 12 confirming their hypothesis. The previous audit (`security_audit_phase6_readiness.md`) was read last and only to answer the question about what it missed — nothing here is inherited from it.
**Files modified:** none.

> **Verdict.** No Critical findings. **Two High findings the previous audit did not identify.** The cryptographic core — AES-GCM nonce discipline, HKDF domain separation, Argon2id parameter choice, the Πbas K1/K2/counter construction, the tokenizer contract, the trust boundary — is correct and must not be changed. Every defect is in the *operational* layer added in Phase 5: what happens when a key is wrong, when the cloud's `meta` table lies, and what the index rebuild destroys on the way through. **Ready for Phase 6 once H1 and H2 are fixed.**

---

## 1. Triage ledger

| Sev | ID | Finding | Evidence | New? |
|---|---|---|---|---|
| **Critical** | — | None found. Confidentiality of contents, filenames and keywords holds; no key material reaches the cloud. | — | — |
| **High** | H1 | A wrong password silently destroys the entire encrypted index on the next upload | Probe P1 | **yes** |
| **High** | H2 | The client trusts unauthenticated KDF material served by the untrusted cloud | Probe P5 | **yes** |
| **Medium** | M1 | Argon2id cost parameters are never persisted — deviation from Sections 07 & 08 | Probe P6 | confirmed |
| **Medium** | M2 | No AAD binds any ciphertext to its record; whole-blob swaps pass the GCM tag | Probe P2 | confirmed |
| **Medium** | M3 | Search-result truncation is silent, and AAD does not fix it | Probe P3 | **yes** |
| **Medium** | M4 | The search flow leaks the exact matching document set, beyond what Πbas requires | Probe P7 | **yes** |
| **Medium** | M5 | A captured K1 stays valid across every future index rebuild | Probe P4 | **yes** |
| **Medium** | M6 | An undecryptable document is silently dropped from the index on the next rebuild | Probe P10 | **yes** |
| **Low** | L1 | Argon2id parameters are misattributed to OWASP; the values themselves are correct | RFC 9106 | **yes** |
| **Low** | L2 | No CSRF protection on the trusted client while unlocked | code | **yes** |
| **Low** | L3 | Architecture Section 06 still specifies `token = (K1, K2)` | doc | confirmed |
| **Low** | L4 | Two unhandled exception paths return HTTP 500 | Probe P9 | **yes** |
| **Low** | L5 | No TLS, although Section 09 states transport is TLS-protected | code | **yes** |
| **Low** | L6 | Wrong password on search is indistinguishable from "no match" | Probe P11 | confirmed |
| **Low** | L7 | Cloud-side PRF duplication is guarded by a test, not by structure | code | confirmed |
| **Info** | I1–I6 | Six accepted-by-scope observations, incl. one new leakage channel (I4) | Probe P12 | partly |

"New?" is relative to `security_audit_phase6_readiness.md`. "Confirmed" = the earlier finding is real and was reproduced independently before that document was read.

---

## 2. High-severity findings

### H1 — Unlocking with a wrong password silently destroys the entire encrypted index on the next upload

**Evidence — three code paths that combine:**

```
client_app.py · api_unlock()               accepts any password; no verifier exists
client_app.py · _rebuild_and_push_index()
    except (DecryptionError, UnicodeDecodeError):
        continue                           # a doc that will not decrypt contributes no keywords
cloud_client.replace_index() -> POST /index/replace
storage.clear_index()  then  save_index_entries()      # destructive replace
```

**Probe P1 (observed):**

```
PROBE P1 unlock-with-wrong-password status: 200 {'status': 'unlocked'}
PROBE P1 upload-under-wrong-key status: 201
PROBE P1 RESULT: search hits before=1  after=0 ; docs still stored=2
```

A typo at the unlock prompt returns `200 unlocked`. The next upload triggers a full rebuild; every pre-existing document fails to decrypt under the wrong `K_file` and is skipped; the resulting index contains only the new file; `/index/replace` clears the real index before inserting it. **Every HTTP status on that path is a success code.**

**Why it matters.** The encrypted index is the project's entire contribution. It is destroyed here by a keystroke, with no error at unlock, at upload, or at the subsequent search (which returns a clean empty result — see L6). Documents survive and the index is rebuilt correctly on the next correct-password upload, so this is recoverable — but only by accident, and hitting it mid-demo looks like a broken system. The scope is wider than "wrong password": *any* key-set mismatch reaches this path, including H2's salt substitution and a future Argon2 parameter change (M1).

**Fix.**
1. Make the rebuild all-or-nothing: count decryption failures in `_rebuild_and_push_index` and **abort with an error** if any document failed, instead of pushing a smaller index.
2. Reject a wrong password at unlock via H2's verifier, so the destructive path is never entered.

*Architecture note:* Section 07 flow B says "add to dictionary D" — additive. The destructive `/index/replace` was a correct Phase 5 fix for counter reassignment, but it turned a benign failure into a destructive one, and the doc was never updated to say this operation now deletes.

---

### H2 — The trusted client accepts unauthenticated key-derivation material from the untrusted cloud

**Evidence — `client_app.py · api_unlock()`:**

```python
salt = cloud_client.get_meta("kdf_salt")
if salt is None:
    salt = generate_salt()              # silently bootstraps a NEW vault identity
    cloud_client.set_meta("kdf_salt", salt)
keys = derive_keys(password, salt)      # nothing verifies these keys are this vault's
```

**Probe P5 — one row deleted from `meta`, then unlock with the CORRECT password:**

```
PROBE P5 RESULT: unlock after salt deletion -> 200 {'status': 'unlocked'}
  | vault list -> [{"filename": "<undecryptable -- wrong password, or corrupted/tampered data>", ...}]
```

The salt is the one piece of setup state the client cannot re-derive, it lives in plaintext on the untrusted side, and nothing authenticates it.

- **Deletion is silent and catastrophic.** Lose that single row — restored backup, disk error, an operator `DELETE FROM meta` — and the next unlock quietly mints a *new* vault identity over the old one. The UI says "Unlocked". Every document is unreadable, permanently. **This needs no adversary**, so it is squarely inside the honest-but-curious model.
- **Substitution defeats the salt's stated purpose.** `generate_salt()`'s docstring says the salt exists "to defeat rainbow-table precomputation". A cloud returning one fixed salt to every vault converts a per-vault Argon2 attack into a single amortised precomputation across all of them, verifiable against any ciphertext the user later uploads. This half needs a deviating cloud (Section 10 scopes that out) — but the design should not be one dishonest row away from nullifying its own KDF hardening.

**Fix — one mechanism closes five findings.** Replace the bare `kdf_salt` row with an **authenticated vault descriptor** under a versioned key, e.g. `vault_descriptor:v1`:

```
descriptor = {"version": 1, "salt": ..., "argon2": {"t": 3, "m": 65536, "p": 4}}
verifier   = AES_GCM_Enc(K_file, b"vault-ok", AAD = canonical_bytes(descriptor))

unlock: fetch descriptor -> derive keys with ITS params -> decrypt verifier
        -> on DecryptionError, refuse to unlock (401, "wrong password or tampered
           vault parameters"); never fall through to an unlocked state.
init:   an absent descriptor requires an explicit POST /api/vault/init.
        /api/unlock must never create one.
```

Because the descriptor bytes are the AAD, tampering with the salt *or* the cost parameters fails the verifier rather than producing a plausible-looking wrong key. This closes H1's entry condition, both halves of H2, M1 and L6 in one change.

A verifier is a genuine addition to the approved design, and the Phase 5 docstring is right that Section 04 does not define one. That was defensible before the index rebuild became destructive; it is not defensible now. Record it as a deliberate, justified addition rather than silent scope creep.

---

## 3. Medium-severity findings

### M1 — Argon2id cost parameters are never persisted (deviation from the approved architecture)

**Probe P6:** `meta rows = [('kdf_salt', 16)]` — the complete table contents after a full workflow.

Section 08 states `meta` holds "KDF salt, Argon2 cost params, scheme version". Section 07 flow A states the client "fetches the stored salt **and KDF parameters** from the cloud". The implementation stores and fetches neither the parameters nor a version; `api_unlock` calls `derive_keys(password, salt)` and takes the module defaults forever.

**Why it matters.** Phase 7 is *Benchmarks & metrics*, and `keymgmt.py`'s docstring says "a later phase's benchmarks should confirm these land in the 'noticeable but not annoying' range". Argon2id output depends on `t`, `m` and `p` — so the first time someone tunes those constants after measuring, **every existing vault becomes permanently undecryptable**, silently, indistinguishably from a wrong password. The project's own next phase is the trigger. Note also that the suite exercises reduced `FAST_PARAMS`, so the production settings are never actually run or timed anywhere today.

**Fix.** Fold into H2's descriptor.

---

### M2 — No AAD binds any ciphertext to its record, and the architecture makes a claim this disproves

`aes_gcm_encrypt` accepts `associated_data` and documents it as "wired through now so a later phase can bind a blob to e.g. its doc_id". No production call site passes it — not contents, not filenames, not index values.

**Probe P2 — the cloud swaps only the body columns of two document rows:**

```
PROBE P2 RESULT: doc A now returns ->
  {"filename": "salaries.txt",
   "content":  "bravo bravo public newsletter text",
   "doc_id":   "4a7a87082d6c1593496bff62e32d7d46"}
  HTTP 200 — no tag failure, no warning
```

**Why this is more than a missing hardening step.** Section 10's risk table gives, as the design response to server result tampering: *"AES-GCM still detects blob tampering."* Probe P2 is a direct counterexample. GCM's tag authenticates `(key, nonce, plaintext)` — it says nothing about *where* a ciphertext is stored, so intact, validly-tagged blobs are freely interchangeable between records under the same key. The claim is true of bit-flips and false of record swaps.

**Fix.**
- Content: `AAD = doc_id`. Filename: `AAD = doc_id + b":name"` — both share `K_file`, so they must be distinguishable from each other as well as from other records.
- Index values: `AAD = label`, binding each encrypted doc_id to the exact dictionary slot it sits in.
- Add a swap test asserting `DecryptionError`. Correct Section 10 to: "AES-GCM detects modification of a blob; AAD binding is what detects relocation of one."

---

### M3 — Search-result truncation is silent, and AAD binding does not fix it

`run_search_loop` stops at the first missing label. Nothing binds the length of a keyword's postings list.

**Probe P3 — delete the single row for counter #1 of the keyword "budget":**

```
PROBE P3 RESULT: status=200  hits before=3  after deleting counter#1=1
```

Three matching documents became one, with a normal success response. The client cannot distinguish "one match" from "three matches, two withheld".

**Why it deserves its own finding.** It survives every fix in M2 — each remaining value still decrypts perfectly under the right key and the right AAD. Binding ciphertext to location cannot detect the *absence* of a record. This is the single most demonstrable gap for the Phase 6 panel, and the previous audit did not identify it.

**Fix — verifiable-lite, one extra row per keyword:**

```
SENTINEL = b"\xff" * 8                     # never a real counter value
label_n  = F(K1, SENTINEL).hex()
value_n  = AES_GCM_Enc(K2, str(count), AAD = label_n)

client: fetch label_n alongside the loop results, decrypt, and assert
        len(results) == count  ->  otherwise raise, do not return a result set.
```

Be precise in the write-up: this detects truncation and deletion; it is **not** verifiable SSE, and a cloud replaying a stale but internally consistent index snapshot still defeats it.

---

### M4 — The search flow hands the cloud the exact matching document set, beyond what Πbas requires

`api_search` loops `cloud_client.fetch_document(doc_id)` over every result, solely to decrypt `enc_name` for display.

**Probe P7 — every cloud request generated by ONE search with two matches:**

```
['POST /search',
 'GET /documents/0e1aee5b123beaf624df6f81f352961b',
 'GET /documents/aaa0c449d8c3172371e5410a3beb960c']
```

**Why it matters.** In Πbas the server returns encrypted identifiers and learns which documents matched only if and when the client retrieves one. Here the client retrieves all of them on every query, even when the user opens nothing — converting *potential* access-pattern leakage into *guaranteed, immediate* access-pattern leakage. Access pattern plus result volume is precisely the input to the IKK and count leakage-abuse attacks Section 09 names.

**Fix.** `GET /documents` already returns `enc_name` for every document in one call. Fetch the list once, build a `doc_id -> enc_name` map, decrypt names locally. One request per search. "We found a place where our implementation leaked more than the scheme requires, and closed it" is a strong viva point.

---

### M5 — A captured K1 remains a valid capability across every future index rebuild

`K_index` is fixed for the vault's lifetime and `_rebuild_and_push_index` re-derives the whole index under it after **every** upload, so a K1 the cloud saw once keeps working forever.

**Probe P4 — replay a K1 captured from an earlier search; issue no new search:**

```
PROBE P4 RESULT: replaying the OLD captured K1 with no new search: 1 -> 2 matching docs
```

**Why it matters.** Section 01 says "static index only… we do not claim forward privacy", and that disclaimer is honest. But the shipped system is *not* static in operation — it rebuilds on every upload, which is exactly the dynamic setting where absent forward privacy bites. A cloud holding K1s from past searches learns, at upload time and with no new query, whether each newly uploaded document contains any previously searched keyword, and watches the count climb. Section 09's leakage table has no row for this.

**Fix.** No code change is appropriate at this scope (forward privacy needs a different construction). What is required is honesty:
- Add a leakage row: *"Update leakage — for any previously searched keyword, whether newly uploaded documents match it, learned at upload time with no new query."*
- Stop calling K1 a per-search "token". It is a **persistent per-keyword recognition capability**; naming it accurately turns a disclaimer into an analysis.
- Make probe P4 a live demo in the Phase 6 panel.

---

### M6 — An undecryptable document is silently evicted from the index on the next rebuild

**Probe P10 — corrupt one document's ciphertext, then upload any other file:**

```
PROBE P10 RESULT: hits before corrupting one doc=2; after next rebuild=2
                  (would be 3 if the corrupt document were reported)  status=200
```

The project's tamper story is "GCM catches it and we fail loud" — true on the read path (`/api/documents/<id>` correctly returns 422), false on the index path, where `except (DecryptionError, UnicodeDecodeError): continue` turns *detected tampering* into a *silent deletion from search*. A cloud that flips one byte of one document removes it from every future result set, invisibly.

**Fix.** Same change as H1: count failures, abort the rebuild, report which `doc_id`s failed. A detected integrity failure must never be handled by quietly continuing.

---

## 4. Low-severity findings

### L1 — Argon2id parameters are misattributed; the values are correct

`keymgmt.py` states: *"We default to OWASP's current baseline recommendation for Argon2id: time_cost = 3, memory_cost = 65536 KiB, parallelism = 4."*

The OWASP Password Storage Cheat Sheet recommends five configurations and **every one uses p = 1**: m=47104/t=1, m=19456/t=2, m=12288/t=3, m=9216/t=4, m=7168/t=5. None uses 64 MiB, none uses four lanes.

The chosen values are **RFC 9106 §4's second recommended option**: "Argon2id with t=3 iterations, p=4 lanes, m=2^16 (64 MiB of RAM), 128-bit salt, and 256-bit tag size" — and the implementation matches all four elements, including `SALT_SIZE = 16` and `KEY_SIZE = 32`.

**Fix.** A one-line docstring edit. **Do not change the parameters.** Citing RFC 9106 is *stronger* than citing OWASP, since these settings exceed every OWASP option on memory. An examiner who checks the OWASP page will find the current sentence untrue — a cheap way to lose credibility on a point you actually got right. The previous audit repeated the attribution without checking it.

### L2 — No CSRF protection on the trusted client while unlocked

`POST /api/documents` accepts `multipart/form-data` (a CORS-simple request) and `POST /api/lock` accepts an empty body. Any page the user visits while unlocked can submit a cross-origin form to `127.0.0.1:5000` — uploading attacker-chosen content (which triggers a full index rebuild) or locking the vault. No CORS headers are set, so responses are unreadable cross-origin: write-side only.
**Fix.** Reject `/api/*` requests whose `Sec-Fetch-Site` is not `same-origin` (fall back to an `Origin` check). ~5 lines in a `before_request` hook.

### L3 — Architecture Section 06 still specifies `token = (K1, K2)`

The code sends K1 only and that is the better design (§6 below). Beyond the mismatch, the doc's justification — *"Sending K2 leaks nothing beyond this keyword"* — understates that K2 is a persistent *decryption* capability valid against every future rebuilt index, whereas K1 is only a *recognition* capability.
**Fix.** Add an "Implementation deviations" section to `architecture.html` listing all four deviations (§5 below) and correct the K2 justification.

### L4 — Two unhandled exception paths return HTTP 500

**Probe P9:** `unhandled exception propagated -> ValueError salt must be 16 bytes, got 8`. `api_unlock` catches only `CloudUnavailableError` / `CloudError`, so a malformed salt from the untrusted side escapes as a 500. Likewise `run_search_loop`'s defensive `RuntimeError` is not caught by `search_route`. Both are inputs from across the trust boundary; untrusted input should never produce a 500.
**Fix.** Validate the descriptor at the boundary and return `502 "the cloud returned malformed vault parameters"`; catch the `RuntimeError` and return 502.

### L5 — No TLS, although Section 09 states transport is TLS-protected

Both Flask processes serve plain HTTP; the vault password crosses `POST /api/unlock` in the clear on that hop. Section 09 asserts "transport is protected by TLS". Reasonable for a loopback demo, but currently an assumption *stated* and not *implemented*.
**Fix.** Either run both dev servers with `ssl_context="adhoc"`, or state explicitly in the report that TLS is assumed at deployment and out of scope for the demo. Do not leave the doc asserting a property the system lacks.

### L6 — Wrong password on search is indistinguishable from "no match"

**Probe P11:** `200 {'keyword': 'zebra', 'query': 'zebra', 'results': []}`. Confirmed; leaks nothing. Rated slightly higher in practical importance than the previous audit did, because it is the mechanism that hides H1 from the user. Closed for free by H2's verifier.

### L7 — Cloud-side PRF duplication is guarded by a test, not by structure

`_cloud_prf` and `_counter_to_bytes` were verified against the client implementations independently, not only through the project's drift detector: HMAC-SHA256 both sides, 8-byte big-endian both sides, and probe P3 confirms the cloud regenerates labels the client wrote. No consistency defect exists today.

**My recommendation differs from the previous audit's.** It proposed extracting a shared `common/` module. I would **keep the duplication**: the AST-enforced statement "`cloud/` imports nothing from `client/`" is one of the cleanest trust-boundary arguments in the project, and a shared module weakens it to "imports nothing except this bit". The right mitigation is to make the guard explicit — state in the drift test's docstring and the README that it is a required gate, and add a one-command CI step if you want it enforced rather than remembered.

---

## 5. Informational

- **I1 — No authentication on cloud routes.** In-model per Sections 02/09. Worth one sentence so it reads as a decision.
- **I2 — One process-wide KeySet.** Honestly documented in `client_app.py`. Correct for a single-operator demo.
- **I3 — `size` is the exact plaintext length.** GCM adds no padding: a 16-byte file stores `size = 16` (probe P6). Named in Section 09; padding is Phase 6 work.
- **I4 — Row-count deltas leak per-file keyword counts. (new)** Probe P12: `sse_index` went 5 -> 7 rows, telling the cloud the uploaded file introduced exactly two new distinct keywords. Add a leakage-table row.
- **I5 — `KeySet.wipe()` cannot zero Python bytes.** Already documented with unusual candour. Leave the code and the docstring exactly as they are — it is a credibility asset.
- **I6 — Section 11 artefacts still absent.** `benchmarks/`, `data/sample_corpus/`, `README.md` do not exist yet. Expected: Phases 7–8.

---

## 6. Correct — do not change

All verified by the auditor rather than accepted from a phase report.

- **AES-GCM nonce discipline** — fresh `os.urandom(12)` per call; no code path accepts a caller-supplied nonce. Probe P8: 230 nonces across documents and index values, 230 distinct.
- **`nonce ‖ ct ‖ tag` framing** — `_split_blob` and its reassembly match Section 08's three columns exactly, no off-by-one at either boundary.
- **Collapsed `DecryptionError`** — wrong key, wrong AAD and tampering report identically. Correct oracle avoidance; say so in the viva.
- **HKDF with `salt=None`** — correct per RFC 5869 when expanding one already-high-entropy 256-bit secret; versioned `info` labels give real independence. Do not add a salt.
- **Argon2id parameter values** — t=3, m=64 MiB, p=4, `Type.ID`, 16-byte salt, 32-byte output: RFC 9106 §4 option 2 exactly. Only the citation needs fixing (L1).
- **K1/K2 domain separation** — `"1"‖w` and `"2"‖w` diverge at the first byte; the tokenizer's `[A-Za-z0-9]+` alphabet rules out delimiter ambiguity too.
- **Counter encoding** — 8-byte big-endian, one exported function reused by `indexer` and `search`, cross-checked byte-for-byte against the cloud's independent copy.
- **One shared tokenizer** — structurally enforced: a single `tokenize()` imported by both paths. Stated limitations are honest; the determinism argument holds.
- **Non-deterministic index values** — fresh nonces mean rebuilt postings do not re-encrypt identically, denying the cloud a snapshot diff. A real security property, correctly reasoned.
- **Atomic index replacement** — `clear_index` + `save_index_entries` share one SQLite transaction; a mid-way failure rolls back rather than leaving a half-index.
- **Zero key material crosses the boundary** — probe P8 searched the raw `.sqlite3` file for `k_file` and `k_index` after a 40-document workflow: `False` and `False`.
- **The browser really is crypto-free, and XSS-clean** — every untrusted string reaches the DOM via `textContent`; `innerHTML` is only ever assigned `''`. No key, no derivation, no direct call to port 5001.
- **Server-computed `size`** — derived from `len(ciphertext)`, never trusted from the caller.
- **Test-suite quality** — 210 tests, non-circular: AST-based import guards, raw-database substring checks, a genuine cross-implementation drift detector. Well above the level typical for this kind of project.

---

## 7. The six questions, answered directly

**1 · Is the K1-only token cryptographically sound?**
**Yes — sound, and strictly better than Section 06's literal pseudocode. Keep it.** The cloud's search loop provably never touches K2: it calls `_cloud_prf(k1, …)` and `get_index_entry`, nothing else. K2 is derived client-side from the same `(K_index, keyword)` pair that just produced K1. Withholding it narrows the capability rather than changing it in kind: K1 lets the cloud *recognise* which rows belong to a keyword; K2 would additionally let it *decrypt* the identifiers under them, permanently and for every future rebuild. The nuance the code's docstring misses, which M5 makes concrete: **neither key is single-use.** K1 is a long-lived per-keyword capability, so "search token" is the wrong name in the write-up.

**2 · Is the cloud-side PRF/counter implementation safe and consistent?**
**Yes on both counts, verified independently.** HMAC-SHA256 and 8-byte big-endian on both sides; probe P3 confirms the cloud regenerates the exact labels the client wrote. The docstring's reasoning is correct — what must not cross the boundary is key-handling code and secrets, not the ability to compute a public hash, and `k1` arriving as a caller argument is a capability the cloud was *given*, not a secret it stole. Only maintenance drift is at issue, and my recommendation is the opposite of the previous audit's (see L7).

**3 · Do encrypted files and index values need AAD binding?**
**Yes — and for a stronger reason than "cheap hardening".** Without it, Section 10's claim that "AES-GCM still detects blob tampering" is false as written, and probe P2 demonstrates it in one HTTP call. But do not oversell the result: AAD closes *relocation*, not *deletion* — M3's truncation attack survives it untouched and needs the count-binding fix instead.

**4 · Do the Argon2 parameters need persisting for future benchmarking?**
**Yes — but benchmarking is the weaker of the two reasons.** The stronger one is that Sections 07 and 08 already say the parameters are stored in `meta` and fetched at unlock. Not doing so deviates from the approved design independent of any future tuning. Persist them inside H2's authenticated descriptor, not as a bare row.

**5 · Does the implementation match the architecture document?**
**Closely, with four deviations** — two improvements, one regression, one gap:
1. **K1-only instead of `(K1, K2)`** — an improvement, undocumented in the approved doc (L3).
2. **Destructive `/index/replace` instead of Section 07's additive "add to D"** — a correct fix for counter reassignment, but it introduced H1 and M6 and was never written back into the document.
3. **Argon2 parameters not persisted** — a regression against Sections 07/08 (M1).
4. **TLS assumed but absent** — Section 09 asserts a property the system does not have (L5).

Everything else — key hierarchy, schema, trust boundary, Πbas construction, tokenizer rule, the browser's thin-shell role — matches faithfully.

**6 · What did the previous audit miss, and were any claims wrong?**
Its two Medium findings are real and were reproduced independently before it was read; its "already correct" list is accurate; its analysis of the K1-only design is sound. It was a competent review of the *code as written*. What it missed is what only appears when you *attack* the running system: **H1, H2, M3, M4, M5, M6, L1, L2, L4, L5, I4.** Two of its statements do not survive:

- *"No Critical or High-severity vulnerabilities found"* — not supportable given probes P1 and P5. Both are silent, both reachable without an adversary, and both destroy or invalidate the vault's central data structure.
- *"a reasonable, citable OWASP-baseline choice"* — the parameters are good, but they are not OWASP's; the attribution was repeated from the source docstring without being checked (L1).

A methodological note worth carrying forward: that audit's method line says the suite was run live and every module read, and both are true. The gap was not diligence — reading code tells you what it does; probing it tells you what it does when something goes wrong. Ask for the second kind explicitly.

---

## 8. Readiness for Phase 6

**Ready to proceed — conditionally.** The cryptographic foundation is sound enough that Phase 6 does not require revisiting Phases 1–4. But do not start the leakage panel with H1 and H2 open: a demo vault that silently wipes its own index, or silently re-keys itself when one row goes missing, will fail in front of an audience at the worst possible moment.

| # | Do this | Items | Size |
|---|---|---|---|
| 1 | Authenticated vault descriptor + verifier; refuse to unlock on verifier failure; explicit `/api/vault/init` | H2, M1, L6 | ~1 sitting |
| 2 | Make index rebuild all-or-nothing; abort and report on any decryption failure | H1, M6 | ~20 lines |
| 3 | AAD binding on content, filenames and index values, with a swap test | M2 | Phase 6 core |
| 4 | Count-binding sentinel row per keyword; assert result length client-side | M3 | Phase 6 core |
| 5 | Decrypt result filenames from the cached listing instead of per-result fetches | M4 | ~10 lines |
| 6 | Reconcile the architecture doc: deviations section, corrected Section 10 tamper claim, two new leakage rows, RFC 9106 citation | L1, L3, M5, I4 | documentation |
| 7 | Same-origin check, boundary exception handling, TLS decision | L2, L4, L5 | optional polish |

**A closing observation on the phase itself.** Phase 6 has better raw material than its plan assumed. The "what the cloud sees" panel was scoped to show the tables hold only ciphertext — true, but static. Probes P2, P3, P4 and P12 give four *live, adversarial* demonstrations instead: a swap the tag does not catch, a truncation the client cannot detect, an old capability that still works against tomorrow's index, and a row count that reads off how many new keywords a file introduced. Showing the fixes land against those is a considerably stronger story than a table of random bytes.

---

**References.** [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) · [RFC 9106 §4](https://www.rfc-editor.org/rfc/rfc9106.html) · Cash, Jaeger, Jarecki, Jutla, Krawczyk, Roşu, Steiner, *Dynamic Searchable Encryption in Very-Large Databases* (NDSS 2014), Πbas.
