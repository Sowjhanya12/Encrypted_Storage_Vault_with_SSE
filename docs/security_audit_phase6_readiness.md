# Security Audit — Encrypted Cloud Vault (SSE) — Phases 1–5

**Reviewer role:** independent cryptography/security review (not the implementer)
**Reviewed against:** `docs/architecture.html` (Stage 1, approved) and the actual source in `client/`, `cloud/`, `web/`, `tests/`
**Method:** full read of every production module, the approved architecture doc, and the test suite; live run of the suite (`python3 -m pytest -q` → **210 passed**, 0 failed, run on 2026-08-26); manual trace of every crypto call site
**Verdict up front:** **No Critical or High-severity cryptographic vulnerabilities found.** The core scheme (AES-256-GCM, HMAC-PRF, HKDF, Argon2id, Πbas) is implemented correctly and matches the approved design closely. There is one **Medium** correctness/architecture defect (Argon2 cost parameters are not versioned/persisted) that should be fixed before Phase 7 benchmarking touches those constants, and a small number of Medium/Low hardening and documentation-sync items. Details and a full readiness call are below.

---

## 1. Summary table

| # | Finding | Area | Severity |
|---|---|---|---|
| 1 | Argon2id cost parameters are not persisted/read from cloud `meta` — a future tuning change silently bricks every existing vault | Key management | **Medium** |
| 2 | No AAD binds ciphertext to its record (doc_id) — content/filename/index-value blobs are swappable between records without a tag failure | AES-GCM usage | **Medium** |
| 3 | Cloud-side PRF/counter reimplementation (`_cloud_prf`, `_counter_to_bytes`) is a hand-duplicated copy of client logic, safeguarded only by tests, not by the type system or a shared contract | SSE consistency | **Low** |
| 4 | Approved `docs/architecture.html` Section 06 still shows `token = (K1, K2)`; the shipped code deliberately sends K1 only — the *approved* document was never updated to reflect this | Documentation / process | **Low** |
| 5 | Wrong password on `/api/search` returns a normal empty result — indistinguishable from "keyword not found" | Wrong-password UX | **Low** |
| 6 | First caller to `/api/unlock` silently bootstraps the vault's salt under whatever password they typed | Trust boundary / setup | **Low (accepted by scope)** |
| 7 | Cloud mutation routes (`/documents`, `/index/replace`, `/meta/*`) have no auth — any party reaching port 5001 can write | Trust boundary | **Informational (in-scope per Section 02/09)** |

Nothing rated Critical or High. Section 3 below covers each item with evidence, impact, and fix. Section 4 lists what is already correct and must **not** be changed. Section 5 answers your two specific questions (K1-only token design, cloud-side PRF duplication). Section 6 gives the readiness call.

---

## 2. What was actually checked (not just the phase reports)

Read end-to-end: `client/crypto.py`, `client/keymgmt.py`, `client/tokenizer.py`, `client/indexer.py`, `client/search.py`, `client/cloud_client.py`, `client/client_app.py`, `cloud/storage.py`, `cloud/cloud_app.py`, `web/main.js`, `docs/architecture.html` (rendered to text and read in full), and the relevant classes/functions in `tests/test_crypto.py`, `tests/test_storage.py`, `tests/test_cloud_app.py`, `tests/test_integration.py`, `tests/test_client_app.py`, `tests/test_cloud_client.py`, `tests/conftest.py`. The full suite was re-run live (not taken on faith from the phase reports): **210/210 passing.**

---

## 3. Findings in detail

### Finding 1 — Argon2 cost parameters are not versioned or persisted (Medium)

**Evidence.** `client/keymgmt.py:158`:

```python
def unlock(password: str, salt: bytes, params: Argon2Params = _DEFAULT_PARAMS) -> KeySet:
```

`client/client_app.py:157`, the only production call site:

```python
keys = derive_keys(password, salt)
```

`params` is never passed — every unlock, forever, uses the module-level `_DEFAULT_PARAMS` constant (`time_cost=3, memory_cost_kib=65536, parallelism=4`). A `grep` across `client/`, `cloud/`, and `tests/` for `argon2_params`, `cost_param`, `kdf_params` confirms nothing in the production path ever writes or reads Argon2 cost parameters to/from the cloud's `meta` table — only `kdf_salt` is ever set/fetched there.

**Why it matters.** `docs/architecture.html` Section 08 explicitly lists the `meta` table's contents as *"Non-secret parameters: KDF salt, Argon2 cost params, scheme version"* — the approved design's own schema description assumes cost params are persisted alongside the salt. They are not. Worse, `keymgmt.py`'s own module docstring flags this as future work that *will* happen: *"a later phase's benchmarks should confirm these land in the 'noticeable but not annoying' range... not just assume the OWASP numbers are correct for this machine"* — and Phase 7 (Section 15, `P7 Benchmarks & metrics`) is exactly where someone would go tune `ARGON2_TIME_COST`/`ARGON2_MEMORY_COST_KIB`/`ARGON2_PARALLELISM` after measuring real unlock latency on the demo machine.

The moment those constants change, `derive_master_key(password, salt, new_params)` produces a **different** Master Key than the one originally used to build the vault, because Argon2id output depends on its cost parameters, not just the password and salt. Every file and every index entry ever encrypted under the old key becomes permanently undecryptable — and the failure is silent and indistinguishable from a wrong password (per Finding 5), so there is no error message pointing at the real cause. This is a **data-loss bug waiting to be triggered by the project's own documented next phase**, not a hypothetical.

**Recommendation.** Store the three Argon2 fields (or a serialized `Argon2Params`) in the cloud `meta` table at first-unlock bootstrap time, next to `kdf_salt`, and read them back on every subsequent unlock instead of using `_DEFAULT_PARAMS` — mirroring exactly what already happens for the salt in `api_unlock()`. Version the meta key the same way HKDF's `info` labels are already versioned (e.g. `kdf_params:v1`) so a deliberate future cost-parameter change is an explicit, opt-in migration rather than an accidental one. This is a small, contained change (touches `api_unlock` and adds two `storage`/`cloud_client` calls) and it directly closes a gap between the approved design and the implementation.

---

### Finding 2 — No AAD binds ciphertext to its record (Medium)

**Evidence.** `client/crypto.py:62` (`aes_gcm_encrypt`) already accepts `associated_data`, with a docstring saying *"wired through now so a later phase can bind a blob to e.g. its doc_id without touching this function's contract"* — but no production call site ever passes it. `client_app.py:203-204`:

```python
file_blob = aes_gcm_encrypt(keys.k_file, raw_bytes)
name_blob = aes_gcm_encrypt(keys.k_file, file.filename.encode("utf-8"))
```

Both file content and filename are encrypted under the same `k_file` key with no AAD tying either ciphertext to the `doc_id` it will be stored under. The same is true of index values in `client/indexer.py:145` (`aes_gcm_encrypt(k2, doc_id.encode("utf-8"))` — no AAD binding the value to its label/counter).

**Why it matters.** AES-GCM's tag authenticates `(key, nonce, plaintext)` but says nothing about *where* that ciphertext is stored. Without AAD, two blobs encrypted under the same key are freely interchangeable: the content blob of document A and the content blob of document B (or A's content and A's filename, since both use `k_file`) can be swapped in the `documents` table and each will still pass its own GCM tag check — the client will simply decrypt document A's row and get document B's plaintext, with no error. The same applies to `sse_index` rows: swapping two values under two different labels is undetectable.

This is honestly adjacent to, not squarely inside, the project's stated threat model — Section 10 explicitly scopes "server result tampering" as out of scope for an honest-but-curious adversary, and AES-GCM already catches byte-level corruption (the thing your tests exercise). AAD would catch a *different, narrower* class of tampering: swapping whole, valid ciphertexts between records. Given that (a) the parameter is already plumbed through specifically for this purpose and never used, (b) it costs nothing (same key, same nonce discipline, one extra `bytes` argument), and (c) Phase 6 is explicitly named "Security hardening & demo panel," this is a cheap, well-scoped, high-credibility addition for that phase rather than a pre-existing bug you need to stop and fix immediately.

**Recommendation.** Pass `doc_id.encode()` as `associated_data` when encrypting file content and filename, and pass something like `label.encode()` (or `keyword` domain marker) when encrypting index values, then require the matching AAD on decrypt. Add one test that swaps two valid ciphertexts between two `doc_id`s and asserts decryption now fails with `DecryptionError`.

---

### Finding 3 — Cloud-side PRF/counter duplication is a manual, not structural, consistency guarantee (Low)

**Evidence.** `cloud/cloud_app.py:64-87` reimplements `client/crypto.py::prf()` and `client/indexer.py::counter_to_bytes()` from scratch with stdlib `hmac`/`hashlib`, by design, to keep the AST-enforced "`cloud/` never imports `client/`" boundary sharp (`tests/test_storage.py::TestTrustBoundary`, `tests/test_cloud_app.py::test_cloud_app_module_does_not_import_client_package`). Today the two implementations are checked byte-for-byte by `tests/test_integration.py::TestCloudSearchLoopMatchesClientImplementation` (20+ random-input HMAC comparisons, counter-encoding comparisons, and a full label cross-check).

**Why it matters.** This is a sound engineering decision, correctly implemented and correctly tested — it is not a vulnerability. It is, however, a maintenance hazard: nothing *stops* someone from changing `prf()`'s hash algorithm or `counter_to_bytes()`'s width in `client/` six months from now and forgetting the cloud-side twin (`grep` alone won't catch it, since the strings genuinely differ by design in this file). The drift-detector test only protects you as long as someone remembers to run the suite after touching either side, and CI is not configured in this project.

**Recommendation (optional, not blocking).** Consider factoring `prf()` and `counter_to_bytes()` — which need no secret and are already public, standard cryptography per the module's own docstring — into a small neutral module, e.g. `common/sse_primitives.py`, imported by *both* `client/` and `cloud/`. This removes the duplication (and the drift risk) entirely while preserving the actual security-relevant invariant the AST tests protect: that `cloud/` never imports `client.keymgmt`/`client.crypto`'s *key-handling* code or ever sees a real secret. If you'd rather keep the current explicit duplication for viva-defensibility ("look, it's independently reimplemented and cross-checked, that's *more* rigorous"), that is a legitimate call too — just be aware it is a deliberate trade-off, not a free one, and say so if asked in viva.

---

### Finding 4 — The approved architecture doc was not updated for the K1-only deviation (Low, documentation)

**Evidence.** `docs/architecture.html` Section 06 (the actual approved text, extracted verbatim from the file):

> `token = (K1, K2)  # send to cloud — K_index itself never leaves`
> *"Why K2 is sent too — The server returns encrypted IDs; the client needs K2 to decrypt them."*

`client/search.py`'s module docstring explains, correctly and at length, that only K1 is sent, and why. This deviation is well-reasoned (see Section 5 below) and was clearly a deliberate, documented decision at implementation time — but "documented in a code comment" and "reflected in the *approved* design document" are different things, and the prompt that started this audit explicitly names `docs/architecture.html` as the source of truth to audit *against*. As written, a side-by-side comparison of the approved doc and the code shows a real discrepancy.

**Recommendation.** Add a short, explicit addendum to Section 06 of `docs/architecture.html` (or a new "Implementation deviations" section, since Section 15/16 already model this kind of transparency) recording that the shipped system sends K1 only, with the same reasoning already in `search.py`'s docstring. This is presentation, not code — but for a course project, an examiner comparing the "approved design" to the delivered system should find them reconciled, not silently diverging in the one document that's supposed to be authoritative.

---

### Finding 5 — Wrong password on search is silently indistinguishable from "no matches" (Low)

**Evidence.** `tests/test_client_app.py::TestWrongPassword::test_wrong_password_search_finds_nothing_not_an_error` documents this as intended behavior: search with a wrong password returns `200` with `results: []`, not an error. This is a direct, correct consequence of the "no password verifier" design (`client_app.py`'s module docstring explains this is deliberate, per Section 04). Compare with `GET /api/documents` (wrong password → visible `<undecryptable...>` filenames) and `GET /api/documents/<id>` (wrong password → `422`) — search is the one operation where a wrong password produces output that looks identical to a correct password with a genuinely absent keyword.

**Why it matters.** This is not a security defect (nothing leaks; if anything it leaks *less* than the other two routes) — it's a usability gap that could read as a bug in a live demo ("I searched a word I know is in there and got nothing — is the app broken?"). Given the demo script in Section 07/16 walks through unlock → search, this is worth pre-empting.

**Recommendation.** No code change is required by the approved design (adding a verifier would be adding a feature the architecture doc deliberately omits). Simplest fix: in the browser UI or demo script, always check the vault list first (which *does* show `<undecryptable>`) before trusting an empty search result — or, if you want a code-level nudge without adding a verifier, have `/api/search` opportunistically check whether *any* document's filename fails to decrypt under the current keys before running the search, and surface a "these keys don't look right" hint. Keep this optional and scoped — don't let it turn into a de facto password verifier by accident, which would need its own security review.

---

### Finding 6 — First `/api/unlock` call silently sets the vault's password (Low, accepted by current scope)

**Evidence.** `client_app.py:149-156`: if `kdf_salt` doesn't exist yet in cloud `meta`, `api_unlock` generates one and derives keys from *whatever password was just POSTed* — there is no separate "create vault" step. Whoever's `POST /api/unlock` reaches the process first, with the process's salt still unset, establishes the vault's password from that point on.

**Why it matters.** In the documented single-operator local demo (`client_app.py`'s own docstring: "this matches the doc's threat model... but is a real, named limitation for anything beyond a local demo"), this is already an accepted limitation and not new. It's listed here for completeness and to make explicit that it also covers *vault creation*, not just post-creation access — worth a one-line mention in the viva if asked "what happens on first run."

**Recommendation.** No change required for the current scope. If you want to harden it cheaply, an explicit `POST /api/vault/init` step (rejecting `/api/unlock` until a vault has been initialized) would remove the ambiguity, but this is optional polish, not a defect against the approved design.

---

### Finding 7 — Cloud mutation routes have no authentication (Informational, in-scope per the model)

**Evidence.** `cloud/cloud_app.py` — `/documents` (POST), `/index/replace`, `/meta/<key>` (POST) accept requests from anyone who can reach port 5001, with no credential check.

**Why it matters.** This is *exactly* the honest-but-curious model as scoped (Section 02: the cloud "stores your data, runs the protocol faithfully" — a malicious/unauthorized writer is a different, explicitly out-of-scope adversary per Section 10's "Server result tampering... out of scope by model"). Not a finding against the approved design — listed only so it's a conscious, stated fact rather than an unstated gap if this project is ever extended past the course scope.

---

## 4. What is already correct — do not change

- **AES-256-GCM usage** (`client/crypto.py`): fresh `os.urandom(12)` nonce on every single call, no code path accepts a caller-supplied nonce, `nonce || ciphertext || tag` framing matches the DB schema exactly, and `InvalidTag` is collapsed into one generic `DecryptionError` rather than leaking *why* decryption failed (correctly avoids a padding-oracle-style side channel). Verified by `test_crypto.py`'s round-trip, tamper-flip (tag byte and ciphertext byte separately), wrong-key, and truncated-blob tests, all passing.
- **Argon2id parameters** (`client/keymgmt.py`): `time_cost=3, memory_cost=64MiB, parallelism=4`, `Type.ID` — a reasonable, citable OWASP-baseline choice, correctly wired as `Argon2Params` rather than hardcoded inline (aside from Finding 1, which is about *persistence*, not the values themselves).
- **HKDF-SHA256 domain separation** (`client/crypto.py`, `client/keymgmt.py`): `salt=None` is the correct, standard call when expanding one already-high-entropy 256-bit secret (RFC 5869); the two `info` labels (`vault:k_file:v1`, `vault:k_index:v1`) are versioned and give K_file/K_index genuine cryptographic independence.
- **SSE K1/K2 derivation and Πbas construction** (`client/indexer.py`, `client/search.py`): label key `K1 = F(K_index, "1"||w)`, value key `K2 = F(K_index, "2"||w)`, `label = F(K1, counter)`, `value = AES-GCM(K2, doc_id)` — matches Section 05 exactly. Domain separation between K1/K2 via the leading `1`/`2` byte is correct and collision-free by construction.
- **Counter encoding**: fixed 8-byte big-endian, exported as a single function (`counter_to_bytes`) reused (not reimplemented) on the client side by both `indexer.py` and `search.py`, and cross-checked byte-for-byte against the cloud's independent copy. No encoding drift found.
- **Tokenizer consistency**: `tokenize()` in `client/tokenizer.py` is the single import used by both `indexer.build_index()` (index time) and `search.normalise_query()` (query time) — verified structurally (one function, two call sites) and behaviorally (`test_query_phrasing_does_not_affect_the_match`, punctuation/case-insensitivity).
- **Index rebuild correctness**: the atomic `clear_index()` + `save_index_entries()` inside `POST /index/replace` correctly solves the counter-reassignment problem from a static full rebuild; proven end-to-end by `test_multiple_uploads_rebuild_index_correctly`, which specifically exercises documents added in an order that would have shifted counters under a naive additive push.
- **Search-token and access-pattern leakage**: correctly implemented *and* correctly named as accepted leakage in Section 09 — the deterministic-token property is real (by design, that's what makes the scheme work), tested explicitly (`test_indexed_corpus_leaks_no_plaintext_keyword_or_doc_id`), and not oversold anywhere in the code or docs.
- **Trust boundary / process separation**: `cloud/storage.py` and `cloud/cloud_app.py` are proven, by AST-based tests, to never import `client/`; `web/main.js` is proven, by direct code inspection, to do zero cryptography and to only ever call same-origin `/api/*` — the browser never touches a key or talks to the cloud process directly. `tests/test_integration.py` and `tests/test_client_app.py` both additionally inspect the raw SQLite file on disk and HTTP payload bodies for literal key bytes and plaintext substrings after full workflows, and find none.
- **Wrong-password / tamper failure modes** (outside Finding 5's UX note): `DecryptionError` is raised and propagated (not swallowed) everywhere it should be — viewing a document with the wrong password is a clean `422`, a bit-flipped search result is a clean `DecryptionError`, decrypting one keyword's results with a different keyword's K2 correctly fails. All fail loud, none fail silently-wrong.
- **`documents.size` computed server-side** (`cloud/storage.py::save_document`) as `len(ciphertext)`, never trusted from the caller — small but correct hygiene.

---

## 5. Your two specific questions, answered directly

### Is sending only K1 to the cloud (not `(K1, K2)` as literally written in Section 06) cryptographically sound?

**Yes — it is sound, and arguably strictly better than the literal pseudocode, not just an acceptable substitute.** The reasoning in `client/search.py`'s docstring holds up under scrutiny:

- The cloud's `run_search_loop()` (`cloud/cloud_app.py:90-124`) never touches K2 anywhere in its body — it only ever calls `_cloud_prf(k1, ...)` to regenerate labels and `storage.get_index_entry()` to look them up. Sending K2 to a process that provably never uses it adds attack surface (one more secret in flight, one more secret sitting in a request log or a debugger breakpoint on the untrusted side) for zero functional gain.
- K2 is derived client-side by `decrypt_search_results()` from the exact same `(k_index, keyword)` pair that produced K1 a moment earlier in the same request — there's no round-trip dependency that would require K2 to have gone anywhere.
- It doesn't change the leakage profile Section 09 already commits to: search-pattern leakage (same word twice → same token) and access-pattern leakage (which doc_ids matched) come entirely from K1's determinism, which is unchanged either way. Withholding K2 makes the design *narrower*, not different in kind.
- It's consistent with the project's own standing invariant, verified since Phase 2, that zero key material ever crosses to the cloud beyond what's strictly required per operation — K1 already is that "narrow, single-purpose capability" the architecture doc's Section 06 callout box argues for; K2 just isn't required to reach that bar.

The only real issue is Finding 4 above: the *approved document itself* wasn't updated, so a literal side-by-side diff looks like a deviation from spec rather than what it actually is — a tightening that's consistent with the spec's own stated goals. Fix the document, keep the code exactly as it is.

### Does the cloud-side reimplementation of the PRF/counter encoding create a subtle consistency or security problem?

**No security problem — it correctly preserves the trust boundary and every input tested checks out byte-for-byte. It does create a real (but currently well-mitigated) maintenance risk**, covered in detail as Finding 3. To restate the core distinction: `_cloud_prf`/`_counter_to_bytes` are *pure functions of caller-supplied, non-secret-to-the-cloud inputs* (`k1` is a client-issued, single-search, single-keyword token by construction — never `K_index` or any longer-lived secret). Duplicating them doesn't weaken anything cryptographically; HMAC-SHA256 needs no protection as an *algorithm*, only its *keys* need protection, and no vault-level key is duplicated into `cloud/`. The risk is entirely about future code drift (someone changes one side and forgets the other), not about anything an attacker could exploit today. The drift-detector test in `test_integration.py` is a genuinely effective safety net for that risk *as long as it keeps running* — recommend either keeping the current duplication with that test as a hard gate (document that the test must never be skipped/deleted), or doing the `common/` extraction from Finding 3 to remove the risk structurally. Both are legitimate; only the second is "no longer relies on someone remembering."

---

## 6. Readiness for the security/leakage demonstration phase

**Verdict: the project is architecturally ready for Phase 6 (security hardening & demo panel) — proceed, with two items folded into that phase's own stated scope rather than treated as separate rework:**

1. **Do Finding 1 (Argon2 param persistence) before or very early in Phase 6/7.** This isn't cosmetic — it's the one item here that can cause real, silent, permanent data loss, and it will most naturally get triggered by Phase 7's own benchmarking work if left unfixed. Small, contained change; fix it now while the cause is fresh context rather than after a confusing "why can't I unlock my demo vault" moment later.
2. **Do Finding 2 (AAD binding) as part of Phase 6 itself** — it's squarely "security hardening," the parameter is already plumbed through for exactly this purpose, and it strengthens the demo story ("we thought about ciphertext-swap tampering too, here's why it now fails") even though the formal threat model doesn't strictly require it.
3. **Findings 3–6 are genuinely optional** — good to mention in the report/viva as considered-and-consciously-scoped, not blocking anything. Finding 4 (sync the architecture doc) costs a few minutes and removes an easy "your code doesn't match your design doc" objection in the viva; do it before submission regardless of when Phase 6 lands.
4. Nothing found here should cause you to revisit Phases 1–4's core crypto (Section 4's list) — that work is correct, well-tested, and should be presented in the viva exactly as built.

Once Findings 1 and 2 are addressed, this is in good shape to move into building the "what the cloud sees" leakage-demonstration panel and the formal leakage write-up.
