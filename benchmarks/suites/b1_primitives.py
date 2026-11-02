"""
Suite B1 -- cryptographic primitive cost.

Measures the primitives the vault is actually built from, in process, with
no HTTP and no SQLite, so the numbers are the cost of the cryptography and
nothing else. Every function timed here is imported from `client/`; none
of it is reimplemented for measurement. What this suite exists to answer
is the question the architecture doc asserts without evidence in Section
14 ("AES-GCM is fast; crypto is not the bottleneck") -- an assertion that
is only worth anything once it is a measurement.

What is measured, and against which implementation
--------------------------------------------------
  argon2id_derive_master_key   client.keymgmt.derive_master_key
  vault_unlock                 client.keymgmt.unlock  (Argon2id + HKDF split)
  argon2id_parameter_sweep     client.keymgmt.derive_master_key at other costs
  hkdf_derive_subkeys          client.keymgmt.derive_subkeys
  hkdf_expand                  client.crypto.hkdf_sha256
  aes_gcm_encrypt              client.crypto.aes_gcm_encrypt
  aes_gcm_decrypt              client.crypto.aes_gcm_decrypt
  hmac_prf_keyword_input       client.crypto.prf  (F(K_index, "1"||w))
  hmac_prf_counter_input       client.crypto.prf  (F(K1, counter))

Why Argon2id is timed differently from everything else
------------------------------------------------------
Argon2id is deliberately expensive -- that is its entire purpose -- and it
runs about five orders of magnitude slower than the other primitives here.
It is therefore never batched (a batch would only add up work that is
already far above the clock floor), it gets its own repeat count from the
profile, and it is reported in its own table. Averaging a memory-hard KDF
into a table of microsecond operations would make both numbers useless.

The parameter sweep is READ-ONLY
--------------------------------
The sweep measures what other Argon2id cost settings would cost. It does
not change the application's settings and must not be read as a
recommendation to. Audit finding M1 is still open: the cost parameters are
not persisted in the vault's `meta` table, so changing the compiled-in
constants would silently make every existing vault permanently
undecryptable -- indistinguishably from a wrong password. Any tuning is
conditional on M1 being fixed first; the report says so next to the curve.
"""

from __future__ import annotations

import os
from typing import Dict

from ..config import Profile
from ..harness.recorder import Recorder
from ..harness.timing import adaptive_measure, measure, timer_resolution

from client.crypto import KEY_SIZE, NONCE_SIZE, TAG_SIZE, aes_gcm_decrypt, aes_gcm_encrypt, hkdf_sha256, prf
from client.keymgmt import ARGON2_PARALLELISM, Argon2Params, derive_master_key, derive_subkeys, unlock

SUITE_ID = "b1_primitives"
TITLE = "Cryptographic primitive cost"

# A fixed password and salt so the KDF work is identical in every run. Not
# a secret: no benchmark vault holds real data (see harness/vault.py).
_PASSWORD = "benchmark-vault-password"
_SALT = bytes(range(16))

# Representative PRF inputs, matching the two places F is actually called:
# once per keyword when deriving K1/K2 (indexer.keyword_label_key), and once
# per posting when deriving a label (F(K1, counter)).
_KEYWORD_INPUT = b"1" + b"encryption"
_COUNTER_INPUT = (7).to_bytes(8, "big")


def _check(condition: bool, message: str) -> None:
    """Correctness gate. A benchmark that measures a broken code path
    produces a fast, confident, meaningless number -- so every timed
    operation is verified to be doing its job before its samples are
    recorded."""
    if not condition:
        raise AssertionError(f"B1 correctness gate failed: {message}")


def run(recorder: Recorder, profile: Profile) -> dict:
    resolution = timer_resolution()
    checks = []

    # -- Argon2id, timed on its own terms ---------------------------------
    keys_a = unlock(_PASSWORD, _SALT)
    keys_b = unlock(_PASSWORD, _SALT)
    _check(keys_a.k_file == keys_b.k_file and keys_a.k_index == keys_b.k_index,
           "unlock is not deterministic for the same password and salt")
    _check(keys_a.k_file != keys_a.k_index, "HKDF returned identical sub-keys")
    checks.append("unlock determinism and sub-key independence verified before timing")

    production = Argon2Params()
    m = measure(
        lambda: derive_master_key(_PASSWORD, _SALT, production),
        repeats=profile.kdf_repeats,
        warmup=profile.kdf_warmup,
        batch=1,
    )
    recorder.add_measurement(
        SUITE_ID, "argon2id_derive_master_key",
        {
            "time_cost": production.time_cost,
            "memory_cost_kib": production.memory_cost_kib,
            "parallelism": production.parallelism,
            "shipped_parameters": True,
        },
        m,
        notes=(
            "client.keymgmt.derive_master_key at the parameters the application "
            "ships with. Never batched: Argon2id is intentionally slow and is "
            "far above the clock floor."
        ),
    )

    m = measure(
        lambda: unlock(_PASSWORD, _SALT, production),
        repeats=profile.kdf_repeats,
        warmup=profile.kdf_warmup,
        batch=1,
    )
    recorder.add_measurement(
        SUITE_ID, "vault_unlock",
        {
            "time_cost": production.time_cost,
            "memory_cost_kib": production.memory_cost_kib,
            "parallelism": production.parallelism,
            "shipped_parameters": True,
        },
        m,
        notes=(
            "client.keymgmt.unlock -- the complete user-visible unlock: Argon2id "
            "followed by the HKDF sub-key split. This is the latency a person "
            "actually waits for."
        ),
    )

    # -- Argon2id parameter sweep (read-only; see the module docstring) ----
    for memory_kib in profile.kdf_sweep_memory_kib:
        for time_cost in profile.kdf_sweep_time_cost:
            params = Argon2Params(
                time_cost=time_cost,
                memory_cost_kib=memory_kib,
                parallelism=ARGON2_PARALLELISM,
            )
            m = measure(
                lambda p=params: derive_master_key(_PASSWORD, _SALT, p),
                repeats=profile.kdf_sweep_repeats,
                warmup=1,
                batch=1,
            )
            recorder.add_measurement(
                SUITE_ID, "argon2id_parameter_sweep",
                {
                    "time_cost": time_cost,
                    "memory_cost_kib": memory_kib,
                    "parallelism": ARGON2_PARALLELISM,
                    "shipped_parameters": (
                        time_cost == production.time_cost
                        and memory_kib == production.memory_cost_kib
                    ),
                },
                m,
                notes=(
                    "Read-only exploration of alternative cost settings. NOT a "
                    "recommendation: audit finding M1 (cost parameters are not "
                    "persisted in the vault's meta table) is still open, so "
                    "changing the shipped constants would silently render "
                    "existing vaults undecryptable."
                ),
            )

    # -- HKDF ---------------------------------------------------------------
    master_key = derive_master_key(_PASSWORD, _SALT, production)
    subkeys = derive_subkeys(master_key)
    _check(len(subkeys.k_file) == KEY_SIZE and len(subkeys.k_index) == KEY_SIZE,
           "derive_subkeys did not return two 256-bit keys")
    checks.append("HKDF sub-key lengths verified")

    m, prov = adaptive_measure(
        lambda: derive_subkeys(master_key),
        repeats=profile.micro_repeats,
        warmup=profile.default_warmup,
        resolution_s=resolution,
        max_batch=profile.micro_batch,
    )
    recorder.add_measurement(
        SUITE_ID, "hkdf_derive_subkeys", {"expansions": 2, **prov}, m,
        notes="client.keymgmt.derive_subkeys -- two HKDF-SHA256 expansions. " + prov["batched_reason"],
    )

    m, prov = adaptive_measure(
        lambda: hkdf_sha256(master_key, KEY_SIZE, None, b"vault:benchmark:v1"),
        repeats=profile.micro_repeats,
        warmup=profile.default_warmup,
        resolution_s=resolution,
        max_batch=profile.micro_batch,
    )
    recorder.add_measurement(
        SUITE_ID, "hkdf_expand", {"output_bytes": KEY_SIZE, **prov}, m,
        notes="client.crypto.hkdf_sha256, one 32-byte expansion. " + prov["batched_reason"],
    )

    # -- AES-256-GCM --------------------------------------------------------
    key = subkeys.k_file
    for size in profile.aead_sizes_bytes:
        plaintext = os.urandom(size)
        blob = aes_gcm_encrypt(key, plaintext)
        _check(aes_gcm_decrypt(key, blob) == plaintext,
               f"AES-GCM round trip failed at {size} bytes")
        _check(len(blob) == size + NONCE_SIZE + TAG_SIZE,
               f"unexpected ciphertext length at {size} bytes: {len(blob)}")

        m, prov = adaptive_measure(
            lambda: aes_gcm_encrypt(key, plaintext),
            repeats=profile.aead_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, "aes_gcm_encrypt", {"payload_bytes": size, **prov}, m,
            notes=(
                "client.crypto.aes_gcm_encrypt, fresh random nonce per call "
                "(the implementation never accepts a caller-supplied one). "
                + prov["batched_reason"]
            ),
        )

        m, prov = adaptive_measure(
            lambda: aes_gcm_decrypt(key, blob),
            repeats=profile.aead_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, "aes_gcm_decrypt", {"payload_bytes": size, **prov}, m,
            notes=(
                "client.crypto.aes_gcm_decrypt including the GCM tag check -- "
                "authentication is not a separate step that could be omitted. "
                + prov["batched_reason"]
            ),
        )

        recorder.add_scalar(
            SUITE_ID, "aes_gcm_ciphertext_bytes", {"payload_bytes": size},
            len(blob), "bytes",
            notes="nonce (12) + ciphertext + tag (16) as stored -- a measured length, not a formula",
        )

    checks.append(f"AES-GCM round trip and ciphertext length verified at {len(profile.aead_sizes_bytes)} sizes")

    # -- HMAC-SHA256 PRF ----------------------------------------------------
    _check(prf(key, _KEYWORD_INPUT) == prf(key, _KEYWORD_INPUT), "PRF is not deterministic")
    _check(len(prf(key, _KEYWORD_INPUT)) == 32, "PRF output is not 32 bytes")
    checks.append("PRF determinism and output length verified")

    for label, data in (("keyword", _KEYWORD_INPUT), ("counter", _COUNTER_INPUT)):
        m, prov = adaptive_measure(
            lambda d=data: prf(key, d),
            repeats=profile.micro_repeats,
            warmup=profile.default_warmup,
            resolution_s=resolution,
            max_batch=profile.micro_batch,
        )
        recorder.add_measurement(
            SUITE_ID, f"hmac_prf_{label}_input",
            {"input_bytes": len(data), **prov}, m,
            notes=(
                ("F(K_index, '1'||w) -- once per keyword at index build and once per search."
                 if label == "keyword" else
                 "F(K1, counter) -- once per posting at index build, and once per counter "
                 "in the cloud's search loop.")
                + " " + prov["batched_reason"]
            ),
        )

    return {
        "measures": [
            "argon2id_derive_master_key", "vault_unlock", "argon2id_parameter_sweep",
            "hkdf_derive_subkeys", "hkdf_expand", "aes_gcm_encrypt", "aes_gcm_decrypt",
            "aes_gcm_ciphertext_bytes", "hmac_prf_keyword_input", "hmac_prf_counter_input",
        ],
        "implementations_under_test": [
            "client.keymgmt.derive_master_key", "client.keymgmt.unlock",
            "client.keymgmt.derive_subkeys", "client.crypto.hkdf_sha256",
            "client.crypto.aes_gcm_encrypt", "client.crypto.aes_gcm_decrypt",
            "client.crypto.prf",
        ],
        "correctness_gates": checks,
        "argon2_sweep_is_read_only": True,
        "clock_resolution_seconds": resolution,
    }
