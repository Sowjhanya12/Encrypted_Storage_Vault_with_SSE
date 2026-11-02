"""
tests/test_crypto.py -- Unit tests for client/crypto.py and client/keymgmt.py.

These are the "primitives are correct" tests from Section 13 of the
architecture doc. Every test here answers one concrete viva question:
"how do you know your building blocks aren't silently broken?" rather
than just "does the happy path run".
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from client.crypto import (  # noqa: E402
    KEY_SIZE,
    NONCE_SIZE,
    DecryptionError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_sha256,
    prf,
)
from client.keymgmt import (  # noqa: E402
    SALT_SIZE,
    Argon2Params,
    derive_master_key,
    derive_subkeys,
    generate_salt,
    unlock,
)

# Cheap Argon2 params so the suite runs in well under a second -- we are
# testing the *shape* of the KDF (determinism, sensitivity to inputs),
# not re-benchmarking production hardness on every run. One test near
# the bottom exercises the real default params separately.
FAST_PARAMS = Argon2Params(time_cost=1, memory_cost_kib=8, parallelism=1)


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

class TestAesGcm:
    def test_round_trip_recovers_plaintext(self):
        key = os.urandom(KEY_SIZE)
        plaintext = b"the quick brown fox jumps over the lazy dog"
        blob = aes_gcm_encrypt(key, plaintext)
        assert aes_gcm_decrypt(key, blob) == plaintext

    def test_round_trip_empty_plaintext(self):
        # GCM supports zero-length plaintext (auth-only); confirm the
        # wrapper doesn't choke on this edge case.
        key = os.urandom(KEY_SIZE)
        blob = aes_gcm_encrypt(key, b"")
        assert aes_gcm_decrypt(key, blob) == b""

    def test_nonce_is_random_per_call(self):
        # Section 10: GCM nonce reuse under one key is catastrophic.
        # Confirm we never hand out the same nonce twice for one key.
        key = os.urandom(KEY_SIZE)
        blobs = [aes_gcm_encrypt(key, b"same message") for _ in range(50)]
        nonces = {b[:NONCE_SIZE] for b in blobs}
        assert len(nonces) == 50

    def test_ciphertext_does_not_contain_plaintext(self):
        key = os.urandom(KEY_SIZE)
        plaintext = b"not visible in the output"
        blob = aes_gcm_encrypt(key, plaintext)
        assert plaintext not in blob

    def test_tamper_flip_tag_byte_fails(self):
        key = os.urandom(KEY_SIZE)
        blob = bytearray(aes_gcm_encrypt(key, b"integrity matters"))
        blob[-1] ^= 0x01  # flip a bit inside the authentication tag
        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(key, bytes(blob))

    def test_tamper_flip_ciphertext_body_byte_fails(self):
        key = os.urandom(KEY_SIZE)
        blob = bytearray(aes_gcm_encrypt(key, b"integrity matters" * 3))
        blob[NONCE_SIZE] ^= 0x01  # flip the first ciphertext byte, not the tag
        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(key, bytes(blob))

    def test_wrong_key_fails(self):
        key_a = os.urandom(KEY_SIZE)
        key_b = os.urandom(KEY_SIZE)
        blob = aes_gcm_encrypt(key_a, b"only key_a should open this")
        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(key_b, blob)

    def test_associated_data_must_match(self):
        key = os.urandom(KEY_SIZE)
        blob = aes_gcm_encrypt(key, b"payload", associated_data=b"doc_id:42")
        assert aes_gcm_decrypt(key, blob, associated_data=b"doc_id:42") == b"payload"
        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(key, blob, associated_data=b"doc_id:43")
        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(key, blob)  # AAD silently omitted should also fail

    def test_rejects_wrong_key_length(self):
        with pytest.raises(ValueError):
            aes_gcm_encrypt(b"too short", b"data")

    def test_rejects_truncated_blob(self):
        key = os.urandom(KEY_SIZE)
        with pytest.raises(DecryptionError):
            aes_gcm_decrypt(key, b"short")


# ---------------------------------------------------------------------------
# HMAC-SHA256 PRF (F)
# ---------------------------------------------------------------------------

class TestPrf:
    def test_deterministic(self):
        key = os.urandom(KEY_SIZE)
        assert prf(key, b"report") == prf(key, b"report")

    def test_different_data_different_output(self):
        key = os.urandom(KEY_SIZE)
        assert prf(key, b"report") != prf(key, b"invoice")

    def test_different_key_different_output(self):
        assert prf(os.urandom(KEY_SIZE), b"report") != prf(os.urandom(KEY_SIZE), b"report")

    def test_output_is_32_bytes(self):
        assert len(prf(os.urandom(KEY_SIZE), b"x")) == 32

    def test_counter_labels_are_distinct(self):
        # This is exactly how indexer.py will call F in a later phase:
        # F(K1, counter) for counter = 0, 1, 2, ...
        k1 = os.urandom(KEY_SIZE)
        labels = [prf(k1, str(i).encode()) for i in range(100)]
        assert len(set(labels)) == 100


# ---------------------------------------------------------------------------
# HKDF-SHA256
# ---------------------------------------------------------------------------

class TestHkdf:
    def test_deterministic(self):
        ikm = os.urandom(32)
        a = hkdf_sha256(ikm, 32, salt=None, info=b"info-a")
        b = hkdf_sha256(ikm, 32, salt=None, info=b"info-a")
        assert a == b

    def test_domain_separation_by_info(self):
        ikm = os.urandom(32)
        a = hkdf_sha256(ikm, 32, salt=None, info=b"k_file")
        b = hkdf_sha256(ikm, 32, salt=None, info=b"k_index")
        assert a != b

    def test_different_input_key_material_different_output(self):
        a = hkdf_sha256(os.urandom(32), 32, salt=None, info=b"same-info")
        b = hkdf_sha256(os.urandom(32), 32, salt=None, info=b"same-info")
        assert a != b

    def test_requested_length_is_honoured(self):
        ikm = os.urandom(32)
        assert len(hkdf_sha256(ikm, 16, salt=None, info=b"x")) == 16
        assert len(hkdf_sha256(ikm, 64, salt=None, info=b"x")) == 64


# ---------------------------------------------------------------------------
# Argon2id master-key derivation
# ---------------------------------------------------------------------------

class TestMasterKeyDerivation:
    def test_deterministic_same_password_and_salt(self):
        salt = generate_salt()
        a = derive_master_key("correct horse battery staple", salt, FAST_PARAMS)
        b = derive_master_key("correct horse battery staple", salt, FAST_PARAMS)
        assert a == b

    def test_different_salt_different_key(self):
        password = "correct horse battery staple"
        a = derive_master_key(password, generate_salt(), FAST_PARAMS)
        b = derive_master_key(password, generate_salt(), FAST_PARAMS)
        assert a != b

    def test_different_password_different_key(self):
        salt = generate_salt()
        a = derive_master_key("password one", salt, FAST_PARAMS)
        b = derive_master_key("password two", salt, FAST_PARAMS)
        assert a != b

    def test_master_key_is_256_bits(self):
        key = derive_master_key("x", generate_salt(), FAST_PARAMS)
        assert len(key) == KEY_SIZE

    def test_salt_is_16_bytes(self):
        assert len(generate_salt()) == SALT_SIZE

    def test_rejects_empty_password(self):
        with pytest.raises(ValueError):
            derive_master_key("", generate_salt(), FAST_PARAMS)

    def test_rejects_wrong_salt_length(self):
        with pytest.raises(ValueError):
            derive_master_key("x", b"too-short", FAST_PARAMS)

    def test_default_production_params_are_self_consistent(self):
        # Exercised once, deliberately: production Argon2id params are
        # slow on purpose (~64 MiB, 3 passes). This single test doubles
        # as a rough timing sanity-check without slowing the suite down.
        salt = generate_salt()
        a = derive_master_key("production password", salt)
        b = derive_master_key("production password", salt)
        assert a == b
        assert len(a) == KEY_SIZE


class TestSubkeyDerivation:
    def test_k_file_and_k_index_differ(self):
        master = derive_master_key("x", generate_salt(), FAST_PARAMS)
        keys = derive_subkeys(master)
        assert keys.k_file != keys.k_index

    def test_deterministic_for_same_master_key(self):
        master = derive_master_key("x", generate_salt(), FAST_PARAMS)
        a = derive_subkeys(master)
        b = derive_subkeys(master)
        assert a.k_file == b.k_file
        assert a.k_index == b.k_index

    def test_different_master_key_different_subkeys(self):
        a = derive_subkeys(derive_master_key("x", generate_salt(), FAST_PARAMS))
        b = derive_subkeys(derive_master_key("y", generate_salt(), FAST_PARAMS))
        assert a.k_file != b.k_file
        assert a.k_index != b.k_index

    def test_subkeys_are_256_bits(self):
        keys = derive_subkeys(derive_master_key("x", generate_salt(), FAST_PARAMS))
        assert len(keys.k_file) == KEY_SIZE
        assert len(keys.k_index) == KEY_SIZE

    def test_rejects_wrong_master_key_length(self):
        with pytest.raises(ValueError):
            derive_subkeys(b"too short")

    def test_wipe_zeroes_the_keyset(self):
        keys = derive_subkeys(derive_master_key("x", generate_salt(), FAST_PARAMS))
        keys.wipe()
        assert keys.k_file == b"\x00" * KEY_SIZE
        assert keys.k_index == b"\x00" * KEY_SIZE


# ---------------------------------------------------------------------------
# unlock() end-to-end (password -> usable keys)
# ---------------------------------------------------------------------------

class TestUnlockEndToEnd:
    def test_same_password_and_salt_unlocks_to_same_keys(self):
        salt = generate_salt()
        a = unlock("vault password", salt, FAST_PARAMS)
        b = unlock("vault password", salt, FAST_PARAMS)
        assert a.k_file == b.k_file
        assert a.k_index == b.k_index

    def test_wrong_password_unlocks_to_different_keys(self):
        salt = generate_salt()
        correct = unlock("vault password", salt, FAST_PARAMS)
        wrong = unlock("not the password", salt, FAST_PARAMS)
        assert correct.k_file != wrong.k_file
        assert correct.k_index != wrong.k_index

    def test_unlock_keys_actually_work_for_encryption(self):
        # Closest thing to an integration test Phase 1 can have: derive
        # keys from a password via the real unlock() path, encrypt with
        # K_file, decrypt with the same K_file.
        salt = generate_salt()
        keys = unlock("vault password", salt, FAST_PARAMS)
        blob = aes_gcm_encrypt(keys.k_file, b"a real file's contents")
        assert aes_gcm_decrypt(keys.k_file, blob) == b"a real file's contents"
