"""
client/crypto.py -- Trusted-client cryptographic primitives.

This module holds every low-level cryptographic operation used by the
Encrypted Cloud Vault. Nothing in here talks to the network or to disk;
it only transforms bytes. Keeping it this narrow is deliberate: it is
something we can unit-test exhaustively and reason about in isolation,
independent of Flask, SQLite, or anything else added in later phases.

Three primitives, one job each (see docs/architecture.html Section 04):

  * AES-256-GCM  -- confidentiality + integrity for file contents and
                    filenames.
  * HMAC-SHA256  -- the pseudorandom function F used (in a later phase)
                    to derive index labels and search tokens.
  * HKDF-SHA256  -- expands one master key into independent,
                    domain-separated sub-keys.

Design notes worth remembering for the viva:

  * AES-GCM nonces are 96 bits and MUST be unique per key. Reusing a
    nonce with the same key breaks both confidentiality and the
    authentication tag (Section 10, "GCM nonce reuse"). We generate a
    fresh random nonce with os.urandom on every call and never accept
    one from the caller -- there is no code path that lets a caller
    reuse a nonce by mistake.
  * We store `nonce || ciphertext_with_tag` as one blob. The
    `cryptography` library's AESGCM.encrypt() already appends the
    16-byte authentication tag to the ciphertext, so we don't handle
    the tag separately -- but decrypt() raises InvalidTag if a single
    byte anywhere in that blob was altered.
  * F(key, data) = HMAC-SHA256(key, data). HMAC is a proven PRF; using
    it for label/token generation is what keeps those values
    unpredictable to anyone without the key.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Sizes fixed by the architecture doc (Section 04).
KEY_SIZE = 32     # 256-bit keys everywhere
NONCE_SIZE = 12   # 96-bit GCM nonce -- the size the spec recommends
TAG_SIZE = 16     # AES-GCM authentication tag, appended by AESGCM.encrypt


class DecryptionError(Exception):
    """Raised when AES-GCM decryption fails: wrong key, wrong
    associated data, or the ciphertext/tag was tampered with or
    corrupted in transit. We deliberately collapse all three causes
    into one exception -- see aes_gcm_decrypt's docstring for why."""


def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Encrypt `plaintext` under `key` with a fresh random nonce.

    Returns nonce || ciphertext || tag, ready to store or send as one
    opaque blob -- exactly the `documents` table's
    nonce . ciphertext . tag layout from Section 08.

    `associated_data`, if given, is authenticated but not encrypted.
    Not used yet, but wired through now so a later phase can bind a
    blob to e.g. its doc_id without touching this function's contract.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, blob: bytes, associated_data: Optional[bytes] = None) -> bytes:
    """Inverse of aes_gcm_encrypt.

    Raises DecryptionError on any failure -- wrong key, wrong
    associated_data, or tampered/corrupted bytes -- rather than
    reporting *which* of those happened. GCM's tag check is designed
    to be all-or-nothing on purpose: a decrypt function that reveals
    "the tag was fine but the padding was wrong" (or similar) hands an
    attacker an oracle to grind through. We don't build one.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("ciphertext blob too short to contain a nonce and a tag")

    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise DecryptionError(
            "authentication failed: wrong key, wrong associated data, "
            "or the ciphertext was tampered with or corrupted"
        ) from exc


def prf(key: bytes, data: bytes) -> bytes:
    """F(key, data) = HMAC-SHA256(key, data).

    This is the PRF the architecture doc calls F everywhere an index
    label or a search token gets derived (Sections 05/06, implemented
    in a later phase). Deterministic: the same key + data always
    produces the same 32-byte output -- that determinism is exactly
    what makes search work, and exactly what the doc names as the
    scheme's main leakage (repeated searches are recognisable).
    """
    return hmac.new(key, data, hashlib.sha256).digest()


def hkdf_sha256(input_key_material: bytes, length: int, salt: Optional[bytes], info: bytes) -> bytes:
    """Expand `input_key_material` into `length` bytes of independent
    key material, domain-separated by `info`.

    Two different `info` values applied to the SAME input key material
    yield keys that are computationally independent of each other --
    this is what lets one master key safely produce K_file and
    K_index (Section 04) without a compromise of one implying anything
    about the other. `salt` may be None here: HKDF's salt argument is
    for domain-separating *independent* secrets, which does not apply
    when we are expanding one already-strong 256-bit master key (see
    keymgmt.derive_subkeys for where this is actually called).
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(input_key_material)
