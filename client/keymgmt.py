"""
client/keymgmt.py -- Password-based key derivation & sub-key management.

Everything here implements Section 04 of the architecture doc:

    password --Argon2id--> Master Key --HKDF(info)--> K_file, K_index

The client never stores a key. On "unlock" (wired up in a later phase)
it re-derives the Master Key from the password and a non-secret salt
fetched from the cloud's `meta` table, then immediately expands it into
the two sub-keys the rest of the system uses. Nothing in this file
touches disk.

Argon2id parameters
--------------------
Argon2id (RFC 9106, winner of the 2015 Password Hashing Competition) is
a memory-hard KDF: brute-forcing a password requires an attacker to pay
both CPU time *and* real memory per guess, which is what makes offline
dictionary attacks on a stolen salt expensive -- unlike a fast hash
(plain SHA-256) or a low-iteration PBKDF2, which an attacker with a GPU
or ASIC farm can grind through cheaply (Section 10, "Weak password ->
keys"). We default to OWASP's current baseline recommendation for
Argon2id:

    time_cost   = 3          iterations
    memory_cost = 65536 KiB  (64 MiB) per hash attempt
    parallelism = 4          lanes

These are intentionally tunable via Argon2Params rather than hardcoded,
because the "right" cost is a function of the hardware unlocking the
vault -- a later phase's benchmarks should confirm these land in the
"noticeable but not annoying" range (roughly 0.3-1s) on real hardware,
not just assume the OWASP numbers are correct for this machine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw

from .crypto import KEY_SIZE, hkdf_sha256

SALT_SIZE = 16

# OWASP baseline Argon2id parameters.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_PARALLELISM = 4

# HKDF domain-separation labels for the two sub-keys (Section 04).
# Versioned ("v1") so a future scheme change can't silently collide
# with these derivations if a key needs to be re-derived differently.
_INFO_K_FILE = b"vault:k_file:v1"
_INFO_K_INDEX = b"vault:k_index:v1"


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters. Frozen (immutable) because these are
    part of a vault's identity -- see the module docstring's note on
    versioning: changing them for an existing vault would silently
    change what password unlocks it."""

    time_cost: int = ARGON2_TIME_COST
    memory_cost_kib: int = ARGON2_MEMORY_COST_KIB
    parallelism: int = ARGON2_PARALLELISM


_DEFAULT_PARAMS = Argon2Params()


@dataclass
class KeySet:
    """The two sub-keys derived for one unlocked session.

    Held in memory only, for the lifetime of the unlocked session --
    never serialised, never written to disk (Section 04's "trap to
    avoid": storing a key defeats the entire at-rest guarantee Argon2id
    is supposed to provide).
    """

    k_file: bytes
    k_index: bytes

    def wipe(self) -> None:
        """Best-effort zeroing of key material on lock/logout.

        Caveat worth being upfront about, including in the viva:
        Python's `bytes` objects are immutable, so this can only
        rebind k_file/k_index to a new all-zero object -- it cannot
        overwrite the original bytes in place, and the interpreter may
        have left other copies behind (temporaries, string interning,
        a moved/copied buffer, swapped memory) that this can never
        reach. Treat it as shrinking the exposure window, not as a
        cryptographic guarantee. A hardened implementation would keep
        key material in a `bytearray`/`mlock`-ed buffer from the start
        instead of plain `bytes` -- named here as a known limitation
        rather than hidden.
        """
        self.k_file = b"\x00" * len(self.k_file)
        self.k_index = b"\x00" * len(self.k_index)


def generate_salt() -> bytes:
    """A fresh random salt for a new vault.

    Not secret -- it is stored in the cloud's `meta` table in
    plaintext (Section 08) -- it only needs to be unique per vault to
    defeat rainbow-table precomputation and to make sure two vaults
    with the same password still derive unrelated keys.
    """
    return os.urandom(SALT_SIZE)


def derive_master_key(password: str, salt: bytes, params: Argon2Params = _DEFAULT_PARAMS) -> bytes:
    """Argon2id(password, salt) -> 256-bit Master Key.

    Deterministic: the same password + salt + params always reproduce
    the same key -- this is what "unlock" relies on, since there is no
    separate password hash to check against (Section 04: we never
    store a key, only the salt). A different salt, a different
    password, or different params each produce an unrelated key.
    """
    if not isinstance(password, str) or password == "":
        raise ValueError("password must be a non-empty string")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"salt must be {SALT_SIZE} bytes, got {len(salt)}")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,  # Argon2*id* specifically -- the hybrid of 2i/2d
    )


def derive_subkeys(master_key: bytes) -> KeySet:
    """HKDF-SHA256(master_key, info=...) -> (K_file, K_index).

    salt=None is intentional here (see crypto.hkdf_sha256's docstring
    and the module docstring above): domain separation comes entirely
    from the distinct `info` labels, which is standard practice per
    RFC 5869 when expanding one already-high-entropy secret.
    """
    if len(master_key) != KEY_SIZE:
        raise ValueError(f"master_key must be {KEY_SIZE} bytes, got {len(master_key)}")

    k_file = hkdf_sha256(master_key, KEY_SIZE, salt=None, info=_INFO_K_FILE)
    k_index = hkdf_sha256(master_key, KEY_SIZE, salt=None, info=_INFO_K_INDEX)
    return KeySet(k_file=k_file, k_index=k_index)


def unlock(password: str, salt: bytes, params: Argon2Params = _DEFAULT_PARAMS) -> KeySet:
    """Convenience wrapper: password + salt -> ready-to-use KeySet.

    This is the single function client_app.py will call on unlock,
    once that phase exists -- the rest of the client should never call
    derive_master_key / derive_subkeys separately.
    """
    master_key = derive_master_key(password, salt, params)
    return derive_subkeys(master_key)
