"""Dual-key plausible-deniability encryption — the Doppelganger.

Implements a ``DoppelgangerNecromancer`` that embeds two independent
AES-256-GCM ciphertexts inside a single envelope.  The real key
decrypts the genuine payload; the decoy key decrypts a convincing
cover story.  An adversary who seizes the blob cannot prove — even
with unlimited computational resources — which plaintext is the
"real" one, because both keys produce valid GCM authentication tags
for their respective blocks.

Wire format (v3 dual)::

    [Magic b"LCH1" (4B)] [Version=3 (1B)] [Flags (1B)]
    [Decoy block len (2B)]
    [Decoy: Nonce (12B)] [Ct_decoy + Tag (...B)]
    [Real:  Nonce (12B)] [Ct_real + Tag (...B)]

The ``Decoy block len`` field counts the nonce + ciphertext + tag of
the decoy block so the receiver knows where the real block starts.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import pickle
import struct
import time
import zlib
from typing import Any

from cryptography.exceptions import InvalidTag

from .crypto import aes_decrypt, aes_encrypt
from .exceptions import (
    CorpseDeliveryError,
    MutilatedCorpseError,
    RottenCorpseError,
    WrongRealmError,
)

# ------------------------------------------------------------------
# Envelope constants
# ------------------------------------------------------------------
_MAGIC: bytes = b"LCH1"
_VERSION: int = 3
_HEADER_FORMAT: str = ">4sBBH"  # magic(4) + version(1) + flags(1) + split(2)
_HEADER_SIZE: int = struct.calcsize(_HEADER_FORMAT)
_NONCE_LENGTH: int = 12
_TTL_SIZE: int = 8

_FLAG_TTL: int = 0x01
_FLAG_STEALTH: int = 0x02
_FLAG_HWID: int = 0x04
_FLAG_DUAL: int = 0x20


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _stealth_mask(key: bytes) -> bytes:
    return hmac.new(key, b"amcrypt-stealth-mask", hashlib.sha256).digest()[:4]


def _apply_stealth_magic(magic: bytes, mask: bytes) -> bytes:
    return bytes(m ^ mask[i] for i, m in enumerate(magic))


def _pack_ttl(ttl_seconds: int) -> bytes:
    expiry = int(time.time()) + ttl_seconds
    return struct.pack(">Q", expiry)


def _unpack_ttl(ttl_raw: bytes) -> int:
    return struct.unpack(">Q", ttl_raw)[0]


def _secure_wipe(view: memoryview) -> None:
    if view.nbytes == 0:
        return
    buf = (ctypes.c_char * view.nbytes).from_buffer(view)
    ctypes.memset(ctypes.addressof(buf), 0, view.nbytes)


def _to_writable(data: bytes | bytearray) -> bytearray:
    if isinstance(data, bytearray):
        return data
    return bytearray(data)


# ------------------------------------------------------------------
# DoppelgangerNecromancer
# ------------------------------------------------------------------

class DoppelgangerNecromancer:
    """Dual-key serializer with plausible deniability.

    The ``kill`` method encrypts both a *real* and a *decoy* payload
    into a single binary blob.  The ``revive`` method decrypts using
    whichever key is provided:

    - **decoy_key** → returns the decoy object (cover story)
    - **real_key** → returns the real object (classified data)

    An attacker who obtains the blob and one key can decrypt their
    block but has zero cryptographic evidence that a second block
    exists.

    Example::

        doppel = DoppelgangerNecromancer()
        corpse = doppel.kill(
            real_obj=top_secret,
            decoy_obj={"status": "nothing here"},
            real_key=real_k,
            decoy_key=decoy_k,
        )
        assert doppel.revive(corpse, key=decoy_k) == {"status": "nothing here"}
        assert doppel.revive(corpse, key=real_k) == top_secret
    """

    def __init__(self) -> None:
        """Initialise the Doppelganger."""
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def kill(
        self,
        real_obj: Any,
        decoy_obj: Any,
        *,
        real_key: bytes,
        decoy_key: bytes,
        hwid: bytes | None = None,
        ttl_seconds: int | None = None,
        stealth: bool = False,
    ) -> bytes:
        """Serialize and dual-encrypt *real_obj* and *decoy_obj*.

        Each object is independently pickled, compressed, and encrypted
        under its own AES-256-GCM key.

        Args:
            real_obj:    The classified Python object.
            decoy_obj:   The cover-story Python object.
            real_key:    32-byte AES key for the real payload.
            decoy_key:   32-byte AES key for the decoy payload.
            hwid:        Optional hardware identifier for soul binding.
            ttl_seconds: Optional time-to-live in seconds.
            stealth:     When ``True`` the magic bytes are XOR-masked.

        Returns:
            A ``LCH1`` v3 binary envelope containing both ciphertexts.
        """
        for k, label in ((real_key, "real_key"), (decoy_key, "decoy_key")):
            if not isinstance(k, (bytes, bytearray)) or len(k) != 32:
                raise ValueError(f"{label} must be exactly 32 bytes")

        real_pickled = pickle.dumps(real_obj, protocol=pickle.HIGHEST_PROTOCOL)
        decoy_pickled = pickle.dumps(decoy_obj, protocol=pickle.HIGHEST_PROTOCOL)
        real_compressed = zlib.compress(real_pickled, level=9)
        decoy_compressed = zlib.compress(decoy_pickled, level=9)

        flags: int = _FLAG_DUAL

        real_plaintext = real_compressed
        decoy_plaintext = decoy_compressed
        if ttl_seconds is not None:
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be a positive integer")
            flags |= _FLAG_TTL
            ttl_raw = _pack_ttl(ttl_seconds)
            real_plaintext = ttl_raw + real_compressed
            decoy_plaintext = ttl_raw + decoy_compressed

        if hwid is not None:
            flags |= _FLAG_HWID

        nonce_d, ct_d = aes_encrypt(decoy_key, decoy_plaintext, hwid)
        nonce_r, ct_r = aes_encrypt(real_key, real_plaintext, hwid)

        # Secure wipe
        for buf in (real_pickled, decoy_pickled, real_compressed, decoy_compressed):
            b = _to_writable(buf)
            _secure_wipe(memoryview(b))

        return self._pack(nonce_d, ct_d, nonce_r, ct_r, flags, stealth, decoy_key)

    def revive(
        self,
        corpse: bytes,
        *,
        key: bytes,
        hwid: bytes | None = None,
        stealth: bool = False,
    ) -> Any:
        """Decrypt a dual-encrypted envelope.

        If *key* matches the decoy, the decoy object is returned.
        If *key* matches the real payload, the real object is returned.

        Args:
            corpse:  A ``LCH1`` v3 dual envelope.
            key:     The 32-byte decryption key (real or decoy).
            hwid:    Soul-binding hardware identifier.
            stealth: Must match the flag used during ``kill``.

        Returns:
            The decrypted Python object (real or decoy).

        Raises:
            WrongRealmError:       If the key matches neither block.
            MutilatedCorpseError:  If the envelope is corrupt.
            RottenCorpseError:     If the TTL has expired.
        """
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("key must be exactly 32 bytes")

        magic, version, flags, split = struct.unpack_from(_HEADER_FORMAT, corpse, 0)

        if not stealth and magic != _MAGIC:
            raise CorpseDeliveryError(
                f"Invalid magic bytes: expected {_MAGIC!r}, got {magic!r}"
            )
        if version != _VERSION:
            raise CorpseDeliveryError(f"Unsupported version: {version}")
        if not (flags & _FLAG_DUAL):
            raise CorpseDeliveryError("Envelope is not a dual-key payload")

        if flags & _FLAG_HWID and hwid is None:
            raise WrongRealmError(
                "This payload is soul-bound; hwid= must be provided"
            )

        # split = decoy block length (nonce + ct_d)
        decoy_end = _HEADER_SIZE + split
        decoy_block = corpse[_HEADER_SIZE:decoy_end]
        real_block = corpse[decoy_end:]

        nonce_d = decoy_block[:_NONCE_LENGTH]
        ct_d = decoy_block[_NONCE_LENGTH:]
        nonce_r = real_block[:_NONCE_LENGTH]
        ct_r = real_block[_NONCE_LENGTH:]

        # Try decoy first, then real
        plaintext: bytes | None = None
        for nonce, ct in [(nonce_d, ct_d), (nonce_r, ct_r)]:
            try:
                plaintext = aes_decrypt(key, nonce, ct, hwid)
                break
            except InvalidTag:
                continue

        if plaintext is None:
            raise WrongRealmError(
                "Key does not match either the real or decoy block"
            )

        if flags & _FLAG_TTL:
            if len(plaintext) < _TTL_SIZE:
                raise MutilatedCorpseError("TTL header truncated")
            expiry = _unpack_ttl(plaintext[:_TTL_SIZE])
            if time.time() > expiry:
                raise RottenCorpseError(f"Payload expired at timestamp {expiry}")
            plaintext = plaintext[_TTL_SIZE:]

        decompressed = zlib.decompress(plaintext)
        result = pickle.loads(decompressed)

        for buf in (decompressed, plaintext):
            b = _to_writable(buf)
            _secure_wipe(memoryview(b))

        return result

    # ------------------------------------------------------------------
    # Internal packing
    # ------------------------------------------------------------------

    def _pack(
        self,
        nonce_d: bytes,
        ct_d: bytes,
        nonce_r: bytes,
        ct_r: bytes,
        flags: int,
        stealth: bool,
        key: bytes,
    ) -> bytes:
        magic = _MAGIC
        if stealth:
            flags |= _FLAG_STEALTH
            mask = _stealth_mask(key)
            magic = _apply_stealth_magic(magic, mask)

        decoy_block = nonce_d + ct_d
        split = len(decoy_block)

        header = struct.pack(_HEADER_FORMAT, magic, _VERSION, flags, split)
        return header + decoy_block + nonce_r + ct_r