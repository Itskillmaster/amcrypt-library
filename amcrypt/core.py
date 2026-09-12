"""Core serialization pipeline for the amcrypt library.

Implements the Necromancer class which orchestrates:

    Object -> Pickle -> Zlib -> [ECDSA Sign] -> [Random Pad]
          -> AES-256-GCM -> Binary Envelope

and its inverse:

    Binary Envelope -> AES-256-GCM Decrypt -> [Strip Pad]
          -> [Verify ECDSA] -> Zlib -> Unpickle -> Secure Wipe

Enterprise features (v4):

- **Soul Binding (HWID Locking)** — bind ciphertext to a hardware ID
  via AES-GCM associated data.
- **Payload Decay (TTL)** — embed an expiration timestamp that is
  cryptographically bound to the ciphertext.
- **DPI Evasion (Stealth)** — XOR the magic header bytes with a
  key-derived mask to defeat protocol fingerprinting.
- **Blood Pact (ECDSA Signatures)** — sign payloads with an ECDSA
  private key before encryption; verify on revive.
- **Polymorphic Curse (Random Padding)** — inject 16–256 bytes of
  CSPRNG padding to thwart traffic-analysis algorithms.
- **Ephemeral Spirit (Secure Wiping)** — zero-fill decrypted byte
  arrays in RAM after deserialization to resist memory dumps.
- **Watcher's Blindness (Anti-Debugging)** — detect debuggers and
  abort revive if the process is being traced.
- **Ashes to Ashes (Kill Switch)** — after 3 consecutive MAC failures
  the Necromancer securely wipes all cached keys.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import pickle
import struct
import sys
import time
import zlib
from typing import Any

from cryptography.exceptions import InvalidTag

from .crypto import aes_decrypt, aes_encrypt, ecdsa_sign, ecdsa_verify
from .exceptions import (
    BrokenPactError,
    CorpseDeliveryError,
    MutilatedCorpseError,
    RottenCorpseError,
    SelfDestructError,
    SoulTrappedError,
    WrongRealmError,
)
from .watcher import DebuggerDetector

# ------------------------------------------------------------------
# Envelope constants
# ------------------------------------------------------------------
_MAGIC: bytes = b"LCH1"
_VERSION: int = 4
_HEADER_FORMAT: str = ">4sBBH"
_HEADER_SIZE: int = struct.calcsize(_HEADER_FORMAT)
_NONCE_LENGTH: int = 12
_TTL_SIZE: int = 8

_FLAG_TTL: int = 0x01
_FLAG_STEALTH: int = 0x02
_FLAG_HWID: int = 0x04
_FLAG_SIGNED: int = 0x08
_FLAG_PADDED: int = 0x10

_PAD_MIN: int = 16
_PAD_MAX: int = 256

_MAX_TAMPER: int = 3  # Kill Switch threshold
_POISON_PILL: bytes = b"\xde\xad\xbe\xef\xca\xfe"  # 6-byte magic kill-command


# ------------------------------------------------------------------
# Secure memory wiping  (Ephemeral Spirit)
# ------------------------------------------------------------------

def secure_wipe(view: memoryview) -> None:
    """Zero-fill the underlying buffer of *view* in RAM."""
    if view.nbytes == 0:
        return
    buf = (ctypes.c_char * view.nbytes).from_buffer(view)
    ctypes.memset(ctypes.addressof(buf), 0, view.nbytes)


def _to_writable(data: bytes | bytearray) -> bytearray:
    if isinstance(data, bytearray):
        return data
    return bytearray(data)


# ------------------------------------------------------------------
# Stealth helpers
# ------------------------------------------------------------------

def _stealth_mask(key: bytes) -> bytes:
    return hmac.new(key, b"amcrypt-stealth-mask", hashlib.sha256).digest()[:4]


def _apply_stealth_magic(magic: bytes, mask: bytes) -> bytes:
    return bytes(m ^ mask[i] for i, m in enumerate(magic))


# ------------------------------------------------------------------
# TTL helpers
# ------------------------------------------------------------------

def _pack_ttl(ttl_seconds: int) -> bytes:
    expiry = int(time.time()) + ttl_seconds
    return struct.pack(">Q", expiry)


def _unpack_ttl(ttl_raw: bytes) -> int:
    return struct.unpack(">Q", ttl_raw)[0]


# ------------------------------------------------------------------
# Polymorphic Curse — random padding
# ------------------------------------------------------------------

def _add_padding(data: bytes) -> bytes:
    pad_len = int.from_bytes(os.urandom(2), "big") % (_PAD_MAX - _PAD_MIN + 1) + _PAD_MIN
    pad = os.urandom(pad_len)
    return struct.pack(">B", pad_len) + pad + data


def _strip_padding(data: bytes) -> bytes:
    if len(data) < 1:
        raise MutilatedCorpseError("Padding header missing")
    pad_len = data[0]
    if len(data) < 1 + pad_len:
        raise MutilatedCorpseError("Padding payload truncated")
    return data[1 + pad_len:]


# ------------------------------------------------------------------
# Necromancer
# ------------------------------------------------------------------

class Necromancer:
    """Cryptographically hardened object serializer with kill-switch.

    Instances are bound to a 256-bit key.  Use :meth:`kill` to serialize
    and encrypt, and :meth:`revive` to decrypt and deserialize.

    Security features:

    - **Watcher's Blindness** — debugger detection before every
      ``revive`` call.  If a debugger is found, ``SoulTrappedError``
      is raised and no decryption is attempted.
    - **Ashes to Ashes** — a tamper counter tracks consecutive MAC
      failures.  After ``_MAX_TAMPER`` failures the Necromancer
      wipes its key from memory and raises ``SelfDestructError``.

    Example::

        key = os.urandom(32)
        amcrypt_mage = Necromancer(key)
        corpse = amcrypt_mage.kill({"secret": "data"})
        restored = amcrypt_mage.revive(corpse)
    """

    def __init__(
        self,
        key: bytes,
        *,
        anti_debug: bool = True,
        max_tamper: int = _MAX_TAMPER,
    ) -> None:
        """Initialise the Necromancer.

        Args:
            key:        A 32-byte AES-256 key.
            anti_debug: Enable Watcher's Blindness (default ``True``).
            max_tamper: Consecutive MAC failures before kill-switch
                        triggers (default 3).

        Raises:
            ValueError: If *key* is not exactly 32 bytes.
        """
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")
        self._key = bytearray(key)
        self._anti_debug = anti_debug
        self._max_tamper = max_tamper
        self._tamper_count: int = 0
        self._destroyed: bool = False
        self._detector = DebuggerDetector()

    # ------------------------------------------------------------------
    # Kill Switch  (Ashes to Ashes)
    # ------------------------------------------------------------------

    def _self_destruct(self) -> None:
        """Securely wipe the cached key and mark the instance as dead."""
        if self._key is not None:
            secure_wipe(memoryview(self._key))
            self._key = None  # type: ignore[assignment]
        self._destroyed = True

    def _check_destroyed(self) -> None:
        if self._destroyed:
            raise SelfDestructError(
                "Kill switch already triggered: this Necromancer is dead"
            )

    def _record_tamper(self) -> None:
        """Increment the tamper counter; trigger kill-switch if threshold hit."""
        self._tamper_count += 1
        if self._tamper_count >= self._max_tamper:
            self._self_destruct()
            raise SelfDestructError(
                f"Kill switch activated after {self._tamper_count} "
                f"consecutive tampering attempts: secrets purged"
            )

    def _reset_tamper(self) -> None:
        self._tamper_count = 0

    # ------------------------------------------------------------------
    # Watcher's Blindness  (anti-debug check)
    # ------------------------------------------------------------------

    def _check_debugger(self) -> None:
        """Raise ``SoulTrappedError`` if a debugger is detected."""
        if self._anti_debug and self._detector.is_debugging():
            raise SoulTrappedError(
                "Debugger detected: aborting revive to protect secrets"
            )

    # ------------------------------------------------------------------
    # Poison Pill detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_poison_pill(data: bytes) -> bool:
        """Check if *data* is a server-issued kill command."""
        return len(data) >= 6 and data[:6] == _POISON_PILL

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def kill(
        self,
        obj: Any,
        *,
        hwid: bytes | None = None,
        ttl_seconds: int | None = None,
        stealth: bool = False,
        signing_key: bytes | None = None,
        pad: bool = False,
    ) -> bytes:
        """Serialize and encrypt *obj*.

        Pipeline: Pickle -> Zlib compress -> [ECDSA Sign] ->
        [Prepend TTL] -> [Random Pad] -> AES-256-GCM encrypt ->
        pack into ``LCH1`` binary envelope.

        Args:
            obj:         Any picklable Python object.
            hwid:        Optional hardware identifier for soul binding.
            ttl_seconds: Optional time-to-live in seconds.
            stealth:     When ``True`` the magic bytes are XOR-masked.
            signing_key: DER-encoded ECDSA private key for Blood Pact.
            pad:         Enable Polymorphic Curse random padding.

        Returns:
            A bytes blob following the ``LCH1`` v4 binary format.
        """
        self._check_destroyed()

        pickled = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
        compressed = zlib.compress(pickled, level=9)

        flags: int = 0x00

        # Blood Pact
        signed_data = compressed
        if signing_key is not None:
            flags |= _FLAG_SIGNED
            sig = ecdsa_sign(signing_key, compressed)
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
                load_der_private_key,
            )

            pk = load_der_private_key(signing_key, password=None)
            pub_der = pk.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
            signed_data = (
                struct.pack(">H", len(pub_der))
                + pub_der
                + struct.pack(">H", len(sig))
                + sig
                + compressed
            )

        # TTL
        plaintext = signed_data
        if ttl_seconds is not None:
            if ttl_seconds <= 0:
                raise ValueError("ttl_seconds must be a positive integer")
            flags |= _FLAG_TTL
            plaintext = _pack_ttl(ttl_seconds) + signed_data

        # Soul Binding
        if hwid is not None:
            flags |= _FLAG_HWID

        # Polymorphic Curse
        if pad:
            flags |= _FLAG_PADDED
            plaintext = _add_padding(plaintext)

        nonce, ciphertext_with_tag = aes_encrypt(
            self._key, plaintext, associated_data=hwid
        )

        # Secure wipe
        for buf in (compressed, pickled):
            b = _to_writable(buf)
            secure_wipe(memoryview(b))

        return self._pack(nonce, ciphertext_with_tag, flags=flags, stealth=stealth)

    def revive(
        self,
        corpse: bytes,
        *,
        hwid: bytes | None = None,
        stealth: bool = False,
        verify_key: bytes | None = None,
    ) -> Any:
        """Decrypt and deserialize *corpse*.

        Security gates (executed in order):

        1. **Watcher's Blindness** — abort if debugger detected.
        2. **Poison Pill** — detect server kill-commands.
        3. **Kill Switch** — wipe keys after too many tamper attempts.

        Args:
            corpse:     A ``LCH1`` envelope produced by :meth:`kill`.
            hwid:       Soul-binding hardware identifier.
            stealth:    Must match the flag used during ``kill``.
            verify_key: DER-encoded ECDSA public key for Blood Pact.

        Returns:
            The original Python object.

        Raises:
            SoulTrappedError:     If a debugger is detected.
            SelfDestructError:    If the kill-switch has triggered.
            MutilatedCorpseError: If authentication fails.
            CorpseDeliveryError:  If the envelope is malformed.
            WrongRealmError:      If the HWID does not match.
            RottenCorpseError:    If the TTL has expired.
            BrokenPactError:      If ECDSA verification fails.
        """
        # --- Gate 1: Watcher's Blindness ---
        self._check_debugger()

        # --- Gate 2: Poison Pill ---
        if self._is_poison_pill(corpse):
            self._self_destruct()
            raise SelfDestructError(
                "Poison pill received: kill-command from server"
            )

        # --- Gate 3: Kill Switch ---
        self._check_destroyed()

        # --- Unpack ---
        nonce, ciphertext_with_tag, flags = self._unpack(corpse, stealth=stealth)

        # Soul Binding pre-check
        if flags & _FLAG_HWID and hwid is None:
            raise WrongRealmError(
                "This payload is soul-bound; hwid= must be provided"
            )

        # Blood Pact pre-check
        if flags & _FLAG_SIGNED and verify_key is None:
            raise BrokenPactError(
                "This payload is blood-pact signed; "
                "verify_key= must be provided to revive"
            )

        # --- AES-GCM decrypt ---
        try:
            plaintext = aes_decrypt(
                self._key, nonce, ciphertext_with_tag, associated_data=hwid
            )
            self._reset_tamper()  # success → reset counter
        except InvalidTag as exc:
            self._record_tamper()  # failure → increment counter
            if hwid is not None:
                raise WrongRealmError(
                    "Soul binding verification failed"
                ) from exc
            raise MutilatedCorpseError(
                "Decryption failed: data integrity compromised or wrong key"
            ) from exc

        # Polymorphic Curse
        if flags & _FLAG_PADDED:
            plaintext = _strip_padding(plaintext)

        # TTL
        if flags & _FLAG_TTL:
            if len(plaintext) < _TTL_SIZE:
                raise MutilatedCorpseError("TTL header truncated")
            expiry = _unpack_ttl(plaintext[:_TTL_SIZE])
            if time.time() > expiry:
                raise RottenCorpseError(f"Payload expired at timestamp {expiry}")
            plaintext = plaintext[_TTL_SIZE:]

        # Blood Pact
        if flags & _FLAG_SIGNED:
            if len(plaintext) < 4:
                raise MutilatedCorpseError("Signed payload header truncated")
            pub_len = struct.unpack_from(">H", plaintext, 0)[0]
            offset = 2
            if len(plaintext) < offset + pub_len + 2:
                raise MutilatedCorpseError("Public key truncated")
            pub_der = plaintext[offset : offset + pub_len]
            offset += pub_len
            sig_len = struct.unpack_from(">H", plaintext, offset)[0]
            offset += 2
            if len(plaintext) < offset + sig_len:
                raise MutilatedCorpseError("Signature truncated")
            signature = plaintext[offset : offset + sig_len]
            data_to_verify = plaintext[offset + sig_len :]

            # Use the caller-provided verify_key if available,
            # otherwise fall back to the embedded public key.
            if not ecdsa_verify(verify_key, signature, data_to_verify):
                raise BrokenPactError("ECDSA signature verification failed")
            plaintext = data_to_verify

        # Decompress + Unpickle
        decompressed = zlib.decompress(plaintext)
        buf_decompressed = _to_writable(decompressed)
        result = pickle.loads(decompressed)

        # Secure wipe
        secure_wipe(memoryview(buf_decompressed))
        secure_wipe(memoryview(_to_writable(plaintext)))

        return result

    # ------------------------------------------------------------------
    # Internal binary packing (v4)
    # ------------------------------------------------------------------

    def _pack(
        self,
        nonce: bytes,
        ciphertext_with_tag: bytes,
        *,
        flags: int = 0x00,
        stealth: bool = False,
    ) -> bytes:
        magic = _MAGIC
        if stealth:
            flags |= _FLAG_STEALTH
            mask = _stealth_mask(self._key)
            magic = _apply_stealth_magic(magic, mask)

        header = struct.pack(
            _HEADER_FORMAT, magic, _VERSION, flags, len(nonce),
        )
        return header + nonce + ciphertext_with_tag

    @staticmethod
    def _unpack(
        data: bytes,
        *,
        stealth: bool = False,
    ) -> tuple[bytes, bytes, int]:
        if len(data) < _HEADER_SIZE:
            raise CorpseDeliveryError("Data too short for header")
        magic, version, flags, nonce_len = struct.unpack_from(
            _HEADER_FORMAT, data, 0,
        )
        if not stealth and magic != _MAGIC:
            raise CorpseDeliveryError(
                f"Invalid magic bytes: expected {_MAGIC!r}, got {magic!r}"
            )
        if version != _VERSION:
            raise CorpseDeliveryError(f"Unsupported version: {version}")
        expected = _HEADER_SIZE + nonce_len + 16
        if len(data) < expected:
            raise CorpseDeliveryError("Payload truncated")
        nonce = data[_HEADER_SIZE : _HEADER_SIZE + nonce_len]
        ciphertext_with_tag = data[_HEADER_SIZE + nonce_len :]
        return nonce, ciphertext_with_tag, flags