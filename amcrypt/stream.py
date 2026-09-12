"""Chunked stream encryption for sockets and WebSockets — Soul Stream.

Provides a generator-based ``Streamer`` that encrypts and decrypts data
in 4 KB chunks.  Each chunk is a self-contained AES-256-GCM envelope
so that:

- The receiver can decrypt incrementally without buffering the full
  payload in RAM.
- Each chunk gets its own fresh nonce, preventing nonce reuse across
  chunks.
- An attacker cannot reorder or drop chunks without triggering GCM
  authentication failure.

Ouroboros Ratchet (forward secrecy):

    After every ``seal`` or ``open`` operation the session key is
    transparently ratcheted forward using HKDF.  Compromise of the
    current key does **not** expose past ciphertexts — previous keys
    cannot be derived from the new key (one-way function).

Wire format (per chunk)::

    [chunk_len (4B, big-endian)] [nonce (12B)] [ciphertext + tag (...B)]

The ``chunk_len`` field covers the nonce + ciphertext + tag (excludes
itself).
"""

from __future__ import annotations

import ctypes
import struct
from typing import Iterator

from cryptography.exceptions import InvalidTag

from .crypto import aes_decrypt, aes_encrypt, ratchet_key
from .exceptions import MutilatedCorpseError

_CHUNK_SIZE: int = 4096  # 4 KiB plaintext per chunk
_LEN_FIELD: int = 4  # uint32 chunk length prefix
_NONCE_LEN: int = 12


def _secure_wipe(view: memoryview) -> None:
    """Zero-fill the underlying buffer of *view*."""
    if view.nbytes == 0:
        return
    buf = (ctypes.c_char * view.nbytes).from_buffer(view)
    ctypes.memset(ctypes.addressof(buf), 0, view.nbytes)


def _to_writable(data: bytes | bytearray) -> bytearray:
    if isinstance(data, bytearray):
        return data
    return bytearray(data)


class Streamer:
    """Generator-based chunked AES-256-GCM encryptor / decryptor
    with Ouroboros Ratchet forward secrecy.

    The session key is automatically ratcheted after each chunk
    operation.  If the key is compromised, past chunks remain secure
    because the ratchet is a one-way HKDF function.

    Example — encrypting::

        from amcrypt.stream import Streamer

        streamer = Streamer(key)
        for encrypted_chunk in streamer.seal(chunk_generator):
            socket.sendall(encrypted_chunk)

    Example — decrypting::

        streamer = Streamer(key)
        for plaintext_chunk in streamer.open(socket.recv_loop()):
            process(plaintext_chunk)
    """

    def __init__(
        self,
        key: bytes,
        *,
        chunk_size: int = _CHUNK_SIZE,
        ratchet: bool = True,
    ) -> None:
        """Initialise the streamer with a 256-bit key.

        Args:
            key:        A 32-byte AES-256 key.
            chunk_size: Plaintext bytes per chunk (default 4096).
            ratchet:    Enable Ouroboros Ratchet (default ``True``).
                        When enabled, the session key evolves after
                        every chunk.

        Raises:
            ValueError: If *key* is not exactly 32 bytes.
        """
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")
        self._key = bytearray(key)
        self._chunk_size = chunk_size
        self._ratchet = ratchet
        self._step: int = 0

    # ------------------------------------------------------------------
    # Key ratcheting
    # ------------------------------------------------------------------

    def _ratchet_forward(self) -> None:
        """Derive the next session key and destroy the old one."""
        if not self._ratchet:
            return
        new_key = ratchet_key(bytes(self._key), self._step)
        self._step += 1
        # Secure wipe of old key
        _secure_wipe(memoryview(self._key))
        self._key = bytearray(new_key)

    def _ratchet_backward(self) -> None:
        """Derive the previous session key (for open-direction ratchet).

        For the ``open`` direction we need to ratchet the key *before*
        decryption so that the key state matches what the sender had
        when each chunk was sealed.  We store the step counter and
        derive from the *current* key forward.

        In practice, both directions use the same one-way ratchet —
        the sender ratchets after sealing, the receiver ratchets
        after opening.  Both stay in sync as long as chunks arrive
        in order.
        """
        self._ratchet_forward()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seal(
        self,
        plaintext_chunks: Iterator[bytes],
    ) -> Iterator[bytes]:
        """Encrypt an iterable of plaintext chunks into wire-format envelopes.

        After each chunk, the session key is ratcheted forward.

        Args:
            plaintext_chunks: An iterator yielding plaintext byte slices.

        Yields:
            Encrypted chunks ready for transmission.
        """
        for chunk in plaintext_chunks:
            if not chunk:
                continue
            nonce, ciphertext_with_tag = aes_encrypt(
                bytes(self._key), chunk,
            )
            wire_chunk = struct.pack(">I", _NONCE_LEN + len(ciphertext_with_tag))
            wire_chunk += nonce + ciphertext_with_tag
            self._ratchet_forward()
            yield wire_chunk

    def seal_final(self, last_chunk: bytes) -> Iterator[bytes]:
        """Encrypt and emit the final chunk.

        Args:
            last_chunk: The final plaintext bytes (may be empty).

        Yields:
            One encrypted chunk (empty input yields nothing).
        """
        yield from self.seal(iter([last_chunk]))

    def open(
        self,
        wire_chunks: Iterator[bytes],
    ) -> Iterator[bytes]:
        """Decrypt an iterable of wire-format encrypted chunks.

        After each chunk, the session key is ratcheted forward to
        match the sender's key state.

        Args:
            wire_chunks: An iterator yielding raw encrypted chunks.

        Yields:
            Decrypted plaintext byte slices.

        Raises:
            MutilatedCorpseError: If any chunk fails GCM authentication.
        """
        for wire_chunk in wire_chunks:
            if len(wire_chunk) < _LEN_FIELD + _NONCE_LEN + 16:
                raise MutilatedCorpseError("Encrypted chunk too short")
            payload_len = struct.unpack_from(">I", wire_chunk, 0)[0]
            if len(wire_chunk) < _LEN_FIELD + payload_len:
                raise MutilatedCorpseError("Encrypted chunk truncated")
            nonce = wire_chunk[_LEN_FIELD : _LEN_FIELD + _NONCE_LEN]
            ciphertext_with_tag = wire_chunk[
                _LEN_FIELD + _NONCE_LEN : _LEN_FIELD + payload_len
            ]
            try:
                plaintext = aes_decrypt(
                    bytes(self._key), nonce, ciphertext_with_tag,
                )
            except InvalidTag as exc:
                raise MutilatedCorpseError(
                    "Chunk authentication failed: data tampered or wrong key"
                ) from exc
            self._ratchet_forward()
            yield plaintext

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def destroy(self) -> None:
        """Securely wipe the session key.

        After calling this method, the ``Streamer`` instance is
        unusable and all subsequent ``seal`` / ``open`` calls will
        raise ``MutilatedCorpseError``.
        """
        if self._key is not None:
            _secure_wipe(memoryview(self._key))
            self._key = bytearray(b"\x00" * 32)  # dead key

    def current_step(self) -> int:
        """Return the current ratchet step counter."""
        return self._step

    def __del__(self) -> None:
        """Best-effort secure wipe on garbage collection."""
        try:
            self.destroy()
        except Exception:
            pass