"""X25519 asymmetric key exchange — the Dark Ritual.

Implements a two-party Diffie-Hellman key agreement over Curve25519.
Neither party ever transmits the shared secret; both independently
derive an identical 256-bit AES-GCM key from the ephemeral exchange.

Typical workflow::

    # --- Client (initiator) ---
    from amcrypt.ritual import DarkRitual

    ritual = DarkRitual()
    client_pub = ritual.public_key_bytes()   # send to server

    # --- Server (responder) ---
    server = DarkRitual()
    server_pub = server.public_key_bytes()   # send to client
    shared_key = server.shared_key(client_pub)

    # --- Client completes the ritual ---
    shared_key = ritual.shared_key(server_pub)

    # Both now hold identical ``shared_key`` for Necromancer(key=shared_key)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from .crypto import x25519_generate_private_key, x25519_public_bytes, x25519_shared_key


class DarkRitual:
    """X25519 Diffie-Hellman key-exchange session.

    Create one ``DarkRitual`` per party.  Each instance generates an
    ephemeral private key and exposes the corresponding public key
    for transmission.  Once the peer's public key is received, call
    :meth:`shared_key` to derive the 256-bit AES-GCM key.

    Example::

        alice = DarkRitual()
        bob   = DarkRitual()

        # Exchange public keys over the wire
        alice.send_to(bob.public_key_bytes())
        bob.send_to(alice.public_key_bytes())

        key_a = alice.shared_key(bob.public_key_bytes())
        key_b = bob.shared_key(alice.public_key_bytes())
        assert key_a == key_b  # both identical
    """

    def __init__(self) -> None:
        """Generate an ephemeral X25519 private key."""
        self._private_key: X25519PrivateKey = x25519_generate_private_key()
        self._shared: bytes | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def public_key_bytes(self) -> bytes:
        """Return the 32-byte raw public key for transmission.

        Returns:
            A 32-byte ``bytes`` object containing the X25519 public key.
        """
        return x25519_public_bytes(self._private_key)

    def shared_key(self, peer_public_key_bytes: bytes) -> bytes:
        """Derive the shared AES-256 key from the peer's public key.

        The raw X25519 output is passed through HKDF-SHA256 to produce
        a uniform 256-bit symmetric key suitable for ``AESGCM``.

        This method can be called at most once per ``DarkRitual`` instance
        (the ephemeral private key is destroyed after exchange to provide
        forward secrecy).

        Args:
            peer_public_key_bytes: The peer's 32-byte raw X25519 public key.

        Returns:
            A 32-byte derived AES-256 key.

        Raises:
            RuntimeError: If called more than once on the same instance.
        """
        if self._shared is not None:
            raise RuntimeError(
                "This ritual has already been completed; "
                "generate a new DarkRitual for a fresh exchange"
            )
        key = x25519_shared_key(self._private_key, peer_public_key_bytes)
        # Forward secrecy: destroy the ephemeral private key
        self._private_key = None  # type: ignore[assignment]
        self._shared = key
        return key

    def is_complete(self) -> bool:
        """Return ``True`` if the shared key has already been derived."""
        return self._shared is not None