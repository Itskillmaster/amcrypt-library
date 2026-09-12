"""Cryptographic primitives for the amcrypt serialization library.

Provides AES-256-GCM authenticated encryption, Scrypt-based key
derivation, X25519 elliptic-curve key exchange, ECDSA digital
signatures, dual-key plausible-deniability encryption, and HKDF
key ratcheting for forward secrecy. All randomness is sourced from
the operating system CSPRNG.
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1,
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)


_KEY_LENGTH: int = 32  # 256-bit key
_NONCE_LENGTH: int = 12  # 96-bit nonce for AES-GCM
_SCRYPT_COST_N: int = 2 ** 20  # ~1 MiB memory cost
_SCRYPT_COST_R: int = 8
_SCRYPT_COST_P: int = 1


# ------------------------------------------------------------------
# Nonce generation
# ------------------------------------------------------------------

def generate_nonce() -> bytes:
    """Generate a cryptographically secure 12-byte nonce.

    Returns:
        A 12-byte random nonce suitable for AES-256-GCM.
    """
    return os.urandom(_NONCE_LENGTH)


# ------------------------------------------------------------------
# Scrypt key derivation
# ------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a password using Scrypt.

    Uses memory-hard Scrypt with N=2^20, r=8, p=1 to resist
    GPU/ASIC brute-force attacks.

    Args:
        password: The plaintext password string.
        salt:     Random salt bytes (recommended: 16+ bytes).

    Returns:
        A 32-byte derived key.
    """
    kdf = Scrypt(
        salt=salt,
        length=_KEY_LENGTH,
        n=_SCRYPT_COST_N,
        r=_SCRYPT_COST_R,
        p=_SCRYPT_COST_P,
    )
    return kdf.derive(password.encode("utf-8"))


# ------------------------------------------------------------------
# AES-256-GCM with optional associated data (AEAD)
# ------------------------------------------------------------------

def aes_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* under *key* using AES-256-GCM.

    Args:
        key:             A 32-byte AES key.
        plaintext:       The data to encrypt.
        associated_data: Optional authenticated-but-not-encrypted data.

    Returns:
        A tuple of (nonce, ciphertext_with_tag).
    """
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag


def aes_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_with_tag: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt *ciphertext_with_tag* under *key* using AES-256-GCM.

    Args:
        key:               A 32-byte AES key.
        nonce:             The 12-byte nonce used during encryption.
        ciphertext_with_tag: The ciphertext with the appended 16-byte MAC.
        associated_data:    Optional authenticated-but-not-encrypted data.

    Returns:
        The decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)


# ------------------------------------------------------------------
# Dual-key encryption  (Doppelganger)
# ------------------------------------------------------------------

_TAG_SIZE: int = 16  # GCM authentication tag

def dual_encrypt(
    real_key: bytes,
    decoy_key: bytes,
    real_plaintext: bytes,
    decoy_plaintext: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt two payloads under two independent AES-256-GCM keys.

    Produces two (nonce, ciphertext+tag) pairs that are concatenated
    into a single blob.  An observer cannot distinguish which block
    contains the "real" data — both are valid AES-256-GCM ciphertexts.

    Wire layout::

        [nonce_real (12B)] [ct_real + tag_real (...B)]
        [nonce_decoy (12B)] [ct_decoy + tag_decoy (...B)]

    Returns:
        A tuple of (nonce_real, ct_real, nonce_decoy, ct_decoy).
    """
    nonce_r, ct_r = aes_encrypt(real_key, real_plaintext)
    nonce_d, ct_d = aes_encrypt(decoy_key, decoy_plaintext)
    return nonce_r, ct_r, nonce_d, ct_d


def dual_decrypt_single(
    key: bytes,
    nonce_r: bytes,
    ct_r: bytes,
    nonce_d: bytes,
    ct_d: bytes,
    *,
    match_real: bool = True,
) -> bytes | None:
    """Attempt to decrypt one side of a dual-encrypted envelope.

    If *match_real* is ``True`` the first block (real) is tried;
    otherwise the second block (decoy) is tried first.

    Returns:
        The decrypted plaintext, or ``None`` if the key does not match
        either block (wrong key for both).
    """
    aesgcm = AESGCM(key)
    blocks = [
        (nonce_r, ct_r),
        (nonce_d, ct_d),
    ] if match_real else [
        (nonce_d, ct_d),
        (nonce_r, ct_r),
    ]
    for nonce, ct in blocks:
        try:
            return aesgcm.decrypt(nonce, ct, None)
        except Exception:
            continue
    return None


# ------------------------------------------------------------------
# ECDSA signing / verification  (Blood Pact)
# ------------------------------------------------------------------

def ecdsa_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ECDSA SECP256K1 private/public key pair.

    Returns:
        A tuple of (private_key_der, public_key_der) in DER format.
    """
    private_key = generate_private_key(SECP256K1())
    public_key = private_key.public_key()
    return (
        private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
        public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
    )


def ecdsa_sign(private_key_der: bytes, data: bytes) -> bytes:
    """Sign *data* with an ECDSA SECP256K1 private key.

    Args:
        private_key_der: DER-encoded ECDSA private key.
        data:            The bytes to sign.

    Returns:
        The DER-encoded ECDSA signature.
    """
    private_key = load_der_private_key(private_key_der, password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey)
    return private_key.sign(data, ECDSA(SHA256()))


def ecdsa_verify(
    public_key_der: bytes,
    signature: bytes,
    data: bytes,
) -> bool:
    """Verify an ECDSA signature.

    Args:
        public_key_der: DER-encoded ECDSA public key.
        signature:      The DER-encoded signature to verify.
        data:           The signed data.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    public_key = load_der_public_key(public_key_der)
    assert isinstance(public_key, EllipticCurvePublicKey)
    try:
        public_key.verify(signature, data, ECDSA(SHA256()))
        return True
    except Exception:
        return False


# ------------------------------------------------------------------
# HKDF key ratcheting  (Ouroboros Ratchet)
# ------------------------------------------------------------------

def ratchet_key(
    current_key: bytes,
    step: int,
    *,
    info: bytes = b"amcrypt-ouroboros-ratchet",
) -> bytes:
    """Derive the next session key from the current key and a step counter.

    Uses HKDF-SHA256 with the step counter mixed into the ``info`` label.
    This is a one-way function — given only the new key, an attacker
    cannot compute the previous key (forward secrecy).

    Args:
        current_key: The 32-byte current session key.
        step:        A monotonically increasing step counter.
        info:        Optional context string for domain separation.

    Returns:
        A fresh 32-byte derived key.
    """
    step_bytes = struct.pack(">Q", step)
    return HKDF(
        algorithm=SHA256(),
        length=_KEY_LENGTH,
        salt=current_key,
        info=info + step_bytes,
    ).derive(current_key)


# ------------------------------------------------------------------
# X25519 key exchange helpers
# ------------------------------------------------------------------

def x25519_generate_private_key() -> X25519PrivateKey:
    """Generate a fresh X25519 private key.

    Returns:
        An X25519PrivateKey instance.
    """
    return X25519PrivateKey.generate()


def x25519_public_bytes(private_key: X25519PrivateKey) -> bytes:
    """Serialize the public key derived from *private_key* to raw bytes.

    Args:
        private_key: An X25519PrivateKey instance.

    Returns:
        The 32-byte raw encoding of the corresponding public key.
    """
    return private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )


def x25519_shared_key(
    private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    """Compute a shared 32-byte secret from our private key and the peer's
    public key, then derive a symmetric AES-256 key via HKDF.

    Args:
        private_key:           Our X25519PrivateKey.
        peer_public_key_bytes: The peer's 32-byte raw public key.

    Returns:
        A 32-byte symmetric AES-256 key suitable for AESGCM.
    """
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    raw_shared = private_key.exchange(peer_public_key)
    derived = HKDF(
        algorithm=SHA256(),
        length=_KEY_LENGTH,
        salt=None,
        info=b"amcrypt-x25519-aesgcm-key",
    ).derive(raw_shared)
    return derived