"""amcrypt — Cryptographically hardened Python object serialization.

Usage::

    from amcrypt import Necromancer, summon_key

    key = summon_key("my-secret-password", salt)
    amcrypt_mage = Necromancer(key)
    corpse = amcrypt_mage.kill({"payload": "classified"})
    data  = amcrypt_mage.revive(corpse)

Enterprise features::

    from amcrypt import Necromancer, DoppelgangerNecromancer

    # Doppelganger (plausible deniability)
    doppel = DoppelgangerNecromancer()
    corpse = doppel.kill(real_obj, decoy_obj, real_key=rk, decoy_key=dk)

    # Watcher's Blindness (anti-debugging) — enabled by default
    amcrypt_mage = Necromancer(key, anti_debug=True)

    # Kill Switch (Ashes to Ashes) — 3 tamper attempts triggers wipe
    amcrypt_mage = Necromancer(key, max_tamper=3)
"""

from __future__ import annotations

import os
from typing import Tuple

from .core import Necromancer
from .crypto import derive_key, ratchet_key
from .doppelganger import DoppelgangerNecromancer
from .exceptions import (
    BrokenPactError,
    CorpseDeliveryError,
    MutilatedCorpseError,
    amcryptError,
    RottenCorpseError,
    SelfDestructError,
    SoulTrappedError,
    WrongRealmError,
)
from .ritual import DarkRitual
from .stream import Streamer
from .watcher import DebuggerDetector

__all__: Tuple[str, ...] = (
    "Necromancer",
    "DoppelgangerNecromancer",
    "Streamer",
    "DebuggerDetector",
    "DarkRitual",
    "summon_key",
    "ratchet_key",
    "amcryptError",
    "MutilatedCorpseError",
    "CorpseDeliveryError",
    "WrongRealmError",
    "RottenCorpseError",
    "BrokenPactError",
    "SoulTrappedError",
    "SelfDestructError",
)

__version__: str = "0.0.1"


def summon_key(
    password: str,
    salt: bytes | None = None,
    *,
    generate_salt: bool = False,
) -> Tuple[bytes, bytes]:
    """Derive a 256-bit key from a password using Scrypt.

    Args:
        password:       The plaintext password.
        salt:           An existing salt (16+ bytes recommended).
        generate_salt:  If *True* (and *salt* is ``None``), a 32-byte
                        random salt is generated automatically.

    Returns:
        A tuple of (derived_key, salt).

    Raises:
        ValueError: If no salt is provided and *generate_salt* is ``False``.
    """
    if salt is None:
        if not generate_salt:
            raise ValueError(
                "A salt is required. Pass salt= or use generate_salt=True"
            )
        salt = os.urandom(32)
    key = derive_key(password, salt)
    return key, salt