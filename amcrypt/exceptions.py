"""Custom exceptions for the amcrypt serialization library."""


class amcryptError(Exception):
    """Base exception for all amcrypt-related errors."""


class MutilatedCorpseError(amcryptError):
    """Raised when decrypted data fails integrity verification.

    This indicates the serialized bytes were tampered with, corrupted,
    or decrypted with an incorrect key. The deserialization pipeline
    is aborted before pickle.loads() is ever invoked, preventing
    arbitrary code execution.
    """

    def __init__(self, message: str = "Data integrity check failed: corpse is mutilated") -> None:
        super().__init__(message)


class CorpseDeliveryError(amcryptError):
    """Raised when the binary envelope structure is invalid.

    Occurs when the input does not start with the expected magic bytes,
    or when the payload is shorter than the minimum required length.
    """

    def __init__(self, message: str = "Invalid corpse envelope format") -> None:
        super().__init__(message)


class WrongRealmError(amcryptError):
    """Raised when soul-binding (HWID) authentication fails during revive.

    The payload was encrypted with a specific hardware identifier that
    does not match the HWID supplied at decryption time.  The data
    cannot be opened outside the machine it was sealed on.
    """

    def __init__(self, message: str = "Soul binding mismatch: wrong realm") -> None:
        super().__init__(message)


class RottenCorpseError(amcryptError):
    """Raised when a payload has exceeded its time-to-live (TTL).

    The encrypted object carried an embedded expiration timestamp that
    has already passed.  The data is considered decayed and will not
    be deserialized.
    """

    def __init__(self, message: str = "Payload expired: corpse has rotted") -> None:
        super().__init__(message)


class BrokenPactError(amcryptError):
    """Raised when an ECDSA signature verification fails.

    The payload was signed by a server key that does not match the
    verification key provided during revive, or the signature was
    forged / tampered with.
    """

    def __init__(self, message: str = "Blood pact broken: signature verification failed") -> None:
        super().__init__(message)


class SoulTrappedError(amcryptError):
    """Raised when a debugger is detected during revive (Watcher's Blindness).

    The process appears to be under active debugging.  To prevent
    forensic extraction of secrets, decryption is aborted and the
    payload is returned in a poisoned state.
    """

    def __init__(self, message: str = "Watcher detected: debugger attached to process") -> None:
        super().__init__(message)


class SelfDestructError(amcryptError):
    """Raised when the Kill Switch (Ashes to Ashes) triggers.

    The maximum number of consecutive tampering attempts has been
    exceeded.  All cached keys and credentials have been securely
    wiped from memory.
    """

    def __init__(self, message: str = "Kill switch activated: secrets purged") -> None:
        super().__init__(message)