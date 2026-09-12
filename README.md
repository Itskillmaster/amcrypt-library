# necro

> *Bury your data in tombs no mortal can crack.*

`necro` is a cryptographically hardened serialization library for Python. It wraps your objects in layers of defense — Pickle, Zlib compression, and AES-256-GCM authenticated encryption — sealed inside a tamper-evident binary envelope.

**No shortcuts. No backdoors. No mercy.**

---

## Features

- **AES-256-GCM** authenticated encryption — confidentiality + integrity in one pass
- **Scrypt** key derivation — memory-hard, GPU-resistant password hashing
- **Soul Binding** — lock payloads to a specific hardware identifier (HWID)
- **Payload Decay** — cryptographically bound TTL / expiration timestamps
- **DPI Evasion** — stealth mode to defeat protocol fingerprinting
- **Blood Pact** — ECDSA signatures for non-repudiation
- **Polymorphic Curse** — random padding to thwart traffic analysis
- **Doppelganger** — dual-key plausible deniability encryption
- **Watcher's Blindness** — anti-debugging protection
- **Ouroboros Ratchet** — forward-secret key evolution in streams
- **Ashes to Ashes** — kill switch that wipes keys after tampering
- **Ephemeral Spirit** — secure memory wiping after decryption
- **X25519 Key Exchange** — Diffie-Hellman shared secret without transmitting the key
- **RCE-immune** — `pickle.loads` is never called unless GCM authentication succeeds first

## Installation

```bash
pip install necro
```

---

## Dark Arts Guide

### 1. Summon a Key

```python
from necro import summon_key

key, salt = summon_key("my-dark-secret", generate_salt=True)
```

### 2. Raise the Necromancer

```python
import os
from necro import Necromancer

key = os.urandom(32)
necro = Necromancer(key)
```

### 3. Kill & Revive

```python
corpse = necro.kill({"spell": "obliterate", "damage": 9999})
restored = necro.revive(corpse)
```

---

## Enterprise Features

### Doppelganger (Plausible Deniability)

Encrypt two payloads under two independent keys into a single blob.
The decoy key reveals a cover story; the real key reveals the classified data.
An adversary **cannot prove** a second payload exists.

```python
from necro import DoppelgangerNecromancer

doppel = DoppelgangerNecromancer()
corpse = doppel.kill(
    real_obj={"top_secret": "launch_codes"},
    decoy_obj={"status": "nothing_here"},
    real_key=real_k,
    decoy_key=decoy_k,
)

# Decoy key → cover story
doppel.revive(corpse, key=decoy_k)  # {"status": "nothing_here"}

# Real key → classified data
doppel.revive(corpse, key=real_k)   # {"top_secret": "launch_codes"}
```

### Watcher's Blindness (Anti-Debugging)

Automatically detects debuggers (pdb, pydevd, debugpy, etc.) via
`sys.gettrace()`, frame inspection, and environment analysis.
Raises `SoulTrappedError` if a debugger is found.

```python
from necro import Necromancer, SoulTrappedError

necro = Necromancer(key, anti_debug=True)  # enabled by default
try:
    necro.revive(corpse)
except SoulTrappedError:
    print("A watcher lurks in the shadows")
```

### Ouroboros Ratchet (Forward Secrecy)

The `Streamer` class automatically ratchets the session key after
every chunk using HKDF. Compromise of the current key does **not**
expose past ciphertexts.

```python
from necro import Streamer

streamer = Streamer(key, ratchet=True)
for enc_chunk in streamer.seal(data_generator):
    socket.sendall(enc_chunk)
```

### Ashes to Ashes (Kill Switch)

After 3 consecutive tampering attempts (MAC failures), the Necromancer
securely wipes its key from memory and raises `SelfDestructError`.

```python
from necro import Necromancer, SelfDestructError

necro = Necromancer(key, max_tamper=3)
for _ in range(3):
    try:
        necro.revive(tampered_corpse)
    except SelfDestructError:
        print("All secrets have been purged")
        break
```

### Soul Binding (HWID Locking)

```python
corpse = necro.kill(data, hwid=b"my-server-01")
restored = necro.revive(corpse, hwid=b"my-server-01")
```

### Payload Decay (TTL)

```python
import time
from necro import RottenCorpseError

corpse = necro.kill(data, ttl_seconds=1)
time.sleep(1.1)
try:
    necro.revive(corpse)
except RottenCorpseError:
    print("The corpse has rotted")
```

### DPI Evasion (Stealth)

```python
corpse = necro.kill(data, stealth=True)
print(corpse[:4])  # Random bytes, not "NCR1"
```

### Blood Pact (ECDSA Signatures)

```python
from necro.crypto import ecdsa_generate_keypair

privkey, pubkey = ecdsa_generate_keypair()
corpse = necro.kill(data, signing_key=privkey)
restored = necro.revive(corpse, verify_key=pubkey)
```

### Polymorphic Curse (Random Padding)

```python
corpse = necro.kill(data, pad=True)  # 16–256 bytes of random junk
```

### X25519 Key Exchange

```python
from necro import Necromancer, DarkRitual

alice, bob = DarkRitual(), DarkRitual()
shared = alice.shared_key(bob.public_key_bytes())
bob.shared_key(alice.public_key_bytes())
necro = Necromancer(shared)
```

---

## Binary Envelope Format (v4)

```
┌──────────────┬─────────┬──────────┬───────────┬──────────────┬──────────────────────────┐
│ Magic (4B)   │ Ver (1) │ Flags(1) │ Nonce(2B) │ Nonce (12B)  │ Ciphertext + Tag (...B)  │
└──────────────┴─────────┴──────────┴───────────┴──────────────┴──────────────────────────┘
```

- **Magic**: `NCR1` (4 bytes, XOR-masked in stealth mode)
- **Version**: `0x04`
- **Flags**:
  - `0x01` — TTL present
  - `0x02` — Stealth mode active
  - `0x04` — HWID soul-binding
  - `0x08` — Blood Pact (ECDSA signed)
  - `0x10` — Polymorphic Curse (random padding)

---

## Security Model

| Layer | Purpose |
|-------|---------|
| Pickle (highest protocol) | Python object serialization |
| Zlib (level 9) | Payload compression |
| ECDSA (Blood Pact) | Non-repudiation / signature |
| Random padding (Polymorphic Curse) | Traffic-analysis resistance |
| TTL (Payload Decay) | Cryptographically bound expiration |
| AES-256-GCM | Authenticated encryption |
| HWID AAD (Soul Binding) | Hardware-bound identity |
| Watcher's Blindness | Anti-debugging |
| Kill Switch (Ashes to Ashes) | Tamper-response key wipe |
| Secure Wipe (Ephemeral Spirit) | RAM zeroing after use |
| HKDF Ratchet (Ouroboros) | Forward secrecy in streams |
| Scrypt | Password → key derivation |
| X25519 + HKDF | Ephemeral key exchange |

---

## API Reference

### `Necromancer(key, *, anti_debug=True, max_tamper=3)`

| Method | Description |
|--------|-------------|
| `kill(obj, *, hwid, ttl_seconds, stealth, signing_key, pad)` | Serialize + encrypt |
| `revive(corpse, *, hwid, stealth, verify_key)` | Decrypt + deserialize |

### `DoppelgangerNecromancer`

| Method | Description |
|--------|-------------|
| `kill(real_obj, decoy_obj, *, real_key, decoy_key, ...)` | Dual-key encrypt |
| `revive(corpse, *, key, hwid, stealth)` | Decrypt with either key |

### `Streamer(key, *, chunk_size=4096, ratchet=True)`

| Method | Description |
|--------|-------------|
| `seal(chunks)` | Encrypt chunks with ratcheting |
| `open(chunks)` | Decrypt chunks with ratcheting |
| `destroy()` | Wipe the session key |

### `DebuggerDetector`

| Method | Description |
|--------|-------------|
| `is_debugging()` | Returns `True` if debugger detected |

### Exceptions

| Exception | Meaning |
|-----------|---------|
| `NecroError` | Base class |
| `MutilatedCorpseError` | Authentication failed |
| `CorpseDeliveryError` | Invalid envelope structure |
| `WrongRealmError` | HWID mismatch |
| `RottenCorpseError` | TTL expired |
| `BrokenPactError` | ECDSA verification failed |
| `SoulTrappedError` | Debugger detected |
| `SelfDestructError` | Kill switch triggered |

---

## License

MIT — use it, break it, raise the dead.
