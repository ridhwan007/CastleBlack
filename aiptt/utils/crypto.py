"""
Cryptographic utility helpers.

Thin wrappers over the `cryptography` library (AES-256-GCM).
"""

from __future__ import annotations

import os
import hashlib
from pathlib import Path


def generate_aes_key() -> str:
    """Generate a new random 32-byte AES-256 key, returned as hex string."""
    return os.urandom(32).hex()


def sha256_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file with 'sha256:' prefix."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison (prevents timing attacks)."""
    import hmac as hmac_mod
    return hmac_mod.compare_digest(
        a.encode("utf-8"),
        b.encode("utf-8"),
    )
