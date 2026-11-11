"""Application-layer encryption at rest for user-submitted content (AES-256-GCM, key rotation by key id).

Ciphertext format (bytes): b"v1:" + key_id + b":" + nonce(12) + ciphertext||tag.
Database columns and object storage only ever see ciphertext. In production the key ring should be loaded
from a KMS / secrets manager; the environment variable is the integration point.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(Exception):
    pass


@dataclass(frozen=True)
class KeyRing:
    primary_id: str
    keys: dict[str, bytes]

    @classmethod
    def parse(cls, spec: str) -> KeyRing:
        keys: dict[str, bytes] = {}
        primary: str | None = None
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            key_id, _, b64 = part.partition(":")
            raw = base64.b64decode(b64)
            if len(raw) != 32:
                raise ValueError(f"encryption key {key_id!r} must be 32 bytes")
            if not key_id.isalnum():
                raise ValueError("encryption key ids must be alphanumeric")
            keys[key_id] = raw
            primary = primary or key_id
        if not primary:
            raise ValueError("no encryption keys configured")
        return cls(primary_id=primary, keys=keys)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        nonce = os.urandom(12)
        ct = AESGCM(self.keys[self.primary_id]).encrypt(nonce, plaintext, associated_data)
        return b"v1:" + self.primary_id.encode() + b":" + nonce + ct

    def decrypt(self, blob: bytes, associated_data: bytes = b"") -> bytes:
        try:
            version, key_id, rest = blob.split(b":", 2)
            if version != b"v1":
                raise DecryptionError("unknown ciphertext version")
            key = self.keys[key_id.decode()]
            return AESGCM(key).decrypt(rest[:12], rest[12:], associated_data)
        except DecryptionError:
            raise
        except Exception as exc:  # noqa: BLE001 - never leak crypto internals
            raise DecryptionError("unable to decrypt") from exc

    def encrypt_text(self, text: str, associated_data: bytes = b"") -> bytes:
        return self.encrypt(text.encode("utf-8"), associated_data)

    def decrypt_text(self, blob: bytes, associated_data: bytes = b"") -> str:
        return self.decrypt(blob, associated_data).decode("utf-8")


_ring: KeyRing | None = None


def get_keyring() -> KeyRing:
    global _ring
    if _ring is None:
        from app.core.config import get_settings

        _ring = KeyRing.parse(get_settings().encryption_keys)
    return _ring
