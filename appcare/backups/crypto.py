"""Authenticated encryption boundary for backup payloads."""

from __future__ import annotations

from os import urandom

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..services.security import is_safe_credential_reference
from .models import EncryptedEnvelope


class EnvelopeEncryptionError(ValueError):
    """The encrypted payload could not be authenticated or decrypted."""


class AesGcmEnvelopeEncryptor:
    """AES-256-GCM implementation with an injected, custody-managed key.

    The key is intentionally held only in memory. Callers must obtain it from
    an approved secret/KMS boundary and must never place it in a manifest,
    checkpoint, log, or provider metadata record.
    """

    __slots__ = ("_key", "key_reference")

    def __init__(self, key: bytes, *, key_reference: str) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise EnvelopeEncryptionError("AES-256 requires a 32-byte custody key")
        if not is_safe_credential_reference(key_reference):
            raise EnvelopeEncryptionError("encryption key reference is unsafe")
        self._key = key
        self.key_reference = key_reference

    def encrypt(self, plaintext: bytes, *, associated_data: bytes) -> EncryptedEnvelope:
        if not isinstance(plaintext, bytes) or not isinstance(associated_data, bytes):
            raise EnvelopeEncryptionError("encryption inputs must be bytes")
        nonce = urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, associated_data)
        return EncryptedEnvelope("AES-256-GCM", self.key_reference, nonce, ciphertext)

    def decrypt(self, envelope: EncryptedEnvelope, *, associated_data: bytes) -> bytes:
        if envelope.key_reference != self.key_reference:
            raise EnvelopeEncryptionError("encryption key reference mismatch")
        try:
            return AESGCM(self._key).decrypt(envelope.nonce, envelope.ciphertext, associated_data)
        except InvalidTag as exc:
            raise EnvelopeEncryptionError("encrypted payload authentication failed") from exc
