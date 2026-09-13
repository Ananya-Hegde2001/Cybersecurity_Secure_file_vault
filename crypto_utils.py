"""
AES-256-GCM helpers.

GCM is an "authenticated" mode: it doesn't just encrypt the data, it also
produces a tag that lets decrypt() detect if the ciphertext was corrupted
or tampered with. If a file has been altered, decrypt_bytes() raises
InvalidTag instead of silently returning garbage.

A fresh random 12-byte nonce is generated for every encryption. Reusing a
nonce with the same key would break GCM's security guarantees, so we never
do that — each file gets its own nonce, stored alongside it in the DB.
"""
import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

NONCE_SIZE = 12  # 96 bits, the recommended size for AES-GCM
ENVELOPE_VERSION = 2


def _load_key() -> bytes:
    key_b64 = current_app.config.get("MASTER_KEY")
    if not key_b64:
        raise RuntimeError(
            "MASTER_KEY is not set. Run `python generate_keys.py` and put "
            "the result in your .env file."
        )
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must decode to exactly 32 bytes (256 bits).")
    return key


def encrypt_bytes(plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext, returning (ciphertext, nonce)."""
    key = _load_key()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return ciphertext, nonce


def decrypt_bytes(ciphertext: bytes, nonce: bytes) -> bytes:
    """Decrypt ciphertext. Raises cryptography.exceptions.InvalidTag if the
    data was tampered with or the wrong key/nonce is used."""
    key = _load_key()
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)


def encrypt_envelope(plaintext: bytes, key_id: str) -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt content with a random data key, then wrap that key with MASTER_KEY."""
    master_key = _load_key()
    data_key = AESGCM.generate_key(bit_length=256)
    content_nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(data_key).encrypt(content_nonce, plaintext, key_id.encode())
    wrap_nonce = os.urandom(NONCE_SIZE)
    wrapped_key = AESGCM(master_key).encrypt(wrap_nonce, data_key, key_id.encode())
    return ciphertext, content_nonce, wrapped_key, wrap_nonce


def decrypt_envelope(ciphertext: bytes, content_nonce: bytes, wrapped_key: bytes, wrap_nonce: bytes, key_id: str) -> bytes:
    """Unwrap a per-file key in memory and decrypt the file payload."""
    master_key = _load_key()
    data_key = AESGCM(master_key).decrypt(wrap_nonce, wrapped_key, key_id.encode())
    return AESGCM(data_key).decrypt(content_nonce, ciphertext, key_id.encode())
