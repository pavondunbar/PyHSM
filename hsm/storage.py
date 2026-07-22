"""
PyHSM Encrypted Key Storage.

File format (binary):
  [0 :16]  salt         (random, 16 bytes)
  [16:48]  HMAC-SHA256  over the ciphertext payload (32 bytes)
  [48:60]  nonce        (GCM, 12 bytes)
  [60:  ]  AES-256-GCM ciphertext+tag  (plaintext is UTF-8 JSON)

The HMAC is keyed with the *same* derived key as the encryption key,
providing encrypt-then-MAC protection — tampering with the ciphertext
or the nonce is detected before any decryption attempt.

Atomic writes: data is written to a temporary file then renamed,
so a crash mid-write can never corrupt the live keystore.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


_SALT_LEN = 16
_HMAC_LEN = 32
_NONCE_LEN = 12
_KDF_ITERATIONS = 480_000


class TamperError(Exception):
    """Raised when keystore HMAC verification fails."""


class KeyStore:
    """Manages encrypted, tamper-evident persistence of HSM keys."""

    def __init__(self, path: str, master_password: str) -> None:
        self.path = path
        self._master_password: bytes = master_password.encode("utf-8")
        self._keys: dict = self._load_store()

    # ------------------------------------------------------------------
    # KDF
    # ------------------------------------------------------------------

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_KDF_ITERATIONS,
        )
        return kdf.derive(self._master_password)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_store(self) -> dict:
        if not os.path.exists(self.path):
            return {}

        with open(self.path, "rb") as f:
            data = f.read()

        min_len = _SALT_LEN + _HMAC_LEN + _NONCE_LEN + 16  # 16 = min GCM tag
        if len(data) < min_len:
            raise TamperError("Keystore file too short — possible truncation or corruption")

        salt = data[:_SALT_LEN]
        stored_hmac = data[_SALT_LEN : _SALT_LEN + _HMAC_LEN]
        payload = data[_SALT_LEN + _HMAC_LEN :]  # nonce + ciphertext+tag

        key = self._derive_key(salt)

        # Verify MAC before decrypting (encrypt-then-MAC)
        expected_hmac = _hmac.new(key, payload, hashlib.sha256).digest()
        if not _hmac.compare_digest(stored_hmac, expected_hmac):
            # Zeroize key before raising
            key = bytes(len(key))
            raise TamperError(
                "PyHSM TAMPER DETECTED: HMAC verification failed. "
                "Keystore may have been modified outside of PyHSM."
            )

        nonce = payload[:_NONCE_LEN]
        ct_plus_tag = payload[_NONCE_LEN:]
        plain = AESGCM(key).decrypt(nonce, ct_plus_tag, None)
        key = bytes(len(key))  # zeroize

        return json.loads(plain.decode("utf-8"))

    def _save_store(self) -> None:
        salt = os.urandom(_SALT_LEN)
        key = self._derive_key(salt)
        nonce = os.urandom(_NONCE_LEN)

        ct = AESGCM(key).encrypt(nonce, json.dumps(self._keys).encode("utf-8"), None)
        payload = nonce + ct
        mac = _hmac.new(key, payload, hashlib.sha256).digest()
        key = bytes(len(key))  # zeroize

        file_data = salt + mac + payload

        # Atomic write: write to sibling temp file, then rename
        tmp = self.path + ".tmp." + secrets.token_hex(4)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(file_data)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Key CRUD
    # ------------------------------------------------------------------

    def save_key(self, key_id: str, entry: dict) -> None:
        if key_id in self._keys:
            raise ValueError(f"Key '{key_id}' already exists")
        self._keys[key_id] = entry
        self._save_store()

    def update_key(self, key_id: str, entry: dict) -> None:
        """Overwrite an existing key entry (used for rotation / policy updates)."""
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        self._keys[key_id] = entry
        self._save_store()

    def load_key(self, key_id: str) -> dict:
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        return self._keys[key_id]

    def load_all(self) -> dict:
        return dict(self._keys)

    def delete_key(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        del self._keys[key_id]
        self._save_store()

    def zeroize_memory(self) -> None:
        """Overwrite the master password bytes held in memory."""
        self._master_password = bytes(len(self._master_password))
        self._keys = {}
