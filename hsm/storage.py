"""
PyHSM Encrypted Key Storage.

Encrypted envelope format (binary):
  [0 :16]  salt         (random, 16 bytes)
  [16:48]  HMAC-SHA256  over the ciphertext payload (32 bytes)
  [48:60]  nonce        (GCM, 12 bytes)
  [60:  ]  AES-256-GCM ciphertext+tag  (plaintext is UTF-8 JSON)

Key separation: the master password is derived via PBKDF2-SHA256 (480k
iterations), then HKDF-Expand produces two independent 32-byte subkeys:
  - Encryption key (info="pyhsm-enc-v1") — used for AES-256-GCM
  - MAC key (info="pyhsm-mac-v1") — used for HMAC-SHA256

This encrypt-then-MAC construction with separated keys ensures that a
weakness in one primitive cannot leak information about the other key.

Persistence is delegated to a StorageBackend implementation. The default
FileBackend uses atomic writes (temp file + rename), so a crash mid-write
can never corrupt the live keystore.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

from .backends import StorageBackend, FileBackend
from .secure_memory import zeroize_bytearray, zeroize_dict_keys


_SALT_LEN = 16
_HMAC_LEN = 32
_NONCE_LEN = 12
_KDF_ITERATIONS = 480_000


class TamperError(Exception):
    """Raised when keystore HMAC verification fails."""


class KeyStore:
    """
    Manages encrypted, tamper-evident persistence of HSM keys.

    Parameters
    ----------
    path : str, optional
        Path to the keystore file. Creates a FileBackend internally.
        Ignored if ``backend`` is provided.
    master_password : str
        Master password for key derivation.
    backend : StorageBackend, optional
        A custom storage backend. If provided, ``path`` is ignored and
        the backend is used directly for persistence.

    Examples
    --------
    Using the default file backend (backward-compatible):

        store = KeyStore("keystore.enc", "my-password")

    Using a custom backend:

        from hsm.backends import MemoryBackend
        store = KeyStore(master_password="pw", backend=MemoryBackend())
    """

    def __init__(
        self,
        path: Optional[str] = None,
        master_password: str = "",
        *,
        backend: Optional[StorageBackend] = None,
    ) -> None:
        if not master_password:
            raise ValueError("KeyStore: master_password is required")

        # Resolve the storage backend
        if backend is not None:
            self._backend = backend
        elif path is not None:
            self._backend = FileBackend(path)
        else:
            raise ValueError(
                "KeyStore: either 'path' (for file storage) or 'backend' "
                "(for custom storage) must be provided"
            )

        # Expose path for backward compatibility (used by tests/audit path derivation)
        self.path = path or getattr(self._backend, "path", "<custom-backend>")

        self._master_password: bytearray = bytearray(master_password.encode("utf-8"))
        self._keys: dict = self._load_store()

    @property
    def backend(self) -> StorageBackend:
        """The underlying storage backend."""
        return self._backend

    # ------------------------------------------------------------------
    # KDF — key separation via HKDF-Expand
    # ------------------------------------------------------------------

    def _derive_master(self, salt: bytes) -> bytearray:
        """Derive the intermediate master key from password + salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=_KDF_ITERATIONS,
        )
        derived = kdf.derive(bytes(self._master_password))
        return bytearray(derived)

    def _derive_subkeys(self, salt: bytes) -> tuple[bytearray, bytearray]:
        """
        Derive separate encryption and MAC keys via HKDF-Expand.

        Returns (enc_key, mac_key) — each 32 bytes.
        Caller is responsible for zeroizing both after use.
        """
        master = self._derive_master(salt)

        enc_key = bytearray(HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"pyhsm-enc-v1",
        ).derive(bytes(master)))

        mac_key = bytearray(HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"pyhsm-mac-v1",
        ).derive(bytes(master)))

        zeroize_bytearray(master)
        return enc_key, mac_key

    def _derive_kek(self) -> bytearray:
        """
        Derive a Key Encryption Key (KEK) for per-key AES-KWP wrapping.

        Uses HMAC-SHA256(master_password, "pyhsm-kek-v1") — independent
        of the salt-based subkeys, so the KEK is stable across save/load
        cycles without storing additional state.
        """
        kek = _hmac.new(
            bytes(self._master_password), b"pyhsm-kek-v1", hashlib.sha256
        ).digest()
        return bytearray(kek)

    # ------------------------------------------------------------------
    # Persistence (delegated to backend)
    # ------------------------------------------------------------------

    def _load_store(self) -> dict:
        if not self._backend.exists():
            return {}

        data = self._backend.read()

        min_len = _SALT_LEN + _HMAC_LEN + _NONCE_LEN + 16  # 16 = min GCM tag
        if len(data) < min_len:
            raise TamperError("Keystore file too short — possible truncation or corruption")

        salt = data[:_SALT_LEN]
        stored_hmac = data[_SALT_LEN : _SALT_LEN + _HMAC_LEN]
        payload = data[_SALT_LEN + _HMAC_LEN :]  # nonce + ciphertext+tag

        enc_key, mac_key = self._derive_subkeys(salt)

        # Verify MAC before decrypting (encrypt-then-MAC)
        expected_hmac = _hmac.new(bytes(mac_key), payload, hashlib.sha256).digest()
        if not _hmac.compare_digest(stored_hmac, expected_hmac):
            zeroize_bytearray(enc_key)
            zeroize_bytearray(mac_key)
            raise TamperError(
                "PyHSM TAMPER DETECTED: HMAC verification failed. "
                "Keystore may have been modified outside of PyHSM."
            )

        nonce = payload[:_NONCE_LEN]
        ct_plus_tag = payload[_NONCE_LEN:]
        plain = AESGCM(bytes(enc_key)).decrypt(nonce, ct_plus_tag, None)
        zeroize_bytearray(enc_key)
        zeroize_bytearray(mac_key)

        return json.loads(plain.decode("utf-8"))

    def _save_store(self) -> None:
        salt = os.urandom(_SALT_LEN)
        enc_key, mac_key = self._derive_subkeys(salt)
        nonce = os.urandom(_NONCE_LEN)

        ct = AESGCM(bytes(enc_key)).encrypt(nonce, json.dumps(self._keys).encode("utf-8"), None)
        payload = nonce + ct
        mac = _hmac.new(bytes(mac_key), payload, hashlib.sha256).digest()
        zeroize_bytearray(enc_key)
        zeroize_bytearray(mac_key)

        file_data = salt + mac + payload
        self._backend.write(file_data)

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
        """Overwrite all sensitive material held in memory byte-by-byte."""
        # Zeroize all key material in the in-memory store
        zeroize_dict_keys(self._keys)
        # Zeroize the master password bytearray
        zeroize_bytearray(self._master_password)
        self._keys = {}
