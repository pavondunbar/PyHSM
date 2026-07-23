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
  - KEK (info="pyhsm-kek-v1") — used for per-key AES-KWP wrapping

The KEK uses a dedicated salt stored inside the encrypted JSON payload,
so it is stable across save/load cycles (the envelope salt rotates on
every write, but the KEK salt is fixed for the lifetime of the keystore).

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
import threading
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


def _internalize_key_data(keys: dict) -> None:
    """
    Convert key_data hex strings to bytearray in-place for secure memory handling.

    After JSON deserialization, key_data is an immutable str which cannot be
    zeroized. This converts it to a mutable bytearray so that deterministic
    erasure is possible when the session closes or key is destroyed.
    """
    for key_id, entry in keys.items():
        if key_id.startswith("_"):
            continue
        for v in entry.get("versions", []):
            kd = v.get("key_data", "")
            if isinstance(kd, str) and kd:
                v["key_data"] = bytearray(bytes.fromhex(kd))


def _externalize_key_data(keys: dict) -> dict:
    """
    Create a JSON-serializable copy of the keys dict, converting bytearray
    key_data back to hex strings. Does NOT modify the original in-memory dict.
    """
    out = {}
    for key_id, entry in keys.items():
        if key_id.startswith("_"):
            out[key_id] = entry
            continue
        entry_copy = dict(entry)
        versions_copy = []
        for v in entry.get("versions", []):
            v_copy = dict(v)
            kd = v_copy.get("key_data", b"")
            if isinstance(kd, (bytearray, bytes)):
                v_copy["key_data"] = bytes(kd).hex()
            versions_copy.append(v_copy)
        entry_copy["versions"] = versions_copy
        out[key_id] = entry_copy
    return out


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
        self._save_lock = threading.Lock()  # serializes _save_store calls from concurrent per-key ops
        self._needs_kek_migration = False
        self._keys: dict = self._load_store()

        # Migrate existing keys to new KEK derivation if needed
        if self._needs_kek_migration:
            self._migrate_kek()

        # Cache the KEK for the session lifetime to avoid repeated PBKDF2
        # derivation (~0.5-1s) on every encrypt/decrypt/sign operation.
        # Zeroized in zeroize_memory() when the session closes.
        self._cached_kek: bytearray = self._compute_kek()

    @property
    def backend(self) -> StorageBackend:
        """The underlying storage backend."""
        return self._backend

    def _migrate_kek(self) -> None:
        """
        Re-wrap all key material from legacy KEK to the new salt-based KEK.

        Called once when opening a keystore that lacks a _kek_salt field.
        After migration, the keystore is saved with the new KEK salt and
        all key material is wrapped with the new KEK.
        """
        from cryptography.hazmat.primitives.keywrap import (
            aes_key_wrap_with_padding,
            aes_key_unwrap_with_padding,
        )

        # Derive the old (legacy) KEK
        old_kek = bytearray(_hmac.new(
            bytes(self._master_password), b"pyhsm-kek-v1", hashlib.sha256
        ).digest())

        # Derive the new KEK (using the freshly generated _kek_salt)
        kek_salt = bytes.fromhex(self._keys["_kek_salt"])
        master = self._derive_master(kek_salt)
        new_kek = bytearray(HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"pyhsm-kek-v1",
        ).derive(bytes(master)))
        zeroize_bytearray(master)

        try:
            for key_id, entry in self._keys.items():
                if key_id.startswith("_"):
                    continue
                for v in entry.get("versions", []):
                    kd = v.get("key_data", b"")
                    if not kd:
                        continue
                    # key_data may be bytearray (post-internalize) or str (pre-internalize)
                    if isinstance(kd, bytearray):
                        wrapped_bytes = bytes(kd)
                    elif isinstance(kd, str):
                        wrapped_bytes = bytes.fromhex(kd)
                    else:
                        wrapped_bytes = bytes(kd)
                    # Unwrap with old KEK, re-wrap with new KEK
                    raw = aes_key_unwrap_with_padding(bytes(old_kek), wrapped_bytes)
                    v["key_data"] = bytearray(aes_key_wrap_with_padding(bytes(new_kek), raw))
        finally:
            zeroize_bytearray(old_kek)
            zeroize_bytearray(new_kek)

        self._needs_kek_migration = False
        self._save_store()

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
        Return a copy of the cached Key Encryption Key (KEK) for per-key AES-KWP wrapping.

        The KEK is computed once during __init__ and cached for the session
        lifetime. This avoids the ~0.5-1s PBKDF2 derivation on every
        encrypt/decrypt/sign operation.

        Returns a copy so callers can safely zeroize it after use without
        destroying the cache.
        """
        return bytearray(self._cached_kek)

    def _compute_kek(self) -> bytearray:
        """
        Compute the Key Encryption Key (KEK) from scratch.

        Uses a dedicated KEK salt stored inside the encrypted keystore JSON.
        The KEK is derived through the full PBKDF2 → HKDF-Expand path:
            PBKDF2(password, kek_salt) → HKDF-Expand(master, "pyhsm-kek-v1")

        This ensures the KEK benefits from the same key-stretching as
        other subkeys, and cannot be derived without both the master
        password AND the salt (which is encrypted at rest).

        Falls back to legacy HMAC derivation for keystores created before
        this change (those lack a "_kek_salt" field).
        """
        kek_salt = self._keys.get("_kek_salt")
        if kek_salt:
            # New derivation: full PBKDF2 + HKDF path
            salt_bytes = bytes.fromhex(kek_salt)
            master = self._derive_master(salt_bytes)
            kek = bytearray(HKDFExpand(
                algorithm=hashes.SHA256(),
                length=32,
                info=b"pyhsm-kek-v1",
            ).derive(bytes(master)))
            zeroize_bytearray(master)
            return kek
        else:
            # Legacy fallback for pre-existing keystores without _kek_salt
            kek = _hmac.new(
                bytes(self._master_password), b"pyhsm-kek-v1", hashlib.sha256
            ).digest()
            return bytearray(kek)

    # ------------------------------------------------------------------
    # Persistence (delegated to backend)
    # ------------------------------------------------------------------

    def _load_store(self) -> dict:
        if not self._backend.exists():
            # New keystore: generate a dedicated KEK salt
            return {"_kek_salt": os.urandom(_SALT_LEN).hex()}

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

        keys = json.loads(plain.decode("utf-8"))

        # Migration: inject a KEK salt if this is a pre-existing keystore
        if "_kek_salt" not in keys:
            keys["_kek_salt"] = os.urandom(_SALT_LEN).hex()
            # Note: the new KEK salt will be persisted on the next _save_store() call.
            # Until then, _derive_kek() falls back to legacy HMAC derivation, so
            # existing wrapped keys remain accessible. On the first write (any key
            # operation that modifies state), keys will be re-wrapped with the new KEK.
            self._needs_kek_migration = True
        else:
            self._needs_kek_migration = False

        # Convert key_data from hex strings to bytearrays for secure zeroization
        _internalize_key_data(keys)

        return keys

    def _save_store(self) -> None:
        """Serialize and persist the keystore. Thread-safe via _save_lock.

        Multiple per-key operations may call update_key concurrently (each
        holding only their per-key lock). This lock ensures the serialize →
        encrypt → write sequence is atomic, preventing one write from
        clobbering another's in-memory state changes.
        """
        with self._save_lock:
            salt = os.urandom(_SALT_LEN)
            enc_key, mac_key = self._derive_subkeys(salt)
            nonce = os.urandom(_NONCE_LEN)

            # Serialize: convert bytearray key_data to hex strings for JSON
            serializable = _externalize_key_data(self._keys)
            ct = AESGCM(bytes(enc_key)).encrypt(nonce, json.dumps(serializable).encode("utf-8"), None)
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
        return {k: v for k, v in self._keys.items() if not k.startswith("_")}

    def delete_key(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        del self._keys[key_id]
        self._save_store()

    def zeroize_memory(self) -> None:
        """Overwrite all sensitive material held in memory byte-by-byte."""
        # Zeroize all key material in the in-memory store
        zeroize_dict_keys(self._keys)
        # Zeroize the cached KEK
        zeroize_bytearray(self._cached_kek)
        # Zeroize the master password bytearray
        zeroize_bytearray(self._master_password)
        self._keys = {}
