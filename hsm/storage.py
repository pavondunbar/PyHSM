"""Encrypted key storage - persists keys encrypted with a master-key-derived AES key."""

import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class KeyStore:
    """Manages encrypted persistence of HSM keys."""

    def __init__(self, path, master_password):
        self.path = path
        self._master_password = master_password.encode()
        self._keys = self._load_store()

    def _derive_key(self, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        return kdf.derive(self._master_password)

    def _load_store(self):
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "rb") as f:
            data = f.read()
        salt, nonce, ct = data[:16], data[16:28], data[28:]
        key = self._derive_key(salt)
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(plaintext)

    def _save_store(self):
        salt = os.urandom(16)
        key = self._derive_key(salt)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, json.dumps(self._keys).encode(), None)
        with open(self.path, "wb") as f:
            f.write(salt + nonce + ct)

    def save_key(self, key_id, entry):
        if key_id in self._keys:
            raise ValueError(f"Key '{key_id}' already exists")
        self._keys[key_id] = entry
        self._save_store()

    def load_key(self, key_id):
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        return self._keys[key_id]

    def load_all(self):
        return dict(self._keys)

    def delete_key(self, key_id):
        if key_id not in self._keys:
            raise KeyError(f"Key '{key_id}' not found")
        del self._keys[key_id]
        self._save_store()
