"""PyHSM - Software-based Hardware Security Module implementation."""

import os
import json
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .storage import KeyStore


class PyHSM:
    """Software-based Hardware Security Module providing key management and crypto operations."""

    def __init__(self, storage_path="keystore.enc", master_password=None):
        self.store = KeyStore(storage_path, master_password or "default-master-key")

    def generate_key(self, key_id, key_type="aes-256", metadata=None):
        """Generate a new cryptographic key."""
        if key_type == "aes-256":
            key_data = os.urandom(32)
        elif key_type == "aes-128":
            key_data = os.urandom(16)
        elif key_type == "rsa-2048":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            key_data = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        elif key_type == "rsa-4096":
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            key_data = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        elif key_type == "ec-p256":
            private_key = ec.generate_private_key(ec.SECP256R1())
            key_data = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        entry = {
            "key_data": key_data.hex() if isinstance(key_data, bytes) and key_type.startswith("aes") else key_data.decode(),
            "key_type": key_type,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
        }
        self.store.save_key(key_id, entry)
        return key_id

    def list_keys(self):
        """List all key IDs with their types and creation dates."""
        keys = self.store.load_all()
        return [
            {"key_id": kid, "key_type": v["key_type"], "created_at": v["created_at"]}
            for kid, v in keys.items()
        ]

    def delete_key(self, key_id):
        """Delete a key from the store."""
        self.store.delete_key(key_id)

    def encrypt(self, key_id, plaintext):
        """Encrypt data using a stored AES key. Returns hex-encoded nonce+ciphertext."""
        entry = self.store.load_key(key_id)
        if not entry["key_type"].startswith("aes"):
            raise ValueError("Encryption requires an AES key")
        key = bytes.fromhex(entry["key_data"])
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode() if isinstance(plaintext, str) else plaintext, None)
        return (nonce + ct).hex()

    def decrypt(self, key_id, ciphertext_hex):
        """Decrypt hex-encoded nonce+ciphertext using a stored AES key."""
        entry = self.store.load_key(key_id)
        if not entry["key_type"].startswith("aes"):
            raise ValueError("Decryption requires an AES key")
        key = bytes.fromhex(entry["key_data"])
        raw = bytes.fromhex(ciphertext_hex)
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(key).decrypt(nonce, ct, None)

    def sign(self, key_id, message):
        """Sign a message using a stored RSA or EC key."""
        entry = self.store.load_key(key_id)
        data = message.encode() if isinstance(message, str) else message
        private_key = serialization.load_pem_private_key(entry["key_data"].encode(), password=None)

        if entry["key_type"].startswith("rsa"):
            sig = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        elif entry["key_type"].startswith("ec"):
            sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError("Signing requires an RSA or EC key")
        return sig.hex()

    def verify(self, key_id, message, signature_hex):
        """Verify a signature. Returns True if valid, False otherwise."""
        entry = self.store.load_key(key_id)
        data = message.encode() if isinstance(message, str) else message
        sig = bytes.fromhex(signature_hex)
        private_key = serialization.load_pem_private_key(entry["key_data"].encode(), password=None)
        public_key = private_key.public_key()

        try:
            if entry["key_type"].startswith("rsa"):
                public_key.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            elif entry["key_type"].startswith("ec"):
                public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def get_public_key(self, key_id):
        """Export the public key (PEM) for an asymmetric key."""
        entry = self.store.load_key(key_id)
        if entry["key_type"].startswith("aes"):
            raise ValueError("AES keys have no public component")
        private_key = serialization.load_pem_private_key(entry["key_data"].encode(), password=None)
        return private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
