"""
PyHSM - Production-hardened software HSM.

Features (Python layer):
  - Explicit master password required; no insecure defaults
  - Key versioning with rotation and archival
  - Per-key policies: allowEncrypt, allowDecrypt, maxOperations, expiresAt
  - Public-key stored at generation time (verify never loads private key)
  - AES-256-GCM encryption with version-prefixed ciphertext
  - RSA-PSS and ECDSA signing
  - Per-key rate limiting
  - HMAC-chained, append-only audit log
  - Session timeout with memory zeroization
  - Startup Known-Answer Tests
  - Prometheus-format metrics
  - Encrypt-then-MAC keystore with atomic writes
"""

from __future__ import annotations

import os
import re
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .storage import KeyStore, TamperError
from .audit import AuditLog
from .rate_limiter import RateLimiter
from .metrics import MetricsCollector
from .self_test import run_self_tests

# Key ID validation: 1-128 chars, start alphanumeric, body [a-zA-Z0-9._-]
_KEY_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}$')

# Ciphertext version prefix length (4 bytes big-endian uint32)
_VERSION_PREFIX_LEN = 4


def _validate_key_id(key_id: str) -> None:
    if not _KEY_ID_RE.match(key_id):
        raise ValueError(
            f"Invalid key ID '{key_id}'. "
            "Must be 1-128 chars, start with alphanumeric, "
            "contain only [a-zA-Z0-9._-]."
        )



class PyHSM:
    """
    Software-based Hardware Security Module providing key management
    and cryptographic operations.

    Parameters
    ----------
    storage_path : str
        Path to the encrypted keystore file.
    master_password : str
        Master password used to derive the keystore encryption key.
        Must be explicitly provided — there is no default.
    audit_log_path : str, optional
        Path for the HMAC-chained audit log. Defaults to
        <storage_path>.audit.jsonl.
    session_timeout_s : float, optional
        Idle seconds before the session is automatically locked.
        Default 300 (5 minutes). Pass 0 to disable.
    rate_limit_max_ops : int, optional
        Maximum operations per key per rate window. Default 100.
    rate_limit_window_s : float, optional
        Rate-limit window in seconds. Default 60.
    """

    def __init__(
        self,
        storage_path: str = "keystore.enc",
        master_password: Optional[str] = None,
        *,
        audit_log_path: Optional[str] = None,
        session_timeout_s: float = 300.0,
        rate_limit_max_ops: int = 100,
        rate_limit_window_s: float = 60.0,
    ) -> None:
        if not master_password:
            raise ValueError(
                "PyHSM: master_password is required. "
                "There is no insecure default — supply an explicit password."
            )

        self._storage_path = storage_path
        self._session_timeout_s = session_timeout_s

        audit_path = audit_log_path or (storage_path + ".audit.jsonl")
        self._audit = AuditLog(audit_path)
        self._rate_limiter = RateLimiter(rate_limit_max_ops, rate_limit_window_s)
        self._metrics = MetricsCollector()

        # Run KATs before accepting any operations
        try:
            run_self_tests()
            self._audit.record("selfTestPass", success=True)
        except RuntimeError as exc:
            self._audit.record("selfTestFail", success=False, reason=str(exc))
            raise

        self._store = KeyStore(storage_path, master_password)
        self._session_active = True
        self._last_activity = _now()
        self._lock = threading.Lock()

        self._start_timeout_thread()
        self._audit.record("sessionOpen", success=True)
        self._update_key_metrics()


    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _start_timeout_thread(self) -> None:
        if self._session_timeout_s <= 0:
            return
        t = threading.Thread(target=self._timeout_loop, daemon=True)
        t.start()

    def _timeout_loop(self) -> None:
        import time
        while True:
            time.sleep(max(1.0, self._session_timeout_s / 10))
            with self._lock:
                if not self._session_active:
                    return
                if _now() - self._last_activity >= self._session_timeout_s:
                    self._close_session_locked()
                    return

    def _touch(self) -> None:
        self._last_activity = _now()

    def _assert_session(self) -> None:
        if not self._session_active:
            raise RuntimeError("PyHSM: session is closed. Create a new instance.")
        self._touch()

    def close_session(self) -> None:
        """Explicitly close the session, flushing and zeroizing key material."""
        with self._lock:
            self._close_session_locked()

    def _close_session_locked(self) -> None:
        if not self._session_active:
            return
        self._audit.record("sessionClose", success=True)
        self._store.zeroize_memory()
        self._session_active = False

    def _update_key_metrics(self) -> None:
        all_keys = self._store.load_all()
        active = archived = 0
        for entry in all_keys.values():
            current_v = entry.get("current_version", 1)
            versions = entry.get("versions", [])
            current = next((v for v in versions if v["version"] == current_v), None)
            if current and current.get("archived"):
                archived += 1
            else:
                active += 1
        self._metrics.set_key_count(active, archived)


    # ------------------------------------------------------------------
    # Policy enforcement
    # ------------------------------------------------------------------

    def _enforce_policy(self, entry: dict, operation: str) -> None:
        """Check per-key policy; raise ValueError if any constraint is violated."""
        policy = entry.get("policy", {})
        key_id = entry.get("key_id", "?")

        if not self._rate_limiter.allow(key_id):
            self._metrics.record_rate_limit()
            self._audit.record("rateLimited", key_id=key_id, success=False)
            raise ValueError(f"PyHSM: key '{key_id}' is rate-limited")

        if operation == "encrypt" and not policy.get("allow_encrypt", True):
            raise ValueError(f"PyHSM: key '{key_id}' policy denies encrypt")
        if operation == "decrypt" and not policy.get("allow_decrypt", True):
            raise ValueError(f"PyHSM: key '{key_id}' policy denies decrypt")
        if operation == "sign" and not policy.get("allow_sign", True):
            raise ValueError(f"PyHSM: key '{key_id}' policy denies sign")

        max_ops = policy.get("max_operations")
        if max_ops is not None and entry.get("operation_count", 0) >= max_ops:
            raise ValueError(f"PyHSM: key '{key_id}' exceeded max operations ({max_ops})")

        expires_at = policy.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(expires_at)
            if datetime.now(timezone.utc) > exp:
                raise ValueError(f"PyHSM: key '{key_id}' has expired")

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_key(
        self,
        key_id: str,
        key_type: str = "aes-256",
        *,
        metadata: Optional[dict] = None,
        policy: Optional[dict] = None,
    ) -> str:
        """
        Generate a new cryptographic key.

        Supported types: aes-128, aes-256, rsa-2048, rsa-4096, ec-p256.
        Returns the key_id.
        """
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)

            if key_type == "aes-256":
                key_data = os.urandom(32).hex()
                public_key_pem = None
            elif key_type == "aes-128":
                key_data = os.urandom(16).hex()
                public_key_pem = None
            elif key_type == "rsa-2048":
                key_data, public_key_pem = _gen_rsa(2048)
            elif key_type == "rsa-4096":
                key_data, public_key_pem = _gen_rsa(4096)
            elif key_type == "ec-p256":
                key_data, public_key_pem = _gen_ec(ec.SECP256R1())
            else:
                raise ValueError(f"Unsupported key type: {key_type}")

            now_iso = _utcnow()
            entry = {
                "key_id": key_id,
                "key_type": key_type,
                "current_version": 1,
                "versions": [
                    {
                        "version": 1,
                        "key_data": key_data,
                        "created_at": now_iso,
                        "archived": False,
                    }
                ],
                "public_key_pem": public_key_pem,
                "policy": policy or {"allow_encrypt": True, "allow_decrypt": True, "allow_sign": True},
                "operation_count": 0,
                "created_at": now_iso,
                "metadata": metadata or {},
            }
            self._store.save_key(key_id, entry)
            self._audit.record("generateKey", key_id=key_id, success=True)
            self._update_key_metrics()
            return key_id


    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------

    def rotate_key(self, key_id: str) -> int:
        """
        Rotate a key: generates a new version, archives the old.
        Returns the new version number.
        Only works for AES keys.
        """
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not entry["key_type"].startswith("aes"):
                raise ValueError("Key rotation is only supported for AES keys")

            # Archive current version
            for v in entry["versions"]:
                if v["version"] == entry["current_version"]:
                    v["archived"] = True
                    break

            # Generate new version
            key_len = 32 if entry["key_type"] == "aes-256" else 16
            new_version = entry["current_version"] + 1
            entry["versions"].append({
                "version": new_version,
                "key_data": os.urandom(key_len).hex(),
                "created_at": _utcnow(),
                "archived": False,
            })
            entry["current_version"] = new_version
            self._store.update_key(key_id, entry)
            self._audit.record("rotateKey", key_id=key_id, success=True)
            self._update_key_metrics()
            return new_version

    # ------------------------------------------------------------------
    # Key destruction / listing
    # ------------------------------------------------------------------

    def destroy_key(self, key_id: str) -> None:
        """Destroy a key — all versions are zeroized and removed."""
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)
            # Overwrite all key material in memory
            for v in entry["versions"]:
                v["key_data"] = "0" * len(v["key_data"])
            self._store.delete_key(key_id)
            self._rate_limiter.reset(key_id)
            self._audit.record("destroyKey", key_id=key_id, success=True)
            self._update_key_metrics()

    def list_keys(self) -> list[dict]:
        """List all key IDs with their types, creation dates, and policies."""
        with self._lock:
            self._assert_session()
            keys = self._store.load_all()
            return [
                {
                    "key_id": kid,
                    "key_type": v["key_type"],
                    "current_version": v.get("current_version", 1),
                    "created_at": v.get("created_at", ""),
                    "policy": v.get("policy", {}),
                }
                for kid, v in keys.items()
            ]

    def has_key(self, key_id: str) -> bool:
        """Check whether a key_id exists in the store."""
        with self._lock:
            self._assert_session()
            try:
                self._store.load_key(key_id)
                return True
            except KeyError:
                return False


    # ------------------------------------------------------------------
    # Encrypt / Decrypt (AES-256-GCM with version prefix)
    # ------------------------------------------------------------------

    def encrypt(self, key_id: str, plaintext) -> str:
        """
        Encrypt data using a stored AES key.
        Returns hex-encoded: version(4 bytes) + nonce(12) + ciphertext+tag.
        Ciphertext is always encrypted with the current key version.
        """
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not entry["key_type"].startswith("aes"):
                raise ValueError("Encryption requires an AES key")

            self._enforce_policy(entry, "encrypt")

            # Get current version
            current = next(
                (v for v in entry["versions"] if v["version"] == entry["current_version"]),
                None,
            )
            if not current or current.get("archived"):
                raise ValueError(f"PyHSM: key '{key_id}' current version is archived")

            key = bytes.fromhex(current["key_data"])
            nonce = os.urandom(12)
            data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
            ct = AESGCM(key).encrypt(nonce, data, None)

            # Version prefix: 4 bytes big-endian
            version_bytes = current["version"].to_bytes(_VERSION_PREFIX_LEN, "big")
            result = (version_bytes + nonce + ct).hex()

            entry["operation_count"] = entry.get("operation_count", 0) + 1
            self._store.update_key(key_id, entry)
            self._metrics.record_op("encrypt")
            self._audit.record("encrypt", key_id=key_id, success=True)
            return result

    def decrypt(self, key_id: str, ciphertext_hex: str) -> bytes:
        """
        Decrypt hex-encoded ciphertext with version prefix.
        Selects the correct key version from the version prefix.
        """
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not entry["key_type"].startswith("aes"):
                raise ValueError("Decryption requires an AES key")

            self._enforce_policy(entry, "decrypt")

            raw = bytes.fromhex(ciphertext_hex)
            if len(raw) < _VERSION_PREFIX_LEN + 12 + 16:
                raise ValueError("PyHSM: ciphertext too short")

            version = int.from_bytes(raw[:_VERSION_PREFIX_LEN], "big")
            nonce = raw[_VERSION_PREFIX_LEN : _VERSION_PREFIX_LEN + 12]
            ct = raw[_VERSION_PREFIX_LEN + 12 :]

            # Find the matching version
            v_entry = next(
                (v for v in entry["versions"] if v["version"] == version), None
            )
            if not v_entry:
                raise ValueError(f"PyHSM: key version {version} not found for '{key_id}'")

            key = bytes.fromhex(v_entry["key_data"])
            plain = AESGCM(key).decrypt(nonce, ct, None)

            entry["operation_count"] = entry.get("operation_count", 0) + 1
            self._store.update_key(key_id, entry)
            self._metrics.record_op("decrypt")
            self._audit.record("decrypt", key_id=key_id, success=True)
            return plain


    # ------------------------------------------------------------------
    # Sign / Verify
    # ------------------------------------------------------------------

    def sign(self, key_id: str, message) -> str:
        """Sign a message using a stored RSA or EC key. Returns hex-encoded signature."""
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not (entry["key_type"].startswith("rsa") or entry["key_type"].startswith("ec")):
                raise ValueError("Signing requires an RSA or EC key")

            self._enforce_policy(entry, "sign")

            data = message.encode("utf-8") if isinstance(message, str) else message

            # Load private key from current version
            current = next(
                (v for v in entry["versions"] if v["version"] == entry["current_version"]),
                None,
            )
            if not current:
                raise ValueError(f"PyHSM: no current version for key '{key_id}'")

            private_key = serialization.load_pem_private_key(
                current["key_data"].encode(), password=None
            )

            if entry["key_type"].startswith("rsa"):
                sig = private_key.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            elif entry["key_type"].startswith("ec"):
                sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            else:
                raise ValueError("Signing requires an RSA or EC key")

            entry["operation_count"] = entry.get("operation_count", 0) + 1
            self._store.update_key(key_id, entry)
            self._metrics.record_op("sign")
            self._audit.record("encrypt", key_id=key_id, success=True)
            return sig.hex()

    def verify(self, key_id: str, message, signature_hex: str) -> bool:
        """
        Verify a signature using the stored PUBLIC key.
        Does NOT load the private key — only the public key PEM stored at generation time.
        Returns True if valid, False otherwise.
        """
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            data = message.encode("utf-8") if isinstance(message, str) else message
            sig = bytes.fromhex(signature_hex)

            pub_pem = entry.get("public_key_pem")
            if not pub_pem:
                raise ValueError(f"PyHSM: key '{key_id}' has no public key")

            public_key = serialization.load_pem_public_key(pub_pem.encode())

            try:
                if entry["key_type"].startswith("rsa"):
                    public_key.verify(
                        sig,
                        data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                elif entry["key_type"].startswith("ec"):
                    public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
                else:
                    return False
                self._metrics.record_op("verify")
                return True
            except Exception:
                return False


    # ------------------------------------------------------------------
    # Public key export
    # ------------------------------------------------------------------

    def get_public_key(self, key_id: str) -> str:
        """Export the public key (PEM) for an asymmetric key. Never touches the private key."""
        with self._lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)
            if entry["key_type"].startswith("aes"):
                raise ValueError("AES keys have no public component")
            pub = entry.get("public_key_pem")
            if not pub:
                raise ValueError(f"PyHSM: no public key stored for '{key_id}'")
            return pub

    # ------------------------------------------------------------------
    # Expiry enforcement
    # ------------------------------------------------------------------

    def enforce_expiry(self) -> None:
        """Archive all keys whose policy.expires_at is in the past."""
        with self._lock:
            self._assert_session()
            now = datetime.now(timezone.utc)
            for entry in self._store.load_all().values():
                expires_at = entry.get("policy", {}).get("expires_at")
                if not expires_at:
                    continue
                if datetime.fromisoformat(expires_at) < now:
                    for v in entry["versions"]:
                        v["archived"] = True
                    self._store.update_key(entry["key_id"], entry)
                    self._audit.record("archiveKey", key_id=entry["key_id"], success=True, reason="expired")
            self._update_key_metrics()

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def get_metrics(self) -> dict:
        """Return current operational metrics as a dict."""
        return self._metrics.get_metrics()

    def get_prometheus_metrics(self) -> str:
        """Return metrics in Prometheus text exposition format."""
        return self._metrics.to_prometheus()

    def get_audit_log(self) -> AuditLog:
        """Return the AuditLog instance for direct inspection or verification."""
        return self._audit


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _now() -> float:
    import time
    return time.monotonic()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _gen_rsa(key_size: int) -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _gen_ec(curve) -> tuple[str, str]:
    private_key = ec.generate_private_key(curve)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem
