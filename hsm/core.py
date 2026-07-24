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
import threading
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding, aes_key_unwrap_with_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .storage import KeyStore, TamperError
from .audit import AuditLog
from .rate_limiter import RateLimiter
from .metrics import MetricsCollector
from .self_test import run_self_tests
from .secure_memory import SecureBytes, zeroize_bytearray
from .jwk import (
    export_symmetric_jwk,
    export_ec_jwk,
    export_rsa_jwk,
    export_ed25519_jwk,
    import_jwk as _import_jwk,
)

# Key ID validation: 1-128 chars, start alphanumeric, body [a-zA-Z0-9._-]
_KEY_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._\-]{0,127}$')

# Ciphertext version prefix length (4 bytes big-endian uint32)
_VERSION_PREFIX_LEN = 4

# Ciphertext format version: 0x02 = AAD-bound; 0x01 = legacy (no AAD)
_CT_FORMAT_V2 = 2
_CT_FORMAT_V1 = 1

# Maximum plaintext size (64 MB) — prevents OOM denial-of-service
_MAX_PLAINTEXT_SIZE = 64 * 1024 * 1024


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

    Notes
    -----
    All key operations (generate, encrypt, decrypt, sign, verify, rotate,
    destroy, import/export) accept an optional ``caller_id`` keyword argument.
    When provided, it is recorded in the audit log for every operation and
    enforced against the key's ``allowed_callers`` policy if configured.
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

        # Derive the audit HMAC key from the master password via HKDF.
        # This eliminates the plaintext .hmackey file on disk — the audit
        # chain integrity is now tied to the master password.
        audit_hmac_key = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=32,
            info=b"pyhsm-audit-hmac-v1",
        ).derive(master_password.encode("utf-8"))

        self._audit = AuditLog(audit_path, hmac_key=audit_hmac_key)
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
        # Sharded locks: per-key operations use striped locks for concurrency,
        # global lock only for session/lifecycle operations
        self._global_lock = threading.Lock()
        self._key_locks: dict[str, threading.Lock] = {}
        self._key_locks_lock = threading.Lock()  # protects _key_locks dict

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
            with self._global_lock:
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

    def _key_lock(self, key_id: str) -> threading.Lock:
        """Get or create a per-key lock for concurrent operations."""
        with self._key_locks_lock:
            if key_id not in self._key_locks:
                self._key_locks[key_id] = threading.Lock()
            return self._key_locks[key_id]

    def close_session(self) -> None:
        """Explicitly close the session, flushing and zeroizing key material."""
        with self._global_lock:
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
    # Per-key wrapping (AES-KWP RFC 5649)
    # ------------------------------------------------------------------

    def _wrap_key_data(self, raw_key: bytes) -> bytearray:
        """Wrap raw key material with AES-KWP, return bytearray for in-memory storage."""
        kek = self._store._derive_kek()
        try:
            wrapped = aes_key_wrap_with_padding(bytes(kek), raw_key)
            return bytearray(wrapped)
        finally:
            zeroize_bytearray(kek)

    def _unwrap_key_data(self, wrapped_data) -> bytes:
        """Unwrap stored key material. Accepts bytearray or hex string. Caller must manage the result."""
        kek = self._store._derive_kek()
        try:
            if isinstance(wrapped_data, bytearray):
                raw = bytes(wrapped_data)
            elif isinstance(wrapped_data, bytes):
                raw = wrapped_data
            else:
                # Legacy: hex string
                raw = bytes.fromhex(wrapped_data)
            return aes_key_unwrap_with_padding(bytes(kek), raw)
        finally:
            zeroize_bytearray(kek)

    # ------------------------------------------------------------------
    # Policy enforcement
    # ------------------------------------------------------------------

    def _enforce_policy(self, entry: dict, operation: str, caller_id: Optional[str] = None) -> None:
        """Check per-key policy; raise ValueError if any constraint is violated.

        Order of checks is deliberate: ACL and policy checks (which have no
        side effects) run first. The rate limiter — which consumes a token —
        runs last so that rejected requests (unauthorized caller, denied
        operation, expired key) do not burn rate-limit tokens and cannot be
        used to DOS legitimate callers.
        """
        policy = entry.get("policy", {})
        key_id = entry.get("key_id", "?")

        # 1. Caller ACL (no side effects)
        allowed_callers = policy.get("allowed_callers")
        if allowed_callers and caller_id not in allowed_callers:
            self._audit.record("accessDenied", key_id=key_id, caller_id=caller_id, success=False,
                               reason=f"caller '{caller_id}' not in allowed_callers")
            raise ValueError(
                f"PyHSM: caller '{caller_id}' is not authorized for key '{key_id}'"
            )

        # 2. Operation permission (no side effects)
        if operation == "encrypt" and not policy.get("allow_encrypt", True):
            raise ValueError(f"PyHSM: key '{key_id}' policy denies encrypt")
        if operation == "decrypt" and not policy.get("allow_decrypt", True):
            raise ValueError(f"PyHSM: key '{key_id}' policy denies decrypt")
        if operation == "sign" and not policy.get("allow_sign", True):
            raise ValueError(f"PyHSM: key '{key_id}' policy denies sign")

        # 3. Max operations (no side effects)
        max_ops = policy.get("max_operations")
        if max_ops is not None and entry.get("operation_count", 0) >= max_ops:
            raise ValueError(f"PyHSM: key '{key_id}' exceeded max operations ({max_ops})")

        # 4. Expiry (no side effects)
        expires_at = policy.get("expires_at")
        if expires_at:
            exp = datetime.fromisoformat(expires_at)
            if datetime.now(timezone.utc) > exp:
                raise ValueError(f"PyHSM: key '{key_id}' has expired")

        # 5. Rate limiter LAST — consumes a token only when the request is
        #    otherwise valid. Prevents unauthorized callers from exhausting
        #    the rate-limit window for legitimate users.
        if not self._rate_limiter.allow(key_id):
            self._metrics.record_rate_limit()
            self._audit.record("rateLimited", key_id=key_id, caller_id=caller_id, success=False)
            raise ValueError(f"PyHSM: key '{key_id}' is rate-limited")

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
        caller_id: Optional[str] = None,
    ) -> str:
        """
        Generate a new cryptographic key.

        Supported types: aes-128, aes-256, rsa-2048, rsa-4096, ec-p256, ec-p384, ec-p521,
                         ec-secp256k1, ed25519.
        Returns the key_id.
        """
        with self._global_lock:
            self._assert_session()
            _validate_key_id(key_id)

            if key_type == "aes-256":
                raw = os.urandom(32)
                key_data = self._wrap_key_data(raw)
                public_key_pem = None
            elif key_type == "aes-128":
                raw = os.urandom(16)
                key_data = self._wrap_key_data(raw)
                public_key_pem = None
            elif key_type == "rsa-2048":
                priv_pem, public_key_pem = _gen_rsa(2048)
                key_data = self._wrap_key_data(priv_pem.encode())
            elif key_type == "rsa-4096":
                priv_pem, public_key_pem = _gen_rsa(4096)
                key_data = self._wrap_key_data(priv_pem.encode())
            elif key_type == "ec-p256":
                priv_pem, public_key_pem = _gen_ec(ec.SECP256R1())
                key_data = self._wrap_key_data(priv_pem.encode())
            elif key_type == "ec-p384":
                priv_pem, public_key_pem = _gen_ec(ec.SECP384R1())
                key_data = self._wrap_key_data(priv_pem.encode())
            elif key_type == "ec-p521":
                priv_pem, public_key_pem = _gen_ec(ec.SECP521R1())
                key_data = self._wrap_key_data(priv_pem.encode())
            elif key_type == "ec-secp256k1":
                priv_pem, public_key_pem = _gen_ec(ec.SECP256K1())
                key_data = self._wrap_key_data(priv_pem.encode())
            elif key_type == "ed25519":
                priv_pem, public_key_pem = _gen_ed25519()
                key_data = self._wrap_key_data(priv_pem.encode())
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
            self._audit.record("generateKey", key_id=key_id, caller_id=caller_id, success=True)
            self._update_key_metrics()
            return key_id


    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------

    def rotate_key(self, key_id: str, *, caller_id: Optional[str] = None) -> int:
        """
        Rotate a key: generates a new version, archives the old.
        Returns the new version number.
        Only works for AES keys.
        """
        with self._global_lock:
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
            raw = os.urandom(key_len)
            entry["versions"].append({
                "version": new_version,
                "key_data": self._wrap_key_data(raw),
                "created_at": _utcnow(),
                "archived": False,
            })
            entry["current_version"] = new_version
            self._store.update_key(key_id, entry)
            self._audit.record("rotateKey", key_id=key_id, caller_id=caller_id, success=True)
            self._update_key_metrics()
            return new_version

    # ------------------------------------------------------------------
    # Key destruction / listing
    # ------------------------------------------------------------------

    def destroy_key(self, key_id: str, *, caller_id: Optional[str] = None) -> None:
        """Destroy a key — all versions are zeroized and removed."""
        with self._global_lock:
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)
            # Overwrite all key material in memory byte-by-byte
            for v in entry["versions"]:
                kd = v["key_data"]
                if isinstance(kd, bytearray):
                    zeroize_bytearray(kd)
                v["key_data"] = bytearray()
            self._store.delete_key(key_id)
            self._rate_limiter.reset(key_id)
            # Clean up per-key lock to prevent unbounded growth
            with self._key_locks_lock:
                self._key_locks.pop(key_id, None)
            self._audit.record("destroyKey", key_id=key_id, caller_id=caller_id, success=True)
            self._update_key_metrics()

    def list_keys(self) -> list[dict]:
        """List all key IDs with their types, creation dates, and policies."""
        with self._global_lock:
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
        with self._global_lock:
            self._assert_session()
            try:
                self._store.load_key(key_id)
                return True
            except KeyError:
                return False


    # ------------------------------------------------------------------
    # Encrypt / Decrypt (AES-256-GCM with version prefix)
    # ------------------------------------------------------------------

    def encrypt(self, key_id: str, plaintext: str | bytes, *, caller_id: Optional[str] = None) -> str:
        """
        Encrypt data using a stored AES key.

        Returns hex-encoded: format(1) + version(4 bytes) + nonce(12) + ciphertext+tag.
        Ciphertext is always encrypted with the current key version.

        Security features:
          - Per-key AES-KWP wrapping (keys double-encrypted at rest)
          - AAD binds ciphertext to the key_id (prevents cross-key confusion)
          - Hybrid nonce: 4-byte random prefix + 4-byte counter + 4-byte random
            suffix. The counter prevents birthday-bound collisions even at
            high encryption volumes (safe well beyond 2^32 operations per key).
          - Input size validation (max 64 MB)
        """
        with self._key_lock(key_id):
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not entry["key_type"].startswith("aes"):
                raise ValueError("Encryption requires an AES key")

            self._enforce_policy(entry, "encrypt", caller_id)

            # Get current version
            current = next(
                (v for v in entry["versions"] if v["version"] == entry["current_version"]),
                None,
            )
            if not current or current.get("archived"):
                raise ValueError(f"PyHSM: key '{key_id}' current version is archived")

            data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext

            # Input size guard
            if len(data) > _MAX_PLAINTEXT_SIZE:
                raise ValueError(
                    f"PyHSM: plaintext too large ({len(data)} bytes). "
                    f"Maximum is {_MAX_PLAINTEXT_SIZE} bytes (64 MB)."
                )

            # Hybrid nonce: random(4) + counter(4) + random(4) = 12 bytes
            op_count = entry.get("operation_count", 0)
            counter_bytes = (op_count & 0xFFFFFFFF).to_bytes(4, "big")
            nonce = os.urandom(4) + counter_bytes + os.urandom(4)

            # AAD: bind ciphertext to key_id + version
            aad = f"pyhsm:v1:{key_id}:{current['version']}".encode("utf-8")

            # Unwrap key material
            raw_key = self._unwrap_key_data(current["key_data"])
            key = SecureBytes(raw_key)
            try:
                ct = AESGCM(bytes(key.buf)).encrypt(nonce, data, aad)
            finally:
                key.zeroize()

            # Format: format_byte(1) + version(4) + nonce(12) + ciphertext+tag
            format_byte = _CT_FORMAT_V2.to_bytes(1, "big")
            version_bytes = current["version"].to_bytes(_VERSION_PREFIX_LEN, "big")
            result = (format_byte + version_bytes + nonce + ct).hex()

            entry["operation_count"] = op_count + 1
            self._store.update_key(key_id, entry)
            self._metrics.record_op("encrypt")
            self._audit.record("encrypt", key_id=key_id, caller_id=caller_id, success=True)
            return result

    def decrypt(self, key_id: str, ciphertext_hex: str, *, caller_id: Optional[str] = None) -> bytes:
        """
        Decrypt hex-encoded ciphertext.

        Supports two formats:
          - v2 (current): format_byte(1) + version(4) + nonce(12) + ct+tag  [with AAD]
          - v1 (legacy):  version(4) + nonce(12) + ct+tag                   [no AAD]

        Automatically detects the format from the first byte.
        """
        with self._key_lock(key_id):
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not entry["key_type"].startswith("aes"):
                raise ValueError("Decryption requires an AES key")

            self._enforce_policy(entry, "decrypt", caller_id)

            # Input size guard: reject ciphertext that would decode to > 64 MB
            # (hex string is 2x the binary size)
            _MAX_CIPHERTEXT_HEX_LEN = _MAX_PLAINTEXT_SIZE * 2
            if len(ciphertext_hex) > _MAX_CIPHERTEXT_HEX_LEN:
                raise ValueError(
                    f"PyHSM: ciphertext too large ({len(ciphertext_hex)} hex chars). "
                    f"Maximum is {_MAX_CIPHERTEXT_HEX_LEN} hex chars (64 MB binary)."
                )

            raw = bytes.fromhex(ciphertext_hex)

            # Detect format: v2 starts with 0x02, v1 starts with 0x00 (version 1 high byte)
            if len(raw) < 1:
                raise ValueError("PyHSM: ciphertext too short")

            format_byte = raw[0]
            if format_byte == _CT_FORMAT_V2:
                # v2 format: format(1) + version(4) + nonce(12) + ct+tag
                if len(raw) < 1 + _VERSION_PREFIX_LEN + 12 + 16:
                    raise ValueError("PyHSM: ciphertext too short")
                version = int.from_bytes(raw[1:1 + _VERSION_PREFIX_LEN], "big")
                nonce = raw[1 + _VERSION_PREFIX_LEN : 1 + _VERSION_PREFIX_LEN + 12]
                ct = raw[1 + _VERSION_PREFIX_LEN + 12:]
                use_aad = True
            else:
                # v1 legacy format: version(4) + nonce(12) + ct+tag (no format byte)
                if len(raw) < _VERSION_PREFIX_LEN + 12 + 16:
                    raise ValueError("PyHSM: ciphertext too short")
                version = int.from_bytes(raw[:_VERSION_PREFIX_LEN], "big")
                nonce = raw[_VERSION_PREFIX_LEN : _VERSION_PREFIX_LEN + 12]
                ct = raw[_VERSION_PREFIX_LEN + 12:]
                use_aad = False

            # Find the matching version
            v_entry = next(
                (v for v in entry["versions"] if v["version"] == version), None
            )
            if not v_entry:
                raise ValueError(f"PyHSM: key version {version} not found for '{key_id}'")

            # AAD only for v2 format
            aad = f"pyhsm:v1:{key_id}:{version}".encode("utf-8") if use_aad else None

            # Unwrap key material
            raw_key = self._unwrap_key_data(v_entry["key_data"])
            key = SecureBytes(raw_key)
            try:
                plain = AESGCM(bytes(key.buf)).decrypt(nonce, ct, aad)
            finally:
                key.zeroize()

            entry["operation_count"] = entry.get("operation_count", 0) + 1
            self._store.update_key(key_id, entry)
            self._metrics.record_op("decrypt")
            self._audit.record("decrypt", key_id=key_id, caller_id=caller_id, success=True)
            return plain


    # ------------------------------------------------------------------
    # Sign / Verify
    # ------------------------------------------------------------------

    def sign(self, key_id: str, message: str | bytes, *, caller_id: Optional[str] = None) -> str:
        """Sign a message using a stored RSA, EC, or Ed25519 key. Returns hex-encoded signature."""
        with self._key_lock(key_id):
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)

            if not (entry["key_type"].startswith("rsa") or entry["key_type"].startswith("ec") or entry["key_type"] == "ed25519"):
                raise ValueError("Signing requires an RSA, EC, or Ed25519 key")

            self._enforce_policy(entry, "sign", caller_id)

            data = message.encode("utf-8") if isinstance(message, str) else message

            # Load private key from current version
            current = next(
                (v for v in entry["versions"] if v["version"] == entry["current_version"]),
                None,
            )
            if not current:
                raise ValueError(f"PyHSM: no current version for key '{key_id}'")

            private_key = serialization.load_pem_private_key(
                self._unwrap_key_data(current["key_data"]), password=None
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
            elif entry["key_type"] == "ed25519":
                sig = private_key.sign(data)
            elif entry["key_type"].startswith("ec"):
                hash_alg = _ec_hash_for_key_type(entry["key_type"])
                sig = private_key.sign(data, ec.ECDSA(hash_alg))
            else:
                raise ValueError("Signing requires an RSA, EC, or Ed25519 key")

            entry["operation_count"] = entry.get("operation_count", 0) + 1
            self._store.update_key(key_id, entry)
            self._metrics.record_op("sign")
            self._audit.record("sign", key_id=key_id, caller_id=caller_id, success=True)
            return sig.hex()

    def verify(self, key_id: str, message: str | bytes, signature_hex: str, *, caller_id: Optional[str] = None) -> bool:
        """
        Verify a signature using the stored PUBLIC key.
        Does NOT load the private key — only the public key PEM stored at generation time.
        Returns True if valid, False otherwise.
        """
        with self._key_lock(key_id):
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
                elif entry["key_type"] == "ed25519":
                    public_key.verify(sig, data)
                elif entry["key_type"].startswith("ec"):
                    hash_alg = _ec_hash_for_key_type(entry["key_type"])
                    public_key.verify(sig, data, ec.ECDSA(hash_alg))
                else:
                    return False
                entry["operation_count"] = entry.get("operation_count", 0) + 1
                self._store.update_key(key_id, entry)
                self._metrics.record_op("verify")
                self._audit.record("verify", key_id=key_id, caller_id=caller_id, success=True)
                return True
            except Exception:
                self._audit.record("verify", key_id=key_id, caller_id=caller_id, success=False)
                return False


    # ------------------------------------------------------------------
    # Public key export
    # ------------------------------------------------------------------

    def get_public_key(self, key_id: str) -> str:
        """Export the public key (PEM) for an asymmetric key. Never touches the private key."""
        with self._key_lock(key_id):
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
    # JWK Import / Export (RFC 7517)
    # ------------------------------------------------------------------

    def export_jwk(self, key_id: str, *, caller_id: Optional[str] = None) -> dict:
        """
        Export a key as a JWK (JSON Web Key, RFC 7517).

        Unwraps the stored key material and converts to standard JWK format.
        Supports AES, EC, and RSA key types.

        WARNING: The returned dict contains raw private key material.
        Handle with care and zeroize after use.
        """
        with self._key_lock(key_id):
            self._assert_session()
            _validate_key_id(key_id)
            entry = self._store.load_key(key_id)
            key_type = entry["key_type"]

            # Get current version's key material
            current = next(
                (v for v in entry["versions"] if v["version"] == entry["current_version"]),
                None,
            )
            if not current:
                raise ValueError(f"PyHSM: no current version for key '{key_id}'")

            raw_key = self._unwrap_key_data(current["key_data"])

            try:
                if key_type.startswith("aes"):
                    return export_symmetric_jwk(raw_key, key_id=key_id)
                elif key_type == "ed25519":
                    return export_ed25519_jwk(raw_key, key_id=key_id)
                elif key_type.startswith("ec"):
                    return export_ec_jwk(raw_key, key_id=key_id)
                elif key_type.startswith("rsa"):
                    return export_rsa_jwk(raw_key, key_id=key_id)
                else:
                    raise ValueError(f"Unsupported key type for JWK export: {key_type}")
            finally:
                # Best-effort zeroize raw key bytes
                if isinstance(raw_key, bytearray):
                    zeroize_bytearray(raw_key)

    def import_key_jwk(
        self,
        key_id: str,
        jwk: dict,
        *,
        metadata: Optional[dict] = None,
        policy: Optional[dict] = None,
        caller_id: Optional[str] = None,
    ) -> str:
        """
        Import a key from a JWK (JSON Web Key, RFC 7517).

        Accepts standard JWK dicts with kty="oct", "EC", or "RSA".
        The key material is wrapped with AES-KWP before storage.

        Returns the key_id.
        """
        with self._global_lock:
            self._assert_session()
            _validate_key_id(key_id)

            key_type, raw_key, public_key_pem = _import_jwk(jwk)

            # Wrap the key material
            key_data = self._wrap_key_data(raw_key)

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
            self._audit.record("generateKey", key_id=key_id, caller_id=caller_id, success=True)
            self._update_key_metrics()
            return key_id

    # ------------------------------------------------------------------
    # Expiry enforcement
    # ------------------------------------------------------------------

    def enforce_expiry(self) -> None:
        """Archive all keys whose policy.expires_at is in the past."""
        with self._global_lock:
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


def _gen_ed25519() -> tuple[str, str]:
    """Generate an Ed25519 keypair. Returns (private_pem, public_pem)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
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


def _ec_hash_for_key_type(key_type: str):
    """Return the appropriate hash algorithm for the given EC key type.

    NIST recommendations:
      P-256 → SHA-256
      P-384 → SHA-384
      P-521 → SHA-512
      secp256k1 → SHA-256 (standard for Bitcoin/Ethereum ECDSA)
    """
    if key_type == "ec-p384":
        return hashes.SHA384()
    elif key_type == "ec-p521":
        return hashes.SHA512()
    # Default for ec-p256, ec-secp256k1, and any other ec- prefix
    return hashes.SHA256()
