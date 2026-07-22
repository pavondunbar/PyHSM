"""
PyHSM HMAC-Chained Audit Log.

Append-only file where each entry is HMAC-linked to the previous,
creating a tamper-evident chain. Optional webhook shipping.
Mirrors the TypeScript AuditLog module.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Optional


_VALID_OPERATIONS = frozenset(
    [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "generateKey",
        "destroyKey",
        "rotateKey",
        "archiveKey",
        "sessionOpen",
        "sessionClose",
        "tamperDetected",
        "selfTestPass",
        "selfTestFail",
        "rateLimited",
        "accessDenied",
        "backup",
        "verifyBackup",
    ]
)


class AuditLog:
    """
    Append-only, HMAC-chained JSON Lines audit log.

    File format: one JSON object per line.
    Each entry carries an 'hmac' field computed as:
        HMAC-SHA256(key, json(entry_without_hmac) + prev_hmac_hex)

    The HMAC key is resolved with the following priority:
      1. Explicit ``hmac_key`` parameter (recommended: derived from master password)
      2. PYHSM_AUDIT_HMAC_KEY environment variable (hex-encoded 32 bytes)
      3. Persisted key file at <log_path>.hmackey (mode 0o600)
      4. Auto-generated random key (written to key file)
    """

    def __init__(self, log_path: str, webhook_url: Optional[str] = None, *, hmac_key: Optional[bytes] = None) -> None:
        self.log_path = log_path
        self.webhook_url = webhook_url or os.environ.get("PYHSM_AUDIT_WEBHOOK")
        self._last_hmac = "0" * 64
        self._sequence = 0

        # Resolve HMAC key (priority: explicit param > env var > key file > generate)
        if hmac_key:
            self._hmac_key = hmac_key
        else:
            env_key = os.environ.get("PYHSM_AUDIT_HMAC_KEY")
            if env_key:
                self._hmac_key = bytes.fromhex(env_key)
            else:
                key_file = log_path + ".hmackey"
                if os.path.exists(key_file):
                    with open(key_file, "r") as f:
                        self._hmac_key = bytes.fromhex(f.read().strip())
                else:
                    self._hmac_key = os.urandom(32)
                    # Write with restricted permissions
                    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as f:
                        f.write(self._hmac_key.hex())

        self._load_last_state()

    def _load_last_state(self) -> None:
        if not os.path.exists(self.log_path):
            return
        with open(self.log_path, "r") as f:
            lines = [l for l in f.read().strip().split("\n") if l.strip()]
        if not lines:
            return
        try:
            last = json.loads(lines[-1])
            self._last_hmac = last.get("hmac", self._last_hmac)
            self._sequence = last.get("sequence", len(lines) - 1) + 1
        except (json.JSONDecodeError, KeyError):
            self._sequence = len(lines)

    def _compute_hmac(self, entry_without_hmac: dict) -> str:
        payload = json.dumps(entry_without_hmac, separators=(",", ":"), sort_keys=True)
        payload += self._last_hmac
        return _hmac.new(self._hmac_key, payload.encode(), hashlib.sha256).hexdigest()

    def record(
        self,
        operation: str,
        *,
        key_id: Optional[str] = None,
        caller_id: Optional[str] = None,
        success: bool,
        reason: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """Append a tamper-evident entry to the audit log."""
        entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sequence": self._sequence,
            "operation": operation,
            "success": success,
        }
        if key_id is not None:
            entry["keyId"] = key_id
        if caller_id is not None:
            entry["callerId"] = caller_id
        if reason is not None:
            entry["reason"] = reason
        if extra:
            entry.update(extra)

        entry["hmac"] = self._compute_hmac(entry)
        self._last_hmac = entry["hmac"]
        self._sequence += 1

        line = json.dumps(entry, separators=(",", ":")) + "\n"
        # Append atomically via os-level append (O_APPEND is atomic on POSIX)
        fd = os.open(
            self.log_path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )
        with os.fdopen(fd, "a") as f:
            f.write(line)

        # Best-effort webhook shipping (non-blocking)
        if self.webhook_url:
            self._ship_to_webhook(entry)

    def verify(self) -> int:
        """
        Verify the HMAC chain of the entire log.
        Returns -1 if the log is clean, or the first corrupted sequence number.
        """
        if not os.path.exists(self.log_path):
            return -1
        with open(self.log_path, "r") as f:
            lines = [l for l in f.read().strip().split("\n") if l.strip()]

        prev_hmac = "0" * 64
        for line in lines:
            entry = json.loads(line)
            stored_hmac = entry.pop("hmac", None)
            # Re-sort keys to match how we serialised
            expected = _hmac.new(
                self._hmac_key,
                (
                    json.dumps(entry, separators=(",", ":"), sort_keys=True) + prev_hmac
                ).encode(),
                hashlib.sha256,
            ).hexdigest()
            if stored_hmac != expected:
                return entry.get("sequence", -2)
            prev_hmac = stored_hmac
        return -1

    def export_jsonl(
        self,
        *,
        operation: Optional[str] = None,
        key_id: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> list[dict]:
        """
        Return filtered log entries as a list of dicts.
        Useful for SIEM ingestion or human inspection.
        All timestamps are ISO-8601 UTC.
        """
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path, "r") as f:
            lines = [l for l in f.read().strip().split("\n") if l.strip()]

        results = []
        for line in lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if operation and entry.get("operation") != operation:
                continue
            if key_id and entry.get("keyId") != key_id:
                continue
            ts = entry.get("timestamp", "")
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            results.append(entry)
        return results

    def _ship_to_webhook(self, entry: dict) -> None:
        """Best-effort HTTP POST of a single audit entry."""
        try:
            data = json.dumps(entry).encode()
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            # Short timeout; failure is silently ignored
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
