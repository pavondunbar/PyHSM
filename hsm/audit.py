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
import threading
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from .logging import get_logger

_logger = get_logger(__name__)


_VALID_OPERATIONS = frozenset(
    [
        "encrypt",
        "decrypt",
        "sign",
        "verify",
        "generateKey",
        "importKey",
        "destroyKey",
        "rotateKey",
        "archiveKey",
        "exportKey",
        "exportKeyDenied",
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
      1. Explicit ``hmac_key`` parameter (required for production use)
      2. PYHSM_AUDIT_HMAC_KEY environment variable (hex-encoded 32 bytes)

    When used through the PyHSM class, the HMAC key is automatically
    derived from the master password via HKDF — no manual configuration
    is needed.

    Log rotation:
      - ``max_bytes``: rotate when the log file exceeds this size (default: 50 MB, 0 = unlimited)
      - ``max_entries``: rotate after this many entries (default: 0 = unlimited)
      - ``max_rotated_files``: how many rotated files to keep (default: 10)

    Rotated files are named ``<log_path>.1``, ``<log_path>.2``, etc.
    The most recent rotated file is always ``.1``.

    Raises ValueError if no HMAC key is provided via either method.
    """

    def __init__(
        self,
        log_path: str,
        webhook_url: Optional[str] = None,
        *,
        hmac_key: Optional[bytes] = None,
        max_bytes: int = 50 * 1024 * 1024,  # 50 MB default
        max_entries: int = 0,  # 0 = no entry-based limit
        max_rotated_files: int = 10,
    ) -> None:
        self.log_path = log_path
        self.webhook_url = webhook_url or os.environ.get("PYHSM_AUDIT_WEBHOOK")
        self._last_hmac = "0" * 64
        self._sequence = 0
        self._max_bytes = max_bytes
        self._max_entries = max_entries
        self._max_rotated_files = max_rotated_files
        self._entries_since_load = 0

        # Resolve HMAC key (priority: explicit param > env var)
        if hmac_key:
            self._hmac_key = hmac_key
        else:
            env_key = os.environ.get("PYHSM_AUDIT_HMAC_KEY")
            if env_key:
                self._hmac_key = bytes.fromhex(env_key)
            else:
                raise ValueError(
                    "AuditLog: hmac_key is required. Provide it explicitly or set "
                    "the PYHSM_AUDIT_HMAC_KEY environment variable (hex-encoded "
                    "32 bytes). When using PyHSM, this is derived automatically "
                    "from the master password."
                )

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

        self._entries_since_load += 1

        # Check if rotation is needed
        self._maybe_rotate()

        # Best-effort webhook shipping (non-blocking)
        if self.webhook_url:
            self._ship_to_webhook(entry)

    def _maybe_rotate(self) -> None:
        """Rotate the log file if it exceeds configured size or entry limits."""
        needs_rotation = False

        if self._max_bytes > 0:
            try:
                file_size = os.path.getsize(self.log_path)
                if file_size >= self._max_bytes:
                    needs_rotation = True
            except OSError:
                pass

        if not needs_rotation and self._max_entries > 0:
            if self._entries_since_load >= self._max_entries:
                needs_rotation = True

        if needs_rotation:
            self._rotate()

    def _rotate(self) -> None:
        """
        Rotate log files using numbered suffixes.

        The current log becomes .1, previous .1 becomes .2, etc.
        Files beyond max_rotated_files are deleted.
        """
        # Delete the oldest file if it would exceed max_rotated_files
        oldest = f"{self.log_path}.{self._max_rotated_files}"
        if os.path.exists(oldest):
            os.unlink(oldest)

        # Shift existing rotated files: .9 → .10, .8 → .9, ..., .1 → .2
        for i in range(self._max_rotated_files - 1, 0, -1):
            src = f"{self.log_path}.{i}"
            dst = f"{self.log_path}.{i + 1}"
            if os.path.exists(src):
                os.rename(src, dst)

        # Rotate current file to .1
        if os.path.exists(self.log_path):
            os.rename(self.log_path, f"{self.log_path}.1")

        # Reset state for the new file — HMAC chain continues from where it left off
        # (this is intentional: the chain spans rotations for tamper evidence)
        self._entries_since_load = 0

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
        """Best-effort, non-blocking HTTP POST of a single audit entry.

        Dispatched in a daemon thread so that webhook latency or failures
        never block HSM operations. If the webhook is unreachable, the
        entry is silently dropped (it's already persisted to the local log).

        Each request includes an X-PyHSM-Signature header containing
        HMAC-SHA256(hmac_key, body) so the receiver can verify authenticity.
        """
        threading.Thread(
            target=self._do_ship_to_webhook,
            args=(entry,),
            daemon=True,
        ).start()

    def _do_ship_to_webhook(self, entry: dict) -> None:
        """Actual HTTP POST — runs in a background thread."""
        try:
            data = json.dumps(entry).encode()
            signature = _hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "X-PyHSM-Signature": f"sha256={signature}",
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            _logger.error("webhook delivery failed", extra={
                "event": "webhook_failure",
                "webhook_url": self.webhook_url,
                "operation": entry.get("operation"),
                "sequence": entry.get("sequence"),
                "error": str(exc),
            })
