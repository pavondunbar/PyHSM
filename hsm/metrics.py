"""
PyHSM Health Metrics.

Tracks per-operation counters and exposes them in both dict and
Prometheus text-exposition format. Mirrors the TypeScript MetricsCollector.
"""

from __future__ import annotations

import time
from typing import Optional


class MetricsCollector:
    """Thread-safe-ish metrics collector (single-process, GIL-protected)."""

    def __init__(self) -> None:
        self._start = time.monotonic()
        self._total_ops = 0
        self._encrypt_ops = 0
        self._decrypt_ops = 0
        self._sign_ops = 0
        self._verify_ops = 0
        self._errors = 0
        self._rate_limit_hits = 0
        self._access_denials = 0
        self._active_keys = 0
        self._archived_keys = 0
        self._last_op_at: Optional[float] = None

    # ------------------------------------------------------------------
    # Increment helpers
    # ------------------------------------------------------------------

    def record_op(self, op_type: str) -> None:
        self._total_ops += 1
        self._last_op_at = time.monotonic()
        if op_type == "encrypt":
            self._encrypt_ops += 1
        elif op_type == "decrypt":
            self._decrypt_ops += 1
        elif op_type == "sign":
            self._sign_ops += 1
        elif op_type == "verify":
            self._verify_ops += 1

    def record_error(self) -> None:
        self._errors += 1

    def record_rate_limit(self) -> None:
        self._rate_limit_hits += 1

    def record_access_denial(self) -> None:
        self._access_denials += 1

    def set_key_count(self, active: int, archived: int) -> None:
        self._active_keys = active
        self._archived_keys = archived

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_metrics(self) -> dict:
        uptime = time.monotonic() - self._start
        return {
            "totalOperations": self._total_ops,
            "encryptOps": self._encrypt_ops,
            "decryptOps": self._decrypt_ops,
            "signOps": self._sign_ops,
            "verifyOps": self._verify_ops,
            "errors": self._errors,
            "rateLimitHits": self._rate_limit_hits,
            "accessDenials": self._access_denials,
            "activeKeys": self._active_keys,
            "archivedKeys": self._archived_keys,
            "uptimeSeconds": uptime,
        }

    def to_prometheus(self) -> str:
        """Render metrics in Prometheus text exposition format."""
        m = self.get_metrics()
        lines = [
            "# HELP pyhsm_operations_total Total HSM operations",
            "# TYPE pyhsm_operations_total counter",
            f'pyhsm_operations_total{{type="encrypt"}} {m["encryptOps"]}',
            f'pyhsm_operations_total{{type="decrypt"}} {m["decryptOps"]}',
            f'pyhsm_operations_total{{type="sign"}} {m["signOps"]}',
            f'pyhsm_operations_total{{type="verify"}} {m["verifyOps"]}',
            "# HELP pyhsm_errors_total Total HSM errors",
            "# TYPE pyhsm_errors_total counter",
            f'pyhsm_errors_total {m["errors"]}',
            "# HELP pyhsm_rate_limit_hits_total Rate limit rejections",
            "# TYPE pyhsm_rate_limit_hits_total counter",
            f'pyhsm_rate_limit_hits_total {m["rateLimitHits"]}',
            "# HELP pyhsm_access_denials_total Access control rejections",
            "# TYPE pyhsm_access_denials_total counter",
            f'pyhsm_access_denials_total {m["accessDenials"]}',
            "# HELP pyhsm_keys Active keys in the HSM",
            "# TYPE pyhsm_keys gauge",
            f'pyhsm_keys{{state="active"}} {m["activeKeys"]}',
            f'pyhsm_keys{{state="archived"}} {m["archivedKeys"]}',
            "# HELP pyhsm_uptime_seconds HSM uptime in seconds",
            "# TYPE pyhsm_uptime_seconds gauge",
            f'pyhsm_uptime_seconds {m["uptimeSeconds"]:.1f}',
        ]
        return "\n".join(lines)
