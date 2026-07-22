"""PyHSM — Software-based Hardware Security Module."""

from .core import PyHSM
from .storage import KeyStore, TamperError
from .audit import AuditLog
from .rate_limiter import RateLimiter
from .metrics import MetricsCollector
from .self_test import run_self_tests
from .shamir import split_secret, reconstruct_secret, zeroize

__all__ = [
    "PyHSM",
    "KeyStore",
    "TamperError",
    "AuditLog",
    "RateLimiter",
    "MetricsCollector",
    "run_self_tests",
    "split_secret",
    "reconstruct_secret",
    "zeroize",
]
