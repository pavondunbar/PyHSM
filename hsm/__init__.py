"""PyHSM — Software-based Hardware Security Module."""

from .core import PyHSM
from .storage import KeyStore, TamperError
from .backends import StorageBackend, FileBackend, MemoryBackend
from .secure_memory import SecureBytes, zeroize_bytearray
from .audit import AuditLog
from .rate_limiter import RateLimiter
from .metrics import MetricsCollector
from .self_test import run_self_tests
from .shamir import split_secret, reconstruct_secret, zeroize
from .jwk import export_symmetric_jwk, export_ec_jwk, export_rsa_jwk

__all__ = [
    "PyHSM",
    "KeyStore",
    "TamperError",
    "StorageBackend",
    "FileBackend",
    "MemoryBackend",
    "SecureBytes",
    "zeroize_bytearray",
    "AuditLog",
    "RateLimiter",
    "MetricsCollector",
    "run_self_tests",
    "split_secret",
    "reconstruct_secret",
    "zeroize",
    "export_symmetric_jwk",
    "export_ec_jwk",
    "export_rsa_jwk",
]
