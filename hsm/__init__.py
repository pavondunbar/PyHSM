"""PyHSM — Production-grade Software Key Management System."""

from .core import PyHSM
from .storage import KeyStore, TamperError
from .backends import StorageBackend, FileBackend, MemoryBackend
from .secure_memory import SecureBytes, zeroize_bytearray
from .audit import AuditLog
from .rate_limiter import RateLimiter
from .metrics import MetricsCollector
from .self_test import run_self_tests
from .shamir import split_secret, reconstruct_secret, zeroize
from .jwk import export_symmetric_jwk, export_ec_jwk, export_rsa_jwk, export_ed25519_jwk, zeroize_jwk
from .logging import get_logger
from .password_file import load_password_from_file, check_password_file_permissions
from .ipc_client import IPCClient
from .ipc_server import IPCServer

__all__ = [
    # Core HSM
    "PyHSM",
    "KeyStore",
    "TamperError",
    # Storage backends
    "StorageBackend",
    "FileBackend",
    "MemoryBackend",
    # Secure memory
    "SecureBytes",
    "zeroize_bytearray",
    # Audit
    "AuditLog",
    # Rate limiting
    "RateLimiter",
    # Metrics
    "MetricsCollector",
    # Self-tests
    "run_self_tests",
    # Shamir secret sharing
    "split_secret",
    "reconstruct_secret",
    "zeroize",
    # JWK import/export
    "export_symmetric_jwk",
    "export_ec_jwk",
    "export_rsa_jwk",
    "export_ed25519_jwk",
    "zeroize_jwk",
    # Logging
    "get_logger",
    # Password file injection
    "load_password_from_file",
    "check_password_file_permissions",
    # Process isolation IPC
    "IPCClient",
    "IPCServer",
]
