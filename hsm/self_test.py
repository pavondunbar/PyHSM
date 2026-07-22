"""
PyHSM Startup Self-Tests (Known Answer Tests).

Verifies cryptographic primitives produce expected outputs before any
operations are accepted. Mirrors the TypeScript self-test module.
Required for FIPS 140-2 Level 1 compliance evidence.
"""

from __future__ import annotations

import os
import hashlib
import hmac as _hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def _test_aes_gcm() -> dict:
    """AES-256-GCM round-trip and tag sanity check."""
    key = bytes(32)
    nonce = bytes(12)
    pt = bytes(16)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, pt, None)
    # ct includes the 16-byte GCM tag appended by cryptography
    try:
        recovered = aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        return {"test": "AES-256-GCM", "passed": False, "error": str(e)}
    if recovered != pt:
        return {"test": "AES-256-GCM", "passed": False, "error": "Round-trip mismatch"}
    # Tag must be non-zero (the last 16 bytes)
    tag = ct[-16:]
    if tag == bytes(16):
        return {"test": "AES-256-GCM", "passed": False, "error": "Auth tag is all zeros"}
    return {"test": "AES-256-GCM", "passed": True}


def _test_pbkdf2() -> dict:
    """PBKDF2-SHA256 against RFC 6070 test vector."""
    expected = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"salt", iterations=4096)
    result = kdf.derive(b"password")
    if result.hex() != expected:
        return {"test": "PBKDF2-SHA256", "passed": False, "error": f"Got {result.hex()}"}
    return {"test": "PBKDF2-SHA256", "passed": True}


def _test_hmac() -> dict:
    """HMAC-SHA256 against RFC 4231 Test Case 1."""
    key = bytes([0x0B] * 20)
    data = b"Hi There"
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    result = _hmac.new(key, data, hashlib.sha256).hexdigest()
    if result != expected:
        return {"test": "HMAC-SHA256", "passed": False, "error": f"Got {result}"}
    return {"test": "HMAC-SHA256", "passed": True}


def _test_csprng() -> dict:
    """Verify CSPRNG produces non-degenerate output."""
    a = os.urandom(32)
    b = os.urandom(32)
    if a == b:
        return {"test": "CSPRNG", "passed": False, "error": "Duplicate random output"}
    if a == bytes(32):
        return {"test": "CSPRNG", "passed": False, "error": "All-zero output"}
    return {"test": "CSPRNG", "passed": True}


def run_self_tests() -> list[dict]:
    """
    Run all KATs. Raises RuntimeError if any fail.
    Returns list of result dicts on success.
    Must be called before the HSM accepts any operations.
    """
    results = [_test_aes_gcm(), _test_pbkdf2(), _test_hmac(), _test_csprng()]
    failures = [r for r in results if not r["passed"]]
    if failures:
        msgs = "; ".join(f"{r['test']}: {r.get('error', '')}" for r in failures)
        raise RuntimeError(f"PyHSM self-test FAILED: {msgs}")
    return results
