# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
Offline JWT license verification for PyHSM.

Tokens are RS256-signed JWTs issued by VectorGuard Labs and verified locally
using an embedded RSA public key. No network call is made at any point.

Token payload schema
--------------------
{
    "sub":   "customer@example.com",   # licensee identity
    "iss":   "vectorguardlabs.com",    # must match ISSUER constant
    "iat":   <unix timestamp>,         # issued-at
    "exp":   <unix timestamp>,         # expiry (recommended: 90 days)
    "tier":  "startup"|"growth"|"scale",
    "seats": <int>,                    # max concurrent PyHSM instances (0 = unlimited)
    "keys":  <int>,                    # max keys per instance (0 = unlimited)
    "jti":   "<uuid4>",                # unique token ID for your records
}

Usage (library consumers)
-------------------------
    hsm = PyHSM(
        storage_path="keystore.enc",
        master_password="...",
        license_token="<jwt>",         # or
        license_file="/etc/pyhsm/license.jwt",
    )

Usage (CLI)
-----------
    vectorguard-pyhsm --license-file /etc/pyhsm/license.jwt generate my-key
    PYHSM_LICENSE_TOKEN=<jwt> vectorguard-pyhsm generate my-key
"""

from __future__ import annotations

import base64
import json
import os
import struct
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

from .logging import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ISSUER = "vectorguardlabs.com"

# Valid tier values (must match COMMERCIAL_LICENSE.md)
VALID_TIERS = {"startup", "growth", "scale"}

# ---------------------------------------------------------------------------
# Embedded public key (RSA-2048, PEM)
# Replace the placeholder below with your real public key after running
# tools/generate_license_keypair.py
# ---------------------------------------------------------------------------

_EMBEDDED_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxh1xul2+DKqJ6W3y3k98
CbHOQUY9FgHMvl/qZYwHwEsUCSfBDYn3kHvp46m/lEcwSS+BHOdrEUvNS9animos
qQhHgKt0hHtIxFMxdf55W2nuFKhcQd+yLPYJFAs9FWkOkF0UzCL96cO6EZO13hST
v2p/ZwvbYP/n1qT6QvL3b1TooRI2osB2ZCJA+AnGAD3AIE7kapZFBBNW2NRLI+zD
dg1fuYvIIo8HsKAh8mNTdt8P9+sXwfCmog6krQYNzRVuj7qkooHiUgp2thId4H7x
A/85MEOv5bERLPAvHRNY1P4RrYkq6kCSA9RIssq/pTuFkVN7I2/5BvdIRbBsAY6m
9QIDAQAB
-----END PUBLIC KEY-----"""

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


class LicenseTier(str, Enum):
    STARTUP = "startup"
    GROWTH = "growth"
    SCALE = "scale"
    AGPL = "agpl"  # no commercial token — AGPL terms apply


@dataclass(frozen=True)
class LicenseInfo:
    """Decoded, verified license information attached to a PyHSM session."""

    tier: LicenseTier
    licensee: str          # "sub" claim — customer identifier
    expires_at: float      # Unix timestamp
    max_seats: int         # 0 = unlimited
    max_keys: int          # 0 = unlimited
    token_id: str          # "jti" claim — unique token ID

    @property
    def is_commercial(self) -> bool:
        return self.tier != LicenseTier.AGPL

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def check_key_limit(self, current_key_count: int) -> None:
        """Raise LicenseError if the key count would exceed the tier limit."""
        if self.max_keys > 0 and current_key_count >= self.max_keys:
            raise LicenseError(
                f"PyHSM: key limit reached for '{self.tier.value}' license "
                f"(max {self.max_keys} keys). "
                "Upgrade your tier or contact pavon@vectorguardlabs.com."
            )

    def __str__(self) -> str:
        import datetime
        exp = datetime.datetime.fromtimestamp(self.expires_at, tz=datetime.timezone.utc).isoformat()
        return (
            f"LicenseInfo(tier={self.tier.value}, licensee={self.licensee!r}, "
            f"expires_at={exp}, max_keys={self.max_keys or 'unlimited'}, "
            f"token_id={self.token_id!r})"
        )


# Sentinel for AGPL (no-token) sessions
AGPL_LICENSE = LicenseInfo(
    tier=LicenseTier.AGPL,
    licensee="agpl-user",
    expires_at=float("inf"),
    max_seats=0,
    max_keys=0,
    token_id="agpl",
)


class LicenseError(Exception):
    """Raised when a commercial license token is present but invalid."""


# ---------------------------------------------------------------------------
# JWT helpers (no PyJWT dependency — uses cryptography primitives directly)
# ---------------------------------------------------------------------------

def _b64url_decode(s: str | bytes) -> bytes:
    """Base64url-decode without padding."""
    if isinstance(s, str):
        s = s.encode("ascii")
    # Add padding
    pad = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + b"=" * pad)


def _load_public_key(pem: bytes) -> RSAPublicKey:
    key = serialization.load_pem_public_key(pem, backend=default_backend())
    if not isinstance(key, RSAPublicKey):
        raise LicenseError("PyHSM: license public key must be RSA.")
    return key


def _verify_rs256(public_key: RSAPublicKey, message: bytes, signature: bytes) -> None:
    """Verify an RS256 (RSASSA-PKCS1-v1_5 + SHA-256) signature. Raises InvalidSignature on failure."""
    public_key.verify(
        signature,
        message,
        asym_padding.PKCS1v15(),
        hashes.SHA256(),
    )


def _decode_jwt_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    """
    Split and decode a JWT without verifying the signature.
    Returns (header, payload, signing_input_bytes, signature_bytes).
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise LicenseError("PyHSM: malformed license token (expected 3 JWT parts).")

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception) as exc:
        raise LicenseError(f"PyHSM: could not decode license token: {exc}") from exc

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _b64url_decode(parts[2])
    return header, payload, signing_input, signature


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_token_from_file(path: str) -> str:
    """
    Read a license token from a file.
    The file may contain just the JWT string, optionally with whitespace.
    """
    if not os.path.exists(path):
        raise LicenseError(f"PyHSM: license file not found: {path!r}")
    with open(path, "r", encoding="utf-8") as f:
        token = f.read().strip()
    if not token:
        raise LicenseError(f"PyHSM: license file is empty: {path!r}")
    return token


def verify_license_token(
    token: str,
    *,
    public_key_pem: Optional[bytes] = None,
) -> LicenseInfo:
    """
    Verify a PyHSM commercial license token and return a ``LicenseInfo``.

    Parameters
    ----------
    token : str
        The RS256-signed JWT issued by VectorGuard Labs.
    public_key_pem : bytes, optional
        Override the embedded public key (useful for testing).

    Raises
    ------
    LicenseError
        If the token is malformed, has an invalid signature, is expired,
        has the wrong issuer, or is missing required claims.
    """
    pem = public_key_pem or _EMBEDDED_PUBLIC_KEY_PEM

    # Reject placeholder key — protects against running before keygen
    if b"PLACEHOLDER_REPLACE_WITH_REAL_PUBLIC_KEY" in pem:
        raise LicenseError(
            "PyHSM: license public key has not been configured. "
            "Run tools/generate_license_keypair.py to generate your keypair, "
            "then embed the public key in hsm/license.py."
        )

    try:
        public_key = _load_public_key(pem)
    except Exception as exc:
        raise LicenseError(f"PyHSM: failed to load license public key: {exc}") from exc

    header, payload, signing_input, signature = _decode_jwt_unverified(token)

    # --- Algorithm check
    if header.get("alg") != "RS256":
        raise LicenseError(
            f"PyHSM: license token uses unsupported algorithm "
            f"'{header.get('alg')}'. Only RS256 is accepted."
        )

    # --- Signature verification
    try:
        _verify_rs256(public_key, signing_input, signature)
    except InvalidSignature:
        raise LicenseError(
            "PyHSM: license token signature is invalid. "
            "The token may have been tampered with or was not issued by VectorGuard Labs."
        )

    # --- Required claims
    for claim in ("sub", "iss", "exp", "iat", "tier", "jti"):
        if claim not in payload:
            raise LicenseError(f"PyHSM: license token is missing required claim '{claim}'.")

    # --- Issuer
    if payload["iss"] != ISSUER:
        raise LicenseError(
            f"PyHSM: license token issuer '{payload['iss']}' is not trusted. "
            f"Expected '{ISSUER}'."
        )

    # --- Expiry
    now = time.time()
    if now > payload["exp"]:
        import datetime
        exp_str = datetime.datetime.fromtimestamp(
            payload["exp"], tz=datetime.timezone.utc
        ).isoformat()
        raise LicenseError(
            f"PyHSM: commercial license expired on {exp_str}. "
            "Renew at pavon@vectorguardlabs.com."
        )

    # --- Not-before (optional)
    if "nbf" in payload and now < payload["nbf"]:
        raise LicenseError("PyHSM: license token is not yet valid (nbf claim).")

    # --- Tier
    tier_str = payload.get("tier", "").lower()
    if tier_str not in VALID_TIERS:
        raise LicenseError(
            f"PyHSM: license token contains unknown tier '{tier_str}'. "
            f"Expected one of: {', '.join(sorted(VALID_TIERS))}."
        )

    info = LicenseInfo(
        tier=LicenseTier(tier_str),
        licensee=payload["sub"],
        expires_at=float(payload["exp"]),
        max_seats=int(payload.get("seats", 0)),
        max_keys=int(payload.get("keys", 0)),
        token_id=payload["jti"],
    )

    _logger.info(
        "commercial license verified",
        extra={
            "event": "license_verified",
            "tier": info.tier.value,
            "licensee": info.licensee,
            "token_id": info.token_id,
        },
    )
    return info
