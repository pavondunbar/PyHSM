"""
PyHSM JWK (JSON Web Key) Import/Export.

Supports RFC 7517 / RFC 7518 key formats for interoperability with
other KMS systems, identity providers, and standards-based tooling.

Supported key types for export:
  - AES-128, AES-256 → {"kty": "oct", "k": <base64url>, ...}
  - EC P-256          → {"kty": "EC", "crv": "P-256", "x": ..., "y": ..., "d": ...}
  - RSA-2048/4096     → {"kty": "RSA", "n": ..., "e": ..., "d": ..., ...}

Supported key types for import:
  - {"kty": "oct"}    → AES symmetric key
  - {"kty": "EC"}     → ECDSA key (P-256)
  - {"kty": "RSA"}    → RSA key
"""

from __future__ import annotations

import base64
import json
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding (RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _int_to_bytes(n: int, length: int) -> bytes:
    """Convert an integer to big-endian bytes of specified length."""
    return n.to_bytes(length, "big")


def _bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to integer."""
    return int.from_bytes(b, "big")


def export_symmetric_jwk(raw_key: bytes, key_id: Optional[str] = None) -> dict:
    """
    Export a symmetric key as a JWK.

    Returns a dict with kty="oct", k=<base64url-encoded key material>.
    """
    jwk: dict = {
        "kty": "oct",
        "k": _b64url_encode(raw_key),
        "alg": f"A{len(raw_key) * 8}GCM",
        "key_ops": ["encrypt", "decrypt"],
    }
    if key_id:
        jwk["kid"] = key_id
    return jwk


def export_ec_jwk(private_key_pem: bytes, key_id: Optional[str] = None) -> dict:
    """
    Export an EC private key (PEM) as a JWK.

    Returns a dict with kty="EC", crv, x, y, d fields.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Not an EC private key")

    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    # Determine curve name
    curve = private_key.curve
    if isinstance(curve, ec.SECP256R1):
        crv = "P-256"
        coord_size = 32
    elif isinstance(curve, ec.SECP384R1):
        crv = "P-384"
        coord_size = 48
    else:
        raise ValueError(f"Unsupported curve: {curve.name}")

    jwk: dict = {
        "kty": "EC",
        "crv": crv,
        "x": _b64url_encode(_int_to_bytes(public_numbers.x, coord_size)),
        "y": _b64url_encode(_int_to_bytes(public_numbers.y, coord_size)),
        "d": _b64url_encode(_int_to_bytes(private_numbers.private_value, coord_size)),
        "key_ops": ["sign", "verify"],
    }
    if key_id:
        jwk["kid"] = key_id
    return jwk


def export_rsa_jwk(private_key_pem: bytes, key_id: Optional[str] = None) -> dict:
    """
    Export an RSA private key (PEM) as a JWK.

    Returns a dict with kty="RSA", n, e, d, p, q, dp, dq, qi fields.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Not an RSA private key")

    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    key_size = private_key.key_size // 8  # bytes

    jwk: dict = {
        "kty": "RSA",
        "n": _b64url_encode(_int_to_bytes(public_numbers.n, key_size)),
        "e": _b64url_encode(_int_to_bytes(public_numbers.e, 3)),
        "d": _b64url_encode(_int_to_bytes(private_numbers.d, key_size)),
        "p": _b64url_encode(_int_to_bytes(private_numbers.p, key_size // 2)),
        "q": _b64url_encode(_int_to_bytes(private_numbers.q, key_size // 2)),
        "dp": _b64url_encode(_int_to_bytes(private_numbers.dmp1, key_size // 2)),
        "dq": _b64url_encode(_int_to_bytes(private_numbers.dmq1, key_size // 2)),
        "qi": _b64url_encode(_int_to_bytes(private_numbers.iqmp, key_size // 2)),
        "key_ops": ["sign", "verify"],
    }
    if key_id:
        jwk["kid"] = key_id
    return jwk


def import_jwk(jwk: dict) -> tuple[str, bytes, Optional[str]]:
    """
    Import a JWK and return (key_type, raw_key_bytes, public_key_pem_or_None).

    Returns:
      key_type: "aes-128", "aes-256", "ec-p256", "rsa-2048", "rsa-4096"
      raw_key_bytes: raw symmetric key bytes OR PEM-encoded private key bytes
      public_key_pem: PEM string for asymmetric keys, None for symmetric
    """
    kty = jwk.get("kty")

    if kty == "oct":
        raw = _b64url_decode(jwk["k"])
        if len(raw) == 16:
            return "aes-128", raw, None
        elif len(raw) == 32:
            return "aes-256", raw, None
        else:
            raise ValueError(f"Unsupported symmetric key size: {len(raw)} bytes")

    elif kty == "EC":
        crv = jwk.get("crv")
        if crv == "P-256":
            curve = ec.SECP256R1()
            coord_size = 32
        elif crv == "P-384":
            curve = ec.SECP384R1()
            coord_size = 48
        else:
            raise ValueError(f"Unsupported curve: {crv}")

        x = _bytes_to_int(_b64url_decode(jwk["x"]))
        y = _bytes_to_int(_b64url_decode(jwk["y"]))
        d = _bytes_to_int(_b64url_decode(jwk["d"]))

        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        private_numbers = ec.EllipticCurvePrivateNumbers(d, public_numbers)
        private_key = private_numbers.private_key()

        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        key_type = "ec-p256" if crv == "P-256" else "ec-p384"
        return key_type, priv_pem, pub_pem

    elif kty == "RSA":
        n = _bytes_to_int(_b64url_decode(jwk["n"]))
        e = _bytes_to_int(_b64url_decode(jwk["e"]))
        d = _bytes_to_int(_b64url_decode(jwk["d"]))
        p = _bytes_to_int(_b64url_decode(jwk["p"]))
        q = _bytes_to_int(_b64url_decode(jwk["q"]))
        dp = _bytes_to_int(_b64url_decode(jwk["dp"]))
        dq = _bytes_to_int(_b64url_decode(jwk["dq"]))
        qi = _bytes_to_int(_b64url_decode(jwk["qi"]))

        public_numbers = rsa.RSAPublicNumbers(e, n)
        private_numbers = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)
        private_key = private_numbers.private_key()

        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        key_size = private_key.key_size
        key_type = f"rsa-{key_size}"
        return key_type, priv_pem, pub_pem

    else:
        raise ValueError(f"Unsupported JWK key type: {kty}")
