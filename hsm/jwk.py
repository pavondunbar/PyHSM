"""
PyHSM JWK (JSON Web Key) Import/Export.

Supports RFC 7517 / RFC 7518 key formats for interoperability with
other KMS systems, identity providers, and standards-based tooling.

Supported key types for export:
  - AES-128, AES-256 → {"kty": "oct", "k": <base64url>, ...}
  - EC P-256/P-384/P-521/secp256k1 → {"kty": "EC", "crv": "P-256"|"P-384"|"P-521"|"secp256k1", ...}
  - Ed25519           → {"kty": "OKP", "crv": "Ed25519", ...}
  - RSA-2048/4096     → {"kty": "RSA", "n": ..., "e": ..., "d": ..., ...}

Supported key types for import:
  - {"kty": "oct"}    → AES symmetric key
  - {"kty": "EC"}     → ECDSA key (P-256, P-384, P-521, secp256k1)
  - {"kty": "OKP"}    → Ed25519 key
  - {"kty": "RSA"}    → RSA key

MEMORY SAFETY WARNING
---------------------
All export functions in this module return Python ``dict`` objects whose
values are ``str`` instances containing base64url-encoded key material.
Python strings are **immutable** — they cannot be overwritten in place,
so there is no way to deterministically zeroize the key material inside a
returned JWK dict once it has been created.

This is an unavoidable limitation of the Python data model for string
types. To limit exposure:

  1. Treat the returned dict as a short-lived secret.
  2. Delete all references to it as soon as possible (``del jwk``).
  3. Call ``zeroize_jwk(jwk)`` before deleting — this overwrites the dict
     values with empty strings, removing the key material from the dict
     object itself (though the original string objects may linger in the
     CPython heap until GC collects them).
  4. Never log, serialize to disk, or pass the dict to untrusted code.
  5. For RSA keys, the full CRT private key (d, p, q, dp, dq, qi) is
     included in the exported dict — treat it with the same care as the
     raw private key bytes.

Example safe usage::

    from hsm.jwk import zeroize_jwk

    jwk = hsm.export_jwk("my-ec-key")
    try:
        send_to_peer(jwk)   # use the JWK
    finally:
        zeroize_jwk(jwk)    # clear dict values before discarding
        del jwk             # drop the reference
"""

from __future__ import annotations

import base64
import json
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519
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

    .. warning::
        The returned dict contains the raw symmetric key as an immutable
        Python ``str`` (base64url-encoded). It **cannot be zeroized** in
        place. Call ``zeroize_jwk(jwk)`` and ``del jwk`` as soon as the
        dict is no longer needed. See module docstring for details.
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
    Supports P-256, P-384, P-521, and secp256k1.

    .. warning::
        The returned dict contains the private scalar ``d`` (and public
        coordinates ``x``, ``y``) as immutable Python ``str`` values
        (base64url-encoded). They **cannot be zeroized** in place. Call
        ``zeroize_jwk(jwk)`` and ``del jwk`` as soon as the dict is no
        longer needed. See module docstring for details.
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
    elif isinstance(curve, ec.SECP521R1):
        crv = "P-521"
        coord_size = 66
    elif isinstance(curve, ec.SECP256K1):
        crv = "secp256k1"
        coord_size = 32
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


def export_ed25519_jwk(private_key_pem: bytes, key_id: Optional[str] = None) -> dict:
    """
    Export an Ed25519 private key (PEM) as a JWK.

    Returns a dict with kty="OKP", crv="Ed25519", x (public), d (private).
    Uses RFC 8037 (CFRG Elliptic Curves) format.

    .. warning::
        The returned dict contains the 32-byte private key seed ``d`` and
        public key ``x`` as immutable Python ``str`` values (base64url-
        encoded). They **cannot be zeroized** in place. Call
        ``zeroize_jwk(jwk)`` and ``del jwk`` as soon as the dict is no
        longer needed. See module docstring for details.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key")

    # Extract raw 32-byte private key seed and public key
    raw_private = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )

    jwk: dict = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": _b64url_encode(raw_public),
        "d": _b64url_encode(raw_private),
        "key_ops": ["sign", "verify"],
    }
    if key_id:
        jwk["kid"] = key_id
    return jwk


def export_rsa_jwk(private_key_pem: bytes, key_id: Optional[str] = None) -> dict:
    """
    Export an RSA private key (PEM) as a JWK.

    Returns a dict with kty="RSA", n, e, d, p, q, dp, dq, qi fields.

    .. warning::
        The returned dict contains the **full CRT private key** — modulus
        ``n``, private exponent ``d``, primes ``p`` and ``q``, and CRT
        coefficients ``dp``, ``dq``, ``qi`` — all as immutable Python
        ``str`` values (base64url-encoded). This is the most sensitive
        possible export: all components needed to reconstruct the private
        key are present. They **cannot be zeroized** in place. Call
        ``zeroize_jwk(jwk)`` and ``del jwk`` immediately after use. See
        module docstring for details.
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


def zeroize_jwk(jwk: dict) -> None:
    """
    Best-effort zeroization of a JWK dict returned by any export function.

    Overwrites every string value in the dict with an empty string, removing
    the key material from the dict object itself. This does **not** guarantee
    that the original string objects are erased from the CPython heap —
    Python ``str`` is immutable and the interpreter may hold references in
    the string intern table or elsewhere. However, it is strictly better
    than doing nothing: it removes the key material from the dict so that
    any code still holding a reference to the dict cannot read it.

    Always follow this call with ``del jwk`` to drop the last reference.

    Parameters
    ----------
    jwk : dict
        A JWK dict previously returned by one of the export functions in
        this module. Modified in place.

    Example
    -------
    ::

        jwk = hsm.export_jwk("my-key")
        try:
            use(jwk)
        finally:
            zeroize_jwk(jwk)
            del jwk
    """
    # Overwrite sensitive string fields with empty strings.
    # Non-string values (lists, ints) are left unchanged — they carry no
    # key material. Unknown keys are also cleared defensively.
    _SENSITIVE_FIELDS = frozenset({"k", "d", "x", "y", "n", "e", "p", "q", "dp", "dq", "qi"})
    for key in list(jwk.keys()):
        val = jwk[key]
        if isinstance(val, str) and key in _SENSITIVE_FIELDS:
            jwk[key] = ""


def import_jwk(jwk: dict) -> tuple[str, bytes, Optional[str]]:
    """
    Import a JWK and return (key_type, raw_key_bytes, public_key_pem_or_None).

    Returns:
      key_type: "aes-128", "aes-256", "ec-p256", "ec-p384", "ec-p521",
                "ec-secp256k1", "ed25519", "rsa-2048", "rsa-4096"
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
        elif crv == "P-521":
            curve = ec.SECP521R1()
            coord_size = 66
        elif crv == "secp256k1":
            curve = ec.SECP256K1()
            coord_size = 32
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

        key_type_map = {
            "P-256": "ec-p256",
            "P-384": "ec-p384",
            "P-521": "ec-p521",
            "secp256k1": "ec-secp256k1",
        }
        key_type = key_type_map[crv]
        return key_type, priv_pem, pub_pem

    elif kty == "OKP":
        crv = jwk.get("crv")
        if crv != "Ed25519":
            raise ValueError(f"Unsupported OKP curve: {crv}")

        # Import Ed25519 from raw seed (d) and derive public key
        raw_d = _b64url_decode(jwk["d"])
        if len(raw_d) != 32:
            raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(raw_d)}")

        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_d)

        priv_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        return "ed25519", priv_pem, pub_pem

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
