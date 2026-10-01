"""Shamir's Secret Sharing over GF(256) with AES irreducible polynomial."""

import hashlib
import os

# GF(256) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
_EXP = [0] * 256
_LOG = [0] * 256

_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11b if _x >= 128 else 0)
    _x &= 0xFF
_EXP[255] = _EXP[0]


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def _gf_div(a, b):
    if b == 0:
        raise ValueError("GF(256) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def split_secret(secret: bytes, k: int, n: int) -> list[dict]:
    """Split secret into n shares with threshold k. Returns list of share dicts.

    Each share dict contains:
      - ``index``: 1-based share index (int)
      - ``data``: hex-encoded share bytes
      - ``checksum``: first 4 bytes of SHA-256(secret) as hex — used by
        ``reconstruct_secret()`` to detect corrupted or mismatched shares
        after reconstruction. Without this, a wrong share silently produces
        an incorrect secret with no indication of failure.
    """
    if k < 2 or k > n or n > 255:
        raise ValueError("Invalid k/n: need 2 <= k <= n <= 255")
    if len(secret) == 0:
        raise ValueError("Secret must not be empty")

    # Compute the 4-byte integrity checksum from the original secret.
    # This is embedded in every share so reconstruct_secret() can verify
    # the output without needing any share to carry the full secret.
    checksum = hashlib.sha256(secret).digest()[:4].hex()

    shares = [bytearray(len(secret)) for _ in range(n)]

    for b in range(len(secret)):
        coeffs = bytearray(k)
        coeffs[0] = secret[b]
        rand = os.urandom(k - 1)
        for c in range(1, k):
            coeffs[c] = rand[c - 1]

        for i in range(n):
            x = i + 1
            y = 0
            for c in range(k - 1, -1, -1):
                y = _gf_mul(y, x) ^ coeffs[c]
            shares[i][b] = y

    return [
        {"index": i + 1, "data": bytes(shares[i]).hex(), "checksum": checksum}
        for i in range(n)
    ]


def zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros to remove secret material from memory."""
    for i in range(len(buf)):
        buf[i] = 0


def reconstruct_secret(shares: list[dict]) -> bytearray:
    """Reconstruct a secret from k or more shares via Lagrange interpolation.

    Returns a mutable bytearray so the caller can zeroize it after use.

    Integrity check
    ---------------
    If shares contain a ``checksum`` field (4 hex bytes = first 4 bytes of
    SHA-256 of the original secret), the reconstructed value is verified
    against it. A mismatch means at least one share is corrupted or belongs
    to a different split, and a ``ValueError`` is raised before the wrong
    value can be used.

    Shares produced by older versions of PyHSM that lack a ``checksum``
    field are still accepted — the check is skipped with no error so
    existing shares remain usable.
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares")

    bufs = [bytearray.fromhex(s["data"]) for s in shares]
    length = len(bufs[0])
    result = bytearray(length)

    for b in range(length):
        secret = 0
        for i in range(len(shares)):
            lagrange = 1
            for j in range(len(shares)):
                if i == j:
                    continue
                lagrange = _gf_mul(lagrange, _gf_div(shares[j]["index"], shares[j]["index"] ^ shares[i]["index"]))
            secret ^= _gf_mul(bufs[i][b], lagrange)
        result[b] = secret

    # Zeroize intermediate share buffers
    for buf in bufs:
        zeroize(buf)

    # Verify integrity checksum if present in shares.
    # All shares from the same split carry the same checksum — use the first.
    stored_checksum = shares[0].get("checksum")
    if stored_checksum is not None:
        actual_checksum = hashlib.sha256(bytes(result)).digest()[:4].hex()
        if actual_checksum != stored_checksum:
            zeroize(result)
            raise ValueError(
                "PyHSM Shamir: reconstructed secret failed checksum verification. "
                "One or more shares may be corrupted or belong to a different split. "
                "Zeroized the result to prevent use of a wrong secret."
            )

    return result
