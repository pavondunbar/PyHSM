"""Shamir's Secret Sharing over GF(256) with AES irreducible polynomial."""

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
    """Split secret into n shares with threshold k. Returns list of {index, data} dicts."""
    if k < 2 or k > n or n > 255:
        raise ValueError("Invalid k/n: need 2 <= k <= n <= 255")
    if len(secret) == 0:
        raise ValueError("Secret must not be empty")

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

    return [{"index": i + 1, "data": bytes(shares[i]).hex()} for i in range(n)]


def zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros to remove secret material from memory."""
    for i in range(len(buf)):
        buf[i] = 0


def reconstruct_secret(shares: list[dict]) -> bytearray:
    """Reconstruct a secret from k or more shares via Lagrange interpolation.

    Returns a mutable bytearray so the caller can zeroize it after use.
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

    return result
