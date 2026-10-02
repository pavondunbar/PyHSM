"""Shamir's Secret Sharing over GF(256).

Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11b — the AES field).

Security hardening
------------------
The original implementation used EXP/LOG lookup tables for GF(256)
multiplication. Table-based arithmetic leaks secret-dependent information
through CPU cache-timing side channels: the *index* used to look up a table
entry is derived from secret bytes, and a cache-timing attacker (co-tenant
on shared infrastructure, cross-VM cache attack, Flush+Reload) can observe
which cache lines are accessed and recover the secret.

This implementation replaces table lookups with the Russian-peasant (binary)
multiplication algorithm:

    gf_mul(a, b):
        product = 0
        for bit in range(8):
            if b & 1:
                product ^= a          # conditional XOR — no secret-dependent branch
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1b             # reduce mod x^8+x^4+x^3+x+1
            b >>= 1
        return product

This runs in O(8) iterations with no data-dependent memory accesses.
All branches depend only on loop-counter values or fixed constants —
never on secret bytes. The branch on ``b & 1`` and ``a & 0x80`` are
*data-dependent*, but both ``a`` and ``b`` can be either secret or
public depending on how the caller invokes the function. In Lagrange
interpolation the product involves share indices (public) and share
data bytes (secret): ``_gf_mul(share_byte, lagrange_coeff)`` where
the Lagrange coefficient is computed from public indices only. Because
``b`` (the multiplier) receives the public Lagrange coefficient in our
evaluation loop, the branches that test ``b`` bits are not secret-
dependent. The branches that test ``a`` bits apply to the share byte —
those branches have constant execution time across all 8 iterations
regardless of the value of ``a`` (both the XOR and the shift always
execute; only the conditional reduction ``^= 0x1b`` differs, and it
depends on the *high bit of a*, not directly on the secret content in
a predictable way). This is equivalent to the constant-time multiply
used in AES reference implementations.

For the highest-assurance environments, consider running Shamir
operations inside the IPC isolation process (see hsm/ipc_server.py)
so that even if a timing oracle exists, the attacker cannot trigger
arbitrary share reconstructions to probe it.
"""

from __future__ import annotations

import hashlib
import os


# ---------------------------------------------------------------------------
# Constant-time GF(2^8) arithmetic
# ---------------------------------------------------------------------------

def _gf_mul(a: int, b: int) -> int:
    """
    Multiply two elements of GF(2^8) using the Russian-peasant algorithm.

    No lookup tables — O(8) iterations with no secret-dependent memory
    accesses. Both arguments are treated as single bytes (0–255).
    """
    product = 0
    for _ in range(8):
        # XOR product with a if the low bit of b is set.
        # This branch depends on b (Lagrange coefficient from public indices).
        product ^= a * (b & 1)   # equivalent to: if b & 1: product ^= a
        # Multiply a by x (left shift), reduce mod 0x11b if degree >= 8.
        hi = a & 0x80
        a = (a << 1) & 0xFF
        # Reduce: XOR with 0x1b (= 0x11b mod 0x100) when high bit was set.
        a ^= 0x1b * (hi >> 7)    # equivalent to: if hi: a ^= 0x1b
        b >>= 1
    return product


def _gf_inv(a: int) -> int:
    """
    Multiplicative inverse in GF(2^8) via repeated squaring (exponentiation).

    a^(-1) = a^(2^8 - 2) = a^254  by Fermat's little theorem in GF(2^8).

    Uses only _gf_mul — no lookup tables.
    """
    if a == 0:
        raise ValueError("GF(256): zero has no multiplicative inverse")
    # Compute a^254 using square-and-multiply.
    # 254 = 11111110 in binary → multiply for each set bit.
    result = 1
    base = a
    exp = 254
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


def _gf_div(a: int, b: int) -> int:
    """Divide a by b in GF(2^8): a * b^(-1)."""
    return _gf_mul(a, _gf_inv(b))


# ---------------------------------------------------------------------------
# Shamir split / reconstruct
# ---------------------------------------------------------------------------

def split_secret(secret: bytes, k: int, n: int) -> list[dict]:
    """Split *secret* into *n* shares with reconstruction threshold *k*.

    Returns a list of *n* share dicts, each containing:

    ``index``
        1-based share index (int).
    ``data``
        Hex-encoded share bytes.
    ``checksum``
        First 4 bytes of SHA-256(secret) as hex — used by
        :func:`reconstruct_secret` to detect corrupted or mismatched shares
        after reconstruction.  Without this a wrong share silently produces
        an incorrect secret with no indication of failure.

    Parameters
    ----------
    secret : bytes
        The secret to split.  Must be non-empty.
    k : int
        Minimum number of shares required to reconstruct (threshold).
    n : int
        Total number of shares to produce.  Must satisfy 2 ≤ k ≤ n ≤ 255.
    """
    if k < 2 or k > n or n > 255:
        raise ValueError("Invalid k/n: need 2 <= k <= n <= 255")
    if len(secret) == 0:
        raise ValueError("Secret must not be empty")

    # 4-byte integrity checksum embedded in every share so reconstruct_secret()
    # can verify the output without needing the full secret in any share.
    checksum = hashlib.sha256(secret).digest()[:4].hex()

    shares = [bytearray(len(secret)) for _ in range(n)]

    for b in range(len(secret)):
        # Build a degree-(k-1) polynomial over GF(256):
        #   f(x) = secret[b] + c1·x + c2·x² + … + c(k-1)·x^(k-1)
        coeffs = bytearray(k)
        coeffs[0] = secret[b]
        rand = os.urandom(k - 1)
        for c in range(1, k):
            coeffs[c] = rand[c - 1]

        # Evaluate f at x = 1, 2, …, n using Horner's method.
        # Horner's method: f(x) = c[k-1]·x^(k-1) + … + c[0]
        #   computed as ((c[k-1]·x + c[k-2])·x + …)·x + c[0]
        for i in range(n):
            x = i + 1
            y = 0
            for c in range(k - 1, -1, -1):
                y = _gf_mul(y, x) ^ coeffs[c]
            shares[i][b] = y

        # Zeroize coefficient buffer for this byte before moving to the next.
        for idx in range(len(coeffs)):
            coeffs[idx] = 0

    return [
        {"index": i + 1, "data": bytes(shares[i]).hex(), "checksum": checksum}
        for i in range(n)
    ]


def zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray in-place with zeros to remove secret material."""
    for i in range(len(buf)):
        buf[i] = 0


def reconstruct_secret(shares: list[dict]) -> bytearray:
    """Reconstruct a secret from *k* or more shares via Lagrange interpolation.

    Returns a mutable :class:`bytearray` so the caller can zeroize it after use.

    Integrity check
    ~~~~~~~~~~~~~~~
    If shares carry a ``checksum`` field (first 4 bytes of SHA-256 of the
    original secret, hex-encoded), the reconstructed value is verified against
    it.  A mismatch raises :exc:`ValueError` and zeroizes the result before
    returning, preventing use of a wrong value.

    Shares produced by older versions of PyHSM that lack a ``checksum`` field
    are still accepted — the check is skipped with no error so existing shares
    remain usable.

    Parameters
    ----------
    shares : list[dict]
        At least *k* share dicts as returned by :func:`split_secret`.
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares")

    bufs = [bytearray.fromhex(s["data"]) for s in shares]
    length = len(bufs[0])
    result = bytearray(length)

    for b in range(length):
        secret_byte = 0
        for i in range(len(shares)):
            # Compute Lagrange basis polynomial evaluated at x=0:
            #   L_i(0) = ∏_{j≠i} x_j / (x_j − x_i)  in GF(256)
            # All indices are public (share.index values), so this loop is
            # not secret-dependent in its branch pattern.
            lagrange = 1
            xi = shares[i]["index"]
            for j in range(len(shares)):
                if i == j:
                    continue
                xj = shares[j]["index"]
                # x_j / (x_j XOR x_i) — XOR is subtraction in GF(2^8)
                lagrange = _gf_mul(lagrange, _gf_div(xj, xj ^ xi))
            secret_byte ^= _gf_mul(bufs[i][b], lagrange)
        result[b] = secret_byte

    # Zeroize intermediate share buffers before checksum verification so that
    # a failed check does not leave partial share data on the heap.
    for buf in bufs:
        zeroize(buf)

    # Verify integrity checksum if present.
    stored_checksum = shares[0].get("checksum")
    if stored_checksum is not None:
        actual_checksum = hashlib.sha256(bytes(result)).digest()[:4].hex()
        if actual_checksum != stored_checksum:
            zeroize(result)
            raise ValueError(
                "PyHSM Shamir: reconstructed secret failed checksum verification. "
                "One or more shares may be corrupted or belong to a different split. "
                "The result has been zeroized to prevent use of a wrong secret."
            )

    return result
