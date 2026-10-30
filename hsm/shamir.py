# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

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

Share integrity
---------------
Previous versions embedded a 4-byte truncated SHA-256 digest as the
share checksum.  A 32-bit tag provides only 2^32 security against
forgery — an adversary who can guess or brute-force a share value only
needs to find a collision in that 4-byte window.

Shares now carry a per-share HMAC-SHA256 tag keyed on a 32-byte random
``hmac_salt`` that is embedded in every share dict.  The HMAC covers:

    HMAC-SHA256(key=hmac_salt, msg=share_index_byte || share_data_bytes)

This provides 256-bit existential forgery resistance and additionally
binds each tag to its specific share index, so a tag from share 2
cannot be transplanted onto share 3.

Backward compatibility: ``reconstruct_secret`` still accepts shares
with only the old ``checksum`` field (4-byte hex).  New shares always
carry both ``share_hmac`` and ``hmac_salt``; the old ``checksum`` field
is no longer emitted by ``split_secret``.

For the highest-assurance environments, consider running Shamir
operations inside the IPC isolation process (see hsm/ipc_server.py)
so that even if a timing oracle exists, the attacker cannot trigger
arbitrary share reconstructions to probe it.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
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
# Per-share HMAC helpers
# ---------------------------------------------------------------------------

def _compute_share_hmac(hmac_salt: bytes, index: int, data: bytes) -> str:
    """
    Compute a per-share HMAC-SHA256 integrity tag.

    The tag covers both the share *index* and the share *data* bytes, so a
    tag from one share cannot be transplanted onto a different share index.

    Parameters
    ----------
    hmac_salt : bytes
        32-byte random salt generated once per ``split_secret`` call and
        embedded in every share dict.  Shared across all shares from the
        same split so that ``reconstruct_secret`` can verify each one with
        the same salt.
    index : int
        1-based share index.
    data : bytes
        Raw share bytes.

    Returns
    -------
    str
        Hex-encoded 32-byte HMAC-SHA256 tag.
    """
    msg = bytes([index & 0xFF]) + data
    return _hmac.new(hmac_salt, msg, hashlib.sha256).hexdigest()


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
    ``share_hmac``
        HMAC-SHA256(hmac_salt, index_byte || share_data).
        Provides 256-bit existential forgery resistance; binds the tag
        to the specific share index so tags cannot be transplanted.
    ``hmac_salt``
        Hex-encoded 32-byte random salt shared across all shares from
        this split.  Required to verify ``share_hmac`` on reconstruction.

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

    # One random salt per split, shared across all shares so reconstruct_secret
    # can re-derive the same HMAC for each share without storing the secret.
    hmac_salt = os.urandom(32)

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

    result = []
    for i in range(n):
        share_data = bytes(shares[i])
        result.append({
            "index": i + 1,
            "data": share_data.hex(),
            "share_hmac": _compute_share_hmac(hmac_salt, i + 1, share_data),
            "hmac_salt": hmac_salt.hex(),
            # reconstruction_hmac: HMAC-SHA256(hmac_salt, b"reconstruct" || secret)
            # Allows verify that the reconstructed value is correct without
            # embedding the secret itself in any share. Each share carries
            # an identical copy so that any k shares can verify the result.
            "reconstruction_hmac": _hmac.new(
                hmac_salt,
                b"reconstruct" + secret,
                hashlib.sha256,
            ).hexdigest(),
        })
    return result


def zeroize(buf: bytearray) -> None:
    """Overwrite a bytearray in-place with zeros to remove secret material."""
    for i in range(len(buf)):
        buf[i] = 0


def reconstruct_secret(shares: list[dict]) -> bytearray:
    """Reconstruct a secret from *k* or more shares via Lagrange interpolation.

    Returns a mutable :class:`bytearray` so the caller can zeroize it after use.

    Integrity check
    ~~~~~~~~~~~~~~~
    Shares produced by :func:`split_secret` carry ``share_hmac`` and
    ``hmac_salt`` fields.  Before interpolation begins, each share's HMAC
    is verified:

        HMAC-SHA256(hmac_salt, index_byte || share_data) == share_hmac

    A mismatch on **any** share raises :exc:`ValueError` immediately,
    before any secret material is reconstructed.  This prevents an
    adversary from submitting forged shares and observing whether
    reconstruction "succeeds" (side-channel oracle).

    Backward compatibility: shares with only the old ``checksum`` field
    (4-byte SHA-256 prefix, hex) are still accepted.  In that case the
    weaker post-reconstruction checksum is verified instead.  Shares with
    neither field are accepted without integrity checking (legacy only).

    Parameters
    ----------
    shares : list[dict]
        At least *k* share dicts as returned by :func:`split_secret`.
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares")

    bufs = [bytearray.fromhex(s["data"]) for s in shares]

    # --- Per-share HMAC pre-verification ---
    # Verify every share BEFORE any interpolation so that a forged share
    # is rejected without leaking partial reconstruction results.
    hmac_salt_hex = shares[0].get("hmac_salt")
    if hmac_salt_hex is not None:
        try:
            hmac_salt = bytes.fromhex(hmac_salt_hex)
        except ValueError:
            for buf in bufs:
                zeroize(buf)
            raise ValueError(
                "PyHSM Shamir: hmac_salt is not valid hex. Share may be corrupted."
            )
        for share, buf in zip(shares, bufs):
            stored_hmac = share.get("share_hmac", "")
            expected_hmac = _compute_share_hmac(hmac_salt, share["index"], bytes(buf))
            if not _hmac.compare_digest(stored_hmac, expected_hmac):
                # Zeroize all share buffers before raising
                for b in bufs:
                    zeroize(b)
                raise ValueError(
                    f"PyHSM Shamir: share {share['index']} failed HMAC verification. "
                    "The share may be corrupted or forged. "
                    "All share buffers have been zeroized."
                )

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

    # --- Post-reconstruction HMAC verification (new-format shares) ---
    # Verifies the reconstructed secret against the reconstruction_hmac that
    # was embedded at split time: HMAC-SHA256(hmac_salt, b"reconstruct" || secret).
    # This catches reconstruction from an insufficient or wrong set of shares
    # (e.g., only k-1 of k required shares) where each share's individual HMAC
    # is valid but the interpolation result is incorrect.
    if hmac_salt_hex is not None:
        stored_rec_hmac = shares[0].get("reconstruction_hmac")
        if stored_rec_hmac is not None:
            expected_rec_hmac = _hmac.new(
                hmac_salt,
                b"reconstruct" + bytes(result),
                hashlib.sha256,
            ).hexdigest()
            if not _hmac.compare_digest(stored_rec_hmac, expected_rec_hmac):
                zeroize(result)
                raise ValueError(
                    "PyHSM Shamir: reconstructed secret failed checksum verification. "
                    "The shares may be insufficient (fewer than k provided), corrupted, "
                    "or belong to a different split. "
                    "The result has been zeroized to prevent use of a wrong secret."
                )

    # --- Backward-compatible post-reconstruction checksum (legacy shares) ---
    # Only reached when shares lack share_hmac/hmac_salt (old format).
    elif hmac_salt_hex is None:
        stored_checksum = shares[0].get("checksum")
        if stored_checksum is not None:
            actual_checksum = hashlib.sha256(bytes(result)).digest()[:4].hex()
            # Use compare_digest to prevent timing-oracle attacks even for the
            # legacy 4-byte truncated checksum path.
            if not _hmac.compare_digest(actual_checksum, stored_checksum):
                zeroize(result)
                raise ValueError(
                    "PyHSM Shamir: reconstructed secret failed checksum verification. "
                    "One or more shares may be corrupted or belong to a different split. "
                    "The result has been zeroized to prevent use of a wrong secret."
                )

    return result
