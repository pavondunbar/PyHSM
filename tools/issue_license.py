#!/usr/bin/env python3
"""
VectorGuard Labs — PyHSM License Token Issuer
==============================================

Mint a signed JWT license token for a paying customer.

Usage
-----
    python tools/issue_license.py \\
        --licensee "acme@example.com" \\
        --tier startup \\
        --days 365 \\
        --keys 5 \\
        --seats 1 \\
        --private-key license_private.pem

Options
-------
    --licensee      Customer email or identifier (stored in "sub" claim)
    --tier          One of: startup, growth, scale
    --days          Token validity in days (default: 90)
    --keys          Max keys allowed (0 = unlimited; default per tier)
    --seats         Max concurrent PyHSM instances (0 = unlimited)
    --private-key   Path to license_private.pem (default: license_private.pem)
    --out           Write token to file instead of stdout

Tier defaults
-------------
    startup   max_keys=5,   seats=1
    growth    max_keys=0,   seats=5   (unlimited keys)
    scale     max_keys=0,   seats=0   (unlimited keys + seats)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

ISSUER = "vectorguardlabs.com"

TIER_DEFAULTS = {
    "startup": {"keys": 5,  "seats": 1},
    "growth":  {"keys": 0,  "seats": 5},
    "scale":   {"keys": 0,  "seats": 0},
}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_jwt(payload: dict, private_key) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    signature = private_key.sign(
        signing_input,
        asym_padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mint a PyHSM commercial license token."
    )
    parser.add_argument("--licensee", required=True, help="Customer email/identifier")
    parser.add_argument(
        "--tier", required=True, choices=["startup", "growth", "scale"],
        help="License tier"
    )
    parser.add_argument(
        "--days", type=int, default=90,
        help="Validity period in days (default: 90)"
    )
    parser.add_argument(
        "--keys", type=int, default=-1,
        help="Max keys (0=unlimited, default: tier default)"
    )
    parser.add_argument(
        "--seats", type=int, default=-1,
        help="Max concurrent PyHSM instances (0=unlimited, default: tier default)"
    )
    parser.add_argument(
        "--private-key", default="license_private.pem",
        metavar="PATH", help="Path to license_private.pem"
    )
    parser.add_argument(
        "--out", metavar="PATH", default=None,
        help="Write token to file (default: print to stdout)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.private_key):
        print(
            f"ERROR: private key not found: {args.private_key}\n"
            "Run tools/generate_license_keypair.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.private_key, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    tier_defaults = TIER_DEFAULTS[args.tier]
    max_keys  = args.keys  if args.keys  >= 0 else tier_defaults["keys"]
    max_seats = args.seats if args.seats >= 0 else tier_defaults["seats"]

    now = int(time.time())
    token_id = str(uuid.uuid4())

    payload = {
        "iss":   ISSUER,
        "sub":   args.licensee,
        "iat":   now,
        "exp":   now + args.days * 86400,
        "tier":  args.tier,
        "keys":  max_keys,
        "seats": max_seats,
        "jti":   token_id,
    }

    token = _build_jwt(payload, private_key)

    import datetime
    exp_str = datetime.datetime.fromtimestamp(
        payload["exp"], tz=datetime.timezone.utc
    ).isoformat()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        print(f"Token written to: {args.out}", file=sys.stderr)
    else:
        print(token)

    # Summary to stderr so it doesn't pollute the token on stdout
    print(f"\nLicense summary:", file=sys.stderr)
    print(f"  Licensee : {args.licensee}", file=sys.stderr)
    print(f"  Tier     : {args.tier}", file=sys.stderr)
    print(f"  Expires  : {exp_str}", file=sys.stderr)
    print(f"  Max keys : {max_keys or 'unlimited'}", file=sys.stderr)
    print(f"  Max seats: {max_seats or 'unlimited'}", file=sys.stderr)
    print(f"  Token ID : {token_id}", file=sys.stderr)


if __name__ == "__main__":
    main()
