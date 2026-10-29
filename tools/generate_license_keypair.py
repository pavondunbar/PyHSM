#!/usr/bin/env python3
"""
VectorGuard Labs — PyHSM License Keypair Generator
===================================================

Run this ONCE to generate the RSA-2048 keypair used to sign license tokens.

Usage
-----
    python tools/generate_license_keypair.py

Output
------
    license_private.pem   — KEEP SECRET. Use with tools/issue_license.py.
                            Store in a password manager or offline vault.
                            NEVER commit this file to version control.

    license_public.pem    — Embed in hsm/license.py (_EMBEDDED_PUBLIC_KEY_PEM).
                            Safe to ship in the package.

After running
-------------
1. Copy the contents of license_public.pem into the _EMBEDDED_PUBLIC_KEY_PEM
   constant in hsm/license.py (replacing the PLACEHOLDER line).
2. Add license_private.pem to .gitignore immediately.
3. Store license_private.pem somewhere safe (e.g. 1Password, offline drive).
"""

from __future__ import annotations

import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY_FILE = "license_private.pem"
PUBLIC_KEY_FILE = "license_public.pem"


def main() -> None:
    # Safety guard — don't silently overwrite an existing private key
    if os.path.exists(PRIVATE_KEY_FILE):
        print(
            f"ERROR: {PRIVATE_KEY_FILE} already exists.\n"
            "Delete it manually if you truly want to regenerate the keypair.\n"
            "WARNING: regenerating invalidates ALL previously issued tokens.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Generating RSA-2048 license keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Write private key (no encryption — you must protect this file yourself)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)
    os.chmod(PRIVATE_KEY_FILE, 0o600)
    print(f"  Private key written to: {PRIVATE_KEY_FILE}  (chmod 600)")

    # Write public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)
    print(f"  Public key written to:  {PUBLIC_KEY_FILE}")

    print()
    print("=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print()
    print(f"1. Embed the public key in hsm/license.py:")
    print(f"   Replace _EMBEDDED_PUBLIC_KEY_PEM with the contents of {PUBLIC_KEY_FILE}:")
    print()
    print(public_pem.decode())
    print()
    print(f"2. Add {PRIVATE_KEY_FILE} to .gitignore (NEVER commit the private key).")
    print(f"3. Store {PRIVATE_KEY_FILE} securely (password manager, offline vault).")
    print(f"4. Use tools/issue_license.py to mint tokens for paying customers.")


if __name__ == "__main__":
    main()
