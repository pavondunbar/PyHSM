#!/usr/bin/env python3
"""CLI interface for the SoftHSM."""

import argparse
import getpass
import sys
from hsm import SoftHSM


def get_hsm(args):
    password = args.password or getpass.getpass("Master password: ")
    return SoftHSM(storage_path=args.store, master_password=password)


def cmd_generate(args):
    hsm = get_hsm(args)
    hsm.generate_key(args.key_id, args.type)
    print(f"Generated {args.type} key: {args.key_id}")


def cmd_list(args):
    hsm = get_hsm(args)
    keys = hsm.list_keys()
    if not keys:
        print("No keys stored.")
        return
    for k in keys:
        print(f"  {k['key_id']:20s}  {k['key_type']:10s}  {k['created_at']}")


def cmd_delete(args):
    hsm = get_hsm(args)
    hsm.delete_key(args.key_id)
    print(f"Deleted key: {args.key_id}")


def cmd_encrypt(args):
    hsm = get_hsm(args)
    data = args.data or sys.stdin.read()
    ct = hsm.encrypt(args.key_id, data)
    print(ct)


def cmd_decrypt(args):
    hsm = get_hsm(args)
    data = args.data or sys.stdin.read().strip()
    pt = hsm.decrypt(args.key_id, data)
    sys.stdout.buffer.write(pt)


def cmd_sign(args):
    hsm = get_hsm(args)
    data = args.data or sys.stdin.read()
    sig = hsm.sign(args.key_id, data)
    print(sig)


def cmd_verify(args):
    hsm = get_hsm(args)
    valid = hsm.verify(args.key_id, args.message, args.signature)
    print("VALID" if valid else "INVALID")
    sys.exit(0 if valid else 1)


def cmd_pubkey(args):
    hsm = get_hsm(args)
    print(hsm.get_public_key(args.key_id))


def main():
    parser = argparse.ArgumentParser(prog="softhsm", description="SoftHSM")
    parser.add_argument("--store", default="keystore.enc", help="Key store file path")
    parser.add_argument("--password", "-p", help="Master password (or use prompt)")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a new key")
    gen.add_argument("key_id")
    gen.add_argument("--type", default="aes-256", choices=["aes-128", "aes-256", "rsa-2048", "rsa-4096", "ec-p256"])
    gen.set_defaults(func=cmd_generate)

    ls = sub.add_parser("list", help="List stored keys")
    ls.set_defaults(func=cmd_list)

    rm = sub.add_parser("delete", help="Delete a key")
    rm.add_argument("key_id")
    rm.set_defaults(func=cmd_delete)

    enc = sub.add_parser("encrypt", help="Encrypt data with an AES key")
    enc.add_argument("key_id")
    enc.add_argument("--data", "-d", help="Data to encrypt (or pipe via stdin)")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="Decrypt data with an AES key")
    dec.add_argument("key_id")
    dec.add_argument("--data", "-d", help="Hex ciphertext (or pipe via stdin)")
    dec.set_defaults(func=cmd_decrypt)

    sgn = sub.add_parser("sign", help="Sign data with an asymmetric key")
    sgn.add_argument("key_id")
    sgn.add_argument("--data", "-d", help="Data to sign (or pipe via stdin)")
    sgn.set_defaults(func=cmd_sign)

    ver = sub.add_parser("verify", help="Verify a signature")
    ver.add_argument("key_id")
    ver.add_argument("message")
    ver.add_argument("signature")
    ver.set_defaults(func=cmd_verify)

    pub = sub.add_parser("pubkey", help="Export public key (PEM)")
    pub.add_argument("key_id")
    pub.set_defaults(func=cmd_pubkey)

    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
