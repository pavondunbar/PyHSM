#!/usr/bin/env python3
"""CLI interface for the PyHSM."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from hsm import PyHSM
from hsm.shamir import split_secret, reconstruct_secret, zeroize


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_hsm(args) -> PyHSM:
    password = args.password or getpass.getpass("Master password: ")
    return PyHSM(
        storage_path=args.store,
        master_password=password,
        session_timeout_s=0,  # CLI is short-lived; disable background timeout thread
    )


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_generate(args) -> None:
    policy: dict = {}
    if args.no_encrypt:
        policy["allow_encrypt"] = False
    if args.no_decrypt:
        policy["allow_decrypt"] = False
    if args.max_operations:
        policy["max_operations"] = args.max_operations
    if args.expires_at:
        policy["expires_at"] = args.expires_at

    hsm = get_hsm(args)
    hsm.generate_key(args.key_id, args.type, policy=policy or None)
    print(f"Generated {args.type} key: {args.key_id}")
    hsm.close_session()


def cmd_list(args) -> None:
    hsm = get_hsm(args)
    keys = hsm.list_keys()
    if not keys:
        print("No keys stored.")
        hsm.close_session()
        return
    for k in keys:
        print(
            f"  {k['key_id']:30s}  {k['key_type']:10s}  "
            f"v{k['current_version']}  {k['created_at']}"
        )
    hsm.close_session()


def cmd_rotate(args) -> None:
    hsm = get_hsm(args)
    new_ver = hsm.rotate_key(args.key_id)
    print(f"Rotated key '{args.key_id}' to version {new_ver}")
    hsm.close_session()


def cmd_delete(args) -> None:
    hsm = get_hsm(args)
    hsm.destroy_key(args.key_id)
    print(f"Destroyed key: {args.key_id}")
    hsm.close_session()


def cmd_encrypt(args) -> None:
    hsm = get_hsm(args)
    data = args.data or sys.stdin.read()
    ct = hsm.encrypt(args.key_id, data)
    print(ct)
    hsm.close_session()


def cmd_decrypt(args) -> None:
    hsm = get_hsm(args)
    data = args.data or sys.stdin.read().strip()
    pt = hsm.decrypt(args.key_id, data)
    sys.stdout.buffer.write(pt)
    hsm.close_session()


def cmd_sign(args) -> None:
    hsm = get_hsm(args)
    data = args.data or sys.stdin.read()
    sig = hsm.sign(args.key_id, data)
    print(sig)
    hsm.close_session()


def cmd_verify(args) -> None:
    hsm = get_hsm(args)
    valid = hsm.verify(args.key_id, args.message, args.signature)
    print("VALID" if valid else "INVALID")
    hsm.close_session()
    sys.exit(0 if valid else 1)


def cmd_pubkey(args) -> None:
    hsm = get_hsm(args)
    print(hsm.get_public_key(args.key_id))
    hsm.close_session()


def cmd_split(args) -> None:
    secret_hex = args.secret or sys.stdin.read().strip()
    secret = bytes.fromhex(secret_hex)
    shares = split_secret(secret, args.threshold, args.shares)
    for s in shares:
        print(json.dumps(s))


def cmd_reconstruct(args) -> None:
    if args.share:
        shares = [json.loads(s) for s in args.share]
    else:
        shares = [json.loads(line) for line in sys.stdin if line.strip()]
    secret = reconstruct_secret(shares)
    try:
        print(secret.hex())
    finally:
        zeroize(secret)


def cmd_metrics(args) -> None:
    hsm = get_hsm(args)
    if args.prometheus:
        print(hsm.get_prometheus_metrics())
    else:
        import pprint
        pprint.pprint(hsm.get_metrics())
    hsm.close_session()


def cmd_audit(args) -> None:
    hsm = get_hsm(args)
    audit = hsm.get_audit_log()

    if args.verify:
        bad_seq = audit.verify()
        if bad_seq == -1:
            print("Audit log integrity: OK")
        else:
            print(f"Audit log CORRUPTED at sequence {bad_seq}", file=sys.stderr)
            sys.exit(1)
    else:
        entries = audit.export_jsonl(
            operation=args.operation,
            key_id=args.key_id,
            since=args.since,
            until=args.until,
        )
        for e in entries:
            print(json.dumps(e))
    hsm.close_session()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(prog="vectorguard-pyhsm", description="PyHSM CLI")
    parser.add_argument("--store", default="keystore.enc", help="Keystore file path")
    parser.add_argument("--password", "-p", help="Master password (or use prompt)")
    sub = parser.add_subparsers(dest="command", required=True)

    # Shared parent parser for global options — allows --store and -p
    # to appear before OR after the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--store", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    common.add_argument("--password", "-p", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    # generate
    gen = sub.add_parser("generate", parents=[common], help="Generate a new key")
    gen.add_argument("key_id")
    gen.add_argument("--type", default="aes-256",
                     choices=["aes-128", "aes-256", "rsa-2048", "rsa-4096", "ec-p256", "ec-p384", "ec-p521"])
    gen.add_argument("--no-encrypt", action="store_true", help="Deny encrypt operations")
    gen.add_argument("--no-decrypt", action="store_true", help="Deny decrypt operations")
    gen.add_argument("--max-operations", type=int, help="Max total operations on this key")
    gen.add_argument("--expires-at", help="ISO-8601 expiry timestamp")
    gen.set_defaults(func=cmd_generate)

    # list
    ls = sub.add_parser("list", parents=[common], help="List stored keys")
    ls.set_defaults(func=cmd_list)

    # rotate
    rot = sub.add_parser("rotate", parents=[common], help="Rotate an AES key to a new version")
    rot.add_argument("key_id")
    rot.set_defaults(func=cmd_rotate)

    # delete
    rm = sub.add_parser("delete", parents=[common], help="Destroy a key")
    rm.add_argument("key_id")
    rm.set_defaults(func=cmd_delete)

    # encrypt
    enc = sub.add_parser("encrypt", parents=[common], help="Encrypt data with an AES key")
    enc.add_argument("key_id")
    enc.add_argument("--data", "-d", help="Data to encrypt (or pipe via stdin)")
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = sub.add_parser("decrypt", parents=[common], help="Decrypt data with an AES key")
    dec.add_argument("key_id")
    dec.add_argument("--data", "-d", help="Hex ciphertext (or pipe via stdin)")
    dec.set_defaults(func=cmd_decrypt)

    # sign
    sgn = sub.add_parser("sign", parents=[common], help="Sign data with an asymmetric key")
    sgn.add_argument("key_id")
    sgn.add_argument("--data", "-d", help="Data to sign (or pipe via stdin)")
    sgn.set_defaults(func=cmd_sign)

    # verify
    ver = sub.add_parser("verify", parents=[common], help="Verify a signature")
    ver.add_argument("key_id")
    ver.add_argument("message")
    ver.add_argument("signature")
    ver.set_defaults(func=cmd_verify)

    # pubkey
    pub = sub.add_parser("pubkey", parents=[common], help="Export public key (PEM)")
    pub.add_argument("key_id")
    pub.set_defaults(func=cmd_pubkey)

    # split
    sp = sub.add_parser("split", parents=[common], help="Split a hex secret into Shamir shares")
    sp.add_argument("--threshold", "-k", type=int, required=True)
    sp.add_argument("--shares", "-n", type=int, required=True)
    sp.add_argument("--secret", "-s", help="Hex-encoded secret (or pipe via stdin)")
    sp.set_defaults(func=cmd_split)

    # reconstruct
    rc = sub.add_parser("reconstruct", parents=[common], help="Reconstruct a secret from Shamir shares")
    rc.add_argument("--share", action="append", help="JSON share (repeat or pipe via stdin)")
    rc.set_defaults(func=cmd_reconstruct)

    # metrics
    met = sub.add_parser("metrics", parents=[common], help="Show operational metrics")
    met.add_argument("--prometheus", action="store_true", help="Output in Prometheus format")
    met.set_defaults(func=cmd_metrics)

    # audit
    aud = sub.add_parser("audit", parents=[common], help="Inspect or verify the audit log")
    aud.add_argument("--verify", action="store_true", help="Verify HMAC chain integrity")
    aud.add_argument("--operation", help="Filter by operation type")
    aud.add_argument("--key-id", help="Filter by key ID")
    aud.add_argument("--since", help="ISO-8601 start timestamp")
    aud.add_argument("--until", help="ISO-8601 end timestamp")
    aud.set_defaults(func=cmd_audit)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except BrokenPipeError:
        # Silently handle broken pipe (e.g. piping to head)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
