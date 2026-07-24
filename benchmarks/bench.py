#!/usr/bin/env python3
"""
PyHSM Performance Benchmarks

Measures throughput and latency for all key operations across supported key types.
Run from the repository root:

    python benchmarks/bench.py

Results are printed as a formatted table suitable for inclusion in documentation.
"""

from __future__ import annotations

import os
import sys
import time
import tempfile
import statistics

# Ensure the repo root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hsm import PyHSM


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ITERATIONS = 50           # Operations per benchmark
WARMUP = 2                # Warmup iterations (discarded)
PLAINTEXT = "The quick brown fox jumps over the lazy dog."  # 44 bytes
SIGN_MESSAGE = b"benchmark message for signing operations"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def bench(func, iterations: int = ITERATIONS, warmup: int = WARMUP) -> dict:
    """Run func() repeatedly and return timing statistics."""
    # Warmup
    for _ in range(warmup):
        func()

    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    total = sum(times)
    ops_per_sec = iterations / total
    p50 = statistics.median(times) * 1000  # ms
    p99 = sorted(times)[int(iterations * 0.99)] * 1000  # ms
    avg = statistics.mean(times) * 1000  # ms

    return {
        "ops_sec": ops_per_sec,
        "p50_ms": p50,
        "p99_ms": p99,
        "avg_ms": avg,
    }


def fmt_ops(n: float) -> str:
    """Format ops/sec with comma separator."""
    return f"{n:,.0f}"


def fmt_ms(n: float) -> str:
    """Format milliseconds to 3 decimal places."""
    return f"{n:.3f}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Create a temporary keystore
    keystore_path = tempfile.mktemp(suffix=".enc")
    audit_path = keystore_path + ".audit.jsonl"

    try:
        hsm = PyHSM(
            storage_path=keystore_path,
            master_password="benchmark-password-do-not-use",
            session_timeout_s=0,
            rate_limit_max_ops=999999,  # Don't let rate limiter interfere
            rate_limit_window_s=1,
        )

        # Generate keys for benchmarking
        hsm.generate_key("aes-256-key", "aes-256")
        hsm.generate_key("aes-128-key", "aes-128")
        hsm.generate_key("rsa-2048-key", "rsa-2048")
        hsm.generate_key("ec-p256-key", "ec-p256")
        hsm.generate_key("ec-p384-key", "ec-p384")
        hsm.generate_key("secp256k1-key", "ec-secp256k1")
        hsm.generate_key("ed25519-key", "ed25519")

        # Pre-encrypt some ciphertext for decrypt benchmarks
        ct_aes256 = hsm.encrypt("aes-256-key", PLAINTEXT)
        ct_aes128 = hsm.encrypt("aes-128-key", PLAINTEXT)

        # Pre-sign for verify benchmarks
        sig_rsa = hsm.sign("rsa-2048-key", SIGN_MESSAGE)
        sig_p256 = hsm.sign("ec-p256-key", SIGN_MESSAGE)
        sig_p384 = hsm.sign("ec-p384-key", SIGN_MESSAGE)
        sig_secp256k1 = hsm.sign("secp256k1-key", SIGN_MESSAGE)
        sig_ed25519 = hsm.sign("ed25519-key", SIGN_MESSAGE)

        print("=" * 78)
        print("PyHSM Performance Benchmarks")
        print(f"Iterations per operation: {ITERATIONS}")
        print(f"Plaintext size: {len(PLAINTEXT)} bytes")
        print(f"Python: {sys.version.split()[0]}")
        print(f"Platform: {sys.platform}")
        print("=" * 78)
        print()

        results = []

        # --- Encryption ---
        print("Running: AES-256 encrypt...")
        r = bench(lambda: hsm.encrypt("aes-256-key", PLAINTEXT))
        results.append(("AES-256 encrypt", r))

        print("Running: AES-256 decrypt...")
        r = bench(lambda: hsm.decrypt("aes-256-key", ct_aes256))
        results.append(("AES-256 decrypt", r))

        print("Running: AES-128 encrypt...")
        r = bench(lambda: hsm.encrypt("aes-128-key", PLAINTEXT))
        results.append(("AES-128 encrypt", r))

        print("Running: AES-128 decrypt...")
        r = bench(lambda: hsm.decrypt("aes-128-key", ct_aes128))
        results.append(("AES-128 decrypt", r))

        # --- Signing ---
        print("Running: RSA-2048 sign...")
        r = bench(lambda: hsm.sign("rsa-2048-key", SIGN_MESSAGE))
        results.append(("RSA-2048 sign", r))

        print("Running: RSA-2048 verify...")
        r = bench(lambda: hsm.verify("rsa-2048-key", SIGN_MESSAGE, sig_rsa))
        results.append(("RSA-2048 verify", r))

        print("Running: EC P-256 sign...")
        r = bench(lambda: hsm.sign("ec-p256-key", SIGN_MESSAGE))
        results.append(("EC P-256 sign", r))

        print("Running: EC P-256 verify...")
        r = bench(lambda: hsm.verify("ec-p256-key", SIGN_MESSAGE, sig_p256))
        results.append(("EC P-256 verify", r))

        print("Running: EC P-384 sign...")
        r = bench(lambda: hsm.sign("ec-p384-key", SIGN_MESSAGE))
        results.append(("EC P-384 sign", r))

        print("Running: EC P-384 verify...")
        r = bench(lambda: hsm.verify("ec-p384-key", SIGN_MESSAGE, sig_p384))
        results.append(("EC P-384 verify", r))

        print("Running: secp256k1 sign...")
        r = bench(lambda: hsm.sign("secp256k1-key", SIGN_MESSAGE))
        results.append(("secp256k1 sign", r))

        print("Running: secp256k1 verify...")
        r = bench(lambda: hsm.verify("secp256k1-key", SIGN_MESSAGE, sig_secp256k1))
        results.append(("secp256k1 verify", r))

        print("Running: Ed25519 sign...")
        r = bench(lambda: hsm.sign("ed25519-key", SIGN_MESSAGE))
        results.append(("Ed25519 sign", r))

        print("Running: Ed25519 verify...")
        r = bench(lambda: hsm.verify("ed25519-key", SIGN_MESSAGE, sig_ed25519))
        results.append(("Ed25519 verify", r))

        # --- Key Generation ---
        gen_counter = [0]

        def gen_aes():
            gen_counter[0] += 1
            hsm.generate_key(f"bench-aes-{gen_counter[0]}", "aes-256")

        def gen_secp256k1():
            gen_counter[0] += 1
            hsm.generate_key(f"bench-secp-{gen_counter[0]}", "ec-secp256k1")

        def gen_ed25519():
            gen_counter[0] += 1
            hsm.generate_key(f"bench-ed-{gen_counter[0]}", "ed25519")

        print("Running: Key generate (AES-256)...")
        r = bench(gen_aes, iterations=20, warmup=2)
        results.append(("Key generate (AES-256)", r))

        print("Running: Key generate (secp256k1)...")
        r = bench(gen_secp256k1, iterations=20, warmup=2)
        results.append(("Key generate (secp256k1)", r))

        print("Running: Key generate (Ed25519)...")
        r = bench(gen_ed25519, iterations=20, warmup=2)
        results.append(("Key generate (Ed25519)", r))

        # --- Key Rotation ---
        print("Running: Key rotate (AES-256)...")
        r = bench(lambda: hsm.rotate_key("aes-256-key"), iterations=20, warmup=2)
        results.append(("Key rotate (AES-256)", r))

        # --- Print Results ---
        print()
        print()
        header = f"{'Operation':<26} | {'Ops/sec':>10} | {'Avg (ms)':>10} | {'p50 (ms)':>10} | {'p99 (ms)':>10}"
        print(header)
        print("-" * len(header))
        for name, r in results:
            print(
                f"{name:<26} | {fmt_ops(r['ops_sec']):>10} | "
                f"{fmt_ms(r['avg_ms']):>10} | {fmt_ms(r['p50_ms']):>10} | "
                f"{fmt_ms(r['p99_ms']):>10}"
            )

        print()
        print("Note: Results include PyHSM overhead (key unwrapping, policy checks,")
        print("audit logging, keystore persistence). Raw crypto primitive speed is higher.")
        print()

        hsm.close_session()

    finally:
        # Cleanup
        for f in [keystore_path, audit_path]:
            if os.path.exists(f):
                os.unlink(f)


if __name__ == "__main__":
    main()
