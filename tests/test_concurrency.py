"""
PyHSM Concurrency Stress Tests.

Proves thread safety of the sharded-lock architecture under realistic
concurrent load. These tests exercise:

  1. Parallel encrypt/decrypt on the SAME key (contention on per-key lock)
  2. Parallel encrypt/decrypt on DIFFERENT keys (no contention, max throughput)
  3. Parallel key generation (contention on global lock)
  4. Mixed workload: generate + encrypt + rotate + destroy concurrently
  5. Data integrity: every ciphertext decrypts back to its original plaintext
     even under heavy concurrent mutation

All tests use real cryptographic operations (no mocking) to expose
race conditions in key material handling, operation counting, and
keystore persistence.
"""

from __future__ import annotations

import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pytest

from hsm import PyHSM


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_TEST_PW = "stress-test-password-123"

# Number of concurrent threads — high enough to expose races,
# low enough to finish in CI within seconds.
_NUM_THREADS = 16
_OPS_PER_THREAD = 20


@pytest.fixture()
def hsm_high_rate(tmp_path: Path):
    """HSM instance with high rate limit for stress testing."""
    store_path = str(tmp_path / "stress.enc")
    h = PyHSM(
        store_path,
        master_password=_TEST_PW,
        session_timeout_s=0,
        rate_limit_max_ops=10000,
        rate_limit_window_s=60,
    )
    yield h
    try:
        h.close_session()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test 1: Parallel encrypt/decrypt on the SAME key
# ---------------------------------------------------------------------------

class TestSameKeyConcurrency:
    """Hammer a single AES key with concurrent encrypt+decrypt operations."""

    def test_concurrent_encrypt_same_key(self, hsm_high_rate):
        """Multiple threads encrypting with the same key must not corrupt state."""
        hsm = hsm_high_rate
        hsm.generate_key("shared-key")

        results = []
        errors = []

        def encrypt_task(thread_id: int):
            try:
                for i in range(_OPS_PER_THREAD):
                    plaintext = f"thread-{thread_id}-msg-{i}"
                    ct = hsm.encrypt("shared-key", plaintext)
                    results.append((plaintext, ct))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=encrypt_task, args=(tid,))
            for tid in range(_NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent encrypt: {errors}"
        assert len(results) == _NUM_THREADS * _OPS_PER_THREAD

        # Verify ALL ciphertexts decrypt correctly
        for plaintext, ct in results:
            decrypted = hsm.decrypt("shared-key", ct)
            assert decrypted == plaintext.encode("utf-8"), (
                f"Data corruption: expected {plaintext!r}, got {decrypted!r}"
            )

    def test_concurrent_encrypt_decrypt_interleaved(self, hsm_high_rate):
        """Interleaved encrypt and decrypt on the same key must be consistent."""
        hsm = hsm_high_rate
        hsm.generate_key("interleave-key")

        # Pre-generate some ciphertexts to decrypt concurrently
        pre_cts = []
        for i in range(50):
            ct = hsm.encrypt("interleave-key", f"pre-{i}")
            pre_cts.append((f"pre-{i}", ct))

        errors = []

        def mixed_task(thread_id: int):
            try:
                for i in range(_OPS_PER_THREAD):
                    # Alternate between encrypt and decrypt
                    if i % 2 == 0:
                        hsm.encrypt("interleave-key", f"t{thread_id}-{i}")
                    else:
                        # Decrypt a random pre-generated ciphertext
                        idx = (thread_id * _OPS_PER_THREAD + i) % len(pre_cts)
                        expected, ct = pre_cts[idx]
                        result = hsm.decrypt("interleave-key", ct)
                        assert result == expected.encode("utf-8")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=mixed_task, args=(tid,))
            for tid in range(_NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during interleaved ops: {errors}"


# ---------------------------------------------------------------------------
# Test 2: Parallel encrypt/decrypt on DIFFERENT keys (no lock contention)
# ---------------------------------------------------------------------------

class TestMultiKeyConcurrency:
    """Each thread operates on its own key — max throughput, no contention."""

    def test_parallel_independent_keys(self, hsm_high_rate):
        """Independent keys operated in parallel must not interfere."""
        hsm = hsm_high_rate

        # Pre-generate one key per thread
        for tid in range(_NUM_THREADS):
            hsm.generate_key(f"key-{tid}")

        all_results: list[tuple[str, str, str]] = []  # (key_id, plaintext, ct)
        errors = []
        lock = threading.Lock()

        def independent_task(thread_id: int):
            try:
                key_id = f"key-{thread_id}"
                for i in range(_OPS_PER_THREAD):
                    plaintext = f"independent-{thread_id}-{i}"
                    ct = hsm.encrypt(key_id, plaintext)
                    with lock:
                        all_results.append((key_id, plaintext, ct))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=independent_task, args=(tid,))
            for tid in range(_NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during parallel independent ops: {errors}"
        assert len(all_results) == _NUM_THREADS * _OPS_PER_THREAD

        # Verify every single ciphertext
        for key_id, plaintext, ct in all_results:
            decrypted = hsm.decrypt(key_id, ct)
            assert decrypted == plaintext.encode("utf-8"), (
                f"Cross-key corruption: {key_id} expected {plaintext!r}"
            )


# ---------------------------------------------------------------------------
# Test 3: Parallel key generation (global lock contention)
# ---------------------------------------------------------------------------

class TestParallelKeyGeneration:
    """Concurrent key generation must not produce duplicates or corrupt state."""

    def test_concurrent_generate(self, hsm_high_rate):
        hsm = hsm_high_rate
        errors = []

        def generate_task(thread_id: int):
            try:
                for i in range(5):
                    key_id = f"gen-{thread_id}-{i}"
                    hsm.generate_key(key_id)
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=generate_task, args=(tid,))
            for tid in range(_NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent generation: {errors}"

        # Verify all keys exist and are functional
        keys = hsm.list_keys()
        generated_ids = {k["key_id"] for k in keys if k["key_id"].startswith("gen-")}
        expected_count = _NUM_THREADS * 5
        assert len(generated_ids) == expected_count, (
            f"Expected {expected_count} keys, got {len(generated_ids)}"
        )

        # Spot-check: encrypt/decrypt with a few generated keys
        for tid in range(min(4, _NUM_THREADS)):
            key_id = f"gen-{tid}-0"
            ct = hsm.encrypt(key_id, "verify")
            assert hsm.decrypt(key_id, ct) == b"verify"


# ---------------------------------------------------------------------------
# Test 4: Mixed workload — generate + encrypt + rotate + destroy
# ---------------------------------------------------------------------------

class TestMixedWorkload:
    """Simulates a realistic production workload with mixed operations."""

    def test_mixed_concurrent_operations(self, hsm_high_rate):
        """Generate, encrypt, rotate, and destroy keys concurrently."""
        hsm = hsm_high_rate

        # Set up some keys that will be rotated/destroyed
        for i in range(8):
            hsm.generate_key(f"rotate-target-{i}")
            hsm.generate_key(f"destroy-target-{i}")

        # Pre-encrypt for decrypt verification during mixed workload
        pre_cts = {}
        for i in range(8):
            ct = hsm.encrypt(f"rotate-target-{i}", f"before-rotate-{i}")
            pre_cts[f"rotate-target-{i}"] = (f"before-rotate-{i}", ct)

        errors = []
        barrier = threading.Barrier(_NUM_THREADS)

        def mixed_worker(thread_id: int):
            try:
                # Synchronize all threads to start simultaneously
                barrier.wait(timeout=10)

                role = thread_id % 4

                if role == 0:
                    # Generator: create new keys
                    for i in range(3):
                        hsm.generate_key(f"mixed-new-{thread_id}-{i}")
                        ct = hsm.encrypt(f"mixed-new-{thread_id}-{i}", "new-key-data")
                        assert hsm.decrypt(f"mixed-new-{thread_id}-{i}", ct) == b"new-key-data"

                elif role == 1:
                    # Encryptor: hammer existing keys
                    key_id = f"rotate-target-{thread_id % 8}"
                    for i in range(10):
                        try:
                            ct = hsm.encrypt(key_id, f"enc-{thread_id}-{i}")
                            # Decrypt immediately to verify
                            result = hsm.decrypt(key_id, ct)
                            assert result == f"enc-{thread_id}-{i}".encode()
                        except (KeyError, ValueError):
                            # Key may have been destroyed by another thread — acceptable
                            pass

                elif role == 2:
                    # Rotator: rotate keys
                    key_id = f"rotate-target-{thread_id % 8}"
                    try:
                        new_ver = hsm.rotate_key(key_id)
                        # Encrypt with new version
                        ct = hsm.encrypt(key_id, "post-rotate")
                        assert hsm.decrypt(key_id, ct) == b"post-rotate"
                    except (KeyError, ValueError):
                        pass  # Key may be destroyed

                elif role == 3:
                    # Destroyer: destroy keys (only destroy-target-*)
                    key_id = f"destroy-target-{thread_id % 8}"
                    try:
                        hsm.destroy_key(key_id)
                    except KeyError:
                        pass  # Already destroyed by another thread

            except Exception as exc:
                errors.append((thread_id, exc))

        threads = [
            threading.Thread(target=mixed_worker, args=(tid,))
            for tid in range(_NUM_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during mixed workload: {errors}"

        # Verify pre-rotation ciphertexts still decrypt (key versioning works)
        for key_id, (plaintext, ct) in pre_cts.items():
            if hsm.has_key(key_id):
                result = hsm.decrypt(key_id, ct)
                assert result == plaintext.encode("utf-8"), (
                    f"Version corruption: {key_id} lost old version data"
                )


# ---------------------------------------------------------------------------
# Test 5: Data integrity under maximum contention
# ---------------------------------------------------------------------------

class TestDataIntegrity:
    """Ensures no data corruption even under extreme thread contention."""

    def test_no_cross_contamination(self, hsm_high_rate):
        """Ciphertexts from one key must NEVER decrypt under another key."""
        hsm = hsm_high_rate

        # Create two keys
        hsm.generate_key("integrity-a")
        hsm.generate_key("integrity-b")

        cts_a = []
        cts_b = []
        errors = []
        lock = threading.Lock()

        def encrypt_a():
            try:
                for i in range(50):
                    ct = hsm.encrypt("integrity-a", f"A-{i}")
                    with lock:
                        cts_a.append((f"A-{i}", ct))
            except Exception as exc:
                errors.append(exc)

        def encrypt_b():
            try:
                for i in range(50):
                    ct = hsm.encrypt("integrity-b", f"B-{i}")
                    with lock:
                        cts_b.append((f"B-{i}", ct))
            except Exception as exc:
                errors.append(exc)

        # Run both in parallel
        threads = [
            threading.Thread(target=encrypt_a),
            threading.Thread(target=encrypt_b),
            threading.Thread(target=encrypt_a),
            threading.Thread(target=encrypt_b),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

        # Verify: all A ciphertexts decrypt under key A
        for plaintext, ct in cts_a:
            assert hsm.decrypt("integrity-a", ct) == plaintext.encode()

        # Verify: all B ciphertexts decrypt under key B
        for plaintext, ct in cts_b:
            assert hsm.decrypt("integrity-b", ct) == plaintext.encode()

        # Verify: A ciphertexts do NOT decrypt under key B (AAD binding)
        for _, ct in cts_a[:5]:
            with pytest.raises(Exception):
                hsm.decrypt("integrity-b", ct)

    def test_operation_count_consistency(self, hsm_high_rate):
        """Operation count must be consistent after concurrent operations."""
        hsm = hsm_high_rate
        hsm.generate_key("count-key")

        num_ops = 50
        errors = []

        def encrypt_counted():
            try:
                for _ in range(num_ops):
                    hsm.encrypt("count-key", "x")
            except Exception as exc:
                errors.append(exc)

        # 4 threads × 50 ops = 200 total expected operations
        threads = [threading.Thread(target=encrypt_counted) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

        # Verify operation count in the stored entry
        entry = hsm._store.load_key("count-key")
        expected = 4 * num_ops
        assert entry["operation_count"] == expected, (
            f"Operation count mismatch: expected {expected}, "
            f"got {entry['operation_count']} (lost updates = race condition)"
        )


# ---------------------------------------------------------------------------
# Test 6: Sign/verify under concurrent load
# ---------------------------------------------------------------------------

class TestConcurrentSigning:
    """Concurrent signing operations must produce valid signatures."""

    def test_parallel_sign_verify(self, hsm_high_rate):
        """Multiple threads signing with the same EC key."""
        hsm = hsm_high_rate
        hsm.generate_key("sign-key", "ec-p256")

        results = []
        errors = []
        lock = threading.Lock()

        def sign_task(thread_id: int):
            try:
                for i in range(10):
                    msg = f"sign-{thread_id}-{i}"
                    sig = hsm.sign("sign-key", msg)
                    with lock:
                        results.append((msg, sig))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=sign_task, args=(tid,))
            for tid in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent signing: {errors}"
        assert len(results) == 80

        # Verify all signatures
        for msg, sig in results:
            assert hsm.verify("sign-key", msg, sig) is True, (
                f"Invalid signature produced under concurrency for: {msg}"
            )
