"""
PyHSM Python Layer — pytest test suite.

Coverage:
  - Self-tests (KATs)
  - KeyStore: tamper detection, atomic writes, HMAC verification
  - PyHSM key validation, generation, rotation, destruction
  - Encrypt/decrypt: round-trip, version selection, tamper resistance
  - Sign/verify: RSA-PSS, ECDSA (uses stored public key, not private key)
  - Policies: allowEncrypt, allowDecrypt, maxOperations, expiresAt
  - Rate limiting
  - Audit log: HMAC chain integrity, filtering, verification
  - Session: close, no-default-password
  - Shamir: split/reconstruct, zeroize
  - Metrics: Prometheus output
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from hsm import PyHSM, TamperError
from hsm.audit import AuditLog
from hsm.rate_limiter import RateLimiter
from hsm.self_test import run_self_tests
from hsm.shamir import reconstruct_secret, split_secret, zeroize


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def store_path(tmp_path: Path) -> str:
    return str(tmp_path / "keystore.enc")


@pytest.fixture()
def hsm(store_path: str) -> PyHSM:
    h = PyHSM(store_path, master_password="test-password-123", session_timeout_s=0)
    yield h
    try:
        h.close_session()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

class TestSelfTests:
    def test_all_kats_pass(self):
        results = run_self_tests()
        assert len(results) >= 4
        for r in results:
            assert r["passed"], f"KAT failed: {r}"

    def test_kat_names(self):
        results = run_self_tests()
        names = {r["test"] for r in results}
        assert "AES-256-GCM" in names
        assert "PBKDF2-SHA256" in names
        assert "HMAC-SHA256" in names
        assert "CSPRNG" in names


# ---------------------------------------------------------------------------
# KeyStore tamper detection & atomic writes
# ---------------------------------------------------------------------------

class TestKeyStore:
    def test_tamper_detection_flipped_byte(self, store_path):
        hsm = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        hsm.generate_key("k1")
        hsm.close_session()

        data = Path(store_path).read_bytes()
        # Flip a byte in the ciphertext area (well past the header)
        ba = bytearray(data)
        ba[-10] ^= 0xFF
        Path(store_path).write_bytes(bytes(ba))

        with pytest.raises(TamperError, match="TAMPER"):
            PyHSM(store_path, master_password="pw", session_timeout_s=0)

    def test_tamper_detection_truncated_file(self, store_path):
        hsm = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        hsm.generate_key("k1")
        hsm.close_session()

        data = Path(store_path).read_bytes()
        Path(store_path).write_bytes(data[:20])  # truncate to junk

        with pytest.raises(TamperError):
            PyHSM(store_path, master_password="pw", session_timeout_s=0)

    def test_wrong_password_raises(self, store_path):
        hsm = PyHSM(store_path, master_password="correct", session_timeout_s=0)
        hsm.generate_key("k1")
        hsm.close_session()

        with pytest.raises(Exception):
            hsm2 = PyHSM(store_path, master_password="wrong", session_timeout_s=0)
            # Will either raise on load or on first operation
            hsm2.list_keys()


# ---------------------------------------------------------------------------
# PyHSM construction
# ---------------------------------------------------------------------------

class TestConstruction:
    def test_no_password_raises(self, store_path):
        with pytest.raises(ValueError, match="master_password is required"):
            PyHSM(store_path)

    def test_empty_password_raises(self, store_path):
        with pytest.raises(ValueError):
            PyHSM(store_path, master_password="")

    def test_explicit_password_works(self, store_path):
        h = PyHSM(store_path, master_password="s3cr3t", session_timeout_s=0)
        assert h is not None
        h.close_session()


# ---------------------------------------------------------------------------
# Key ID validation
# ---------------------------------------------------------------------------

class TestKeyIdValidation:
    def test_valid_ids(self, hsm):
        for kid in ("k", "my-key", "key.v1", "Key_123", "a" * 128):
            hsm.generate_key(kid)

    def test_invalid_ids(self, hsm):
        for kid in ("", "-bad", ".bad", "a" * 129, "key/path", "key space"):
            with pytest.raises(ValueError, match="[Ii]nvalid key ID"):
                hsm.generate_key(kid)


# ---------------------------------------------------------------------------
# Key generation, rotation, destruction
# ---------------------------------------------------------------------------

class TestKeyLifecycle:
    def test_generate_aes256(self, hsm):
        hsm.generate_key("aes-key")
        assert hsm.has_key("aes-key")

    def test_generate_aes128(self, hsm):
        hsm.generate_key("aes128", "aes-128")
        assert hsm.has_key("aes128")

    def test_generate_rsa2048(self, hsm):
        hsm.generate_key("rsa-key", "rsa-2048")
        pub = hsm.get_public_key("rsa-key")
        assert "BEGIN PUBLIC KEY" in pub

    def test_generate_ec_p256(self, hsm):
        hsm.generate_key("ec-key", "ec-p256")
        pub = hsm.get_public_key("ec-key")
        assert "BEGIN PUBLIC KEY" in pub

    def test_duplicate_key_raises(self, hsm):
        hsm.generate_key("dup")
        with pytest.raises(ValueError, match="already exists"):
            hsm.generate_key("dup")

    def test_unsupported_type_raises(self, hsm):
        with pytest.raises(ValueError, match="Unsupported"):
            hsm.generate_key("bad", "rsa-1024")

    def test_rotate_key_increments_version(self, hsm):
        hsm.generate_key("rot")
        new_ver = hsm.rotate_key("rot")
        assert new_ver == 2

    def test_rotate_missing_key_raises(self, hsm):
        with pytest.raises(KeyError):
            hsm.rotate_key("nonexistent")

    def test_destroy_key(self, hsm):
        hsm.generate_key("del")
        hsm.destroy_key("del")
        assert not hsm.has_key("del")

    def test_destroy_missing_key_raises(self, hsm):
        with pytest.raises(KeyError):
            hsm.destroy_key("ghost")

    def test_list_keys(self, hsm):
        hsm.generate_key("k1")
        hsm.generate_key("k2")
        listing = hsm.list_keys()
        ids = {k["key_id"] for k in listing}
        assert {"k1", "k2"} <= ids


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def test_round_trip_string(self, hsm):
        hsm.generate_key("enc")
        ct = hsm.encrypt("enc", "hello world")
        assert hsm.decrypt("enc", ct) == b"hello world"

    def test_round_trip_empty(self, hsm):
        hsm.generate_key("enc")
        ct = hsm.encrypt("enc", "")
        assert hsm.decrypt("enc", ct) == b""

    def test_round_trip_unicode(self, hsm):
        hsm.generate_key("enc")
        msg = "日本語テスト 🔐"
        ct = hsm.encrypt("enc", msg)
        assert hsm.decrypt("enc", ct).decode("utf-8") == msg

    def test_random_nonces_differ(self, hsm):
        hsm.generate_key("enc")
        ct1 = hsm.encrypt("enc", "same")
        ct2 = hsm.encrypt("enc", "same")
        assert ct1 != ct2

    def test_decrypt_after_rotation(self, hsm):
        hsm.generate_key("rot")
        ct1 = hsm.encrypt("rot", "before")
        hsm.rotate_key("rot")
        ct2 = hsm.encrypt("rot", "after")
        assert hsm.decrypt("rot", ct1) == b"before"
        assert hsm.decrypt("rot", ct2) == b"after"

    def test_tampered_ciphertext_raises(self, hsm):
        hsm.generate_key("enc")
        ct = hsm.encrypt("enc", "secret")
        ba = bytearray(bytes.fromhex(ct))
        ba[-1] ^= 0xFF
        with pytest.raises(Exception):
            hsm.decrypt("enc", ba.hex())

    def test_too_short_ciphertext_raises(self, hsm):
        hsm.generate_key("enc")
        with pytest.raises(ValueError, match="too short"):
            hsm.decrypt("enc", bytes(10).hex())

    def test_nonexistent_key_raises(self, hsm):
        with pytest.raises(KeyError):
            hsm.encrypt("ghost", "x")

    def test_aes_key_for_sign_raises(self, hsm):
        hsm.generate_key("aes-only")
        with pytest.raises(ValueError, match="RSA or EC"):
            hsm.sign("aes-only", "data")

    def test_asymmetric_key_for_encrypt_raises(self, hsm):
        hsm.generate_key("rsa", "rsa-2048")
        with pytest.raises(ValueError, match="AES key"):
            hsm.encrypt("rsa", "data")


# ---------------------------------------------------------------------------
# Sign / Verify (uses stored public key only)
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_rsa_sign_verify(self, hsm):
        hsm.generate_key("rsa", "rsa-2048")
        sig = hsm.sign("rsa", "test message")
        assert hsm.verify("rsa", "test message", sig) is True

    def test_ec_sign_verify(self, hsm):
        hsm.generate_key("ec", "ec-p256")
        sig = hsm.sign("ec", "hello")
        assert hsm.verify("ec", "hello", sig) is True

    def test_wrong_message_fails(self, hsm):
        hsm.generate_key("ec", "ec-p256")
        sig = hsm.sign("ec", "correct")
        assert hsm.verify("ec", "wrong", sig) is False

    def test_tampered_signature_fails(self, hsm):
        hsm.generate_key("ec", "ec-p256")
        sig = hsm.sign("ec", "msg")
        bad_sig = sig[:-4] + "0000"
        assert hsm.verify("ec", "msg", bad_sig) is False

    def test_aes_verify_raises(self, hsm):
        hsm.generate_key("aes")
        with pytest.raises(ValueError):
            hsm.verify("aes", "x", "00" * 64)


# ---------------------------------------------------------------------------
# Persistence across sessions
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_persists_keys(self, store_path):
        h1 = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        h1.generate_key("pk")
        ct = h1.encrypt("pk", "persistent")
        h1.close_session()

        h2 = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        assert h2.has_key("pk")
        assert h2.decrypt("pk", ct) == b"persistent"
        h2.close_session()

    def test_persists_rotation(self, store_path):
        h1 = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        h1.generate_key("rk")
        ct1 = h1.encrypt("rk", "v1 data")
        h1.rotate_key("rk")
        ct2 = h1.encrypt("rk", "v2 data")
        h1.close_session()

        h2 = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        assert h2.decrypt("rk", ct1) == b"v1 data"
        assert h2.decrypt("rk", ct2) == b"v2 data"
        h2.close_session()


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class TestPolicies:
    def test_allow_encrypt_false(self, hsm):
        hsm.generate_key("noenc", policy={"allow_encrypt": False, "allow_decrypt": True})
        with pytest.raises(ValueError, match="policy denies encrypt"):
            hsm.encrypt("noenc", "x")

    def test_allow_decrypt_false(self, hsm):
        hsm.generate_key("nodec", policy={"allow_encrypt": True, "allow_decrypt": False})
        ct = hsm.encrypt("nodec", "x")
        with pytest.raises(ValueError, match="policy denies decrypt"):
            hsm.decrypt("nodec", ct)

    def test_max_operations(self, hsm):
        hsm.generate_key("limited", policy={"allow_encrypt": True, "allow_decrypt": True, "max_operations": 2})
        hsm.encrypt("limited", "op1")
        hsm.encrypt("limited", "op2")
        with pytest.raises(ValueError, match="exceeded max operations"):
            hsm.encrypt("limited", "op3")

    def test_expires_at(self, hsm):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        hsm.generate_key("expired", policy={"allow_encrypt": True, "allow_decrypt": True, "expires_at": past})
        with pytest.raises(ValueError, match="has expired"):
            hsm.encrypt("expired", "x")

    def test_enforce_expiry_archives(self, hsm):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        hsm.generate_key("exp2", policy={"allow_encrypt": True, "allow_decrypt": True, "expires_at": past})
        hsm.enforce_expiry()
        # After archival, encrypt should fail because current version is archived
        with pytest.raises(Exception):
            hsm.encrypt("exp2", "x")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_rate_limiter_allows_within_window(self):
        rl = RateLimiter(max_ops_per_window=3, window_seconds=60)
        assert rl.allow("k") is True
        assert rl.allow("k") is True
        assert rl.allow("k") is True

    def test_rate_limiter_blocks_over_limit(self):
        rl = RateLimiter(max_ops_per_window=2, window_seconds=60)
        assert rl.allow("k") is True
        assert rl.allow("k") is True
        assert rl.allow("k") is False

    def test_rate_limiter_independent_per_key(self):
        rl = RateLimiter(max_ops_per_window=1, window_seconds=60)
        assert rl.allow("k1") is True
        assert rl.allow("k2") is True
        assert rl.allow("k1") is False

    def test_rate_limiter_usage(self):
        rl = RateLimiter(max_ops_per_window=10, window_seconds=60)
        rl.allow("k")
        rl.allow("k")
        u = rl.usage("k")
        assert u["current"] == 2
        assert u["max"] == 10

    def test_rate_limiter_reset(self):
        rl = RateLimiter(max_ops_per_window=1, window_seconds=60)
        rl.allow("k")
        assert rl.allow("k") is False
        rl.reset("k")
        assert rl.allow("k") is True

    def test_hsm_rate_limited_key(self, store_path):
        h = PyHSM(store_path, master_password="pw", session_timeout_s=0,
                  rate_limit_max_ops=2, rate_limit_window_s=60)
        h.generate_key("rl")
        h.encrypt("rl", "1")
        h.encrypt("rl", "2")
        with pytest.raises(ValueError, match="rate-limited"):
            h.encrypt("rl", "3")
        h.close_session()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_records_are_written(self, tmp_path):
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        log.record("generateKey", key_id="k1", success=True)
        log.record("encrypt", key_id="k1", success=True)
        entries = log.export_jsonl()
        assert len(entries) >= 2

    def test_hmac_chain_is_valid(self, tmp_path):
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        for i in range(5):
            log.record("encrypt", key_id=f"k{i}", success=True)
        assert log.verify() == -1

    def test_tampered_log_detected(self, tmp_path):
        path = str(tmp_path / "audit.jsonl")
        log = AuditLog(path)
        log.record("generateKey", key_id="k1", success=True)
        log.record("encrypt", key_id="k1", success=True)

        # Tamper with the first line
        lines = Path(path).read_text().strip().split("\n")
        entry = json.loads(lines[0])
        entry["success"] = False  # change success flag
        lines[0] = json.dumps(entry)
        Path(path).write_text("\n".join(lines) + "\n")

        bad_seq = log.verify()
        assert bad_seq >= 0

    def test_filter_by_operation(self, tmp_path):
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        log.record("encrypt", key_id="k1", success=True)
        log.record("decrypt", key_id="k1", success=True)
        log.record("encrypt", key_id="k2", success=True)
        entries = log.export_jsonl(operation="encrypt")
        assert all(e["operation"] == "encrypt" for e in entries)
        assert len(entries) == 2

    def test_filter_by_key_id(self, tmp_path):
        log = AuditLog(str(tmp_path / "audit.jsonl"))
        log.record("encrypt", key_id="k1", success=True)
        log.record("encrypt", key_id="k2", success=True)
        entries = log.export_jsonl(key_id="k1")
        assert all(e.get("keyId") == "k1" for e in entries)


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

class TestSession:
    def test_closed_session_raises(self, store_path):
        h = PyHSM(store_path, master_password="pw", session_timeout_s=0)
        h.close_session()
        with pytest.raises(RuntimeError, match="session is closed"):
            h.list_keys()

    def test_double_close_is_safe(self, hsm):
        hsm.close_session()
        hsm.close_session()  # should not raise


# ---------------------------------------------------------------------------
# Shamir Secret Sharing
# ---------------------------------------------------------------------------

class TestShamir:
    def test_split_reconstruct_2_of_3(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, 2, 3)
        assert len(shares) == 3
        recovered = reconstruct_secret(shares[:2])
        assert bytes(recovered) == secret

    def test_split_reconstruct_3_of_5(self):
        secret = secrets.token_bytes(32)
        shares = split_secret(secret, 3, 5)
        for combo in [(0, 1, 2), (0, 2, 4), (1, 3, 4)]:
            recovered = reconstruct_secret([shares[i] for i in combo])
            assert bytes(recovered) == secret

    def test_insufficient_shares_wrong(self):
        secret = secrets.token_bytes(16)
        shares = split_secret(secret, 3, 5)
        # Only 2 shares — will reconstruct wrong value
        recovered = reconstruct_secret(shares[:2])
        assert bytes(recovered) != secret

    def test_zeroize_clears_buffer(self):
        buf = bytearray(b"\xff" * 16)
        zeroize(buf)
        assert buf == bytearray(16)

    def test_invalid_params(self):
        with pytest.raises(ValueError):
            split_secret(b"x", 1, 3)  # k < 2
        with pytest.raises(ValueError):
            split_secret(b"x", 4, 3)  # k > n

    def test_empty_secret_raises(self):
        with pytest.raises(ValueError):
            split_secret(b"", 2, 3)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_metrics_recorded(self, hsm):
        hsm.generate_key("m")
        hsm.encrypt("m", "data")
        hsm.encrypt("m", "data2")
        m = hsm.get_metrics()
        assert m["encryptOps"] == 2
        assert m["totalOperations"] >= 2

    def test_prometheus_output(self, hsm):
        hsm.generate_key("p")
        hsm.encrypt("p", "x")
        prom = hsm.get_prometheus_metrics()
        assert "pyhsm_operations_total" in prom
        assert "pyhsm_keys" in prom
        assert "pyhsm_uptime_seconds" in prom

    def test_active_key_count(self, hsm):
        hsm.generate_key("k1")
        hsm.generate_key("k2")
        m = hsm.get_metrics()
        assert m["activeKeys"] >= 2
