"""
CLI integration tests for vectorguard-pyhsm.

Tests the CLI via subprocess to ensure the user-facing entry point
works correctly end-to-end. Covers:
  - Key generation (various types)
  - Encrypt/decrypt round-trip
  - Key listing
  - Key rotation
  - Key destruction
  - Sign/verify round-trip
  - Error cases (missing key, bad password, invalid key ID)
  - Audit log
  - Metrics
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

CLI = [sys.executable, "-m", "cli"]
PASSWORD = "test-password-secure-123"


@pytest.fixture()
def store_path(tmp_path: Path) -> str:
    return str(tmp_path / "test-cli-keystore.enc")


def run_cli(args: list[str], store: str, env_extra: dict | None = None,
            input_data: str | None = None, expect_fail: bool = False) -> subprocess.CompletedProcess:
    """Run the CLI with the given arguments and return the result."""
    env = os.environ.copy()
    env["PYHSM_MASTER_PASSWORD"] = PASSWORD
    if env_extra:
        env.update(env_extra)

    cmd = CLI + ["--store", store] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        input=input_data,
        timeout=30,
    )
    if not expect_fail and result.returncode != 0:
        raise AssertionError(
            f"CLI failed (exit {result.returncode}):\n"
            f"  cmd: {' '.join(cmd)}\n"
            f"  stdout: {result.stdout}\n"
            f"  stderr: {result.stderr}"
        )
    return result


class TestKeyGeneration:
    """Test key generation via CLI."""

    def test_generate_aes256(self, store_path: str) -> None:
        result = run_cli(["generate", "my-aes-key", "--type", "aes-256"], store_path)
        assert "Generated aes-256 key: my-aes-key" in result.stdout

    def test_generate_aes128(self, store_path: str) -> None:
        result = run_cli(["generate", "my-aes128", "--type", "aes-128"], store_path)
        assert "Generated aes-128 key: my-aes128" in result.stdout

    def test_generate_ec_p256(self, store_path: str) -> None:
        result = run_cli(["generate", "my-ec-key", "--type", "ec-p256"], store_path)
        assert "Generated ec-p256 key: my-ec-key" in result.stdout

    def test_generate_ed25519(self, store_path: str) -> None:
        result = run_cli(["generate", "my-ed-key", "--type", "ed25519"], store_path)
        assert "Generated ed25519 key: my-ed-key" in result.stdout

    def test_generate_rsa(self, store_path: str) -> None:
        result = run_cli(["generate", "my-rsa-key", "--type", "rsa-2048"], store_path)
        assert "Generated rsa-2048 key: my-rsa-key" in result.stdout

    def test_generate_secp256k1(self, store_path: str) -> None:
        result = run_cli(["generate", "eth-key", "--type", "ec-secp256k1"], store_path)
        assert "Generated ec-secp256k1 key: eth-key" in result.stdout

    def test_generate_duplicate_fails(self, store_path: str) -> None:
        run_cli(["generate", "dup-key"], store_path)
        result = run_cli(["generate", "dup-key"], store_path, expect_fail=True)
        assert result.returncode != 0
        assert "already exists" in result.stderr

    def test_generate_with_policy(self, store_path: str) -> None:
        result = run_cli([
            "generate", "policy-key", "--type", "aes-256",
            "--max-operations", "10", "--no-decrypt",
        ], store_path)
        assert "Generated aes-256 key: policy-key" in result.stdout


class TestEncryptDecrypt:
    """Test encrypt/decrypt round-trip via CLI."""

    def test_round_trip(self, store_path: str) -> None:
        run_cli(["generate", "rt-key"], store_path)
        # Encrypt
        enc_result = run_cli(["encrypt", "rt-key", "-d", "hello world"], store_path)
        ciphertext = enc_result.stdout.strip()
        assert ciphertext  # non-empty hex string
        # Decrypt
        dec_result = run_cli(["decrypt", "rt-key", "-d", ciphertext], store_path)
        assert dec_result.stdout == "hello world"

    def test_encrypt_via_stdin(self, store_path: str) -> None:
        run_cli(["generate", "stdin-key"], store_path)
        enc_result = run_cli(["encrypt", "stdin-key"], store_path, input_data="stdin secret")
        ciphertext = enc_result.stdout.strip()
        dec_result = run_cli(["decrypt", "stdin-key", "-d", ciphertext], store_path)
        assert dec_result.stdout == "stdin secret"

    def test_decrypt_wrong_key_fails(self, store_path: str) -> None:
        run_cli(["generate", "key-a"], store_path)
        run_cli(["generate", "key-b"], store_path)
        enc_result = run_cli(["encrypt", "key-a", "-d", "secret"], store_path)
        ct = enc_result.stdout.strip()
        result = run_cli(["decrypt", "key-b", "-d", ct], store_path, expect_fail=True)
        assert result.returncode != 0

    def test_encrypt_nonexistent_key_fails(self, store_path: str) -> None:
        result = run_cli(["encrypt", "no-such-key", "-d", "data"], store_path, expect_fail=True)
        assert result.returncode != 0
        assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()


class TestSignVerify:
    """Test sign/verify round-trip via CLI."""

    def test_sign_verify_ec(self, store_path: str) -> None:
        run_cli(["generate", "sig-key", "--type", "ec-p256"], store_path)
        sig_result = run_cli(["sign", "sig-key", "-d", "message to sign"], store_path)
        signature = sig_result.stdout.strip()
        assert signature
        verify_result = run_cli(["verify", "sig-key", "message to sign", signature], store_path)
        assert "VALID" in verify_result.stdout

    def test_sign_verify_ed25519(self, store_path: str) -> None:
        run_cli(["generate", "ed-sig-key", "--type", "ed25519"], store_path)
        sig_result = run_cli(["sign", "ed-sig-key", "-d", "ed25519 msg"], store_path)
        signature = sig_result.stdout.strip()
        verify_result = run_cli(["verify", "ed-sig-key", "ed25519 msg", signature], store_path)
        assert "VALID" in verify_result.stdout

    def test_verify_invalid_signature(self, store_path: str) -> None:
        run_cli(["generate", "v-key", "--type", "ec-p256"], store_path)
        sig_result = run_cli(["sign", "v-key", "-d", "original"], store_path)
        signature = sig_result.stdout.strip()
        # Verify with wrong message
        result = run_cli(["verify", "v-key", "tampered", signature], store_path, expect_fail=True)
        assert result.returncode != 0
        assert "INVALID" in result.stdout


class TestKeyLifecycle:
    """Test key listing, rotation, and deletion."""

    def test_list_keys(self, store_path: str) -> None:
        run_cli(["generate", "list-key-1", "--type", "aes-256"], store_path)
        run_cli(["generate", "list-key-2", "--type", "ec-p256"], store_path)
        result = run_cli(["list"], store_path)
        assert "list-key-1" in result.stdout
        assert "list-key-2" in result.stdout
        assert "aes-256" in result.stdout
        assert "ec-p256" in result.stdout

    def test_list_empty_store(self, store_path: str) -> None:
        result = run_cli(["list"], store_path)
        assert "No keys stored" in result.stdout

    def test_rotate_key(self, store_path: str) -> None:
        run_cli(["generate", "rot-key"], store_path)
        # Encrypt before rotation
        enc1 = run_cli(["encrypt", "rot-key", "-d", "before rotation"], store_path)
        ct1 = enc1.stdout.strip()
        # Rotate
        rot_result = run_cli(["rotate", "rot-key"], store_path)
        assert "Rotated" in rot_result.stdout
        assert "version 2" in rot_result.stdout
        # Old ciphertext still decryptable
        dec1 = run_cli(["decrypt", "rot-key", "-d", ct1], store_path)
        assert dec1.stdout == "before rotation"
        # New encryption works
        enc2 = run_cli(["encrypt", "rot-key", "-d", "after rotation"], store_path)
        ct2 = enc2.stdout.strip()
        dec2 = run_cli(["decrypt", "rot-key", "-d", ct2], store_path)
        assert dec2.stdout == "after rotation"

    def test_delete_key(self, store_path: str) -> None:
        run_cli(["generate", "del-key"], store_path)
        run_cli(["delete", "del-key", "--yes"], store_path)
        result = run_cli(["list"], store_path)
        assert "del-key" not in result.stdout

    def test_delete_nonexistent_fails(self, store_path: str) -> None:
        result = run_cli(["delete", "ghost-key", "--yes"], store_path, expect_fail=True)
        assert result.returncode != 0


class TestPubkey:
    """Test public key export."""

    def test_pubkey_ec(self, store_path: str) -> None:
        run_cli(["generate", "pub-ec", "--type", "ec-p256"], store_path)
        result = run_cli(["pubkey", "pub-ec"], store_path)
        assert "BEGIN PUBLIC KEY" in result.stdout
        assert "END PUBLIC KEY" in result.stdout

    def test_pubkey_aes_fails(self, store_path: str) -> None:
        run_cli(["generate", "pub-aes"], store_path)
        result = run_cli(["pubkey", "pub-aes"], store_path, expect_fail=True)
        assert result.returncode != 0


class TestErrorCases:
    """Test error handling."""

    def test_bad_password(self, tmp_path: Path) -> None:
        store = str(tmp_path / "bad-pw.enc")
        # Create with good password
        run_cli(["generate", "k1"], store)
        # Try with wrong password
        env = {"PYHSM_MASTER_PASSWORD": "wrong-password-here"}
        result = run_cli(["list"], store, env_extra=env, expect_fail=True)
        assert result.returncode != 0

    def test_short_password(self, tmp_path: Path) -> None:
        store = str(tmp_path / "short-pw.enc")
        env = {"PYHSM_MASTER_PASSWORD": "short"}
        result = run_cli(["generate", "k1"], store, env_extra=env, expect_fail=True)
        assert result.returncode != 0
        assert "too short" in result.stderr.lower() or "minimum" in result.stderr.lower()

    def test_invalid_key_id(self, store_path: str) -> None:
        result = run_cli(["generate", "../bad-id"], store_path, expect_fail=True)
        assert result.returncode != 0


class TestMetrics:
    """Test metrics output."""

    def test_metrics_default(self, store_path: str) -> None:
        run_cli(["generate", "m-key"], store_path)
        run_cli(["encrypt", "m-key", "-d", "data"], store_path)
        result = run_cli(["metrics"], store_path)
        assert "encrypt" in result.stdout.lower() or "operations" in result.stdout.lower()

    def test_metrics_prometheus(self, store_path: str) -> None:
        run_cli(["generate", "p-key"], store_path)
        result = run_cli(["metrics", "--prometheus"], store_path)
        assert "pyhsm_" in result.stdout


class TestAudit:
    """Test audit log commands."""

    def test_audit_entries(self, store_path: str) -> None:
        run_cli(["generate", "a-key"], store_path)
        run_cli(["encrypt", "a-key", "-d", "secret"], store_path)
        result = run_cli(["audit"], store_path)
        assert "generateKey" in result.stdout or "generate" in result.stdout

    def test_audit_verify(self, store_path: str) -> None:
        run_cli(["generate", "v-key"], store_path)
        result = run_cli(["audit", "--verify"], store_path)
        assert "OK" in result.stdout

    def test_audit_raw(self, store_path: str) -> None:
        run_cli(["generate", "r-key"], store_path)
        result = run_cli(["audit", "--raw"], store_path)
        # Each line should be valid JSON
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                json.loads(line)
