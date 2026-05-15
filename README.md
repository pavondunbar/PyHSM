# PyHSM

A software-based Hardware Security Module (PyHSM) providing cryptographic key management, encryption, signing, and secure key storage.

## Features

- **Key Generation**: AES-128, AES-256, RSA-2048, RSA-4096, EC P-256
- **Encryption/Decryption**: AES-GCM authenticated encryption
- **Signing/Verification**: RSA-PSS and ECDSA with SHA-256
- **Secure Storage**: Keys encrypted at rest with AES-256-GCM, master key derived via PBKDF2 (480k iterations)

## Install

```bash
pip install cryptography
```

## Usage

```bash
# Generate keys
python cli.py -p mypassword generate my-aes-key --type aes-256
python cli.py -p mypassword generate my-rsa-key --type rsa-2048
python cli.py -p mypassword generate my-ec-key --type ec-p256

# List keys
python cli.py -p mypassword list

# Encrypt / Decrypt
python cli.py -p mypassword encrypt my-aes-key -d "secret message"
python cli.py -p mypassword decrypt my-aes-key -d <ciphertext-hex>

# Sign / Verify
python cli.py -p mypassword sign my-ec-key -d "message to sign"
python cli.py -p mypassword verify my-ec-key "message to sign" <signature-hex>

# Export public key
python cli.py -p mypassword pubkey my-rsa-key

# Delete a key
python cli.py -p mypassword delete my-aes-key
```

Stdin is also supported — omit `-d` and pipe data in.

## Architecture

```
cli.py          — Command-line interface
hsm/
  core.py       — PyHSM class (crypto operations)
  storage.py    — KeyStore class (encrypted persistence)
```

## TypeScript / Node.js Integration

A production-hardened TypeScript implementation is available for Node.js projects and includes:

- **AES-256-GCM-SIV** — nonce-misuse-resistant encryption
- **Argon2id** — memory-hard key derivation (replaces PBKDF2)
- **AES-KWP** (RFC 5649) — key wrapping
- **Key versioning** — rotate keys without breaking old ciphertexts
- **Per-key ACLs** — restrict which services can use which keys
- **Rate limiting** — prevent bulk decryption attacks
- **HMAC tamper detection** — zeroizes all keys on keystore modification
- **Process isolation** — runs in a separate process via Unix socket
- **Shamir M-of-N unlock** — ceremony-based startup
- **FIPS mode** — enables OpenSSL FIPS provider when available
- **Prometheus metrics** — health monitoring
- **HMAC-chained audit log** — tamper-evident operation history

## Security Notes

- Keys never exist unencrypted on disk — the keystore file is always AES-256-GCM encrypted
- Master key is derived from your password using PBKDF2-SHA256 with 480,000 iterations
- Each encryption operation uses a fresh random nonce
- This is a **development/educational tool** — not a replacement for a certified hardware HSM
