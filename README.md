# PyHSM

A software-based Hardware Security Module (HSM) providing cryptographic key management, encryption, signing, and secure key storage. Available as a Python CLI tool and a production-hardened TypeScript library.

## Python CLI

### Features

- **Key Generation**: AES-128, AES-256, RSA-2048, RSA-4096, EC P-256
- **Encryption/Decryption**: AES-GCM authenticated encryption
- **Signing/Verification**: RSA-PSS and ECDSA with SHA-256
- **Secure Storage**: Keys encrypted at rest with AES-256-GCM, master key derived via PBKDF2 (480k iterations)

### Install

```bash
pip install cryptography
```

### Usage

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

### Architecture

```
cli.py          — Command-line interface
hsm/
  core.py       — PyHSM class (crypto operations)
  storage.py    — KeyStore class (encrypted persistence)
```

## TypeScript / Node.js

A production-hardened TypeScript implementation lives in `./pyhsm-ts/` and features:

- **AES-256-GCM-SIV** — nonce-misuse-resistant encryption
- **Argon2id** — memory-hard key derivation (replaces PBKDF2)
- **AES-KWP** (RFC 5649) — key wrapping for stored key material
- **Key versioning** — rotate keys without breaking old ciphertexts
- **Per-key ACLs** — restrict which services can use which keys
- **Rate limiting** — prevent bulk decryption attacks
- **HMAC tamper detection** — zeroizes all keys on keystore modification
- **Shamir M-of-N unlock** — ceremony-based startup
- **Session auto-lock** — keys zeroized after inactivity timeout
- **Startup self-tests** — known-answer tests run before accepting operations
- **HMAC-chained audit log** — tamper-evident operation history
- **Prometheus metrics** — health monitoring

### Install

```bash
npm install
```

### Usage

```typescript
import { PyHSM } from './pyhsm-ts';

// Initialize with a single passphrase
const hsm = new PyHSM({
  storePath: './pyhsm-keystore.enc',
  masterPassword: 'my-passphrase',
});

// Or use the async factory for Argon2id key derivation (preferred)
const hsm = await PyHSM.create({
  storePath: './pyhsm-keystore.enc',
  masterPassword: 'my-passphrase',
});

// Generate a key
hsm.generateKey('my-aes-key');

// Generate a key with a custom policy
hsm.generateKey('restricted-key', {
  allowEncrypt: true,
  allowDecrypt: true,
  maxOperations: 1000,
  expiresAt: '2027-01-01T00:00:00Z',
  allowedCallers: ['service-a', 'service-b'],
});

// Encrypt / Decrypt (AES-256-GCM-SIV)
const ciphertext = hsm.encrypt('my-aes-key', 'secret message');
const plaintext = hsm.decrypt('my-aes-key', ciphertext);

// Key rotation (old ciphertexts remain decryptable)
hsm.rotateKey('my-aes-key');

// Destroy a key (zeroizes all versions)
hsm.destroyKey('my-aes-key');

// Close session (zeroizes memory)
hsm.closeSession();
```

### Shamir M-of-N Unlock

Instead of a single passphrase, you can split the master password into N shares requiring K to reconstruct:

```typescript
import { splitMasterPassword, PyHSM } from './pyhsm-ts';
import type { ShamirShare } from './pyhsm-ts';

// One-time setup: split the master password into 5 shares, requiring 3 to unlock
const shares: ShamirShare[] = splitMasterPassword('my-passphrase', 3, 5);
// Distribute one share to each operator:
// { index: 1, data: "a1b2c3..." }
// { index: 2, data: "d4e5f6..." }
// ...

// Later: collect 3 shares from operators and unlock
const hsm = new PyHSM({
  storePath: './pyhsm-keystore.enc',
  shares: [
    JSON.stringify(shares[0]),
    JSON.stringify(shares[2]),
    JSON.stringify(shares[4]),
  ],
});
```

Shares can also be provided via environment variable:

```bash
export PYHSM_SHARES='{"index":1,"data":"a1b2c3..."},{"index":3,"data":"d4e5f6..."},{"index":5,"data":"789abc..."}'
```

### Configuration

```typescript
const hsm = new PyHSM({
  storePath: './pyhsm-keystore.enc',
  masterPassword: 'my-passphrase',
  sessionTimeoutMs: 300000,          // Auto-lock after 5 min inactivity (default)
  auditLogPath: './pyhsm.audit.jsonl', // Audit log location
  backupDir: './backups',             // Encrypted backup directory
  callerSecret: 'shared-secret',     // HMAC-based caller authentication
});
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PYHSM_KEYSTORE_PATH` | Path to encrypted keystore file |
| `PYHSM_MASTER_PASSWORD` | Master password (alternative to config) |
| `PYHSM_SHARES` | Comma-separated JSON Shamir shares |
| `PYHSM_AUDIT_LOG_PATH` | Audit log file path |
| `PYHSM_BACKUP_DIR` | Backup directory |
| `PYHSM_CALLER_SECRET` | Shared secret for caller auth |
| `PYHSM_SESSION_TIMEOUT_MS` | Session timeout in milliseconds |
| `PYHSM_RATE_LIMIT` | Max operations per window (default: 100) |
| `PYHSM_RATE_WINDOW_MS` | Rate limit window in ms (default: 60000) |
| `PYHSM_KEY_ID` | Default key ID for drop-in helpers |

### Architecture

```
pyhsm-ts/
  index.ts        — Exports, singleton factory, drop-in helpers
  core.ts         — PyHSM class (encrypt, decrypt, key lifecycle)
  types.ts        — TypeScript interfaces
  shamir.ts       — Shamir's Secret Sharing (GF(256))
  rate-limiter.ts — Per-key rate limiting
  audit.ts        — HMAC-chained audit log
  metrics.ts      — Prometheus metrics collector
  self-test.ts    — Startup known-answer tests, FIPS mode
  process.ts      — Process isolation (Unix socket IPC)
  client.ts       — IPC client
```

## Security Notes

- Keys never exist unencrypted on disk — the keystore is always AES-256-GCM encrypted
- HMAC integrity check on every keystore load — tamper triggers immediate zeroization
- Master key derived via Argon2id (64 MB memory, 3 iterations) or PBKDF2-SHA256 (480k iterations) as fallback
- Each encryption uses a fresh random nonce with AES-256-GCM-SIV (nonce-misuse resistant)
- Key material is zeroized on session close or tamper detection
- Atomic file writes prevent keystore corruption
- This is a **development/educational tool** — not a replacement for a certified hardware HSM
