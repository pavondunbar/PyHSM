# PyHSM Operations Guide

Production deployment, environment variables, and operational procedures.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Application Process                                  │
│  ┌────────────┐                                      │
│  │ PyHSMClient├────── Unix domain socket ──────┐     │
│  └────────────┘                                │     │
└────────────────────────────────────────────────┼─────┘
                                                 │
┌────────────────────────────────────────────────┼─────┐
│  PyHSM Process (process.ts)                    │     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │     │
│  │ Wrapped  │  │  Audit   │  │ Self-Test│     ▼     │
│  │ AES keys │  │  Log     │  │  (KAT)   │  IPC     │
│  │ (AES-KWP)│  │          │  │          │  Server   │
│  └──────────┘  └──────────┘  └──────────┘           │
│  ┌──────────────────────────────────────────┐        │
│  │ Encrypted Keystore (StorageBackend)      │        │
│  │  • FileBackend (default, atomic writes)  │        │
│  │  • MemoryBackend (testing)               │        │
│  │  • Custom (DB, S3, etc.)                 │        │
│  └──────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────┘
```

Key material lives exclusively in the PyHSM process, double-encrypted at rest:
individual keys are wrapped with AES-KWP (RFC 5649) inside the outer AES-256-GCM
encrypted keystore envelope. The application process communicates over a Unix domain
socket (NDJSON protocol) via the `PyHSMClient`. A vulnerability in the application
cannot directly read key material in the HSM process's address space.

The IPC server enforces a 1 MB maximum message size per connection to prevent
memory exhaustion from malicious or buggy clients.

---

## Environment Variables

### Required (one of)

| Variable                | Description                                         |
|-------------------------|-----------------------------------------------------|
| `PYHSM_MASTER_PASSWORD` | Master password for keystore encryption.           |
| `PYHSM_SHARES`          | Comma-separated Shamir share JSON objects.         |

### Paths & Storage

| Variable                  | Default                          | Description                     |
|---------------------------|----------------------------------|---------------------------------|
| `PYHSM_KEYSTORE_PATH`    | `./pyhsm-keystore.enc`          | Encrypted keystore location.   |
| `PYHSM_AUDIT_LOG_PATH`   | `<storePath>.audit.jsonl`        | HMAC-chained audit log path.   |
| `PYHSM_BACKUP_DIR`       | *(none — backups disabled)*      | Directory for encrypted backups.|
| `PYHSM_SOCKET_PATH`      | `/tmp/pyhsm.sock`               | Unix domain socket for IPC.    |

### Security

| Variable                  | Default   | Description                                       |
|---------------------------|-----------|---------------------------------------------------|
| `PYHSM_CALLER_SECRET`    | *(none)*  | Shared secret for IPC caller HMAC authentication. |
| `PYHSM_AUDIT_HMAC_KEY`   | *(auto)*  | Hex-encoded 32-byte key for audit HMAC chain. Auto-generated and stored at `<audit_log_path>.hmackey` if not set. Independent of master password — audit verification survives master password rotation. |

### Tuning

| Variable                     | Default   | Description                                    |
|------------------------------|-----------|------------------------------------------------|
| `PYHSM_SESSION_TIMEOUT_MS`  | `300000`  | Idle time before session auto-closes (ms).    |
| `PYHSM_RATE_LIMIT`          | `100`     | Max operations per key per rate window.        |
| `PYHSM_RATE_WINDOW_MS`      | `60000`   | Rate limiting window duration (ms).            |

### Observability

| Variable                  | Default  | Description                               |
|---------------------------|----------|-------------------------------------------|
| `PYHSM_AUDIT_WEBHOOK`    | *(none)* | URL for non-blocking audit event POST (shipped in a background thread/fire-and-forget). |

---

## Deployment Modes

### Embedded (in-process)

```typescript
import { PyHSM } from "pyhsm-ts";

const hsm = new PyHSM({
  storePath: "/secure/keystore.enc",
  masterPassword: process.env.PYHSM_MASTER_PASSWORD!,
});

hsm.generateKey("app-key");
const ct = hsm.encrypt("app-key", plaintext);
```

Key material resides in the same process as the application.

### With custom storage backend

```typescript
import { PyHSM, MemoryBackend } from "pyhsm-ts";

// Example: in-memory for testing
const hsm = new PyHSM({
  storePath: "test",
  masterPassword: "test-pw",
  backend: new MemoryBackend(),
});

// For production: implement StorageBackend interface for your database/cloud
// interface StorageBackend {
//   exists(): boolean;
//   read(): Buffer;
//   write(data: Buffer): void;
//   delete(): void;
// }
```

### Process-Isolated (recommended for production)

Start the HSM process:

```bash
export PYHSM_MASTER_PASSWORD="..."
export PYHSM_KEYSTORE_PATH="/secure/keystore.enc"
export PYHSM_SOCKET_PATH="/run/pyhsm/pyhsm.sock"
export PYHSM_CALLER_SECRET="<shared-secret>"
export PYHSM_BACKUP_DIR="/secure/backups"

npx tsx pyhsm-ts/process.ts
```

Application connects via client:

```typescript
import { PyHSMClient } from "pyhsm-ts";

const client = new PyHSMClient("/run/pyhsm/pyhsm.sock", "my-service");
const ct = await client.encrypt("app-key", plaintext);
```

### Shamir Ceremony (M-of-N Unlock)

For maximum security, the master password itself can be split into
Shamir shares distributed to separate operators:

```typescript
import { splitMasterPassword } from "pyhsm-ts";

// One-time: split the master password into 5 shares, 3 required
const shares = splitMasterPassword(masterPassword, 3, 5);
// Distribute shares[0..4] to five key custodians
```

At startup, collect shares from K operators:

```bash
export PYHSM_SHARES='{"index":1,"data":"..."}, {"index":3,"data":"..."}, {"index":5,"data":"..."}'
npx tsx pyhsm-ts/process.ts
```

---

## Operational Procedures

### Key Rotation

Generates a new key version; old version is archived (can still decrypt
ciphertexts encrypted with it, but new encryptions use the new version).
New key material is wrapped with AES-KWP before storage.

```typescript
hsm.rotateKey("my-key");
```

### Backup

Creates an encrypted copy of the keystore:

```typescript
const path = hsm.createBackup();
```

### Verify Backup

Confirms a backup file is intact (HMAC + decryption check) without
loading it into the live store:

```typescript
hsm.verifyBackup("/secure/backups/pyhsm-backup-2025-01-01.enc");
```

### Audit Log Verification

The audit log uses an independently stored HMAC key (at `<log_path>.hmackey`),
so verification works even if the master password changes or is unknown:

```typescript
const corrupted = hsm.getAuditLog().verify();
if (corrupted >= 0) {
  console.error(`Audit log corrupted at sequence ${corrupted}`);
}
```

### SIEM Export (Elasticsearch, Splunk, Datadog)

```typescript
const ndjson = hsm.getAuditLog().toNdjson({ since: "2025-01-01T00:00:00Z" });
// Ship to your SIEM as-is (Newline-Delimited JSON format)
```

---

## Ciphertext Format

### Python Layer

The Python layer uses a versioned ciphertext format:

**v2 (current):** `format_byte(1) + version(4) + nonce(12) + ciphertext+tag`

- Format byte `0x02` identifies AAD-bound ciphertext
- AAD = `pyhsm:v1:{key_id}:{version}` — binds ciphertext to the specific key
- Nonce = `random(4) + counter(4) + random(4)` — hybrid strategy eliminates birthday collisions

**v1 (legacy):** `version(4) + nonce(12) + ciphertext+tag`

- No format byte prefix (first byte is `0x00` for version 1 keys)
- No AAD binding
- Decrypt auto-detects format and handles both transparently

### TypeScript Layer

- Base64-encoded: `version(4) + nonce(12) + ciphertext+tag`
- Uses AES-256-GCM-SIV (nonce-misuse resistant from `@noble/ciphers`)

---

## Metrics (Prometheus)

Expose the `/metrics` endpoint:

```typescript
const text = hsm.getPrometheusMetrics();
// Serve via HTTP or write to file for node_exporter textfile collector
```

Available metrics:

- `pyhsm_operations_total{type="encrypt|decrypt|sign|verify"}`
- `pyhsm_errors_total`
- `pyhsm_rate_limit_hits_total`
- `pyhsm_access_denials_total`
- `pyhsm_keys{state="active|archived"}`
- `pyhsm_uptime_seconds`

---

## Security Considerations

1. **Key separation**: The keystore uses HKDF-Expand to derive independent encryption and MAC keys from the master key (info strings: `pyhsm-enc-v1`, `pyhsm-mac-v1`). A weakness in one primitive cannot leak the other key.

2. **Per-key wrapping**: Individual keys are wrapped with AES-KWP (RFC 5649) using a KEK derived through the full PBKDF2 → HKDF-Expand path with a dedicated salt stored inside the encrypted keystore. The KEK is cached in memory for the session lifetime (avoiding repeated PBKDF2 on every operation) and zeroized on session close. Even if the decrypted keystore JSON is exposed (e.g., core dump), individual key material remains encrypted. Legacy keystores (pre-salt KEK) are automatically migrated on first open.

3. **Memory zeroization**: Key material is stored as mutable `bytearray` (Python) or `Buffer` (TypeScript) with deterministic byte-by-byte zeroization. In the Python layer, key_data is held as `bytearray` in memory (not immutable hex strings), so it can be reliably zeroed on destroy or session close. The master password is stored as a mutable `bytearray` and overwritten on session close. The cached KEK is also zeroized. V8/CPython string immutability means metadata (key IDs, timestamps) is not deterministically clearable.

4. **File permissions**: The keystore is written mode `0o600`. The Unix socket is `chmod 0o600`. The audit HMAC key file is `0o600`.

5. **Tamper detection**: The keystore uses encrypt-then-MAC with separated keys. Any modification to the file triggers a tamper alert, zeroizes all memory, and throws.

6. **KDF**: The async `PyHSM.create()` factory uses Argon2id (64 MB / 3 passes / 4 parallelism). The synchronous constructor falls back to PBKDF2-SHA256 at 480,000 iterations. Both layers then apply HKDF-Expand to derive separate encryption and MAC subkeys.

7. **Nonce safety**: Python uses a hybrid nonce (random + counter + random) that prevents birthday-bound collisions even at high operation volumes. TypeScript uses AES-256-GCM-SIV which is inherently nonce-misuse resistant.

8. **AAD binding (Python)**: Ciphertext is bound to `pyhsm:v1:{key_id}:{version}` via GCM authenticated data. This prevents an attacker from moving ciphertext between keys or versions — decryption fails if the AAD doesn't match.

9. **Input validation**: Both layers reject plaintext larger than 64 MB before encryption, and the Python layer also validates ciphertext input size before decryption, to prevent memory exhaustion attacks.

10. **Constant-time comparisons**: HMAC verification uses `hmac.compare_digest` (Python) and length-padded `crypto.timingSafeEqual` (TypeScript). The TypeScript implementation pads both buffers to the same length before comparison to prevent length-based timing side channels.

11. **Audit log independence**: The audit HMAC key is derived from the master password via HKDF-Expand (info: `pyhsm-audit-hmac-v1`) in the Python layer — no plaintext key file on disk. In the TypeScript layer, it is stored separately at `<log_path>.hmackey` (auto-generated on first use). Can be overridden via `PYHSM_AUDIT_HMAC_KEY` env var in both layers.

12. **Concurrency (Python)**: Per-key operations (encrypt, decrypt, sign, verify) use sharded locks — operations on different keys execute in parallel. Only lifecycle operations (generate, rotate, destroy) acquire the global lock. The keystore persistence layer (`_save_store`) uses a dedicated save lock to serialize writes, preventing concurrent per-key operations from interleaving their serialize → encrypt → write sequences.

13. **Deferred persistence (TypeScript)**: Encrypt, decrypt, sign, and verify increment operation counts in memory and mark the store as dirty. The keystore is persisted on the next structural mutation (generate, rotate, destroy, import, backup) or on session close. This eliminates a full serialize+encrypt+write cycle on every read-path operation while ensuring operation counts and `maxOperations` policy enforcement survive process restarts. If the process crashes between operations, at most a few operation count increments may be lost — the keys themselves remain safely encrypted on disk from the last mutation.

14. **Operation counting consistency**: All cryptographic operations (encrypt, decrypt, sign, verify) increment the per-key `operation_count` and persist state. The `max_operations` policy applies uniformly across all operation types.

15. **Caller ACL enforcement (Python)**: Keys can define an `allowed_callers` list in their policy. When set, every operation must provide a `caller_id` that matches one of the allowed callers. Unauthorized access is denied, logged as an `accessDenied` audit entry with the caller identity, and raises an error. All operations record `caller_id` in the audit log when provided.

16. **Rate limiter ordering (Python)**: Policy enforcement checks are ordered to prevent denial-of-service: caller ACL, operation permission, max operations, and expiry are all validated before the rate limiter consumes a token. This ensures unauthorized or policy-denied requests cannot exhaust the rate-limit window for legitimate callers.

17. **EC curve hash pairing (Python)**: ECDSA signing uses NIST-recommended hash algorithms per curve: P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512. This ensures the hash security level matches the curve security level.

---

## JWK Key Import / Export (RFC 7517)

PyHSM supports standard JSON Web Key format for key migration and interoperability.

### Export

Export a stored key to JWK for use in another system:

**Python:**

```python
jwk = hsm.export_jwk("my-aes-key")
# {"kty": "oct", "k": "...", "alg": "A256GCM", "kid": "my-aes-key"}

ec_jwk = hsm.export_jwk("my-ec-key")
# {"kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "...", "kid": "my-ec-key"}

rsa_jwk = hsm.export_jwk("my-rsa-key")
# {"kty": "RSA", "n": "...", "e": "...", "d": "...", ...}
```

**TypeScript:**

```typescript
const jwk = hsm.exportJwk("my-key");
```

### Import

Import a key from another KMS, identity provider, or standards-compliant system:

**Python:**

```python
# Import an AES key
hsm.import_key_jwk("imported-aes", {
    "kty": "oct",
    "k": "base64url-encoded-32-bytes",
    "alg": "A256GCM",
})

# Import an EC signing key from an OAuth provider
hsm.import_key_jwk("idp-key", jwk_from_provider, policy={
    "allow_encrypt": False,
    "allow_sign": True,
})
```

**TypeScript:**

```typescript
hsm.importKeyJwk("external-key", jwkObject, { allowEncrypt: true, allowDecrypt: true });
```

### Supported Key Types

| JWK `kty` | PyHSM key type | Notes |
|---|---|---|
| `oct` (16 bytes) | `aes-128` | Symmetric encryption |
| `oct` (32 bytes) | `aes-256` | Symmetric encryption |
| `EC` (P-256) | `ec-p256` | ECDSA signing (SHA-256) |
| `EC` (P-384) | `ec-p384` | ECDSA signing (SHA-384) |
| `EC` (P-521) | `ec-p521` | ECDSA signing (SHA-512) |
| `RSA` (2048-bit) | `rsa-2048` | RSA-PSS signing |
| `RSA` (4096-bit) | `rsa-4096` | RSA-PSS signing |

Imported keys are wrapped with AES-KWP before storage, matching the security properties of locally-generated keys.

---

## Implementing a Custom Storage Backend

To store keystore data in a database, S3, or other system, implement the `StorageBackend` interface:

### Python

```python
from hsm.backends import StorageBackend

class PostgresBackend(StorageBackend):
    def __init__(self, dsn: str, key_name: str = "default"):
        self.dsn = dsn
        self.key_name = key_name

    def exists(self) -> bool:
        # SELECT COUNT(*) FROM keystores WHERE name = self.key_name
        ...

    def read(self) -> bytes:
        # SELECT data FROM keystores WHERE name = self.key_name
        ...

    def write(self, data: bytes) -> None:
        # INSERT ... ON CONFLICT UPDATE (upsert)
        ...

    def delete(self) -> None:
        # DELETE FROM keystores WHERE name = self.key_name
        ...
```

### TypeScript

```typescript
import type { StorageBackend } from "pyhsm-ts";

class S3Backend implements StorageBackend {
  constructor(private bucket: string, private key: string) {}

  exists(): boolean { /* HEAD object */ }
  read(): Buffer { /* GET object */ }
  write(data: Buffer): void { /* PUT object */ }
  delete(): void { /* DELETE object */ }
}
```

The backend never sees plaintext key material — it only stores and retrieves the fully-encrypted keystore blob.
