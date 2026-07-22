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
│  │ AES keys │  │  Audit   │  │ Self-Test│     ▼     │
│  │ (memory) │  │  Log     │  │  (KAT)   │  IPC     │
│  └──────────┘  └──────────┘  └──────────┘  Server   │
│  ┌──────────────────────────────────────────┐        │
│  │ Encrypted Keystore (filesystem)          │        │
│  └──────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────┘
```

Key material lives exclusively in the PyHSM process.  The application
process communicates over a Unix domain socket (NDJSON protocol) via the
`PyHSMClient`.  A vulnerability in the application cannot directly read
key material in the HSM process's address space.

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
| `PYHSM_AUDIT_HMAC_KEY`   | *(auto)*  | Hex-encoded 32-byte key for audit HMAC chain.     |
| `PYHSM_FIPS`             | `0`       | Set to `1` to enable FIPS mode (requires OpenSSL 3.x FIPS provider). |

### Tuning

| Variable                     | Default   | Description                                    |
|------------------------------|-----------|------------------------------------------------|
| `PYHSM_SESSION_TIMEOUT_MS`  | `300000`  | Idle time before session auto-closes (ms).    |
| `PYHSM_RATE_LIMIT`          | `100`     | Max operations per key per rate window.        |
| `PYHSM_RATE_WINDOW_MS`      | `60000`   | Rate limiting window duration (ms).            |

### Observability

| Variable                  | Default  | Description                               |
|---------------------------|----------|-------------------------------------------|
| `PYHSM_AUDIT_WEBHOOK`    | *(none)* | URL for fire-and-forget audit event POST. |

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

## Metrics (Prometheus)

Expose the `/metrics` endpoint:

```typescript
const text = hsm.getPrometheusMetrics();
// Serve via HTTP or write to file for node_exporter textfile collector
```

Available metrics:

- `pyhsm_operations_total{type="encrypt|decrypt"}`
- `pyhsm_errors_total`
- `pyhsm_rate_limit_hits_total`
- `pyhsm_access_denials_total`
- `pyhsm_keys{state="active|archived"}`
- `pyhsm_uptime_seconds`

---

## Security Considerations

1. **Memory zeroization**: Key material is zeroized via `Buffer.fill(0)` / `SecureBuffer.dispose()` when sessions close or keys are unwrapped. V8 strings (key IDs, metadata) are not deterministically clearable; only `Buffer`-backed data benefits.

2. **File permissions**: The keystore is written mode `0o600`. The Unix socket is `chmod 0o600`. The audit HMAC key file is `0o600`.

3. **Tamper detection**: The keystore uses encrypt-then-MAC (AES-256-GCM + HMAC-SHA256). Any modification to the file triggers a tamper alert, zeroizes all memory, and throws.

4. **KDF**: The async `PyHSM.create()` factory uses Argon2id (64 MB / 3 passes / 4 parallelism). The synchronous constructor falls back to PBKDF2-SHA256 at 480,000 iterations.

5. **Nonce misuse resistance**: Encryption uses AES-256-GCM-SIV (from `@noble/ciphers`), which remains secure even if a nonce is accidentally reused.

6. **Key wrapping**: At-rest key material is double-encrypted: the keystore file is AES-256-GCM encrypted, and individual keys within it are additionally wrapped with AES-KWP (RFC 5649).
