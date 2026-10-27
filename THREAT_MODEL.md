# PyHSM Threat Model

**Last updated:** v2.2.0 (2026-10-27)

This document defines the security boundaries, assumptions, and threat actors
that PyHSM is designed to defend against — and explicitly states what is out of scope.

---

## Assets Protected

| Asset | Description |
|---|---|
| Cryptographic key material | AES-256, AES-128, RSA-2048/4096, EC P-256/P-384/P-521/secp256k1, Ed25519 private keys |
| Master password | The credential used to derive keystore encryption keys |
| KEK (Key Encryption Key) | Derived from master password via Argon2id → HKDF; used for per-key AES-KWP wrapping |
| Keystore integrity | The encrypted keystore file must not be silently modified |
| Audit log integrity | The HMAC-chained log must be tamper-evident |
| Operational metadata | Key policies, operation counts, caller ACLs |

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  Boundary 1: Application Process                                     │
│                                                                      │
│  Your application code calls PyHSM API (sign, encrypt, etc.)         │
│  Raw key material is NEVER returned to this layer                    │
│  (except explicit export_jwk, which is audited)                      │
└────────────────────────────────────┬────────────────────────────────┘
                                     │
┌────────────────────────────────────┼────────────────────────────────┐
│  Boundary 2: PyHSM Core (in-process or isolated process)             │
│                                                                      │
│  Key material exists here in plaintext ONLY during cryptographic      │
│  operations (sign, encrypt, decrypt). Stored as mutable bytearray    │
│  and zeroized immediately after use.                                 │
│                                                                      │
│  In process-isolation mode, this runs in a SEPARATE OS process       │
│  communicating over a Unix domain socket.                            │
└────────────────────────────────────┬────────────────────────────────┘
                                     │
┌────────────────────────────────────┼────────────────────────────────┐
│  Boundary 3: Persistent Storage (Filesystem)                         │
│                                                                      │
│  keystore.enc — AES-256-GCM encrypted + HMAC-SHA256 sealed           │
│  Individual keys additionally wrapped with AES-KWP (RFC 5649)        │
│  Audit log — HMAC-chained, append-only                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Threat Actors

### T1: External Attacker with Network Access

**Capability:** Can reach services running on the host (web app, APIs).
Cannot directly access the filesystem or PyHSM process.

**Relevant attacks:**
- Exploit application vulnerability (RCE, SSRF, injection)
- If successful, escalates to T2

**PyHSM mitigation:**
- Process isolation mode: keys in separate address space
- Application never holds raw key material
- `allowed_callers` policy restricts which services can use which keys

### T2: Attacker with Application-Level Code Execution

**Capability:** Can execute arbitrary code in the application process.
Cannot directly access the PyHSM process memory (if isolation mode is used).

**Relevant attacks:**
- Call `hsm.sign()` / `hsm.encrypt()` with attacker-controlled inputs
- Attempt to export keys via `export_jwk()`
- Read environment variables or config for master password
- Connect to the IPC socket if they can read the IPC secret from the application environment

**PyHSM mitigation:**
- Rate limiting caps the number of operations per key per time window
- `max_operations` policy provides a hard lifetime cap
- `allowed_callers` denies unauthorized caller IDs
- `expires_at` auto-expires keys
- Audit log records all operations (including denied ones) for forensic review
- Process isolation prevents reading HSM process memory
- IPC mutual authentication (HMAC-SHA256 shared secret, **required** since v2.2.0) — an attacker who doesn't have the IPC secret cannot authenticate even if they can reach the socket

**Residual risk:** If the master password or IPC secret is in the same process's
environment variables, an attacker with code execution can read it. Mitigation:
use Shamir shares, inject credentials at startup, and place secrets on tmpfs.

### T3: Attacker with Filesystem Read Access

**Capability:** Can read files on the host (stolen backup, leaked disk image,
compromised CI artifact, misconfigured file permissions).

**Relevant attacks:**
- Read `keystore.enc`
- Read audit log
- Read application config for master password

**PyHSM mitigation:**
- Keystore is AES-256-GCM encrypted with a key derived from Argon2id (64 MB memory-hard)
- Each key inside is additionally wrapped with AES-KWP (RFC 5649)
- Keystore has HMAC-SHA256 tamper seal — modification is detectable
- File permissions are set to `0o600`
- Master password is not stored on disk (must be provided at runtime or via Shamir)

**Residual risk:** If the master password is stored in plaintext on the same filesystem
(e.g., in a `.env` file), this mitigation is bypassed. Use Shamir ceremony or
inject via environment variable at deploy time.

### T4: Malicious Insider with Partial Access

**Capability:** Has legitimate access to some systems but not the master password.
Could be a developer, operator, or SRE.

**Relevant attacks:**
- Copy the keystore file
- Attempt brute-force on the master password
- Tamper with the keystore or audit log
- Delete rotated audit log files to erase evidence
- Attempt to use keys without authorization

**PyHSM mitigation:**
- Argon2id with 64 MB memory cost makes brute-force expensive (~$1M+ for a 12-char password)
- Shamir M-of-N means no single insider holds the complete master password
- Tamper detection destroys all keys if keystore is modified
- Audit log HMAC chain detects deletions or modifications within a file
- Rotation-seal entries (v2.2.0) make deletion of rotated log files detectable — `verify_across_rotations()` confirms the chain from the oldest retained file to the active file; a missing file breaks the seal-to-open stitch
- Per-key `allowed_callers` restricts usage even with HSM access

### T5: Attacker with Root / Kernel Access

**Capability:** Full root access to the running machine. Can attach debuggers,
read process memory, modify kernel, intercept system calls.

**Relevant attacks:**
- Attach `gdb` / `ptrace` to the PyHSM process during signing
- Read key material from process memory
- Intercept syscalls to capture plaintext before encryption

**PyHSM mitigation:** **LIMITED.**
- Deterministic zeroization reduces the window of exposure
- No persistent plaintext keys in memory (unwrap → use → zeroize per operation)
- But a root attacker with precise timing CAN extract keys

**This is explicitly out of scope.** Hardware HSMs exist specifically for this threat.
PyHSM acknowledges this limitation in its scope statement.

---

## Assumptions

1. **The `cryptography` library (Python) and Node.js `crypto` module are correctly implemented.** PyHSM does not re-implement cryptographic primitives.

2. **The operating system provides process isolation.** A non-root user cannot read another process's memory.

3. **The master password has sufficient entropy.** PyHSM uses Argon2id to stretch weak passwords, but a 4-character password is still brutable regardless of KDF.

4. **The host system's random number generator (`/dev/urandom`, `os.urandom()`) is cryptographically secure.**

5. **File permissions are not overridden.** PyHSM sets `0o600` on the keystore, but a misconfigured system (world-readable `/secure/` directory) bypasses this.

6. **Time is approximately correct.** Key expiry (`expires_at`) relies on the system clock. An attacker who can set the clock backward can bypass expiry policies.

7. **The audit log file is on the same trust-level storage as the keystore.** If an attacker can delete the audit log file, they can erase evidence (though they cannot forge entries without the HMAC key).

---

## Cryptographic Design Decisions

| Decision | Rationale |
|---|---|
| Encrypt-then-MAC (not MAC-then-encrypt) | Proven secure composition (Bellare & Namprempre). MAC covers ciphertext, preventing padding oracle and chosen-ciphertext attacks. |
| HKDF key separation | Encryption key, MAC key, and KEK are cryptographically independent. Compromise of one does not reveal the others. |
| AES-KWP per-key wrapping | Even if the outer envelope is somehow decrypted (e.g., future cryptanalytic advance against AES-GCM), individual keys remain wrapped. |
| Argon2id over bcrypt/scrypt | Memory-hard (defeats GPU/ASIC attacks), time-hard, and resistant to side-channel (hybrid of Argon2i and Argon2d). OWASP recommended. |
| Hybrid nonce (Python) | `random(4) + counter(4) + random(4)` = 12 bytes. Counter eliminates birthday-bound collisions at high operation volumes while random prefix/suffix prevent predictability. |
| AES-256-GCM-SIV (TypeScript) | Nonce-misuse resistant. Even if a nonce is accidentally reused, only a limited amount of information leaks (ciphertext equality for same plaintext). |
| AAD binding | Ciphertext is bound to `key_id + version` via GCM authenticated data. Prevents an attacker from moving ciphertext between keys or replaying old versions. |
| Deterministic zeroization | Mutable `bytearray` (Python) / `Buffer` (TypeScript) with explicit byte-by-byte overwrite. Avoids reliance on garbage collector timing. |
| No custom crypto | All primitives are from `cryptography` (Python) / Node.js `crypto` / `@noble/ciphers`. No novel algorithms. |
| Per-share HMAC-SHA256 (v2.2.0) | Shamir shares carry `HMAC-SHA256(salt, index_byte \|\| data)` rather than a 4-byte SHA-256 truncation. Provides 256-bit existential forgery resistance; index binding prevents tag transplantation between shares. A reconstruction HMAC covering the full secret catches insufficient-share reconstruction. |
| IPC mandatory authentication (v2.2.0) | The IPC server requires `--ipc-secret` at startup. Unauthenticated socket access is rejected before any HSM operation is touched. Previous optional authentication meant an attacker reaching the socket (same UID, no secret) had full access. |
| IPC per-key locking (v2.2.0) | The previous global lock was a DoS vector: one slow RSA-4096 keygen blocked every other client. Per-key locks allow parallel operations on different keys. Read-only ops hold no lock at all. |
| Audit rotation seals (v2.2.0) | `rotationSeal` and `rotationOpen` entries cryptographically stitch the HMAC chain across file boundaries. An attacker who deletes a rotated log file cannot prevent detection because the next file's `rotationOpen.prev_seal_hmac` will not match any seal the verifier can find. |
| Startup KATs for all primitives (v2.2.0) | Extended from 4 to 10 KATs: Argon2id, HKDF-SHA256, AES-256-KWP, ECDSA P-256, RSA-2048-PSS, and Ed25519 added. Ensures the installed library versions produce correct output before any keys are used. |

---

## Known Limitations

1. **Not FIPS 140-2/3 validated.** FIPS requires NIST laboratory certification of the specific binary. PyHSM uses FIPS-approved algorithms but is not certified.

2. **No hardware tamper evidence.** Physical access to the machine is not defended against.

3. **V8/CPython string immutability.** Metadata (key IDs, timestamps, JSON structure) is stored as immutable strings and cannot be deterministically zeroized. Only key material bytes are zeroized.

4. **Single-file keystore is a single point of failure.** If the keystore file is lost and no backup exists, all keys are lost. Mitigate with regular encrypted backups.

5. **Side-channel resistance is limited.** Constant-time comparisons are used for HMAC verification, and Shamir reconstruction uses constant-time GF(256) arithmetic. However, the underlying AES and EC operations depend on the `cryptography` library's side-channel properties.

6. **No distributed consensus.** There is no multi-node replication or quorum-based access control. PyHSM is a single-instance system.

7. **Rate limiter is in-process and non-persistent.** The per-key rate limiter does not survive process restarts and does not coordinate across multiple PyHSM instances. A restart resets all rate-limit windows. Mitigation: enforce rate limits at the infrastructure layer (API gateway, reverse proxy) in addition to PyHSM's internal limits.

8. **Audit log rotation seal does not protect against truncation of the active file.** The `rotationSeal`/`rotationOpen` mechanism detects deletion of entire rotated files. Truncation of the *active* (not yet rotated) log file is detectable only by the HMAC chain within that file — a truncation at a clean HMAC boundary could evade detection. Mitigation: use `auditd` or file-integrity monitoring to detect any write to audit log files from processes other than the PyHSM server.

---

## Comparison to Hardware HSM Threat Coverage

| Threat | Hardware HSM | PyHSM |
|---|---|---|
| Filesystem theft | Protected (keys never on disk in plaintext) | Protected (double-encrypted at rest) |
| Application compromise | Protected (separate hardware) | Protected (process isolation mode) |
| Unauthenticated IPC access | Protected (hardware bus, no socket) | Protected (HMAC mutual auth required, v2.2.0) |
| IPC DoS via slow operation | Not applicable | Protected (per-key locking, connection timeout, v2.2.0) |
| Root attacker with debugger | Protected (tamper-evident hardware boundary) | **NOT protected** (software boundary only) |
| Physical theft of device | Protected (tamper-responsive, key destruction) | **NOT protected** (no hardware tamper response) |
| Side-channel attacks | Protected (certified countermeasures) | **Partially** (constant-time HMAC + Shamir GF arithmetic, but depends on library for AES/EC) |
| Supply chain (firmware) | Risk exists (vendor trust) | Risk exists (dependency trust, mitigated by pinning) |
| Forged Shamir shares | N/A (hardware ceremony) | Protected (per-share HMAC-SHA256, 256-bit, index-bound, v2.2.0) |
| Deleted audit log files | Protected (hardware audit journal) | Protected (rotation seals detect file deletion, v2.2.0) |
| KAT regression in crypto library | Protected (certified module) | Protected (10 primitive KATs at startup, v2.2.0) |

PyHSM is appropriate for environments where software key management is acceptable.
For environments mandating certified hardware, use a FIPS 140-2/3 Level 3+ device.
