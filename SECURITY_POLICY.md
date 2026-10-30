# PyHSM Security Policy

**Version:** 2.3.0  
**Effective Date:** 2026-10-29  
**Owner:** PyHSM Project Maintainers  

This document is the formal security policy for the PyHSM software key
management system. It defines the security objectives, cryptographic
standards, operational requirements, and incident response commitments
that govern the project. Deploying organizations may incorporate this
document into their own security documentation packages.

---

## 1. Security Objectives

PyHSM is designed to achieve the following security objectives, in
priority order:

1. **Key material confidentiality.** Private and symmetric key material
   must never be exposed outside the PyHSM process in plaintext form,
   except through explicitly authorized export operations.

2. **Key material integrity.** Stored key material must be protected
   against unauthorized modification. Any tampering must be detectable
   and must cause PyHSM to refuse to operate.

3. **Audit non-repudiation.** Every cryptographic operation must produce
   an unforgeable, tamper-evident audit record that can be used to
   reconstruct who did what and when.

4. **Availability under policy.** Legitimate authorized operations must
   succeed within documented policy constraints (rate limits, expiry,
   operation counts). Denial-of-service must not be achievable by
   unauthorized callers without consuming their own rate-limit budget.

---

## 2. Cryptographic Standards

### 2.1 Approved Algorithms

All cryptographic operations in PyHSM use the following approved algorithms.
No custom or novel cryptographic primitives are used.

| Purpose | Algorithm | Parameters | Standard |
|---|---|---|---|
| Symmetric encryption | AES-256-GCM | 96-bit nonce, 128-bit tag | NIST SP 800-38D |
| Symmetric encryption (TS) | AES-256-GCM-SIV | Nonce-misuse resistant | RFC 8452 |
| Key wrapping | AES-KWP | RFC 5649 alternative IV | RFC 5649 |
| RSA signatures | RSA-PSS | SHA-256, MAX salt | PKCS#1 v2.2 |
| EC signatures | ECDSA | P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 | FIPS 186-5 |
| EdDSA signatures | Ed25519 | — | RFC 8032 |
| Password KDF | Argon2id | 64 MB, t=3, p=4, 32-byte output | RFC 9106 |
| Password KDF (fallback) | PBKDF2-SHA256 | 480,000 iterations | NIST SP 800-132 |
| Key derivation | HKDF-SHA256 | RFC 5869 extract+expand | RFC 5869 |
| MAC | HMAC-SHA256 | — | FIPS 198-1 |
| Audit HMAC key derivation | Argon2id → HKDF-SHA256 | Per-instance salt | — |

### 2.2 Minimum Key Sizes

| Key Type | Minimum Size | Recommended |
|---|---|---|
| AES | 128 bits | 256 bits |
| RSA | 2048 bits (enforced at import) | 4096 bits |
| EC | P-256 | P-384 or P-521 |
| Master password | 12 characters | 20+ characters, passphrase |

RSA keys below 2048 bits are rejected at import (`import_key_jwk`) with a clear
error citing NIST SP 800-131A Rev. 2. Only 2048 and 4096 bits are accepted.

### 2.3 Algorithm Deprecation

When NIST or IETF deprecates an algorithm used by PyHSM, the project
will publish a migration guide and provide a replacement within the
timeframes in Section 6.

---

## 3. Key Management Policy

### 3.1 Key Generation

- All key material is generated using the operating system's
  cryptographically secure random number generator (`os.urandom()` /
  `crypto.randomBytes()`).
- Keys are wrapped with AES-KWP (RFC 5649) immediately after generation
  and never stored in plaintext.
- Every key generation is recorded in the audit log.

### 3.2 Key Storage

- The keystore is encrypted with AES-256-GCM using a key derived via
  Argon2id from the master password and a random 16-byte salt.
- An HMAC-SHA256 tamper seal covers the entire ciphertext
  (encrypt-then-MAC). Keystore files with invalid HMACs are rejected.
- Individual keys are double-encrypted with AES-KWP using a KEK derived
  from the master password via Argon2id → HKDF.
- Keystore files are written atomically (temp file + rename) to prevent
  corruption from crashes mid-write.

### 3.3 Key Rotation

- AES keys should be rotated at least annually, or after any suspected
  compromise.
- The `rotate_every_days` policy field automates rotation.
- After rotation, the previous version is archived (decrypt-only) and
  remains accessible for decryption of existing ciphertext.

### 3.4 Key Destruction

- `destroy_key()` overwrites all key material with zeros before removal.
- Destruction is logged in the audit trail and is irreversible.
- Operators should verify destruction via the audit log.

### 3.5 Key Export

- Key export is **disabled by default**. A key must have `allow_export: true`
  in its policy to permit JWK export.
- All export operations are logged.
- Exported keys should be treated with the same security controls as the
  keystore itself.

### 3.6 Master Password

- The master password must be at least 12 characters (enforced).
- Known-weak passwords are blocked at initialization.
- The password must be injected via a password file (`--password-file`)
  or Shamir reconstruction in production. Environment variable injection
  requires explicit opt-in (`PYHSM_ALLOW_ENV_PASSWORD=1`) and is
  unsuitable for production.
- The master password is stored in a mutable `bytearray` and zeroized
  when the session closes.

### 3.7 Commercial License Token

- Commercial license tokens are RS256-signed JWTs issued by VectorGuard Labs.
- Tokens are verified locally against an embedded RSA-2048 public key.
  No network call is made. Tokens are safe to use in air-gapped environments.
- A `LicenseError` is raised immediately at `PyHSM()` construction if the
  token is malformed, has an invalid signature, uses a non-RS256 algorithm,
  has an unexpected issuer, is expired, or is missing required claims.
- The license state (`license_verified` for commercial, `agpl_mode` for
  open source) is recorded in the HMAC-chained audit log at every
  session open.
- Tokens should be stored in a `0o600`-permission file and injected via
  `--license-file` or the `license_file=` constructor parameter.
  Injection via `PYHSM_LICENSE_TOKEN` environment variable is acceptable
  in automated deployments managed by a secrets manager.
- Per-tier key limits are enforced at `generate_key()` time. A `LicenseError`
  is raised if the limit would be exceeded; the operation is not performed
  and no rate-limit token is consumed.
- Token renewal is the commercial licensee's responsibility. Renew before
  the token's `exp` claim by contacting pavon@vectorguardlabs.com.

---

## 4. Access Control Policy

### 4.1 Per-Key ACLs

Each key can specify an `allowed_callers` list. Operations from callers
not on this list are rejected and logged before any cryptographic work
is performed.

### 4.2 Caller Authentication

When using IPC mode, callers are authenticated via HMAC-SHA256 of the
request ID and operation name using a shared secret. **This authentication
is required** — the IPC server refuses to start without a configured
`--ipc-secret` (or `PYHSM_IPC_SECRET` environment variable). Unauthenticated
requests are rejected without processing.

### 4.3 Rate Limiting

Rate limiting is enforced per-key with a configurable sliding window.
The rate limiter runs **after** ACL and policy checks to prevent
unauthorized callers from exhausting rate-limit budget for legitimate
callers. As of v2.3.1, the rate limiter is **thread-safe**: `allow()`,
`usage()`, and `reset()` are all protected by a `threading.Lock` to
prevent the check-then-act race that could previously allow up to
2× `max_ops` through under concurrent load.

### 4.4 Operation Policies

Each key supports:
- `allow_encrypt` / `allow_decrypt` / `allow_sign` — per-operation gates
- `max_operations` — hard lifetime operation cap
- `expires_at` — automatic expiry timestamp
- `rotate_every_days` — automatic rotation policy

---

## 5. Audit Policy

### 5.1 What Is Logged

Every operation — successful or failed — produces an audit entry:
- Timestamp (UTC ISO-8601)
- Operation type
- Key ID (if applicable)
- Caller ID (if provided)
- Success/failure
- Failure reason (if applicable)
- Sequence number
- HMAC linking to previous entry

### 5.2 Tamper Evidence

Each entry is HMAC-SHA256 linked to the previous entry. Deletion or
modification of any entry breaks the chain, detectable via
`audit --verify`. The HMAC key is derived from the master password via
Argon2id → HKDF so an attacker cannot forge entries without the password.
All HMAC comparisons in `verify()` and `verify_across_rotations()` use
`hmac.compare_digest()` to prevent timing-oracle attacks (enforced since
v2.3.1).

As of v2.2.0, tamper evidence extends across rotation boundaries. When
the log file is rotated, a `rotationSeal` entry is appended containing
the chain's final HMAC, and the new file begins with a `rotationOpen`
entry recording the seal. The `verify_across_rotations()` method
verifies the full chain across all retained rotated files. Deletion
of a rotated file is detectable because the next file's `rotationOpen`
entry will not match any seal entry the verifier can find.

### 5.3 SIEM Integration

The audit log is exportable in:
- CEF (ArcSight Common Event Format) — for Splunk, QRadar, ArcSight
- LEEF (Log Event Enhanced Format) — for IBM QRadar
- JSON — for Elastic/OpenSearch, Datadog, custom pipelines

### 5.4 Log Retention

Deploying organizations must retain audit logs for a period consistent
with their compliance obligations. Minimum recommended retention:
- General: 1 year
- PCI-DSS: 1 year (Req 10.7)
- HIPAA: 6 years (§164.530(j))
- SOC 2: Duration of audit period + 1 year

---

## 6. Vulnerability Response and Patch Commitments

### 6.1 Severity Definitions

| Severity | Definition | Response SLA |
|---|---|---|
| Critical | Remote key extraction, authentication bypass, keystore decryption without password | **72 hours** |
| High | Local privilege escalation to read key material, audit log forgery, KDF downgrade | **7 days** |
| Medium | Information disclosure (non-key), denial of service, policy bypass | **30 days** |
| Low | Hardening gaps, informational findings | **90 days** |

### 6.2 Reporting Security Vulnerabilities

Report security vulnerabilities privately to the maintainers via the
GitHub Security Advisories feature:
`https://github.com/pavondunbar/PyHSM/security/advisories/new`

Do **not** open a public GitHub issue for security vulnerabilities.

Include in your report:
- Affected version(s)
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if known)

### 6.3 Dependency Vulnerabilities

Dependency vulnerabilities (in `cryptography`, `argon2-cffi`, etc.) are
monitored via:
- Dependabot automatic PRs on version updates
- Daily `pip-audit` and `npm audit` runs in CI
- GitHub Actions Security Audit workflow on every dependency change

Critical dependency CVEs will receive a patched release within 72 hours
of public disclosure.

---

## 7. Out-of-Scope Threats

The following threats are **explicitly outside PyHSM's security boundary**:

1. **Root / kernel-level attacker with ptrace access.** A root attacker
   can attach a debugger to the PyHSM process during a signing operation
   and extract key material from memory. This is mitigated only by
   hardware HSMs with tamper-responsive key destruction. PyHSM's
   deterministic zeroization reduces the exposure window but cannot
   eliminate it.

2. **Physical theft of the host machine.** Without encrypted storage and
   full-disk encryption, a stolen disk may expose the keystore to offline
   attack. PyHSM's Argon2id KDF raises the brute-force cost but encrypted
   storage provides defense-in-depth.

3. **Hypervisor / host compromise in virtual environments.** A compromised
   hypervisor can read guest VM memory. This requires hardware-level
   protections (AMD SEV, Intel TDX) beyond PyHSM's scope.

4. **Master password compromise.** If the master password is obtained,
   all keys in the keystore are at risk. Mitigate with Shamir M-of-N and
   strict password file controls (see `HARDENING.md`).

5. **Side-channel attacks from co-tenant processes.** Constant-time HMAC
   comparison is used throughout. Shamir secret reconstruction uses
   constant-time GF(256) arithmetic. However, the underlying AES and EC
   operations depend on the `cryptography` library's side-channel
   properties. For the highest side-channel assurance, use a hardware HSM.

---

## 8. Security Testing

PyHSM maintains the following security testing baseline:

- **Unit tests:** ≥ 73% line and branch coverage (Python layer; 142 tests as of v2.3.1)
- **Known-Answer Tests (KATs):** Run on every `PyHSM` instantiation via
  `run_self_tests()`. Fail-fast on any mismatch. As of v2.2.0, covers all
  10 primitives in active use: AES-256-GCM, PBKDF2-SHA256, HMAC-SHA256,
  CSPRNG, Argon2id, HKDF-SHA256, AES-256-KWP, ECDSA P-256, RSA-2048-PSS,
  and Ed25519. As of v2.3.1, the RSA-PSS KAT uses a fixed embedded private
  key with a pinned public-key fingerprint, and adds wrong-key and
  tamper-detection checks. The Ed25519 KAT adds a wrong-key rejection check.
- **Dependency audit:** `pip-audit` and `npm audit` on every CI run
- **Static type checking:** mypy strict mode on every CI run
- **Linting:** ESLint (TypeScript), enforced in CI
- **Fuzz testing:** Recommended for production deployments; not included
  in the base test suite

---

## 9. Change Management

- All changes to cryptographic code (`hsm/storage.py`, `hsm/core.py`,
  `hsm/shamir.py`, `hsm/self_test.py`, `pyhsm-ts/core.ts`) require review
  by at least one maintainer with cryptographic expertise before merge.
- Changes to authentication, IPC, or audit code require the same.
- The `requirements.lock` file must be updated with new hashes whenever
  production dependencies change.
- This security policy is reviewed and updated with each major version
  release.

---

## Appendix: v2.3.1 Security Hardening

The following issues were identified in a security audit of v2.3.0 and resolved in v2.3.1:

| # | Issue | Category | Resolution |
|---|---|---|---|
| 1 | `RateLimiter.allow()` check-then-act race under concurrent access | Availability / DoS | `threading.Lock` added; all three public methods (`allow`, `usage`, `reset`) are now atomic read-modify-write |
| 2 | Audit `verify()` used plain `!=` for HMAC string comparison | Timing oracle | Replaced with `hmac.compare_digest()` |
| 3 | `verify_across_rotations()` cross-file stitch used plain `!=` for HMAC | Timing oracle | Replaced with `hmac.compare_digest()` |
| 4 | Legacy Shamir 4-byte checksum path used plain `!=` | Timing oracle | Replaced with `hmac.compare_digest()` |
| 5 | JWK RSA import accepted keys below 2048 bits | Weak key injection | Allowlist `{2048, 4096}` enforced; sub-2048 raises `ValueError` citing NIST SP 800-131A Rev. 2 |
| 6 | Ed25519 KAT docstring cited wrong source | Accuracy | Docstring corrected; wrong-key rejection check added to the test |
| 7 | RSA-PSS KAT was round-trip only (no cross-key confusion test) | KAT quality | Fixed embedded private key (SHA-256 fingerprint pinned); wrong-key and tamper-detection negative checks added |

---

## Appendix: v2.3.0 Licensing and Notice Changes

The following additions were made in v2.3.0:

| # | Addition | Category | Details |
|---|---|---|---|
| 1 | Runtime AGPL license notice at `PyHSM()` instantiation | Notice | `INFO`-level log entry, `event: license_notice`, on every session open |
| 2 | CLI banner to stderr on every subcommand | Notice | Printed before subcommand dispatch; appears in terminal and CI logs |
| 3 | `hsm/license.py` — offline JWT verification | Access control | RS256 / RSA-2048; no network dependency; `LicenseError` on any invalid token attribute |
| 4 | `license_verified` and `agpl_mode` audit events | Audit | License state is part of the tamper-evident audit record |
| 5 | Per-tier key limit enforcement in `generate_key()` | Policy | Startup tier: 5 keys; Growth/Scale: unlimited; enforced before key material generation |
| 6 | `--license-file` CLI flag and `PYHSM_LICENSE_TOKEN` env var | Interface | Consistent with password injection patterns already in the CLI |
| 7 | `get_license_info()` method | API | Returns `LicenseInfo` dataclass; exposes tier, licensee, expiry, limits to operators |
| 8 | `license` CLI subcommand | CLI | Human-readable license status; useful for health checks and deployment verification |

---

## Appendix: v2.2.0 Security Hardening Summary

The following issues were resolved in the v2.2.0 release following an
internal security audit:

| # | Issue | Category | Resolution |
|---|---|---|---|
| 1 | IPC server: global lock DoS | Availability | Per-key locking; read-only ops hold no lock; 30 s connection timeout |
| 2 | IPC server: no mutual auth by default | Authentication | `--ipc-secret` mandatory; server refuses to start without it |
| 3 | Shamir: 4-byte truncated checksum | Integrity | Per-share HMAC-SHA256 (256-bit, index-bound) + reconstruction HMAC |
| 4 | KATs missing 6 primitives | Verification | KATs added for Argon2id, HKDF, AES-KWP, ECDSA P-256, RSA-PSS, Ed25519 |
| 5 | Audit chain not spanning rotations | Audit integrity | `rotationSeal`/`rotationOpen` + `verify_across_rotations()` |
| 6 | SECURITY.md listed v1.x as supported | Documentation | Corrected; v1.x marked EOL |
