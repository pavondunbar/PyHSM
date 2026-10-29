# PyHSM Compliance Framework Coverage

This document states, per compliance framework, which requirements PyHSM
satisfies, which it partially satisfies, and which are out of scope. It is
intended for security auditors, compliance officers, and institutional
procurement teams evaluating PyHSM for regulated deployments.

**Last reviewed:** 2026-10-29  
**PyHSM version:** 2.3.0

---

## Important Disclaimer

PyHSM is a **software** key management system. It uses FIPS-approved
cryptographic algorithms but is **not FIPS 140-2/3 certified**. For
environments where certification of the specific binary is mandatory
(PCI-DSS Level 1 SAQ D, U.S. Federal FedRAMP High, DoD IL4+), a
validated hardware HSM is required. PyHSM is appropriate as a software
KMS for all other environments where software key protection is acceptable.

---

## v2.3.0 Licensing and Notice Changes

The following changes were made in v2.3.0. Auditors reviewing evidence of
license compliance controls should note these additions.

| Change | Compliance Impact |
|---|---|
| Runtime license notice emitted at every `PyHSM()` instantiation | Establishes constructive notice of AGPL-3.0 obligations; supports CC6.1 (access controls communicated), A.8.9 (configuration management), legal defensibility |
| CLI banner printed to stderr on every subcommand invocation | Same as above; applies to CLI-based deployments |
| Offline JWT license token verification (`hsm/license.py`) | Enables contractual tier-limit enforcement (max keys per instance); `license_verified` event audited; supports SOC 2 CC6.2 (authentication of commercial licensees) |
| `LicenseError` raised at startup on invalid/expired tokens | Prevents inadvertent operation under a lapsed commercial license; supports CC6.3 (timely access revocation) |
| `license_verified` and `agpl_mode` events added to audit log | Extends audit trail to include license state at session open; supports CC7.2, Req 10.2, §164.312(b) |
| Per-tier key limit enforced in `generate_key()` | Startup tier (max 5 keys) enforced at runtime; supports CC6.1 resource-level access control |

---

## v2.2.5 Security Hardening Summary

The following security improvements were made in v2.2.5 and are reflected
throughout this document. Auditors reviewing a prior version should note
these changes when comparing coverage assessments.

| Change | Compliance Impact |
|---|---|
| IPC mutual authentication now mandatory (`--ipc-secret` required) | Strengthens CC6.1, Req 8.2, A.8.20, §164.312(a)(1) |
| IPC global lock replaced with per-key locking + connection timeout | Strengthens A1.1 (availability), §164.308(a)(7) |
| Shamir shares: 4-byte checksum replaced with per-share HMAC-SHA256 | Strengthens CC6.2, Req 3.6, A.8.24 |
| Startup KATs expanded from 4 to 10 primitives | Strengthens FIPS 140-2 Level 1 evidence, NIST SP 800-57 |
| Audit log chain now spans rotation boundaries (`rotationSeal`/`rotationOpen` + `verify_across_rotations()`) | Strengthens CC7.2, Req 10.3, §164.312(b), A.5.33 |

---

## Framework Coverage Table

| Framework | Coverage | Notes |
|---|---|---|
| SOC 2 Type II | **Partial** | See Section 1 |
| PCI-DSS v4.0 | **Partial** | See Section 2 |
| HIPAA Security Rule | **Partial** | See Section 3 |
| NIST SP 800-57 | **Meets** | See Section 4 |
| NIST SP 800-63B | **Meets** | See Section 5 |
| ISO/IEC 27001:2022 | **Partial** | See Section 6 |
| FIPS 140-2/3 | **Does not meet** | See Section 7 |
| GDPR Article 32 | **Meets (technical)** | See Section 8 |

---

## 1. SOC 2 Type II

### Covered

- **CC6.1 — Logical access controls:** Per-key ACLs (`allowed_callers`),
  caller authentication (HMAC-based, **required** in IPC mode since v2.2.5),
  rate limiting, and operation policies (`allow_encrypt`, `allow_decrypt`,
  `allow_sign`). IPC mutual authentication is now mandatory — any client
  connecting to the HSM process must present a valid HMAC-SHA256 token on
  every request; unauthenticated connections are rejected before any
  operation is processed.
- **CC6.2 — Authentication:** Master password with Argon2id KDF (64 MB
  memory-hard), minimum 12-character enforcement, weak-password blocklist.
  Shamir M-of-N for multi-custodian access control, now with per-share
  HMAC-SHA256 integrity (256-bit forgery resistance, index-bound tags)
  replacing the previous 4-byte truncated checksum.
- **CC6.6 — Encryption at rest:** AES-256-GCM with per-key AES-KWP
  double-encryption. Master key derived via Argon2id.
- **CC7.2 — System monitoring:** HMAC-chained audit log with tamper
  detection now spanning rotation boundaries (`rotationSeal`/`rotationOpen`
  entries). `verify_across_rotations()` allows auditors to cryptographically
  verify the complete chain across all retained log files, detecting
  deletion of any rotated file. CEF/LEEF/JSON SIEM export. Prometheus and
  OTLP metrics.
- **CC9.1 — Change management (dependencies):** Hash-pinned `requirements.lock`
  with SHA-256 verification prevents supply-chain modifications.

### Partially Covered

- **CC6.3 — Removal of access:** Key destruction (`destroy_key`) is
  implemented. Access revocation for a caller ID requires operator action
  to update the key policy and rotate affected keys.
- **CC7.3 — Incident response:** PyHSM detects and logs tamper events,
  including cross-file audit chain breaks. The incident response *process*
  (notification, escalation, remediation) must be defined by the deploying
  organization.

### Out of Scope

- **CC6.8 — Physical security:** PyHSM has no hardware tamper protection.
  Physical access controls are the deploying organization's responsibility.
- **A1.1 — Availability SLA:** PyHSM does not provide HA clustering or
  automatic failover. The v2.2.5 IPC server improvements (per-key locking,
  connection timeout) significantly reduce availability risk from slow
  operations or stalled clients, but single-instance deployment remains.
  Deploy behind a process supervisor (systemd, Kubernetes) for availability.

---

## 2. PCI-DSS v4.0

### Covered

- **Req 3.5 — Key management procedures:** Key generation, rotation,
  destruction, versioning, and export policies are implemented and audited.
- **Req 3.6 — Cryptographic key storage:** AES-256-GCM with Argon2id KDF.
  Keys never stored in plaintext. Double-wrapped with AES-KWP. Shamir
  share integrity now enforced with HMAC-SHA256 (per-share, index-bound),
  providing cryptographic assurance that reconstructed master passwords
  have not been tampered with.
- **Req 3.7 — Key lifecycle:** Key expiry (`expires_at`), archival,
  rotation (`rotate_key`), and operation count limits (`max_operations`).
- **Req 10.2 — Audit log:** Append-only HMAC-chained log covering all
  cryptographic operations, access denials, and session events.
- **Req 10.3 — Audit log protection:** HMAC chain tamper detection now
  spanning rotation boundaries. Deletion of any rotated audit log file is
  detectable via `verify_across_rotations()`. SIEM export for centralized
  log management.
- **Req 10.5 — Audit log integrity:** The `rotationSeal`/`rotationOpen`
  mechanism (v2.2.5) provides cryptographic evidence that no rotated log
  file has been removed or altered between the time of rotation and the
  time of audit review.
- **Req 6.3 — Patch management:** Dependabot automation and daily
  `pip-audit` / `npm audit` scans in CI/CD.
- **Req 8.2 — Account management (service-level):** IPC mutual
  authentication is now mandatory. Service-to-HSM access requires a
  configured shared HMAC secret. This tightens service-level access
  control beyond UID-based socket permissions alone.

### Partially Covered

- **Req 3.3 — SAD protection:** PyHSM encrypts key material. Whether SAD
  (Sensitive Authentication Data) flows through PyHSM-encrypted fields
  depends on the application's data model.
- **Req 8.2 — Account management (human-level):** Per-key `allowed_callers`
  ACL provides service-level access control. User-level access management
  (individual human accounts, MFA) is the application layer's
  responsibility.

### Does Not Meet

- **Req 12.3.3 — FIPS-validated cryptography (for Level 1 SAQ D):**
  PyHSM uses FIPS-approved algorithms but the implementation is not FIPS
  140-2/3 validated. Level 1 merchants using PyHSM must accept this gap
  or use a hardware HSM.
- **Req 9 — Physical security:** Not applicable to a software library.

---

## 3. HIPAA Security Rule

### Covered

- **§164.312(a)(1) — Access control:** IPC mutual authentication is now
  mandatory (v2.2.5). Any process connecting to the HSM over the Unix
  socket must present a valid HMAC-SHA256 credential. Unauthenticated
  access is rejected before any ePHI-related key operation is performed.
- **§164.312(a)(2)(iv) — Encryption and decryption:** AES-256-GCM
  encryption with audited key usage.
- **§164.312(e)(2)(ii) — Encryption of ePHI in transit:** If used to
  encrypt ePHI before storage or transmission, PyHSM satisfies this
  control. The application must use the encrypted output correctly.
- **§164.312(b) — Audit controls:** HMAC-chained audit log recording all
  cryptographic operations, now with cross-rotation chain verification.
  Deletion of rotated log files is detectable. SIEM-exportable in
  CEF/LEEF/JSON. Rotation-seal entries provide evidence of log continuity
  across file boundaries, supporting the "complete and accurate" audit
  trail requirement.
- **§164.308(a)(1)(ii)(D) — Information system activity review:**
  Prometheus and OTLP metrics for operational monitoring.

### Partially Covered

- **§164.308(a)(3) — Workforce access management:** PyHSM's `allowed_callers`
  restricts service-level access. Workforce (human) access management is
  outside PyHSM's scope.
- **§164.308(a)(5) — Security awareness:** Not applicable to a library.
- **§164.308(a)(7) — Contingency plan:** The IPC server's per-key locking
  and connection timeout (v2.2.5) reduce the risk of availability
  disruption from slow operations. Full HA/DR planning is the covered
  entity's responsibility.

### Out of Scope

- **§164.310 — Physical safeguards:** Hardware-level controls are the
  covered entity's responsibility.

---

## 4. NIST SP 800-57 (Key Management)

PyHSM **fully implements** the NIST SP 800-57 key lifecycle model:

| Lifecycle Phase | PyHSM Implementation |
|---|---|
| Pre-activation | Key generated, not yet used |
| Active | `current_version`, policies enforced |
| Suspended (archived) | `archived: true`, decrypt-only |
| Deactivated | `expires_at` enforced |
| Destroyed | `destroy_key()` — material overwritten |
| Compromised | `destroy_key()` with audit event |

**Algorithm compliance (NIST SP 800-131A Rev. 2):**

| Algorithm | Usage | Status |
|---|---|---|
| AES-256-GCM | Symmetric encryption | Approved |
| AES-128 | Symmetric encryption | Approved |
| RSA-2048 (PSS) | Digital signatures | Approved through 2030 |
| RSA-4096 (PSS) | Digital signatures | Approved |
| ECDSA P-256/P-384/P-521 | Digital signatures | Approved |
| Ed25519 | Digital signatures | Acceptable |
| SHA-256/384/512 | Hashing | Approved |
| Argon2id | Password KDF | NIST SP 800-132 compliant |
| HKDF-SHA256 | Key derivation | Approved |
| AES-KWP (RFC 5649) | Key wrapping | Approved |

**Known-Answer Test (KAT) coverage (v2.2.5):**

As of v2.2.5, startup KATs cover all 10 cryptographic primitives in
active use, verified against published NIST and RFC test vectors before
any key operation is accepted:

| Primitive | Test Vector Source |
|---|---|
| AES-256-GCM | NIST SP 800-38D Appendix B, Test Case 14 |
| PBKDF2-SHA256 | RFC 6070 |
| HMAC-SHA256 | RFC 4231 Test Case 1 |
| CSPRNG | Non-degenerate output sanity check |
| Argon2id | Pinned vector at production parameters (t=3, m=64MB, p=4) |
| HKDF-SHA256 | RFC 5869 Appendix A, Test Case 1 |
| AES-256-KWP | NIST SP 800-38F / RFC 5649 |
| ECDSA P-256 | Sign + verify + tamper-detection round-trip |
| RSA-2048-PSS | Sign + verify + tamper-detection round-trip |
| Ed25519 | Pinned seed → public key + signature vectors |

This KAT coverage strengthens NIST SP 800-57 Part 1 Rev. 5 §8.1
(cryptographic algorithm validation) and provides evidence for FIPS
140-2 Level 1 self-test requirements (even though PyHSM is not FIPS
certified).

---

## 5. NIST SP 800-63B (Authentication)

- **Memorized Secret requirements:** PyHSM enforces minimum 12-character
  passwords (§5.1.1), rejects a blocklist of known-weak passwords (§5.1.1.2),
  and uses Argon2id for verifier storage (§5.1.1.2 — memory-hard KDF).
- **Look-up Secrets (Shamir shares):** The Shamir M-of-N implementation
  provides multi-factor authentication at the key-ceremony level (§5.1.2).
  As of v2.2.5, each share carries a per-share HMAC-SHA256 integrity tag
  (keyed on a random salt, bound to the share index) and a reconstruction
  HMAC covering the full secret. This prevents a corrupted or adversarially
  crafted share from being accepted during reconstruction.

---

## 6. ISO/IEC 27001:2022

### Covered Controls

| Control | Coverage |
|---|---|
| A.8.24 — Use of cryptography | AES-256-GCM, RSA-PSS, ECDSA, Ed25519, Argon2id, HKDF, AES-KWP — all verified at startup via KATs against published vectors (v2.2.5) |
| A.8.10 — Information deletion | `destroy_key()` zeroizes material |
| A.8.15 — Logging | HMAC-chained append-only audit log with cross-rotation chain integrity (v2.2.5) |
| A.8.16 — Monitoring | Prometheus/OTLP metrics, SIEM export, `verify_across_rotations()` for continuous audit integrity monitoring |
| A.5.33 — Protection of records | Audit log tamper detection within files and across rotation boundaries; deletion of rotated files is cryptographically detectable |
| A.8.20 — Network security | IPC Unix socket isolation (0o600), mandatory HMAC mutual authentication on every request (v2.2.5) |

### Partially Covered

- **A.8.7 — Protection against malware:** Dependency hash-pinning and
  automated CVE scanning reduce supply-chain risk. Runtime malware
  detection is the deploying organization's responsibility.
- **A.8.9 — Configuration management:** PyHSM documents its configuration
  parameters. Configuration management *process* is the organization's
  responsibility.

---

## 7. FIPS 140-2/3

**PyHSM does not meet FIPS 140-2/3.**

PyHSM uses FIPS-approved algorithms implemented in the `cryptography`
Python library (which uses OpenSSL). However:

- The `cryptography` library binary is not FIPS 140-2/3 validated.
- PyHSM itself is not validated by NIST's Cryptographic Module Validation
  Program (CMVP).
- Argon2id is not a FIPS-approved KDF (FIPS requires PBKDF2, bcrypt is
  not approved, scrypt is Level 1 only).

**v2.2.5 improvement:** The expanded KAT suite (10 primitives, up from 4)
provides stronger evidence for FIPS 140-2 Level 1 self-test requirements
than prior versions. While this does not constitute certification, it
demonstrates that all cryptographic modules are exercised against published
test vectors on every startup — a key element auditors look for when
assessing software KMS controls in the absence of formal certification.

**For environments requiring FIPS 140-2 Level 2+ or Level 3:**

Use a hardware HSM (Thales Luna, Entrust nShield, AWS CloudHSM,
Azure Dedicated HSM) for all key operations. PyHSM can coexist with a
hardware HSM as a software cache layer for non-FIPS operations.

---

## 8. GDPR Article 32

GDPR Article 32 requires "appropriate technical measures" for protecting
personal data. PyHSM satisfies the **technical** requirements:

- **Pseudonymisation and encryption:** AES-256-GCM encryption of personal
  data fields using PyHSM-managed keys.
- **Confidentiality and integrity:** Encrypt-then-MAC construction,
  per-key AES-KWP, Argon2id KDF. IPC mutual authentication (mandatory
  since v2.2.5) ensures only authorized services can request encryption
  or decryption operations on personal data keys.
- **Availability and resilience:** Backup and restore procedures documented
  in `HARDENING.md`. IPC per-key locking (v2.2.5) eliminates the
  availability risk of a single slow operation blocking all clients.
- **Regular testing:** `run_self_tests()` on every startup now covers
  all 10 active primitives. CI/CD automated test suite with 76%+ coverage.
- **Ongoing confidentiality assurance:** The audit log's cross-rotation
  chain verification (`verify_across_rotations()`) provides evidence that
  the complete record of personal data access operations has not been
  tampered with or selectively deleted — directly supporting GDPR's
  accountability principle (Article 5(2)).

**Organizational measures** (Data Protection Officer, breach notification
procedures, data processing agreements) are outside PyHSM's scope and
must be implemented by the data controller.

---

## Requesting Evidence for Audits

When an auditor requests evidence of PyHSM's security controls, provide:

1. **`THREAT_MODEL.md`** — security boundary documentation
2. **`SECURITY_POLICY.md`** — formal security policy (v2.3.0)
3. **`COMPLIANCE.md`** — this document
4. **`COMMERCIAL_LICENSE.md`** — license enforcement architecture and tier details
5. **Audit log export** — `vectorguard-pyhsm audit --verify && audit --raw`
6. **License audit events** — filter for `license_verified` and `agpl_mode` events: `vectorguard-pyhsm audit --operation license_verified`
7. **Cross-rotation audit chain verification** — output of `verify_across_rotations()` showing `ok: true` across all retained log files
8. **Dependency scan results** — `pip-audit` output from the latest CI run
9. **Test coverage report** — from the latest CI run (76%+ line coverage)
10. **`requirements.lock`** — hash-pinned dependency manifest
11. **KAT results** — logged at startup as `selfTestPass` in the audit log; confirm all 10 primitives passed
