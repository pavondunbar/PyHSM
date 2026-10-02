# PyHSM Compliance Framework Coverage

This document states, per compliance framework, which requirements PyHSM
satisfies, which it partially satisfies, and which are out of scope. It is
intended for security auditors, compliance officers, and institutional
procurement teams evaluating PyHSM for regulated deployments.

**Last reviewed:** 2026-10-01  
**PyHSM version:** 2.1.0

---

## Important Disclaimer

PyHSM is a **software** key management system. It uses FIPS-approved
cryptographic algorithms but is **not FIPS 140-2/3 certified**. For
environments where certification of the specific binary is mandatory
(PCI-DSS Level 1 SAQ D, U.S. Federal FedRAMP High, DoD IL4+), a
validated hardware HSM is required. PyHSM is appropriate as a software
KMS for all other environments where software key protection is acceptable.

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
  caller authentication (HMAC-based), rate limiting, and operation policies
  (`allow_encrypt`, `allow_decrypt`, `allow_sign`).
- **CC6.2 — Authentication:** Master password with Argon2id KDF (64 MB
  memory-hard), minimum 12-character enforcement, weak-password blocklist.
  Shamir M-of-N for multi-custodian access control.
- **CC6.6 — Encryption at rest:** AES-256-GCM with per-key AES-KWP
  double-encryption. Master key derived via Argon2id.
- **CC7.2 — System monitoring:** HMAC-chained audit log with tamper
  detection. CEF/LEEF/JSON SIEM export. Prometheus and OTLP metrics.
- **CC9.1 — Change management (dependencies):** Hash-pinned `requirements.lock`
  with SHA-256 verification prevents supply-chain modifications.

### Partially Covered

- **CC6.3 — Removal of access:** Key destruction (`destroy_key`) is
  implemented. Access revocation for a caller ID requires operator action
  to update the key policy and rotate affected keys.
- **CC7.3 — Incident response:** PyHSM detects and logs tamper events.
  The incident response *process* (notification, escalation, remediation)
  must be defined by the deploying organization.

### Out of Scope

- **CC6.8 — Physical security:** PyHSM has no hardware tamper protection.
  Physical access controls are the deploying organization's responsibility.
- **A1.1 — Availability SLA:** PyHSM does not provide HA clustering or
  automatic failover. Deploy behind a process supervisor (systemd,
  Kubernetes) for availability.

---

## 2. PCI-DSS v4.0

### Covered

- **Req 3.5 — Key management procedures:** Key generation, rotation,
  destruction, versioning, and export policies are implemented and audited.
- **Req 3.6 — Cryptographic key storage:** AES-256-GCM with Argon2id KDF.
  Keys never stored in plaintext. Double-wrapped with AES-KWP.
- **Req 3.7 — Key lifecycle:** Key expiry (`expires_at`), archival,
  rotation (`rotate_key`), and operation count limits (`max_operations`).
- **Req 10.2 — Audit log:** Append-only HMAC-chained log covering all
  cryptographic operations, access denials, and session events.
- **Req 10.3 — Audit log protection:** HMAC chain tamper detection.
  SIEM export for centralized log management.
- **Req 6.3 — Patch management:** Dependabot automation and daily
  `pip-audit` / `npm audit` scans in CI/CD.

### Partially Covered

- **Req 3.3 — SAD protection:** PyHSM encrypts key material. Whether SAD
  (Sensitive Authentication Data) flows through PyHSM-encrypted fields
  depends on the application's data model.
- **Req 8.2 — Account management:** Per-key `allowed_callers` ACL provides
  service-level access control. User-level access management (individual
  human accounts, MFA) is the application layer's responsibility.

### Does Not Meet

- **Req 12.3.3 — FIPS-validated cryptography (for Level 1 SAQ D):**
  PyHSM uses FIPS-approved algorithms but the implementation is not FIPS
  140-2/3 validated. Level 1 merchants using PyHSM must accept this gap
  or use a hardware HSM.
- **Req 9 — Physical security:** Not applicable to a software library.

---

## 3. HIPAA Security Rule

### Covered

- **§164.312(a)(2)(iv) — Encryption and decryption:** AES-256-GCM
  encryption with audited key usage.
- **§164.312(e)(2)(ii) — Encryption of ePHI in transit:** If used to
  encrypt ePHI before storage or transmission, PyHSM satisfies this
  control. The application must use the encrypted output correctly.
- **§164.312(b) — Audit controls:** HMAC-chained audit log recording all
  cryptographic operations. SIEM-exportable in CEF/LEEF/JSON.
- **§164.308(a)(1)(ii)(D) — Information system activity review:**
  Prometheus and OTLP metrics for operational monitoring.

### Partially Covered

- **§164.308(a)(3) — Workforce access management:** PyHSM's `allowed_callers`
  restricts service-level access. Workforce (human) access management is
  outside PyHSM's scope.
- **§164.308(a)(5) — Security awareness:** Not applicable to a library.

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

---

## 5. NIST SP 800-63B (Authentication)

- **Memorized Secret requirements:** PyHSM enforces minimum 12-character
  passwords (§5.1.1), rejects a blocklist of known-weak passwords (§5.1.1.2),
  and uses Argon2id for verifier storage (§5.1.1.2 — memory-hard KDF).
- **Look-up Secrets (Shamir shares):** The Shamir M-of-N implementation
  provides multi-factor authentication at the key-ceremony level (§5.1.2).

---

## 6. ISO/IEC 27001:2022

### Covered Controls

| Control | Coverage |
|---|---|
| A.8.24 — Use of cryptography | AES-256-GCM, RSA-PSS, ECDSA, Ed25519, Argon2id |
| A.8.10 — Information deletion | `destroy_key()` zeroizes material |
| A.8.15 — Logging | HMAC-chained append-only audit log |
| A.8.16 — Monitoring | Prometheus/OTLP metrics, SIEM export |
| A.5.33 — Protection of records | Audit log tamper detection |
| A.8.20 — Network security | IPC Unix socket isolation, 0o600 permissions |

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
  per-key AES-KWP, Argon2id KDF.
- **Availability and resilience:** Backup and restore procedures documented
  in `HARDENING.md`.
- **Regular testing:** `run_self_tests()` on every startup. CI/CD
  automated test suite with 80%+ coverage.

**Organizational measures** (Data Protection Officer, breach notification
procedures, data processing agreements) are outside PyHSM's scope and
must be implemented by the data controller.

---

## Requesting Evidence for Audits

When an auditor requests evidence of PyHSM's security controls, provide:

1. **`THREAT_MODEL.md`** — security boundary documentation
2. **`SECURITY_POLICY.md`** — formal security policy
3. **`COMPLIANCE.md`** — this document
4. **Audit log export** — `vectorguard-pyhsm audit --verify && audit --raw`
5. **Dependency scan results** — `pip-audit` output from the latest CI run
6. **Test coverage report** — from the latest CI run (≥80% line coverage)
7. **`requirements.lock`** — hash-pinned dependency manifest
