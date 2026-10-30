# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | :white_check_mark: |
| 1.x     | :x:                |

Only the latest release on the `main` branch receives security patches.
v1.x is no longer supported. Upgrade to v2.3.0 or later.

---

## Changes in v2.3.0

| Change | Category | Details |
|---|---|---|
| Runtime license notice at every `PyHSM()` instantiation | Notice | Logged at INFO with `event: license_notice`; establishes constructive notice of AGPL-3.0 obligations |
| CLI license banner on every subcommand | Notice | Printed to stderr before each subcommand dispatch |
| Offline JWT license token verification (`hsm/license.py`) | Access control | RS256-signed tokens verified locally; no network call; `LicenseError` on invalid/expired token |
| `license_verified` / `agpl_mode` audit events | Audit | License state recorded in the HMAC-chained audit log at session open |
| Per-tier key limit enforced in `generate_key()` | Policy | Startup tier capped at 5 keys; Growth/Scale unlimited |
| `--license-file` / `PYHSM_LICENSE_TOKEN` | Interface | CLI flag and env var for supplying commercial tokens |
| `get_license_info()` method | API | Returns `LicenseInfo` dataclass with tier, licensee, expiry, and limits |
| `license` CLI subcommand | CLI | Displays active license status in human-readable format |

---

## Security Fixes (v2.3.1)

The following vulnerabilities were identified in a security audit of v2.3.0 and fixed in v2.3.1:

| Issue | Severity | Fix |
|---|---|---|
| `RateLimiter.allow()` had a check-then-act race under concurrent access | High | Added `threading.Lock` to `RateLimiter`; all three public methods (`allow`, `usage`, `reset`) are now atomic |
| Audit log `verify()` and `verify_across_rotations()` used plain `!=` for HMAC comparison | Medium | Replaced all HMAC string comparisons with `hmac.compare_digest()` — prevents timing-oracle attacks |
| Legacy Shamir checksum path used plain `!=` for hash comparison | Medium | Replaced with `hmac.compare_digest()` in the backward-compatible 4-byte checksum path |
| JWK import accepted RSA keys below 2048 bits (e.g. RSA-1024) | Medium | Added allowlist `{2048, 4096}`; keys below 2048 bits raise `ValueError` citing NIST SP 800-131A Rev. 2 |
| Ed25519 KAT used self-generated vectors, not independently published standard values | Low | KAT docstring corrected with accurate sourcing; wrong-key rejection check added |
| RSA-PSS KAT was a round-trip only (no cross-key confusion or fixed-key test) | Low | Replaced with a fixed embedded private key (SHA-256 public key fingerprint pinned); added wrong-key rejection and tamper-detection checks |

---

## Recent Security Fixes (v2.2.0)

The following vulnerabilities were identified in an internal security audit and fixed in v2.2.0:

| Issue | Severity | Fix |
|---|---|---|
| IPC server unauthenticated by default | High | `--ipc-secret` now mandatory; server refuses to start without it |
| IPC server global lock DoS | Medium | Replaced with per-key locking; read-only ops hold no lock; 30 s connection timeout |
| Shamir shares use 4-byte truncated checksum | Medium | Replaced with per-share HMAC-SHA256 (256-bit, index-bound) + reconstruction HMAC |
| KAT coverage missing 6 primitives | Medium | Added KATs for Argon2id, HKDF, AES-KWP, ECDSA P-256, RSA-PSS, Ed25519 |
| Audit log chain did not span rotation boundaries | Low | `rotationSeal`/`rotationOpen` entries + `verify_across_rotations()` |
| Supported versions table incorrect in SECURITY.md | Informational | Updated (v1.x EOL, v2.x supported) |

---

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately via one of:

- **Email:** security@vectorguardlabs.com
- **GitHub Security Advisories:** [Report a vulnerability](https://github.com/pavondunbar/PyHSM/security/advisories/new)

Include the following in your report:

1. Affected component (Python layer, TypeScript layer, or both)
2. Description of the vulnerability and potential impact
3. Steps to reproduce or proof-of-concept (if available)
4. Your assessment of severity (Critical / High / Medium / Low)

You will receive an acknowledgment within **24 hours** of submission.

---

## Patch Commitment

PyHSM maintains the following response targets for confirmed vulnerabilities:

| Severity | Response Time | Patch Target | Disclosure |
|----------|--------------|--------------|------------|
| **Critical** (RCE, key exposure, auth bypass) | 2-hour acknowledgment | 72 hours | Coordinated after patch |
| **High** (data exposure, privilege escalation) | 4-hour acknowledgment | 7 days | Coordinated after patch |
| **Medium** (DoS, information leak) | 24-hour acknowledgment | 30 days | Coordinated after patch |
| **Low** (minor issues, hardening) | 48-hour acknowledgment | Next release | Public |

Enterprise support customers receive **private pre-notification** before public disclosure, giving them time to patch before the fix is published.

---

## Upstream Dependency Monitoring

PyHSM's cryptographic security depends on these upstream libraries:

### Python
- [`cryptography`](https://github.com/pyca/cryptography) — AES-256-GCM, HKDF, RSA, ECDSA, AES-KWP (PBKDF2 retained as fallback only; Argon2id is required for production)
- [`argon2-cffi`](https://github.com/hynek/argon2-cffi) — Argon2id primary key derivation (64 MB memory-hard, OWASP recommended)

### TypeScript
- [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) — AES-256-GCM-SIV
- [`argon2`](https://github.com/ranisalt/node-argon2) — Argon2id key derivation

### How we monitor

- **Dependabot** scans daily for known CVEs in all direct dependencies
- **Automated security audit** (`pip-audit` + `npm audit`) runs daily via GitHub Actions
- **GitHub Security Advisories** are watched for all upstream repositories
- All dependency update PRs trigger the full CI + security audit pipeline before merge

When a CVE is published against any of these libraries:

1. The daily audit workflow fails and notifies maintainers immediately
2. Dependabot opens a PR with the patched version (if available)
3. The maintainer triages severity against PyHSM's specific usage
4. A patched PyHSM release is published within the commitment window above

---

## Scope

The following are **in scope** for security reports:

- Cryptographic weaknesses (key derivation, encryption, signing, HMAC)
- Authentication or access control bypass (caller ACLs, session management)
- Key material exposure (memory leaks, insufficient zeroization, side channels)
- Keystore tamper detection bypass
- Audit log integrity bypass
- Denial of service via crafted input
- License token forgery or bypass (signature verification, claim tampering)

The following are **out of scope**:

- Vulnerabilities requiring physical access to the host machine
- Social engineering attacks
- Issues in development dependencies (devDependencies)
- Theoretical attacks without a practical proof-of-concept
- Issues already documented in the "Honest scope statement" in README.md (e.g., lack of FIPS 140-2 certification, no hardware enclave)

---

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits vulnerability privately
2. We confirm and assess severity within the response time above
3. We develop and test a fix
4. Enterprise support customers receive private pre-notification
5. Fix is released publicly with a security advisory
6. Reporter is credited (unless they prefer anonymity)

We request a **90-day disclosure window** from the date of report. If we fail to patch within that window, the reporter is free to disclose publicly.

---

## Security Design Decisions

For a complete description of PyHSM's security architecture, see:

- [README.md — Security Model](README.md#security-model)
- [OPERATIONS.md — Security Considerations](pyhsm-ts/OPERATIONS.md#security-considerations)

Key design principles:

- No custom cryptography — only proven, audited primitives (AES-256-GCM, Argon2id, HKDF, HMAC-SHA256)
- Key separation via HKDF-Expand with distinct info strings
- Encrypt-then-MAC with independent subkeys
- Deterministic memory zeroization (mutable bytearray/Buffer, not immutable strings)
- Constant-time comparisons for all secret-dependent operations (`hmac.compare_digest` throughout, including audit log verification and legacy Shamir checksum path — enforced in v2.3.1)
- Input size validation to prevent memory exhaustion
- Atomic file writes to prevent corruption
- Offline RS256 JWT license verification — no network call, no server dependency, air-gap safe
- License state recorded in the tamper-evident audit log at every session open
- Thread-safe rate limiter — `allow()`, `usage()`, and `reset()` protected by `threading.Lock` (v2.3.1)
- RSA key import restricted to NIST SP 800-131A approved sizes (2048 and 4096 bits) — weaker keys rejected at import (v2.3.1)
