# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

Only the latest release on the `main` branch receives security patches.

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
- [`cryptography`](https://github.com/pyca/cryptography) — AES-256-GCM, PBKDF2, HKDF, RSA, ECDSA, AES-KWP

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
- Constant-time comparisons for all secret-dependent operations
- Input size validation to prevent memory exhaustion
- Atomic file writes to prevent corruption
