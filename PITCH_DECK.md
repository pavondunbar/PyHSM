# VectorGuard (PyHSM) — Pitch Deck

---

## Slide 1: The Problem

### Key management is broken for 99% of companies.

Companies that need cryptographic key management face an impossible choice:

| Option | Reality |
|--------|---------|
| Hardware HSM (Thales, Entrust) | $20K–$100K+ upfront, 12-week procurement, dedicated ops team |
| Cloud KMS (AWS, GCP, Azure) | Vendor lock-in, data sovereignty concerns, per-operation billing adds up |
| DIY ("keys in .env") | Inevitable breach. No rotation, no audit trail, no access control |

**The result:** Startups and mid-market teams skip key management entirely — storing secrets in environment variables, hardcoding keys, or hoping their cloud provider handles everything.

**What happens next:**
- 82% of breaches involve stolen credentials or cryptographic keys (Verizon DBIR 2024)
- SOC 2 / PCI-DSS auditors flag the gap — teams scramble to patch it retroactively
- Web3 companies lose millions to compromised wallet keys with zero audit trail

**There is no middle ground between "enterprise overkill" and "dangerously insecure."**

Until now.

---

## Slide 2: The Solution

### VectorGuard (PyHSM) — Production-grade software KMS you deploy in minutes, not months.

**One-liner:** Replace $50K hardware HSMs with a battle-tested software KMS that provides the same security guarantees for the 99% of teams that don't need certified hardware.

**What it does:**
- Full key lifecycle: generate, rotate, archive, destroy — with versioning
- Authenticated encryption (AES-256-GCM-SIV) and digital signing (RSA, ECDSA, Ed25519)
- Per-key policies: expiry, operation limits, caller ACLs, rate limiting
- Tamper-evident HMAC-chained audit log (SIEM-ready)
- Blockchain-native: secp256k1 (Ethereum/Bitcoin) and Ed25519 (Solana) signing built-in
- Deploy anywhere: single binary, no cloud dependency, no vendor lock-in

**How it's different:**
- **Not a wrapper** — purpose-built cryptographic engine with double encryption at rest
- **Not cloud-dependent** — runs on your infra, air-gapped if needed
- **Not a toy** — Argon2id KDF, encrypt-then-MAC, AES-KWP key wrapping, startup self-tests
- **Two SDKs** — Python and TypeScript/Node.js, covering 80%+ of backend development

---

## Slide 3: How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  YOUR APPLICATION                                            │
│                                                              │
│  hsm.sign("eth-wallet", tx_hash)                             │
│  hsm.encrypt("app-key", user_data)                           │
│                                                              │
│  Raw key material NEVER leaves this boundary                 │
└────────────────────────────┬────────────────────────────────┘
                             │ API call or Unix socket IPC
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  VECTORGUARD CORE (separate process, optional)               │
│                                                              │
│  ┌───────────┐  ┌────────────┐  ┌─────────┐  ┌──────────┐  │
│  │ Key Unwrap│→ │ Policy     │→ │ Crypto  │→ │ Audit +  │  │
│  │ (AES-KWP) │  │ Enforce    │  │ Execute │  │ Metrics  │  │
│  └───────────┘  └────────────┘  └─────────┘  └──────────┘  │
│                                       │                      │
│                                 Key zeroized                 │
│                                 from memory                  │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  ENCRYPTED STORAGE                                           │
│                                                              │
│  ┌────────────────────────────┐  ┌────────────────────────┐ │
│  │ AES-256-GCM Envelope       │  │ HMAC-Chained Audit Log │ │
│  │ + HMAC-SHA256 Tamper Seal   │  │ (append-only, signed)  │ │
│  │   ┌──────────────────────┐ │  └────────────────────────┘ │
│  │   │ AES-KWP Per-Key Wrap │ │                             │
│  │   │  • eth-wallet         │ │                             │
│  │   │  • app-secrets        │ │                             │
│  │   │  • signing-key        │ │                             │
│  │   └──────────────────────┘ │                             │
│  └────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────┘
```

### Security Stack

| Layer | Protection |
|-------|-----------|
| Key Derivation | Argon2id (64 MB memory-hard, OWASP recommended) |
| Envelope Encryption | AES-256-GCM + HMAC-SHA256 (encrypt-then-MAC) |
| Per-Key Wrapping | AES-KWP (RFC 5649) — keys double-encrypted at rest |
| Key Separation | HKDF-Expand with distinct info strings per subkey |
| Memory | Deterministic zeroization (SecureBytes/SecureBuffer) |
| Access Control | Per-key ACLs, rate limiting, operation caps, expiry |
| Audit | HMAC-chained tamper-evident log with webhook delivery |
| Startup | Known-Answer Tests (KATs) before accepting any ops |
| Isolation | Optional process isolation via Unix domain socket |
| Unlock | Shamir M-of-N secret sharing for ceremony-based access |

---

## Slide 4: Market Size

### Enterprise Key Management is a $3.5B market growing 19%+ annually.

| Market Segment | 2025 Size | 2030 Forecast | CAGR |
|---------------|-----------|---------------|------|
| Enterprise Key Management | $3.5B | $8.3B | 18.7% |
| Hardware Security Modules | $2.0B | $4.8B | 15.3% |
| Key Management as a Service | $1.6B | $4.7B | 22.4% |
| Encryption as a Service | $2.0B | $6.0B | 24.9% |

*Sources: Grand View Research, MarketsandMarkets, The Business Research Company (2025-2026 reports)*

### Our Beachhead

**$2B+ addressable from Day 1:** Teams currently paying for cloud KMS that want sovereignty, plus teams using no key management at all (the largest underserved segment).

**Why now:**
- Post-quantum migration is forcing companies to rethink key infrastructure
- SOC 2 Type II / PCI-DSS 4.0 are tightening key management requirements
- Web3/DeFi requires programmatic signing with audit trails (not MetaMask)
- Data sovereignty regulations (GDPR, DORA) make cloud-only KMS problematic

---

## Slide 5: Traction

### Shipped. Tested. Production-hardened.

| Milestone | Status |
|-----------|--------|
| Version | v1.9.0 (stable) |
| SDKs | Python + TypeScript/Node.js |
| Distribution | Published on PyPI (`pip install vectorguard-pyhsm`) |
| Test Coverage | 264 tests (unit, integration, concurrency stress) |
| Coverage Gate | 80%+ enforced in CI |
| CI/CD | Multi-version testing (Python 3.11-3.13), daily CVE scanning |
| Type Safety | `mypy --strict` + full TypeScript strict mode |
| Security Audit | Automated `pip-audit` + `npm audit` on every push |
| Documentation | Complete API docs, threat model, FAQ, operations guide |

### Key Types Supported

AES-128, AES-256, RSA-2048, RSA-4096, EC P-256, EC P-384, EC P-521, secp256k1 (Ethereum/Bitcoin), Ed25519 (Solana/SSH)

### What's Already Built (not planned — shipped)

- Encrypted backup/restore with HMAC verification
- Automatic key rotation policies
- JWK (RFC 7517) import/export for KMS interoperability
- Prometheus + OpenTelemetry metrics
- Process isolation mode
- Shamir M-of-N unlock ceremony
- Pluggable storage backends (file, memory, or custom)

---

## Slide 6: Business Model

### Open Core + Managed Service

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   OPEN SOURCE (MIT)              COMMERCIAL                  │
│   ─────────────────              ──────────                  │
│                                                              │
│   • Core KMS engine              • VectorGuard Cloud         │
│   • Python + TS SDKs               (managed multi-tenant)    │
│   • CLI tool                     • Enterprise SSO + RBAC     │
│   • Single-node deployment       • Multi-node HA / clustering│
│   • Community support            • Compliance reports        │
│                                    (SOC 2, PCI-DSS, HIPAA)   │
│                                  • Priority support + SLA    │
│                                  • Custom storage backends   │
│                                    (DynamoDB, PostgreSQL, S3) │
│                                  • Threshold signing (FROST)  │
│                                  • Key ceremony tooling       │
│                                                              │
│   FREE                           $500-5,000/mo per cluster   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Revenue Model

| Tier | Price | Target |
|------|-------|--------|
| Open Source | Free | Individual developers, startups validating |
| Team | $500/mo | Startups with compliance needs (SOC 2 prep) |
| Business | $2,000/mo | Mid-market with HA, RBAC, audit exports |
| Enterprise | $5,000+/mo | Regulated industries, custom deployment |

### Comparable Pricing Context

- AWS CloudHSM: $1.50/hr = ~$1,100/mo per instance (plus per-operation fees)
- Thales Luna Network HSM: $20K–$100K upfront + annual maintenance
- HashiCorp Vault Enterprise: $1.58/hr minimum
- **VectorGuard: 50-80% cheaper with no vendor lock-in**

---

## Slide 7: Team

### Pavon Dunbar — Founder & CEO

Built the entire system — both Python and TypeScript implementations — from scratch.

**Why me:**

- **Deep cryptographic engineering expertise**: Implemented Shamir secret sharing over GF(256), encrypt-then-MAC with HKDF key separation, AES-KWP wrapping, and Argon2id KDF — not abstracting over libraries, understanding the primitives
- **Full-stack security thinking**: Wrote the threat model, designed the trust boundaries, implemented constant-time comparisons, deterministic memory zeroization, and tamper-evident audit chains
- **Shipping velocity**: Solo-built a production-grade KMS with 264 tests, dual-language SDKs, CLI, process isolation, and daily automated CVE scanning — v1.9.0 and counting
- **Builder's mentality**: Identified a real gap (no middle ground between .env files and $50K HSMs), built the solution, published it, and is already using it

---

## Slide 8: The Ask

### Raising $500K–$1M

| Use of Funds | Allocation | Outcome |
|-------------|------------|---------|
| Engineering (hire 1-2) | 50% | Multi-node HA, managed cloud service, FROST threshold signing |
| Go-to-market | 25% | Developer advocacy, content, 10 design partners |
| Compliance & audit | 15% | Third-party pen test, SOC 2 Type I for the product itself |
| Operations | 10% | Infrastructure, legal, runway buffer |

### 12-Month Milestones

| Quarter | Goal |
|---------|------|
| Q1 | 10 paying design partners (Team tier), third-party security audit published |
| Q2 | VectorGuard Cloud (managed service) live, multi-node replication |
| Q3 | SOC 2 Type I for VectorGuard itself, 50 paying customers |
| Q4 | $50K ARR, Series Seed positioning, FROST threshold signing shipped |

### Why $500K–$1M (not more)

- Core product is already built and working — this isn't R&D risk capital
- Capital-efficient: solo founder has shipped v1.9.0; team of 3 ships the managed service
- 18-month runway at this burn rate
- Proves PMF before raising a larger round

---

## Appendix: Competitive Landscape

| | VectorGuard | AWS CloudHSM | HashiCorp Vault | Thales Luna |
|---|---|---|---|---|
| Deploy in minutes | Yes | No (hours) | No (complex) | No (weeks) |
| No vendor lock-in | Yes | No | Partial | Yes |
| Open source core | Yes | No | Yes (BSL) | No |
| Blockchain-native signing | Yes | No | No | Limited |
| Software-only (no hardware) | Yes | No | Yes | No |
| Self-hosted option | Yes | No | Yes | Yes |
| Starting price | Free / $500/mo | $1,100/mo | $1.58/hr | $20K+ |
| Double encryption at rest | Yes | N/A (hardware) | No | N/A |
| Tamper-evident audit log | Yes (HMAC-chained) | CloudTrail | Yes | Yes |
| Memory zeroization | Yes | N/A (hardware) | No | N/A |

---

## Contact

**Pavon Dunbar**
GitHub: [github.com/pavondunbar/PyHSM](https://github.com/pavondunbar/PyHSM)
Package: `pip install vectorguard-pyhsm`

---

*VectorGuard — The key management system the other 99% have been waiting for.*
