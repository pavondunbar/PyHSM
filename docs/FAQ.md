# PyHSM — Frequently Asked Questions

Architecture, security, and design questions about PyHSM.

---

## Why did you build a software HSM instead of using Vault?

Vault solves a different problem at a different scale. It's a secrets management platform — it manages database credentials, API tokens, PKI certificates, and dynamic secrets across an organization. It requires Consul for HA, needs dedicated operators, and the Enterprise license for features like HSM auto-unseal costs six figures.

PyHSM is a focused key management library. You `pip install` it, import it in your code, and you have key generation, signing, encryption, and audit logging in five lines. There's no cluster to manage, no Consul dependency, no operator UI to secure, no HCL policy language to learn.

**Use Vault if:** You need org-wide secrets management with 50 services and dynamic credential rotation.

**Use PyHSM if:** You need to encrypt data or sign transactions from your application with proper key lifecycle management — without the operational overhead.

Additional distinction: Vault's Transit engine doesn't support secp256k1. If you're signing Ethereum or Bitcoin transactions, Vault can't do it natively. PyHSM can.

---

## How do you prevent key extraction?

Short answer: PyHSM doesn't claim the key is *impossible* to extract. It makes extraction as difficult as possible within software constraints, and makes all access auditable.

The layers of defense:

1. **Double-encrypted at rest.** The keystore file is AES-256-GCM encrypted (master password → Argon2id → HKDF → encryption key). Each individual key inside is additionally wrapped with AES-KWP (RFC 5649). Stealing the file gives an attacker nothing without the master password.

2. **Never in memory as immutable objects.** Key material is stored as mutable `bytearray` (Python) or `Buffer` (Node.js) and deterministically zeroized byte-by-byte after each operation. It doesn't sit in a string pool waiting for garbage collection.

3. **The API never returns raw key bytes.** You call `hsm.sign()` and get a signature back. The private key is unwrapped internally, used, and zeroized — your application code never holds it.

4. **Process isolation mode** puts the keys in a separate OS process. Even a full RCE in your application can't read the HSM process's address space without a kernel exploit.

5. **Export is explicit and audited.** `export_jwk()` exists for interoperability, but it's a deliberate call that gets logged in the audit trail. You can design key policies that allow signing but never export.

**What PyHSM cannot prevent:** A root-level attacker with memory debugging tools attached to the running HSM process during the microseconds of signing. That's what hardware HSMs solve with a physical trust boundary. The [THREAT_MODEL.md](../THREAT_MODEL.md) documents this explicitly.

---

## How is key rotation implemented?

Key rotation generates a new key version and archives the old one. Old ciphertexts remain decryptable because the version number is embedded in the ciphertext format.

```
Before rotation:
  "my-key" → version 1 (active)

After hsm.rotate_key("my-key"):
  "my-key" → version 2 (active — used for new encryptions)
             version 1 (archived — can still decrypt old ciphertexts)
```

Mechanically:

1. New random key material is generated (`os.urandom(32)`)
2. It's wrapped with AES-KWP before storage
3. The previous version is marked `archived: true`
4. New `encrypt()` calls use version 2
5. `decrypt()` reads the version prefix from the ciphertext header and selects the matching key version automatically

This means you can rotate keys without re-encrypting your entire database. Old data decrypts with the old version, new data uses the new version. Both versions remain protected at rest with the same double-encryption.

Rotation is currently supported for AES keys. Asymmetric keys (EC, RSA, Ed25519) don't rotate in-place — you generate a new key ID and transition callers.

---

## How are audit logs protected from tampering?

Each audit entry contains an HMAC that chains to the previous entry — similar to a blockchain of log records.

```
Entry 0: HMAC(key, timestamp + operation + data)
Entry 1: HMAC(key, timestamp + operation + data + HMAC_of_entry_0)
Entry 2: HMAC(key, timestamp + operation + data + HMAC_of_entry_1)
...
```

**To tamper with entry N**, an attacker would need to recompute the HMAC for entries N, N+1, N+2, ... all the way to the end. And to compute any HMAC, they need the audit HMAC key — which is derived from the master password via HKDF (Python layer) or stored independently (TypeScript layer).

**Verification** walks the chain and checks every HMAC against its predecessor. If any entry was modified, inserted, or deleted, the chain breaks and verification reports the exact sequence number where corruption occurred.

**The log is append-only** — entries are never modified or deleted during normal operation. Every operation (including denied ones) is recorded with timestamp, operation type, key ID, caller ID, and success/failure status.

---

## What cryptographic guarantees do you provide?

| Property | Mechanism | Standard |
|---|---|---|
| Confidentiality at rest | AES-256-GCM (Python) / AES-256-GCM-SIV (TypeScript) | NIST SP 800-38D / RFC 8452 |
| Key wrapping | AES-KWP | RFC 5649 |
| Key derivation | Argon2id (64MB/3 passes) → HKDF-Expand | RFC 9106 / RFC 5869 |
| Key separation | HKDF with distinct info strings | Enc, MAC, and KEK are cryptographically independent |
| Authentication | Encrypt-then-MAC (HMAC-SHA256) | Bellare & Namprempre proven-secure composition |
| Nonce safety | Hybrid nonce (random+counter+random) / GCM-SIV | Birthday bound eliminated / nonce-misuse resistant |
| Ciphertext binding | AAD = key_id + version | Prevents cross-key confusion attacks |
| Signing (ECDSA) | SHA-256 (P-256, secp256k1), SHA-384 (P-384), SHA-512 (P-521) | FIPS 186-5 |
| Signing (EdDSA) | Ed25519 | RFC 8032 |
| Constant-time comparison | `hmac.compare_digest` / length-padded `timingSafeEqual` | Timing side-channel resistant |
| Audit integrity | HMAC-chained append-only log | Tamper-evident |

**What is explicitly NOT guaranteed:**

- Protection against an attacker with kernel-level access to a running process
- Side-channel attacks on the CPU (cache timing, speculative execution)
- Physical access to the hardware
- Resistance to compromised underlying crypto libraries (supply chain)

---

## What threat model did you design against?

PyHSM defends against five classes of threat actors:

| Threat Actor | Capability | PyHSM Defense |
|---|---|---|
| **T1: Network attacker** | Can reach services on the host | Process isolation; app never holds keys |
| **T2: App-level code execution** | RCE in the application process | Rate limiting, ACLs, operation caps, process isolation |
| **T3: Filesystem read access** | Stolen disk/backup | Double-encryption (AES-GCM + AES-KWP), Argon2id |
| **T4: Malicious insider** | Partial system access, no master password | Shamir M-of-N, tamper detection, audit log |
| **T5: Root/kernel access** | Full machine control | **LIMITED** — deterministic zeroization reduces window only |

**In-scope:** Filesystem theft, application compromise, unauthorized key usage, silent key abuse, insider threats with partial access, keystore tampering, audit log manipulation.

**Out-of-scope (acknowledged):** Root attacker with debugger during signing, CPU side-channels, physical hardware access, compromised OS kernel.

The full threat model with detailed mitigations for each actor is in [THREAT_MODEL.md](../THREAT_MODEL.md).

---

## Why should I use this instead of AWS KMS?

It depends on your constraints. Neither is universally better.

| Factor | AWS KMS | PyHSM |
|---|---|---|
| Cost | $1/key/month + $0.03/10K API calls | $0 (MIT licensed) |
| secp256k1 support | No | Yes |
| Ed25519 support | No | Yes |
| Data sovereignty | Keys in AWS infrastructure | Keys on your infrastructure |
| Vendor lock-in | Yes (ciphertext only decryptable via AWS) | No (JWK export, standard formats) |
| Network dependency | Yes (API call per operation) | No (local library call) |
| Latency | 5–50 ms per API call (network round-trip) | <1 ms crypto + ~103 ms persistence |
| Audit | CloudTrail (managed by AWS) | Self-managed HMAC-chained log you own |
| FIPS certification | Yes (Level 2) | No |
| Hardware isolation | Yes (HSM-backed) | No (software process boundaries) |
| Compliance checkbox | Yes | Depends on your auditor |

**Use AWS KMS if:** You're in a regulated environment requiring FIPS certification, you're already all-in on AWS, you don't need secp256k1/Ed25519, and you're fine with per-operation costs and network latency.

**Use PyHSM if:** You need secp256k1/Ed25519 signing (blockchain), you want to avoid per-operation costs at scale, you require data sovereignty, you want zero vendor lock-in, or your latency budget can't tolerate network round-trips for every operation.

**They're not mutually exclusive:** Some teams use AWS KMS for general infrastructure encryption and PyHSM specifically for blockchain transaction signing where AWS has no native support.
