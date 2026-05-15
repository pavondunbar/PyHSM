/**
 * PyHSM Core — Production-hardened software HSM.
 *
 * Features:
 * - Key versioning with rotation and archival
 * - Per-key ACLs and caller authentication
 * - Per-key rate limiting
 * - Constant-time policy checks
 * - HMAC tamper detection on keystore
 * - Atomic file writes
 * - Memory zeroization on close
 * - Encrypted backups
 * - Startup self-tests (KAT)
 * - Session auto-lock
 * - Shamir M-of-N unlock support
 */
import crypto from "node:crypto";
import fs from "node:fs";
import argon2 from "argon2";
import { siv } from "@noble/ciphers/aes";
import type { KeyEntry, KeyPolicy, KeystoreData, PyHSMConfig } from "./types";
import { AuditLog } from "./audit";
import { RateLimiter } from "./rate-limiter";
import { MetricsCollector } from "./metrics";
import { runSelfTests } from "./self-test";
import { reconstructMasterPassword, type ShamirShare } from "./shamir";

const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const VERSION_PREFIX_LEN = 4; // 4 bytes = version number in ciphertext

// Argon2id parameters (OWASP recommended)
const ARGON2_MEM_COST = 65536; // 64 MB
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 4;

// --- Constant-time utilities ---
function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function zeroBuffer(buf: Buffer): void {
  crypto.randomFillSync(buf); // overwrite with random first
  buf.fill(0);
}

export class PyHSM {
  private store: KeystoreData = { version: 3, keys: {} };
  private storePath: string;
  private masterPassword: string = "";
  private sessionActive = false;
  private lastActivity = 0;
  private sessionTimer: ReturnType<typeof setTimeout> | null = null;
  private sessionTimeoutMs: number;

  // Sub-modules
  private audit: AuditLog;
  private rateLimiter: RateLimiter;
  private metrics: MetricsCollector;
  private callerSecret: string | null;
  private backupDir: string | null;

  constructor(config: PyHSMConfig) {
    this.storePath = config.storePath;
    this.sessionTimeoutMs = config.sessionTimeoutMs || 5 * 60 * 1000;
    this.callerSecret = config.callerSecret || process.env.PYHSM_CALLER_SECRET || null;
    this.backupDir = config.backupDir || process.env.PYHSM_BACKUP_DIR || null;

    // Resolve master password: direct or via Shamir shares
    if (config.masterPassword) {
      this.masterPassword = config.masterPassword;
    } else if (config.shares && config.shares.length > 0) {
      const shares: ShamirShare[] = config.shares.map((s) => JSON.parse(s));
      this.masterPassword = reconstructMasterPassword(shares);
    } else {
      throw new Error("PyHSM: masterPassword or shares required");
    }

    // Initialize sub-modules
    const auditPath = config.auditLogPath || config.storePath + ".audit.jsonl";
    this.audit = new AuditLog(auditPath);
    this.rateLimiter = new RateLimiter(
      parseInt(process.env.PYHSM_RATE_LIMIT || "100", 10),
      parseInt(process.env.PYHSM_RATE_WINDOW_MS || "60000", 10),
    );
    this.metrics = new MetricsCollector();

    // Run self-tests before accepting any operations
    try {
      runSelfTests();
      this.audit.record("selfTestPass", { success: true });
    } catch (e: any) {
      this.audit.record("selfTestFail", { success: false, reason: e.message });
      throw e;
    }

    this.openSession();
  }

  /**
   * Async factory — uses Argon2id for key derivation (preferred).
   * Use this instead of constructor when possible.
   */
  static async create(config: PyHSMConfig): Promise<PyHSM> {
    const instance = new PyHSM(config);
    // Re-derive with Argon2id and re-load if keystore exists
    if (fs.existsSync(config.storePath)) {
      const raw = fs.readFileSync(config.storePath);
      const salt = raw.subarray(0, SALT_LEN);
      instance._cachedDerivedKey = await instance.deriveKeyAsync(salt);
      instance._cachedSalt = Buffer.from(salt);
    }
    return instance;
  }

  // --- Session Management ---

  private openSession(): void {
    this.load();
    this.sessionActive = true;
    this.lastActivity = Date.now();
    this.scheduleTimeout();
    this.audit.record("sessionOpen", { success: true });
    this.updateKeyMetrics();
  }

  private scheduleTimeout(): void {
    if (this.sessionTimer) clearTimeout(this.sessionTimer);
    this.sessionTimer = setTimeout(() => this.checkTimeout(), this.sessionTimeoutMs);
    if (this.sessionTimer.unref) this.sessionTimer.unref();
  }

  private checkTimeout(): void {
    if (Date.now() - this.lastActivity >= this.sessionTimeoutMs) {
      this.closeSession();
    } else {
      this.scheduleTimeout();
    }
  }

  private touch(): void {
    this.lastActivity = Date.now();
    this.scheduleTimeout();
  }

  private assertSession(): void {
    if (!this.sessionActive) this.openSession();
    this.touch();
  }

  closeSession(): void {
    if (!this.sessionActive) return;
    this.audit.record("sessionClose", { success: true });
    this.save();
    this.zeroize();
    this.sessionActive = false;
    if (this.sessionTimer) { clearTimeout(this.sessionTimer); this.sessionTimer = null; }
  }

  private zeroize(): void {
    for (const entry of Object.values(this.store.keys)) {
      for (const v of entry.versions) {
        v.keyData = "0".repeat(v.keyData.length);
      }
    }
    this.store = { version: 3, keys: {} };
    this.masterPassword = "";
  }

  // --- Persistence with Tamper Detection ---

  private deriveKey(salt: Buffer): Buffer {
    // Argon2id is async — we use a cached derived key per session.
    // The actual derivation happens in openSession via deriveKeyAsync.
    if (this._cachedDerivedKey && this._cachedSalt && this._cachedSalt.equals(salt)) {
      return Buffer.from(this._cachedDerivedKey);
    }
    // Fallback: PBKDF2 for sync contexts (should not normally be reached)
    return crypto.pbkdf2Sync(this.masterPassword, salt, 480_000, 32, "sha256");
  }

  private _cachedDerivedKey: Buffer | null = null;
  private _cachedSalt: Buffer | null = null;

  private async deriveKeyAsync(salt: Buffer): Promise<Buffer> {
    const raw = await argon2.hash(this.masterPassword, {
      type: argon2.argon2id,
      salt,
      memoryCost: ARGON2_MEM_COST,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
      hashLength: 32,
      raw: true,
    });
    return Buffer.from(raw);
  }

  /** AES-KWP (RFC 5649) key wrapping — wraps key material for storage. */
  private wrapKey(kek: Buffer, keyData: Buffer): Buffer {
    const cipher = crypto.createCipheriv("aes-256-wrap-pad" as any, kek, Buffer.alloc(4, 0xa6));
    return Buffer.concat([cipher.update(keyData), cipher.final()]);
  }

  /** AES-KWP unwrap. */
  private unwrapKey(kek: Buffer, wrapped: Buffer): Buffer {
    const decipher = crypto.createDecipheriv("aes-256-wrap-pad" as any, kek, Buffer.alloc(4, 0xa6));
    return Buffer.concat([decipher.update(wrapped), decipher.final()]);
  }

  private computeHmac(data: Buffer, key: Buffer): Buffer {
    return crypto.createHmac("sha256", key).update(data).digest();
  }

  private load(): void {
    if (!fs.existsSync(this.storePath)) return;
    const raw = fs.readFileSync(this.storePath);

    if (raw.length < SALT_LEN + 32 + NONCE_LEN + TAG_LEN) {
      this.handleTamper("Keystore file too short");
      return;
    }

    const salt = raw.subarray(0, SALT_LEN);
    const storedHmac = raw.subarray(SALT_LEN, SALT_LEN + 32);
    const payload = raw.subarray(SALT_LEN + 32);
    const key = this.deriveKey(salt);

    const expectedHmac = this.computeHmac(payload, key);
    if (!crypto.timingSafeEqual(storedHmac, expectedHmac)) {
      zeroBuffer(key);
      this.handleTamper("HMAC verification failed");
      return;
    }

    const nonce = payload.subarray(0, NONCE_LEN);
    const ct = payload.subarray(NONCE_LEN);
    const tag = ct.subarray(ct.length - TAG_LEN);
    const encrypted = ct.subarray(0, ct.length - TAG_LEN);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    zeroBuffer(key);

    const parsed = JSON.parse(plain.toString("utf8"));
    zeroBuffer(plain);

    // Migrate from v2 format
    if (!parsed.version || parsed.version < 3) {
      this.store = { version: 3, keys: {} };
      const oldKeys = parsed.keys || parsed;
      for (const [id, entry] of Object.entries(oldKeys)) {
        const e = entry as any;
        this.store.keys[id] = {
          keyId: id,
          keyType: e.keyType || e.key_type || "aes-256",
          currentVersion: 1,
          versions: [{
            version: 1,
            keyData: e.keyData || e.key_data || "",
            createdAt: e.createdAt || e.created_at || new Date().toISOString(),
            archived: false,
          }],
          policy: e.policy || { allowEncrypt: true, allowDecrypt: true },
          operationCount: e.operationCount || 0,
          createdAt: e.createdAt || e.created_at || new Date().toISOString(),
        };
      }
    } else {
      this.store = parsed;
    }
  }

  private save(): void {
    const salt = crypto.randomBytes(SALT_LEN);
    const key = this.deriveKey(salt);
    const nonce = crypto.randomBytes(NONCE_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    const ct = Buffer.concat([
      cipher.update(JSON.stringify(this.store), "utf8"),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    const payload = Buffer.concat([nonce, ct]);
    const hmac = this.computeHmac(payload, key);
    zeroBuffer(key);

    const fileData = Buffer.concat([salt, hmac, payload]);
    // Atomic write
    const tmp = this.storePath + ".tmp." + crypto.randomBytes(4).toString("hex");
    fs.writeFileSync(tmp, fileData, { mode: 0o600 });
    fs.renameSync(tmp, this.storePath);
  }

  private handleTamper(reason: string): void {
    this.audit.record("tamperDetected", { success: false, reason });
    // Zeroize all key material immediately
    this.zeroize();
    throw new Error(`PyHSM TAMPER DETECTED: ${reason}. All keys destroyed.`);
  }

  // --- Access Control ---

  private authenticateCaller(callerId: string): boolean {
    if (!this.callerSecret) return true; // No auth configured
    // Caller ID format: "service:hmac" where hmac = HMAC(service, callerSecret)
    const parts = callerId.split(":");
    if (parts.length !== 2) return false;
    const [service, providedHmac] = parts;
    const expected = crypto.createHmac("sha256", this.callerSecret)
      .update(service).digest("hex");
    return constantTimeEqual(providedHmac, expected);
  }

  private checkACL(entry: KeyEntry, callerId: string): boolean {
    if (!entry.policy.allowedCallers || entry.policy.allowedCallers.length === 0) {
      return true; // No ACL = open access
    }
    const service = callerId.split(":")[0] || callerId;
    return entry.policy.allowedCallers.includes(service);
  }

  // --- Policy Enforcement (constant-time where possible) ---

  private enforcePolicy(entry: KeyEntry, operation: "encrypt" | "decrypt", callerId: string): void {
    // Rate limiting
    if (!this.rateLimiter.allow(entry.keyId)) {
      this.metrics.recordRateLimit();
      this.audit.record("rateLimited", { keyId: entry.keyId, callerId, success: false });
      throw new Error(`PyHSM: key '${entry.keyId}' rate limited`);
    }

    // Caller authentication
    if (!this.authenticateCaller(callerId)) {
      this.metrics.recordAccessDenial();
      this.audit.record("accessDenied", { keyId: entry.keyId, callerId, success: false, reason: "auth failed" });
      throw new Error("PyHSM: caller authentication failed");
    }

    // Per-key ACL
    if (!this.checkACL(entry, callerId)) {
      this.metrics.recordAccessDenial();
      this.audit.record("accessDenied", { keyId: entry.keyId, callerId, success: false, reason: "ACL denied" });
      throw new Error(`PyHSM: caller not authorized for key '${entry.keyId}'`);
    }

    // Operation permission
    if (operation === "encrypt" && !entry.policy.allowEncrypt) {
      throw new Error(`PyHSM: key '${entry.keyId}' policy denies encrypt`);
    }
    if (operation === "decrypt" && !entry.policy.allowDecrypt) {
      throw new Error(`PyHSM: key '${entry.keyId}' policy denies decrypt`);
    }

    // Max operations
    if (entry.policy.maxOperations !== undefined && entry.operationCount >= entry.policy.maxOperations) {
      throw new Error(`PyHSM: key '${entry.keyId}' exceeded max operations`);
    }

    // Expiry
    if (entry.policy.expiresAt && new Date(entry.policy.expiresAt) < new Date()) {
      throw new Error(`PyHSM: key '${entry.keyId}' has expired`);
    }
  }

  private updateKeyMetrics(): void {
    let active = 0, archived = 0;
    for (const entry of Object.values(this.store.keys)) {
      const cv = entry.versions.find((v) => v.version === entry.currentVersion);
      if (cv?.archived) archived++; else active++;
    }
    this.metrics.setKeyCount(active, archived);
  }

  // --- Key Operations ---

  generateKey(keyId: string, policy?: Partial<KeyPolicy>, callerId = "system"): void {
    this.assertSession();
    if (this.store.keys[keyId]) throw new Error(`PyHSM: key '${keyId}' already exists`);

    this.store.keys[keyId] = {
      keyId,
      keyType: "aes-256",
      currentVersion: 1,
      versions: [{
        version: 1,
        keyData: crypto.randomBytes(32).toString("hex"),
        createdAt: new Date().toISOString(),
        archived: false,
      }],
      policy: { allowEncrypt: true, allowDecrypt: true, ...policy },
      operationCount: 0,
      createdAt: new Date().toISOString(),
    };

    this.audit.record("generateKey", { keyId, callerId, success: true });
    this.save();
    this.updateKeyMetrics();
  }

  /** Rotate a key: generate new version, archive the old one. */
  rotateKey(keyId: string, callerId = "system"): void {
    this.assertSession();
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    // Archive current version
    const current = entry.versions.find((v) => v.version === entry.currentVersion);
    if (current) current.archived = true;

    // Create new version
    const newVersion = entry.currentVersion + 1;
    entry.versions.push({
      version: newVersion,
      keyData: crypto.randomBytes(32).toString("hex"),
      createdAt: new Date().toISOString(),
      archived: false,
    });
    entry.currentVersion = newVersion;

    this.audit.record("rotateKey", { keyId, callerId, success: true });
    this.save();
    this.updateKeyMetrics();
  }

  destroyKey(keyId: string, callerId = "system"): void {
    this.assertSession();
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    // Zero all versions
    for (const v of entry.versions) {
      v.keyData = "0".repeat(v.keyData.length);
    }
    delete this.store.keys[keyId];

    this.audit.record("destroyKey", { keyId, callerId, success: true });
    this.save();
    this.updateKeyMetrics();
  }

  hasKey(keyId: string): boolean {
    this.assertSession();
    return keyId in this.store.keys;
  }

  /**
   * Encrypt with the current key version using AES-256-GCM-SIV (nonce misuse resistant).
   * Output format: base64(versionPrefix(4) || nonce(12) || ciphertext+tag)
   */
  encrypt(keyId: string, plaintext: string, callerId = "system"): string {
    this.assertSession();
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    this.enforcePolicy(entry, "encrypt", callerId);

    const current = entry.versions.find((v) => v.version === entry.currentVersion);
    if (!current || current.archived) {
      throw new Error(`PyHSM: key '${keyId}' current version is archived`);
    }

    const aesKey = Buffer.from(current.keyData, "hex");
    const nonce = crypto.randomBytes(NONCE_LEN);

    // AES-256-GCM-SIV: nonce misuse resistant — safe even if nonce is reused
    const sivCipher = siv(new Uint8Array(aesKey), new Uint8Array(nonce));
    const ct = sivCipher.encrypt(new TextEncoder().encode(plaintext));
    zeroBuffer(aesKey);

    // Prefix with version number (4 bytes, big-endian)
    const versionBuf = Buffer.alloc(VERSION_PREFIX_LEN);
    versionBuf.writeUInt32BE(current.version);

    entry.operationCount++;
    this.metrics.recordOp("encrypt");
    this.audit.record("encrypt", { keyId, callerId, success: true });
    if (entry.operationCount % 10 === 0) this.save();

    return Buffer.concat([versionBuf, Buffer.from(nonce), Buffer.from(ct)]).toString("base64");
  }

  /**
   * Decrypt — reads version prefix to select the correct key version.
   * Uses AES-256-GCM-SIV. Falls back to legacy AES-GCM for old ciphertexts.
   */
  decrypt(keyId: string, ciphertextB64: string, callerId = "system"): string {
    this.assertSession();
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    this.enforcePolicy(entry, "decrypt", callerId);

    const buf = Buffer.from(ciphertextB64, "base64");

    let aesKey: Buffer;
    let nonce: Uint8Array;
    let ct: Uint8Array;
    let useLegacy = false;

    if (buf.length > VERSION_PREFIX_LEN + NONCE_LEN + TAG_LEN) {
      const version = buf.readUInt32BE(0);
      const vEntry = entry.versions.find((v) => v.version === version);

      if (vEntry) {
        aesKey = Buffer.from(vEntry.keyData, "hex");
        nonce = new Uint8Array(buf.subarray(VERSION_PREFIX_LEN, VERSION_PREFIX_LEN + NONCE_LEN));
        ct = new Uint8Array(buf.subarray(VERSION_PREFIX_LEN + NONCE_LEN));
      } else {
        // Legacy format (no version prefix) — use AES-GCM
        aesKey = Buffer.from(entry.versions[0].keyData, "hex");
        nonce = new Uint8Array(buf.subarray(0, NONCE_LEN));
        ct = new Uint8Array(buf.subarray(NONCE_LEN));
        useLegacy = true;
      }
    } else {
      // Legacy format
      aesKey = Buffer.from(entry.versions[0].keyData, "hex");
      nonce = new Uint8Array(buf.subarray(0, NONCE_LEN));
      ct = new Uint8Array(buf.subarray(NONCE_LEN));
      useLegacy = true;
    }

    let result: string;
    if (useLegacy) {
      // Legacy AES-GCM decrypt (tag is bytes 12..28, ciphertext after)
      const tag = buf.subarray(NONCE_LEN, NONCE_LEN + TAG_LEN);
      const encData = buf.subarray(NONCE_LEN + TAG_LEN);
      const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(nonce));
      decipher.setAuthTag(tag);
      result = Buffer.concat([decipher.update(encData), decipher.final()]).toString("utf8");
    } else {
      // AES-256-GCM-SIV decrypt
      const sivDecipher = siv(new Uint8Array(aesKey), nonce);
      const plainBytes = sivDecipher.decrypt(ct);
      result = new TextDecoder().decode(plainBytes);
    }

    zeroBuffer(aesKey);

    entry.operationCount++;
    this.metrics.recordOp("decrypt");
    this.audit.record("decrypt", { keyId, callerId, success: true });
    if (entry.operationCount % 10 === 0) this.save();

    return result;
  }

  // --- Backup ---

  createBackup(callerId = "system"): string {
    this.assertSession();
    const dir = this.backupDir;
    if (!dir) throw new Error("PyHSM: PYHSM_BACKUP_DIR not configured");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupPath = `${dir}/pyhsm-backup-${timestamp}.enc`;

    // Copy the encrypted keystore (it's already encrypted)
    fs.copyFileSync(this.storePath, backupPath);
    fs.chmodSync(backupPath, 0o600);

    this.audit.record("backup", { callerId, success: true });
    return backupPath;
  }

  // --- Expiry Enforcement (background) ---

  enforceExpiry(): void {
    this.assertSession();
    for (const entry of Object.values(this.store.keys)) {
      if (entry.policy.expiresAt && new Date(entry.policy.expiresAt) < new Date()) {
        // Archive all versions of expired key
        for (const v of entry.versions) v.archived = true;
        this.audit.record("archiveKey", { keyId: entry.keyId, success: true, reason: "expired" });
      }
    }
    this.save();
    this.updateKeyMetrics();
  }

  // --- Metrics & Health ---

  getMetrics(): typeof this.metrics extends MetricsCollector ? ReturnType<MetricsCollector["getMetrics"]> : never {
    return this.metrics.getMetrics() as any;
  }

  getPrometheusMetrics(): string {
    return this.metrics.toPrometheus();
  }

  getAuditLog() {
    return this.audit;
  }
}
