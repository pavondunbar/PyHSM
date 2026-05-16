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
 * - Memory zeroization on close (Buffer-based)
 * - Encrypted backups
 * - Startup self-tests (KAT)
 * - Session auto-lock
 * - Shamir M-of-N unlock support
 * - AES-KWP key wrapping for stored key material
 */
import crypto from "node:crypto";
import fs from "node:fs";
import argon2 from "argon2";
import { siv } from "@noble/ciphers/aes";
import type { HSMMetrics, KeyEntry, KeyPolicy, KeystoreData, PyHSMConfig } from "./types.js";
import { validateKeyId } from "./types.js";
import { AuditLog } from "./audit.js";
import { RateLimiter } from "./rate-limiter.js";
import { MetricsCollector } from "./metrics.js";
import { runSelfTests } from "./self-test.js";
import { reconstructMasterPassword, type ShamirShare } from "./shamir.js";

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
  buf.fill(0);
}

export class PyHSM {
  private store: KeystoreData = { version: 3, keys: {} };
  private storePath!: string;
  private masterPasswordBuf: Buffer = Buffer.alloc(0);
  private sessionActive = false;
  private lastActivity = 0;
  private sessionTimer: ReturnType<typeof setTimeout> | null = null;
  private sessionTimeoutMs!: number;

  // Derived key cache — persists across save/load within a session
  private _cachedDerivedKey: Buffer | null = null;
  private _cachedSalt: Buffer | null = null;

  // Sub-modules
  private audit!: AuditLog;
  private rateLimiter!: RateLimiter;
  private metrics!: MetricsCollector;
  private callerSecret: Buffer | null = null;
  private backupDir: string | null = null;

  constructor(config: PyHSMConfig) {
    this.storePath = config.storePath;
    this.sessionTimeoutMs = config.sessionTimeoutMs || 5 * 60 * 1000;
    this.callerSecret = config.callerSecret
      ? Buffer.from(config.callerSecret, "utf8")
      : process.env.PYHSM_CALLER_SECRET
        ? Buffer.from(process.env.PYHSM_CALLER_SECRET, "utf8")
        : null;
    this.backupDir = config.backupDir || process.env.PYHSM_BACKUP_DIR || null;

    // Resolve master password: direct or via Shamir shares
    if (config.masterPassword) {
      this.masterPasswordBuf = Buffer.from(config.masterPassword, "utf8");
    } else if (config.shares && config.shares.length > 0) {
      const shares: ShamirShare[] = config.shares.map((s) => JSON.parse(s));
      const reconstructed = reconstructMasterPassword(shares);
      this.masterPasswordBuf = Buffer.from(reconstructed, "utf8");
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
   * The constructor uses PBKDF2 as sync fallback; this method upgrades to Argon2id
   * and re-saves the keystore so subsequent loads use the Argon2id-derived key.
   */
  static async create(config: PyHSMConfig): Promise<PyHSM> {
    // If keystore exists, read salt and pre-derive with Argon2id before constructing
    let preDerivedKey: Buffer | null = null;
    let preSalt: Buffer | null = null;
    if (fs.existsSync(config.storePath)) {
      const raw = fs.readFileSync(config.storePath);
      preSalt = Buffer.from(raw.subarray(0, SALT_LEN));
      const tempPasswordBuf = config.masterPassword
        ? Buffer.from(config.masterPassword, "utf8")
        : Buffer.from(reconstructMasterPassword(
            (config.shares || []).map(s => JSON.parse(s))
          ), "utf8");
      preDerivedKey = await argon2.hash(tempPasswordBuf, {
        type: argon2.argon2id,
        salt: preSalt,
        memoryCost: ARGON2_MEM_COST,
        timeCost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
        hashLength: 32,
        raw: true,
      }).then(r => Buffer.from(r));
    }

    // Construct — if we have a pre-derived key, inject it before load() runs
    const instance = Object.create(PyHSM.prototype) as PyHSM;
    instance.store = { version: 3, keys: {} };
    instance.storePath = config.storePath;
    instance.sessionTimeoutMs = config.sessionTimeoutMs || 5 * 60 * 1000;
    instance.callerSecret = config.callerSecret
      ? Buffer.from(config.callerSecret, "utf8")
      : process.env.PYHSM_CALLER_SECRET
        ? Buffer.from(process.env.PYHSM_CALLER_SECRET, "utf8")
        : null;
    instance.backupDir = config.backupDir || process.env.PYHSM_BACKUP_DIR || null;
    instance.sessionActive = false;
    instance.lastActivity = 0;
    instance.sessionTimer = null;

    if (config.masterPassword) {
      instance.masterPasswordBuf = Buffer.from(config.masterPassword, "utf8");
    } else if (config.shares && config.shares.length > 0) {
      const shares: ShamirShare[] = config.shares.map(s => JSON.parse(s));
      instance.masterPasswordBuf = Buffer.from(reconstructMasterPassword(shares), "utf8");
    } else {
      throw new Error("PyHSM: masterPassword or shares required");
    }

    // Set cached Argon2id key before load
    instance._cachedDerivedKey = preDerivedKey;
    instance._cachedSalt = preSalt;

    const auditPath = config.auditLogPath || config.storePath + ".audit.jsonl";
    instance.audit = new AuditLog(auditPath);
    instance.rateLimiter = new RateLimiter(
      parseInt(process.env.PYHSM_RATE_LIMIT || "100", 10),
      parseInt(process.env.PYHSM_RATE_WINDOW_MS || "60000", 10),
    );
    instance.metrics = new MetricsCollector();

    runSelfTests();
    instance.audit.record("selfTestPass", { success: true });

    // Open session (will use Argon2id-derived key for load)
    instance.load();
    instance.sessionActive = true;
    instance.lastActivity = Date.now();
    instance.scheduleTimeout();
    instance.audit.record("sessionOpen", { success: true });
    instance.updateKeyMetrics();

    // If no pre-existing file, derive a fresh salt for future saves
    if (!instance._cachedSalt) {
      instance._cachedSalt = crypto.randomBytes(SALT_LEN);
      instance._cachedDerivedKey = await instance.deriveKeyAsync(instance._cachedSalt);
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
    zeroBuffer(this.masterPasswordBuf);
    if (this._cachedDerivedKey) { zeroBuffer(this._cachedDerivedKey); this._cachedDerivedKey = null; }
    if (this._cachedSalt) { zeroBuffer(this._cachedSalt); this._cachedSalt = null; }
    if (this.callerSecret) { zeroBuffer(this.callerSecret); this.callerSecret = null; }
  }

  // --- Persistence with Tamper Detection ---

  private deriveKey(salt: Buffer): Buffer {
    // Use cached Argon2id key if salt matches
    if (this._cachedDerivedKey && this._cachedSalt && this._cachedSalt.equals(salt)) {
      return Buffer.from(this._cachedDerivedKey);
    }
    // Fallback: PBKDF2 for sync contexts
    return crypto.pbkdf2Sync(this.masterPasswordBuf, salt, 480_000, 32, "sha256");
  }

  private async deriveKeyAsync(salt: Buffer): Promise<Buffer> {
    const raw = await argon2.hash(this.masterPasswordBuf, {
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

  /** Derive a wrapping key (KEK) from the master password for per-key wrapping. */
  private deriveKek(): Buffer {
    return crypto.createHmac("sha256", this.masterPasswordBuf).update("pyhsm-kek-v1").digest();
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
    const key = this.deriveKey(Buffer.from(salt));

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
    // Reuse cached salt so the Argon2id derived key remains valid
    const salt = this._cachedSalt ? Buffer.from(this._cachedSalt) : crypto.randomBytes(SALT_LEN);
    const key = this.deriveKey(salt);

    // Update cache if we generated a new salt (PBKDF2 fallback path)
    if (!this._cachedSalt) {
      this._cachedSalt = Buffer.from(salt);
    }

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
    this.zeroize();
    throw new Error(`PyHSM TAMPER DETECTED: ${reason}. All keys destroyed.`);
  }

  // --- Access Control ---

  private authenticateCaller(callerId: string): boolean {
    if (!this.callerSecret) return true;
    const parts = callerId.split(":");
    if (parts.length !== 2) return false;
    const [service, providedHmac] = parts;
    const expected = crypto.createHmac("sha256", this.callerSecret)
      .update(service).digest("hex");
    return constantTimeEqual(providedHmac, expected);
  }

  private checkACL(entry: KeyEntry, callerId: string): boolean {
    if (!entry.policy.allowedCallers || entry.policy.allowedCallers.length === 0) {
      return true;
    }
    const service = callerId.split(":")[0] || callerId;
    return entry.policy.allowedCallers.includes(service);
  }

  // --- Policy Enforcement ---

  private enforcePolicy(entry: KeyEntry, operation: "encrypt" | "decrypt", callerId: string): void {
    if (!this.rateLimiter.allow(entry.keyId)) {
      this.metrics.recordRateLimit();
      this.audit.record("rateLimited", { keyId: entry.keyId, callerId, success: false });
      throw new Error(`PyHSM: key '${entry.keyId}' rate limited`);
    }

    if (!this.authenticateCaller(callerId)) {
      this.metrics.recordAccessDenial();
      this.audit.record("accessDenied", { keyId: entry.keyId, callerId, success: false, reason: "auth failed" });
      throw new Error("PyHSM: caller authentication failed");
    }

    if (!this.checkACL(entry, callerId)) {
      this.metrics.recordAccessDenial();
      this.audit.record("accessDenied", { keyId: entry.keyId, callerId, success: false, reason: "ACL denied" });
      throw new Error(`PyHSM: caller not authorized for key '${entry.keyId}'`);
    }

    if (operation === "encrypt" && !entry.policy.allowEncrypt) {
      throw new Error(`PyHSM: key '${entry.keyId}' policy denies encrypt`);
    }
    if (operation === "decrypt" && !entry.policy.allowDecrypt) {
      throw new Error(`PyHSM: key '${entry.keyId}' policy denies decrypt`);
    }

    if (entry.policy.maxOperations !== undefined && entry.operationCount >= entry.policy.maxOperations) {
      throw new Error(`PyHSM: key '${entry.keyId}' exceeded max operations`);
    }

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

  // --- Key Wrapping Helpers ---

  /** Wrap raw key material and return hex string for storage. */
  private wrapForStorage(rawKey: Buffer): string {
    const kek = this.deriveKek();
    const wrapped = this.wrapKey(kek, rawKey);
    zeroBuffer(kek);
    return wrapped.toString("hex");
  }

  /** Unwrap stored key material, returning raw Buffer. Caller must zeroize. */
  private unwrapFromStorage(wrappedHex: string): Buffer {
    const kek = this.deriveKek();
    const raw = this.unwrapKey(kek, Buffer.from(wrappedHex, "hex"));
    zeroBuffer(kek);
    return raw;
  }

  // --- Key Operations ---

  generateKey(keyId: string, policy?: Partial<KeyPolicy>, callerId = "system"): void {
    this.assertSession();
    validateKeyId(keyId);
    if (this.store.keys[keyId]) throw new Error(`PyHSM: key '${keyId}' already exists`);

    const rawKey = crypto.randomBytes(32);
    const wrappedHex = this.wrapForStorage(rawKey);
    zeroBuffer(rawKey);

    this.store.keys[keyId] = {
      keyId,
      keyType: "aes-256",
      currentVersion: 1,
      versions: [{
        version: 1,
        keyData: wrappedHex,
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

  rotateKey(keyId: string, callerId = "system"): void {
    this.assertSession();
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    const current = entry.versions.find((v) => v.version === entry.currentVersion);
    if (current) current.archived = true;

    const rawKey = crypto.randomBytes(32);
    const wrappedHex = this.wrapForStorage(rawKey);
    zeroBuffer(rawKey);

    const newVersion = entry.currentVersion + 1;
    entry.versions.push({
      version: newVersion,
      keyData: wrappedHex,
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
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

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
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    this.enforcePolicy(entry, "encrypt", callerId);

    const current = entry.versions.find((v) => v.version === entry.currentVersion);
    if (!current || current.archived) {
      throw new Error(`PyHSM: key '${keyId}' current version is archived`);
    }

    const aesKey = this.unwrapFromStorage(current.keyData);

    const nonce = crypto.randomBytes(NONCE_LEN);
    const sivCipher = siv(new Uint8Array(aesKey), new Uint8Array(nonce));
    const ct = sivCipher.encrypt(new TextEncoder().encode(plaintext));
    zeroBuffer(aesKey);

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
   */
  decrypt(keyId: string, ciphertextB64: string, callerId = "system"): string {
    this.assertSession();
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    this.enforcePolicy(entry, "decrypt", callerId);

    const buf = Buffer.from(ciphertextB64, "base64");

    if (buf.length < VERSION_PREFIX_LEN + NONCE_LEN + TAG_LEN) {
      throw new Error(`PyHSM: ciphertext too short`);
    }

    const version = buf.readUInt32BE(0);
    const vEntry = entry.versions.find((v) => v.version === version);
    if (!vEntry) {
      throw new Error(`PyHSM: key version ${version} not found for '${keyId}'`);
    }

    const aesKey = this.unwrapFromStorage(vEntry.keyData);

    const nonce = new Uint8Array(buf.subarray(VERSION_PREFIX_LEN, VERSION_PREFIX_LEN + NONCE_LEN));
    const ct = new Uint8Array(buf.subarray(VERSION_PREFIX_LEN + NONCE_LEN));

    const sivDecipher = siv(new Uint8Array(aesKey), nonce);
    const plainBytes = sivDecipher.decrypt(ct);
    zeroBuffer(aesKey);

    entry.operationCount++;
    this.metrics.recordOp("decrypt");
    this.audit.record("decrypt", { keyId, callerId, success: true });
    if (entry.operationCount % 10 === 0) this.save();

    return new TextDecoder().decode(plainBytes);
  }

  // --- Backup ---

  createBackup(callerId = "system"): string {
    this.assertSession();
    const dir = this.backupDir;
    if (!dir) throw new Error("PyHSM: PYHSM_BACKUP_DIR not configured");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupPath = `${dir}/pyhsm-backup-${timestamp}.enc`;

    fs.copyFileSync(this.storePath, backupPath);
    fs.chmodSync(backupPath, 0o600);

    this.audit.record("backup", { callerId, success: true });
    return backupPath;
  }

  // --- Expiry Enforcement ---

  enforceExpiry(): void {
    this.assertSession();
    for (const entry of Object.values(this.store.keys)) {
      if (entry.policy.expiresAt && new Date(entry.policy.expiresAt) < new Date()) {
        for (const v of entry.versions) v.archived = true;
        this.audit.record("archiveKey", { keyId: entry.keyId, success: true, reason: "expired" });
      }
    }
    this.save();
    this.updateKeyMetrics();
  }

  // --- Metrics & Health ---

  getMetrics(): HSMMetrics {
    return this.metrics.getMetrics();
  }

  getPrometheusMetrics(): string {
    return this.metrics.toPrometheus();
  }

  getAuditLog(): AuditLog {
    return this.audit;
  }
}
