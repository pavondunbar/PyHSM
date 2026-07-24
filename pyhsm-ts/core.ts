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
import { SecureBuffer, zeroBuffer } from "./secure-buffer.js";
import type { StorageBackend } from "./storage-backend.js";
import { FileBackend } from "./storage-backend.js";
import { exportSymmetricJwk, exportAsymmetricJwk, importJwk, type JWK } from "./jwk.js";

const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const VERSION_PREFIX_LEN = 4; // 4 bytes = version number in ciphertext

// Argon2id parameters (OWASP recommended)
const ARGON2_MEM_COST = 65536; // 64 MB
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 4;

// Maximum plaintext size (64 MB) — prevents OOM denial-of-service
const MAX_PLAINTEXT_SIZE = 64 * 1024 * 1024;

// --- Constant-time utilities ---
function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // Pad the shorter buffer to prevent length-based timing leak
  const maxLen = Math.max(bufA.length, bufB.length);
  const paddedA = Buffer.alloc(maxLen);
  const paddedB = Buffer.alloc(maxLen);
  bufA.copy(paddedA);
  bufB.copy(paddedB);
  // timingSafeEqual requires same length — now guaranteed
  const equal = crypto.timingSafeEqual(paddedA, paddedB);
  // Also check original lengths match (after constant-time compare)
  return equal && bufA.length === bufB.length;
}

/**
 * Return the appropriate hash algorithm for the given EC key type.
 * NIST recommendations: P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512
 * secp256k1 → SHA-256 (standard for Bitcoin/Ethereum ECDSA)
 */
function ecHashForKeyType(keyType: string): string {
  if (keyType === "ec-p384") return "sha384";
  if (keyType === "ec-p521") return "sha512";
  return "sha256"; // ec-p256, ec-secp256k1 default
}

export class PyHSM {
  private store: KeystoreData = { version: 3, keys: {}, kekSalt: undefined };
  private storePath!: string;
  private backend!: StorageBackend;
  private masterPasswordBuf: Buffer = Buffer.alloc(0);
  private sessionActive = false;
  private lastActivity = 0;
  private sessionTimer: ReturnType<typeof setTimeout> | null = null;
  private sessionTimeoutMs!: number;

  // Derived key cache — persists across save/load within a session
  private _cachedDerivedKey: Buffer | null = null;
  private _cachedSalt: Buffer | null = null;

  // Dirty flag: true when operationCount changes need to be flushed.
  // encrypt/decrypt/sign/verify increment operationCount in memory and set
  // this flag. The next structural mutation (rotate, destroy, close) or
  // explicit flushDirty() will persist them. This eliminates a full
  // serialize+encrypt+write cycle on every read-path operation.
  private _dirty = false;

  // Sub-modules
  private audit!: AuditLog;
  private rateLimiter!: RateLimiter;
  private metrics!: MetricsCollector;
  private callerSecret: Buffer | null = null;
  private backupDir: string | null = null;

  constructor(config: PyHSMConfig) {
    // When called from create(), config is the sentinel — skip all initialization
    if ((config as unknown) === PyHSM._createSentinel) return;

    this.initFields(config);

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
    // Construct instance without calling the normal constructor (skip sync open)
    const instance = new PyHSM(PyHSM._createSentinel as unknown as PyHSMConfig);
    instance.initFields(config);

    // If keystore exists, pre-derive with Argon2id before loading
    if (instance.backend.exists()) {
      const raw = instance.backend.read();
      instance._cachedSalt = Buffer.from(raw.subarray(0, SALT_LEN));
      instance._cachedDerivedKey = await instance.deriveKeyAsync(instance._cachedSalt);
    }

    // Run self-tests
    runSelfTests();
    instance.audit.record("selfTestPass", { success: true });

    // Open session (will use Argon2id-derived key for load)
    instance.load();
    instance.sessionActive = true;
    instance.lastActivity = Date.now();
    instance.scheduleTimeout();
    instance.audit.record("sessionOpen", { success: true });
    instance.updateKeyMetrics();

    // Ensure Argon2id key is cached for saves on new keystores
    if (!instance._cachedDerivedKey || !instance._cachedSalt) {
      instance._cachedSalt = crypto.randomBytes(SALT_LEN);
      instance._cachedDerivedKey = await instance.deriveKeyAsync(instance._cachedSalt);
    }

    return instance;
  }

  /** Sentinel value to distinguish internal create() calls from user constructor calls. */
  private static readonly _createSentinel = Symbol("PyHSM.create");

  /**
   * Shared initialization logic used by both the constructor and create().
   * Resolves the storage backend, master password, and sub-modules.
   */
  private initFields(config: PyHSMConfig): void {
    this.storePath = config.storePath;
    this.backend = config.backend || new FileBackend(config.storePath);
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
    // IMPORTANT: save() MUST precede zeroize(). save() needs masterPasswordBuf
    // to derive encryption keys. Reordering these calls will silently corrupt
    // the keystore (encrypting with a zeroed key).
    this.save();
    this.zeroize();
    this.sessionActive = false;
    if (this.sessionTimer) { clearTimeout(this.sessionTimer); this.sessionTimer = null; }
  }

  /**
   * Mark the in-memory store as dirty (operation counts changed).
   * The actual save is deferred until the next mutation or session close.
   */
  private markDirty(): void {
    this._dirty = true;
  }

  /**
   * Flush pending operation-count changes to disk if dirty.
   * Called before mutations (generate, rotate, destroy) and on close
   * so that operation counts are never lost.
   */
  private flushIfDirty(): void {
    if (this._dirty) {
      this.save();
      this._dirty = false;
    }
  }

  private zeroize(): void {
    // Overwrite keyData strings — V8 strings are immutable so we can only
    // replace the reference, but SecureBuffer wraps the master password
    // Buffer and fill(0)s it deterministically.
    for (const entry of Object.values(this.store.keys)) {
      for (const v of entry.versions) {
        v.keyData = "0".repeat(v.keyData.length);
      }
    }
    this.store = { version: 3, keys: {}, kekSalt: undefined };
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

  /**
   * Derive separate encryption and MAC keys via HKDF-Expand.
   * Returns { encKey, macKey } — each 32 bytes. Caller must zeroize both.
   */
  private deriveSubkeys(salt: Buffer): { encKey: Buffer; macKey: Buffer } {
    const master = this.deriveKey(salt);
    const encKey = Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), "pyhsm-enc-v1", 32));
    const macKey = Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), "pyhsm-mac-v1", 32));
    zeroBuffer(master);
    return { encKey, macKey };
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

  /**
   * AES-KWP (RFC 5649) key wrapping — wraps key material for storage.
   *
   * The RFC 5649 Alternative Initial Value (AIV) constant is the 4-byte
   * big-endian value 0xa65959a6 (NOT four repetitions of 0xa6).
   * Node.js's aes-256-wrap-pad cipher expects this 4-byte IV.
   */
  private wrapKey(kek: Buffer, keyData: Buffer): Buffer {
    const algo: string = "aes-256-wrap-pad";
    // RFC 5649 §3 AIV prefix: 0xa65959a6 in big-endian
    const aiv = Buffer.from([0xa6, 0x59, 0x59, 0xa6]);
    const cipher = crypto.createCipheriv(algo, kek, aiv);
    return Buffer.concat([cipher.update(keyData), cipher.final()]);
  }

  /** AES-KWP unwrap (RFC 5649). Uses the same AIV constant. */
  private unwrapKey(kek: Buffer, wrapped: Buffer): Buffer {
    const algo: string = "aes-256-wrap-pad";
    const aiv = Buffer.from([0xa6, 0x59, 0x59, 0xa6]);
    const decipher = crypto.createDecipheriv(algo, kek, aiv);
    return Buffer.concat([decipher.update(wrapped), decipher.final()]);
  }

  /** Derive a wrapping key (KEK) from the master password via PBKDF2→HKDF.
   *
   * Uses a dedicated KEK salt stored inside the encrypted keystore JSON.
   * The KEK is derived through: PBKDF2(password, kekSalt) → HKDF-Expand("pyhsm-kek-v1")
   *
   * This ensures the KEK benefits from the same key-stretching as other subkeys,
   * and cannot be derived without both the master password AND the salt
   * (which is encrypted at rest).
   *
   * Falls back to legacy HMAC derivation for keystores created before this change
   * (those lack a kekSalt field). Legacy keystores are migrated on first write.
   */
  private deriveKek(): Buffer {
    const kekSalt = this.store.kekSalt;
    if (kekSalt) {
      // New derivation: full PBKDF2 + HKDF path (matches Python layer)
      const saltBuf = Buffer.from(kekSalt, "hex");
      const master = this.deriveKey(saltBuf);
      const kek = Buffer.from(
        crypto.hkdfSync("sha256", master, Buffer.alloc(0), "pyhsm-kek-v1", 32)
      );
      zeroBuffer(master);
      return kek;
    }
    // Legacy fallback for pre-existing keystores without kekSalt
    return crypto.createHmac("sha256", this.masterPasswordBuf).update("pyhsm-kek-v1").digest();
  }

  private computeHmac(data: Buffer, key: Buffer): Buffer {
    return crypto.createHmac("sha256", key).update(data).digest();
  }

  private load(): void {
    if (!this.backend.exists()) {
      // New keystore — initialize kekSalt so all key wrapping uses PBKDF2→HKDF from the start
      this.store.kekSalt = crypto.randomBytes(SALT_LEN).toString("hex");
      return;
    }
    const raw = this.backend.read();

    if (raw.length < SALT_LEN + 32 + NONCE_LEN + TAG_LEN) {
      this.handleTamper("Keystore file too short");
      return;
    }

    const salt = raw.subarray(0, SALT_LEN);
    const storedHmac = raw.subarray(SALT_LEN, SALT_LEN + 32);
    const payload = raw.subarray(SALT_LEN + 32);
    const { encKey, macKey } = this.deriveSubkeys(Buffer.from(salt));

    const expectedHmac = this.computeHmac(payload, macKey);
    if (!crypto.timingSafeEqual(storedHmac, expectedHmac)) {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
      this.handleTamper("HMAC verification failed");
      return;
    }

    const nonce = payload.subarray(0, NONCE_LEN);
    const ct = payload.subarray(NONCE_LEN);
    const tag = ct.subarray(ct.length - TAG_LEN);
    const encrypted = ct.subarray(0, ct.length - TAG_LEN);

    const decipher = crypto.createDecipheriv("aes-256-gcm", encKey, nonce);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    zeroBuffer(encKey);
    zeroBuffer(macKey);

    const parsed = JSON.parse(plain.toString("utf8"));
    zeroBuffer(plain);

    // Migrate from v2 format
    if (!parsed.version || parsed.version < 3) {
      this.store = { version: 3, keys: {}, kekSalt: undefined };
      const oldKeys = parsed.keys || parsed;
      for (const [id, entry] of Object.entries(oldKeys)) {
        const e = entry as Record<string, unknown>;
        this.store.keys[id] = {
          keyId: id,
          keyType: (e.keyType || e.key_type || "aes-256") as string,
          currentVersion: 1,
          versions: [{
            version: 1,
            keyData: (e.keyData || e.key_data || "") as string,
            createdAt: (e.createdAt || e.created_at || new Date().toISOString()) as string,
            archived: false,
          }],
          policy: (e.policy || { allowEncrypt: true, allowDecrypt: true }) as KeyPolicy,
          operationCount: (e.operationCount || 0) as number,
          createdAt: (e.createdAt || e.created_at || new Date().toISOString()) as string,
        };
      }
    } else {
      this.store = parsed;
    }

    // Migrate KEK derivation: if keystore lacks a kekSalt, generate one
    // and re-wrap all key material from legacy HMAC KEK to PBKDF2→HKDF KEK
    if (!this.store.kekSalt) {
      this.migrateKek();
    }
  }

  /**
   * Migrate existing key material from legacy HMAC-based KEK to the new
   * PBKDF2→HKDF KEK derivation path. Generates a kekSalt, unwraps all keys
   * with the old KEK, and re-wraps with the new KEK.
   */
  private migrateKek(): void {
    // Derive old (legacy) KEK via simple HMAC
    const oldKek = crypto.createHmac("sha256", this.masterPasswordBuf)
      .update("pyhsm-kek-v1").digest();

    // Generate new KEK salt and derive new KEK via PBKDF2→HKDF
    const newKekSalt = crypto.randomBytes(SALT_LEN);
    this.store.kekSalt = newKekSalt.toString("hex");
    const master = this.deriveKey(newKekSalt);
    const newKek = Buffer.from(
      crypto.hkdfSync("sha256", master, Buffer.alloc(0), "pyhsm-kek-v1", 32)
    );
    zeroBuffer(master);

    try {
      for (const entry of Object.values(this.store.keys)) {
        for (const v of entry.versions) {
          if (!v.keyData) continue;
          const wrapped = Buffer.from(v.keyData, "hex");
          // Unwrap with old KEK, re-wrap with new KEK
          const raw = this.unwrapKey(oldKek, wrapped);
          const rewrapped = this.wrapKey(newKek, raw);
          zeroBuffer(raw);
          v.keyData = rewrapped.toString("hex");
        }
      }
    } finally {
      zeroBuffer(oldKek);
      zeroBuffer(newKek);
    }

    // Save immediately to persist the migration
    this.save();
  }

  private save(): void {
    // Reuse cached salt so the Argon2id derived key remains valid
    const salt = this._cachedSalt ? Buffer.from(this._cachedSalt) : crypto.randomBytes(SALT_LEN);
    const { encKey, macKey } = this.deriveSubkeys(salt);

    // Update cache if we generated a new salt (PBKDF2 fallback path)
    if (!this._cachedSalt) {
      this._cachedSalt = Buffer.from(salt);
    }

    const nonce = crypto.randomBytes(NONCE_LEN);
    const cipher = crypto.createCipheriv("aes-256-gcm", encKey, nonce);
    const ct = Buffer.concat([
      cipher.update(JSON.stringify(this.store), "utf8"),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    const payload = Buffer.concat([nonce, ct]);
    const hmac = this.computeHmac(payload, macKey);
    zeroBuffer(encKey);
    zeroBuffer(macKey);

    const fileData = Buffer.concat([salt, hmac, payload]);
    this.backend.write(fileData);
    this._dirty = false;
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

  private enforcePolicy(entry: KeyEntry, operation: "encrypt" | "decrypt" | "sign", callerId: string): void {
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
    if (operation === "sign" && entry.policy.allowSign === false) {
      throw new Error(`PyHSM: key '${entry.keyId}' policy denies sign`);
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
    const kekBuf = SecureBuffer.wrap(this.deriveKek());
    try {
      const wrapped = this.wrapKey(kekBuf.buf, rawKey);
      return wrapped.toString("hex");
    } finally {
      kekBuf.dispose();
    }
  }

  /** Unwrap stored key material, returning raw Buffer. Caller must zeroize. */
  private unwrapFromStorage(wrappedHex: string): Buffer {
    const kekBuf = SecureBuffer.wrap(this.deriveKek());
    try {
      return this.unwrapKey(kekBuf.buf, Buffer.from(wrappedHex, "hex"));
    } finally {
      kekBuf.dispose();
    }
  }

  // --- Key Operations ---

  generateKey(keyId: string, keyTypeOrPolicy?: string | Partial<KeyPolicy>, policyOrCallerId?: Partial<KeyPolicy> | string, callerIdArg?: string): void {
    this.assertSession();
    this.flushIfDirty();
    validateKeyId(keyId);
    if (this.store.keys[keyId]) throw new Error(`PyHSM: key '${keyId}' already exists`);

    // Resolve overloaded arguments:
    //   generateKey(id, policy?, callerId?)          — original AES-only API
    //   generateKey(id, keyType, policy?, callerId?) — new multi-type API
    let keyType = "aes-256";
    let policy: Partial<KeyPolicy> | undefined;
    let callerId = "system";

    if (typeof keyTypeOrPolicy === "string") {
      // generateKey(id, keyType, policy?, callerId?)
      keyType = keyTypeOrPolicy;
      if (typeof policyOrCallerId === "object") {
        policy = policyOrCallerId;
        if (callerIdArg) callerId = callerIdArg;
      } else if (typeof policyOrCallerId === "string") {
        callerId = policyOrCallerId;
      }
    } else if (typeof keyTypeOrPolicy === "object") {
      // generateKey(id, policy, callerId?)
      policy = keyTypeOrPolicy;
      if (typeof policyOrCallerId === "string") callerId = policyOrCallerId;
    } else if (typeof keyTypeOrPolicy === "undefined") {
      // generateKey(id) — defaults
      if (typeof policyOrCallerId === "string") callerId = policyOrCallerId;
    }

    let wrappedHex: string;
    let publicKeyPem: string | undefined;

    if (keyType === "aes-256" || keyType === "aes-128") {
      const keyLen = keyType === "aes-256" ? 32 : 16;
      const rawKey = crypto.randomBytes(keyLen);
      wrappedHex = this.wrapForStorage(rawKey);
      zeroBuffer(rawKey);
    } else if (keyType === "rsa-2048" || keyType === "rsa-4096") {
      const modulusLength = keyType === "rsa-2048" ? 2048 : 4096;
      const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength,
        publicExponent: 65537,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      wrappedHex = this.wrapForStorage(Buffer.from(privateKey as string, "utf8"));
      publicKeyPem = publicKey as string;
    } else if (keyType === "ec-p256" || keyType === "ec-p384" || keyType === "ec-p521" || keyType === "ec-secp256k1") {
      const namedCurve = keyType === "ec-p256" ? "P-256"
        : keyType === "ec-p384" ? "P-384"
        : keyType === "ec-p521" ? "P-521"
        : "secp256k1";
      const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
        namedCurve,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      wrappedHex = this.wrapForStorage(Buffer.from(privateKey as string, "utf8"));
      publicKeyPem = publicKey as string;
    } else if (keyType === "ed25519") {
      const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      wrappedHex = this.wrapForStorage(Buffer.from(privateKey as string, "utf8"));
      publicKeyPem = publicKey as string;
    } else {
      throw new Error(`PyHSM: unsupported key type '${keyType}'`);
    }

    this.store.keys[keyId] = {
      keyId,
      keyType,
      currentVersion: 1,
      versions: [{
        version: 1,
        keyData: wrappedHex,
        createdAt: new Date().toISOString(),
        archived: false,
      }],
      publicKeyPem,
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
    this.flushIfDirty();
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
    this.flushIfDirty();
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
   * Export a key as a JWK (JSON Web Key, RFC 7517).
   * WARNING: The returned object contains raw private key material.
   */
  exportJwk(keyId: string): JWK {
    this.assertSession();
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    const current = entry.versions.find((v) => v.version === entry.currentVersion);
    if (!current) throw new Error(`PyHSM: no current version for key '${keyId}'`);

    const rawKey = this.unwrapFromStorage(current.keyData);
    try {
      if (entry.keyType.startsWith("aes")) {
        return exportSymmetricJwk(rawKey, keyId);
      } else {
        return exportAsymmetricJwk(rawKey, keyId);
      }
    } finally {
      zeroBuffer(rawKey);
    }
  }

  /**
   * Import a key from a JWK (JSON Web Key, RFC 7517).
   * The key material is wrapped with AES-KWP before storage.
   */
  importKeyJwk(keyId: string, jwk: JWK, policy?: Partial<KeyPolicy>, callerId = "system"): void {
    this.assertSession();
    this.flushIfDirty();
    validateKeyId(keyId);
    if (this.store.keys[keyId]) throw new Error(`PyHSM: key '${keyId}' already exists`);

    const { keyType, rawKeyBytes, publicKeyPem } = importJwk(jwk);

    const wrappedHex = this.wrapForStorage(rawKeyBytes);
    zeroBuffer(rawKeyBytes);

    this.store.keys[keyId] = {
      keyId,
      keyType,
      currentVersion: 1,
      versions: [{
        version: 1,
        keyData: wrappedHex,
        createdAt: new Date().toISOString(),
        archived: false,
      }],
      publicKeyPem: publicKeyPem ?? undefined,
      policy: { allowEncrypt: true, allowDecrypt: true, ...policy },
      operationCount: 0,
      createdAt: new Date().toISOString(),
    };

    this.audit.record("generateKey", { keyId, callerId, success: true });
    this.save();
    this.updateKeyMetrics();
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

    const aesKeyBuf = SecureBuffer.wrap(this.unwrapFromStorage(current.keyData));
    let result: string;
    try {
      const plaintextBytes = new TextEncoder().encode(plaintext);
      if (plaintextBytes.length > MAX_PLAINTEXT_SIZE) {
        throw new Error(
          `PyHSM: plaintext too large (${plaintextBytes.length} bytes). ` +
          `Maximum is ${MAX_PLAINTEXT_SIZE} bytes (64 MB).`
        );
      }
      const nonce = crypto.randomBytes(NONCE_LEN);
      const sivCipher = siv(new Uint8Array(aesKeyBuf.buf), new Uint8Array(nonce));
      const ct = sivCipher.encrypt(plaintextBytes);

      const versionBuf = Buffer.alloc(VERSION_PREFIX_LEN);
      versionBuf.writeUInt32BE(current.version);
      result = Buffer.concat([versionBuf, Buffer.from(nonce), Buffer.from(ct)]).toString("base64");
    } finally {
      aesKeyBuf.dispose();
    }

    entry.operationCount++;
    this.metrics.recordOp("encrypt");
    this.audit.record("encrypt", { keyId, callerId, success: true });
    this.markDirty();

    return result;
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

    const aesKeyBuf = SecureBuffer.wrap(this.unwrapFromStorage(vEntry.keyData));
    let plainText: string;
    try {
      const nonce = new Uint8Array(buf.subarray(VERSION_PREFIX_LEN, VERSION_PREFIX_LEN + NONCE_LEN));
      const ct = new Uint8Array(buf.subarray(VERSION_PREFIX_LEN + NONCE_LEN));
      const sivDecipher = siv(new Uint8Array(aesKeyBuf.buf), nonce);
      const plainBytes = sivDecipher.decrypt(ct);
      plainText = new TextDecoder().decode(plainBytes);
    } finally {
      aesKeyBuf.dispose();
    }

    entry.operationCount++;
    this.metrics.recordOp("decrypt");
    this.audit.record("decrypt", { keyId, callerId, success: true });
    this.markDirty();

    return plainText;
  }

  // --- Sign / Verify ---

  /**
   * Sign a message using a stored RSA, EC, or Ed25519 key.
   * Returns hex-encoded signature.
   *
   * RSA keys use RSA-PSS with SHA-256.
   * EC keys use ECDSA with the NIST-recommended hash for the curve:
   *   P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512, secp256k1 → SHA-256
   * Ed25519 keys use EdDSA (no separate hash needed).
   */
  sign(keyId: string, message: string | Buffer, callerId = "system"): string {
    this.assertSession();
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    if (!entry.keyType.startsWith("rsa") && !entry.keyType.startsWith("ec") && entry.keyType !== "ed25519") {
      throw new Error(`PyHSM: signing requires an RSA, EC, or Ed25519 key`);
    }

    this.enforcePolicy(entry, "sign", callerId);

    const current = entry.versions.find((v) => v.version === entry.currentVersion);
    if (!current) throw new Error(`PyHSM: no current version for key '${keyId}'`);

    const data = typeof message === "string" ? Buffer.from(message, "utf8") : message;

    // Unwrap private key PEM
    const privateKeyPem = this.unwrapFromStorage(current.keyData);
    let sig: Buffer;
    try {
      const privateKey = crypto.createPrivateKey({
        key: privateKeyPem,
        format: "pem",
      });

      if (entry.keyType.startsWith("rsa")) {
        sig = crypto.sign("sha256", data, {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
        });
      } else if (entry.keyType === "ed25519") {
        sig = crypto.sign(null, data, privateKey);
      } else {
        // EC — select hash algorithm based on curve
        const hashAlg = ecHashForKeyType(entry.keyType);
        sig = crypto.sign(hashAlg, data, privateKey);
      }
    } finally {
      zeroBuffer(privateKeyPem);
    }

    entry.operationCount++;
    this.metrics.recordOp("sign");
    this.audit.record("sign", { keyId, callerId, success: true });
    this.markDirty();

    return sig.toString("hex");
  }

  /**
   * Verify a signature using the stored PUBLIC key.
   * Does NOT load the private key — only the public key PEM stored at generation time.
   * Returns true if valid, false otherwise.
   */
  verify(keyId: string, message: string | Buffer, signatureHex: string, callerId = "system"): boolean {
    this.assertSession();
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    if (!entry.keyType.startsWith("rsa") && !entry.keyType.startsWith("ec") && entry.keyType !== "ed25519") {
      throw new Error(`PyHSM: verification requires an RSA, EC, or Ed25519 key`);
    }

    if (!entry.publicKeyPem) {
      throw new Error(`PyHSM: key '${keyId}' has no public key`);
    }

    const data = typeof message === "string" ? Buffer.from(message, "utf8") : message;
    const sig = Buffer.from(signatureHex, "hex");

    const publicKey = crypto.createPublicKey({
      key: entry.publicKeyPem,
      format: "pem",
    });

    let valid: boolean;
    try {
      if (entry.keyType.startsWith("rsa")) {
        valid = crypto.verify("sha256", data, {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN,
        }, sig);
      } else if (entry.keyType === "ed25519") {
        valid = crypto.verify(null, data, publicKey, sig);
      } else {
        const hashAlg = ecHashForKeyType(entry.keyType);
        valid = crypto.verify(hashAlg, data, publicKey, sig);
      }
    } catch {
      valid = false;
    }

    entry.operationCount++;
    this.metrics.recordOp("verify");
    this.audit.record("verify", { keyId, callerId, success: valid });
    this.markDirty();

    return valid;
  }

  /**
   * Export the public key (PEM) for an asymmetric key.
   * Never touches the private key.
   */
  getPublicKey(keyId: string): string {
    this.assertSession();
    validateKeyId(keyId);
    const entry = this.store.keys[keyId];
    if (!entry) throw new Error(`PyHSM: key '${keyId}' not found`);

    if (entry.keyType.startsWith("aes")) {
      throw new Error(`PyHSM: AES keys have no public component`);
    }
    if (!entry.publicKeyPem) {
      throw new Error(`PyHSM: no public key stored for '${keyId}'`);
    }
    return entry.publicKeyPem;
  }

  // --- Backup ---

  createBackup(callerId = "system"): string {
    this.assertSession();
    this.flushIfDirty();
    const dir = this.backupDir;
    if (!dir) throw new Error("PyHSM: PYHSM_BACKUP_DIR not configured");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupPath = `${dir}/pyhsm-backup-${timestamp}.enc`;

    // Read current keystore data from backend and write to backup file
    const data = this.backend.read();
    fs.writeFileSync(backupPath, data, { mode: 0o600 });

    this.audit.record("backup", { callerId, success: true });
    return backupPath;
  }

  /**
   * Verify a backup file can be decrypted and has a valid HMAC.
   * Does NOT load the backup into the live store.
   * Returns true if the backup is intact, throws if tampered or unreadable.
   */
  verifyBackup(backupPath: string, callerId = "system"): boolean {
    this.assertSession();

    if (!fs.existsSync(backupPath)) {
      throw new Error(`PyHSM: backup file not found: ${backupPath}`);
    }

    const raw = fs.readFileSync(backupPath);

    if (raw.length < SALT_LEN + 32 + NONCE_LEN + TAG_LEN) {
      throw new Error(`PyHSM: backup file too short — likely corrupted: ${backupPath}`);
    }

    const salt = raw.subarray(0, SALT_LEN);
    const storedHmac = raw.subarray(SALT_LEN, SALT_LEN + 32);
    const payload = raw.subarray(SALT_LEN + 32);
    const { encKey, macKey } = this.deriveSubkeys(Buffer.from(salt));

    const expectedHmac = this.computeHmac(payload, macKey);
    if (!crypto.timingSafeEqual(storedHmac, expectedHmac)) {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
      this.audit.record("verifyBackup", { callerId, success: false });
      throw new Error(`PyHSM: backup HMAC verification FAILED — file may be corrupted or tampered: ${backupPath}`);
    }

    // Attempt decryption to confirm the file is fully readable
    const nonce = payload.subarray(0, NONCE_LEN);
    const ct = payload.subarray(NONCE_LEN);
    const tag = ct.subarray(ct.length - TAG_LEN);
    const encrypted = ct.subarray(0, ct.length - TAG_LEN);

    const decipher = crypto.createDecipheriv("aes-256-gcm", encKey, nonce);
    decipher.setAuthTag(tag);
    try {
      Buffer.concat([decipher.update(encrypted), decipher.final()]);
    } catch {
      zeroBuffer(encKey);
      zeroBuffer(macKey);
      this.audit.record("verifyBackup", { callerId, success: false });
      throw new Error(`PyHSM: backup decryption FAILED — file may be corrupted: ${backupPath}`);
    }

    zeroBuffer(encKey);
    zeroBuffer(macKey);
    this.audit.record("verifyBackup", { callerId, success: true });
    return true;
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
