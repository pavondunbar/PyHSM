import type { HSMMetrics, KeyPolicy, PyHSMConfig } from "./types.js";
import { AuditLog } from "./audit.js";
export declare class PyHSM {
    private store;
    private storePath;
    private masterPasswordBuf;
    private sessionActive;
    private lastActivity;
    private sessionTimer;
    private sessionTimeoutMs;
    private _cachedDerivedKey;
    private _cachedSalt;
    private audit;
    private rateLimiter;
    private metrics;
    private callerSecret;
    private backupDir;
    constructor(config: PyHSMConfig);
    /**
     * Async factory — uses Argon2id for key derivation (preferred).
     * The constructor uses PBKDF2 as sync fallback; this method upgrades to Argon2id
     * and re-saves the keystore so subsequent loads use the Argon2id-derived key.
     */
    static create(config: PyHSMConfig): Promise<PyHSM>;
    private openSession;
    private scheduleTimeout;
    private checkTimeout;
    private touch;
    private assertSession;
    closeSession(): void;
    private zeroize;
    private deriveKey;
    private deriveKeyAsync;
    /** AES-KWP (RFC 5649) key wrapping — wraps key material for storage. */
    private wrapKey;
    /** AES-KWP unwrap. */
    private unwrapKey;
    /** Derive a wrapping key (KEK) from the master password for per-key wrapping. */
    private deriveKek;
    private computeHmac;
    private load;
    private save;
    private handleTamper;
    private authenticateCaller;
    private checkACL;
    private enforcePolicy;
    private updateKeyMetrics;
    /** Wrap raw key material and return hex string for storage. */
    private wrapForStorage;
    /** Unwrap stored key material, returning raw Buffer. Caller must zeroize. */
    private unwrapFromStorage;
    generateKey(keyId: string, policy?: Partial<KeyPolicy>, callerId?: string): void;
    rotateKey(keyId: string, callerId?: string): void;
    destroyKey(keyId: string, callerId?: string): void;
    hasKey(keyId: string): boolean;
    /**
     * Encrypt with the current key version using AES-256-GCM-SIV (nonce misuse resistant).
     * Output format: base64(versionPrefix(4) || nonce(12) || ciphertext+tag)
     */
    encrypt(keyId: string, plaintext: string, callerId?: string): string;
    /**
     * Decrypt — reads version prefix to select the correct key version.
     */
    decrypt(keyId: string, ciphertextB64: string, callerId?: string): string;
    createBackup(callerId?: string): string;
    enforceExpiry(): void;
    getMetrics(): HSMMetrics;
    getPrometheusMetrics(): string;
    getAuditLog(): AuditLog;
}
//# sourceMappingURL=core.d.ts.map