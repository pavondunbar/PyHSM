/**
 * PyHSM Module Exports
 */
export { PyHSM } from "./core";
export { AuditLog } from "./audit";
export { RateLimiter } from "./rate-limiter";
export { MetricsCollector } from "./metrics";
export { runSelfTests, enableFipsIfRequested, isFipsEnabled } from "./self-test";
export { splitMasterPassword, reconstructMasterPassword, splitSecret, reconstructSecret } from "./shamir";
export type { ShamirShare } from "./shamir";
export type * from "./types";

import { PyHSM } from "./core";
import type { PyHSMConfig } from "./types";

// --- Singleton ---
let instance: PyHSM | null = null;

export function getPyHSM(): PyHSM {
  if (!instance) {
    const config: PyHSMConfig = {
      storePath: process.env.PYHSM_KEYSTORE_PATH || "./pyhsm-keystore.enc",
      masterPassword: process.env.PYHSM_MASTER_PASSWORD,
      auditLogPath: process.env.PYHSM_AUDIT_LOG_PATH,
      backupDir: process.env.PYHSM_BACKUP_DIR,
      callerSecret: process.env.PYHSM_CALLER_SECRET,
      sessionTimeoutMs: parseInt(process.env.PYHSM_SESSION_TIMEOUT_MS || "300000", 10),
    };

    // Support Shamir shares via comma-separated JSON
    if (!config.masterPassword && process.env.PYHSM_SHARES) {
      config.shares = process.env.PYHSM_SHARES.split(",");
    }

    instance = new PyHSM(config);
  }
  return instance;
}

export function resetPyHSM(): void {
  if (instance) instance.closeSession();
  instance = null;
}

// Cleanup on exit
process.on("exit", () => { if (instance) instance.closeSession(); });

/**
 * Drop-in replacements for vault.ts
 */
export function hsmEncryptSecret(plaintext: string, _keyHex?: string): string {
  const keyId = process.env.PYHSM_KEY_ID || "pyhsm-master";
  return getPyHSM().encrypt(keyId, plaintext);
}

export function hsmDecryptSecret(ciphertextB64: string, _keyHex?: string): string {
  const keyId = process.env.PYHSM_KEY_ID || "pyhsm-master";
  return getPyHSM().decrypt(keyId, ciphertextB64);
}
