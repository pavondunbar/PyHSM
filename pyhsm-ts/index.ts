/**
 * PyHSM Module Exports
 */
export { PyHSM } from "./core.js";
export { AuditLog } from "./audit.js";
export { RateLimiter } from "./rate-limiter.js";
export { MetricsCollector } from "./metrics.js";
export { runSelfTests, enableFipsIfRequested, isFipsEnabled } from "./self-test.js";
export { splitMasterPassword, reconstructMasterPassword, splitSecret, reconstructSecret } from "./shamir.js";
export type { ShamirShare } from "./shamir.js";
export type * from "./types.js";

import { PyHSM } from "./core.js";
import type { PyHSMConfig } from "./types.js";

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

process.on("exit", () => { if (instance) instance.closeSession(); });

export function hsmEncryptSecret(plaintext: string, _keyHex?: string): string {
  const keyId = process.env.PYHSM_KEY_ID || "pyhsm-master";
  return getPyHSM().encrypt(keyId, plaintext);
}

export function hsmDecryptSecret(ciphertextB64: string, _keyHex?: string): string {
  const keyId = process.env.PYHSM_KEY_ID || "pyhsm-master";
  return getPyHSM().decrypt(keyId, ciphertextB64);
}
