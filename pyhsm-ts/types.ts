/**
 * PyHSM Type Definitions
 */

// --- Key ID validation ---
const KEY_ID_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

export function validateKeyId(keyId: string): void {
  if (!KEY_ID_REGEX.test(keyId)) {
    throw new Error(
      `PyHSM: invalid key ID '${keyId}'. ` +
      `Must be 1-128 chars, start with alphanumeric, contain only [a-zA-Z0-9._-]`
    );
  }
}

// --- Key Policies ---
export interface KeyPolicy {
  allowEncrypt: boolean;
  allowDecrypt: boolean;
  maxOperations?: number;
  expiresAt?: string; // ISO timestamp
  allowedCallers?: string[]; // caller IDs that can use this key
}

// --- Key Versioning ---
export interface KeyVersion {
  version: number;
  keyData: string; // hex-encoded wrapped key (AES-KWP)
  createdAt: string;
  archived: boolean; // archived = can decrypt only, not encrypt
}

// --- Key Entry ---
export interface KeyEntry {
  keyId: string;
  keyType: string;
  currentVersion: number;
  versions: KeyVersion[];
  policy: KeyPolicy;
  operationCount: number;
  createdAt: string;
}

// --- Keystore Format ---
export interface KeystoreData {
  version: 3;
  keys: Record<string, KeyEntry>;
}

// --- Audit ---
export type AuditOperation =
  | "encrypt"
  | "decrypt"
  | "generateKey"
  | "destroyKey"
  | "rotateKey"
  | "archiveKey"
  | "sessionOpen"
  | "sessionClose"
  | "tamperDetected"
  | "selfTestPass"
  | "selfTestFail"
  | "rateLimited"
  | "accessDenied"
  | "backup";

export interface AuditEntry {
  timestamp: string;
  sequence: number;
  operation: AuditOperation;
  keyId?: string;
  callerId?: string;
  success: boolean;
  reason?: string;
  hmac?: string; // chain HMAC for tamper detection
}

// --- Metrics ---
export interface HSMMetrics {
  totalOperations: number;
  encryptOps: number;
  decryptOps: number;
  errors: number;
  rateLimitHits: number;
  accessDenials: number;
  activeKeys: number;
  archivedKeys: number;
  uptimeMs: number;
  lastOperationAt: string | null;
}

// --- IPC Messages ---
export type IPCRequest =
  | { type: "encrypt"; keyId: string; plaintext: string; callerId: string }
  | { type: "decrypt"; keyId: string; ciphertext: string; callerId: string }
  | { type: "generateKey"; keyId: string; policy?: Partial<KeyPolicy>; callerId: string }
  | { type: "destroyKey"; keyId: string; callerId: string }
  | { type: "rotateKey"; keyId: string; callerId: string }
  | { type: "metrics"; callerId: string }
  | { type: "backup"; callerId: string }
  | { type: "health"; callerId: string };

export type IPCResponse =
  | { ok: true; data: unknown }
  | { ok: false; error: string };

// --- Config ---
export interface PyHSMConfig {
  storePath: string;
  masterPassword?: string;
  shares?: string[]; // Shamir shares for M-of-N unlock
  threshold?: number;
  auditLogPath?: string;
  backupDir?: string;
  sessionTimeoutMs?: number;
  socketPath?: string;
  callerSecret?: string; // shared secret for IPC auth
}
