/**
 * PyHSM Type Definitions
 */
export declare function validateKeyId(keyId: string): void;
export interface KeyPolicy {
    allowEncrypt: boolean;
    allowDecrypt: boolean;
    maxOperations?: number;
    expiresAt?: string;
    allowedCallers?: string[];
}
export interface KeyVersion {
    version: number;
    keyData: string;
    createdAt: string;
    archived: boolean;
}
export interface KeyEntry {
    keyId: string;
    keyType: string;
    currentVersion: number;
    versions: KeyVersion[];
    policy: KeyPolicy;
    operationCount: number;
    createdAt: string;
}
export interface KeystoreData {
    version: 3;
    keys: Record<string, KeyEntry>;
}
export type AuditOperation = "encrypt" | "decrypt" | "generateKey" | "destroyKey" | "rotateKey" | "archiveKey" | "sessionOpen" | "sessionClose" | "tamperDetected" | "selfTestPass" | "selfTestFail" | "rateLimited" | "accessDenied" | "backup";
export interface AuditEntry {
    timestamp: string;
    sequence: number;
    operation: AuditOperation;
    keyId?: string;
    callerId?: string;
    success: boolean;
    reason?: string;
    hmac?: string;
}
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
export type IPCRequest = {
    type: "encrypt";
    keyId: string;
    plaintext: string;
    callerId: string;
} | {
    type: "decrypt";
    keyId: string;
    ciphertext: string;
    callerId: string;
} | {
    type: "generateKey";
    keyId: string;
    policy?: Partial<KeyPolicy>;
    callerId: string;
} | {
    type: "destroyKey";
    keyId: string;
    callerId: string;
} | {
    type: "rotateKey";
    keyId: string;
    callerId: string;
} | {
    type: "metrics";
    callerId: string;
} | {
    type: "backup";
    callerId: string;
} | {
    type: "health";
    callerId: string;
};
export type IPCResponse = {
    ok: true;
    data: unknown;
} | {
    ok: false;
    error: string;
};
export interface PyHSMConfig {
    storePath: string;
    masterPassword?: string;
    shares?: string[];
    threshold?: number;
    auditLogPath?: string;
    backupDir?: string;
    sessionTimeoutMs?: number;
    socketPath?: string;
    callerSecret?: string;
}
//# sourceMappingURL=types.d.ts.map