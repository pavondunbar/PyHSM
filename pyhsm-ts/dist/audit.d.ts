import type { AuditOperation } from "./types.js";
export declare class AuditLog {
    private logPath;
    private hmacKey;
    private lastHmac;
    private sequence;
    private webhookUrl;
    constructor(logPath: string, webhookUrl?: string);
    private loadLastState;
    private computeHmac;
    record(operation: AuditOperation, opts: {
        keyId?: string;
        callerId?: string;
        success: boolean;
        reason?: string;
    }): void;
    /** Verify integrity of the entire audit log. Returns first corrupted sequence or -1 if clean. */
    verify(): number;
    private shipToWebhook;
}
//# sourceMappingURL=audit.d.ts.map