"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLog = void 0;
/**
 * PyHSM Externalized Audit Log
 *
 * - Append-only file outside the encrypted keystore
 * - Each entry is HMAC-chained: HMAC(entry + prevHMAC) → tamper-evident
 * - Supports log shipping via optional webhook
 */
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_fs_1 = __importDefault(require("node:fs"));
const HMAC_KEY_ENV = "PYHSM_AUDIT_HMAC_KEY";
class AuditLog {
    logPath;
    hmacKey;
    lastHmac = "0".repeat(64);
    sequence = 0;
    webhookUrl;
    constructor(logPath, webhookUrl) {
        this.logPath = logPath;
        this.webhookUrl = webhookUrl || process.env.PYHSM_AUDIT_WEBHOOK || null;
        // Derive HMAC key from env or generate deterministically from log path
        const envKey = process.env[HMAC_KEY_ENV];
        this.hmacKey = envKey
            ? Buffer.from(envKey, "hex")
            : node_crypto_1.default.createHash("sha256").update("pyhsm-audit-" + logPath).digest();
        this.loadLastState();
    }
    loadLastState() {
        if (!node_fs_1.default.existsSync(this.logPath))
            return;
        const content = node_fs_1.default.readFileSync(this.logPath, "utf8").trim();
        if (!content)
            return;
        const lines = content.split("\n");
        const lastLine = lines[lines.length - 1];
        try {
            const entry = JSON.parse(lastLine);
            this.lastHmac = entry.hmac || this.lastHmac;
            this.sequence = entry.sequence + 1;
        }
        catch {
            // Corrupted last line — continue from what we have
            this.sequence = lines.length;
        }
    }
    computeHmac(entry) {
        const payload = JSON.stringify(entry) + this.lastHmac;
        return node_crypto_1.default.createHmac("sha256", this.hmacKey).update(payload).digest("hex");
    }
    record(operation, opts) {
        const entry = {
            timestamp: new Date().toISOString(),
            sequence: this.sequence,
            operation,
            keyId: opts.keyId,
            callerId: opts.callerId,
            success: opts.success,
            reason: opts.reason,
        };
        const hmac = this.computeHmac(entry);
        const fullEntry = { ...entry, hmac };
        // Append to file
        const line = JSON.stringify(fullEntry) + "\n";
        node_fs_1.default.appendFileSync(this.logPath, line, { mode: 0o600 });
        this.lastHmac = hmac;
        this.sequence++;
        // Fire-and-forget webhook
        if (this.webhookUrl) {
            this.shipToWebhook(fullEntry).catch(() => { });
        }
    }
    /** Verify integrity of the entire audit log. Returns first corrupted sequence or -1 if clean. */
    verify() {
        if (!node_fs_1.default.existsSync(this.logPath))
            return -1;
        const lines = node_fs_1.default.readFileSync(this.logPath, "utf8").trim().split("\n");
        let prevHmac = "0".repeat(64);
        for (const line of lines) {
            if (!line)
                continue;
            const entry = JSON.parse(line);
            const { hmac, ...rest } = entry;
            const expected = node_crypto_1.default.createHmac("sha256", this.hmacKey)
                .update(JSON.stringify(rest) + prevHmac)
                .digest("hex");
            if (hmac !== expected)
                return entry.sequence;
            prevHmac = hmac;
        }
        return -1;
    }
    async shipToWebhook(entry) {
        if (!this.webhookUrl)
            return;
        try {
            await fetch(this.webhookUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(entry),
                signal: AbortSignal.timeout(5000),
            });
        }
        catch {
            // Best-effort — don't block HSM operations
        }
    }
}
exports.AuditLog = AuditLog;
//# sourceMappingURL=audit.js.map