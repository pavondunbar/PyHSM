/**
 * PyHSM Externalized Audit Log
 *
 * - Append-only file outside the encrypted keystore
 * - Each entry is HMAC-chained: HMAC(entry + prevHMAC) → tamper-evident
 * - Supports log shipping via optional webhook
 */
import crypto from "node:crypto";
import fs from "node:fs";
import type { AuditEntry, AuditOperation } from "./types.js";

const HMAC_KEY_ENV = "PYHSM_AUDIT_HMAC_KEY";

export class AuditLog {
  private logPath: string;
  private hmacKey: Buffer;
  private lastHmac: string = "0".repeat(64);
  private sequence = 0;
  private webhookUrl: string | null;

  constructor(logPath: string, webhookUrl?: string) {
    this.logPath = logPath;
    this.webhookUrl = webhookUrl || process.env.PYHSM_AUDIT_WEBHOOK || null;

    // HMAC key: from env, or generate a random key and persist it alongside the log
    const envKey = process.env[HMAC_KEY_ENV];
    if (envKey) {
      this.hmacKey = Buffer.from(envKey, "hex");
    } else {
      const keyFile = logPath + ".hmackey";
      if (fs.existsSync(keyFile)) {
        this.hmacKey = Buffer.from(fs.readFileSync(keyFile, "utf8").trim(), "hex");
      } else {
        this.hmacKey = crypto.randomBytes(32);
        fs.writeFileSync(keyFile, this.hmacKey.toString("hex"), { mode: 0o600 });
      }
    }

    this.loadLastState();
  }

  private loadLastState(): void {
    if (!fs.existsSync(this.logPath)) return;
    const content = fs.readFileSync(this.logPath, "utf8").trim();
    if (!content) return;
    const lines = content.split("\n");
    const lastLine = lines[lines.length - 1];
    try {
      const entry: AuditEntry = JSON.parse(lastLine);
      this.lastHmac = entry.hmac || this.lastHmac;
      this.sequence = entry.sequence + 1;
    } catch {
      // Corrupted last line — continue from what we have
      this.sequence = lines.length;
    }
  }

  private computeHmac(entry: Omit<AuditEntry, "hmac">): string {
    const payload = JSON.stringify(entry) + this.lastHmac;
    return crypto.createHmac("sha256", this.hmacKey).update(payload).digest("hex");
  }

  record(operation: AuditOperation, opts: {
    keyId?: string;
    callerId?: string;
    success: boolean;
    reason?: string;
  }): void {
    const entry: Omit<AuditEntry, "hmac"> = {
      timestamp: new Date().toISOString(),
      sequence: this.sequence,
      operation,
      keyId: opts.keyId,
      callerId: opts.callerId,
      success: opts.success,
      reason: opts.reason,
    };

    const hmac = this.computeHmac(entry);
    const fullEntry: AuditEntry = { ...entry, hmac };

    // Append to file
    const line = JSON.stringify(fullEntry) + "\n";
    fs.appendFileSync(this.logPath, line, { mode: 0o600 });

    this.lastHmac = hmac;
    this.sequence++;

    // Fire-and-forget webhook
    if (this.webhookUrl) {
      this.shipToWebhook(fullEntry).catch(() => {});
    }
  }

  /** Verify integrity of the entire audit log. Returns first corrupted sequence or -1 if clean. */
  verify(): number {
    if (!fs.existsSync(this.logPath)) return -1;
    const lines = fs.readFileSync(this.logPath, "utf8").trim().split("\n");
    let prevHmac = "0".repeat(64);

    for (const line of lines) {
      if (!line) continue;
      const entry: AuditEntry = JSON.parse(line);
      const { hmac, ...rest } = entry;
      const expected = crypto.createHmac("sha256", this.hmacKey)
        .update(JSON.stringify(rest) + prevHmac)
        .digest("hex");
      if (hmac !== expected) return entry.sequence;
      prevHmac = hmac;
    }
    return -1;
  }

  /**
   * Export filtered audit log entries as an array of objects.
   *
   * All fields are included (including hmac chain field) so the output
   * can be shipped directly to a SIEM (Splunk, Elasticsearch, Datadog, etc.)
   * as newline-delimited JSON.
   *
   * @param operation  Filter to a single operation type.
   * @param keyId      Filter to a specific key ID.
   * @param callerId   Filter to a specific caller ID.
   * @param since      ISO-8601 timestamp — include entries at or after this time.
   * @param until      ISO-8601 timestamp — include entries at or before this time.
   * @param onlyFailed Only include entries where success === false.
   */
  exportJsonl(opts: {
    operation?: string;
    keyId?: string;
    callerId?: string;
    since?: string;
    until?: string;
    onlyFailed?: boolean;
  } = {}): AuditEntry[] {
    if (!fs.existsSync(this.logPath)) return [];
    const lines = fs.readFileSync(this.logPath, "utf8").trim().split("\n");
    const results: AuditEntry[] = [];

    for (const line of lines) {
      if (!line.trim()) continue;
      let entry: AuditEntry;
      try {
        entry = JSON.parse(line);
      } catch {
        continue;
      }
      if (opts.operation && entry.operation !== opts.operation) continue;
      if (opts.keyId && entry.keyId !== opts.keyId) continue;
      if (opts.callerId && entry.callerId !== opts.callerId) continue;
      if (opts.since && entry.timestamp < opts.since) continue;
      if (opts.until && entry.timestamp > opts.until) continue;
      if (opts.onlyFailed && entry.success !== false) continue;
      results.push(entry);
    }
    return results;
  }

  /**
   * Render filtered entries as a newline-delimited JSON string,
   * ready to pipe to a file or forward to a SIEM HTTP endpoint.
   */
  toNdjson(opts: Parameters<AuditLog["exportJsonl"]>[0] = {}): string {
    return this.exportJsonl(opts).map((e) => JSON.stringify(e)).join("\n");
  }

  private async shipToWebhook(entry: AuditEntry): Promise<void> {
    if (!this.webhookUrl) return;
    try {
      await fetch(this.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry),
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      // Best-effort — don't block HSM operations
    }
  }
}
