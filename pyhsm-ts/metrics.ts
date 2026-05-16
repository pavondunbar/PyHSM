/**
 * PyHSM Health Metrics
 *
 * Tracks operations, errors, and exposes health status.
 */
import type { HSMMetrics } from "./types.js";

export class MetricsCollector {
  private startTime = Date.now();
  private counters = {
    totalOps: 0,
    encryptOps: 0,
    decryptOps: 0,
    errors: 0,
    rateLimitHits: 0,
    accessDenials: 0,
  };
  private lastOpAt: string | null = null;
  private activeKeys = 0;
  private archivedKeys = 0;

  recordOp(type: "encrypt" | "decrypt"): void {
    this.counters.totalOps++;
    if (type === "encrypt") this.counters.encryptOps++;
    else this.counters.decryptOps++;
    this.lastOpAt = new Date().toISOString();
  }

  recordError(): void {
    this.counters.errors++;
  }

  recordRateLimit(): void {
    this.counters.rateLimitHits++;
  }

  recordAccessDenial(): void {
    this.counters.accessDenials++;
  }

  setKeyCount(active: number, archived: number): void {
    this.activeKeys = active;
    this.archivedKeys = archived;
  }

  getMetrics(): HSMMetrics {
    return {
      totalOperations: this.counters.totalOps,
      encryptOps: this.counters.encryptOps,
      decryptOps: this.counters.decryptOps,
      errors: this.counters.errors,
      rateLimitHits: this.counters.rateLimitHits,
      accessDenials: this.counters.accessDenials,
      activeKeys: this.activeKeys,
      archivedKeys: this.archivedKeys,
      uptimeMs: Date.now() - this.startTime,
      lastOperationAt: this.lastOpAt,
    };
  }

  /** Prometheus-compatible text format. */
  toPrometheus(): string {
    const m = this.getMetrics();
    return [
      `# HELP pyhsm_operations_total Total HSM operations`,
      `# TYPE pyhsm_operations_total counter`,
      `pyhsm_operations_total{type="encrypt"} ${m.encryptOps}`,
      `pyhsm_operations_total{type="decrypt"} ${m.decryptOps}`,
      `# HELP pyhsm_errors_total Total HSM errors`,
      `# TYPE pyhsm_errors_total counter`,
      `pyhsm_errors_total ${m.errors}`,
      `# HELP pyhsm_rate_limit_hits_total Rate limit rejections`,
      `# TYPE pyhsm_rate_limit_hits_total counter`,
      `pyhsm_rate_limit_hits_total ${m.rateLimitHits}`,
      `# HELP pyhsm_access_denials_total Access control rejections`,
      `# TYPE pyhsm_access_denials_total counter`,
      `pyhsm_access_denials_total ${m.accessDenials}`,
      `# HELP pyhsm_keys Active keys in the HSM`,
      `# TYPE pyhsm_keys gauge`,
      `pyhsm_keys{state="active"} ${m.activeKeys}`,
      `pyhsm_keys{state="archived"} ${m.archivedKeys}`,
      `# HELP pyhsm_uptime_seconds HSM uptime`,
      `# TYPE pyhsm_uptime_seconds gauge`,
      `pyhsm_uptime_seconds ${(m.uptimeMs / 1000).toFixed(1)}`,
    ].join("\n");
  }
}
