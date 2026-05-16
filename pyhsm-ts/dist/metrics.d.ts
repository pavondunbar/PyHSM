/**
 * PyHSM Health Metrics
 *
 * Tracks operations, errors, and exposes health status.
 */
import type { HSMMetrics } from "./types.js";
export declare class MetricsCollector {
    private startTime;
    private counters;
    private lastOpAt;
    private activeKeys;
    private archivedKeys;
    recordOp(type: "encrypt" | "decrypt"): void;
    recordError(): void;
    recordRateLimit(): void;
    recordAccessDenial(): void;
    setKeyCount(active: number, archived: number): void;
    getMetrics(): HSMMetrics;
    /** Prometheus-compatible text format. */
    toPrometheus(): string;
}
//# sourceMappingURL=metrics.d.ts.map