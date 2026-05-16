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
export declare function getPyHSM(): PyHSM;
export declare function resetPyHSM(): void;
export declare function hsmEncryptSecret(plaintext: string, _keyHex?: string): string;
export declare function hsmDecryptSecret(ciphertextB64: string, _keyHex?: string): string;
//# sourceMappingURL=index.d.ts.map