/**
 * PyHSM Per-Key Rate Limiter
 *
 * Sliding window rate limiting per key to prevent bulk decryption attacks.
 */
export declare class RateLimiter {
    private windows;
    private maxOps;
    private windowMs;
    constructor(maxOpsPerWindow?: number, windowMs?: number);
    /** Returns true if the operation is allowed, false if rate-limited. */
    allow(keyId: string): boolean;
    /** Get current usage for a key. */
    usage(keyId: string): {
        current: number;
        max: number;
    };
}
//# sourceMappingURL=rate-limiter.d.ts.map