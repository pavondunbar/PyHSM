/**
 * PyHSM Per-Key Rate Limiter
 *
 * Sliding window rate limiting per key to prevent bulk decryption attacks.
 */

interface RateWindow {
  timestamps: number[];
}

export class RateLimiter {
  private windows: Map<string, RateWindow> = new Map();
  private maxOps: number;
  private windowMs: number;

  constructor(maxOpsPerWindow = 100, windowMs = 60_000) {
    this.maxOps = maxOpsPerWindow;
    this.windowMs = windowMs;
  }

  /** Returns true if the operation is allowed, false if rate-limited. */
  allow(keyId: string): boolean {
    const now = Date.now();
    let window = this.windows.get(keyId);
    if (!window) {
      window = { timestamps: [] };
      this.windows.set(keyId, window);
    }

    // Evict expired entries
    const cutoff = now - this.windowMs;
    window.timestamps = window.timestamps.filter((t) => t > cutoff);

    if (window.timestamps.length >= this.maxOps) {
      return false;
    }

    window.timestamps.push(now);
    return true;
  }

  /** Get current usage for a key. */
  usage(keyId: string): { current: number; max: number } {
    const now = Date.now();
    const window = this.windows.get(keyId);
    if (!window) return { current: 0, max: this.maxOps };
    const cutoff = now - this.windowMs;
    const current = window.timestamps.filter((t) => t > cutoff).length;
    return { current, max: this.maxOps };
  }
}
