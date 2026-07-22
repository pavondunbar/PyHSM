/**
 * PyHSM SecureBuffer — best-effort sensitive data container.
 *
 * JavaScript/V8 cannot guarantee deterministic memory zeroization because:
 *   1. Strings are immutable and interned — you cannot overwrite them.
 *   2. The GC may move objects before we zeroize.
 *   3. JIT compilation may duplicate values in registers.
 *
 * Using Node.js Buffer (backed by a fixed ArrayBuffer) is the closest we
 * can get: Buffer.fill(0) overwrites the *underlying* ArrayBuffer bytes
 * immediately. This does not prevent the OS from swapping the page to disk
 * before we zeroize, but it does eliminate the sensitive value from the
 * heap as soon as `dispose()` is called — which is the best achievable in
 * a managed runtime without native bindings.
 *
 * Usage pattern:
 *
 *   const secret = SecureBuffer.from(rawBytes);
 *   try {
 *     // use secret.buf
 *   } finally {
 *     secret.dispose();
 *   }
 *
 * The `using` keyword (TC39 Explicit Resource Management, TS 5.2+) is also
 * supported via the [Symbol.dispose] method.
 */

export class SecureBuffer {
  private _buf: Buffer;
  private _disposed = false;

  private constructor(buf: Buffer) {
    this._buf = buf;
  }

  /** Wrap an existing Buffer. The buffer is owned by this SecureBuffer. */
  static wrap(buf: Buffer): SecureBuffer {
    return new SecureBuffer(buf);
  }

  /** Allocate a zeroed SecureBuffer of the given byte length. */
  static alloc(size: number): SecureBuffer {
    return new SecureBuffer(Buffer.alloc(size));
  }

  /** Copy bytes into a new SecureBuffer. */
  static from(data: Buffer | Uint8Array | string, encoding?: BufferEncoding): SecureBuffer {
    const buf = typeof data === "string"
      ? Buffer.from(data, encoding ?? "utf8")
      : Buffer.from(data);
    return new SecureBuffer(buf);
  }

  /** Access the underlying Buffer. Throws if already disposed. */
  get buf(): Buffer {
    if (this._disposed) throw new Error("SecureBuffer: accessed after dispose()");
    return this._buf;
  }

  get length(): number {
    return this._buf.length;
  }

  get disposed(): boolean {
    return this._disposed;
  }

  /**
   * Zeroize the underlying buffer and mark this SecureBuffer as disposed.
   * Safe to call multiple times.
   */
  dispose(): void {
    if (!this._disposed) {
      this._buf.fill(0);
      this._disposed = true;
    }
  }

  /** TC39 Explicit Resource Management (`using` keyword in TS 5.2+). */
  [Symbol.dispose](): void {
    this.dispose();
  }

  /**
   * Execute a callback with this buffer, then dispose.
   * Ensures zeroization even if the callback throws.
   */
  withBuffer<T>(fn: (buf: Buffer) => T): T {
    try {
      return fn(this.buf);
    } finally {
      this.dispose();
    }
  }
}

/**
 * Zeroize a plain Buffer immediately. Convenience wrapper for call sites
 * that don't use SecureBuffer but need a one-liner zeroize.
 */
export function zeroBuffer(buf: Buffer): void {
  buf.fill(0);
}
