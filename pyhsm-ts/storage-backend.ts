/**
 * PyHSM Storage Backend Interface.
 *
 * Provides an abstraction over keystore persistence. Backends are responsible
 * for raw byte storage only — encryption, HMAC, and key management logic
 * lives in the PyHSM core.
 *
 * Available backends:
 *   - FileBackend   — Atomic file writes with crash-safe rename (default)
 *   - MemoryBackend — In-memory storage for testing and ephemeral use cases
 *
 * To implement a custom backend (e.g. S3, DynamoDB, PostgreSQL), implement
 * the StorageBackend interface.
 */
import fs from "node:fs";
import crypto from "node:crypto";

/**
 * Abstract interface for keystore persistence.
 *
 * Implementations must provide atomic-or-best-effort writes.
 * The data passed to write() is already encrypted — backends do NOT
 * need to handle encryption or authentication.
 */
export interface StorageBackend {
  /** Check whether the backing store has any data. */
  exists(): boolean;

  /** Read the full stored blob. Throws if not exists(). */
  read(): Buffer;

  /**
   * Persist data. Must be atomic or best-effort atomic.
   * @param data The encrypted keystore blob (salt + HMAC + payload).
   */
  write(data: Buffer): void;

  /** Remove the stored data entirely. Idempotent — no error if empty. */
  delete(): void;
}

/**
 * File-based storage backend with atomic writes.
 *
 * Uses a temporary sibling file + fs.renameSync() to guarantee that the
 * keystore file is never in a partially-written state — a crash mid-write
 * leaves the previous version intact.
 */
export class FileBackend implements StorageBackend {
  readonly path: string;

  constructor(path: string) {
    this.path = path;
  }

  exists(): boolean {
    return fs.existsSync(this.path);
  }

  read(): Buffer {
    if (!fs.existsSync(this.path)) {
      throw new Error(`Keystore file not found: ${this.path}`);
    }
    return fs.readFileSync(this.path);
  }

  write(data: Buffer): void {
    const tmp = this.path + ".tmp." + crypto.randomBytes(4).toString("hex");
    try {
      fs.writeFileSync(tmp, data, { mode: 0o600 });
      fs.renameSync(tmp, this.path);
    } catch (err) {
      try {
        fs.unlinkSync(tmp);
      } catch {
        // best-effort cleanup
      }
      throw err;
    }
  }

  delete(): void {
    try {
      fs.unlinkSync(this.path);
    } catch {
      // idempotent — ignore if file doesn't exist
    }
  }
}

/**
 * In-memory storage backend for testing and ephemeral use cases.
 *
 * Data is held in a Buffer and lost when the process exits.
 */
export class MemoryBackend implements StorageBackend {
  private data: Buffer | null;

  constructor(initialData?: Buffer) {
    this.data = initialData ? Buffer.from(initialData) : null;
  }

  exists(): boolean {
    return this.data !== null;
  }

  read(): Buffer {
    if (this.data === null) {
      throw new Error("MemoryBackend: no data stored");
    }
    return Buffer.from(this.data); // defensive copy
  }

  write(data: Buffer): void {
    this.data = Buffer.from(data); // defensive copy
  }

  delete(): void {
    this.data = null;
  }
}
