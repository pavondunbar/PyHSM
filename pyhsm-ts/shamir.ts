/**
 * PyHSM Shamir's Secret Sharing
 *
 * Splits the master password into N shares with threshold K.
 * Used for ceremony-based unlock: K operators must provide their shares.
 */
import crypto from "node:crypto";

// GF(256) with AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);

(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x = x ^ (x << 1) ^ (x >= 128 ? 0x11b : 0);
    x &= 0xff;
  }
  EXP[255] = EXP[0];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a] + LOG[b]) % 255];
}

function gfDiv(a: number, b: number): number {
  if (b === 0) throw new Error("GF(256) division by zero");
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

export interface ShamirShare {
  index: number; // 1-based
  data: string;  // hex-encoded
  checksum?: string; // first 4 bytes of SHA-256(secret) as hex — for integrity verification
}

/** Split a secret (Buffer) into n shares with threshold k.
 *
 * Each share includes a `checksum` field — the first 4 bytes of
 * SHA-256(secret) as hex. `reconstructSecret()` uses this to detect
 * corrupted or mismatched shares after reconstruction, preventing a
 * wrong secret from being silently used.
 */
export function splitSecret(secret: Buffer, k: number, n: number): ShamirShare[] {
  if (k < 2 || k > n || n > 255) throw new Error("Invalid k/n parameters");

  // Compute the integrity checksum from the original secret before splitting.
  const checksum = crypto.createHash("sha256").update(secret).digest().subarray(0, 4).toString("hex");

  const shares: Buffer[] = Array.from({ length: n }, () => Buffer.alloc(secret.length));

  for (let b = 0; b < secret.length; b++) {
    // Random polynomial of degree k-1 with secret as constant term
    const coeffs = new Uint8Array(k);
    coeffs[0] = secret[b];
    const rand = crypto.randomBytes(k - 1);
    for (let c = 1; c < k; c++) coeffs[c] = rand[c - 1];

    // Evaluate polynomial at x = 1..n
    for (let i = 0; i < n; i++) {
      const x = i + 1;
      let y = 0;
      for (let c = k - 1; c >= 0; c--) {
        y = gfMul(y, x) ^ coeffs[c];
      }
      shares[i][b] = y;
    }
  }

  return shares.map((data, i) => ({ index: i + 1, data: data.toString("hex"), checksum }));
}

/** Reconstruct a secret from k or more shares via Lagrange interpolation.
 *
 * Integrity check
 * ---------------
 * If shares carry a `checksum` field (first 4 bytes of SHA-256 of the
 * original secret as hex), the reconstructed value is verified against it.
 * A mismatch raises an Error before the wrong value can be used. Shares
 * without a `checksum` field (produced by older versions) are still
 * accepted — the check is skipped so existing shares remain usable.
 */
export function reconstructSecret(shares: ShamirShare[]): Buffer {
  if (shares.length < 2) throw new Error("Need at least 2 shares");
  const len = Buffer.from(shares[0].data, "hex").length;
  const result = Buffer.alloc(len);

  const bufs = shares.map((s) => Buffer.from(s.data, "hex"));

  for (let b = 0; b < len; b++) {
    let secret = 0;
    for (let i = 0; i < shares.length; i++) {
      let lagrange = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        lagrange = gfMul(lagrange, gfDiv(shares[j].index, shares[j].index ^ shares[i].index));
      }
      secret ^= gfMul(bufs[i][b], lagrange);
    }
    result[b] = secret;
  }

  // Verify integrity checksum if present in shares.
  // All shares from the same split carry the same checksum — use the first.
  const storedChecksum = shares[0].checksum;
  if (storedChecksum !== undefined) {
    const actualChecksum = crypto.createHash("sha256").update(result).digest().subarray(0, 4).toString("hex");
    if (actualChecksum !== storedChecksum) {
      result.fill(0);
      throw new Error(
        "PyHSM Shamir: reconstructed secret failed checksum verification. " +
        "One or more shares may be corrupted or belong to a different split. " +
        "Result has been zeroized to prevent use of a wrong secret."
      );
    }
  }

  return result;
}

/** Split a master password string into shares. */
export function splitMasterPassword(password: string, k: number, n: number): ShamirShare[] {
  return splitSecret(Buffer.from(password, "utf8"), k, n);
}

/**
 * Reconstruct master password from shares, returning a Buffer.
 *
 * Returning a Buffer (rather than a string) allows the caller to call
 * buf.fill(0) after copying the password into the HSM, deterministically
 * removing the sensitive value from memory. JavaScript strings are
 * immutable and cannot be zeroed — passing through a string would leave
 * the password in the V8 heap until GC.
 *
 * The caller is responsible for calling buf.fill(0) after use.
 */
export function reconstructMasterPassword(shares: ShamirShare[]): Buffer {
  return reconstructSecret(shares);
}
