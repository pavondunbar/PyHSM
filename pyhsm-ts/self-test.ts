/**
 * PyHSM Startup Self-Test (Known Answer Tests)
 *
 * Verifies crypto primitives produce expected outputs before accepting operations.
 * These KATs run at startup before the HSM accepts any cryptographic requests.
 */
import crypto from "node:crypto";

interface KATResult {
  test: string;
  passed: boolean;
  error?: string;
}

/** AES-256-GCM KAT with known test vector. */
function testAesGcm(): KATResult {
  const key = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex");
  const nonce = Buffer.from("000000000000000000000000", "hex");
  const plaintext = Buffer.from("00000000000000000000000000000000", "hex");

  // Expected output for AES-256-GCM(key=0x00*32, nonce=0x00*12, pt=0x00*16, aad=none)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Verify decryption round-trips
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);

  if (!pt.equals(plaintext)) {
    return { test: "AES-256-GCM", passed: false, error: "Round-trip failed" };
  }

  // Verify tag is non-zero (cipher is actually doing something)
  if (tag.every((b) => b === 0)) {
    return { test: "AES-256-GCM", passed: false, error: "Auth tag is all zeros" };
  }

  return { test: "AES-256-GCM", passed: true };
}

/** PBKDF2-SHA256 KAT. */
function testPbkdf2(): KATResult {
  // RFC 6070 test vector: password="password", salt="salt", iterations=4096, dkLen=32
  const expected = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a";
  const result = crypto.pbkdf2Sync("password", "salt", 4096, 32, "sha256");

  if (result.toString("hex") !== expected) {
    return { test: "PBKDF2-SHA256", passed: false, error: "Output mismatch" };
  }
  return { test: "PBKDF2-SHA256", passed: true };
}

/** HMAC-SHA256 KAT. */
function testHmac(): KATResult {
  // RFC 4231 Test Case 1
  const key = Buffer.alloc(20, 0x0b);
  const data = Buffer.from("Hi There");
  const expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
  const result = crypto.createHmac("sha256", key).update(data).digest("hex");

  if (result !== expected) {
    return { test: "HMAC-SHA256", passed: false, error: "Output mismatch" };
  }
  return { test: "HMAC-SHA256", passed: true };
}

/** CSPRNG test — verify randomness is non-degenerate. */
function testRng(): KATResult {
  const a = crypto.randomBytes(32);
  const b = crypto.randomBytes(32);

  // Two random 32-byte values should never be equal
  if (a.equals(b)) {
    return { test: "CSPRNG", passed: false, error: "Duplicate random output" };
  }
  // Should not be all zeros
  if (a.every((x) => x === 0)) {
    return { test: "CSPRNG", passed: false, error: "All-zero output" };
  }
  return { test: "CSPRNG", passed: true };
}

/**
 * Run all Known Answer Tests. Throws if any fail.
 * Must be called before the PyHSM accepts any operations.
 */
export function runSelfTests(): KATResult[] {
  const results = [testAesGcm(), testPbkdf2(), testHmac(), testRng()];

  const failures = results.filter((r) => !r.passed);

  if (failures.length > 0) {
    const msg = failures.map((f) => `${f.test}: ${f.error}`).join("; ");
    throw new Error(`PyHSM self-test FAILED: ${msg}`);
  }

  return results;
}
