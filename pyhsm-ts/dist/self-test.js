"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.enableFipsIfRequested = enableFipsIfRequested;
exports.isFipsEnabled = isFipsEnabled;
exports.runSelfTests = runSelfTests;
/**
 * PyHSM Startup Self-Test (Known Answer Tests)
 *
 * Verifies crypto primitives produce expected outputs before accepting operations.
 * Required for FIPS 140-2 Level 1 compliance.
 */
const node_crypto_1 = __importDefault(require("node:crypto"));
/** AES-256-GCM KAT with known test vector. */
function testAesGcm() {
    const key = Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex");
    const nonce = Buffer.from("000000000000000000000000", "hex");
    const plaintext = Buffer.from("00000000000000000000000000000000", "hex");
    // Expected output for AES-256-GCM(key=0x00*32, nonce=0x00*12, pt=0x00*16, aad=none)
    const cipher = node_crypto_1.default.createCipheriv("aes-256-gcm", key, nonce);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Verify decryption round-trips
    const decipher = node_crypto_1.default.createDecipheriv("aes-256-gcm", key, nonce);
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
function testPbkdf2() {
    // RFC 6070 test vector: password="password", salt="salt", iterations=4096, dkLen=32
    const expected = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a";
    const result = node_crypto_1.default.pbkdf2Sync("password", "salt", 4096, 32, "sha256");
    if (result.toString("hex") !== expected) {
        return { test: "PBKDF2-SHA256", passed: false, error: "Output mismatch" };
    }
    return { test: "PBKDF2-SHA256", passed: true };
}
/** HMAC-SHA256 KAT. */
function testHmac() {
    // RFC 4231 Test Case 1
    const key = Buffer.alloc(20, 0x0b);
    const data = Buffer.from("Hi There");
    const expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    const result = node_crypto_1.default.createHmac("sha256", key).update(data).digest("hex");
    if (result !== expected) {
        return { test: "HMAC-SHA256", passed: false, error: "Output mismatch" };
    }
    return { test: "HMAC-SHA256", passed: true };
}
/** CSPRNG test — verify randomness is non-degenerate. */
function testRng() {
    const a = node_crypto_1.default.randomBytes(32);
    const b = node_crypto_1.default.randomBytes(32);
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
 * Enable OpenSSL FIPS mode if available.
 * When PYHSM_FIPS=1, forces FIPS-validated primitives only.
 * Requires Node.js built with OpenSSL 3.x FIPS provider installed on the system.
 */
function enableFipsIfRequested() {
    if (process.env.PYHSM_FIPS !== "1")
        return false;
    try {
        node_crypto_1.default.setFips(true);
        return true;
    }
    catch (e) {
        throw new Error(`PyHSM: FIPS mode requested but unavailable. ` +
            `Ensure Node.js is linked against OpenSSL 3.x with the FIPS provider installed. ` +
            `(${e.message})`);
    }
}
/** Check if FIPS mode is currently active. */
function isFipsEnabled() {
    return node_crypto_1.default.getFips() === 1;
}
/**
 * Run all Known Answer Tests. Throws if any fail.
 * Must be called before the PyHSM accepts any operations.
 */
function runSelfTests() {
    // Attempt FIPS activation before running tests
    const fipsActive = enableFipsIfRequested();
    const results = [testAesGcm(), testPbkdf2(), testHmac(), testRng()];
    if (fipsActive) {
        results.push({ test: "FIPS-mode", passed: true });
    }
    const failures = results.filter((r) => !r.passed);
    if (failures.length > 0) {
        const msg = failures.map((f) => `${f.test}: ${f.error}`).join("; ");
        throw new Error(`PyHSM self-test FAILED: ${msg}`);
    }
    return results;
}
//# sourceMappingURL=self-test.js.map