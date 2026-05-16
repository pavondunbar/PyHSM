"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.splitSecret = splitSecret;
exports.reconstructSecret = reconstructSecret;
exports.splitMasterPassword = splitMasterPassword;
exports.reconstructMasterPassword = reconstructMasterPassword;
/**
 * PyHSM Shamir's Secret Sharing
 *
 * Splits the master password into N shares with threshold K.
 * Used for ceremony-based unlock: K operators must provide their shares.
 */
const node_crypto_1 = __importDefault(require("node:crypto"));
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
function gfMul(a, b) {
    if (a === 0 || b === 0)
        return 0;
    return EXP[(LOG[a] + LOG[b]) % 255];
}
function gfDiv(a, b) {
    if (b === 0)
        throw new Error("GF(256) division by zero");
    if (a === 0)
        return 0;
    return EXP[(LOG[a] - LOG[b] + 255) % 255];
}
/** Split a secret (Buffer) into n shares with threshold k. */
function splitSecret(secret, k, n) {
    if (k < 2 || k > n || n > 255)
        throw new Error("Invalid k/n parameters");
    const shares = Array.from({ length: n }, () => Buffer.alloc(secret.length));
    for (let b = 0; b < secret.length; b++) {
        // Random polynomial of degree k-1 with secret as constant term
        const coeffs = new Uint8Array(k);
        coeffs[0] = secret[b];
        const rand = node_crypto_1.default.randomBytes(k - 1);
        for (let c = 1; c < k; c++)
            coeffs[c] = rand[c - 1];
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
    return shares.map((data, i) => ({ index: i + 1, data: data.toString("hex") }));
}
/** Reconstruct a secret from k or more shares via Lagrange interpolation. */
function reconstructSecret(shares) {
    if (shares.length < 2)
        throw new Error("Need at least 2 shares");
    const len = Buffer.from(shares[0].data, "hex").length;
    const result = Buffer.alloc(len);
    const bufs = shares.map((s) => Buffer.from(s.data, "hex"));
    for (let b = 0; b < len; b++) {
        let secret = 0;
        for (let i = 0; i < shares.length; i++) {
            let lagrange = 1;
            for (let j = 0; j < shares.length; j++) {
                if (i === j)
                    continue;
                lagrange = gfMul(lagrange, gfDiv(shares[j].index, shares[j].index ^ shares[i].index));
            }
            secret ^= gfMul(bufs[i][b], lagrange);
        }
        result[b] = secret;
    }
    return result;
}
/** Split a master password string into shares. */
function splitMasterPassword(password, k, n) {
    return splitSecret(Buffer.from(password, "utf8"), k, n);
}
/** Reconstruct master password from shares. */
function reconstructMasterPassword(shares) {
    return reconstructSecret(shares).toString("utf8");
}
//# sourceMappingURL=shamir.js.map