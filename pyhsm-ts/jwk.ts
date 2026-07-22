/**
 * PyHSM JWK (JSON Web Key) Import/Export.
 *
 * Supports RFC 7517 / RFC 7518 key formats for interoperability with
 * other KMS systems, identity providers, and standards-based tooling.
 *
 * Supported key types:
 *   - AES-128, AES-256 → {"kty": "oct", "k": <base64url>, ...}
 *   - EC P-256          → {"kty": "EC", "crv": "P-256", ...}
 *   - RSA               → {"kty": "RSA", ...}
 */
import crypto from "node:crypto";

export interface JWK {
  kty: string;
  kid?: string;
  alg?: string;
  key_ops?: string[];
  [key: string]: unknown;
}

function b64urlEncode(buf: Buffer): string {
  return buf.toString("base64url");
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

/**
 * Export a symmetric (AES) key as a JWK.
 */
export function exportSymmetricJwk(rawKey: Buffer, keyId?: string): JWK {
  const jwk: JWK = {
    kty: "oct",
    k: b64urlEncode(rawKey),
    alg: `A${rawKey.length * 8}GCM`,
    key_ops: ["encrypt", "decrypt"],
  };
  if (keyId) jwk.kid = keyId;
  return jwk;
}

/**
 * Export an EC or RSA private key (DER/PEM buffer) as a JWK.
 * Uses Node.js crypto.createPrivateKey for conversion.
 */
export function exportAsymmetricJwk(privateKeyDer: Buffer, keyId?: string): JWK {
  const keyObj = crypto.createPrivateKey({ key: privateKeyDer, format: "pem" });
  const exported = keyObj.export({ format: "jwk" }) as JWK;
  if (keyId) exported.kid = keyId;
  return exported;
}

/**
 * Import a JWK and return { keyType, rawKeyBytes, publicKeyPem }.
 *
 * - kty="oct" → AES symmetric key (returns raw bytes, no publicKeyPem)
 * - kty="EC"  → returns PEM-encoded private key bytes + public key PEM
 * - kty="RSA" → returns PEM-encoded private key bytes + public key PEM
 */
export function importJwk(jwk: JWK): {
  keyType: string;
  rawKeyBytes: Buffer;
  publicKeyPem: string | null;
} {
  const kty = jwk.kty;

  if (kty === "oct") {
    const raw = b64urlDecode(jwk.k as string);
    let keyType: string;
    if (raw.length === 16) keyType = "aes-128";
    else if (raw.length === 32) keyType = "aes-256";
    else throw new Error(`Unsupported symmetric key size: ${raw.length} bytes`);
    return { keyType, rawKeyBytes: raw, publicKeyPem: null };
  }

  if (kty === "EC" || kty === "RSA") {
    // Use Node.js crypto to convert JWK → KeyObject → PEM
    const privateKeyObj = crypto.createPrivateKey({ key: jwk as crypto.JsonWebKey, format: "jwk" });
    const privateKeyPem = privateKeyObj.export({ type: "pkcs8", format: "pem" }) as string;

    const publicKeyObj = crypto.createPublicKey(privateKeyObj);
    const publicKeyPem = publicKeyObj.export({ type: "spki", format: "pem" }) as string;

    let keyType: string;
    if (kty === "EC") {
      const crv = jwk.crv as string;
      if (crv === "P-256") keyType = "ec-p256";
      else if (crv === "P-384") keyType = "ec-p384";
      else if (crv === "P-521") keyType = "ec-p521";
      else throw new Error(`Unsupported EC curve: ${crv}`);
    } else {
      // Determine RSA key size from modulus
      const nBytes = b64urlDecode(jwk.n as string);
      const keySize = nBytes.length * 8;
      keyType = `rsa-${keySize}`;
    }

    return {
      keyType,
      rawKeyBytes: Buffer.from(privateKeyPem, "utf8"),
      publicKeyPem,
    };
  }

  throw new Error(`Unsupported JWK key type: ${kty}`);
}
