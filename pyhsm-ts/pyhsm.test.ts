import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import crypto from "node:crypto";
import { PyHSM } from "./core.js";
import { AuditLog } from "./audit.js";
import { validateKeyId } from "./types.js";
import { splitMasterPassword, reconstructMasterPassword, splitSecret, reconstructSecret } from "./shamir.js";
import { RateLimiter } from "./rate-limiter.js";
import { runSelfTests } from "./self-test.js";
import { PyHSMClient } from "./client.js";
import { SecureBuffer } from "./secure-buffer.js";
import type { PyHSMConfig } from "./types.js";

const TEST_STORE = "/tmp/pyhsm-test-" + crypto.randomBytes(4).toString("hex") + ".enc";
const TEST_AUDIT = TEST_STORE + ".audit.jsonl";

function makeConfig(overrides?: Partial<PyHSMConfig>): PyHSMConfig {
  return {
    storePath: TEST_STORE,
    masterPassword: "test-password-123",
    sessionTimeoutMs: 60_000,
    ...overrides,
  };
}

function cleanup() {
  for (const f of [TEST_STORE, TEST_AUDIT, TEST_STORE + ".tmp"]) {
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }
  // Clean up any tmp files
  const dir = "/tmp";
  for (const f of fs.readdirSync(dir)) {
    if (f.startsWith("pyhsm-test-") && f.endsWith(".enc")) {
      try { fs.unlinkSync(`${dir}/${f}`); } catch {}
    }
  }
}

describe("validateKeyId", () => {
  it("accepts valid key IDs", () => {
    expect(() => validateKeyId("my-key")).not.toThrow();
    expect(() => validateKeyId("key.v1")).not.toThrow();
    expect(() => validateKeyId("a")).not.toThrow();
    expect(() => validateKeyId("Key_123.test-v2")).not.toThrow();
  });

  it("rejects empty string", () => {
    expect(() => validateKeyId("")).toThrow("invalid key ID");
  });

  it("rejects keys starting with non-alphanumeric", () => {
    expect(() => validateKeyId("-key")).toThrow("invalid key ID");
    expect(() => validateKeyId(".key")).toThrow("invalid key ID");
    expect(() => validateKeyId("_key")).toThrow("invalid key ID");
  });

  it("rejects keys with invalid characters", () => {
    expect(() => validateKeyId("key/path")).toThrow("invalid key ID");
    expect(() => validateKeyId("key space")).toThrow("invalid key ID");
    expect(() => validateKeyId("__proto__")).toThrow("invalid key ID");
    expect(() => validateKeyId("constructor")).not.toThrow(); // valid chars
  });

  it("rejects keys longer than 128 chars", () => {
    expect(() => validateKeyId("a".repeat(129))).toThrow("invalid key ID");
    expect(() => validateKeyId("a".repeat(128))).not.toThrow();
  });
});

describe("PyHSM Core", () => {
  let hsm: PyHSM;

  beforeEach(() => {
    cleanup();
    hsm = new PyHSM(makeConfig());
  });

  afterEach(() => {
    try { hsm.closeSession(); } catch {}
    cleanup();
  });

  describe("key generation", () => {
    it("generates a key", () => {
      hsm.generateKey("test-key");
      expect(hsm.hasKey("test-key")).toBe(true);
    });

    it("rejects duplicate key IDs", () => {
      hsm.generateKey("dup-key");
      expect(() => hsm.generateKey("dup-key")).toThrow("already exists");
    });

    it("rejects invalid key IDs", () => {
      expect(() => hsm.generateKey("")).toThrow("invalid key ID");
      expect(() => hsm.generateKey("../escape")).toThrow("invalid key ID");
    });
  });

  describe("encrypt / decrypt", () => {
    it("round-trips plaintext", () => {
      hsm.generateKey("enc-key");
      const ct = hsm.encrypt("enc-key", "hello world");
      const pt = hsm.decrypt("enc-key", ct);
      expect(pt).toBe("hello world");
    });

    it("encrypts empty string", () => {
      hsm.generateKey("enc-key");
      const ct = hsm.encrypt("enc-key", "");
      const pt = hsm.decrypt("enc-key", ct);
      expect(pt).toBe("");
    });

    it("encrypts unicode", () => {
      hsm.generateKey("enc-key");
      const msg = "日本語テスト 🔐";
      const ct = hsm.encrypt("enc-key", msg);
      expect(hsm.decrypt("enc-key", ct)).toBe(msg);
    });

    it("produces different ciphertexts for same plaintext (random nonce)", () => {
      hsm.generateKey("enc-key");
      const ct1 = hsm.encrypt("enc-key", "same");
      const ct2 = hsm.encrypt("enc-key", "same");
      expect(ct1).not.toBe(ct2);
    });

    it("throws on non-existent key", () => {
      expect(() => hsm.encrypt("no-key", "x")).toThrow("not found");
      expect(() => hsm.decrypt("no-key", "x")).toThrow("not found");
    });

    it("throws on tampered ciphertext", () => {
      hsm.generateKey("enc-key");
      const ct = hsm.encrypt("enc-key", "secret");
      const buf = Buffer.from(ct, "base64");
      buf[buf.length - 1] ^= 0xff; // flip last byte
      expect(() => hsm.decrypt("enc-key", buf.toString("base64"))).toThrow();
    });

    it("throws on too-short ciphertext", () => {
      hsm.generateKey("enc-key");
      expect(() => hsm.decrypt("enc-key", Buffer.alloc(10).toString("base64"))).toThrow("too short");
    });
  });

  describe("key rotation", () => {
    it("rotates key and still decrypts old ciphertexts", () => {
      hsm.generateKey("rot-key");
      const ct1 = hsm.encrypt("rot-key", "before rotation");
      hsm.rotateKey("rot-key");
      const ct2 = hsm.encrypt("rot-key", "after rotation");

      expect(hsm.decrypt("rot-key", ct1)).toBe("before rotation");
      expect(hsm.decrypt("rot-key", ct2)).toBe("after rotation");
    });

    it("throws on non-existent key", () => {
      expect(() => hsm.rotateKey("no-key")).toThrow("not found");
    });
  });

  describe("key destruction", () => {
    it("destroys a key", () => {
      hsm.generateKey("del-key");
      hsm.destroyKey("del-key");
      expect(hsm.hasKey("del-key")).toBe(false);
    });

    it("throws on non-existent key", () => {
      expect(() => hsm.destroyKey("no-key")).toThrow("not found");
    });

    it("cannot decrypt after destruction", () => {
      hsm.generateKey("del-key");
      const ct = hsm.encrypt("del-key", "secret");
      hsm.destroyKey("del-key");
      expect(() => hsm.decrypt("del-key", ct)).toThrow("not found");
    });
  });

  describe("persistence", () => {
    it("persists keys across sessions", () => {
      hsm.generateKey("persist-key");
      const ct = hsm.encrypt("persist-key", "persistent data");
      hsm.closeSession();

      const hsm2 = new PyHSM(makeConfig());
      expect(hsm2.hasKey("persist-key")).toBe(true);
      expect(hsm2.decrypt("persist-key", ct)).toBe("persistent data");
      hsm2.closeSession();
    });

    it("detects tampered keystore", () => {
      hsm.generateKey("tamper-key");
      hsm.closeSession();

      // Tamper with the file
      const data = fs.readFileSync(TEST_STORE);
      data[data.length - 10] ^= 0xff;
      fs.writeFileSync(TEST_STORE, data);

      expect(() => new PyHSM(makeConfig())).toThrow("TAMPER DETECTED");
    });
  });

  describe("policies", () => {
    it("enforces maxOperations", () => {
      hsm.generateKey("limited-key", { maxOperations: 2 });
      hsm.encrypt("limited-key", "op1");
      hsm.encrypt("limited-key", "op2");
      expect(() => hsm.encrypt("limited-key", "op3")).toThrow("exceeded max operations");
    });

    it("enforces expiresAt", () => {
      hsm.generateKey("expired-key", { expiresAt: "2020-01-01T00:00:00Z" });
      expect(() => hsm.encrypt("expired-key", "x")).toThrow("has expired");
    });

    it("enforces allowEncrypt=false", () => {
      hsm.generateKey("no-enc", { allowEncrypt: false });
      expect(() => hsm.encrypt("no-enc", "x")).toThrow("policy denies encrypt");
    });

    it("enforces allowDecrypt=false", () => {
      hsm.generateKey("no-dec", { allowDecrypt: false });
      const ct = hsm.encrypt("no-dec", "x");
      // Need to re-generate with both allowed to get a ciphertext, then restrict
      // Actually the key was generated with allowDecrypt:false, so encrypt works but decrypt won't
      expect(() => hsm.decrypt("no-dec", ct)).toThrow("policy denies decrypt");
    });
  });
});

describe("PyHSM Async Factory", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("creates instance with Argon2id", async () => {
    const hsm = await PyHSM.create(makeConfig());
    hsm.generateKey("async-key");
    const ct = hsm.encrypt("async-key", "argon2id test");
    expect(hsm.decrypt("async-key", ct)).toBe("argon2id test");
    hsm.closeSession();
  });

  it("persists across async sessions", async () => {
    const hsm1 = await PyHSM.create(makeConfig());
    hsm1.generateKey("persist-async");
    const ct = hsm1.encrypt("persist-async", "data");
    hsm1.closeSession();

    const hsm2 = await PyHSM.create(makeConfig());
    expect(hsm2.decrypt("persist-async", ct)).toBe("data");
    hsm2.closeSession();
  });
});

describe("Shamir Secret Sharing", () => {
  it("splits and reconstructs a password (3-of-5)", () => {
    const shares = splitMasterPassword("my-secret-password", 3, 5);
    expect(shares).toHaveLength(5);

    // Any 3 shares should reconstruct
    const result = reconstructMasterPassword([shares[0], shares[2], shares[4]]);
    expect(result).toBe("my-secret-password");
  });

  it("works with different share combinations", () => {
    const shares = splitMasterPassword("test", 2, 4);
    expect(reconstructMasterPassword([shares[0], shares[1]])).toBe("test");
    expect(reconstructMasterPassword([shares[1], shares[3]])).toBe("test");
    expect(reconstructMasterPassword([shares[0], shares[2]])).toBe("test");
  });

  it("splits and reconstructs binary data", () => {
    const secret = crypto.randomBytes(32);
    const shares = splitSecret(secret, 3, 5);
    const reconstructed = reconstructSecret([shares[1], shares[3], shares[4]]);
    expect(reconstructed.equals(secret)).toBe(true);
  });

  it("rejects invalid parameters", () => {
    expect(() => splitMasterPassword("x", 1, 3)).toThrow("Invalid k/n");
    expect(() => splitMasterPassword("x", 4, 3)).toThrow("Invalid k/n");
  });

  it("works with PyHSM constructor", () => {
    cleanup();
    const shares = splitMasterPassword("ceremony-password", 3, 5);
    const hsm = new PyHSM({
      storePath: TEST_STORE,
      shares: [JSON.stringify(shares[0]), JSON.stringify(shares[2]), JSON.stringify(shares[4])],
    });
    hsm.generateKey("shamir-key");
    const ct = hsm.encrypt("shamir-key", "shamir works");
    expect(hsm.decrypt("shamir-key", ct)).toBe("shamir works");
    hsm.closeSession();
    cleanup();
  });
});

describe("RateLimiter", () => {
  it("allows operations within limit", () => {
    const rl = new RateLimiter(3, 1000);
    expect(rl.allow("key1")).toBe(true);
    expect(rl.allow("key1")).toBe(true);
    expect(rl.allow("key1")).toBe(true);
  });

  it("blocks operations over limit", () => {
    const rl = new RateLimiter(2, 1000);
    expect(rl.allow("key1")).toBe(true);
    expect(rl.allow("key1")).toBe(true);
    expect(rl.allow("key1")).toBe(false);
  });

  it("tracks keys independently", () => {
    const rl = new RateLimiter(1, 1000);
    expect(rl.allow("key1")).toBe(true);
    expect(rl.allow("key2")).toBe(true);
    expect(rl.allow("key1")).toBe(false);
  });

  it("reports usage", () => {
    const rl = new RateLimiter(10, 1000);
    rl.allow("key1");
    rl.allow("key1");
    const usage = rl.usage("key1");
    expect(usage.current).toBe(2);
    expect(usage.max).toBe(10);
  });
});

describe("Self-Tests", () => {
  it("passes all KATs", () => {
    const results = runSelfTests();
    expect(results.length).toBeGreaterThanOrEqual(4);
    for (const r of results) {
      expect(r.passed).toBe(true);
    }
  });
});

describe("Constructor validation", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("throws without masterPassword or shares", () => {
    expect(() => new PyHSM({ storePath: TEST_STORE } as any)).toThrow("masterPassword or shares required");
  });
});



// ---------------------------------------------------------------------------
// SecureBuffer
// ---------------------------------------------------------------------------

describe("SecureBuffer", () => {
  it("stores and returns buffer contents", () => {
    const sb = SecureBuffer.from(Buffer.from("hello"));
    expect(sb.buf.toString()).toBe("hello");
    sb.dispose();
  });

  it("zeroizes on dispose", () => {
    const raw = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    const sb = SecureBuffer.wrap(raw);
    sb.dispose();
    // The underlying buffer should now be zeroed
    expect(raw.every((b) => b === 0)).toBe(true);
  });

  it("throws on access after dispose", () => {
    const sb = SecureBuffer.alloc(16);
    sb.dispose();
    expect(() => sb.buf).toThrow("after dispose");
  });

  it("double dispose is safe", () => {
    const sb = SecureBuffer.alloc(8);
    sb.dispose();
    expect(() => sb.dispose()).not.toThrow();
  });

  it("withBuffer disposes even on throw", () => {
    const raw = Buffer.from([0xff, 0xff]);
    const sb = SecureBuffer.wrap(raw);
    try {
      sb.withBuffer(() => { throw new Error("test error"); });
    } catch {}
    expect(raw.every((b) => b === 0)).toBe(true);
  });

  it("[Symbol.dispose] works for 'using' pattern", () => {
    const raw = Buffer.from([1, 2, 3]);
    const sb = SecureBuffer.wrap(raw);
    sb[Symbol.dispose]();
    expect(raw.every((b) => b === 0)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Audit log — SIEM export and filtering
// ---------------------------------------------------------------------------

describe("AuditLog SIEM export", () => {
  let logPath: string;
  let log: AuditLog;

  beforeEach(() => {
    logPath = `/tmp/pyhsm-audit-test-${crypto.randomBytes(4).toString("hex")}.jsonl`;
    log = new AuditLog(logPath);
  });

  afterEach(() => {
    for (const f of [logPath, logPath + ".hmackey"]) {
      if (fs.existsSync(f)) fs.unlinkSync(f);
    }
  });

  it("exportJsonl returns all entries when no filter", () => {
    log.record("generateKey", { keyId: "k1", success: true });
    log.record("encrypt", { keyId: "k1", success: true });
    log.record("decrypt", { keyId: "k1", success: true });
    const entries = log.exportJsonl();
    expect(entries.length).toBe(3);
  });

  it("filters by operation", () => {
    log.record("encrypt", { keyId: "k1", success: true });
    log.record("decrypt", { keyId: "k1", success: true });
    log.record("encrypt", { keyId: "k2", success: true });
    const entries = log.exportJsonl({ operation: "encrypt" });
    expect(entries.length).toBe(2);
    expect(entries.every((e) => e.operation === "encrypt")).toBe(true);
  });

  it("filters by keyId", () => {
    log.record("encrypt", { keyId: "k1", success: true });
    log.record("encrypt", { keyId: "k2", success: true });
    const entries = log.exportJsonl({ keyId: "k1" });
    expect(entries.length).toBe(1);
    expect(entries[0].keyId).toBe("k1");
  });

  it("filters onlyFailed", () => {
    log.record("encrypt", { keyId: "k1", success: true });
    log.record("accessDenied", { keyId: "k2", success: false, reason: "ACL" });
    log.record("rateLimited", { keyId: "k3", success: false });
    const entries = log.exportJsonl({ onlyFailed: true });
    expect(entries.length).toBe(2);
    expect(entries.every((e) => e.success === false)).toBe(true);
  });

  it("toNdjson returns newline-separated JSON strings", () => {
    log.record("encrypt", { keyId: "k1", success: true });
    log.record("decrypt", { keyId: "k1", success: true });
    const ndjson = log.toNdjson();
    const lines = ndjson.split("\n").filter(Boolean);
    expect(lines.length).toBe(2);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it("verify() returns -1 for unmodified log", () => {
    for (let i = 0; i < 5; i++) {
      log.record("encrypt", { keyId: `k${i}`, success: true });
    }
    expect(log.verify()).toBe(-1);
  });
});

// ---------------------------------------------------------------------------
// Backup verification
// ---------------------------------------------------------------------------

describe("Backup and verifyBackup", () => {
  let storePath: string;
  let backupDir: string;
  let hsm: PyHSM;

  beforeEach(() => {
    storePath = `/tmp/pyhsm-bkup-${crypto.randomBytes(4).toString("hex")}.enc`;
    backupDir = `/tmp/pyhsm-bkup-dir-${crypto.randomBytes(4).toString("hex")}`;
    hsm = new PyHSM({ storePath, masterPassword: "backup-test-pw", backupDir });
    hsm.generateKey("bk-key");
  });

  afterEach(() => {
    try { hsm.closeSession(); } catch {}
    for (const p of [storePath, storePath + ".audit.jsonl",
                     storePath + ".audit.jsonl.hmackey"]) {
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
    if (fs.existsSync(backupDir)) {
      for (const f of fs.readdirSync(backupDir)) fs.unlinkSync(`${backupDir}/${f}`);
      fs.rmdirSync(backupDir);
    }
  });

  it("createBackup returns a valid path", () => {
    const bp = hsm.createBackup();
    expect(fs.existsSync(bp)).toBe(true);
  });

  it("verifyBackup returns true for a valid backup", () => {
    const bp = hsm.createBackup();
    expect(hsm.verifyBackup(bp)).toBe(true);
  });

  it("verifyBackup throws for a tampered backup", () => {
    const bp = hsm.createBackup();
    const data = fs.readFileSync(bp);
    const tampered = Buffer.from(data);
    tampered[tampered.length - 5] ^= 0xff;
    fs.writeFileSync(bp, tampered);
    expect(() => hsm.verifyBackup(bp)).toThrow(/HMAC verification FAILED|decryption FAILED/);
  });

  it("verifyBackup throws for missing file", () => {
    expect(() => hsm.verifyBackup("/tmp/pyhsm-does-not-exist.enc")).toThrow("not found");
  });

  it("round-trips data through backup store", () => {
    const ct = hsm.encrypt("bk-key", "backup round-trip");
    const bp = hsm.createBackup();
    hsm.closeSession();

    // Open from the backup path directly
    const hsm2 = new PyHSM({ storePath: bp, masterPassword: "backup-test-pw" });
    expect(hsm2.decrypt("bk-key", ct)).toBe("backup round-trip");
    hsm2.closeSession();
  });
});

// ---------------------------------------------------------------------------
// IPC process isolation
// ---------------------------------------------------------------------------

describe("IPC process isolation (process.ts + client.ts)", () => {
  const SOCKET = `/tmp/pyhsm-ipc-test-${crypto.randomBytes(4).toString("hex")}.sock`;
  const STORE  = `/tmp/pyhsm-ipc-store-${crypto.randomBytes(4).toString("hex")}.enc`;
  let server: net.Server;
  let hsmInstance: PyHSM;

  // Spin up an in-process IPC server identical to process.ts but without exec
  beforeEach(async () => {
    if (fs.existsSync(SOCKET)) fs.unlinkSync(SOCKET);

    hsmInstance = new PyHSM({
      storePath: STORE,
      masterPassword: "ipc-test-pw",
    });

    server = net.createServer((conn) => {
      let buf = "";
      conn.on("data", (chunk) => {
        buf += chunk.toString();
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const req = JSON.parse(line);
            let res: object;
            try {
              switch (req.type) {
                case "generateKey":
                  hsmInstance.generateKey(req.keyId, req.policy, req.callerId);
                  res = { ok: true, data: null };
                  break;
                case "encrypt":
                  res = { ok: true, data: hsmInstance.encrypt(req.keyId, req.plaintext, req.callerId) };
                  break;
                case "decrypt":
                  res = { ok: true, data: hsmInstance.decrypt(req.keyId, req.ciphertext, req.callerId) };
                  break;
                case "rotateKey":
                  hsmInstance.rotateKey(req.keyId, req.callerId);
                  res = { ok: true, data: null };
                  break;
                case "destroyKey":
                  hsmInstance.destroyKey(req.keyId, req.callerId);
                  res = { ok: true, data: null };
                  break;
                case "health":
                  res = { ok: true, data: { status: "healthy" } };
                  break;
                case "metrics":
                  res = { ok: true, data: hsmInstance.getMetrics() };
                  break;
                default:
                  res = { ok: false, error: "Unknown type" };
              }
            } catch (e: any) {
              res = { ok: false, error: e.message };
            }
            conn.write(JSON.stringify(res) + "\n");
          } catch {
            conn.write(JSON.stringify({ ok: false, error: "parse error" }) + "\n");
          }
        }
      });
    });

    await new Promise<void>((resolve) => server.listen(SOCKET, () => {
      fs.chmodSync(SOCKET, 0o600);
      resolve();
    }));
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try { hsmInstance.closeSession(); } catch {}
    for (const p of [SOCKET, STORE,
                     STORE + ".audit.jsonl",
                     STORE + ".audit.jsonl.hmackey"]) {
      if (fs.existsSync(p)) try { fs.unlinkSync(p); } catch {}
    }
  });

  it("client can generate and encrypt/decrypt over socket", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    await client.generateKey("ipc-key");
    const ct = await client.encrypt("ipc-key", "hello over IPC");
    const pt = await client.decrypt("ipc-key", ct);
    expect(pt).toBe("hello over IPC");
  });

  it("client health check responds", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    const h = await client.health();
    expect(h.status).toBe("healthy");
  });

  it("client metrics responds", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    const m = await client.metrics();
    expect(m).toBeDefined();
  });

  it("client rotate key over socket", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    await client.generateKey("rot-ipc");
    const ct = await client.encrypt("rot-ipc", "before rotate");
    await client.rotateKey("rot-ipc");
    const ct2 = await client.encrypt("rot-ipc", "after rotate");
    expect(await client.decrypt("rot-ipc", ct)).toBe("before rotate");
    expect(await client.decrypt("rot-ipc", ct2)).toBe("after rotate");
  });

  it("client destroy key over socket", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    await client.generateKey("del-ipc");
    await client.destroyKey("del-ipc");
    await expect(client.encrypt("del-ipc", "x")).rejects.toThrow("not found");
  });

  it("client error propagated correctly", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    await expect(client.encrypt("ghost-key", "x")).rejects.toThrow("not found");
  });

  it("concurrent requests are handled without interleaving", async () => {
    const client = new PyHSMClient(SOCKET, "test-service");
    await client.generateKey("concurrent-key");
    // Fire 5 encrypt calls simultaneously and verify all return correct data
    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) =>
        client.encrypt("concurrent-key", `msg-${i}`)
      )
    );
    const decrypted = await Promise.all(
      results.map((ct, i) =>
        client.decrypt("concurrent-key", ct).then((pt) => ({ i, pt }))
      )
    );
    for (const { i, pt } of decrypted) {
      expect(pt).toBe(`msg-${i}`);
    }
  });
});
