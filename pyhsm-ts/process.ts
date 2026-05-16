/**
 * PyHSM Process Worker
 *
 * Runs the PyHSM in a separate process, communicating via Unix domain socket.
 * This provides process isolation — a vulnerability in the main app cannot
 * directly access key material in this process's memory.
 *
 * Usage: node --require tsx/cjs src/lib/crypto/pyhsm/process.ts
 * Or:    npx tsx src/lib/crypto/pyhsm/process.ts
 */
import net from "node:net";
import fs from "node:fs";
import crypto from "node:crypto";
import { PyHSM } from "./core.js";
import type { IPCRequest, IPCResponse, PyHSMConfig } from "./types.js";

const SOCKET_PATH = process.env.PYHSM_SOCKET_PATH || "/tmp/pyhsm.sock";
const CALLER_SECRET = process.env.PYHSM_CALLER_SECRET || null;

function createHSM(): PyHSM {
  const config: PyHSMConfig = {
    storePath: process.env.PYHSM_KEYSTORE_PATH || "./pyhsm-keystore.enc",
    masterPassword: process.env.PYHSM_MASTER_PASSWORD,
    auditLogPath: process.env.PYHSM_AUDIT_LOG_PATH,
    backupDir: process.env.PYHSM_BACKUP_DIR,
    callerSecret: CALLER_SECRET || undefined,
    sessionTimeoutMs: parseInt(process.env.PYHSM_SESSION_TIMEOUT_MS || "300000", 10),
  };

  if (!config.masterPassword && process.env.PYHSM_SHARES) {
    config.shares = process.env.PYHSM_SHARES.split(",");
  }

  return new PyHSM(config);
}

function handleRequest(hsm: PyHSM, req: IPCRequest): IPCResponse {
  try {
    switch (req.type) {
      case "encrypt":
        return { ok: true, data: hsm.encrypt(req.keyId, req.plaintext, req.callerId) };
      case "decrypt":
        return { ok: true, data: hsm.decrypt(req.keyId, req.ciphertext, req.callerId) };
      case "generateKey":
        hsm.generateKey(req.keyId, req.policy, req.callerId);
        return { ok: true, data: null };
      case "destroyKey":
        hsm.destroyKey(req.keyId, req.callerId);
        return { ok: true, data: null };
      case "rotateKey":
        hsm.rotateKey(req.keyId, req.callerId);
        return { ok: true, data: null };
      case "metrics":
        return { ok: true, data: hsm.getMetrics() };
      case "backup":
        return { ok: true, data: hsm.createBackup(req.callerId) };
      case "health":
        return { ok: true, data: { status: "healthy", uptime: hsm.getMetrics().uptimeMs } };
      default:
        return { ok: false, error: "Unknown request type" };
    }
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

function startServer(): void {
  // Clean up stale socket
  if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);

  const hsm = createHSM();
  console.log(`[PyHSM] Process started (PID ${process.pid})`);
  console.log(`[PyHSM] Listening on ${SOCKET_PATH}`);

  const server = net.createServer((conn) => {
    let buffer = "";

    conn.on("data", (chunk) => {
      buffer += chunk.toString();
      // Messages are newline-delimited JSON
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const req: IPCRequest = JSON.parse(line);
          const res = handleRequest(hsm, req);
          conn.write(JSON.stringify(res) + "\n");
        } catch (e: any) {
          conn.write(JSON.stringify({ ok: false, error: "Invalid request" }) + "\n");
        }
      }
    });
  });

  server.listen(SOCKET_PATH, () => {
    // Restrict socket permissions
    fs.chmodSync(SOCKET_PATH, 0o600);
  });

  // Graceful shutdown
  const shutdown = () => {
    console.log("[PyHSM] Shutting down...");
    hsm.closeSession();
    server.close();
    if (fs.existsSync(SOCKET_PATH)) fs.unlinkSync(SOCKET_PATH);
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

// Only start if this file is executed directly
if (require.main === module || process.argv[1]?.endsWith("process.ts")) {
  startServer();
}

export { startServer };
