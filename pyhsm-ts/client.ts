/**
 * PyHSM IPC Client
 *
 * Connects to the PyHSM process via Unix domain socket.
 * Used when PYHSM_SOCKET_PATH is set (process isolation mode).
 */
import net from "node:net";
import crypto from "node:crypto";
import type { IPCRequest, IPCResponse } from "./types.js";

export class PyHSMClient {
  private socketPath: string;
  private callerId: string;

  constructor(socketPath?: string, callerService?: string) {
    this.socketPath = socketPath || process.env.PYHSM_SOCKET_PATH || "/tmp/pyhsm.sock";

    // Generate caller ID with HMAC auth if secret is configured
    const service = callerService || "default";
    const secret = process.env.PYHSM_CALLER_SECRET;
    if (secret) {
      const hmac = crypto.createHmac("sha256", secret).update(service).digest("hex");
      this.callerId = `${service}:${hmac}`;
    } else {
      this.callerId = service;
    }
  }

  private send(req: IPCRequest): Promise<IPCResponse> {
    return new Promise((resolve, reject) => {
      const conn = net.createConnection(this.socketPath);
      let buffer = "";
      const timeout = setTimeout(() => {
        conn.destroy();
        reject(new Error("PyHSM IPC timeout"));
      }, 10_000);

      conn.on("connect", () => {
        conn.write(JSON.stringify(req) + "\n");
      });

      conn.on("data", (chunk) => {
        buffer += chunk.toString();
        const idx = buffer.indexOf("\n");
        if (idx !== -1) {
          clearTimeout(timeout);
          const line = buffer.substring(0, idx);
          conn.end();
          try {
            resolve(JSON.parse(line));
          } catch {
            reject(new Error("Invalid IPC response"));
          }
        }
      });

      conn.on("error", (err) => {
        clearTimeout(timeout);
        reject(new Error(`PyHSM IPC error: ${err.message}`));
      });
    });
  }

  async encrypt(keyId: string, plaintext: string): Promise<string> {
    const res = await this.send({ type: "encrypt", keyId, plaintext, callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
    return res.data as string;
  }

  async decrypt(keyId: string, ciphertext: string): Promise<string> {
    const res = await this.send({ type: "decrypt", keyId, ciphertext, callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
    return res.data as string;
  }

  async generateKey(keyId: string, policy?: Record<string, unknown>): Promise<void> {
    const res = await this.send({ type: "generateKey", keyId, policy, callerId: this.callerId } as any);
    if (!res.ok) throw new Error(res.error);
  }

  async rotateKey(keyId: string): Promise<void> {
    const res = await this.send({ type: "rotateKey", keyId, callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
  }

  async destroyKey(keyId: string): Promise<void> {
    const res = await this.send({ type: "destroyKey", keyId, callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
  }

  async health(): Promise<{ status: string; uptime: number }> {
    const res = await this.send({ type: "health", callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
    return res.data as { status: string; uptime: number };
  }

  async metrics(): Promise<Record<string, unknown>> {
    const res = await this.send({ type: "metrics", callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
    return res.data as Record<string, unknown>;
  }

  async backup(): Promise<string> {
    const res = await this.send({ type: "backup", callerId: this.callerId });
    if (!res.ok) throw new Error(res.error);
    return res.data as string;
  }
}
