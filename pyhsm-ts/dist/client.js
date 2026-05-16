"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PyHSMClient = void 0;
/**
 * PyHSM IPC Client
 *
 * Connects to the PyHSM process via Unix domain socket.
 * Used when PYHSM_SOCKET_PATH is set (process isolation mode).
 */
const node_net_1 = __importDefault(require("node:net"));
const node_crypto_1 = __importDefault(require("node:crypto"));
class PyHSMClient {
    socketPath;
    callerId;
    constructor(socketPath, callerService) {
        this.socketPath = socketPath || process.env.PYHSM_SOCKET_PATH || "/tmp/pyhsm.sock";
        // Generate caller ID with HMAC auth if secret is configured
        const service = callerService || "default";
        const secret = process.env.PYHSM_CALLER_SECRET;
        if (secret) {
            const hmac = node_crypto_1.default.createHmac("sha256", secret).update(service).digest("hex");
            this.callerId = `${service}:${hmac}`;
        }
        else {
            this.callerId = service;
        }
    }
    send(req) {
        return new Promise((resolve, reject) => {
            const conn = node_net_1.default.createConnection(this.socketPath);
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
                    }
                    catch {
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
    async encrypt(keyId, plaintext) {
        const res = await this.send({ type: "encrypt", keyId, plaintext, callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
        return res.data;
    }
    async decrypt(keyId, ciphertext) {
        const res = await this.send({ type: "decrypt", keyId, ciphertext, callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
        return res.data;
    }
    async generateKey(keyId, policy) {
        const res = await this.send({ type: "generateKey", keyId, policy, callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
    }
    async rotateKey(keyId) {
        const res = await this.send({ type: "rotateKey", keyId, callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
    }
    async destroyKey(keyId) {
        const res = await this.send({ type: "destroyKey", keyId, callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
    }
    async health() {
        const res = await this.send({ type: "health", callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
        return res.data;
    }
    async metrics() {
        const res = await this.send({ type: "metrics", callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
        return res.data;
    }
    async backup() {
        const res = await this.send({ type: "backup", callerId: this.callerId });
        if (!res.ok)
            throw new Error(res.error);
        return res.data;
    }
}
exports.PyHSMClient = PyHSMClient;
//# sourceMappingURL=client.js.map