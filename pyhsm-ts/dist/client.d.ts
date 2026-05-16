export declare class PyHSMClient {
    private socketPath;
    private callerId;
    constructor(socketPath?: string, callerService?: string);
    private send;
    encrypt(keyId: string, plaintext: string): Promise<string>;
    decrypt(keyId: string, ciphertext: string): Promise<string>;
    generateKey(keyId: string, policy?: Record<string, unknown>): Promise<void>;
    rotateKey(keyId: string): Promise<void>;
    destroyKey(keyId: string): Promise<void>;
    health(): Promise<{
        status: string;
        uptime: number;
    }>;
    metrics(): Promise<Record<string, unknown>>;
    backup(): Promise<string>;
}
//# sourceMappingURL=client.d.ts.map