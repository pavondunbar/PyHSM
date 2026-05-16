export interface ShamirShare {
    index: number;
    data: string;
}
/** Split a secret (Buffer) into n shares with threshold k. */
export declare function splitSecret(secret: Buffer, k: number, n: number): ShamirShare[];
/** Reconstruct a secret from k or more shares via Lagrange interpolation. */
export declare function reconstructSecret(shares: ShamirShare[]): Buffer;
/** Split a master password string into shares. */
export declare function splitMasterPassword(password: string, k: number, n: number): ShamirShare[];
/** Reconstruct master password from shares. */
export declare function reconstructMasterPassword(shares: ShamirShare[]): string;
//# sourceMappingURL=shamir.d.ts.map