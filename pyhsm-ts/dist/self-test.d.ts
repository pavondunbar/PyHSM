interface KATResult {
    test: string;
    passed: boolean;
    error?: string;
}
/**
 * Enable OpenSSL FIPS mode if available.
 * When PYHSM_FIPS=1, forces FIPS-validated primitives only.
 * Requires Node.js built with OpenSSL 3.x FIPS provider installed on the system.
 */
export declare function enableFipsIfRequested(): boolean;
/** Check if FIPS mode is currently active. */
export declare function isFipsEnabled(): boolean;
/**
 * Run all Known Answer Tests. Throws if any fail.
 * Must be called before the PyHSM accepts any operations.
 */
export declare function runSelfTests(): KATResult[];
export {};
//# sourceMappingURL=self-test.d.ts.map