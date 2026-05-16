"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reconstructSecret = exports.splitSecret = exports.reconstructMasterPassword = exports.splitMasterPassword = exports.isFipsEnabled = exports.enableFipsIfRequested = exports.runSelfTests = exports.MetricsCollector = exports.RateLimiter = exports.AuditLog = exports.PyHSM = void 0;
exports.getPyHSM = getPyHSM;
exports.resetPyHSM = resetPyHSM;
exports.hsmEncryptSecret = hsmEncryptSecret;
exports.hsmDecryptSecret = hsmDecryptSecret;
/**
 * PyHSM Module Exports
 */
var core_js_1 = require("./core.js");
Object.defineProperty(exports, "PyHSM", { enumerable: true, get: function () { return core_js_1.PyHSM; } });
var audit_js_1 = require("./audit.js");
Object.defineProperty(exports, "AuditLog", { enumerable: true, get: function () { return audit_js_1.AuditLog; } });
var rate_limiter_js_1 = require("./rate-limiter.js");
Object.defineProperty(exports, "RateLimiter", { enumerable: true, get: function () { return rate_limiter_js_1.RateLimiter; } });
var metrics_js_1 = require("./metrics.js");
Object.defineProperty(exports, "MetricsCollector", { enumerable: true, get: function () { return metrics_js_1.MetricsCollector; } });
var self_test_js_1 = require("./self-test.js");
Object.defineProperty(exports, "runSelfTests", { enumerable: true, get: function () { return self_test_js_1.runSelfTests; } });
Object.defineProperty(exports, "enableFipsIfRequested", { enumerable: true, get: function () { return self_test_js_1.enableFipsIfRequested; } });
Object.defineProperty(exports, "isFipsEnabled", { enumerable: true, get: function () { return self_test_js_1.isFipsEnabled; } });
var shamir_js_1 = require("./shamir.js");
Object.defineProperty(exports, "splitMasterPassword", { enumerable: true, get: function () { return shamir_js_1.splitMasterPassword; } });
Object.defineProperty(exports, "reconstructMasterPassword", { enumerable: true, get: function () { return shamir_js_1.reconstructMasterPassword; } });
Object.defineProperty(exports, "splitSecret", { enumerable: true, get: function () { return shamir_js_1.splitSecret; } });
Object.defineProperty(exports, "reconstructSecret", { enumerable: true, get: function () { return shamir_js_1.reconstructSecret; } });
const core_js_2 = require("./core.js");
// --- Singleton ---
let instance = null;
function getPyHSM() {
    if (!instance) {
        const config = {
            storePath: process.env.PYHSM_KEYSTORE_PATH || "./pyhsm-keystore.enc",
            masterPassword: process.env.PYHSM_MASTER_PASSWORD,
            auditLogPath: process.env.PYHSM_AUDIT_LOG_PATH,
            backupDir: process.env.PYHSM_BACKUP_DIR,
            callerSecret: process.env.PYHSM_CALLER_SECRET,
            sessionTimeoutMs: parseInt(process.env.PYHSM_SESSION_TIMEOUT_MS || "300000", 10),
        };
        if (!config.masterPassword && process.env.PYHSM_SHARES) {
            config.shares = process.env.PYHSM_SHARES.split(",");
        }
        instance = new core_js_2.PyHSM(config);
    }
    return instance;
}
function resetPyHSM() {
    if (instance)
        instance.closeSession();
    instance = null;
}
process.on("exit", () => { if (instance)
    instance.closeSession(); });
function hsmEncryptSecret(plaintext, _keyHex) {
    const keyId = process.env.PYHSM_KEY_ID || "pyhsm-master";
    return getPyHSM().encrypt(keyId, plaintext);
}
function hsmDecryptSecret(ciphertextB64, _keyHex) {
    const keyId = process.env.PYHSM_KEY_ID || "pyhsm-master";
    return getPyHSM().decrypt(keyId, ciphertextB64);
}
//# sourceMappingURL=index.js.map