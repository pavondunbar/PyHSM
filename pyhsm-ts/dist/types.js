"use strict";
/**
 * PyHSM Type Definitions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateKeyId = validateKeyId;
// --- Key ID validation ---
const KEY_ID_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
function validateKeyId(keyId) {
    if (!KEY_ID_REGEX.test(keyId)) {
        throw new Error(`PyHSM: invalid key ID '${keyId}'. ` +
            `Must be 1-128 chars, start with alphanumeric, contain only [a-zA-Z0-9._-]`);
    }
}
//# sourceMappingURL=types.js.map