#!/bin/sh
# PyHSM Docker entrypoint script.
#
# Performs pre-flight security checks before starting the IPC server:
#   1. Verifies the password file exists and has correct permissions.
#   2. Verifies the data directory is writable.
#   3. Verifies the socket directory exists and is writable.
#   4. Execs the server process (replaces this shell with the Python process
#      so PID 1 is the actual server, not a shell wrapper).
#
# Usage: set as ENTRYPOINT in Dockerfile, or override CMD for CLI use.

set -eu

# --------------------------------------------------------------------------
# 1. Password file checks
# --------------------------------------------------------------------------
PASSWORD_FILE="${PYHSM_PASSWORD_FILE:-/run/secrets/pyhsm-password}"

if [ ! -f "${PASSWORD_FILE}" ]; then
    echo "ERROR: Password file not found: ${PASSWORD_FILE}" >&2
    echo "Create it with:" >&2
    echo "  printf '%s' 'YourPassword' > ${PASSWORD_FILE}" >&2
    echo "  chmod 600 ${PASSWORD_FILE}" >&2
    exit 1
fi

# Check permissions: must be 600 (no group or world read/write)
PERMS=$(stat -c "%a" "${PASSWORD_FILE}" 2>/dev/null || stat -f "%OLp" "${PASSWORD_FILE}" 2>/dev/null || echo "unknown")
if [ "${PERMS}" != "600" ] && [ "${PERMS}" != "400" ]; then
    echo "ERROR: Password file ${PASSWORD_FILE} has unsafe permissions: ${PERMS}" >&2
    echo "Fix with: chmod 600 ${PASSWORD_FILE}" >&2
    exit 1
fi

# --------------------------------------------------------------------------
# 2. Data directory check
# --------------------------------------------------------------------------
DATA_DIR="${PYHSM_DATA_DIR:-/data}"
if [ ! -d "${DATA_DIR}" ]; then
    echo "ERROR: Data directory not found: ${DATA_DIR}" >&2
    exit 1
fi
if [ ! -w "${DATA_DIR}" ]; then
    echo "ERROR: Data directory is not writable: ${DATA_DIR}" >&2
    echo "Fix with: chown pyhsm:pyhsm ${DATA_DIR}" >&2
    exit 1
fi

# --------------------------------------------------------------------------
# 3. Socket directory check
# --------------------------------------------------------------------------
SOCKET_DIR=$(dirname "${PYHSM_SOCKET:-/run/pyhsm/pyhsm.sock}")
if [ ! -d "${SOCKET_DIR}" ]; then
    mkdir -p "${SOCKET_DIR}"
    chmod 700 "${SOCKET_DIR}"
fi

# --------------------------------------------------------------------------
# 4. Exec the server (replaces shell — PID 1 is Python)
# --------------------------------------------------------------------------
echo "PyHSM entrypoint: all checks passed, starting server..." >&2
exec "$@"
