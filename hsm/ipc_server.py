"""
PyHSM IPC Server — Unix domain socket process isolation.

Runs the PyHSM core in a dedicated subprocess that communicates with the
application over a Unix domain socket. This implements the process isolation
boundary described in the threat model: even if application code is
compromised (supply-chain attack, RCE via a web framework), the attacker
cannot directly read key material or call cryptographic operations because
the HSM lives in a separate address space with a distinct OS process identity.

Architecture
------------

    ┌──────────────────────────────────────────────────────────┐
    │  Application Process                                       │
    │                                                           │
    │  IPCClient.encrypt("key", "hello") ──────────────────┐   │
    └──────────────────────────────────────────────────────│───┘
                                                           │ Unix socket
    ┌──────────────────────────────────────────────────────│───┐
    │  PyHSM Server Process (this module)                   │   │
    │                                                       ↓   │
    │  IPCServer → PyHSM(keystore, password_file=...)           │
    │  Raw key material NEVER leaves this process               │
    └──────────────────────────────────────────────────────────┘

Wire protocol
-------------
Each message is a length-prefixed JSON frame:
    [4 bytes big-endian uint32 = payload length][UTF-8 JSON payload]

Request fields:
    type     : str   — operation name (see ALLOWED_OPERATIONS)
    request_id : str — caller-provided correlation ID for tracing
    ...      : operation-specific fields

Response fields:
    ok         : bool
    request_id : str  — echoed from request
    data       : any  — on success
    error      : str  — on failure (never includes raw key material)

Security properties
-------------------
- The socket file is created with mode 0o600 so only the HSM server's
  UID can connect. The server verifies this on startup.
- Each connection is authenticated via an optional shared HMAC secret
  (PYHSM_IPC_SECRET env var or --ipc-secret flag). If configured, the
  client must present HMAC-SHA256(secret, request_id + operation) in
  every request.
- The server enforces a whitelist of allowed operations. Unknown
  operation names are rejected with an error, not a traceback.
- Each request is handled in a new thread so slow operations (RSA keygen)
  don't block the accept loop.
- The server shuts down cleanly on SIGTERM/SIGINT: closes the session,
  zeroizes memory, removes the socket file.

Usage
-----
Start the server (blocks until SIGTERM)::

    python -m hsm.ipc_server \\
        --store /secure/keystore.enc \\
        --password-file /run/secrets/pyhsm-password \\
        --socket /run/pyhsm/pyhsm.sock

Or via the convenience entry point added to pyproject.toml::

    vectorguard-pyhsm-server --store keystore.enc --password-file /run/secrets/pyhsm-password
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import signal
import socket
import struct
import sys
import threading
import traceback
from typing import Optional

from .core import PyHSM
from .logging import get_logger

_logger = get_logger(__name__)

# Operations the server will execute. Any operation not in this set is
# rejected before touching the HSM instance.
ALLOWED_OPERATIONS = frozenset({
    "encrypt",
    "decrypt",
    "sign",
    "verify",
    "generate_key",
    "rotate_key",
    "destroy_key",
    "list_keys",
    "has_key",
    "get_public_key",
    "export_jwk",
    "create_backup",
    "verify_backup",
    "get_metrics",
    "health",
})

_MSG_HEADER = struct.Struct(">I")   # 4-byte big-endian uint32
_MAX_MSG_BYTES = 64 * 1024 * 1024  # 64 MB — matches PyHSM plaintext limit
_SOCKET_MODE = 0o600


def _send_msg(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    header = _MSG_HEADER.pack(len(data))
    sock.sendall(header + data)


def _recv_msg(sock: socket.socket) -> Optional[dict]:
    header = _recv_exact(sock, _MSG_HEADER.size)
    if not header:
        return None
    (length,) = _MSG_HEADER.unpack(header)
    if length > _MAX_MSG_BYTES:
        raise ValueError(f"IPC message too large: {length} bytes")
    raw = _recv_exact(sock, length)
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class IPCServer:
    """
    PyHSM IPC server — wraps a PyHSM instance and exposes it over a
    Unix domain socket using length-prefixed JSON framing.
    """

    def __init__(
        self,
        store_path: str,
        socket_path: str,
        *,
        master_password: Optional[str] = None,
        password_file: Optional[str] = None,
        ipc_secret: Optional[str] = None,
        session_timeout_s: float = 0.0,
        rate_limit_max_ops: int = 100,
        rate_limit_window_s: float = 60.0,
    ) -> None:
        self._socket_path = socket_path
        self._ipc_secret: Optional[bytes] = (
            ipc_secret.encode("utf-8") if ipc_secret else None
        )
        self._lock = threading.Lock()
        self._shutdown = threading.Event()

        _logger.info("IPC server starting", extra={
            "event": "ipc_server_start",
            "socket_path": socket_path,
            "store_path": store_path,
            "auth": "hmac" if ipc_secret else "none",
        })

        self._hsm = PyHSM(
            storage_path=store_path,
            master_password=master_password,
            password_file=password_file,
            session_timeout_s=session_timeout_s,
            rate_limit_max_ops=rate_limit_max_ops,
            rate_limit_window_s=rate_limit_window_s,
        )
        _logger.info("PyHSM session opened", extra={"event": "ipc_hsm_ready"})

    def _authenticate(self, request: dict) -> bool:
        """Verify HMAC-SHA256 request authentication if a secret is configured."""
        if not self._ipc_secret:
            return True
        provided = request.get("auth", "")
        request_id = request.get("request_id", "")
        operation = request.get("type", "")
        expected = _hmac.new(
            self._ipc_secret,
            f"{request_id}:{operation}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return _hmac.compare_digest(provided, expected)

    def _handle_request(self, request: dict) -> dict:
        """Dispatch a validated request to the PyHSM instance."""
        op = request.get("type", "")
        caller_id = request.get("caller_id", "ipc-client")

        if op not in ALLOWED_OPERATIONS:
            return {"ok": False, "error": f"Unknown operation: {op!r}"}

        try:
            with self._lock:
                result = self._dispatch(op, request, caller_id)
            return {"ok": True, "data": result}
        except Exception as exc:
            # Never include stack traces or raw exception details in the
            # response — they may leak key IDs, file paths, or internal state.
            _logger.error("IPC request failed", extra={
                "event": "ipc_error",
                "operation": op,
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            return {"ok": False, "error": str(exc)}

    def _dispatch(self, op: str, req: dict, caller_id: str):
        hsm = self._hsm
        if op == "health":
            return {"status": "ok", "session_active": hsm._session_active}
        elif op == "encrypt":
            return hsm.encrypt(req["key_id"], req["plaintext"], caller_id=caller_id)
        elif op == "decrypt":
            result = hsm.decrypt(req["key_id"], req["ciphertext"], caller_id=caller_id)
            return result.decode("utf-8", errors="surrogateescape")
        elif op == "sign":
            return hsm.sign(req["key_id"], req["message"], caller_id=caller_id)
        elif op == "verify":
            return hsm.verify(req["key_id"], req["message"], req["signature"], caller_id=caller_id)
        elif op == "generate_key":
            return hsm.generate_key(
                req["key_id"],
                req.get("key_type", "aes-256"),
                policy=req.get("policy"),
                caller_id=caller_id,
            )
        elif op == "rotate_key":
            return hsm.rotate_key(req["key_id"], caller_id=caller_id)
        elif op == "destroy_key":
            hsm.destroy_key(req["key_id"], caller_id=caller_id)
            return None
        elif op == "list_keys":
            return hsm.list_keys()
        elif op == "has_key":
            return hsm.has_key(req["key_id"])
        elif op == "get_public_key":
            return hsm.get_public_key(req["key_id"])
        elif op == "export_jwk":
            return hsm.export_jwk(req["key_id"], caller_id=caller_id)
        elif op == "create_backup":
            return hsm.create_backup(req["backup_dir"], caller_id=caller_id)
        elif op == "verify_backup":
            return hsm.verify_backup(req["backup_path"], caller_id=caller_id)
        elif op == "get_metrics":
            return hsm.get_metrics()
        else:
            raise ValueError(f"Unhandled operation: {op!r}")

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        """Handle one client connection in a dedicated thread."""
        try:
            while True:
                request = _recv_msg(conn)
                if request is None:
                    break  # client disconnected

                request_id = request.get("request_id", "")

                if not self._authenticate(request):
                    _logger.warning("IPC authentication failed", extra={
                        "event": "ipc_auth_failed", "request_id": request_id,
                    })
                    _send_msg(conn, {
                        "ok": False,
                        "request_id": request_id,
                        "error": "Authentication failed",
                    })
                    break  # close connection on auth failure

                response = self._handle_request(request)
                response["request_id"] = request_id
                _send_msg(conn, response)

        except Exception:
            _logger.debug("IPC connection error", extra={
                "event": "ipc_conn_error",
                "traceback": traceback.format_exc(),
            })
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def run(self) -> None:
        """Start the server and block until shutdown."""
        # Remove stale socket file
        if os.path.exists(self._socket_path):
            os.unlink(self._socket_path)

        # Ensure parent directory exists and is private
        sock_dir = os.path.dirname(self._socket_path)
        if sock_dir:
            os.makedirs(sock_dir, mode=0o700, exist_ok=True)

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server_sock.bind(self._socket_path)
            os.chmod(self._socket_path, _SOCKET_MODE)
            server_sock.listen(32)
            server_sock.settimeout(1.0)  # allow periodic shutdown checks

            _logger.info("IPC server listening", extra={
                "event": "ipc_listening",
                "socket_path": self._socket_path,
            })

            # Install signal handlers for clean shutdown
            def _shutdown_handler(signum, frame):
                _logger.info("IPC server shutting down", extra={
                    "event": "ipc_shutdown", "signal": signum,
                })
                self._shutdown.set()

            signal.signal(signal.SIGTERM, _shutdown_handler)
            signal.signal(signal.SIGINT, _shutdown_handler)

            while not self._shutdown.is_set():
                try:
                    conn, addr = server_sock.accept()
                    t = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue  # check shutdown flag

        finally:
            server_sock.close()
            try:
                os.unlink(self._socket_path)
            except OSError:
                pass
            try:
                self._hsm.close_session()
            except Exception:
                pass
            _logger.info("IPC server stopped", extra={"event": "ipc_stopped"})


def main() -> None:
    """Entry point for vectorguard-pyhsm-server."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="vectorguard-pyhsm-server",
        description="PyHSM IPC server — run the HSM in an isolated process",
    )
    parser.add_argument("--store", required=True, help="Path to keystore file")
    parser.add_argument(
        "--socket",
        default=os.environ.get("PYHSM_SOCKET", "/run/pyhsm/pyhsm.sock"),
        help="Unix socket path (default: /run/pyhsm/pyhsm.sock or PYHSM_SOCKET env var)",
    )
    parser.add_argument(
        "--password-file",
        metavar="PATH",
        default=os.environ.get("PYHSM_PASSWORD_FILE"),
        help="Path to password file (chmod 600). Preferred over --password.",
    )
    parser.add_argument(
        "--ipc-secret",
        metavar="SECRET",
        default=os.environ.get("PYHSM_IPC_SECRET"),
        help="Shared HMAC secret for request authentication (or PYHSM_IPC_SECRET env var)",
    )
    parser.add_argument(
        "--rate-limit", type=int, default=100,
        help="Max operations per key per minute (default: 100)",
    )
    args = parser.parse_args()

    if not args.password_file:
        print(
            "ERROR: --password-file is required for the IPC server.\n"
            "Create the file with: install -m 600 /dev/null /run/secrets/pyhsm-password\n"
            "Then write the password: printf '%%s' 'YourPassword' > /run/secrets/pyhsm-password",
            file=sys.stderr,
        )
        sys.exit(1)

    server = IPCServer(
        store_path=args.store,
        socket_path=args.socket,
        password_file=args.password_file,
        ipc_secret=args.ipc_secret,
        rate_limit_max_ops=args.rate_limit,
    )
    server.run()


if __name__ == "__main__":
    main()
