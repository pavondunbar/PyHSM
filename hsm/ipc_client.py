"""
PyHSM IPC Client — connect to a PyHSM IPC server over a Unix domain socket.

Drop-in companion to IPCServer. Applications that run PyHSM in process
isolation mode use IPCClient instead of PyHSM directly. The interface
mirrors the PyHSM public API so switching between in-process and isolated
mode requires only changing the constructor call.

Usage
-----
::

    from hsm.ipc_client import IPCClient

    # Connect to an already-running IPCServer
    with IPCClient("/run/pyhsm/pyhsm.sock", ipc_secret="shared-secret") as client:
        client.generate_key("my-key", "aes-256")
        ct = client.encrypt("my-key", "hello world")
        pt = client.decrypt("my-key", ct)

Authentication
--------------
If the server was started with ``--ipc-secret``, the client must be
constructed with the matching ``ipc_secret``. Each request includes an
HMAC-SHA256 token over ``request_id:operation`` computed with this secret.
The server verifies the token before dispatching.

Connection handling
-------------------
The client maintains a persistent connection. If the connection drops
(server restart, timeout), reconnect by creating a new IPCClient instance
or calling ``reconnect()``. All operations raise ``ConnectionError`` if
the server is unreachable.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import socket
import struct
import uuid
from typing import Any, Optional

_MSG_HEADER = struct.Struct(">I")
_MAX_MSG_BYTES = 64 * 1024 * 1024


def _send_msg(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    header = _MSG_HEADER.pack(len(data))
    sock.sendall(header + data)


def _recv_msg(sock: socket.socket) -> dict:
    header = _recv_exact(sock, _MSG_HEADER.size)
    if not header:
        raise ConnectionError("IPC server closed the connection")
    (length,) = _MSG_HEADER.unpack(header)
    if length > _MAX_MSG_BYTES:
        raise ValueError(f"IPC response too large: {length} bytes")
    raw = _recv_exact(sock, length)
    if not raw:
        raise ConnectionError("IPC server closed the connection mid-message")
    return json.loads(raw.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


class IPCClient:
    """
    Client for the PyHSM IPC server.

    Parameters
    ----------
    socket_path : str
        Path to the Unix domain socket created by IPCServer.
    ipc_secret : str, optional
        Shared HMAC secret for request authentication. Must match the
        server's ``--ipc-secret`` value if the server was started with one.
    caller_id : str, optional
        Identifier included in every request for audit log attribution.
        Default: ``"ipc-client"``.
    timeout : float, optional
        Socket operation timeout in seconds. Default: 30.0.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        ipc_secret: Optional[str] = None,
        caller_id: str = "ipc-client",
        timeout: float = 30.0,
    ) -> None:
        self._socket_path = socket_path
        self._ipc_secret: Optional[bytes] = (
            ipc_secret.encode("utf-8") if ipc_secret else None
        )
        self._caller_id = caller_id
        self._timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._connect()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(self._socket_path)
        except FileNotFoundError:
            raise ConnectionError(
                f"PyHSM IPC server socket not found: {self._socket_path}. "
                "Start the server with: vectorguard-pyhsm-server --store <path> "
                "--password-file <path> --socket " + self._socket_path
            )
        self._sock = sock

    def reconnect(self) -> None:
        """Close the current connection and reconnect to the server."""
        self.close()
        self._connect()

    def close(self) -> None:
        """Close the connection to the IPC server."""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> "IPCClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Request/response
    # ------------------------------------------------------------------

    def _auth_token(self, request_id: str, operation: str) -> str:
        if not self._ipc_secret:
            return ""
        return _hmac.new(
            self._ipc_secret,
            f"{request_id}:{operation}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _call(self, operation: str, **kwargs: Any) -> Any:
        """Send a request and return the response data, raising on error."""
        if not self._sock:
            raise ConnectionError("IPC client is closed. Call reconnect() first.")

        request_id = str(uuid.uuid4())
        request = {
            "type": operation,
            "request_id": request_id,
            "caller_id": self._caller_id,
            "auth": self._auth_token(request_id, operation),
            **kwargs,
        }

        try:
            _send_msg(self._sock, request)
            response = _recv_msg(self._sock)
        except (OSError, ConnectionError) as e:
            self._sock = None
            raise ConnectionError(
                f"IPC communication failed during '{operation}': {e}. "
                "The server may have restarted. Call reconnect() to re-establish."
            ) from e

        if response.get("request_id") != request_id:
            raise ValueError(
                f"IPC response request_id mismatch: "
                f"expected {request_id!r}, got {response.get('request_id')!r}"
            )

        if not response.get("ok"):
            raise RuntimeError(
                f"PyHSM IPC error ({operation}): {response.get('error', 'unknown error')}"
            )

        return response.get("data")

    # ------------------------------------------------------------------
    # PyHSM API mirror
    # ------------------------------------------------------------------

    def health(self) -> dict:
        """Check server health. Returns {'status': 'ok', 'session_active': bool}."""
        return self._call("health")

    def generate_key(
        self,
        key_id: str,
        key_type: str = "aes-256",
        *,
        policy: Optional[dict] = None,
    ) -> str:
        return self._call("generate_key", key_id=key_id, key_type=key_type, policy=policy)

    def rotate_key(self, key_id: str) -> int:
        return self._call("rotate_key", key_id=key_id)

    def destroy_key(self, key_id: str) -> None:
        self._call("destroy_key", key_id=key_id)

    def list_keys(self) -> list:
        return self._call("list_keys")

    def has_key(self, key_id: str) -> bool:
        return self._call("has_key", key_id=key_id)

    def encrypt(self, key_id: str, plaintext: str) -> str:
        return self._call("encrypt", key_id=key_id, plaintext=plaintext)

    def decrypt(self, key_id: str, ciphertext: str) -> str:
        return self._call("decrypt", key_id=key_id, ciphertext=ciphertext)

    def sign(self, key_id: str, message: str) -> str:
        return self._call("sign", key_id=key_id, message=message)

    def verify(self, key_id: str, message: str, signature: str) -> bool:
        return self._call("verify", key_id=key_id, message=message, signature=signature)

    def get_public_key(self, key_id: str) -> str:
        return self._call("get_public_key", key_id=key_id)

    def export_jwk(self, key_id: str) -> dict:
        return self._call("export_jwk", key_id=key_id)

    def create_backup(self, backup_dir: str) -> str:
        return self._call("create_backup", backup_dir=backup_dir)

    def verify_backup(self, backup_path: str) -> bool:
        return self._call("verify_backup", backup_path=backup_path)

    def get_metrics(self) -> dict:
        return self._call("get_metrics")
