"""
PyHSM Storage Backends.

Provides a StorageBackend abstract base class and concrete implementations.
Backends are responsible for raw byte persistence only — encryption, HMAC,
and key management logic lives in KeyStore.

Available backends:
  - FileBackend     — Atomic file writes with crash-safe rename (default)
  - MemoryBackend   — In-memory storage for testing and ephemeral use cases

To implement a custom backend (e.g. S3, DynamoDB, PostgreSQL), subclass
StorageBackend and implement the four required methods.
"""

from __future__ import annotations

import os
import secrets
from abc import ABC, abstractmethod


class StorageBackend(ABC):
    """
    Abstract interface for keystore persistence.

    Implementations must provide atomic-or-best-effort writes.
    The data passed to write() is already encrypted — backends do NOT
    need to handle encryption or authentication.

    Methods
    -------
    exists() -> bool
        Return True if the backing store contains data.
    read() -> bytes
        Return the full raw content. Raises if not exists().
    write(data: bytes) -> None
        Persist data atomically (or as close as the backend allows).
    delete() -> None
        Remove the stored data entirely.
    """

    @abstractmethod
    def exists(self) -> bool:
        """Check whether the backing store has any data."""
        ...

    @abstractmethod
    def read(self) -> bytes:
        """
        Read the full stored blob.

        Raises
        ------
        FileNotFoundError
            If the backing store is empty / does not exist.
        """
        ...

    @abstractmethod
    def write(self, data: bytes) -> None:
        """
        Persist data. Must be atomic or best-effort atomic.

        Parameters
        ----------
        data : bytes
            The encrypted keystore blob (salt + HMAC + payload).
        """
        ...

    @abstractmethod
    def delete(self) -> None:
        """
        Remove the stored data entirely.

        Should be idempotent — calling delete() when nothing exists
        must not raise.
        """
        ...


class FileBackend(StorageBackend):
    """
    File-based storage backend with atomic writes.

    Uses a temporary sibling file + os.replace() to guarantee that the
    keystore file is never in a partially-written state — a crash mid-write
    leaves the previous version intact.

    Parameters
    ----------
    path : str
        Path to the keystore file on disk.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def read(self) -> bytes:
        if not os.path.exists(self.path):
            raise FileNotFoundError(f"Keystore file not found: {self.path}")
        with open(self.path, "rb") as f:
            return f.read()

    def write(self, data: bytes) -> None:
        # Atomic write: write to sibling temp file, then rename
        tmp = self.path + ".tmp." + secrets.token_hex(4)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def delete(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


class MemoryBackend(StorageBackend):
    """
    In-memory storage backend for testing and ephemeral use cases.

    Data is held in a bytearray and lost when the process exits.
    Thread-safe for single-writer usage (matches KeyStore's locking model).

    Parameters
    ----------
    initial_data : bytes, optional
        Pre-populate the backend (useful for testing tamper scenarios).
    """

    def __init__(self, initial_data: bytes | None = None) -> None:
        self._data: bytes | None = initial_data

    def exists(self) -> bool:
        return self._data is not None

    def read(self) -> bytes:
        if self._data is None:
            raise FileNotFoundError("MemoryBackend: no data stored")
        return self._data

    def write(self, data: bytes) -> None:
        self._data = bytes(data)  # defensive copy

    def delete(self) -> None:
        self._data = None
