"""
PyHSM Secure Memory Utilities.

Provides deterministic zeroization of sensitive byte buffers. Python's
garbage collector and string immutability make true secure erasure
impossible for str objects, but bytearray instances CAN be reliably
overwritten in-place.

Usage pattern:
    key_buf = SecureBytes(os.urandom(32))
    try:
        # use key_buf.buf for crypto operations
        AESGCM(bytes(key_buf.buf)).encrypt(...)
    finally:
        key_buf.zeroize()

Or as a context manager:
    with SecureBytes(raw_key) as key_buf:
        AESGCM(bytes(key_buf)).encrypt(...)
"""

from __future__ import annotations


class SecureBytes:
    """
    A wrapper around bytearray that guarantees in-place zeroization.

    Unlike Python str or bytes objects, bytearray is mutable and its
    memory can be overwritten deterministically. This class ensures
    sensitive material is erased when no longer needed.

    Parameters
    ----------
    data : bytes | bytearray
        The sensitive data to protect. A copy is made into an internal
        bytearray; the caller should zeroize the original if possible.
    """

    __slots__ = ("_buf", "_disposed")

    def __init__(self, data: bytes | bytearray) -> None:
        self._buf = bytearray(data)
        self._disposed = False

    @property
    def buf(self) -> bytearray:
        """Access the underlying buffer. Raises if already zeroized."""
        if self._disposed:
            raise RuntimeError("SecureBytes: buffer has been zeroized")
        return self._buf

    def zeroize(self) -> None:
        """Overwrite the buffer with zeros in-place. Idempotent."""
        if self._disposed:
            return
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._disposed = True

    def __enter__(self) -> bytearray:
        return self.buf

    def __exit__(self, *_exc) -> None:
        self.zeroize()

    def __len__(self) -> int:
        return len(self._buf)

    def __del__(self) -> None:
        # Best-effort zeroization on GC
        self.zeroize()


def zeroize_bytearray(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros in-place."""
    for i in range(len(buf)):
        buf[i] = 0


def zeroize_dict_keys(keys_dict: dict) -> None:
    """
    Overwrite all key_data fields in a keys dictionary with zeros.

    This handles the in-memory keystore structure where each key entry
    has a 'versions' list, each containing a 'key_data' hex string.
    Since strings are immutable, we replace them with a zeroed bytearray
    of the same length, then clear the reference.
    """
    for entry in keys_dict.values():
        versions = entry.get("versions", [])
        for v in versions:
            key_data = v.get("key_data", "")
            if isinstance(key_data, bytearray):
                zeroize_bytearray(key_data)
            # Replace string references with empty (can't overwrite str in-place)
            v["key_data"] = ""
