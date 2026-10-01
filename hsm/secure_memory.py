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
    Overwrite all ``key_data`` bytearrays in a keys dictionary with zeros.

    This handles the in-memory keystore structure where each key entry
    has a ``versions`` list, each containing a ``key_data`` field. When
    that field is a ``bytearray`` (the normal in-memory representation
    after ``_internalize_key_data()`` has run), it is overwritten in-place
    with zeros for deterministic memory erasure.

    LIMITATION — Python string immutability
    ----------------------------------------
    If ``key_data`` is a ``str`` (e.g. on a code path that skips
    internalization, or in a very old keystore format), this function
    **cannot** zeroize it. Python ``str`` objects are immutable — there
    is no way to overwrite their underlying bytes in place. In that case
    the field is set to an empty string ``""``, which removes the key
    material from the dict object itself, but the original string value
    may linger in the CPython heap until garbage collected.

    All production code paths in PyHSM call ``_internalize_key_data()``
    immediately after JSON deserialisation, converting ``str`` values to
    ``bytearray`` before any cryptographic use. This function therefore
    operates on ``bytearray`` values in all normal usage.
    """
    for key_id, entry in keys_dict.items():
        if isinstance(entry, str):
            continue  # skip metadata fields like _kek_salt
        versions = entry.get("versions", [])
        for v in versions:
            key_data = v.get("key_data", "")
            if isinstance(key_data, bytearray):
                # Mutable — overwrite in place deterministically.
                zeroize_bytearray(key_data)
            # Whether bytearray or str, clear the dict reference.
            # For str values this only removes the reference from the dict;
            # the original immutable string object cannot be zeroed.
            v["key_data"] = ""
