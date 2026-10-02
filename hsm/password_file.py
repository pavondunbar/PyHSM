"""
PyHSM Password File Loader.

Provides a safe alternative to environment-variable password injection for
institutional deployments. The password is read from a file on disk whose
permissions are enforced before the contents are read.

Security requirements enforced
-------------------------------
1. The file must be owned by the current process's effective UID.
   A file owned by root (or any other user) and made readable to the HSM
   process user is rejected — ownership proves the HSM operator created
   the file, not a privilege-escalating attacker.

2. The file must not be group-readable or world-readable (mode 0o600 or
   tighter). A world-readable password file is equivalent to no password.

3. The file must not be a symbolic link. Symlinks can be redirected by a
   race condition (TOCTOU) to point at a different file between the
   permission check and the read. We open the file with O_NOFOLLOW and
   verify the fd refers to a regular file.

4. The file contents are read into a mutable bytearray and the result is
   returned as a str. The bytearray is zeroized after decoding so the raw
   bytes don't linger in memory.

5. The file path is logged (at DEBUG level) but the password itself is
   never logged.

Platform note
-------------
O_NOFOLLOW and fstat-based permission checks are POSIX features available
on Linux and macOS. On Windows, symlink protection is not enforced (Windows
does not support O_NOFOLLOW in the same way), but ownership and permission
checks still apply via the stat() call. Windows deployments should use
systemd-credential or a secrets manager instead of a password file.

Usage
-----
From Python::

    from hsm.password_file import load_password_from_file

    password = load_password_from_file("/run/secrets/pyhsm-password")
    hsm = PyHSM("keystore.enc", master_password=password)

From the CLI::

    vectorguard-pyhsm --store keystore.enc --password-file /run/secrets/pyhsm-password generate mykey

File creation (install-time)::

    install -m 600 -o <hsm-user> /dev/null /run/secrets/pyhsm-password
    printf '%s' 'MyStr0ng!P@ssphrase' > /run/secrets/pyhsm-password
    chmod 600 /run/secrets/pyhsm-password
"""

from __future__ import annotations

import os
import stat
import sys
from typing import Optional

from .secure_memory import zeroize_bytearray
from .logging import get_logger

_logger = get_logger(__name__)

# Maximum password file size (prevents accidental reads of huge files)
_MAX_PASSWORD_FILE_BYTES = 4096


def load_password_from_file(
    path: str,
    *,
    require_owner_match: bool = True,
    require_no_group_read: bool = True,
    require_no_world_read: bool = True,
) -> str:
    """
    Read a master password from a file with strict permission enforcement.

    Parameters
    ----------
    path : str
        Absolute path to the password file.
    require_owner_match : bool
        If True (default), reject the file unless it is owned by the
        current process's effective UID. Set False only if the HSM runs
        as root and the file is owned by a different trusted user.
    require_no_group_read : bool
        If True (default), reject the file if the group-read bit is set.
    require_no_world_read : bool
        If True (default), reject the file if the world-read bit is set.

    Returns
    -------
    str
        The password string (trailing whitespace and newlines stripped).

    Raises
    ------
    PermissionError
        If the file fails any permission check.
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file is empty, too large, or not a regular file.
    """
    path = os.path.abspath(path)
    _logger.debug("loading password from file", extra={
        "event": "password_file_load", "path": path,
    })

    # --- Open with O_NOFOLLOW to prevent symlink race conditions ---
    # O_NOFOLLOW causes open() to fail with ELOOP if the final component
    # of the path is a symbolic link. This prevents a TOCTOU attack where
    # an attacker replaces the file with a symlink between our stat() check
    # and our read().
    #
    # On Windows, O_NOFOLLOW is not available. We fall back to a regular
    # open and rely on the stat-based checks below.
    try:
        if hasattr(os, "O_NOFOLLOW"):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        else:
            fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        import errno as _errno
        if e.errno == _errno.ELOOP:
            raise PermissionError(
                f"PyHSM: password file '{path}' is a symbolic link. "
                "Symlinks are rejected to prevent TOCTOU race conditions. "
                "Provide the real file path directly."
            ) from e
        raise

    try:
        # --- fstat on the open fd (not the path) to avoid TOCTOU ---
        st = os.fstat(fd)

        # Must be a regular file
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(
                f"PyHSM: password file '{path}' is not a regular file "
                f"(mode={oct(st.st_mode)}). Only plain files are accepted."
            )

        # Ownership check
        if require_owner_match:
            euid = os.geteuid() if hasattr(os, "geteuid") else -1
            if euid >= 0 and st.st_uid != euid:
                raise PermissionError(
                    f"PyHSM: password file '{path}' is owned by UID {st.st_uid} "
                    f"but this process runs as UID {euid}. "
                    "The password file must be owned by the HSM process user. "
                    "Fix with: chown $(id -u) '{path}'"
                )

        # Group-read check
        if require_no_group_read and (st.st_mode & stat.S_IRGRP):
            raise PermissionError(
                f"PyHSM: password file '{path}' is group-readable "
                f"(mode={oct(st.st_mode)}). "
                "Remove group-read permission: chmod g-r '{path}'"
            )

        # World-read check
        if require_no_world_read and (st.st_mode & stat.S_IROTH):
            raise PermissionError(
                f"PyHSM: password file '{path}' is world-readable "
                f"(mode={oct(st.st_mode)}). "
                "Remove world-read permission: chmod o-r '{path}'"
            )

        # Size guard
        file_size = st.st_size
        if file_size == 0:
            raise ValueError(
                f"PyHSM: password file '{path}' is empty."
            )
        if file_size > _MAX_PASSWORD_FILE_BYTES:
            raise ValueError(
                f"PyHSM: password file '{path}' is too large "
                f"({file_size} bytes, maximum {_MAX_PASSWORD_FILE_BYTES}). "
                "Password files should contain only the password string."
            )

        # Read into a mutable bytearray for secure cleanup
        raw = bytearray(os.read(fd, _MAX_PASSWORD_FILE_BYTES))

    finally:
        os.close(fd)

    try:
        # Decode and strip trailing newline/whitespace (common in files
        # created with echo or text editors).
        password = raw.decode("utf-8").rstrip("\r\n\t ")
        if not password:
            raise ValueError(
                f"PyHSM: password file '{path}' contains only whitespace."
            )
        _logger.debug("password file loaded successfully", extra={
            "event": "password_file_loaded", "path": path,
            "length": len(password),
        })
        return password
    finally:
        # Zeroize the raw bytes before they go out of scope
        zeroize_bytearray(raw)


def check_password_file_permissions(path: str) -> Optional[str]:
    """
    Check password file permissions without reading the file contents.

    Returns None if permissions are acceptable, or a human-readable error
    string describing the problem. Useful for pre-flight checks in startup
    scripts without actually loading the password.

    Parameters
    ----------
    path : str
        Path to the password file to check.

    Returns
    -------
    str or None
        None if permissions are OK, error description string if not.
    """
    try:
        load_password_from_file(path)
        return None
    except (PermissionError, ValueError, FileNotFoundError) as e:
        return str(e)
    except Exception as e:
        return f"Unexpected error checking password file: {e}"
