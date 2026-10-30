# Copyright (c) 2026 VectorGuard Labs (Pavon Dunbar)
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This file is part of PyHSM. For commercial licensing (use in proprietary
# products or services without AGPL obligations), contact:
# pavon@vectorguardlabs.com

"""
PyHSM Per-Key Sliding-Window Rate Limiter.

Prevents bulk decryption attacks by limiting how many operations
any single key can service within a rolling time window.
Mirrors the TypeScript RateLimiter module.

Thread-safety (v2.3.1+)
------------------------
All operations are protected by a global lock to prevent race conditions
when multiple threads call allow() on the same key_id concurrently. The
previous implementation had a check-then-act race where two threads could
both pass the len(window) >= max_ops check before either appended, allowing
up to 2×max_ops operations through in a burst.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Dict


class RateLimiter:
    """
    Sliding-window rate limiter keyed by key_id.

    Thread-safe: all public methods acquire a global lock before accessing
    shared state. The lock granularity is coarse (not per-key), but the
    critical section is short (typically 1-2 deque operations), so contention
    is minimal under realistic load.

    Parameters
    ----------
    max_ops_per_window : int
        Maximum number of operations allowed per key per window. Default 100.
    window_seconds : float
        Duration of the sliding window in seconds. Default 60.
    """

    def __init__(self, max_ops_per_window: int = 100, window_seconds: float = 60.0) -> None:
        self._max_ops = max_ops_per_window
        self._window_s = window_seconds
        self._windows: Dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key_id: str) -> bool:
        """
        Check and record an operation attempt.
        Returns True if allowed, False if the key is rate-limited.

        Thread-safe: acquires self._lock before read-modify-write.
        """
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_s
            window = self._windows.get(key_id)
            if window is None:
                window = deque()
                self._windows[key_id] = window

            # Evict expired timestamps — O(1) per eviction with deque.popleft()
            while window and window[0] <= cutoff:
                window.popleft()

            if len(window) >= self._max_ops:
                return False

            window.append(now)
            return True

    def usage(self, key_id: str) -> dict:
        """Return current usage statistics for a key.
        
        Thread-safe: acquires self._lock before reading shared state.
        """
        with self._lock:
            now = time.monotonic()
            cutoff = now - self._window_s
            window = self._windows.get(key_id, deque())
            current = sum(1 for t in window if t > cutoff)
            return {"current": current, "max": self._max_ops, "window_seconds": self._window_s}

    def reset(self, key_id: str) -> None:
        """Reset the rate-limit window for a key (e.g. after key destruction).
        
        Thread-safe: acquires self._lock before mutating shared state.
        """
        with self._lock:
            self._windows.pop(key_id, None)
