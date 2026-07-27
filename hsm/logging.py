"""
PyHSM Structured Logging.

JSON-structured logging via stdlib ``logging``. Every log entry is a single
JSON line with consistent fields for machine parsing, SIEM ingestion, and
3am incident debugging.

Usage within PyHSM internals::

    from .logging import get_logger
    logger = get_logger(__name__)
    logger.info("key generated", extra={"key_id": "my-key", "key_type": "aes-256"})

Configuration by consumers::

    import logging
    # To see PyHSM logs at INFO level:
    logging.getLogger("hsm").setLevel(logging.INFO)

    # To send to a file:
    handler = logging.FileHandler("/var/log/pyhsm.log")
    logging.getLogger("hsm").addHandler(handler)

    # To silence PyHSM logs:
    logging.getLogger("hsm").setLevel(logging.CRITICAL)

Environment variable override:
    PYHSM_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR|CRITICAL
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any


class _JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects.

    Output fields:
      - timestamp: ISO-8601 UTC
      - level: DEBUG/INFO/WARNING/ERROR/CRITICAL
      - logger: logger name (e.g., "hsm.core")
      - message: the log message
      - ... any extra fields passed via ``extra={}``

    Internal fields (exc_info, stack_info, args) are excluded from output
    unless they carry useful information.
    """

    # Fields from LogRecord that are internal/noise — not included in JSON output
    _SKIP_FIELDS = frozenset({
        "name", "msg", "args", "created", "relativeCreated", "thread",
        "threadName", "msecs", "pathname", "filename", "module", "exc_info",
        "exc_text", "stack_info", "lineno", "funcName", "levelname",
        "levelno", "processName", "process", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include any extra fields the caller passed
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in self._SKIP_FIELDS:
                continue
            entry[key] = value

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str, ensure_ascii=False)


def _configure_root_logger() -> None:
    """One-time setup of the 'hsm' root logger with JSON formatting.

    Called automatically on first import. Adds a StreamHandler (stderr)
    with JSON formatting. The log level defaults to WARNING but can be
    overridden via the PYHSM_LOG_LEVEL environment variable.
    """
    root = logging.getLogger("hsm")

    # Don't add handlers if already configured (e.g., by consuming application)
    if root.handlers:
        return

    handler = logging.StreamHandler()
    handler.setFormatter(_JSONFormatter())
    root.addHandler(handler)

    # Default to WARNING so PyHSM is quiet unless asked to be verbose.
    # Consumers can override via PYHSM_LOG_LEVEL or programmatic config.
    level_name = os.environ.get("PYHSM_LOG_LEVEL", "WARNING").upper()
    level = getattr(logging, level_name, logging.WARNING)
    root.setLevel(level)

    # Don't propagate to root logger (avoid duplicate output)
    root.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Get a child logger under the 'hsm' namespace.

    Args:
        name: Module name (typically __name__). If it doesn't start with
              'hsm', it will be prefixed automatically.

    Returns:
        A configured logging.Logger instance.
    """
    if not name.startswith("hsm"):
        name = f"hsm.{name}"
    return logging.getLogger(name)


# Auto-configure on import
_configure_root_logger()
