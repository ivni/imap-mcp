"""Structured logging and per-request correlation IDs (issue #67).

Logging is human-readable plaintext by default. Set ``IMAP_MCP_LOG_FORMAT=json``
to emit one JSON object per line instead — suitable for ingestion by log
aggregators (ELK, Datadog, Loki, …).

A correlation ID is bound per HTTP request (see
``CorrelationIdMiddleware`` in ``server.py``) and attached to every log record
produced while handling that request, including records emitted from worker
threads — ``anyio.to_thread.run_sync`` copies the active context, so the
``ContextVar`` set in the request task is visible in the offloaded IMAP work.

Security: this module only *formats* records the application already emits. It
adds no fields sourced from log-message arguments, so the project-wide invariant
that email content, subjects, addresses, and credentials are never logged (see
CLAUDE.md) is preserved regardless of the chosen format.
"""

import contextvars
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

LOG_FORMAT_ENV = "IMAP_MCP_LOG_FORMAT"

_TEXT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Holds the correlation ID for the active request/task. Defaults to None outside
# an HTTP request (e.g. stdio transport, startup, shutdown).
_correlation_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "imap_mcp_correlation_id", default=None
)


def get_correlation_id() -> Optional[str]:
    """Return the correlation ID bound to the current context, if any."""
    return _correlation_id.get()


def set_correlation_id(value: str) -> contextvars.Token[Optional[str]]:
    """Bind *value* as the current correlation ID.

    Returns:
        A token to pass to :func:`reset_correlation_id` to restore the previous
        value (use it in a ``finally`` block).
    """
    return _correlation_id.set(value)


def reset_correlation_id(token: contextvars.Token[Optional[str]]) -> None:
    """Restore the correlation ID to its value before :func:`set_correlation_id`."""
    _correlation_id.reset(token)


class _CorrelationIdFilter(logging.Filter):
    """Snapshot the active correlation ID onto each record as ``correlation_id``."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _correlation_id.get()
        return True


class _TextFormatter(logging.Formatter):
    """Plaintext formatter that appends the correlation ID only when present.

    Output is identical to the historical format when no correlation ID is
    bound (the common case for stdio), and gains a trailing ``[cid=...]`` marker
    during HTTP requests.
    """

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        cid = getattr(record, "correlation_id", None)
        return f"{base} [cid={cid}]" if cid else base


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON objects.

    Only a fixed set of non-sensitive fields is serialized — timestamp, level,
    logger name, message, optional correlation ID, and (when present) exception
    text. Arbitrary record attributes are never emitted, so no caller-supplied
    data can leak through this formatter.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        cid = getattr(record, "correlation_id", None)
        if cid:
            payload["correlation_id"] = cid
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _build_formatter() -> logging.Formatter:
    """Select the formatter based on ``IMAP_MCP_LOG_FORMAT`` (json | text)."""
    if os.environ.get(LOG_FORMAT_ENV, "text").strip().lower() == "json":
        return JsonFormatter()
    return _TextFormatter(_TEXT_FORMAT)


def configure_logging(debug: bool = False) -> None:
    """Configure root logging once, honoring ``IMAP_MCP_LOG_FORMAT``.

    Installs a single stderr handler with the correlation-ID filter and the
    selected formatter, replacing any handlers a previous call added. Safe to
    call more than once (idempotent); the level is updated on each call.

    Args:
        debug: When True, set the root level to DEBUG instead of INFO.
    """
    handler = logging.StreamHandler()
    handler.addFilter(_CorrelationIdFilter())
    handler.setFormatter(_build_formatter())

    root = logging.getLogger()
    # Replace handlers so repeated calls (e.g. import then main()) don't stack.
    for existing in root.handlers[:]:
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug else logging.INFO)
