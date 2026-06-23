"""Prometheus metrics for production observability (issue #67).

Defines the process-wide metric instruments and the ASGI middleware that
records HTTP request counts and latencies. Metrics are exposed over the
``/metrics`` endpoint (registered in ``server.py``) in the standard Prometheus
text exposition format.

Security: metric labels are restricted to fixed, non-sensitive dimensions
(HTTP method, a normalized path, status code). Email content, subjects,
addresses, and credentials are never used as label values — consistent with the
project-wide rule that such data is never logged or exported (see CLAUDE.md).
Request paths are normalized against a known-route allowlist so that
unauthenticated callers (the ``/metrics`` and health routes bypass auth) cannot
inflate label cardinality by hitting arbitrary URLs.
"""

import time
from typing import Any, Awaitable, Callable, FrozenSet, MutableMapping, Tuple

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# --- Metric instruments (process-wide singletons) ---------------------------

REQUEST_COUNT = Counter(
    "imap_mcp_http_requests_total",
    "Total HTTP requests handled, labeled by method, normalized path, and "
    "response status code.",
    ["method", "path", "status"],
)

REQUEST_LATENCY = Histogram(
    "imap_mcp_http_request_duration_seconds",
    "HTTP request latency in seconds, labeled by method and normalized path.",
    ["method", "path"],
)

ACTIVE_SESSIONS = Gauge(
    "imap_mcp_active_sessions",
    "MCP sessions currently holding a live IMAP connection.",
)

SESSION_CONNECTIONS = Counter(
    "imap_mcp_session_connections_total",
    "MCP sessions that successfully established an IMAP connection.",
)

SESSION_CONNECTION_ERRORS = Counter(
    "imap_mcp_session_connection_errors_total",
    "MCP sessions that failed to establish an IMAP connection at startup.",
)

# Label value used for any request path outside the known-route allowlist.
# Keeps the ``path`` label bounded regardless of arbitrary inbound URLs.
_OTHER_PATH = "other"

# Minimal ASGI type aliases (ASGI dicts are intentionally loosely typed).
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def render_latest() -> Tuple[bytes, str]:
    """Render all registered metrics in the Prometheus text format.

    Returns:
        A ``(body, content_type)`` tuple ready to use in an HTTP response.
    """
    return generate_latest(), CONTENT_TYPE_LATEST


class PrometheusMiddleware:
    """ASGI middleware that records request counts and latencies.

    Implemented as raw ASGI (not Starlette's ``BaseHTTPMiddleware``) so it does
    not buffer responses — the MCP streamable-http endpoint streams, and
    ``BaseHTTPMiddleware`` would break that.

    Args:
        app: The wrapped ASGI application.
        known_paths: Exact request paths that are recorded verbatim in the
            ``path`` label. Any other path is recorded as ``"other"`` to bound
            label cardinality.
    """

    def __init__(self, app: ASGIApp, known_paths: FrozenSet[str]) -> None:
        self.app = app
        self.known_paths = known_paths

    def _label_path(self, raw_path: str) -> str:
        return raw_path if raw_path in self.known_paths else _OTHER_PATH

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method", "GET"))
        path = self._label_path(str(scope.get("path", "")))
        # Status defaults to 500: if the app errors before sending a response
        # start message, the failure is still counted rather than dropped.
        status = 500

        async def send_wrapper(message: Message) -> None:
            if message.get("type") == "http.response.start":
                nonlocal status
                status = int(message.get("status", 500))
            await send(message)

        start = time.perf_counter()
        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - start
            REQUEST_COUNT.labels(method, path, str(status)).inc()
            REQUEST_LATENCY.labels(method, path).observe(duration)
