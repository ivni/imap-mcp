"""Main server implementation for IMAP MCP."""

import argparse
import logging
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

import anyio
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from imap_mcp import metrics
from imap_mcp.config import ServerConfig, load_config
from imap_mcp.imap_client import ImapClient
from imap_mcp.logging_config import (
    configure_logging,
    reset_correlation_id,
    set_correlation_id,
)
from imap_mcp.metrics import ASGIApp, PrometheusMiddleware, Receive, Scope, Send
from imap_mcp.resources import register_resources
from imap_mcp.smtp_client import verify_smtp_connection
from imap_mcp.tools import register_tools

logger = logging.getLogger("imap_mcp")

# Inbound correlation IDs are sanitized to a conservative character set and
# length before use, so a hostile X-Request-ID cannot inject newlines into text
# logs or carry an unbounded payload into log records.
_CID_DISALLOWED = re.compile(r"[^A-Za-z0-9._-]")
_CID_MAX_LEN = 128

# The /ready probe opens a real IMAP connection. Cache the result briefly so the
# unauthenticated endpoint cannot be used to force an IMAP login (and provoke
# server-side rate limits or account lockouts) on every request.
_READINESS_CACHE_TTL_SECONDS = 5.0


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[Dict]:
    """Server lifespan manager to handle IMAP client lifecycle.

    Args:
        server: MCP server instance

    Yields:
        Context dictionary containing IMAP client
    """
    # Access the config that was set in create_server
    # The config is stored in the server's state
    config = getattr(server, "_config", None)
    if not config:
        # This is a fallback in case we can't find the config
        config = load_config()

    if not isinstance(config, ServerConfig):
        raise TypeError("Invalid server configuration")

    imap_client = ImapClient(config.imap, config.allowed_folders)

    def _connect_and_verify() -> None:
        imap_client.connect()
        # Verify IMAP connection works (essential — fail startup if broken)
        imap_client.verify_connection()

    session_active = False
    try:
        # Connect to IMAP server off the event loop: a slow login or
        # unresponsive server must not block other sessions while this one is
        # being established (issue #65).
        try:
            logger.info("Connecting to IMAP server...")
            await anyio.to_thread.run_sync(_connect_and_verify)
        except Exception:
            metrics.SESSION_CONNECTION_ERRORS.inc()
            raise

        metrics.SESSION_CONNECTIONS.inc()
        metrics.ACTIVE_SESSIONS.inc()
        session_active = True

        # Log effective folder access policy
        if config.allowed_folders:
            logger.info(
                "Folder access restricted to: %s",
                ", ".join(config.allowed_folders),
            )
        else:
            logger.info("Folder access: unrestricted (all folders)")

        # Build context with IMAP client and optional SMTP config
        context: Dict[str, Any] = {"imap_client": imap_client}
        if config.smtp:
            context["smtp_config"] = config.smtp

            # Verify SMTP connection (optional — warn on failure)
            try:
                verify_smtp_connection(config.smtp)
            except ConnectionError as e:
                logger.warning(
                    "SMTP verification failed; send/reply tools will be unavailable: %s",
                    e,
                )

        yield context
    finally:
        if session_active:
            metrics.ACTIVE_SESSIONS.dec()
        # Disconnect from IMAP server (off the event loop, like connect).
        logger.info("Disconnecting from IMAP server...")
        await anyio.to_thread.run_sync(imap_client.disconnect)


def _verify_imap_reachable(config: ServerConfig) -> None:
    """Open a short-lived IMAP connection and verify it works.

    Used by the readiness probe. Establishes its own connection rather than
    reusing a session's client, because IMAP connections in this server are
    created per MCP session (there is no shared server-wide connection).

    Args:
        config: Server configuration.

    Raises:
        ConnectionError: If the IMAP server is unreachable or login fails.
    """
    client = ImapClient(config.imap, config.allowed_folders)
    try:
        client.connect()
        client.verify_connection()
    finally:
        client.disconnect()


def create_server(
    config_path: Optional[str] = None,
    debug: bool = False,
    transport: str = "stdio",
    host: str = "127.0.0.1",
    port: int = 8010,
) -> FastMCP:
    """Create and configure the MCP server.

    Args:
        config_path: Path to configuration file
        debug: Enable debug mode
        transport: Transport protocol ("stdio" or "streamable-http")
        host: Host address for HTTP transport (default: 127.0.0.1)
        port: Port for HTTP transport (default: 8010)

    Returns:
        Configured MCP server instance
    """
    # Logging (including the debug level) is configured once by
    # ``configure_logging`` in ``main``; ``create_server`` must not also touch
    # the logger level to avoid double configuration.
    # Load configuration
    config = load_config(config_path)

    # Create MCP server with all the necessary capabilities
    server_kwargs: Dict[str, Any] = {
        "name": "IMAP",
        "instructions": "IMAP Model Context Protocol server for email processing",
        "lifespan": server_lifespan,
    }
    if transport == "streamable-http":
        server_kwargs["host"] = host
        server_kwargs["port"] = port

        # JWT auth via OIDC provider (required for HTTP transport)
        oidc_issuer = os.environ.get("OIDC_ISSUER_URL")
        if not oidc_issuer:
            raise ValueError(
                "OIDC_ISSUER_URL is required for streamable-http transport"
            )

        # Bind tokens to this server. Without an expected audience, any token
        # the trusted issuer minted for *another* resource server would be
        # accepted here (token passthrough / confused-deputy; see RFC 8707).
        # Require OIDC_AUDIENCE for HTTP transport; allow an explicit, logged
        # opt-out for setups that genuinely cannot scope tokens per audience.
        # Treat an empty/whitespace OIDC_AUDIENCE as unset so it cannot reach
        # the verifier as a (rejecting) empty expected audience.
        audience = (os.environ.get("OIDC_AUDIENCE") or "").strip() or None
        allow_any_audience = (
            os.environ.get("OIDC_ALLOW_ANY_AUDIENCE", "").lower() == "true"
        )
        if not audience and not allow_any_audience:
            raise ValueError(
                "OIDC_AUDIENCE is required for streamable-http transport: it binds "
                "tokens to this server so tokens issued for other resource servers "
                "of the same OIDC provider cannot be replayed here (token "
                "passthrough / confused-deputy). Set OIDC_AUDIENCE to this server's "
                "expected 'aud' claim, or set OIDC_ALLOW_ANY_AUDIENCE=true to "
                "explicitly opt out (NOT recommended)."
            )
        if not audience:
            logger.warning(
                "OIDC_AUDIENCE is not set and OIDC_ALLOW_ANY_AUDIENCE=true — JWT "
                "audience will NOT be verified; any token from the trusted issuer "
                "is accepted (token passthrough risk)."
            )

        from imap_mcp.auth import OIDCJWTVerifier, discover_jwks_uri

        jwks_uri = os.environ.get("OIDC_JWKS_URI") or discover_jwks_uri(oidc_issuer)
        mcp_server_url = os.environ.get(
            "MCP_RESOURCE_SERVER_URL", f"http://{host}:{port}/mcp"
        )

        server_kwargs["token_verifier"] = OIDCJWTVerifier(
            issuer=oidc_issuer,
            jwks_uri=jwks_uri,
            audience=audience,
        )
        server_kwargs["auth"] = AuthSettings(
            issuer_url=AnyHttpUrl(oidc_issuer),
            resource_server_url=AnyHttpUrl(mcp_server_url),
        )
        logger.info("OIDC JWT authentication enabled (issuer: %s)", oidc_issuer)

    server = FastMCP(**server_kwargs)

    # Store config for access in the lifespan
    server._config = config  # type: ignore[attr-defined]

    # Register resources and tools. The connected IMAP client is supplied
    # per-request from the lifespan context (see server_lifespan).
    register_resources(server)
    register_tools(server)

    # Health endpoints for container orchestrators. Routes registered via
    # custom_route bypass OIDC authentication by design (see FastMCP docs),
    # so probes work without credentials. Only reachable over HTTP transport.
    @server.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> Response:
        """Liveness probe: 200 whenever the process is serving HTTP."""
        return JSONResponse({"status": "ok"})

    # Cached readiness state shared across requests to this server instance.
    # ``lock`` (created lazily inside the event loop) coalesces concurrent
    # probes so at most one IMAP login runs per TTL window.
    readiness_cache: Dict[str, Any] = {
        "checked_at": None,
        "ready": False,
        "lock": None,
    }

    @server.custom_route("/ready", methods=["GET"])
    async def readiness_check(request: Request) -> Response:
        """Readiness probe: 200 only when the IMAP server is reachable.

        Opens a short-lived IMAP connection off the event loop, but caches the
        result for ``_READINESS_CACHE_TTL_SECONDS`` so a flood of unauthenticated
        probes cannot hammer the IMAP server with logins (rate-limit / lockout
        risk). Returns 503 when IMAP is unreachable so orchestrators hold traffic
        until the dependency recovers. Response bodies carry no connection
        details.
        """

        def _is_fresh() -> bool:
            checked_at = readiness_cache["checked_at"]
            return (
                checked_at is not None
                and (time.monotonic() - checked_at) < _READINESS_CACHE_TTL_SECONDS
            )

        if not _is_fresh():
            lock = readiness_cache["lock"]
            if lock is None:
                # Safe to create without its own guard: the event loop is
                # single-threaded between awaits, and no await precedes this.
                lock = anyio.Lock()
                readiness_cache["lock"] = lock
            async with lock:
                # Another request may have refreshed the cache while we waited.
                if not _is_fresh():
                    try:
                        await anyio.to_thread.run_sync(_verify_imap_reachable, config)
                        readiness_cache["ready"] = True
                    except Exception:
                        # A probe must never propagate: any failure means "not
                        # ready". Detail is intentionally omitted to avoid
                        # leaking config to unauthenticated callers; the cause is
                        # logged server-side.
                        logger.warning(
                            "Readiness check failed: IMAP server unreachable"
                        )
                        readiness_cache["ready"] = False
                    readiness_cache["checked_at"] = time.monotonic()

        if readiness_cache["ready"]:
            return JSONResponse({"status": "ready"})
        return JSONResponse({"status": "unavailable"}, status_code=503)

    @server.custom_route("/metrics", methods=["GET"])
    async def metrics_endpoint(request: Request) -> Response:
        """Prometheus scrape endpoint exposing request and IMAP session metrics.

        Unauthenticated, like the health probes (custom routes bypass OIDC).
        Exposes only aggregate counters/gauges — never email content or
        connection details — so restrict it to the monitoring network.
        """
        body, content_type = metrics.render_latest()
        return Response(body, media_type=content_type)

    # Add server status tool
    @server.tool(
        title="Server Status",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    def server_status() -> str:
        """Return IMAP MCP server configuration and connection status.

        Shows IMAP host, port, username, SSL settings, allowed folders,
        and SMTP configuration. Does not reveal passwords.
        """
        status = {
            "server": "IMAP MCP",
            "imap_host": config.imap.host,
            "imap_port": config.imap.port,
            "imap_user": config.imap.username,
            "imap_ssl": config.imap.use_ssl,
        }

        if config.imap.tls_ca_bundle:
            status["imap_tls_ca_bundle"] = config.imap.tls_ca_bundle

        if config.allowed_folders:
            status["allowed_folders"] = list(config.allowed_folders)
        else:
            status["allowed_folders"] = "All folders allowed (explicitly configured)"

        if config.smtp:
            status["smtp_host"] = config.smtp.host
            status["smtp_port"] = config.smtp.port
            status["smtp_user"] = config.smtp.username
            status["smtp_tls"] = config.smtp.use_tls
        else:
            status["smtp"] = "Not configured"

        return "\n".join(f"{k}: {v}" for k, v in status.items())

    return server


def _sanitize_correlation_id(value: str) -> str:
    """Reduce an inbound correlation ID to a safe, bounded token.

    Strips characters outside ``[A-Za-z0-9._-]`` and truncates, so a hostile
    ``X-Request-ID`` cannot inject log-line breaks or carry an oversized payload.
    Returns an empty string when nothing usable remains.
    """
    return _CID_DISALLOWED.sub("", value)[:_CID_MAX_LEN]


class CorrelationIdMiddleware:
    """Bind a correlation ID to each HTTP request for log correlation.

    Reuses a sanitized inbound ``X-Request-ID`` header when present (preserving
    an upstream proxy's ID end-to-end), otherwise generates one. The ID is
    echoed in the ``X-Request-ID`` response header and bound to the logging
    context (a ``ContextVar``) for the request's duration — including offloaded
    IMAP work, since ``anyio.to_thread.run_sync`` copies the active context.

    Raw ASGI (not ``BaseHTTPMiddleware``) so the streaming /mcp endpoint is not
    buffered.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        inbound = Headers(scope=scope).get("x-request-id", "")
        correlation_id = _sanitize_correlation_id(inbound) or uuid.uuid4().hex
        token = set_correlation_id(correlation_id)

        async def send_wrapper(message: Any) -> None:
            if message.get("type") == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["x-request-id"] = correlation_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_correlation_id(token)


def build_streamable_http_app(server: FastMCP) -> Starlette:
    """Build the streamable-HTTP ASGI app wrapped with observability middleware.

    Adds correlation-ID and Prometheus middleware around FastMCP's app. Both are
    raw ASGI middleware, so the streaming /mcp endpoint is not buffered.
    Middleware is added before the app serves any request, so Starlette's
    deferred stack is still mutable.
    """
    app = server.streamable_http_app()
    known_paths = frozenset(
        {server.settings.streamable_http_path, "/health", "/ready", "/metrics"}
    )
    # add_middleware prepends, so the last added is outermost. Correlation ID
    # must be bound before anything else runs, so add it last (outermost).
    app.add_middleware(PrometheusMiddleware, known_paths=known_paths)
    app.add_middleware(CorrelationIdMiddleware)
    return app


def _run_http(server: FastMCP, host: str, port: int) -> None:
    """Serve the streamable-HTTP app with uvicorn, including observability.

    Runs uvicorn directly (rather than ``server.run``) so the correlation-ID and
    Prometheus middleware wrap the app. ``log_config=None`` leaves uvicorn's
    loggers propagating to the root handler configured by ``configure_logging``,
    so its output follows the same (optionally JSON) format.
    """
    import uvicorn

    app = build_streamable_http_app(server)
    uvicorn.run(app, host=host, port=port, log_config=None)


def main() -> None:
    """Run the IMAP MCP server."""
    parser = argparse.ArgumentParser(description="IMAP MCP Server")
    parser.add_argument(
        "--config",
        help="Path to configuration file",
        default=os.environ.get("IMAP_MCP_CONFIG"),
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="Transport protocol (env: MCP_TRANSPORT)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Host for HTTP transport (env: MCP_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MCP_PORT", "8010")),
        help="Port for HTTP transport (env: MCP_PORT)",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Enable development mode",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information and exit",
    )
    args = parser.parse_args()

    if args.version:
        print("IMAP MCP Server version 0.1.0")
        return

    # Configure logging before anything logs; honors IMAP_MCP_LOG_FORMAT.
    configure_logging(debug=args.debug)

    server = create_server(
        args.config, args.debug, args.transport, args.host, args.port
    )

    # Start the server
    logger.info(
        "Starting server{}...".format(" in development mode" if args.dev else "")
    )
    if args.transport == "streamable-http":
        _run_http(server, args.host, args.port)
    else:
        server.run(transport=args.transport)


if __name__ == "__main__":
    main()
