"""Main server implementation for IMAP MCP."""

import argparse
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional

import anyio
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from imap_mcp.config import ServerConfig, load_config
from imap_mcp.imap_client import ImapClient
from imap_mcp.resources import register_resources
from imap_mcp.smtp_client import verify_smtp_connection
from imap_mcp.tools import register_tools

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("imap_mcp")


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

    try:
        # Connect to IMAP server
        logger.info("Connecting to IMAP server...")
        imap_client.connect()

        # Verify IMAP connection works (essential — fail startup if broken)
        imap_client.verify_connection()

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
        # Disconnect from IMAP server
        logger.info("Disconnecting from IMAP server...")
        imap_client.disconnect()


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
    # Set up logging level
    if debug:
        logger.setLevel(logging.DEBUG)

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

        from imap_mcp.auth import OIDCJWTVerifier, discover_jwks_uri

        jwks_uri = os.environ.get("OIDC_JWKS_URI") or discover_jwks_uri(oidc_issuer)
        audience = os.environ.get("OIDC_AUDIENCE")
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

    @server.custom_route("/ready", methods=["GET"])
    async def readiness_check(request: Request) -> Response:
        """Readiness probe: 200 only when the IMAP server is reachable.

        Opens a short-lived IMAP connection off the event loop. Returns 503
        when IMAP is unreachable so orchestrators hold traffic until the
        dependency recovers. Response bodies carry no connection details.
        """
        try:
            await anyio.to_thread.run_sync(_verify_imap_reachable, config)
        except Exception:
            # A probe must never propagate: any failure means "not ready".
            # Detail is intentionally omitted to avoid leaking config to
            # unauthenticated callers; the cause is logged server-side.
            logger.warning("Readiness check failed: IMAP server unreachable")
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

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

    if args.debug:
        logger.setLevel(logging.DEBUG)

    server = create_server(
        args.config, args.debug, args.transport, args.host, args.port
    )

    # Start the server
    logger.info(
        "Starting server{}...".format(" in development mode" if args.dev else "")
    )
    server.run(transport=args.transport)


if __name__ == "__main__":
    main()
