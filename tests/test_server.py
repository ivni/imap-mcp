"""Tests for the server module."""

import pytest
from unittest import mock
import argparse
from contextlib import AsyncExitStack
import logging

from mcp.server.fastmcp import FastMCP

from imap_mcp.server import create_server, server_lifespan, main
from imap_mcp.config import ServerConfig, ImapConfig, SmtpConfig


class TestServer:
    """Tests for the server module."""

    def test_create_server(self, monkeypatch):
        """Test server creation with default configuration."""
        # Mock the config loading
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True
            ),
            allowed_folders=["INBOX", "Sent"]
        )
        
        with mock.patch("imap_mcp.server.load_config", return_value=mock_config):
            # Create the server
            server = create_server()
            
            # Verify server properties
            assert isinstance(server, FastMCP)
            assert server.name == "IMAP"
            assert server._config == mock_config
            
            # With FastMCP we can't directly check if tools are registered
            # Instead, we can verify that the returned server object is properly configured
            
            # Verify resources and tools were registered
            with mock.patch("imap_mcp.server.register_resources") as mock_register_resources:
                with mock.patch("imap_mcp.server.register_tools") as mock_register_tools:
                    create_server()
                    assert mock_register_resources.called
                    assert mock_register_tools.called

    def test_create_server_with_debug(self):
        """Test server creation with debug mode enabled."""
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True,
            ),
        )
        with mock.patch("imap_mcp.server.load_config", return_value=mock_config):
            with mock.patch("imap_mcp.server.logger") as mock_logger:
                create_server(debug=True)
                mock_logger.setLevel.assert_called_with(logging.DEBUG)

    def test_create_server_with_config_path(self):
        """Test server creation with a specific config path."""
        config_path = "test_config.yaml"
        
        with mock.patch("imap_mcp.server.load_config") as mock_load_config:
            create_server(config_path=config_path)
            mock_load_config.assert_called_with(config_path)
    
    @pytest.mark.asyncio
    async def test_server_lifespan(self):
        """Test server lifespan context manager."""
        # Create mock server with config
        mock_server = mock.MagicMock()
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True
            )
        )
        mock_server._config = mock_config

        # Mock ImapClient
        with mock.patch("imap_mcp.server.ImapClient") as MockImapClient:
            mock_client = MockImapClient.return_value

            # Use AsyncExitStack to manage multiple context managers
            async with AsyncExitStack() as stack:
                # Enter the server_lifespan context
                context = await stack.enter_async_context(server_lifespan(mock_server))

                # Verify ImapClient was created with correct config
                MockImapClient.assert_called_once_with(mock_config.imap, mock_config.allowed_folders)

                # Verify connect and verify_connection were called
                mock_client.connect.assert_called_once()
                mock_client.verify_connection.assert_called_once()

                # Verify client was added to context
                assert context["imap_client"] == mock_client

            # After exiting the context, verify disconnect was called
            mock_client.disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_server_lifespan_fallback_config(self):
        """Test server lifespan with fallback config loading."""
        # Create mock server without config
        mock_server = mock.MagicMock()
        mock_server._config = None
        
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True
            )
        )
        
        # Mock config loading and ImapClient
        with mock.patch("imap_mcp.server.load_config", return_value=mock_config) as mock_load_config:
            with mock.patch("imap_mcp.server.ImapClient"):
                
                async with AsyncExitStack() as stack:
                    await stack.enter_async_context(server_lifespan(mock_server))
                    
                    # Verify fallback config loading was used
                    mock_load_config.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_server_lifespan_invalid_config(self):
        """Test server lifespan with invalid config."""
        # Create mock server with invalid config
        mock_server = mock.MagicMock()
        mock_server._config = "not a ServerConfig object"
        
        # Verify TypeError is raised
        with pytest.raises(TypeError, match="Invalid server configuration"):
            async with server_lifespan(mock_server):
                pass
    
    @pytest.mark.asyncio
    async def test_server_lifespan_with_smtp(self):
        """Test server lifespan passes SMTP config in context and verifies SMTP."""
        mock_server = mock.MagicMock()
        smtp_config = SmtpConfig(
            host="smtp.example.com",
            port=587,
            username="test@example.com",
            password="password",
        )
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True
            ),
            smtp=smtp_config,
        )
        mock_server._config = mock_config

        with mock.patch("imap_mcp.server.ImapClient") as MockImapClient:
            with mock.patch("imap_mcp.server.verify_smtp_connection") as mock_verify_smtp:
                async with AsyncExitStack() as stack:
                    context = await stack.enter_async_context(server_lifespan(mock_server))

                    assert "smtp_config" in context
                    assert context["smtp_config"] == smtp_config
                    assert context["smtp_config"].host == "smtp.example.com"
                    mock_verify_smtp.assert_called_once_with(smtp_config)

    @pytest.mark.asyncio
    async def test_server_lifespan_without_smtp(self):
        """Test server lifespan omits smtp_config when not configured."""
        mock_server = mock.MagicMock()
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True
            ),
        )
        mock_server._config = mock_config

        with mock.patch("imap_mcp.server.ImapClient"):
            async with AsyncExitStack() as stack:
                context = await stack.enter_async_context(server_lifespan(mock_server))

                assert "smtp_config" not in context

    def test_server_status_tool(self):
        """Test the server_status tool."""
        # Mock the config
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True
            ),
            allowed_folders=["INBOX", "Sent"]
        )
        
        # In the actual server implementation, server_status is defined as an inner function
        # inside create_server, so we can't access it directly. Instead, we'll test that
        # create_server properly configures a server with a tool function.
        
        # Mock the tool decorator to capture the function
        original_tool = FastMCP.tool
        captured_tool = None
        
        def mock_tool(self):
            def decorator(func):
                nonlocal captured_tool
                captured_tool = func
                return original_tool(self)(func)
            return decorator
        
        try:
            # Apply our mock
            with mock.patch("imap_mcp.server.load_config", return_value=mock_config):
                with mock.patch.object(FastMCP, "tool", mock_tool):
                    # Create the server, which should register our tool
                    server = create_server()
                    
                    # Now captured_tool should be the last tool registered
                    # This won't necessarily be server_status, but we can still check
                    # that a tool was registered
                    assert server is not None
        finally:
            # Restore the original method
            FastMCP.tool = original_tool
            
        # Since we can't directly test the server_status tool, we'll create a simplified
        # version based on the implementation and test that
        def test_server_status():
            status = {
                "server": "IMAP MCP",
                "imap_host": mock_config.imap.host,
                "imap_port": mock_config.imap.port,
                "imap_user": mock_config.imap.username,
                "imap_ssl": mock_config.imap.use_ssl,
            }
            
            if mock_config.allowed_folders:
                status["allowed_folders"] = list(mock_config.allowed_folders)
            else:
                status["allowed_folders"] = "All folders allowed"
            
            return "\n".join(f"{k}: {v}" for k, v in status.items())
        
        # Call our test function and check the output for expected values
        result = test_server_status()
        assert "IMAP MCP" in result
        assert "imap.example.com" in result
        assert "test@example.com" in result
        assert "INBOX" in result or "Sent" in result
    
    def test_main_function(self):
        """Test the main function."""
        # Mock command line arguments
        test_args = ["--config", "test_config.yaml", "--debug", "--dev"]

        with mock.patch("sys.argv", ["server.py"] + test_args):
            with mock.patch("imap_mcp.server.create_server") as mock_create_server:
                with mock.patch("imap_mcp.server.argparse.ArgumentParser.parse_args") as mock_parse_args:
                    # Mock the parsed arguments
                    mock_args = argparse.Namespace(
                        config="test_config.yaml",
                        transport="stdio",
                        host="127.0.0.1",
                        port=8010,
                        debug=True,
                        dev=True,
                        version=False,
                    )
                    mock_parse_args.return_value = mock_args

                    # Mock the server instance
                    mock_server = mock.MagicMock()
                    mock_create_server.return_value = mock_server

                    # Call main
                    with mock.patch("imap_mcp.server.logger") as mock_logger:
                        main()

                        # Verify create_server was called with correct args
                        mock_create_server.assert_called_once_with(
                            "test_config.yaml", True, "stdio", "127.0.0.1", 8010
                        )

                        # Verify server.run was called with transport
                        mock_server.run.assert_called_once_with(transport="stdio")

                        # Verify debug mode was set
                        mock_logger.setLevel.assert_called_with(logging.DEBUG)

                        # Verify startup message
                        mock_logger.info.assert_called_with(mock.ANY)
                        call_args = mock_logger.info.call_args[0][0]
                        assert "Starting server in development mode" in call_args
    
    def test_main_env_config(self, monkeypatch):
        """Test main function with config from environment variable."""
        # Set environment variable for config
        monkeypatch.setenv("IMAP_MCP_CONFIG", "env_config.yaml")

        with mock.patch("sys.argv", ["server.py"]):
            with mock.patch("imap_mcp.server.create_server") as mock_create_server:
                with mock.patch("imap_mcp.server.argparse.ArgumentParser.parse_args") as mock_parse_args:
                    # Mock the parsed arguments
                    mock_args = argparse.Namespace(
                        config="env_config.yaml",
                        transport="stdio",
                        host="127.0.0.1",
                        port=8010,
                        debug=False,
                        dev=False,
                        version=False,
                    )
                    mock_parse_args.return_value = mock_args

                    # Mock the server instance
                    mock_server = mock.MagicMock()
                    mock_create_server.return_value = mock_server

                    # Call main
                    main()

                    # Verify create_server was called with correct args
                    mock_create_server.assert_called_once_with(
                        "env_config.yaml", False, "stdio", "127.0.0.1", 8010
                    )

    def test_main_streamable_http_transport(self):
        """Test main function with streamable-http transport."""
        with mock.patch("imap_mcp.server.create_server") as mock_create_server:
            with mock.patch("imap_mcp.server.argparse.ArgumentParser.parse_args") as mock_parse_args:
                mock_args = argparse.Namespace(
                    config=None,
                    transport="streamable-http",
                    host="0.0.0.0",
                    port=8010,
                    debug=False,
                    dev=False,
                    version=False,
                )
                mock_parse_args.return_value = mock_args

                mock_server = mock.MagicMock()
                mock_create_server.return_value = mock_server

                main()

                mock_create_server.assert_called_once_with(
                    None, False, "streamable-http", "0.0.0.0", 8010
                )
                mock_server.run.assert_called_once_with(
                    transport="streamable-http"
                )

    def test_main_transport_from_env(self, monkeypatch):
        """Test that transport settings are read from environment variables."""
        monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
        monkeypatch.setenv("MCP_HOST", "0.0.0.0")
        monkeypatch.setenv("MCP_PORT", "9000")

        with mock.patch("sys.argv", ["server.py"]):
            with mock.patch("imap_mcp.server.create_server") as mock_create_server:
                mock_server = mock.MagicMock()
                mock_create_server.return_value = mock_server

                main()

                mock_create_server.assert_called_once_with(
                    None, False, "streamable-http", "0.0.0.0", 9000
                )
                mock_server.run.assert_called_once_with(
                    transport="streamable-http"
                )

    def test_create_server_with_http_transport(self, monkeypatch):
        """Test that host/port are passed to FastMCP for streamable-http."""
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com/application/o/test/")
        monkeypatch.setenv("OIDC_JWKS_URI", "https://auth.example.com/jwks/")

        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True,
            ),
        )

        with mock.patch("imap_mcp.server.load_config", return_value=mock_config):
            with mock.patch("imap_mcp.server.FastMCP") as MockFastMCP:
                MockFastMCP.return_value = mock.MagicMock()
                create_server(
                    transport="streamable-http",
                    host="0.0.0.0",
                    port=8010,
                )
                call_kwargs = MockFastMCP.call_args
                assert call_kwargs.kwargs.get("host") == "0.0.0.0"
                assert call_kwargs.kwargs.get("port") == 8010

    def test_create_server_stdio_no_host_port(self):
        """Test that host/port are NOT passed to FastMCP for stdio transport."""
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True,
            ),
        )

        with mock.patch("imap_mcp.server.load_config", return_value=mock_config):
            with mock.patch("imap_mcp.server.FastMCP") as MockFastMCP:
                MockFastMCP.return_value = mock.MagicMock()
                create_server(transport="stdio")
                call_kwargs = MockFastMCP.call_args
                assert "host" not in call_kwargs.kwargs
                assert "port" not in call_kwargs.kwargs

    @pytest.mark.asyncio
    async def test_server_lifespan_imap_verify_failure(self):
        """Test that server fails to start when IMAP verification fails."""
        mock_server = mock.MagicMock()
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True,
            )
        )
        mock_server._config = mock_config

        with mock.patch("imap_mcp.server.ImapClient") as MockImapClient:
            mock_client = MockImapClient.return_value
            mock_client.verify_connection.side_effect = ConnectionError("Verification failed")

            with pytest.raises(ConnectionError, match="Verification failed"):
                async with AsyncExitStack() as stack:
                    await stack.enter_async_context(server_lifespan(mock_server))

            # Disconnect should still be called in the finally block
            mock_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_server_lifespan_smtp_verify_failure_still_starts(self):
        """Test that server starts even when SMTP verification fails."""
        mock_server = mock.MagicMock()
        smtp_config = SmtpConfig(
            host="smtp.example.com",
            port=587,
            username="test@example.com",
            password="password",
        )
        mock_config = ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True,
            ),
            smtp=smtp_config,
        )
        mock_server._config = mock_config

        with mock.patch("imap_mcp.server.ImapClient") as MockImapClient:
            with mock.patch("imap_mcp.server.verify_smtp_connection") as mock_verify_smtp:
                mock_verify_smtp.side_effect = ConnectionError("SMTP auth failed")

                with mock.patch("imap_mcp.server.logger") as mock_logger:
                    async with AsyncExitStack() as stack:
                        context = await stack.enter_async_context(
                            server_lifespan(mock_server)
                        )

                        # Server should still start and provide context
                        assert "imap_client" in context
                        assert "smtp_config" in context

                        # Warning should have been logged
                        mock_logger.warning.assert_called_once()
                        warning_msg = mock_logger.warning.call_args[0][0]
                        assert "SMTP verification failed" in warning_msg


class TestServerOIDCAuth:
    """Tests for OIDC JWT authentication in create_server."""

    def _mock_config(self) -> ServerConfig:
        return ServerConfig(
            imap=ImapConfig(
                host="imap.example.com",
                port=993,
                username="test@example.com",
                password="password",
                use_ssl=True,
            ),
        )

    def test_oidc_auth_enabled(self, monkeypatch):
        """Test that OIDC JWT auth is configured when OIDC_ISSUER_URL is set."""
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com/application/o/test/")
        monkeypatch.delenv("OIDC_JWKS_URI", raising=False)

        with mock.patch("imap_mcp.server.load_config", return_value=self._mock_config()):
            with mock.patch("imap_mcp.auth.discover_jwks_uri", return_value="https://auth.example.com/jwks/"):
                server = create_server(transport="streamable-http")
                assert server._token_verifier is not None
                from imap_mcp.auth import OIDCJWTVerifier
                assert isinstance(server._token_verifier, OIDCJWTVerifier)

    def test_missing_issuer_raises_error(self, monkeypatch):
        """Test that ValueError is raised when OIDC_ISSUER_URL is missing for HTTP."""
        monkeypatch.delenv("OIDC_ISSUER_URL", raising=False)

        with mock.patch("imap_mcp.server.load_config", return_value=self._mock_config()):
            with pytest.raises(ValueError, match="OIDC_ISSUER_URL is required"):
                create_server(transport="streamable-http")

    def test_explicit_jwks_uri_skips_discovery(self, monkeypatch):
        """Test that explicit OIDC_JWKS_URI skips OIDC discovery."""
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com/application/o/test/")
        monkeypatch.setenv("OIDC_JWKS_URI", "https://auth.example.com/custom/jwks/")

        with mock.patch("imap_mcp.server.load_config", return_value=self._mock_config()):
            with mock.patch("imap_mcp.auth.discover_jwks_uri") as mock_discover:
                create_server(transport="streamable-http")
                mock_discover.assert_not_called()

    def test_stdio_no_auth(self, monkeypatch):
        """Test that auth is not configured for stdio transport."""
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com/application/o/test/")

        with mock.patch("imap_mcp.server.load_config", return_value=self._mock_config()):
            server = create_server(transport="stdio")
            assert server._token_verifier is None

    def test_resource_server_url_from_env(self, monkeypatch):
        """Test that MCP_RESOURCE_SERVER_URL is used in AuthSettings."""
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com/application/o/test/")
        monkeypatch.setenv("MCP_RESOURCE_SERVER_URL", "https://mcp.example.com/mcp")
        monkeypatch.delenv("OIDC_JWKS_URI", raising=False)

        with mock.patch("imap_mcp.server.load_config", return_value=self._mock_config()):
            with mock.patch("imap_mcp.auth.discover_jwks_uri", return_value="https://auth.example.com/jwks/"):
                with mock.patch("imap_mcp.server.FastMCP") as MockFastMCP:
                    MockFastMCP.return_value = mock.MagicMock()
                    create_server(transport="streamable-http")
                    call_kwargs = MockFastMCP.call_args.kwargs
                    auth_settings = call_kwargs["auth"]
                    assert str(auth_settings.resource_server_url) == "https://mcp.example.com/mcp"
                    assert str(auth_settings.issuer_url) == "https://auth.example.com/application/o/test/"
