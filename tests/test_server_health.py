"""Tests for the /health and /ready HTTP endpoints (issue #64)."""

from typing import Iterator
from unittest import mock

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from imap_mcp.config import ImapConfig, ServerConfig
from imap_mcp.server import _verify_imap_reachable, create_server


def _mock_config() -> ServerConfig:
    return ServerConfig(
        imap=ImapConfig(
            host="imap.example.com",
            port=993,
            username="test@example.com",
            password="password",
            use_ssl=True,
        ),
    )


@pytest.fixture
def http_app() -> Iterator[Starlette]:
    """Build the Starlette app from a stdio-created server (no auth middleware)."""
    with mock.patch("imap_mcp.server.load_config", return_value=_mock_config()):
        server = create_server(transport="stdio")
    yield server.streamable_http_app()


class TestHealthEndpoint:
    """Liveness probe must always succeed without authentication."""

    def test_health_returns_200(self, http_app: Starlette) -> None:
        with TestClient(http_app) as client:
            resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_health_no_auth_required_when_auth_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With OIDC auth configured, /health is still reachable unauthenticated."""
        monkeypatch.setenv(
            "OIDC_ISSUER_URL", "https://auth.example.com/application/o/test/"
        )
        monkeypatch.setenv("OIDC_JWKS_URI", "https://auth.example.com/jwks/")

        with mock.patch("imap_mcp.server.load_config", return_value=_mock_config()):
            server = create_server(
                transport="streamable-http", host="0.0.0.0", port=8010
            )
        app = server.streamable_http_app()

        with TestClient(app) as client:
            resp = client.get("/health")  # no Authorization header
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestReadyEndpoint:
    """Readiness probe reflects IMAP reachability."""

    def test_ready_returns_200_when_imap_reachable(self, http_app: Starlette) -> None:
        with mock.patch("imap_mcp.server._verify_imap_reachable") as mock_verify:
            with TestClient(http_app) as client:
                resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready"}
        mock_verify.assert_called_once()

    def test_ready_returns_503_when_imap_unreachable(self, http_app: Starlette) -> None:
        with mock.patch(
            "imap_mcp.server._verify_imap_reachable",
            side_effect=ConnectionError("connection refused"),
        ):
            with TestClient(http_app) as client:
                resp = client.get("/ready")
        assert resp.status_code == 503
        assert resp.json() == {"status": "unavailable"}

    def test_ready_response_leaks_no_connection_details(
        self, http_app: Starlette
    ) -> None:
        """A 503 body must not expose IMAP host/credentials to anonymous callers."""
        with mock.patch(
            "imap_mcp.server._verify_imap_reachable",
            side_effect=ConnectionError(
                "Failed to connect to IMAP server imap.example.com: refused"
            ),
        ):
            with TestClient(http_app) as client:
                resp = client.get("/ready")
        assert resp.status_code == 503
        assert "imap.example.com" not in resp.text
        assert "test@example.com" not in resp.text


class TestVerifyImapReachable:
    """The readiness helper opens, verifies, and always closes a connection."""

    def test_connects_verifies_and_disconnects(self) -> None:
        with mock.patch("imap_mcp.server.ImapClient") as MockClient:
            client = MockClient.return_value
            _verify_imap_reachable(_mock_config())

            client.connect.assert_called_once()
            client.verify_connection.assert_called_once()
            client.disconnect.assert_called_once()

    def test_disconnects_even_when_connect_fails(self) -> None:
        with mock.patch("imap_mcp.server.ImapClient") as MockClient:
            client = MockClient.return_value
            client.connect.side_effect = ConnectionError("connect failed")

            with pytest.raises(ConnectionError, match="connect failed"):
                _verify_imap_reachable(_mock_config())

            client.disconnect.assert_called_once()
