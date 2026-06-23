"""Tests for Prometheus metrics and correlation-ID middleware (issue #67)."""

import re
from typing import Dict, Iterator
from unittest import mock

import pytest
from prometheus_client import REGISTRY
from starlette.applications import Starlette
from starlette.testclient import TestClient

from imap_mcp.config import ImapConfig, ServerConfig
from imap_mcp.server import build_streamable_http_app, create_server, server_lifespan


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


def _sample(name: str, labels: Dict[str, str]) -> float:
    """Read a metric sample value, treating absent series as 0."""
    value = REGISTRY.get_sample_value(name, labels)
    return value if value is not None else 0.0


@pytest.fixture
def http_app() -> Iterator[Starlette]:
    """Streamable-HTTP app wrapped with the observability middleware."""
    with mock.patch("imap_mcp.server.load_config", return_value=_mock_config()):
        server = create_server(transport="stdio")
    yield build_streamable_http_app(server)


class TestMetricsEndpoint:
    def test_metrics_returns_prometheus_text(self, http_app: Starlette) -> None:
        with TestClient(http_app) as client:
            resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert "imap_mcp_http_requests_total" in resp.text

    def test_metrics_unauthenticated(self, http_app: Starlette) -> None:
        """Like the health probes, /metrics needs no Authorization header."""
        with TestClient(http_app) as client:
            resp = client.get("/metrics")  # no auth header
        assert resp.status_code == 200


class TestRequestMetrics:
    def test_request_count_increments(self, http_app: Starlette) -> None:
        labels = {"method": "GET", "path": "/health", "status": "200"}
        before = _sample("imap_mcp_http_requests_total", labels)
        with TestClient(http_app) as client:
            client.get("/health")
        after = _sample("imap_mcp_http_requests_total", labels)
        assert after == before + 1

    def test_latency_histogram_observed(self, http_app: Starlette) -> None:
        labels = {"method": "GET", "path": "/health"}
        before = _sample("imap_mcp_http_request_duration_seconds_count", labels)
        with TestClient(http_app) as client:
            client.get("/health")
        after = _sample("imap_mcp_http_request_duration_seconds_count", labels)
        assert after == before + 1

    def test_unknown_path_bucketed_as_other(self, http_app: Starlette) -> None:
        """Arbitrary URLs must not explode the ``path`` label cardinality."""
        raw_labels = {
            "method": "GET",
            "path": "/totally-unknown-xyz",
            "status": "404",
        }
        other_labels = {"method": "GET", "path": "other", "status": "404"}
        before_other = _sample("imap_mcp_http_requests_total", other_labels)
        with TestClient(http_app) as client:
            resp = client.get("/totally-unknown-xyz")
        assert resp.status_code == 404
        # The raw path is never used as a label value.
        assert (
            REGISTRY.get_sample_value("imap_mcp_http_requests_total", raw_labels)
            is None
        )
        assert _sample("imap_mcp_http_requests_total", other_labels) == before_other + 1


class TestCorrelationIdMiddleware:
    _HEX32 = re.compile(r"^[0-9a-f]{32}$")

    def test_generates_id_when_absent(self, http_app: Starlette) -> None:
        with TestClient(http_app) as client:
            resp = client.get("/health")
        assert self._HEX32.match(resp.headers["x-request-id"])

    def test_echoes_inbound_id(self, http_app: Starlette) -> None:
        with TestClient(http_app) as client:
            resp = client.get("/health", headers={"X-Request-ID": "trace-abc-123"})
        assert resp.headers["x-request-id"] == "trace-abc-123"

    def test_sanitizes_inbound_id(self, http_app: Starlette) -> None:
        """Disallowed characters (spaces, punctuation) are stripped."""
        with TestClient(http_app) as client:
            resp = client.get("/health", headers={"X-Request-ID": "abc 123 !@#"})
        assert resp.headers["x-request-id"] == "abc123"

    def test_falls_back_to_generated_when_sanitized_empty(
        self, http_app: Starlette
    ) -> None:
        with TestClient(http_app) as client:
            resp = client.get("/health", headers={"X-Request-ID": "!@#$%"})
        assert self._HEX32.match(resp.headers["x-request-id"])


class TestSessionMetrics:
    """``server_lifespan`` maintains the IMAP connection gauges/counters."""

    def _active(self) -> float:
        return _sample("imap_mcp_active_sessions", {})

    def _counter(self, name: str) -> float:
        return _sample(name, {})

    def _server(self) -> object:
        server = mock.Mock()
        server._config = _mock_config()
        return server

    @pytest.mark.asyncio
    async def test_active_gauge_inc_then_dec(self) -> None:
        with mock.patch("imap_mcp.server.ImapClient") as MockClient:
            client = MockClient.return_value
            before_active = self._active()
            before_total = self._counter("imap_mcp_session_connections_total")

            async with server_lifespan(self._server()) as ctx:
                assert self._active() == before_active + 1
                assert ctx["imap_client"] is client

            assert self._active() == before_active  # decremented on exit
            assert (
                self._counter("imap_mcp_session_connections_total") == before_total + 1
            )
            client.connect.assert_called_once()
            client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_connection_error_counted_and_gauge_untouched(self) -> None:
        with mock.patch("imap_mcp.server.ImapClient") as MockClient:
            client = MockClient.return_value
            client.connect.side_effect = ConnectionError("refused")
            before_active = self._active()
            before_err = self._counter("imap_mcp_session_connection_errors_total")

            with pytest.raises(ConnectionError):
                async with server_lifespan(self._server()):
                    pass

            assert self._active() == before_active  # never incremented
            assert (
                self._counter("imap_mcp_session_connection_errors_total")
                == before_err + 1
            )
            client.disconnect.assert_called_once()  # still cleaned up
