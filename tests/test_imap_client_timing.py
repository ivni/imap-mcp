"""Tests for per-operation IMAP timing logs.

When debug logging is on (``IMAP_MCP_DEBUG=true`` or ``--debug``) each IMAP
network round-trip emits a DEBUG line with the operation name, target folder,
and ``duration_ms`` — the signal needed to see which folder/operation is slow
when a search or fetch approaches the client's tool-call timeout. The line is
content-safe: it carries no criteria, subjects, addresses, or bodies. When
debug is off, no timing line is emitted at all.
"""

import logging

import pytest

from imap_mcp.config import ImapConfig
from imap_mcp.imap_client import ImapClient

LOGGER_NAME = "imap_mcp.imap_client"


def _make_config() -> ImapConfig:
    return ImapConfig(
        host="imap.example.com",
        port=993,
        username="test@example.com",
        password="password",
        use_ssl=True,
    )


class _FakeConnection:
    """Minimal stand-in for imapclient.IMAPClient for timing tests."""

    def noop(self) -> None:
        return None

    def select_folder(self, folder: str, readonly: bool = False) -> dict:
        return {b"EXISTS": 1}

    def search(self, criteria: object, charset: object = None) -> list[int]:
        return [1, 2, 3]


@pytest.fixture
def connected_client() -> ImapClient:
    client = ImapClient(_make_config())
    client.client = _FakeConnection()  # type: ignore[assignment]
    client.connected = True
    return client


def _timing_lines(records: list[logging.LogRecord], operation: str) -> list[str]:
    return [
        r.getMessage()
        for r in records
        if r.getMessage().startswith(f"imap op={operation} ")
    ]


class TestImapTimingLogs:
    def test_search_emits_timing_line_at_debug(
        self, connected_client: ImapClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A search at DEBUG logs op, folder, and duration_ms."""
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            connected_client.search("ALL", folder="INBOX")

        lines = _timing_lines(caplog.records, "search")
        assert lines, "expected a timing line for op=search"
        line = lines[0]
        assert "folder=INBOX" in line
        assert "duration_ms=" in line
        assert "status=ok" in line

    def test_select_folder_emits_timing_line_with_folder(
        self, connected_client: ImapClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """select_folder (called with a positional folder) still logs the folder."""
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            connected_client.select_folder("Sent", readonly=True)

        lines = _timing_lines(caplog.records, "select_folder")
        assert lines, "expected a timing line for op=select_folder"
        assert "folder=Sent" in lines[0]

    def test_no_timing_line_when_debug_disabled(
        self, connected_client: ImapClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """At INFO level the timing line is not emitted at all."""
        with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
            connected_client.search("ALL", folder="INBOX")

        assert not _timing_lines(caplog.records, "search")

    def test_timing_line_carries_no_search_criteria(
        self, connected_client: ImapClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The query/criteria must never appear in the timing log (content-safety)."""
        secret_query = "secret-subject-token"
        with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
            connected_client.search(["SUBJECT", secret_query], folder="INBOX")

        for line in _timing_lines(caplog.records, "search"):
            assert secret_query not in line
