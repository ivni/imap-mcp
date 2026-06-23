"""Tests for structured logging and correlation IDs (issue #67)."""

import json
import logging
from typing import Iterator

import pytest

from imap_mcp.logging_config import (
    JsonFormatter,
    _CorrelationIdFilter,
    _TextFormatter,
    configure_logging,
    get_correlation_id,
    reset_correlation_id,
    set_correlation_id,
)


@pytest.fixture(autouse=True)
def _restore_root_logging() -> Iterator[None]:
    """Snapshot and restore root logger handlers/level around each test.

    ``configure_logging`` mutates the global root logger; without this the
    handler it installs would leak into other tests (and clobber pytest's).
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)


def _make_record(msg: str = "hello", name: str = "imap_mcp") -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=(),
        exc_info=None,
    )


class TestCorrelationIdContextVar:
    def test_default_is_none(self) -> None:
        # Run inside a fresh set/reset so leakage from other tests can't fool us.
        token = set_correlation_id("temp")
        reset_correlation_id(token)
        assert get_correlation_id() is None

    def test_set_and_reset(self) -> None:
        assert get_correlation_id() is None
        token = set_correlation_id("abc123")
        assert get_correlation_id() == "abc123"
        reset_correlation_id(token)
        assert get_correlation_id() is None


class TestCorrelationIdFilter:
    def test_filter_snapshots_active_id(self) -> None:
        record = _make_record()
        token = set_correlation_id("cid-42")
        try:
            assert _CorrelationIdFilter().filter(record) is True
            assert record.correlation_id == "cid-42"
        finally:
            reset_correlation_id(token)

    def test_filter_sets_none_when_unset(self) -> None:
        record = _make_record()
        _CorrelationIdFilter().filter(record)
        assert record.correlation_id is None


class TestJsonFormatter:
    def test_emits_valid_json_with_core_fields(self) -> None:
        record = _make_record("a message")
        payload = json.loads(JsonFormatter().format(record))
        assert payload["level"] == "INFO"
        assert payload["logger"] == "imap_mcp"
        assert payload["message"] == "a message"
        assert "timestamp" in payload
        assert "correlation_id" not in payload  # absent when unset

    def test_includes_correlation_id_when_present(self) -> None:
        record = _make_record()
        record.correlation_id = "req-7"
        payload = json.loads(JsonFormatter().format(record))
        assert payload["correlation_id"] == "req-7"

    def test_includes_exception_text(self) -> None:
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = logging.LogRecord(
                "imap_mcp", logging.ERROR, __file__, 1, "failed", (), sys.exc_info()
            )
        payload = json.loads(JsonFormatter().format(record))
        assert "exception" in payload
        assert "ValueError" in payload["exception"]

    def test_output_is_single_line_even_with_newline_in_message(self) -> None:
        """A newline in the message must not break the one-object-per-line format."""
        record = _make_record("line1\nline2")
        out = JsonFormatter().format(record)
        assert "\n" not in out
        assert json.loads(out)["message"] == "line1\nline2"

    def test_preserves_non_ascii(self) -> None:
        record = _make_record("Привет")
        payload = json.loads(JsonFormatter().format(record))
        assert payload["message"] == "Привет"


class TestTextFormatter:
    def test_no_correlation_id_appends_nothing(self) -> None:
        record = _make_record("plain")
        out = _TextFormatter("%(name)s - %(message)s").format(record)
        assert out == "imap_mcp - plain"

    def test_appends_correlation_id_when_present(self) -> None:
        record = _make_record("plain")
        record.correlation_id = "xyz"
        out = _TextFormatter("%(name)s - %(message)s").format(record)
        assert out == "imap_mcp - plain [cid=xyz]"


class TestConfigureLogging:
    def test_default_uses_text_formatter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IMAP_MCP_LOG_FORMAT", raising=False)
        configure_logging()
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler.formatter, _TextFormatter)

    def test_json_format_env_uses_json_formatter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("IMAP_MCP_LOG_FORMAT", "json")
        configure_logging()
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler.formatter, JsonFormatter)

    def test_json_value_is_case_insensitive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("IMAP_MCP_LOG_FORMAT", "JSON")
        configure_logging()
        assert isinstance(logging.getLogger().handlers[0].formatter, JsonFormatter)

    def test_debug_sets_debug_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IMAP_MCP_LOG_FORMAT", raising=False)
        configure_logging(debug=True)
        assert logging.getLogger().level == logging.DEBUG

    def test_idempotent_single_handler(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("IMAP_MCP_LOG_FORMAT", raising=False)
        configure_logging()
        configure_logging()
        # Both calls install exactly one handler total (the second replaces).
        assert len(logging.getLogger().handlers) == 1

    def test_handler_carries_correlation_filter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("IMAP_MCP_LOG_FORMAT", raising=False)
        configure_logging()
        handler = logging.getLogger().handlers[0]
        assert any(isinstance(f, _CorrelationIdFilter) for f in handler.filters)
