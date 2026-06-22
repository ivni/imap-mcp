"""Tests for MCP tool annotations and descriptions.

Verifies that all tools have correct ToolAnnotations for proper
client-side grouping (read-only vs write vs destructive).
"""

from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from imap_mcp.tools import register_tools


@pytest.fixture
def registered_tools() -> dict[str, dict[str, Any]]:
    """Register tools and capture decorator kwargs."""
    mcp = MagicMock(spec=FastMCP)
    captured: dict[str, dict[str, Any]] = {}

    def mock_tool_decorator(**kwargs: Any) -> Any:
        def decorator(func: Any) -> Any:
            captured[func.__name__] = kwargs
            return func

        return decorator

    mcp.tool = mock_tool_decorator
    register_tools(mcp)
    return captured


# --- All tools must have annotations and titles ---


class TestAllToolsAnnotated:
    """Every registered tool must have ToolAnnotations and a title."""

    def test_all_tools_have_annotations(
        self, registered_tools: dict[str, dict[str, Any]]
    ) -> None:
        """Every tool must provide ToolAnnotations."""
        for name, kwargs in registered_tools.items():
            assert "annotations" in kwargs, f"{name} missing annotations kwarg"
            ann = kwargs["annotations"]
            assert isinstance(ann, ToolAnnotations), (
                f"{name} annotations must be ToolAnnotations, got {type(ann)}"
            )

    def test_all_tools_have_title(
        self, registered_tools: dict[str, dict[str, Any]]
    ) -> None:
        """Every tool must have a human-readable title on the decorator."""
        for name, kwargs in registered_tools.items():
            assert "title" in kwargs, f"{name} missing title kwarg"
            assert kwargs["title"], f"{name} title must be non-empty"
            assert isinstance(kwargs["title"], str), f"{name} title must be a string"


# --- Read-only tools ---

READ_ONLY_TOOLS = [
    "search_emails",
    "identify_meeting_invite_tool",
    "check_calendar_availability_tool",
    "draft_meeting_reply_tool",
]


class TestReadOnlyTools:
    """Read-only tools must have readOnlyHint=True."""

    @pytest.mark.parametrize("tool_name", READ_ONLY_TOOLS)
    def test_read_only_hint(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Read-only tool must have readOnlyHint=True."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.readOnlyHint is True, f"{tool_name} should be readOnlyHint=True"


# --- Write, non-destructive tools ---

WRITE_NON_DESTRUCTIVE_TOOLS = [
    "mark_as_read",
    "mark_as_unread",
    "flag_email",
    "draft_reply_tool",
    "process_meeting_invite",
]


class TestWriteNonDestructiveTools:
    """Non-destructive write tools must have readOnlyHint=False, destructiveHint=False."""

    @pytest.mark.parametrize("tool_name", WRITE_NON_DESTRUCTIVE_TOOLS)
    def test_not_read_only(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Non-destructive write tool must have readOnlyHint=False."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.readOnlyHint is False, f"{tool_name} should be readOnlyHint=False"

    @pytest.mark.parametrize("tool_name", WRITE_NON_DESTRUCTIVE_TOOLS)
    def test_not_destructive(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Non-destructive write tool must have destructiveHint=False."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.destructiveHint is False, (
            f"{tool_name} should be destructiveHint=False"
        )


# --- Write, destructive tools ---

DESTRUCTIVE_TOOLS = [
    "move_email",
    "delete_email",
    "process_email",
]


class TestDestructiveTools:
    """Destructive tools must have readOnlyHint=False, destructiveHint=True."""

    @pytest.mark.parametrize("tool_name", DESTRUCTIVE_TOOLS)
    def test_not_read_only(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Destructive tool must have readOnlyHint=False."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.readOnlyHint is False, f"{tool_name} should be readOnlyHint=False"

    @pytest.mark.parametrize("tool_name", DESTRUCTIVE_TOOLS)
    def test_destructive(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Destructive tool must have destructiveHint=True."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.destructiveHint is True, (
            f"{tool_name} should be destructiveHint=True"
        )


# --- Idempotent tools ---

IDEMPOTENT_TOOLS = [
    "mark_as_read",
    "mark_as_unread",
    "flag_email",
]


class TestIdempotentTools:
    """Flag/mark tools are idempotent — repeated calls have no additional effect."""

    @pytest.mark.parametrize("tool_name", IDEMPOTENT_TOOLS)
    def test_idempotent(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Idempotent tool must have idempotentHint=True."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.idempotentHint is True, f"{tool_name} should be idempotentHint=True"


# --- openWorldHint correctness ---


class TestOpenWorldHint:
    """Tools interacting with IMAP server are openWorld=True; local-only are False."""

    OPEN_WORLD_TOOLS = [
        "search_emails",
        "identify_meeting_invite_tool",
        "mark_as_read",
        "mark_as_unread",
        "flag_email",
        "draft_reply_tool",
        "move_email",
        "delete_email",
        "process_email",
        "process_meeting_invite",
    ]

    CLOSED_WORLD_TOOLS = [
        "check_calendar_availability_tool",
        "draft_meeting_reply_tool",
    ]

    @pytest.mark.parametrize("tool_name", OPEN_WORLD_TOOLS)
    def test_open_world(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """IMAP-interacting tool must have openWorldHint=True."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.openWorldHint is True, f"{tool_name} should be openWorldHint=True"

    @pytest.mark.parametrize("tool_name", CLOSED_WORLD_TOOLS)
    def test_closed_world(
        self, registered_tools: dict[str, dict[str, Any]], tool_name: str
    ) -> None:
        """Local-only tool must have openWorldHint=False."""
        ann: ToolAnnotations = registered_tools[tool_name]["annotations"]
        assert ann.openWorldHint is False, f"{tool_name} should be openWorldHint=False"


# --- Completeness check ---


class TestToolCompleteness:
    """Ensure we test all registered tools (no tool left behind)."""

    EXPECTED_TOOLS = sorted(
        READ_ONLY_TOOLS + WRITE_NON_DESTRUCTIVE_TOOLS + DESTRUCTIVE_TOOLS
    )

    def test_all_tools_categorized(
        self, registered_tools: dict[str, dict[str, Any]]
    ) -> None:
        """Every registered tool must be in exactly one category."""
        actual = sorted(registered_tools.keys())
        assert actual == self.EXPECTED_TOOLS, (
            f"Tool list mismatch.\n"
            f"  Missing from categories: {set(actual) - set(self.EXPECTED_TOOLS)}\n"
            f"  Extra in categories: {set(self.EXPECTED_TOOLS) - set(actual)}"
        )
