"""Tests for MCP tools implementation."""

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]
from mcp.server.fastmcp import Context, FastMCP

from imap_mcp.imap_client import MAX_FETCH_UIDS, ImapClient
from imap_mcp.models import Email, EmailAddress, EmailContent, EmailSummary
from imap_mcp.tools import ConfirmationResult, register_tools, require_confirmation


def _summary_from(email: Email, has_attachments: bool = False) -> EmailSummary:
    """Build an EmailSummary mirroring an Email fixture (search/list use these)."""
    return EmailSummary(
        uid=email.uid if email.uid is not None else 0,
        from_=email.from_,
        to=email.to,
        subject=email.subject,
        date=email.date,
        flags=email.flags,
        has_attachments=bool(email.attachments),
        folder=email.folder,
    )


# --- Shared fixtures ---


@pytest.fixture
def mock_email() -> Any:
    """Create a mock email object."""
    return Email(
        message_id="<test123@example.com>",
        subject="Test Email",
        from_=EmailAddress(name="Sender", address="sender@example.com"),
        to=[EmailAddress(name="Recipient", address="recipient@example.com")],
        cc=[],
        bcc=[],
        date=datetime.now(),
        content=EmailContent(text="Test content", html="<p>Test content</p>"),
        attachments=[],
        flags=["\\Seen"],
        headers={},
        folder="INBOX",
        uid=1,
    )


@pytest.fixture
def mock_client(mock_email: Any) -> Any:
    """Create a mock IMAP client."""
    client = MagicMock(spec=ImapClient)
    client.move_email.return_value = True
    client.mark_email.return_value = True
    client.delete_email.return_value = True
    client.list_folders.return_value = ["INBOX", "Sent", "Archive", "Trash"]
    client.search.return_value = [1, 2, 3]
    client.search_newest.return_value = ([1, 2, 3], 3)
    client.fetch_emails.return_value = {1: mock_email, 2: mock_email, 3: mock_email}
    summary = _summary_from(mock_email)
    client.fetch_summaries.return_value = {1: summary, 2: summary, 3: summary}
    client.fetch_email.return_value = mock_email
    return client


@pytest.fixture
def tools(mock_client: Any) -> Any:
    """Register and return MCP tools backed by mock_client."""
    mcp = MagicMock(spec=FastMCP)
    stored_tools = {}

    def mock_tool_decorator(**kwargs: Any) -> Any:
        def decorator(func: Any) -> Any:
            stored_tools[func.__name__] = func
            return func

        return decorator

    mcp.tool = mock_tool_decorator
    register_tools(mcp)
    return stored_tools


def _make_elicit_result(action: str = "accept", confirmed: bool = True) -> MagicMock:
    """Helper to create a mock elicitation result."""
    result = MagicMock()
    result.action = action
    if action == "accept":
        result.data = MagicMock()
        result.data.confirmed = confirmed
    return result


def _make_confirmed_context() -> MagicMock:
    """Create a mock context where user confirms all actions."""
    context = MagicMock(spec=Context)
    context.elicit = AsyncMock(return_value=_make_elicit_result("accept", True))
    return context


class TestTools:
    """Test class for MCP tools."""

    @pytest.fixture(autouse=True)
    def patch_get_client(self, mock_client: Any) -> Generator[Any, None, None]:
        """Patch get_client_from_context for this class only."""
        with patch("imap_mcp.tools.get_client_from_context") as mock_get_client:
            mock_get_client.return_value = mock_client
            yield mock_get_client

    @pytest.fixture
    def mock_context(self) -> Any:
        """Create a mock context with elicitation support.

        Default: user confirms all actions (accept + confirmed=True).
        """
        return _make_confirmed_context()

    @pytest.mark.asyncio
    async def test_move_email(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test moving an email from one folder to another."""
        # Get the move_email function
        move_email = tools["move_email"]

        # Call the move_email function
        result = await move_email("INBOX", 123, "Archive", mock_context)

        # Check the client was called correctly
        mock_client.move_email.assert_called_once_with(123, "INBOX", "Archive")

        # Check the result
        assert "Email moved from INBOX to Archive" in result

        # Test error handling
        mock_client.move_email.side_effect = IMAPClientError("Connection error")
        result = await move_email("INBOX", 123, "Archive", mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_mark_as_read(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test marking an email as read."""
        # Get the mark_as_read function
        mark_as_read = tools["mark_as_read"]

        # Call the function
        result = await mark_as_read("INBOX", 123, mock_context)

        # Check the client was called correctly
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Seen", True)

        # Check the result
        assert "Email marked as read" in result

        # Test failure case
        mock_client.mark_email.side_effect = IMAPClientError("Server error")
        result = await mark_as_read("INBOX", 123, mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_mark_as_unread(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test marking an email as unread."""
        # Get the mark_as_unread function
        mark_as_unread = tools["mark_as_unread"]

        # Reset mock for this test
        mock_client.mark_email.reset_mock()
        mock_client.mark_email.return_value = True

        # Call the function
        result = await mark_as_unread("INBOX", 123, mock_context)

        # Check the client was called correctly
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Seen", False)

        # Check the result
        assert "Email marked as unread" in result

        # Test error handling
        mock_client.mark_email.side_effect = IMAPClientError("Server error")
        result = await mark_as_unread("INBOX", 123, mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_flag_email(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test flagging and unflagging an email."""
        # Get the flag_email function
        flag_email = tools["flag_email"]

        # Reset mock for this test
        mock_client.mark_email.reset_mock()
        mock_client.mark_email.return_value = True

        # Test flagging
        result = await flag_email("INBOX", 123, mock_context, True)
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Flagged", True)
        assert "Email flagged" in result

        # Reset mock
        mock_client.mark_email.reset_mock()

        # Test unflagging
        result = await flag_email("INBOX", 123, mock_context, False)
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Flagged", False)
        assert "Email unflagged" in result

    @pytest.mark.asyncio
    async def test_delete_email(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test deleting an email."""
        # Get the delete_email function
        delete_email = tools["delete_email"]

        # Call the function
        result = await delete_email("INBOX", 123, mock_context)

        # Check the client was called correctly
        mock_client.delete_email.assert_called_once_with(123, "INBOX")

        # Check the result
        assert "Email deleted" in result

        # Test failure case
        mock_client.delete_email.side_effect = IMAPClientError("Permission denied")
        result = await delete_email("INBOX", 123, mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_search_emails(
        self, tools: Any, mock_client: Any, mock_context: Any, mock_email: Any
    ) -> None:
        """Test searching for emails."""
        # Get the search_emails function
        search_emails = tools["search_emails"]

        # Test searching with default parameters
        result = await search_emails("test query", mock_context)
        response = result

        # Assert client methods were called properly
        mock_client.list_folders.assert_called_once()
        assert mock_client.search_newest.call_count > 0

        # Check pagination metadata
        assert "total" in response
        assert response["offset"] == 0
        assert response["limit"] == 10

        # Check result structure
        result_data = response["results"]
        assert isinstance(result_data, list)
        assert len(result_data) > 0
        assert "uid" in result_data[0]
        assert "folder" in result_data[0]
        assert "subject" in result_data[0]

        # Reset mocks
        mock_client.list_folders.reset_mock()
        mock_client.search_newest.reset_mock()
        mock_client.fetch_summaries.reset_mock()

        # Test searching with specific folder
        result = await search_emails("test query", mock_context, folder="INBOX")

        # Assert client methods were called properly
        mock_client.list_folders.assert_not_called()
        mock_client.search_newest.assert_called_once()

        # Test with different criteria
        criteria_tests = ["from", "to", "subject", "all", "unseen", "seen"]
        for criteria in criteria_tests:
            mock_client.search_newest.reset_mock()
            result = await search_emails("test query", mock_context, criteria=criteria)
            assert mock_client.search_newest.called

        # Test with invalid criteria
        result = await search_emails("test query", mock_context, criteria="invalid")
        assert "Invalid search criteria" in result["error"]

    @pytest.mark.asyncio
    async def test_process_email(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test processing an email with multiple actions."""
        # Get the process_email function
        process_email = tools["process_email"]

        # Test move action
        mock_client.move_email.reset_mock()
        mock_client.move_email.return_value = True

        result = await process_email(
            "INBOX", 123, "move", mock_context, target_folder="Archive"
        )

        mock_client.move_email.assert_called_once_with(123, "INBOX", "Archive")
        assert "Email moved" in result

        # Test move action without target folder
        result = await process_email("INBOX", 123, "move", mock_context)
        assert "Target folder must be specified" in result

        # Test read action
        mock_client.mark_email.reset_mock()
        mock_client.mark_email.return_value = True

        result = await process_email("INBOX", 123, "read", mock_context)

        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Seen", True)
        assert "Email marked as read" in result

        # Test unread action
        mock_client.mark_email.reset_mock()
        mock_client.mark_email.return_value = True

        result = await process_email("INBOX", 123, "unread", mock_context)

        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Seen", False)
        assert "Email marked as unread" in result

        # Test flag action
        mock_client.mark_email.reset_mock()
        mock_client.mark_email.return_value = True

        result = await process_email("INBOX", 123, "flag", mock_context)

        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Flagged", True)
        assert "Email flagged" in result

        # Test delete action
        mock_client.delete_email.reset_mock()
        mock_client.delete_email.return_value = True

        result = await process_email("INBOX", 123, "delete", mock_context)

        mock_client.delete_email.assert_called_once_with(123, "INBOX")
        assert "Email deleted" in result

        # Test invalid action
        result = await process_email("INBOX", 123, "invalid_action", mock_context)
        assert "Invalid action" in result

        # Test email not found
        mock_client.fetch_email.return_value = None
        result = await process_email("INBOX", 123, "read", mock_context)
        assert "not found" in result

    @pytest.mark.asyncio
    async def test_tool_error_handling(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test error handling in tools."""
        # Get tools to test
        move_email = tools["move_email"]
        mark_as_read = tools["mark_as_read"]
        search_emails = tools["search_emails"]

        # Test move_email error handling
        mock_client.move_email.side_effect = IMAPClientError("Network error")
        result = await move_email("INBOX", 123, "Archive", mock_context)
        assert "Error" in result

        # Test mark_as_read error handling
        mock_client.mark_email.side_effect = IMAPClientError("Server timeout")
        result = await mark_as_read("INBOX", 123, mock_context)
        assert "Error" in result

        # Test search_emails error handling
        mock_client.search_newest.side_effect = IMAPClientError("Search failed")
        result = await search_emails("test", mock_context)
        # Search should continue with other folders and return empty results
        response = result
        assert response["results"] == []

    @pytest.mark.asyncio
    async def test_tool_unexpected_exception_catch_all(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that unexpected exceptions hit the catch-all branch."""
        move_email = tools["move_email"]
        mark_as_read = tools["mark_as_read"]
        search_emails = tools["search_emails"]
        delete_email = tools["delete_email"]

        # RuntimeError is not in (IMAPClientError, OSError, ValueError)
        mock_client.move_email.side_effect = RuntimeError("unexpected")
        result = await move_email("INBOX", 123, "Archive", mock_context)
        assert result == "Error: an unexpected error occurred (RuntimeError)"

        mock_client.mark_email.side_effect = RuntimeError("unexpected")
        result = await mark_as_read("INBOX", 123, mock_context)
        assert result == "Error: an unexpected error occurred (RuntimeError)"

        mock_client.delete_email.side_effect = RuntimeError("unexpected")
        result = await delete_email("INBOX", 123, mock_context)
        assert result == "Error: an unexpected error occurred (RuntimeError)"

        mock_client.search_newest.side_effect = RuntimeError("unexpected")
        result = await search_emails("test", mock_context)
        response = result
        assert response["results"] == []

    @pytest.mark.asyncio
    async def test_tool_parameter_validation(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test parameter validation in tools."""
        # Get tools to test
        search_emails = tools["search_emails"]
        process_email = tools["process_email"]

        # Test search_emails with invalid criteria
        result = await search_emails("test", mock_context, criteria="invalid_criteria")
        assert "Invalid search criteria" in result["error"]

        # Test process_email with missing target folder for move action
        result = await process_email("INBOX", 123, "move", ctx=mock_context)
        assert "Target folder must be specified" in result

        # Test process_email with invalid action
        result = await process_email(
            "INBOX", 123, "nonexistent_action", ctx=mock_context
        )
        assert "Invalid action" in result


class TestConfirmation:
    """Tests for destructive action confirmation mechanism."""

    @pytest.fixture
    def confirmed_context(self) -> Any:
        """Context where user confirms the action."""
        return _make_confirmed_context()

    @pytest.fixture
    def declined_context(self) -> Any:
        """Context where user declines the action."""
        context = MagicMock(spec=Context)
        context.elicit = AsyncMock(return_value=_make_elicit_result("decline"))
        return context

    @pytest.fixture
    def cancelled_context(self) -> Any:
        """Context where user cancels the action."""
        context = MagicMock(spec=Context)
        context.elicit = AsyncMock(return_value=_make_elicit_result("cancel"))
        return context

    @pytest.fixture
    def not_confirmed_context(self) -> Any:
        """Context where user accepts but sets confirmed=False."""
        context = MagicMock(spec=Context)
        context.elicit = AsyncMock(return_value=_make_elicit_result("accept", False))
        return context

    @pytest.fixture
    def unsupported_context(self) -> Any:
        """Context where elicitation is not supported."""
        context = MagicMock(spec=Context)
        context.elicit = AsyncMock(side_effect=Exception("elicitation not supported"))
        return context

    @pytest.mark.asyncio
    async def test_delete_email_confirmation_declined(
        self, tools: Any, mock_client: Any, declined_context: Any
    ) -> None:
        """Test that declining confirmation prevents deletion."""
        delete_email = tools["delete_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await delete_email("INBOX", 123, declined_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_email_confirmation_not_confirmed(
        self, tools: Any, mock_client: Any, not_confirmed_context: Any
    ) -> None:
        """Test that accepting with confirmed=False prevents deletion."""
        delete_email = tools["delete_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await delete_email("INBOX", 123, not_confirmed_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_email_confirmation_cancelled(
        self, tools: Any, mock_client: Any, cancelled_context: Any
    ) -> None:
        """Test that cancelling confirmation prevents deletion."""
        delete_email = tools["delete_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await delete_email("INBOX", 123, cancelled_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_email_confirmation_declined(
        self, tools: Any, mock_client: Any, declined_context: Any
    ) -> None:
        """Test that declining confirmation prevents move."""
        move_email = tools["move_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await move_email("INBOX", 123, "Archive", declined_context)

        assert "cancelled" in result.lower()
        mock_client.move_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_delete_requires_confirmation(
        self, tools: Any, mock_client: Any, declined_context: Any
    ) -> None:
        """Test that process_email with delete action requires confirmation."""
        process_email = tools["process_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await process_email("INBOX", 123, "delete", declined_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_move_requires_confirmation(
        self, tools: Any, mock_client: Any, declined_context: Any
    ) -> None:
        """Test that process_email with move action requires confirmation."""
        process_email = tools["process_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await process_email(
                "INBOX", 123, "move", declined_context, target_folder="Archive"
            )

        assert "cancelled" in result.lower()
        mock_client.move_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_read_no_confirmation(
        self, tools: Any, mock_client: Any, confirmed_context: Any
    ) -> None:
        """Test that process_email with read action does NOT require confirmation."""
        process_email = tools["process_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await process_email("INBOX", 123, "read", confirmed_context)

        assert "Email marked as read" in result
        confirmed_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_flag_no_confirmation(
        self, tools: Any, mock_client: Any, confirmed_context: Any
    ) -> None:
        """Test that process_email with flag action does NOT require confirmation."""
        process_email = tools["process_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await process_email("INBOX", 123, "flag", confirmed_context)

        assert "Email flagged" in result
        confirmed_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_elicitation_not_supported_aborts_delete(
        self, tools: Any, mock_client: Any, unsupported_context: Any
    ) -> None:
        """Test that when elicitation raises, delete is aborted with error."""
        delete_email = tools["delete_email"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await delete_email("INBOX", 123, unsupported_context)

        assert "aborted" in result.lower() or "error" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_confirmation_env_var(
        self, tools: Any, mock_client: Any, declined_context: Any
    ) -> None:
        """Test that IMAP_MCP_SKIP_CONFIRMATION=true bypasses confirmation."""
        delete_email = tools["delete_email"]

        with (
            patch("imap_mcp.tools.get_client_from_context", return_value=mock_client),
            patch.dict(os.environ, {"IMAP_MCP_SKIP_CONFIRMATION": "true"}),
        ):
            result = await delete_email("INBOX", 123, declined_context)

        assert "Email deleted" in result
        mock_client.delete_email.assert_called_once_with(123, "INBOX")
        declined_context.elicit.assert_not_called()


class TestRequireConfirmation:
    """Tests for the require_confirmation helper function."""

    @pytest.mark.asyncio
    async def test_confirmation_message_excludes_email_content(self) -> None:
        """Verify confirmation message contains only UID and folder, not email content."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("accept", True))

        await require_confirmation(ctx, "delete", "INBOX", 42)

        message = ctx.elicit.call_args.kwargs["message"]
        # Expected fields present
        assert "42" in message
        assert "INBOX" in message
        assert "delete" in message
        # Email content must NOT leak into confirmation message
        assert "Test Email" not in message
        assert "sender@example.com" not in message
        assert "Test content" not in message

    @pytest.mark.asyncio
    async def test_confirmation_message_includes_target_folder_for_move(self) -> None:
        """Verify move confirmation includes target folder."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("accept", True))

        await require_confirmation(ctx, "move", "INBOX", 42, target_folder="Archive")

        message = ctx.elicit.call_args.kwargs["message"]
        assert "Archive" in message
        assert "INBOX" in message
        assert "42" in message

    @pytest.mark.asyncio
    async def test_returns_declined_on_decline(self) -> None:
        """Verify require_confirmation returns DECLINED on decline."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("decline"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result == ConfirmationResult.DECLINED

    @pytest.mark.asyncio
    async def test_returns_declined_on_cancel(self) -> None:
        """Verify require_confirmation returns DECLINED on cancel."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("cancel"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result == ConfirmationResult.DECLINED

    @pytest.mark.asyncio
    async def test_returns_confirmed_on_accept(self) -> None:
        """Verify require_confirmation returns CONFIRMED on accept+confirmed."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("accept", True))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result == ConfirmationResult.CONFIRMED

    @pytest.mark.asyncio
    async def test_returns_error_on_generic_exception(self) -> None:
        """Verify require_confirmation returns ERROR on unexpected exceptions."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(side_effect=Exception("not supported"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result == ConfirmationResult.ERROR

    @pytest.mark.asyncio
    async def test_returns_error_on_connection_error(self) -> None:
        """Verify require_confirmation returns ERROR on network errors."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(side_effect=ConnectionError("connection refused"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result == ConfirmationResult.ERROR

    @pytest.mark.asyncio
    async def test_returns_error_on_type_error(self) -> None:
        """Verify require_confirmation returns ERROR on schema validation errors."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(side_effect=TypeError("invalid schema"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result == ConfirmationResult.ERROR

    @pytest.mark.asyncio
    async def test_skip_via_env_var(self) -> None:
        """Verify IMAP_MCP_SKIP_CONFIRMATION=true skips elicitation."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(side_effect=AssertionError("should not be called"))

        with patch.dict(os.environ, {"IMAP_MCP_SKIP_CONFIRMATION": "true"}):
            result = await require_confirmation(ctx, "delete", "INBOX", 1)

        assert result == ConfirmationResult.CONFIRMED
        ctx.elicit.assert_not_called()


class TestSearchEmailsFolderEnforcement:
    """Tests for allowed_folders enforcement in search_emails(folder=None)."""

    @pytest.fixture
    def mock_email(self) -> Any:
        """Create a mock email object for search results."""
        return Email(
            message_id="<test123@example.com>",
            subject="Test Email",
            from_=EmailAddress(name="Sender", address="sender@example.com"),
            to=[EmailAddress(name="Recipient", address="recipient@example.com")],
            cc=[],
            bcc=[],
            date=datetime.now(),
            content=EmailContent(text="Test content", html="<p>Test content</p>"),
            attachments=[],
            flags=["\\Seen"],
            headers={},
            folder="INBOX",
            uid=1,
        )

    @pytest.fixture
    def tools_with_client(self, mock_email: Any) -> Any:
        """Register tools and return (stored_tools, mock_client) tuple.

        Allows each test to configure the mock client's allowed_folders
        and list_folders behavior before calling the tool.
        """
        client = MagicMock(spec=ImapClient)
        client.search.return_value = [1]
        client.search_newest.return_value = ([1], 1)
        client.fetch_summaries.return_value = {1: _summary_from(mock_email)}

        mcp = MagicMock(spec=FastMCP)
        stored_tools: dict[str, Any] = {}

        def mock_tool_decorator(**kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                stored_tools[func.__name__] = func
                return func

            return decorator

        mcp.tool = mock_tool_decorator
        register_tools(mcp)
        return stored_tools, client

    @pytest.mark.asyncio
    async def test_search_emails_folder_none_respects_allowed_folders(
        self, tools_with_client: Any
    ) -> None:
        """When folder=None, search_emails uses list_folders() which respects allowed_folders."""
        stored_tools, client = tools_with_client
        search_emails = stored_tools["search_emails"]

        # Configure client: allowed_folders restricts to INBOX and Sent
        client.allowed_folders = {"INBOX", "Sent"}
        client.list_folders.return_value = ["INBOX", "Sent"]

        ctx = _make_confirmed_context()

        with patch("imap_mcp.tools.get_client_from_context", return_value=client):
            await search_emails("test", ctx, folder=None)

        # list_folders should be called once (to discover folders)
        client.list_folders.assert_called_once()

        # search should be called exactly for the allowed folders
        searched_folders = {
            call.kwargs.get("folder", call.args[1] if len(call.args) > 1 else None)
            for call in client.search_newest.call_args_list
        }
        assert searched_folders == {"INBOX", "Sent"}
        assert client.search_newest.call_count == 2

    @pytest.mark.asyncio
    async def test_search_emails_rejects_disallowed_folder(
        self, tools_with_client: Any
    ) -> None:
        """When a disallowed folder is explicitly requested, search returns error/empty."""
        stored_tools, client = tools_with_client
        search_emails = stored_tools["search_emails"]

        # Configure client: only INBOX is allowed
        client.allowed_folders = {"INBOX"}
        client.search_newest.side_effect = ValueError("Folder 'Trash' is not allowed")

        ctx = _make_confirmed_context()

        with patch("imap_mcp.tools.get_client_from_context", return_value=client):
            result = await search_emails("test", ctx, folder="Trash")

        # The search catches exceptions and continues — result should be empty
        response = result
        assert response["results"] == []

    @pytest.mark.asyncio
    async def test_search_emails_all_folders_when_allowed_empty(
        self, tools_with_client: Any
    ) -> None:
        """When allowed_folders is None (unrestricted), all folders are searched."""
        stored_tools, client = tools_with_client
        search_emails = stored_tools["search_emails"]

        # Configure client: no restrictions
        client.allowed_folders = None
        client.list_folders.return_value = ["INBOX", "Sent", "Trash", "Drafts"]

        ctx = _make_confirmed_context()

        with patch("imap_mcp.tools.get_client_from_context", return_value=client):
            await search_emails("test", ctx, folder=None)

        # list_folders should be called once
        client.list_folders.assert_called_once()

        # search should be called for all 4 folders
        searched_folders = {
            call.kwargs.get("folder", call.args[1] if len(call.args) > 1 else None)
            for call in client.search_newest.call_args_list
        }
        assert searched_folders == {"INBOX", "Sent", "Trash", "Drafts"}
        assert client.search_newest.call_count == 4


class TestToolFolderValidation:
    """Tests for folder name validation in MCP tool handlers."""

    @pytest.fixture(autouse=True)
    def patch_get_client(self, mock_client: Any) -> Generator[Any, None, None]:
        """Patch get_client_from_context for this class only."""
        with patch("imap_mcp.tools.get_client_from_context") as mock_get_client:
            mock_get_client.return_value = mock_client
            yield mock_get_client

    @pytest.fixture
    def mock_context(self) -> Any:
        """Create a mock context with elicitation support."""
        return _make_confirmed_context()

    @pytest.mark.asyncio
    async def test_mark_as_read_rejects_invalid_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that mark_as_read rejects folder names with injection characters."""
        mock_client._validate_folder_name.side_effect = ValueError(
            "contains invalid characters"
        )
        mark_as_read = tools["mark_as_read"]

        result = await mark_as_read("INBOX\r\nDELETE", 123, mock_context)

        assert "Invalid folder name" in result
        mock_client.mark_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_mark_as_read_rejects_disallowed_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that mark_as_read rejects folders not in allowed list."""
        mock_client._validate_folder_name.return_value = None
        mock_client._is_folder_allowed.return_value = False
        mark_as_read = tools["mark_as_read"]

        result = await mark_as_read("SecretFolder", 123, mock_context)

        assert "not in the allowed folders list" in result
        mock_client.mark_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_email_rejects_invalid_source_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that move_email rejects invalid source folder name."""
        mock_client._validate_folder_name.side_effect = ValueError(
            "contains invalid characters"
        )
        move_email = tools["move_email"]

        result = await move_email("INBOX\r\nDELETE", 123, "Archive", mock_context)

        assert "Invalid folder name" in result
        mock_client.move_email.assert_not_called()
        mock_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_email_rejects_invalid_target_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that move_email rejects invalid target folder name."""

        def validate_side_effect(folder: str) -> None:
            if folder == "INBOX":
                return None
            raise ValueError("contains invalid characters")

        mock_client._validate_folder_name.side_effect = validate_side_effect
        mock_client._is_folder_allowed.return_value = True
        move_email = tools["move_email"]

        result = await move_email("INBOX", 123, "BAD\r\nFOLDER", mock_context)

        assert "Invalid folder name" in result
        mock_client.move_email.assert_not_called()
        mock_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_email_rejects_disallowed_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that move_email rejects folders not in allowed list."""
        mock_client._validate_folder_name.return_value = None
        mock_client._is_folder_allowed.return_value = False
        move_email = tools["move_email"]

        result = await move_email("SecretFolder", 123, "Archive", mock_context)

        assert "not in the allowed folders list" in result
        mock_client.move_email.assert_not_called()
        mock_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_email_rejects_invalid_folder_before_confirmation(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that delete_email rejects invalid folder before confirmation."""
        mock_client._validate_folder_name.side_effect = ValueError(
            "contains invalid characters"
        )
        delete_email = tools["delete_email"]

        result = await delete_email("INBOX\r\nDELETE", 123, mock_context)

        assert "Invalid folder name" in result
        mock_client.delete_email.assert_not_called()
        mock_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_search_emails_rejects_invalid_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that search_emails rejects invalid explicit folder."""
        mock_client._validate_folder_name.side_effect = ValueError(
            "contains invalid characters"
        )
        search_emails = tools["search_emails"]

        result = await search_emails("test query", mock_context, folder="BAD\x00FOLDER")

        assert "Invalid folder name" in result["error"]
        mock_client.search_newest.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_rejects_invalid_target_folder(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email rejects invalid target_folder for move."""

        # Source folder passes validation, target folder fails
        def validate_side_effect(folder: str) -> None:
            if folder == "INBOX":
                return None
            raise ValueError("contains invalid characters")

        mock_client._validate_folder_name.side_effect = validate_side_effect
        mock_client._is_folder_allowed.return_value = True
        process_email = tools["process_email"]

        result = await process_email(
            "INBOX", 123, "move", mock_context, target_folder="BAD\r\nFOLDER"
        )

        assert "Invalid folder name" in result
        mock_client.move_email.assert_not_called()
        mock_context.elicit.assert_not_called()


class TestProcessEmailFailurePaths:
    """Test that process_email returns error messages when client methods raise."""

    @pytest.fixture(autouse=True)
    def patch_get_client(self, mock_client: Any) -> Generator[Any, None, None]:
        """Patch get_client_from_context for this class only."""
        with patch("imap_mcp.tools.get_client_from_context") as mock_get_client:
            mock_get_client.return_value = mock_client
            yield mock_get_client

    @pytest.fixture
    def mock_context(self) -> Any:
        """Create a mock context where user confirms all actions."""
        return _make_confirmed_context()

    @pytest.mark.asyncio
    async def test_process_email_move_returns_failure(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email returns error when move_email raises."""
        mock_client.move_email.side_effect = IMAPClientError("Move failed")
        process_email = tools["process_email"]

        result = await process_email(
            "INBOX", 123, "move", mock_context, target_folder="Archive"
        )

        assert "Error" in result
        mock_client.move_email.assert_called_once_with(123, "INBOX", "Archive")

    @pytest.mark.asyncio
    async def test_process_email_read_returns_failure(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email returns error when marking as read raises."""
        mock_client.mark_email.side_effect = IMAPClientError("Mark failed")
        process_email = tools["process_email"]

        result = await process_email("INBOX", 123, "read", mock_context)

        assert "Error" in result
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Seen", True)

    @pytest.mark.asyncio
    async def test_process_email_unread_returns_failure(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email returns error when marking as unread raises."""
        mock_client.mark_email.side_effect = IMAPClientError("Mark failed")
        process_email = tools["process_email"]

        result = await process_email("INBOX", 123, "unread", mock_context)

        assert "Error" in result
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Seen", False)

    @pytest.mark.asyncio
    async def test_process_email_flag_returns_failure(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email returns error when flagging raises."""
        mock_client.mark_email.side_effect = IMAPClientError("Flag failed")
        process_email = tools["process_email"]

        result = await process_email("INBOX", 123, "flag", mock_context)

        assert "Error" in result
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Flagged", True)

    @pytest.mark.asyncio
    async def test_process_email_unflag_returns_failure(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email returns error when unflagging raises."""
        mock_client.mark_email.side_effect = IMAPClientError("Unflag failed")
        process_email = tools["process_email"]

        result = await process_email("INBOX", 123, "unflag", mock_context)

        assert "Error" in result
        mock_client.mark_email.assert_called_once_with(123, "INBOX", "\\Flagged", False)

    @pytest.mark.asyncio
    async def test_process_email_delete_returns_failure(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that process_email returns error when delete_email raises."""
        mock_client.delete_email.side_effect = IMAPClientError("Delete failed")
        process_email = tools["process_email"]

        result = await process_email("INBOX", 123, "delete", mock_context)

        assert "Error" in result
        mock_client.delete_email.assert_called_once_with(123, "INBOX")


class TestSearchEmailsPagination:
    """Tests for search_emails pagination."""

    @pytest.fixture
    def many_emails(self) -> Any:
        """Create multiple mock summaries with different dates."""
        emails = {}
        for i in range(20):
            uid = 100 + i
            emails[uid] = EmailSummary(
                uid=uid,
                subject=f"Email {i}",
                from_=EmailAddress(name=f"Sender {i}", address=f"sender{i}@test.com"),
                to=[EmailAddress(name="Recipient", address="recipient@test.com")],
                date=datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(days=i),
                flags=[],
                has_attachments=False,
            )
        return emails

    @pytest.fixture
    def mock_client(self) -> Any:
        """Create a mock IMAP client for pagination tests."""
        client = MagicMock(spec=ImapClient)
        client.list_folders.return_value = ["INBOX"]
        return client

    @pytest.fixture
    def tools(self, mock_client: Any) -> Any:
        """Register and return MCP tools backed by mock_client."""
        mcp = MagicMock(spec=FastMCP)
        stored_tools: dict[str, Any] = {}

        def mock_tool_decorator(**kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                stored_tools[func.__name__] = func
                return func

            return decorator

        mcp.tool = mock_tool_decorator
        register_tools(mcp)
        return stored_tools

    @pytest.fixture
    def mock_context(self) -> Any:
        """Create a mock context with elicitation support."""
        return _make_confirmed_context()

    @pytest.mark.asyncio
    async def test_pagination_offset(
        self, tools: Any, mock_client: Any, mock_context: Any, many_emails: Any
    ) -> None:
        """Test that offset skips results correctly."""
        search_emails = tools["search_emails"]
        mock_client.search_newest.return_value = (
            list(many_emails.keys()),
            len(many_emails),
        )
        mock_client.fetch_summaries.return_value = many_emails
        mock_client.list_folders.return_value = ["INBOX"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            # First page
            result1 = await search_emails("test", mock_context, limit=5, offset=0)
            assert result1["total"] == 20
            assert result1["offset"] == 0
            assert result1["limit"] == 5
            assert len(result1["results"]) == 5

            # Second page
            result2 = await search_emails("test", mock_context, limit=5, offset=5)
            assert result2["total"] == 20
            assert result2["offset"] == 5
            assert len(result2["results"]) == 5

        # Results should not overlap
        uids1 = {r["uid"] for r in result1["results"]}
        uids2 = {r["uid"] for r in result2["results"]}
        assert uids1.isdisjoint(uids2)

    @pytest.mark.asyncio
    async def test_pagination_offset_beyond_total(
        self, tools: Any, mock_client: Any, mock_context: Any, many_emails: Any
    ) -> None:
        """Test that offset beyond total returns empty results."""
        search_emails = tools["search_emails"]
        mock_client.search_newest.return_value = (
            list(many_emails.keys()),
            len(many_emails),
        )
        mock_client.fetch_summaries.return_value = many_emails
        mock_client.list_folders.return_value = ["INBOX"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, limit=10, offset=100)
        assert result["total"] == 20
        assert result["offset"] == 100
        assert len(result["results"]) == 0

    @pytest.mark.asyncio
    async def test_pagination_default_offset(
        self, tools: Any, mock_client: Any, mock_context: Any, many_emails: Any
    ) -> None:
        """Test that default offset is 0."""
        search_emails = tools["search_emails"]
        mock_client.search_newest.return_value = ([101, 102, 103], 3)
        mock_client.fetch_summaries.return_value = {
            k: v for k, v in many_emails.items() if k in [101, 102, 103]
        }
        mock_client.list_folders.return_value = ["INBOX"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context)
        assert result["offset"] == 0
        assert result["total"] == 3

    @pytest.mark.asyncio
    async def test_negative_offset_rejected(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that negative offset returns an error."""
        search_emails = tools["search_emails"]
        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, offset=-1)
        assert "error" in result
        assert result["results"] == []

    @pytest.mark.asyncio
    async def test_zero_limit_rejected(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that zero limit returns an error."""
        search_emails = tools["search_emails"]
        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, limit=0)
        assert "error" in result
        assert result["results"] == []

    @pytest.mark.asyncio
    async def test_negative_limit_rejected(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Test that negative limit returns an error."""
        search_emails = tools["search_emails"]
        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, limit=-5)
        assert "error" in result
        assert result["results"] == []

    @staticmethod
    def _inverse_uid_folders() -> dict[str, dict[int, EmailSummary]]:
        """Two folders where FolderB's UID order is the inverse of its dates.

        FolderA: UIDs 101-105, dates Jan 1,3,5,7,9 (UID order == date order).
        FolderB: UIDs 1-5, dates Jan 10,8,6,4,2 (low UID == newest).
        Global date-desc across both: 10,9,8,7,6,5,4,3,2,1.
        """
        folder_emails: dict[str, dict[int, EmailSummary]] = {}

        folder_a: dict[int, EmailSummary] = {}
        for i in range(5):
            uid = 101 + i
            day = 1 + i * 2  # days 1, 3, 5, 7, 9
            folder_a[uid] = EmailSummary(
                uid=uid,
                subject=f"Email day {day}",
                from_=EmailAddress(name="Sender", address="s@test.com"),
                to=[EmailAddress(name="R", address="r@test.com")],
                date=datetime(2024, 1, day, tzinfo=timezone.utc),
                flags=[],
                has_attachments=False,
            )
        folder_emails["FolderA"] = folder_a

        folder_b: dict[int, EmailSummary] = {}
        for i in range(5):
            uid = 1 + i
            day = 10 - i * 2  # UID1=day10, UID2=day8, …, UID5=day2
            folder_b[uid] = EmailSummary(
                uid=uid,
                subject=f"Email day {day}",
                from_=EmailAddress(name="Sender", address="s@test.com"),
                to=[EmailAddress(name="R", address="r@test.com")],
                date=datetime(2024, 1, day, tzinfo=timezone.utc),
                flags=[],
                has_attachments=False,
            )
        folder_emails["FolderB"] = folder_b
        return folder_emails

    @pytest.mark.asyncio
    async def test_multi_folder_pagination_global_date_order_with_sort(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Multi-folder search paginates by exact global date order under SORT.

        Regression for #41: results that belong on the requested page must not be
        dropped when sorted globally by date. ``search_newest`` returns each
        folder's newest-first candidates (exact by Date when the server supports
        SORT); the tool merges them and paginates. Even with FolderB's UID order
        *inverse* to its dates, offset=2/limit=2 yields the globally-correct page.
        """
        search_emails = tools["search_emails"]
        folder_emails = self._inverse_uid_folders()
        mock_client.list_folders.return_value = list(folder_emails.keys())

        # A SORT-capable server orders candidates by Date (newest first).
        def search_newest_sorted(
            criteria: Any,
            folder: str = "INBOX",
            limit: Any = None,
            charset: Any = None,
        ) -> tuple[list[int], int]:
            emails = folder_emails.get(folder, {})
            ordered = sorted(emails, key=lambda u: emails[u].date, reverse=True)
            total = len(ordered)
            if limit:
                ordered = ordered[:limit]
            return ordered, total

        def fetch_side_effect(
            uids: Any, folder: str = "INBOX"
        ) -> dict[int, EmailSummary]:
            return {u: folder_emails[folder][u] for u in uids}

        mock_client.search_newest.side_effect = search_newest_sorted
        mock_client.fetch_summaries.side_effect = fetch_side_effect

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, limit=2, offset=2)

        assert result["total"] == 10
        # Global date-desc: 10,9,8,7,6,5,4,3,2,1 → offset=2,limit=2 → day 8, day 7
        subjects = [r["subject"] for r in result["results"]]
        assert subjects == ["Email day 8", "Email day 7"]

    @pytest.mark.asyncio
    async def test_multi_folder_pagination_uid_proxy_without_sort(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Without SORT, per-folder candidates use the UID-order date proxy.

        Documents the accepted trade-off: on servers lacking SORT (e.g. Yandex)
        ``search_newest`` picks the newest candidates by UID, so a folder whose
        UID order diverges from its dates can have a genuinely-newer message fall
        outside the per-folder window. Here FolderB's UID 1 (the globally newest,
        day 10) is dropped, shifting the offset=2/limit=2 page off the exact
        answer — the price of bounding the fetch on a non-SORT server.
        """
        search_emails = tools["search_emails"]
        folder_emails = self._inverse_uid_folders()
        mock_client.list_folders.return_value = list(folder_emails.keys())

        # A non-SORT server: search_newest approximates newest by UID descending.
        def search_newest_uid_proxy(
            criteria: Any,
            folder: str = "INBOX",
            limit: Any = None,
            charset: Any = None,
        ) -> tuple[list[int], int]:
            emails = folder_emails.get(folder, {})
            ordered = sorted(emails, reverse=True)  # by UID descending
            total = len(ordered)
            if limit:
                ordered = ordered[:limit]
            return ordered, total

        def fetch_side_effect(
            uids: Any, folder: str = "INBOX"
        ) -> dict[int, EmailSummary]:
            return {u: folder_emails[folder][u] for u in uids}

        mock_client.search_newest.side_effect = search_newest_uid_proxy
        mock_client.fetch_summaries.side_effect = fetch_side_effect

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, limit=2, offset=2)

        # total still reflects every match across both folders.
        assert result["total"] == 10
        # fetch_count=offset+limit=4. UID-desc candidates: FolderA days [9,7,5,3],
        # FolderB days [2,4,6,8] (UID 1/day 10 dropped). Merged date-desc:
        # 9,8,7,6,5,4,3,2 → offset=2,limit=2 → day 7, day 6 (approximate).
        subjects = [r["subject"] for r in result["results"]]
        assert subjects == ["Email day 7", "Email day 6"]

    @pytest.mark.asyncio
    async def test_global_sort_uses_true_instant_across_timezones(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """Cross-folder ordering compares instants, not raw ISO strings.

        Two messages whose wall-clock strings sort one way but whose real
        instants sort the other (different UTC offsets) must be ordered by the
        actual instant. ``…T11:00+02:00`` (09:00 UTC) is *older* than
        ``…T10:00+00:00`` (10:00 UTC) even though it sorts later as text.
        """
        search_emails = tools["search_emails"]

        earlier = EmailSummary(  # 09:00 UTC — but "11" sorts after "10" as text
            uid=1,
            subject="Earlier instant",
            from_=EmailAddress(name="S", address="s@test.com"),
            to=[EmailAddress(name="R", address="r@test.com")],
            date=datetime(2024, 1, 1, 11, 0, tzinfo=timezone(timedelta(hours=2))),
            flags=[],
            has_attachments=False,
        )
        later = EmailSummary(  # 10:00 UTC — the genuinely newer message
            uid=2,
            subject="Later instant",
            from_=EmailAddress(name="S", address="s@test.com"),
            to=[EmailAddress(name="R", address="r@test.com")],
            date=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
            flags=[],
            has_attachments=False,
        )
        emails = {1: earlier, 2: later}
        mock_client.list_folders.return_value = ["INBOX"]
        mock_client.search_newest.return_value = ([1, 2], 2)
        mock_client.fetch_summaries.return_value = emails

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, limit=10, offset=0)

        # Newest-first by real instant: 10:00 UTC before 09:00 UTC.
        subjects = [r["subject"] for r in result["results"]]
        assert subjects == ["Later instant", "Earlier instant"]

    @pytest.mark.asyncio
    async def test_rejects_page_beyond_fetch_ceiling(
        self, tools: Any, mock_client: Any, mock_context: Any
    ) -> None:
        """A page reaching past ``MAX_FETCH_UIDS`` is rejected, not truncated.

        ``offset + limit`` bounds the per-folder fetch and ``fetch_summaries``
        caps at ``MAX_FETCH_UIDS``; a page past that ceiling cannot be served
        fully, so the tool returns an error rather than a quietly-incomplete page.
        """
        search_emails = tools["search_emails"]

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails(
                "test", mock_context, limit=10, offset=MAX_FETCH_UIDS
            )

        assert "error" in result
        assert str(MAX_FETCH_UIDS) in result["error"]
        assert result["results"] == []
        mock_client.search_newest.assert_not_called()

        # The boundary itself (offset + limit == MAX_FETCH_UIDS) is allowed.
        mock_client.search_newest.return_value = ([], 0)
        mock_client.fetch_summaries.return_value = {}
        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            ok = await search_emails(
                "test", mock_context, limit=10, offset=MAX_FETCH_UIDS - 10
            )
        assert "error" not in ok


class TestSearchEmailsBudget:
    """Tests for the multi-folder search_emails wall-clock budget (folder=None).

    A fan-out across many folders must not hang past the MCP client's tool-call
    timeout: once the budget is spent, remaining folders are skipped and the
    response is flagged ``truncated`` rather than failing the whole call.
    """

    @pytest.fixture
    def summary(self) -> EmailSummary:
        return EmailSummary(
            uid=1,
            subject="Email",
            from_=EmailAddress(name="Sender", address="sender@test.com"),
            to=[EmailAddress(name="Recipient", address="recipient@test.com")],
            date=datetime(2024, 1, 1, tzinfo=timezone.utc),
            flags=[],
            has_attachments=False,
        )

    @pytest.fixture
    def mock_client(self) -> Any:
        client = MagicMock(spec=ImapClient)
        client.list_folders.return_value = ["INBOX", "Sent", "Archive", "Trash"]
        return client

    @pytest.fixture
    def tools(self, mock_client: Any) -> Any:
        mcp = MagicMock(spec=FastMCP)
        stored_tools: dict[str, Any] = {}

        def mock_tool_decorator(**kwargs: Any) -> Any:
            def decorator(func: Any) -> Any:
                stored_tools[func.__name__] = func
                return func

            return decorator

        mcp.tool = mock_tool_decorator
        register_tools(mcp)
        return stored_tools

    @pytest.fixture
    def mock_context(self) -> Any:
        return _make_confirmed_context()

    @pytest.mark.asyncio
    async def test_truncates_when_budget_exceeded(
        self,
        tools: Any,
        mock_client: Any,
        mock_context: Any,
        summary: EmailSummary,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When folder=None and the budget is spent, remaining folders are skipped."""
        # A sub-nanosecond budget is exceeded by the real (tiny) wall-clock time
        # spent searching the first folder, so the test needs no sleeps and is
        # deterministic rather than dependent on a sleep racing a timer.
        monkeypatch.setenv("IMAP_MCP_SEARCH_BUDGET", "1e-9")
        search_emails = tools["search_emails"]

        mock_client.search_newest.return_value = ([1], 1)
        mock_client.fetch_summaries.return_value = {1: summary}

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, folder=None)

        # Only the first folder is searched (budget check never precedes folder 0).
        assert result["truncated"] is True
        assert result["folders_searched"] == ["INBOX"]
        assert result["folders_skipped"] == ["Sent", "Archive", "Trash"]

    @pytest.mark.asyncio
    async def test_single_folder_not_bounded_by_budget(
        self,
        tools: Any,
        mock_client: Any,
        mock_context: Any,
        summary: EmailSummary,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An explicit folder is the caller's choice and is never truncated."""
        # Even with an effectively-zero budget, an explicit folder is never
        # truncated — the budget only applies to the folder=None fan-out.
        monkeypatch.setenv("IMAP_MCP_SEARCH_BUDGET", "1e-9")
        search_emails = tools["search_emails"]

        mock_client.search_newest.return_value = ([1], 1)
        mock_client.fetch_summaries.return_value = {1: summary}

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, folder="INBOX")

        assert "truncated" not in result
        mock_client.list_folders.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_truncation_within_budget(
        self,
        tools: Any,
        mock_client: Any,
        mock_context: Any,
        summary: EmailSummary,
    ) -> None:
        """Fast multi-folder search keeps the normal response shape (no extra keys)."""
        search_emails = tools["search_emails"]
        mock_client.search_newest.return_value = ([1], 1)
        mock_client.fetch_summaries.return_value = {1: summary}

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, folder=None)

        assert "truncated" not in result
        assert "folders_searched" not in result
        assert "folders_skipped" not in result
        assert "folders_errored" not in result

    @pytest.mark.asyncio
    async def test_errored_folder_reported_not_counted(
        self,
        tools: Any,
        mock_client: Any,
        mock_context: Any,
        summary: EmailSummary,
    ) -> None:
        """A folder whose search raises is listed in folders_errored, not dropped.

        Its UIDs must not leak into ``total`` and the surviving folders must
        still return their results — coverage is reported, never silent. The
        budget is not hit here, so the response is not flagged ``truncated``.
        """
        search_emails = tools["search_emails"]

        def search_by_folder(
            criteria: Any,
            folder: str = "INBOX",
            limit: Any = None,
            charset: Any = None,
        ) -> tuple[list[int], int]:
            if folder == "Archive":
                raise IMAPClientError("boom")
            return [1], 1

        mock_client.search_newest.side_effect = search_by_folder
        mock_client.fetch_summaries.return_value = {1: summary}

        with patch("imap_mcp.tools.get_client_from_context", return_value=mock_client):
            result = await search_emails("test", mock_context, folder=None)

        assert "truncated" not in result  # budget not hit, only an error
        assert result["folders_errored"] == ["Archive"]
        assert result["folders_searched"] == ["INBOX", "Sent", "Trash"]
        # 3 successful folders x 1 uid each; the errored folder contributes 0.
        assert result["total"] == 3
