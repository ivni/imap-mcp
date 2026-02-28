"""Tests for MCP tools implementation."""

import json
import os
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import Context, FastMCP

from imap_mcp.imap_client import ImapClient
from imap_mcp.models import Email, EmailAddress, EmailContent
from imap_mcp.tools import register_tools, require_confirmation

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
    client.fetch_emails.return_value = {1: mock_email, 2: mock_email, 3: mock_email}
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
    register_tools(mcp, mock_client)
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
    def patch_get_client(self, mock_client: Any) -> None:
        """Patch get_client_from_context for this class only."""
        with patch('imap_mcp.tools.get_client_from_context') as mock_get_client:
            mock_get_client.return_value = mock_client
            yield mock_get_client

    @pytest.fixture
    def mock_context(self) -> Any:
        """Create a mock context with elicitation support.

        Default: user confirms all actions (accept + confirmed=True).
        """
        return _make_confirmed_context()

    @pytest.mark.asyncio
    async def test_move_email(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
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
        mock_client.move_email.side_effect = Exception("Connection error")
        result = await move_email("INBOX", 123, "Archive", mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_mark_as_read(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
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
        mock_client.mark_email.return_value = False
        result = await mark_as_read("INBOX", 123, mock_context)
        assert "Failed to mark email as read" in result

    @pytest.mark.asyncio
    async def test_mark_as_unread(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
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
        mock_client.mark_email.side_effect = Exception("Server error")
        result = await mark_as_unread("INBOX", 123, mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_flag_email(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
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
    async def test_delete_email(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
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
        mock_client.delete_email.return_value = False
        result = await delete_email("INBOX", 123, mock_context)
        assert "Failed to delete" in result

        # Test error handling
        mock_client.delete_email.side_effect = Exception("Permission denied")
        result = await delete_email("INBOX", 123, mock_context)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_search_emails(self, tools: Any, mock_client: Any, mock_context: Any, mock_email: Any) -> None:
        """Test searching for emails."""
        # Get the search_emails function
        search_emails = tools["search_emails"]

        # Test searching with default parameters
        result = await search_emails("test query", mock_context)
        result_data = json.loads(result)

        # Assert client methods were called properly
        mock_client.list_folders.assert_called_once()
        assert mock_client.search.call_count > 0

        # Check result structure
        assert isinstance(result_data, list)
        assert len(result_data) > 0
        assert "uid" in result_data[0]
        assert "folder" in result_data[0]
        assert "subject" in result_data[0]

        # Reset mocks
        mock_client.list_folders.reset_mock()
        mock_client.search.reset_mock()
        mock_client.fetch_emails.reset_mock()

        # Test searching with specific folder
        result = await search_emails("test query", mock_context, folder="INBOX")

        # Assert client methods were called properly
        mock_client.list_folders.assert_not_called()
        mock_client.search.assert_called_once()

        # Test with different criteria
        criteria_tests = ["from", "to", "subject", "all", "unseen", "seen"]
        for criteria in criteria_tests:
            mock_client.search.reset_mock()
            result = await search_emails("test query", mock_context, criteria=criteria)
            assert mock_client.search.called

        # Test with invalid criteria
        result = await search_emails("test query", mock_context, criteria="invalid")
        assert "Invalid search criteria" in result

    @pytest.mark.asyncio
    async def test_process_email(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
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
    async def test_tool_error_handling(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
        """Test error handling in tools."""
        # Get tools to test
        move_email = tools["move_email"]
        mark_as_read = tools["mark_as_read"]
        search_emails = tools["search_emails"]

        # Test move_email error handling
        mock_client.move_email.side_effect = Exception("Network error")
        result = await move_email("INBOX", 123, "Archive", mock_context)
        assert "Error" in result

        # Test mark_as_read error handling
        mock_client.mark_email.side_effect = Exception("Server timeout")
        result = await mark_as_read("INBOX", 123, mock_context)
        assert "Error" in result

        # Test search_emails error handling
        mock_client.search.side_effect = Exception("Search failed")
        result = await search_emails("test", mock_context)
        # Search should continue with other folders and return an empty list
        assert "[]" in result or result == "[]"

    @pytest.mark.asyncio
    async def test_tool_parameter_validation(self, tools: Any, mock_client: Any, mock_context: Any) -> None:
        """Test parameter validation in tools."""
        # Get tools to test
        search_emails = tools["search_emails"]
        process_email = tools["process_email"]

        # Test search_emails with invalid criteria
        result = await search_emails("test", mock_context, criteria="invalid_criteria")
        assert "Invalid search criteria" in result

        # Test process_email with missing target folder for move action
        result = await process_email("INBOX", 123, "move", ctx=mock_context)
        assert "Target folder must be specified" in result

        # Test process_email with invalid action
        result = await process_email("INBOX", 123, "nonexistent_action", ctx=mock_context)
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
    async def test_delete_email_confirmation_declined(self, tools: Any, mock_client: Any, declined_context: Any) -> None:
        """Test that declining confirmation prevents deletion."""
        delete_email = tools["delete_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await delete_email("INBOX", 123, declined_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_email_confirmation_not_confirmed(self, tools: Any, mock_client: Any, not_confirmed_context: Any) -> None:
        """Test that accepting with confirmed=False prevents deletion."""
        delete_email = tools["delete_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await delete_email("INBOX", 123, not_confirmed_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_email_confirmation_cancelled(self, tools: Any, mock_client: Any, cancelled_context: Any) -> None:
        """Test that cancelling confirmation prevents deletion."""
        delete_email = tools["delete_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await delete_email("INBOX", 123, cancelled_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_move_email_confirmation_declined(self, tools: Any, mock_client: Any, declined_context: Any) -> None:
        """Test that declining confirmation prevents move."""
        move_email = tools["move_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await move_email("INBOX", 123, "Archive", declined_context)

        assert "cancelled" in result.lower()
        mock_client.move_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_delete_requires_confirmation(self, tools: Any, mock_client: Any, declined_context: Any) -> None:
        """Test that process_email with delete action requires confirmation."""
        process_email = tools["process_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await process_email("INBOX", 123, "delete", declined_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_move_requires_confirmation(self, tools: Any, mock_client: Any, declined_context: Any) -> None:
        """Test that process_email with move action requires confirmation."""
        process_email = tools["process_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await process_email("INBOX", 123, "move", declined_context, target_folder="Archive")

        assert "cancelled" in result.lower()
        mock_client.move_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_read_no_confirmation(self, tools: Any, mock_client: Any, confirmed_context: Any) -> None:
        """Test that process_email with read action does NOT require confirmation."""
        process_email = tools["process_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await process_email("INBOX", 123, "read", confirmed_context)

        assert "Email marked as read" in result
        confirmed_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_process_email_flag_no_confirmation(self, tools: Any, mock_client: Any, confirmed_context: Any) -> None:
        """Test that process_email with flag action does NOT require confirmation."""
        process_email = tools["process_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await process_email("INBOX", 123, "flag", confirmed_context)

        assert "Email flagged" in result
        confirmed_context.elicit.assert_not_called()

    @pytest.mark.asyncio
    async def test_elicitation_not_supported_aborts_delete(self, tools: Any, mock_client: Any, unsupported_context: Any) -> None:
        """Test that when elicitation raises, delete is aborted for safety."""
        delete_email = tools["delete_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client):
            result = await delete_email("INBOX", 123, unsupported_context)

        assert "cancelled" in result.lower()
        mock_client.delete_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_skip_confirmation_env_var(self, tools: Any, mock_client: Any, declined_context: Any) -> None:
        """Test that IMAP_MCP_SKIP_CONFIRMATION=true bypasses confirmation."""
        delete_email = tools["delete_email"]

        with patch('imap_mcp.tools.get_client_from_context', return_value=mock_client), \
             patch.dict(os.environ, {"IMAP_MCP_SKIP_CONFIRMATION": "true"}):
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
    async def test_returns_false_on_decline(self) -> None:
        """Verify require_confirmation returns False on decline."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("decline"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_on_accept_confirmed(self) -> None:
        """Verify require_confirmation returns True on accept+confirmed."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(return_value=_make_elicit_result("accept", True))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_on_exception(self) -> None:
        """Verify require_confirmation returns False when elicitation raises."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(side_effect=Exception("not supported"))

        result = await require_confirmation(ctx, "delete", "INBOX", 1)
        assert result is False

    @pytest.mark.asyncio
    async def test_skip_via_env_var(self) -> None:
        """Verify IMAP_MCP_SKIP_CONFIRMATION=true skips elicitation."""
        ctx = MagicMock(spec=Context)
        ctx.elicit = AsyncMock(side_effect=AssertionError("should not be called"))

        with patch.dict(os.environ, {"IMAP_MCP_SKIP_CONFIRMATION": "true"}):
            result = await require_confirmation(ctx, "delete", "INBOX", 1)

        assert result is True
        ctx.elicit.assert_not_called()
