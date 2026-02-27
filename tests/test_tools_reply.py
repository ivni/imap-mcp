"""Tests for reply-related MCP tools."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import Context, FastMCP

from imap_mcp.models import Email, EmailAddress, EmailContent
from imap_mcp.tools import register_tools


class TestToolsReply:
    """Test class for reply-related MCP tools."""

    @pytest.fixture
    def mock_email(self):
        """Create a mock email object for testing."""
        return Email(
            message_id="<test123@example.com>",
            subject="Test Email",
            from_=EmailAddress(name="Sender", address="sender@example.com"),
            to=[EmailAddress(name="Recipient", address="recipient@example.com")],
            cc=[],
            date=datetime.now(),
            content=EmailContent(text="Test content", html="<p>Test content</p>"),
            attachments=[],
            flags=["\\Seen"],
            headers={},
            folder="INBOX",
            uid=1
        )

    @pytest.fixture
    def registered_tools(self):
        """Register tools and return captured tool functions with mock client."""
        mcp = MagicMock(spec=FastMCP)
        stored_tools = {}

        def mock_tool_decorator(**kwargs):
            def decorator(func):
                stored_tools[func.__name__] = func
                return func
            return decorator

        mcp.tool = mock_tool_decorator
        imap_client = MagicMock()
        register_tools(mcp, imap_client)
        return stored_tools, imap_client

    @pytest.fixture
    def mock_context(self):
        """Create a mock context with elicitation support.

        Default: user confirms all actions (accept + confirmed=True).
        """
        context = MagicMock(spec=Context)

        # Default elicitation: user accepts and confirms
        accepted = MagicMock()
        accepted.action = "accept"
        accepted.data = MagicMock()
        accepted.data.confirmed = True
        context.elicit = AsyncMock(return_value=accepted)

        return context

    @pytest.mark.asyncio
    @patch("imap_mcp.smtp_client.create_reply_mime")
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_draft_reply_tool_success(
        self, mock_get_client, mock_create_reply, registered_tools, mock_email, mock_context
    ):
        """Test successful creation of a draft reply."""
        tools_dict, imap_client = registered_tools
        draft_reply_tool = tools_dict["draft_reply_tool"]

        mock_get_client.return_value = imap_client
        imap_client.fetch_email.return_value = mock_email
        imap_client.config.username = "recipient@example.com"

        mime_message = MagicMock()
        mock_create_reply.return_value = mime_message
        imap_client.save_draft_mime.return_value = 123

        result = await draft_reply_tool(
            folder="INBOX",
            uid=1,
            reply_body="This is my reply",
            ctx=mock_context
        )

        assert result["status"] == "success"
        assert result["draft_uid"] == 123

        imap_client.fetch_email.assert_called_once_with(1, "INBOX")
        mock_create_reply.assert_called_once()
        imap_client.save_draft_mime.assert_called_once_with(mime_message)

    @pytest.mark.asyncio
    @patch("imap_mcp.smtp_client.create_reply_mime")
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_draft_reply_tool_with_options(
        self, mock_get_client, mock_create_reply, registered_tools, mock_email, mock_context
    ):
        """Test draft reply with reply_all and cc options."""
        tools_dict, imap_client = registered_tools
        draft_reply_tool = tools_dict["draft_reply_tool"]

        mock_get_client.return_value = imap_client
        imap_client.fetch_email.return_value = mock_email
        imap_client.config.username = "recipient@example.com"

        mime_message = MagicMock()
        mock_create_reply.return_value = mime_message
        imap_client.save_draft_mime.return_value = 456

        cc_list = ["extra@example.com", "another@example.com"]
        result = await draft_reply_tool(
            folder="INBOX",
            uid=1,
            reply_body="Reply with options",
            reply_all=True,
            cc=cc_list,
            ctx=mock_context
        )

        assert result["status"] == "success"

        # Verify create_reply_mime was called with reply_all=True and cc addresses
        call_kwargs = mock_create_reply.call_args[1]
        assert call_kwargs["reply_all"] is True
        assert call_kwargs["cc"] is not None

    @pytest.mark.asyncio
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_draft_reply_tool_fetch_fail(
        self, mock_get_client, registered_tools, mock_context
    ):
        """Test handling when email fetch fails."""
        tools_dict, imap_client = registered_tools
        draft_reply_tool = tools_dict["draft_reply_tool"]

        mock_get_client.return_value = imap_client
        imap_client.fetch_email.return_value = None

        result = await draft_reply_tool(
            folder="INBOX",
            uid=999,
            reply_body="Reply to nothing",
            ctx=mock_context
        )

        assert result["status"] == "error"
        assert "not found" in result["message"].lower()
        imap_client.save_draft_mime.assert_not_called()

    @pytest.mark.asyncio
    @patch("imap_mcp.smtp_client.create_reply_mime")
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_draft_reply_tool_save_fail(
        self, mock_get_client, mock_create_reply, registered_tools, mock_email, mock_context
    ):
        """Test handling when draft saving fails."""
        tools_dict, imap_client = registered_tools
        draft_reply_tool = tools_dict["draft_reply_tool"]

        mock_get_client.return_value = imap_client
        imap_client.fetch_email.return_value = mock_email
        imap_client.config.username = "recipient@example.com"

        mime_message = MagicMock()
        mock_create_reply.return_value = mime_message
        imap_client.save_draft_mime.return_value = None

        result = await draft_reply_tool(
            folder="INBOX",
            uid=1,
            reply_body="Reply that can't be saved",
            ctx=mock_context
        )

        assert result["status"] == "error"
        assert "failed to save" in result["message"].lower()
        imap_client.save_draft_mime.assert_called_once()

    @pytest.mark.asyncio
    async def test_draft_reply_tool_confirmation_declined(
        self, registered_tools, mock_context
    ):
        """Test that declining confirmation prevents draft creation."""
        tools_dict, imap_client = registered_tools
        draft_reply_tool = tools_dict["draft_reply_tool"]

        # Override elicit to return declined
        declined = MagicMock()
        declined.action = "decline"
        mock_context.elicit = AsyncMock(return_value=declined)

        result = await draft_reply_tool(
            folder="INBOX",
            uid=1,
            reply_body="reply text",
            ctx=mock_context
        )

        assert result["status"] == "cancelled"
        assert "not confirmed" in result["message"].lower()
        imap_client.fetch_email.assert_not_called()
        imap_client.save_draft_mime.assert_not_called()
