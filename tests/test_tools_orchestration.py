"""Tests for the meeting invite orchestration tool."""

from datetime import datetime
from email.message import EmailMessage
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import Context, FastMCP

from imap_mcp.config import ImapConfig
from imap_mcp.imap_client import ImapClient
from imap_mcp.models import Email, EmailAddress, EmailContent
from imap_mcp.tools import register_tools


class TestMeetingInviteOrchestration:
    """Tests for the meeting invite orchestration functionality."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context with elicitation support."""
        ctx = MagicMock(spec=Context)
        # Default elicitation: user accepts and confirms
        accepted = MagicMock()
        accepted.action = "accept"
        accepted.data = MagicMock()
        accepted.data.confirmed = True
        ctx.elicit = AsyncMock(return_value=accepted)
        return ctx

    @pytest.fixture
    def mock_imap_client(self):
        """Create a mock IMAP client."""
        config = ImapConfig(
            host="imap.example.com",
            port=993,
            username="test@example.com",
            password="password",
            use_ssl=True
        )
        client = ImapClient(config)

        # Mock necessary methods
        client.fetch_email = MagicMock()
        client.save_draft_mime = MagicMock()
        client._get_drafts_folder = MagicMock(return_value="Drafts")

        return client

    @pytest.fixture
    def mock_invite_email(self):
        """Create a mock meeting invite email."""
        return Email(
            message_id="<invite123@example.com>",
            subject="Meeting Invitation: Team Sync",
            from_=EmailAddress(name="Organizer", address="organizer@example.com"),
            to=[EmailAddress(name="Me", address="me@example.com")],
            date=datetime(2025, 4, 1, 10, 0, 0),
            content=EmailContent(
                text="You are invited to a team sync meeting.\nWhen: Tuesday, April 1, 2025 10:00 AM - 11:00 AM"
            ),
            headers={"Content-Type": "text/calendar; method=REQUEST"}
        )

    @pytest.fixture
    def mock_non_invite_email(self):
        """Create a mock non-invite email."""
        return Email(
            message_id="<message123@example.com>",
            subject="Regular Email",
            from_=EmailAddress(name="Sender", address="sender@example.com"),
            to=[EmailAddress(name="Me", address="me@example.com")],
            date=datetime(2025, 4, 1, 9, 0, 0),
            content=EmailContent(
                text="This is a regular email, not a meeting invite."
            ),
            headers={}
        )

    @pytest.fixture
    def registered_tools(self):
        """Register tools and return captured tool functions."""
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
        return stored_tools

    @pytest.mark.asyncio
    @patch("imap_mcp.smtp_client.create_reply_mime")
    @patch("imap_mcp.workflows.meeting_reply.generate_meeting_reply_content")
    @patch("imap_mcp.workflows.calendar_mock.check_mock_availability")
    @patch("imap_mcp.workflows.invite_parser.identify_meeting_invite_details")
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_process_meeting_invite_success(
        self,
        mock_get_client,
        mock_identify_invite,
        mock_check_availability,
        mock_generate_reply,
        mock_create_reply_mime,
        mock_context,
        mock_imap_client,
        mock_invite_email,
        registered_tools,
    ):
        """Test successful processing of a meeting invite."""
        mock_get_client.return_value = mock_imap_client
        mock_imap_client.fetch_email.return_value = mock_invite_email

        mock_identify_invite.return_value = {
            "is_invite": True,
            "details": {
                "subject": "Team Sync",
                "start_time": datetime(2025, 4, 1, 10, 0, 0),
                "end_time": datetime(2025, 4, 1, 11, 0, 0),
                "organizer": "Organizer <organizer@example.com>",
                "location": "Conference Room"
            }
        }

        mock_check_availability.return_value = {
            "available": True,
            "reason": "Time slot is available",
            "alternative_times": []
        }

        mock_generate_reply.return_value = {
            "reply_subject": "Accepted: Team Sync",
            "reply_body": "I'll attend the meeting...",
            "reply_type": "accept"
        }

        mock_mime_message = MagicMock(spec=EmailMessage)
        mock_create_reply_mime.return_value = mock_mime_message

        mock_imap_client.save_draft_mime.return_value = 123

        process_meeting_invite = registered_tools["process_meeting_invite"]
        result = await process_meeting_invite(
            folder="INBOX",
            uid=456,
            ctx=mock_context,
            availability_mode="always_available"
        )

        assert result["status"] == "success"
        assert result["draft_uid"] == 123
        assert result["draft_folder"] == "Drafts"
        assert result["availability"] is True

        mock_imap_client.fetch_email.assert_called_once_with(456, "INBOX")
        mock_identify_invite.assert_called_once_with(mock_invite_email)
        mock_check_availability.assert_called_once()
        mock_generate_reply.assert_called_once()
        mock_create_reply_mime.assert_called_once()
        mock_imap_client.save_draft_mime.assert_called_once_with(mock_mime_message)
        mock_imap_client._get_drafts_folder.assert_called_once()

    @pytest.mark.asyncio
    @patch("imap_mcp.workflows.invite_parser.identify_meeting_invite_details")
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_process_non_invite_email(
        self,
        mock_get_client,
        mock_identify_invite,
        mock_context,
        mock_imap_client,
        mock_non_invite_email,
        registered_tools,
    ):
        """Test processing a non-invite email."""
        mock_get_client.return_value = mock_imap_client
        mock_imap_client.fetch_email.return_value = mock_non_invite_email

        mock_identify_invite.return_value = {
            "is_invite": False,
            "details": {}
        }

        process_meeting_invite = registered_tools["process_meeting_invite"]
        result = await process_meeting_invite(
            folder="INBOX",
            uid=456,
            ctx=mock_context
        )

        assert result["status"] == "not_invite"
        assert "The email is not a meeting invite" in result["message"]

        mock_imap_client.fetch_email.assert_called_once_with(456, "INBOX")
        mock_identify_invite.assert_called_once_with(mock_non_invite_email)

    @pytest.mark.asyncio
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_process_meeting_invite_email_not_found(
        self,
        mock_get_client,
        mock_context,
        mock_imap_client,
        registered_tools,
    ):
        """Test handling when the email is not found."""
        mock_get_client.return_value = mock_imap_client
        mock_imap_client.fetch_email.return_value = None

        process_meeting_invite = registered_tools["process_meeting_invite"]
        result = await process_meeting_invite(
            folder="INBOX",
            uid=456,
            ctx=mock_context
        )

        assert result["status"] == "error"
        assert "not found" in result["message"]

        mock_imap_client.fetch_email.assert_called_once_with(456, "INBOX")

    @pytest.mark.asyncio
    @patch("imap_mcp.smtp_client.create_reply_mime")
    @patch("imap_mcp.workflows.meeting_reply.generate_meeting_reply_content")
    @patch("imap_mcp.workflows.calendar_mock.check_mock_availability")
    @patch("imap_mcp.workflows.invite_parser.identify_meeting_invite_details")
    @patch("imap_mcp.tools.get_client_from_context")
    async def test_process_meeting_invite_save_draft_failure(
        self,
        mock_get_client,
        mock_identify_invite,
        mock_check_availability,
        mock_generate_reply,
        mock_create_reply_mime,
        mock_context,
        mock_imap_client,
        mock_invite_email,
        registered_tools,
    ):
        """Test handling when saving the draft fails."""
        mock_get_client.return_value = mock_imap_client
        mock_imap_client.fetch_email.return_value = mock_invite_email

        mock_identify_invite.return_value = {
            "is_invite": True,
            "details": {
                "subject": "Team Sync",
                "start_time": datetime(2025, 4, 1, 10, 0, 0),
                "end_time": datetime(2025, 4, 1, 11, 0, 0),
                "organizer": "Organizer <organizer@example.com>",
                "location": "Conference Room"
            }
        }

        mock_check_availability.return_value = {
            "available": False,
            "reason": "Calendar is busy during this time",
            "alternative_times": []
        }

        mock_generate_reply.return_value = {
            "reply_subject": "Declined: Team Sync",
            "reply_body": "I'm unable to attend the meeting...",
            "reply_type": "decline"
        }

        mock_mime_message = MagicMock(spec=EmailMessage)
        mock_create_reply_mime.return_value = mock_mime_message

        mock_imap_client.save_draft_mime.return_value = None

        process_meeting_invite = registered_tools["process_meeting_invite"]
        result = await process_meeting_invite(
            folder="INBOX",
            uid=456,
            ctx=mock_context,
            availability_mode="always_busy"
        )

        assert result["status"] == "error"
        assert "Failed to save draft" in result["message"]
        assert result["availability"] is False

        mock_imap_client.fetch_email.assert_called_once_with(456, "INBOX")
        mock_identify_invite.assert_called_once_with(mock_invite_email)
        mock_check_availability.assert_called_once()
        mock_generate_reply.assert_called_once()
        mock_create_reply_mime.assert_called_once()
        mock_imap_client.save_draft_mime.assert_called_once_with(mock_mime_message)
