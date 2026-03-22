"""Tests for meeting invite identification and parsing logic."""

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from imap_mcp.models import Email, EmailAddress, EmailAttachment, EmailContent
from imap_mcp.workflows.invite_parser import (
    _extract_description,
    _extract_location,
    _extract_meeting_times,
    _extract_organizer,
    identify_meeting_invite_details,
)


class TestInviteParser:
    """Tests for invite parser functions."""

    @pytest.fixture
    def basic_invite_email(self) -> Any:
        """Create a basic meeting invite email."""
        return Email(
            message_id="<meeting123@example.com>",
            subject="Meeting Invitation: Project Review",
            from_=EmailAddress(name="John Smith", address="john@example.com"),
            to=[EmailAddress(name="Jane Doe", address="jane@example.com")],
            date=datetime(2025, 3, 30, 14, 0, 0),
            content=EmailContent(
                text=(
                    "You are invited to a meeting.\n"
                    "When: Monday, March 31, 2025 2:00 PM - 3:00 PM\n"
                    "Location: Conference Room A\n"
                    "Organizer: John Smith\n\n"
                    "Project review meeting to discuss progress."
                )
            ),
            headers={"Content-Type": "text/calendar; method=REQUEST"},
        )

    @pytest.fixture
    def calendar_attachment_invite_email(self) -> Any:
        """Create a meeting invite email with calendar attachment."""
        email = Email(
            message_id="<meeting456@example.com>",
            subject="Team Sync",
            from_=EmailAddress(name="Alice Manager", address="alice@example.com"),
            to=[EmailAddress(name="Team", address="team@example.com")],
            date=datetime(2025, 4, 1, 10, 0, 0),
            content=EmailContent(
                text="Weekly team sync meeting.\nPlease review the agenda."
            ),
            headers={},
        )

        # Add calendar attachment
        email.attachments = [
            EmailAttachment(
                filename="invite.ics", content_type="text/calendar", size=1024
            )
        ]

        return email

    @pytest.fixture
    def online_meeting_invite_email(self) -> Any:
        """Create an online meeting invite email."""
        return Email(
            message_id="<meeting789@example.com>",
            subject="Virtual Workshop Invitation",
            from_=EmailAddress(name="Training Dept", address="training@example.com"),
            to=[EmailAddress(name="Participants", address="participants@example.com")],
            date=datetime(2025, 4, 2, 13, 0, 0),
            content=EmailContent(
                text=(
                    "Join our virtual workshop!\n"
                    "When: Wednesday, April 2, 2025 1:00 PM - 3:00 PM\n"
                    "Location: https://meeting.example.com/workshop\n\n"
                    "Please prepare by reviewing the materials."
                )
            ),
            headers={},
        )

    @pytest.fixture
    def non_invite_email(self) -> Any:
        """Create a regular non-invite email."""
        return Email(
            message_id="<message123@example.com>",
            subject="Weekly Report",
            from_=EmailAddress(name="Reports", address="reports@example.com"),
            to=[EmailAddress(name="Manager", address="manager@example.com")],
            date=datetime(2025, 3, 28, 9, 0, 0),
            content=EmailContent(
                text="Please find attached the weekly report.\nLet me know if you have questions."
            ),
            headers={},
        )

    @pytest.fixture
    def ambiguous_email(self) -> Any:
        """Create an email with some meeting-like keywords but not an invite."""
        return Email(
            message_id="<message456@example.com>",
            subject="About yesterday's meeting",
            from_=EmailAddress(name="Colleague", address="colleague@example.com"),
            to=[EmailAddress(name="You", address="you@example.com")],
            date=datetime(2025, 3, 29, 11, 0, 0),
            content=EmailContent(
                text="I wanted to follow up on our discussion in yesterday's meeting.\nLet's schedule a call next week."
            ),
            headers={},
        )

    def test_identify_meeting_invite_by_subject(self, basic_invite_email: Any) -> None:
        """Test identifying meeting invite by subject keywords."""
        result = identify_meeting_invite_details(basic_invite_email)
        assert result["is_invite"] is True
        assert "subject" in result["details"]
        assert result["details"]["subject"] == "Project Review"

    def test_identify_meeting_invite_by_attachment(
        self, calendar_attachment_invite_email: Any
    ) -> None:
        """Test identifying meeting invite by calendar attachment."""
        result = identify_meeting_invite_details(calendar_attachment_invite_email)
        assert result["is_invite"] is True
        assert "subject" in result["details"]
        assert result["details"]["subject"] == "Team Sync"

    def test_identify_meeting_invite_by_content(
        self, online_meeting_invite_email: Any
    ) -> None:
        """Test identifying meeting invite by content patterns."""
        result = identify_meeting_invite_details(online_meeting_invite_email)
        assert result["is_invite"] is True
        assert "location" in result["details"]
        assert "https://meeting.example.com/workshop" in result["details"]["location"]

    def test_non_invite_email(self, non_invite_email: Any) -> None:
        """Test that non-invite emails are correctly identified."""
        result = identify_meeting_invite_details(non_invite_email)
        assert result["is_invite"] is False
        assert result["details"] == {}

    def test_ambiguous_email(self, ambiguous_email: Any) -> None:
        """Test handling of ambiguous emails with meeting keywords."""
        # Our implementation might identify this as a meeting or not depending on threshold
        # The important thing is consistent behavior
        result = identify_meeting_invite_details(ambiguous_email)
        is_invite = result["is_invite"]

        # If identified as invite, check extracted details
        if is_invite:
            assert "subject" in result["details"]
            assert result["details"]["subject"] == "About yesterday's meeting"
        else:
            assert result["details"] == {}

    def test_extract_meeting_times(self, basic_invite_email: Any) -> None:
        """Test extracting meeting start and end times."""
        start_time, end_time = _extract_meeting_times(basic_invite_email)

        assert start_time is not None
        assert end_time is not None

        # Date must come from When line (March 31), not email send date (March 30)
        assert start_time.year == 2025
        assert start_time.month == 3
        assert start_time.day == 31
        assert start_time.hour == 14  # 2 PM
        assert start_time.minute == 0
        assert end_time.day == 31
        assert end_time.hour == 15  # 3 PM
        assert end_time.minute == 0

    def test_extract_meeting_times_date_from_when_text(self) -> None:
        """Test that meeting date is parsed from When line, not email send date."""
        email_obj = Email(
            message_id="<test-date@example.com>",
            subject="Meeting Invitation: Sprint Planning",
            from_=EmailAddress(name="PM", address="pm@example.com"),
            to=[EmailAddress(name="Dev", address="dev@example.com")],
            date=datetime(2025, 6, 10, 9, 0, 0),  # Email sent June 10
            content=EmailContent(
                text="When: Thursday, June 12, 2025 3:00 PM - 4:00 PM\n"
            ),
        )
        start_time, end_time = _extract_meeting_times(email_obj)

        assert start_time is not None
        assert end_time is not None
        # Meeting is June 12, NOT June 10 (the email send date)
        assert start_time.date() == datetime(2025, 6, 12).date()
        assert start_time.hour == 15
        assert end_time.date() == datetime(2025, 6, 12).date()
        assert end_time.hour == 16

    def test_extract_meeting_location(
        self, basic_invite_email: Any, online_meeting_invite_email: Any
    ) -> None:
        """Test extracting meeting location for physical and online meetings."""
        # Physical location
        location1 = _extract_location(basic_invite_email)
        assert "Conference Room A" in location1

        # Online location
        location2 = _extract_location(online_meeting_invite_email)
        assert "https://meeting.example.com/workshop" in location2

    def test_extract_meeting_organizer(self, basic_invite_email: Any) -> None:
        """Test extracting meeting organizer."""
        organizer = _extract_organizer(basic_invite_email)
        assert "John Smith" in organizer

    def test_fallback_to_email_date(self) -> None:
        """Test fallback to email date when no explicit meeting time is found."""
        email = Email(
            message_id="<meeting999@example.com>",
            subject="Quick Meeting",
            from_=EmailAddress(name="Colleague", address="colleague@example.com"),
            to=[EmailAddress(name="You", address="you@example.com")],
            date=datetime(2025, 4, 5, 10, 0, 0),
            content=EmailContent(
                text="Let's have a quick meeting to discuss the project."
            ),
            headers={},
        )

        result = identify_meeting_invite_details(email)

        # We might identify this as a meeting due to the keyword
        if result["is_invite"]:
            assert result["details"]["start_time"] is not None
            # Should fall back to email date
            assert result["details"]["start_time"].date() == datetime(2025, 4, 5).date()

    def test_extract_description(self, basic_invite_email: Any) -> None:
        """Test extracting meeting description."""
        description = _extract_description(basic_invite_email)
        assert "Project review meeting" in description


class TestExtractMeetingTimesAMPM:
    """Tests for AM/PM time parsing in _extract_meeting_times."""

    def test_12_am_midnight(self) -> None:
        """Test that 12:00 AM is parsed as midnight (hour 0)."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 12:00 AM - 1:00 AM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 0
        assert end_time.hour == 1

    def test_12_pm_noon(self) -> None:
        """Test that 12:00 PM is parsed as noon (hour 12)."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 12:00 PM - 1:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 12
        assert end_time.hour == 13

    def test_12_30_am(self) -> None:
        """Test that 12:30 AM is parsed as hour 0, minute 30."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 12:30 AM - 1:30 AM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert start_time.hour == 0
        assert start_time.minute == 30

    def test_regular_pm(self) -> None:
        """Test that regular PM times are parsed correctly (regression test)."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 2:00 PM - 3:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 14
        assert end_time.hour == 15

    def test_regular_am(self) -> None:
        """Test that regular AM times are parsed correctly (regression test)."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 9:00 AM - 10:00 AM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 9
        assert end_time.hour == 10

    def test_24h_afternoon(self) -> None:
        """Test that 24-hour afternoon times are parsed correctly."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 10, 0, 0),
            content=EmailContent(text="When: Monday, March 31, 2025 14:00 - 15:00"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 14
        assert start_time.minute == 0
        assert end_time.hour == 15
        assert end_time.minute == 0

    def test_24h_morning(self) -> None:
        """Test that 24-hour morning times with minutes are parsed correctly."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 10, 0, 0),
            content=EmailContent(text="When: Monday, March 31, 2025 9:30 - 10:30"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 9
        assert start_time.minute == 30
        assert end_time.hour == 10
        assert end_time.minute == 30

    def test_mixed_24h_and_ampm(self) -> None:
        """Test mixed format: 24-hour start, AM/PM end."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 10, 0, 0),
            content=EmailContent(text="When: Monday, March 31, 2025 14:00 - 3:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.hour == 14
        assert end_time.hour == 15

    def test_bare_time_treated_as_24h(self) -> None:
        """Test that bare times without AM/PM are treated as 24-hour format.

        "2:00 - 3:00" without AM/PM is interpreted as 02:00-03:00 (early morning).
        This is strictly better than the old behavior where the regex didn't match
        at all and fell back to the email send date (losing the correct date).
        """
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 30, 14, 0, 0),  # Email sent March 30
            content=EmailContent(text="When: Monday, March 31, 2025 2:00 - 3:00"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        # Date comes from When line (March 31), not email send date (March 30)
        assert start_time.date() == datetime(2025, 3, 31).date()
        # Bare "2:00" without AM/PM → 24-hour interpretation → 2 AM
        assert start_time.hour == 2
        assert end_time.hour == 3

    def test_when_line_no_date_falls_back_to_email_date(self) -> None:
        """Test that When lines without a date fall back to email send date."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 2:00 PM - 3:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        # No date in When line, so should use email date (March 31)
        assert start_time.date() == datetime(2025, 3, 31).date()
        assert end_time.date() == datetime(2025, 3, 31).date()
        assert start_time.hour == 14
        assert end_time.hour == 15

    def test_abbreviated_month(self) -> None:
        """Test that abbreviated month names are parsed correctly."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 28, 10, 0, 0),
            content=EmailContent(text="When: Thu, Mar 31, 2025 2:00 PM - 3:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.date() == datetime(2025, 3, 31).date()
        assert start_time.hour == 14
        assert end_time.hour == 15

    def test_iso_date_format(self) -> None:
        """Test that ISO 8601 dates (YYYY-MM-DD) are parsed from When line."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 6, 10, 9, 0, 0),
            content=EmailContent(text="When: 2025-06-15 3:00 PM - 4:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.date() == datetime(2025, 6, 15).date()
        assert start_time.hour == 15
        assert end_time.hour == 16

    def test_timezone_preserved(self) -> None:
        """Test that timezone from email date is preserved in parsed meeting time."""
        tz = timezone(timedelta(hours=3))
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 30, 14, 0, 0, tzinfo=tz),
            content=EmailContent(text="When: Monday, March 31, 2025 2:00 PM - 3:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.date() == datetime(2025, 3, 31).date()
        assert start_time.tzinfo == tz
        assert end_time.tzinfo == tz

    def test_seconds_zeroed(self) -> None:
        """Test that seconds/microseconds are zeroed in parsed meeting times."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 30, 45, 123456),
            content=EmailContent(text="When: Monday 2:00 PM - 3:00 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.second == 0
        assert start_time.microsecond == 0
        assert end_time.second == 0
        assert end_time.microsecond == 0

    def test_fallback_hour_23_no_overflow(self) -> None:
        """Test that fallback end time at hour 23 doesn't crash (fixes #44)."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 23, 30, 0),
            content=EmailContent(text="Let's discuss the project."),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert end_time is not None
        assert start_time.date() == datetime(2025, 3, 31).date()
        assert start_time.hour == 23
        assert start_time.minute == 30
        assert start_time.second == 0
        assert end_time == start_time + timedelta(hours=1)
        # End time rolls over to next day
        assert end_time.day == 1
        assert end_time.hour == 0
        assert end_time.minute == 30

    def test_invalid_time_falls_back_to_email_date(self) -> None:
        """Test that invalid times trigger fallback to email date."""
        email_obj = Email(
            message_id="<test@example.com>",
            subject="Meeting",
            from_=EmailAddress(name="", address="test@example.com"),
            to=[],
            date=datetime(2025, 3, 31, 14, 0, 0),
            content=EmailContent(text="When: Monday 25:99 AM - 26:99 PM"),
        )
        start_time, end_time = _extract_meeting_times(email_obj)
        assert start_time is not None
        assert start_time.date() == datetime(2025, 3, 31).date()
        assert start_time.hour == 14
        assert start_time.second == 0
