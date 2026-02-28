"""Tests for email models."""

import email
import unittest
from email.header import Header
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock

from imap_mcp.models import (
    MAX_ATTACHMENT_SIZE,
    Email,
    EmailAddress,
    EmailAttachment,
    decode_mime_header,
)


class TestModels(unittest.TestCase):
    """Test cases for email models."""

    def test_decode_mime_header(self) -> None:
        """Test MIME header decoding."""
        # Test ASCII header
        self.assertEqual(decode_mime_header("Hello"), "Hello")

        # Test encoded header
        encoded_header = Header("Héllö Wörld", "utf-8").encode()
        self.assertEqual(decode_mime_header(encoded_header), "Héllö Wörld")

        # Test empty header
        self.assertEqual(decode_mime_header(None), "")
        self.assertEqual(decode_mime_header(""), "")

    def test_email_address_parse(self) -> None:
        """Test email address parsing."""
        # Test name + address
        addr = EmailAddress.parse("John Doe <john@example.com>")
        self.assertEqual(addr.name, "John Doe")
        self.assertEqual(addr.address, "john@example.com")

        # Test quoted name
        addr = EmailAddress.parse('"Smith, John" <john@example.com>')
        self.assertEqual(addr.name, "Smith, John")
        self.assertEqual(addr.address, "john@example.com")

        # Test address only
        addr = EmailAddress.parse("jane@example.com")
        self.assertEqual(addr.name, "")
        self.assertEqual(addr.address, "jane@example.com")

        # Test string conversion
        addr = EmailAddress("Jane Smith", "jane@example.com")
        self.assertEqual(str(addr), "Jane Smith <jane@example.com>")
        addr = EmailAddress("", "jane@example.com")
        self.assertEqual(str(addr), "jane@example.com")

    def test_email_from_message(self) -> None:
        """Test creating email from message."""
        # Create a multipart email
        msg = MIMEMultipart()
        msg["From"] = "John Doe <john@example.com>"
        msg["To"] = "Jane Smith <jane@example.com>, bob@example.com"
        msg["Subject"] = "Test Email"
        msg["Message-ID"] = "<test123@example.com>"
        msg["Date"] = email.utils.formatdate()

        # Add plain text part
        text_part = MIMEText("Hello, this is a test email.", "plain")
        msg.attach(text_part)

        # Add HTML part
        html_part = MIMEText("<p>Hello, this is a <b>test</b> email.</p>", "html")
        msg.attach(html_part)

        # Parse email
        email_obj = Email.from_message(msg, uid=1234, folder="INBOX")

        # Check basic fields
        self.assertEqual(email_obj.message_id, "<test123@example.com>")
        self.assertEqual(email_obj.subject, "Test Email")
        self.assertEqual(str(email_obj.from_), "John Doe <john@example.com>")
        self.assertEqual(len(email_obj.to), 2)
        self.assertEqual(str(email_obj.to[0]), "Jane Smith <jane@example.com>")
        self.assertEqual(str(email_obj.to[1]), "bob@example.com")
        self.assertEqual(email_obj.folder, "INBOX")
        self.assertEqual(email_obj.uid, 1234)

        # Check content
        self.assertEqual(email_obj.content.text, "Hello, this is a test email.")
        self.assertEqual(
            email_obj.content.html, "<p>Hello, this is a <b>test</b> email.</p>"
        )

        # Check summary
        summary = email_obj.summary()
        self.assertIn("From: John Doe <john@example.com>", summary)
        self.assertIn("Subject: Test Email", summary)


class TestEmailAddressValidation(unittest.TestCase):
    """Test cases for email address validation in EmailAddress.parse()."""

    def test_parse_valid_email(self) -> None:
        """Test that a valid plain email address is accepted."""
        addr = EmailAddress.parse("user@example.com")
        self.assertEqual(addr.address, "user@example.com")
        self.assertEqual(addr.name, "")

    def test_parse_valid_email_with_name(self) -> None:
        """Test that a valid email address with display name is accepted."""
        addr = EmailAddress.parse("John Doe <john@example.com>")
        self.assertEqual(addr.name, "John Doe")
        self.assertEqual(addr.address, "john@example.com")

    def test_parse_rejects_at_only(self) -> None:
        """Test that a bare '@' is rejected."""
        with self.assertRaises(ValueError):
            EmailAddress.parse("@")

    def test_parse_rejects_missing_domain(self) -> None:
        """Test that an address missing the domain is rejected."""
        with self.assertRaises(ValueError):
            EmailAddress.parse("foo@")

    def test_parse_rejects_missing_local(self) -> None:
        """Test that an address missing the local part is rejected."""
        with self.assertRaises(ValueError):
            EmailAddress.parse("@bar.com")

    def test_parse_rejects_no_at_sign(self) -> None:
        """Test that a string with no '@' sign is rejected."""
        with self.assertRaises(ValueError):
            EmailAddress.parse("notanemail")

    def test_from_message_handles_invalid_addresses_gracefully(self) -> None:
        """Test that Email.from_message() doesn't crash on invalid From address."""
        msg = MIMEText("Hello", "plain")
        msg["From"] = "not-a-valid-email"
        msg["To"] = "user@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"

        email_obj = Email.from_message(msg, uid=1, folder="INBOX")
        # Should not crash; the invalid address is preserved as-is
        self.assertEqual(email_obj.from_.address, "not-a-valid-email")


class TestAttachmentSizeLimits(unittest.TestCase):
    """Test attachment size limits (issue #17)."""

    def _make_email_part(self, payload: bytes, filename: str = "test.bin") -> MagicMock:
        """Create a mock email part with the given payload.

        Args:
            payload: Raw bytes payload for the attachment.
            filename: Filename for the attachment.

        Returns:
            A mock email Message part.
        """
        part = MagicMock(spec=Message)
        part.get_payload.return_value = payload
        part.get_filename.return_value = filename
        part.get_content_type.return_value = "application/octet-stream"
        part.get.side_effect = lambda key, default="": {
            "Content-ID": None,
            "Content-Disposition": "attachment",
            "Content-Type": "application/octet-stream",
        }.get(key, default)
        return part

    def test_attachment_from_part_skips_oversized_content(self) -> None:
        """Test that oversized attachments have content set to None."""
        oversized_payload = b"x" * (MAX_ATTACHMENT_SIZE + 1)
        part = self._make_email_part(oversized_payload, filename="huge.bin")

        attachment = EmailAttachment.from_part(part)

        self.assertIsNone(attachment.content)
        self.assertEqual(attachment.size, len(oversized_payload))
        self.assertEqual(attachment.filename, "huge.bin")
        self.assertEqual(attachment.content_type, "application/octet-stream")

    def test_attachment_from_part_keeps_normal_content(self) -> None:
        """Test that normal-sized attachments retain their content."""
        normal_payload = b"Hello, this is a small attachment."
        part = self._make_email_part(normal_payload, filename="small.txt")

        attachment = EmailAttachment.from_part(part)

        self.assertEqual(attachment.content, normal_payload)
        self.assertEqual(attachment.size, len(normal_payload))
        self.assertEqual(attachment.filename, "small.txt")
        self.assertEqual(attachment.content_type, "application/octet-stream")


class TestFromMessageAddressParsing(unittest.TestCase):
    """Test cases for address parsing in Email.from_message() (issue #37)."""

    def test_from_message_quoted_name_with_comma(self) -> None:
        """Test that a quoted display name with comma is parsed as one address."""
        msg = MIMEText("Hello", "plain")
        msg["From"] = "sender@example.com"
        msg["To"] = '"Doe, John" <john@example.com>'
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"

        email_obj = Email.from_message(msg, uid=1, folder="INBOX")

        self.assertEqual(len(email_obj.to), 1)
        self.assertEqual(email_obj.to[0].name, "Doe, John")
        self.assertEqual(email_obj.to[0].address, "john@example.com")

    def test_from_message_multiple_recipients_with_comma_in_name(self) -> None:
        """Test multiple recipients where one has a comma in the display name."""
        msg = MIMEText("Hello", "plain")
        msg["From"] = "sender@example.com"
        msg["To"] = '"Doe, John" <john@example.com>, Bob Smith <bob@example.com>'
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"

        email_obj = Email.from_message(msg, uid=1, folder="INBOX")

        self.assertEqual(len(email_obj.to), 2)
        self.assertEqual(email_obj.to[0].name, "Doe, John")
        self.assertEqual(email_obj.to[0].address, "john@example.com")
        self.assertEqual(email_obj.to[1].name, "Bob Smith")
        self.assertEqual(email_obj.to[1].address, "bob@example.com")

    def test_from_message_cc_with_comma_in_name(self) -> None:
        """Test that Cc header with comma in display name is parsed correctly."""
        msg = MIMEText("Hello", "plain")
        msg["From"] = "sender@example.com"
        msg["To"] = "recipient@example.com"
        msg["Cc"] = '"Doe, John" <john@example.com>, Bob Smith <bob@example.com>'
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"

        email_obj = Email.from_message(msg, uid=1, folder="INBOX")

        self.assertEqual(len(email_obj.cc), 2)
        self.assertEqual(email_obj.cc[0].name, "Doe, John")
        self.assertEqual(email_obj.cc[0].address, "john@example.com")
        self.assertEqual(email_obj.cc[1].name, "Bob Smith")
        self.assertEqual(email_obj.cc[1].address, "bob@example.com")

    def test_from_message_mixed_address_formats(self) -> None:
        """Test a mix of plain address, comma-in-name, and regular name formats."""
        msg = MIMEText("Hello", "plain")
        msg["From"] = "sender@example.com"
        msg["To"] = (
            'plain@example.com, "Name, With Comma" <name@example.com>, '
            "Regular Name <reg@example.com>"
        )
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"

        email_obj = Email.from_message(msg, uid=1, folder="INBOX")

        self.assertEqual(len(email_obj.to), 3)
        self.assertEqual(email_obj.to[0].address, "plain@example.com")
        self.assertEqual(email_obj.to[1].name, "Name, With Comma")
        self.assertEqual(email_obj.to[1].address, "name@example.com")
        self.assertEqual(email_obj.to[2].name, "Regular Name")
        self.assertEqual(email_obj.to[2].address, "reg@example.com")

    def test_from_message_empty_to(self) -> None:
        """Test that an empty or missing To header results in an empty list."""
        msg = MIMEText("Hello", "plain")
        msg["From"] = "sender@example.com"
        msg["Subject"] = "Test"
        msg["Message-ID"] = "<test@example.com>"

        email_obj = Email.from_message(msg, uid=1, folder="INBOX")

        self.assertEqual(email_obj.to, [])


if __name__ == "__main__":
    unittest.main()
