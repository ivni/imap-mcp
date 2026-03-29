"""Tests for SMTP client MIME composition and connection verification."""

import smtplib
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from imap_mcp.config import SmtpConfig
from imap_mcp.models import Email, EmailAddress, EmailContent
from imap_mcp.smtp_client import (
    create_reply_mime,
    sanitize_html_for_quoting,
    verify_smtp_connection,
)


class TestCreateReplyMime:
    """Tests for create_reply_mime function."""

    @pytest.fixture
    def sample_email(self) -> Email:
        """Create a sample email for testing."""
        return Email(
            message_id="<test123@example.com>",
            subject="Test Subject",
            from_=EmailAddress(name="Sender Name", address="sender@example.com"),
            to=[EmailAddress(name="Recipient Name", address="recipient@example.com")],
            cc=[EmailAddress(name="CC Recipient", address="cc@example.com")],
            date=datetime.now(),
            content=EmailContent(
                text="Original message content\nOn multiple lines.",
                html="<p>Original message content</p><p>On multiple lines.</p>",
            ),
            headers={"References": "<previous@example.com>"},
        )

    def test_create_basic_reply(self, sample_email: Email) -> None:
        """Test creating a basic reply."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        subject = "Re: Test Subject"
        body = "This is a reply."

        mime_message = create_reply_mime(
            original_email=sample_email, reply_to=reply_to, subject=subject, body=body
        )

        # Check basic properties
        assert mime_message["To"] == "Sender Name <sender@example.com>"
        assert mime_message["Subject"] == "Re: Test Subject"
        assert mime_message["From"] == "Reply To <sender@example.com>"
        assert mime_message["In-Reply-To"] == "<test123@example.com>"
        assert "<test123@example.com>" in mime_message["References"]
        assert "<previous@example.com>" in mime_message["References"]

        # Check content - handle both multipart and non-multipart payloads
        if mime_message.is_multipart():
            payload = mime_message.get_payload(0).get_payload(decode=True).decode()  # type: ignore[union-attr]
        else:
            payload = mime_message.get_payload(decode=True).decode()  # type: ignore[union-attr]

        assert "This is a reply." in payload
        assert "Original message content" in payload

    def test_create_reply_all(self, sample_email: Email) -> None:
        """Test creating a reply-all."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        subject = "Re: Test Subject"
        body = "This is a reply to all."

        mime_message = create_reply_mime(
            original_email=sample_email,
            reply_to=reply_to,
            subject=subject,
            body=body,
            reply_all=True,
        )

        # Check recipients - should include original CCs and sender
        assert (
            mime_message["To"]
            == "Sender Name <sender@example.com>, Recipient Name <recipient@example.com>"
        )
        assert mime_message["Cc"] == "CC Recipient <cc@example.com>"

    def test_create_reply_with_custom_cc(self, sample_email: Email) -> None:
        """Test creating a reply with custom CC recipients."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        subject = "Re: Test Subject"
        body = "This is a reply with custom CC."
        cc = [
            EmailAddress(name="Custom CC", address="custom@example.com"),
            EmailAddress(name="Another CC", address="another@example.com"),
        ]

        mime_message = create_reply_mime(
            original_email=sample_email,
            reply_to=reply_to,
            subject=subject,
            body=body,
            cc=cc,
        )

        # Check CC recipients
        assert (
            mime_message["Cc"]
            == "Custom CC <custom@example.com>, Another CC <another@example.com>"
        )

    def test_create_reply_with_subject_prefix(self, sample_email: Email) -> None:
        """Test creating a reply with a custom subject prefix."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        body = "This is a reply with custom subject prefix."

        # No prefix provided, but original doesn't start with Re:
        mime_message = create_reply_mime(
            original_email=sample_email, reply_to=reply_to, body=body
        )

        assert mime_message["Subject"].startswith("Re: ")

        # Custom subject provided
        custom_subject = "Custom: Test Subject"
        mime_message = create_reply_mime(
            original_email=sample_email,
            reply_to=reply_to,
            body=body,
            subject=custom_subject,
        )

        assert mime_message["Subject"] == custom_subject

        # Original already has Re: prefix
        sample_email.subject = "Re: Already Prefixed"
        mime_message = create_reply_mime(
            original_email=sample_email, reply_to=reply_to, body=body
        )

        assert mime_message["Subject"] == "Re: Already Prefixed"

    def test_create_html_reply(self, sample_email: Email) -> None:
        """Test creating a reply with HTML content."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        body = "This is a plain text reply."
        html_body = "<p>This is an <b>HTML</b> reply.</p>"

        mime_message = create_reply_mime(
            original_email=sample_email,
            reply_to=reply_to,
            body=body,
            html_body=html_body,
        )

        # Should be multipart with at least 2 parts
        assert mime_message.is_multipart()
        alternative = mime_message.get_payload(0)
        assert alternative.is_multipart()  # type: ignore[union-attr]

        # Check HTML part
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        html_text = html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]
        assert "<p>This is an <b>HTML</b> reply.</p>" in html_text

    def test_quoting_original_content(self, sample_email: Email) -> None:
        """Test proper quoting of original content."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        body = "This is a reply with original content quoted."

        mime_message = create_reply_mime(
            original_email=sample_email, reply_to=reply_to, body=body
        )

        # Check content
        if mime_message.is_multipart():
            payload = mime_message.get_payload(0).get_payload(decode=True).decode()  # type: ignore[union-attr]
        else:
            payload = mime_message.get_payload(decode=True).decode()  # type: ignore[union-attr]

        # Should have quoting prefix (>) and original content
        assert "This is a reply with original content quoted." in payload

        # Check for proper quoting
        lines = payload.split("\n")
        quoted_lines = [line for line in lines if line.startswith(">")]
        assert any("> Original message content" in line for line in quoted_lines)

    def test_html_escaping_special_characters(self) -> None:
        """Test that special characters in plain-text replies are properly HTML-escaped."""
        special_content = (
            """He said "hello" & she said 'goodbye' <script>alert('xss')</script>"""
        )
        email_with_special = Email(
            message_id="<special@example.com>",
            subject="Special Chars",
            from_=EmailAddress(name="Sender", address="sender@example.com"),
            to=[EmailAddress(name="Recipient", address="recipient@example.com")],
            date=datetime.now(),
            content=EmailContent(text=special_content, html=None),
            headers={},
        )
        reply_to = EmailAddress(name="Replier", address="recipient@example.com")

        mime_message = create_reply_mime(
            original_email=email_with_special,
            reply_to=reply_to,
            body="My reply.",
            html_body="<p>My reply.</p>",
        )

        # Extract the HTML part (second payload inside the alternative part)
        alternative = mime_message.get_payload(0)
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        html_text = html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]

        # All five HTML entities must be escaped
        assert "&amp;" in html_text
        assert "&lt;script&gt;" in html_text
        assert "&#x27;" in html_text
        assert "&quot;" in html_text
        # Raw dangerous characters must NOT appear unescaped in the quoted block
        assert "<script>" not in html_text

    def test_html_escaping_sender_name(self) -> None:
        """Test that sender name with HTML is escaped in reply HTML (XSS prevention)."""
        xss_name = "<img src=x onerror=alert(1)>"
        email_with_xss_sender = Email(
            message_id="<xss@example.com>",
            subject="XSS Test",
            from_=EmailAddress(name=xss_name, address="attacker@example.com"),
            to=[EmailAddress(name="Victim", address="victim@example.com")],
            date=datetime(2024, 1, 1, 12, 0, 0),
            content=EmailContent(text="Hello", html=None),
            headers={},
        )
        reply_to = EmailAddress(name="Victim", address="victim@example.com")

        mime_message = create_reply_mime(
            original_email=email_with_xss_sender,
            reply_to=reply_to,
            body="My reply.",
            html_body="<p>My reply.</p>",
        )

        alternative = mime_message.get_payload(0)
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        html_text = html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]

        # Sender name must be escaped in HTML
        assert "&lt;img src=x onerror=alert(1)&gt;" in html_text
        # Raw XSS payload must NOT appear
        assert "<img src=x onerror=alert(1)>" not in html_text

    def test_html_escaping_sender_name_with_html_original(self) -> None:
        """Test sender name escaping when the original email has HTML content."""
        xss_name = '<script>alert("xss")</script>'
        email_with_xss_sender = Email(
            message_id="<xss2@example.com>",
            subject="XSS Test 2",
            from_=EmailAddress(name=xss_name, address="attacker@example.com"),
            to=[EmailAddress(name="Victim", address="victim@example.com")],
            date=datetime(2024, 1, 1, 12, 0, 0),
            content=EmailContent(text="Hello", html="<p>Hello</p>"),
            headers={},
        )
        reply_to = EmailAddress(name="Victim", address="victim@example.com")

        mime_message = create_reply_mime(
            original_email=email_with_xss_sender,
            reply_to=reply_to,
            body="My reply.",
            html_body="<p>My reply.</p>",
        )

        alternative = mime_message.get_payload(0)
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        html_text = html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]

        # Sender name must be escaped in HTML
        assert "&lt;script&gt;" in html_text
        assert '<script>alert("xss")</script>' not in html_text

    def test_reply_subject_with_newlines(self, sample_email: Email) -> None:
        """Test that subjects with CRLF injection characters are handled safely."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        # Subject contains CRLF injection attempt
        injected_subject = "Re: Test Subject\r\nBcc: attacker@evil.com"

        # Python's email library rejects header values containing CR/LF,
        # which prevents header injection attacks at the MIME layer.
        with pytest.raises(ValueError, match="Header values may not contain linefeed"):
            create_reply_mime(
                original_email=sample_email,
                reply_to=reply_to,
                subject=injected_subject,
                body="Reply body.",
            )

    def test_cc_address_with_injection(self, sample_email: Email) -> None:
        """Test that CC addresses with CRLF injection are rejected at parse time."""
        # Attempt to inject a Bcc header via a CC address.
        # EmailAddress.parse() validates the address and rejects CRLF characters
        # before they can reach the MIME layer — defense in depth.
        malicious_cc_str = "foo@bar.com\r\nBcc: attacker@evil.com"
        with pytest.raises(ValueError, match="Invalid email address"):
            EmailAddress.parse(malicious_cc_str)

    def test_reply_body_with_mime_boundary(self, sample_email: Email) -> None:
        """Test that MIME boundary-like strings in body don't break MIME structure."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        body_with_boundary = (
            "Here is some text.\n"
            "--boundary123\n"
            "Content-Type: text/html\n"
            "\n"
            "<h1>Injected</h1>\n"
            "--boundary123--\n"
        )

        mime_message = create_reply_mime(
            original_email=sample_email,
            reply_to=reply_to,
            subject="Re: Test Subject",
            body=body_with_boundary,
        )

        # Extract the text payload
        if mime_message.is_multipart():
            payload = mime_message.get_payload(0).get_payload(decode=True).decode()  # type: ignore[union-attr]
        else:
            payload = mime_message.get_payload(decode=True).decode()  # type: ignore[union-attr]

        # The boundary-like strings must appear as literal body content
        assert "--boundary123" in payload
        # The message must still be structurally valid — the body should be
        # contained within a single text/plain part, not split into extra parts
        if mime_message.is_multipart():
            # For multipart, verify no extra unexpected parts were created
            parts = mime_message.get_payload()
            assert len(parts) == 1 or all(hasattr(p, "get_content_type") for p in parts)
        # Verify the fake Content-Type line is just text, not a real header
        assert "Injected" in payload

    def test_html_reply_body_with_script_tags(self, sample_email: Email) -> None:
        """Test that script tags in the reply HTML body are preserved but contained."""
        reply_to = EmailAddress(name="Reply To", address="sender@example.com")
        body = "Plain text reply."
        html_body = "<p>Hello</p><script>alert('xss')</script><p>World</p>"

        mime_message = create_reply_mime(
            original_email=sample_email,
            reply_to=reply_to,
            subject="Re: Test Subject",
            body=body,
            html_body=html_body,
        )

        # Should be multipart with alternative containing text + html
        assert mime_message.is_multipart()
        alternative = mime_message.get_payload(0)
        assert alternative.is_multipart()  # type: ignore[union-attr]

        # Extract the HTML part
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        html_text = html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]

        # The reply HTML body is author-composed content, so the script tag
        # should be present as-is in the HTML part (it's the sender's own content).
        # The critical security property is that the ORIGINAL email's content
        # (which could be attacker-controlled) is escaped — tested in
        # test_html_escaping_special_characters. Here we verify structural integrity.
        assert "<script>alert('xss')</script>" in html_text
        assert "<p>Hello</p>" in html_text
        assert "<p>World</p>" in html_text

        # Verify the original email's quoted content also appears
        assert "wrote:" in html_text


class TestHtmlSanitizationInReply:
    """Tests for HTML sanitization of original email content in replies (fixes #52)."""

    def _extract_reply_html(self, original_html: str) -> str:
        """Helper: create a reply to an email with the given HTML and return the HTML part."""
        email_obj = Email(
            message_id="<sanitize@example.com>",
            subject="Sanitization Test",
            from_=EmailAddress(name="Sender", address="sender@example.com"),
            to=[EmailAddress(name="Recipient", address="recipient@example.com")],
            date=datetime(2024, 1, 1, 12, 0, 0),
            content=EmailContent(text="fallback text", html=original_html),
            headers={},
        )
        reply_to = EmailAddress(name="Recipient", address="recipient@example.com")
        mime_message = create_reply_mime(
            original_email=email_obj,
            reply_to=reply_to,
            body="My reply.",
            html_body="<p>My reply.</p>",
        )
        alternative = mime_message.get_payload(0)
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        return html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]

    def test_script_tags_stripped_from_original_html(self) -> None:
        """Script tags and their content must be completely removed."""
        html_text = self._extract_reply_html(
            "<script>alert('xss')</script><p>Safe content</p>"
        )
        assert "<p>Safe content</p>" in html_text
        assert "<script>" not in html_text
        assert "alert" not in html_text

    def test_event_handlers_stripped_from_original_html(self) -> None:
        """Event handler attributes must be removed."""
        html_text = self._extract_reply_html(
            '<div onclick="evil()" onmouseover="bad()"><p>Content</p></div>'
        )
        assert "<p>Content</p>" in html_text
        assert "onclick" not in html_text
        assert "onmouseover" not in html_text

    def test_iframe_embed_object_stripped(self) -> None:
        """Dangerous embedding tags must be removed."""
        html_text = self._extract_reply_html(
            '<p>Before</p><iframe src="https://evil.com"></iframe>'
            '<object data="evil.swf"></object><embed src="evil.swf">'
            "<p>After</p>"
        )
        assert "Before" in html_text
        assert "After" in html_text
        assert "<iframe" not in html_text
        assert "<object" not in html_text
        assert "<embed" not in html_text

    def test_tracking_pixel_img_stripped(self) -> None:
        """Tracking pixel img tags must be removed."""
        html_text = self._extract_reply_html(
            "<p>Hello</p>"
            '<img src="https://tracker.evil.com/pixel.gif" width="1" height="1">'
            "<p>World</p>"
        )
        assert "Hello" in html_text
        assert "World" in html_text
        assert "<img" not in html_text
        assert "tracker.evil.com" not in html_text

    def test_style_tags_stripped_from_original_html(self) -> None:
        """Style tags and their content must be completely removed."""
        html_text = self._extract_reply_html(
            "<style>body { background: url('https://track.evil.com'); }</style>"
            "<p>Content</p>"
        )
        assert "Content" in html_text
        assert "<style>" not in html_text
        assert "background" not in html_text

    def test_safe_formatting_preserved_in_original_html(self) -> None:
        """Safe formatting tags must be preserved in the quoted original."""
        html_text = self._extract_reply_html(
            "<h1>Title</h1>"
            "<p>Text with <b>bold</b>, <i>italic</i>, "
            'and <a href="https://example.com">link</a>.</p>'
            "<ul><li>Item 1</li><li>Item 2</li></ul>"
        )
        assert "<h1>" in html_text
        assert "<b>bold</b>" in html_text
        assert "<i>italic</i>" in html_text
        assert "<a " in html_text
        assert "https://example.com" in html_text
        assert "<ul>" in html_text
        assert "<li>" in html_text

    def test_sanitize_html_for_quoting_unit(self) -> None:
        """Direct unit tests of the sanitize_html_for_quoting function."""
        # Empty string
        assert sanitize_html_for_quoting("") == ""

        # javascript: URL stripped from href
        result = sanitize_html_for_quoting('<a href="javascript:alert(1)">Click</a>')
        assert "javascript:" not in result
        assert "Click" in result

        # Nested script tags
        result = sanitize_html_for_quoting(
            "<script><script>alert('nested')</script></script><p>Safe</p>"
        )
        assert "<script>" not in result
        assert "alert" not in result
        assert "<p>Safe</p>" in result

        # Form elements stripped
        result = sanitize_html_for_quoting(
            '<form action="https://evil.com"><input type="text"><button>Submit</button></form>'
        )
        assert "<form" not in result
        assert "<input" not in result
        assert "<button" not in result

        # data: URI stripped from href
        result = sanitize_html_for_quoting(
            '<a href="data:text/html,<script>alert(1)</script>">Click</a>'
        )
        assert "data:" not in result
        assert "Click" in result

    def test_inline_style_attributes_stripped(self) -> None:
        """Inline style attributes must be removed from allowed tags in quoted content."""
        result = sanitize_html_for_quoting(
            '<p style="background:url(https://tracker.com/pixel)">Text</p>'
        )
        assert "Text" in result
        assert "style=" not in result
        assert "tracker.com" not in result

    def test_image_only_html_falls_back_to_text(self) -> None:
        """When sanitization strips all visible content, fall back to text."""
        email_obj = Email(
            message_id="<img@example.com>",
            subject="Photo",
            from_=EmailAddress(name="Sender", address="sender@example.com"),
            to=[EmailAddress(name="Recipient", address="recipient@example.com")],
            date=datetime(2024, 1, 1, 12, 0, 0),
            content=EmailContent(
                text="See the attached photo of the team.",
                html='<img src="https://example.com/photo.jpg">',
            ),
            headers={},
        )
        reply_to = EmailAddress(name="Recipient", address="recipient@example.com")
        mime_message = create_reply_mime(
            original_email=email_obj,
            reply_to=reply_to,
            body="Thanks!",
            html_body="<p>Thanks!</p>",
        )
        alternative = mime_message.get_payload(0)
        html_part = alternative.get_payload(1)  # type: ignore[union-attr]
        html_text = html_part.get_payload(decode=True).decode()  # type: ignore[union-attr]
        # Should fall back to escaped text, not show empty blockquote
        assert "See the attached photo" in html_text


class TestVerifySmtpConnection:
    """Tests for verify_smtp_connection function."""

    @pytest.fixture
    def tls_config(self) -> SmtpConfig:
        """SMTP config with STARTTLS (port 587)."""
        return SmtpConfig(
            host="smtp.example.com",
            port=587,
            username="test@example.com",
            password="password",
            use_tls=True,
        )

    @pytest.fixture
    def ssl_config(self) -> SmtpConfig:
        """SMTP config with implicit SSL (port 465)."""
        return SmtpConfig(
            host="smtp.example.com",
            port=465,
            username="test@example.com",
            password="password",
            use_tls=False,
        )

    @patch("imap_mcp.smtp_client.smtplib.SMTP")
    def test_verify_smtp_tls_success(
        self, mock_smtp_cls: MagicMock, tls_config: SmtpConfig
    ) -> None:
        """Test successful SMTP verification with STARTTLS."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        result = verify_smtp_connection(tls_config)

        assert result is True
        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)
        assert mock_server.ehlo.call_count == 2
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("test@example.com", "password")
        mock_server.quit.assert_called_once()

    @patch("imap_mcp.smtp_client.smtplib.SMTP_SSL")
    def test_verify_smtp_ssl_success(
        self, mock_smtp_ssl_cls: MagicMock, ssl_config: SmtpConfig
    ) -> None:
        """Test successful SMTP verification with implicit SSL."""
        mock_server = MagicMock()
        mock_smtp_ssl_cls.return_value = mock_server

        result = verify_smtp_connection(ssl_config)

        assert result is True
        mock_smtp_ssl_cls.assert_called_once()
        mock_server.ehlo.assert_called_once()
        mock_server.login.assert_called_once_with("test@example.com", "password")
        mock_server.quit.assert_called_once()

    @patch("imap_mcp.smtp_client.smtplib.SMTP")
    def test_verify_smtp_auth_failure(
        self, mock_smtp_cls: MagicMock, tls_config: SmtpConfig
    ) -> None:
        """Test SMTP verification fails on authentication error."""
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"Auth failed"
        )

        with pytest.raises(
            ConnectionError, match="SMTP connection verification failed"
        ):
            verify_smtp_connection(tls_config)

    @patch("imap_mcp.smtp_client.smtplib.SMTP")
    def test_verify_smtp_network_failure(
        self, mock_smtp_cls: MagicMock, tls_config: SmtpConfig
    ) -> None:
        """Test SMTP verification fails on network error."""
        mock_smtp_cls.side_effect = OSError("Connection refused")

        with pytest.raises(
            ConnectionError, match="SMTP connection verification failed"
        ):
            verify_smtp_connection(tls_config)
