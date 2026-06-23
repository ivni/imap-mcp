"""MCP resources implementation for email access."""

import json
import logging
from typing import Any, Dict, List

import anyio
from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]
from mcp.server.fastmcp import Context, FastMCP

from imap_mcp.imap_client import ImapClient

logger = logging.getLogger(__name__)


def get_client_from_context(ctx: Context) -> ImapClient:
    """Get IMAP client from context.

    Args:
        ctx: MCP context

    Returns:
        IMAP client

    Raises:
        RuntimeError: If IMAP client is not available
    """
    client = ctx.request_context.lifespan_context.get("imap_client")
    if not client:
        raise RuntimeError("IMAP client not available")
    return client  # type: ignore[no-any-return]


def register_resources(mcp: FastMCP) -> None:
    """Register MCP resources.

    The connected IMAP client is retrieved per-request from the lifespan
    context via ``get_client_from_context``.

    Args:
        mcp: MCP server
    """

    @mcp.resource(
        "email://folders",
        title="Email Folders",
        description="List all available IMAP folders filtered by allowed_folders config",
    )
    async def get_folders() -> str:
        """List all available email folders on the IMAP server.

        Returns a JSON array of folder names the server can access, filtered
        by the allowed_folders configuration. Use these folder names as
        parameters for other email tools and resources.

        Returns:
            JSON-formatted list of folders
        """
        ctx: Context = mcp.get_context()  # type: ignore[assignment]
        client = get_client_from_context(ctx)
        folders = await anyio.to_thread.run_sync(client.list_folders)
        return json.dumps(folders, indent=2)

    @mcp.resource(
        "email://{folder}/list",
        title="List Emails in Folder",
        description="List the most recent emails in a folder (up to 50, newest first)",
    )
    async def list_emails(folder: str) -> str:
        """List the most recent emails in the specified IMAP folder.

        Returns up to 50 email summaries sorted by date (newest first). Each
        summary includes UID, folder, sender, recipients, subject, date, flags,
        and attachment indicator. Use the UID with other tools to act on emails.

        Args:
            folder: Folder name

        Returns:
            JSON-formatted list of email summaries
        """
        ctx: Context = mcp.get_context()  # type: ignore[assignment]
        client = get_client_from_context(ctx)

        def _do_list() -> str:
            # Search for all emails in the folder
            try:
                uids = client.search("ALL", folder=folder)

                # Limit to the 50 most recent emails to avoid overwhelming
                # the LLM with too much context
                uids = sorted(uids, reverse=True)[:50]

                # Fetch emails
                emails = client.fetch_emails(uids, folder=folder)

                # Create summaries
                summaries: List[Dict[str, Any]] = []
                for uid, email_obj in emails.items():
                    summaries.append(
                        {
                            "uid": uid,
                            "folder": folder,
                            "from": str(email_obj.from_),
                            "to": [str(to) for to in email_obj.to],
                            "subject": email_obj.subject,
                            "date": email_obj.date.isoformat()
                            if email_obj.date
                            else None,
                            "flags": email_obj.flags,
                            "has_attachments": len(email_obj.attachments) > 0,
                        }
                    )

                return json.dumps(summaries, indent=2)
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error listing emails: {e}")
                return f"Error: {e}"
            except Exception:
                logger.error("Unexpected error listing emails", exc_info=True)
                return "Error: an unexpected error occurred"

        return await anyio.to_thread.run_sync(_do_list)

    @mcp.resource(
        "email://search/{query}",
        title="Search Emails",
        description="Search for emails matching a query across all accessible folders",
    )
    async def search_emails(query: str) -> str:
        """Search for emails matching a query across all accessible IMAP folders.

        Supports predefined searches (all, unseen, seen, today, week, month) and
        free-text search. Returns up to 10 results per folder, sorted by date
        (newest first). For more control, use the search_emails tool instead.

        Args:
            query: Search query — predefined keyword or free-text search term

        Returns:
            JSON-formatted list of email summaries
        """
        ctx: Context = mcp.get_context()  # type: ignore[assignment]
        client = get_client_from_context(ctx)

        def _do_search() -> List[Dict[str, Any]]:
            # Get all folders
            folders = client.list_folders()
            results: List[Dict[str, Any]] = []

            for folder in folders:
                try:
                    # Customize the search criteria based on the query
                    if query.lower() in [
                        "all",
                        "unseen",
                        "seen",
                        "today",
                        "week",
                        "month",
                    ]:
                        # Predefined searches
                        uids = client.search(query, folder=folder)
                    else:
                        # Text search
                        uids = client.search(["TEXT", query], folder=folder)

                    # Limit results per folder
                    uids = sorted(uids, reverse=True)[:10]

                    if uids:
                        # Fetch emails
                        emails = client.fetch_emails(uids, folder=folder)

                        # Create summaries
                        for uid, email_obj in emails.items():
                            results.append(
                                {
                                    "uid": uid,
                                    "folder": folder,
                                    "from": str(email_obj.from_),
                                    "to": [str(to) for to in email_obj.to],
                                    "subject": email_obj.subject,
                                    "date": email_obj.date.isoformat()
                                    if email_obj.date
                                    else None,
                                    "flags": email_obj.flags,
                                    "has_attachments": len(email_obj.attachments) > 0,
                                }
                            )
                except (IMAPClientError, OSError, ValueError) as e:
                    logger.warning(f"Error searching folder {folder}: {e}")
                except Exception:
                    logger.warning(
                        "Unexpected error searching folder %s", folder, exc_info=True
                    )

            # Sort results by date (newest first)
            results.sort(key=lambda x: str(x.get("date") or "0"), reverse=True)
            return results

        results = await anyio.to_thread.run_sync(_do_search)
        return json.dumps(results, indent=2)

    @mcp.resource(
        "email://{folder}/{uid}",
        title="Get Email Content",
        description="Retrieve the full content of a specific email by folder and UID",
    )
    async def get_email(folder: str, uid: str) -> str:
        """Retrieve the full content of a specific email by folder and UID.

        Returns the complete email including headers (From, To, Cc, Date,
        Subject), flags, attachment list, and the message body (prefers plain
        text, falls back to HTML). Use UIDs from list or search results.

        Args:
            folder: Folder name
            uid: Email UID (positive integer)

        Returns:
            Email content in text format
        """
        ctx: Context = mcp.get_context()  # type: ignore[assignment]
        client = get_client_from_context(ctx)

        def _do_get_email() -> str:
            try:
                try:
                    uid_int = int(uid)
                except (ValueError, TypeError):
                    return f"Invalid UID '{uid}': must be a numeric value"

                if uid_int <= 0:
                    return f"Invalid UID '{uid}': must be a positive integer"

                # Fetch email
                email_obj = client.fetch_email(uid_int, folder=folder)

                if not email_obj:
                    return f"Email with UID {uid} not found in folder {folder}"

                # Format email as text
                parts = [
                    f"From: {email_obj.from_}",
                    f"To: {', '.join(str(to) for to in email_obj.to)}",
                ]

                if email_obj.cc:
                    parts.append(f"Cc: {', '.join(str(cc) for cc in email_obj.cc)}")

                if email_obj.date:
                    parts.append(f"Date: {email_obj.date.isoformat()}")

                parts.append(f"Subject: {email_obj.subject}")
                parts.append(f"Flags: {', '.join(email_obj.flags)}")

                if email_obj.attachments:
                    parts.append(f"Attachments: {len(email_obj.attachments)}")
                    for i, attachment in enumerate(email_obj.attachments, 1):
                        parts.append(
                            f"  {i}. {attachment.filename} ({attachment.content_type}, {attachment.size} bytes)"
                        )

                parts.append("")  # Empty line before content

                # Add email content
                content = email_obj.content.get_best_content()
                parts.append(content)

                return "\n".join(parts)
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error fetching email: {e}")
                return f"Error: {e}"
            except Exception:
                logger.error("Unexpected error fetching email", exc_info=True)
                return "Error: an unexpected error occurred"

        return await anyio.to_thread.run_sync(_do_get_email)
