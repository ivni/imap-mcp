"""MCP tools implementation for email operations."""

import json
import logging
import os
from enum import Enum
from typing import Any, Dict, List, Optional

from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]
from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from imap_mcp.imap_client import ImapClient
from imap_mcp.models import EmailAddress
from imap_mcp.resources import get_client_from_context

logger = logging.getLogger(__name__)


def _validate_tool_folder(client: ImapClient, folder: str) -> str | None:
    """Validate folder name and access for tool handlers.

    Returns error message string if validation fails, None if valid.
    """
    try:
        client._validate_folder_name(folder)
    except ValueError as e:
        return f"Invalid folder name: {e}"
    if not client._is_folder_allowed(folder):
        return f"Folder '{folder}' is not in the allowed folders list"
    return None


class ConfirmationResult(Enum):
    """Result of a confirmation elicitation request."""

    CONFIRMED = "confirmed"
    DECLINED = "declined"
    ERROR = "error"


class ConfirmAction(BaseModel):
    """Schema for destructive action confirmation elicitation.

    Only primitive types allowed per MCP elicitation spec.
    """

    confirmed: bool = Field(
        description="Set to true to confirm the action, false to cancel"
    )


async def require_confirmation(
    ctx: Context,
    action: str,
    folder: str,
    uid: int,
    *,
    target_folder: str | None = None,
) -> ConfirmationResult:
    """Request user confirmation before a destructive action.

    Uses MCP elicitation to present a confirmation dialog to the user.
    Does NOT include email content, subject, or sender in the message
    to prevent information leakage and prompt injection exploitation.

    Args:
        ctx: MCP context for elicitation
        action: Description of the action (e.g., "delete", "move")
        folder: Email folder name
        uid: Email UID
        target_folder: Target folder for move operations

    Returns:
        ConfirmationResult.CONFIRMED if the user confirmed,
        ConfirmationResult.DECLINED if the user declined/cancelled,
        ConfirmationResult.ERROR if elicitation failed due to a system error.
    """
    if os.environ.get("IMAP_MCP_SKIP_CONFIRMATION", "").lower() == "true":
        logger.warning(
            "Confirmation skipped for %s (IMAP_MCP_SKIP_CONFIRMATION=true)",
            action,
        )
        return ConfirmationResult.CONFIRMED

    message = f"Confirm {action}: email UID {uid} in folder '{folder}'"
    if target_folder:
        message += f" -> '{target_folder}'"
    message += "\n\nDo you want to proceed?"

    try:
        result = await ctx.elicit(
            message=message,
            schema=ConfirmAction,
        )
    except (TypeError, ValueError) as e:
        logger.error(
            "Elicitation schema/validation error for %s: %s",
            action,
            e,
            exc_info=True,
        )
        return ConfirmationResult.ERROR
    except (ConnectionError, TimeoutError, OSError) as e:
        logger.error(
            "Elicitation network error for %s: %s",
            action,
            e,
            exc_info=True,
        )
        return ConfirmationResult.ERROR
    except Exception:
        logger.error(
            "Elicitation failed for %s, aborting for safety",
            action,
            exc_info=True,
        )
        return ConfirmationResult.ERROR

    if result.action == "accept" and result.data is not None:
        if result.data.confirmed:
            return ConfirmationResult.CONFIRMED
        return ConfirmationResult.DECLINED

    logger.info("User %s %s for UID %d in '%s'", result.action, action, uid, folder)
    return ConfirmationResult.DECLINED


def register_tools(mcp: FastMCP, imap_client: ImapClient) -> None:
    """Register MCP tools.

    Args:
        mcp: MCP server
        imap_client: IMAP client
    """

    # Using decorator pattern to register tools
    @mcp.tool(
        title="Generate Meeting Reply",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    async def draft_meeting_reply_tool(
        invite_details: Dict[str, Any],
        availability_status: bool,
        ctx: Context,
    ) -> Dict[str, str]:
        """Generate meeting reply text (accept or decline) without saving to the server.

        Returns reply text and metadata but does NOT save a draft or send anything.
        Use process_meeting_invite to save the reply as a draft.

        Args:
            invite_details: Dictionary containing invite details (subject, start_time, end_time, organizer, location)
            availability_status: Whether the user is available for the meeting (True=available/accept, False=unavailable/decline)
            ctx: MCP context

        Returns:
            Dictionary with reply text and additional metadata
        """
        from imap_mcp.workflows.meeting_reply import generate_meeting_reply_content

        availability = {"available": availability_status}
        return generate_meeting_reply_content(invite_details, availability)

    @mcp.tool(
        title="Identify Meeting Invite",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
    )
    async def identify_meeting_invite_tool(
        folder: str, uid: int, ctx: Context
    ) -> Dict[str, Any]:
        """Analyze an email to determine if it contains a meeting/calendar invite.

        Fetches the email and inspects content for iCalendar data. If found,
        extracts subject, organizer, start/end times, and location. Does not
        modify any server state.

        Args:
            folder: Email folder name
            uid: Email UID
            ctx: MCP context

        Returns:
            Dictionary with invite details if it's a meeting invite, or status information if not
        """
        from imap_mcp.workflows.invite_parser import identify_meeting_invite_details

        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return {"is_invite": False, "details": {}, "error": error}
        email_obj = client.fetch_email(uid, folder)
        if not email_obj:
            return {
                "is_invite": False,
                "details": {},
                "error": f"Email UID {uid} not found",
            }
        return identify_meeting_invite_details(email_obj)

    @mcp.tool(
        title="Check Calendar Availability",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    async def check_calendar_availability_tool(
        start_time: str, end_time: str, ctx: Context
    ) -> Dict[str, Any]:
        """Check calendar availability for a proposed meeting time slot.

        Returns availability status for the specified time range. Currently uses
        a mock calendar implementation. Times must be ISO 8601 format.

        Args:
            start_time: Meeting start time (ISO 8601 format, e.g. "2024-01-15T10:00:00Z")
            end_time: Meeting end time (ISO 8601 format)
            ctx: MCP context

        Returns:
            Dictionary with availability status and additional information
        """
        from imap_mcp.workflows.calendar_mock import check_mock_availability

        return check_mock_availability(start_time, end_time)

    @mcp.tool(
        title="Save Draft Reply",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )
    async def draft_reply_tool(
        folder: str,
        uid: int,
        reply_body: str,
        ctx: Context,
        reply_all: bool = False,
        cc: Optional[List[str]] = None,
        body_html: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compose a reply to an email and save it as a draft on the IMAP server.

        Creates a MIME reply with proper threading headers (In-Reply-To, References).
        Supports plain text, optional HTML, reply-all with CC. Requires user
        confirmation. Additive — creates a new draft without modifying the original.

        Args:
            folder: Email folder name
            uid: Email UID
            reply_body: Reply text content
            ctx: MCP context
            reply_all: Whether to reply to all recipients
            cc: Optional CC recipients
            body_html: Optional HTML version of the reply

        Returns:
            Dictionary with status and the UID of the created draft
        """
        confirmation = await require_confirmation(ctx, "save draft reply", folder, uid)
        if confirmation != ConfirmationResult.CONFIRMED:
            if confirmation == ConfirmationResult.ERROR:
                return {
                    "status": "error",
                    "message": "Confirmation system error for save draft reply",
                }
            return {
                "status": "cancelled",
                "message": "Draft reply not confirmed by user",
            }

        from imap_mcp.smtp_client import create_reply_mime

        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return {"status": "error", "message": error}
        email_obj = client.fetch_email(uid, folder)
        if not email_obj:
            return {
                "status": "error",
                "message": f"Email UID {uid} not found in {folder}",
            }

        # Determine sender for the reply
        reply_from = EmailAddress(name="", address=client.config.username)

        # Parse CC addresses
        if cc:
            try:
                cc_addresses = [EmailAddress.parse(addr) for addr in cc]
            except ValueError as e:
                return {"status": "error", "message": f"Invalid CC address: {e}"}
        else:
            cc_addresses = None

        # Create the reply MIME message
        mime_message = create_reply_mime(
            original_email=email_obj,
            reply_to=reply_from,
            body=reply_body,
            cc=cc_addresses,
            reply_all=reply_all,
            html_body=body_html,
        )

        # Save as draft
        draft_uid = client.save_draft_mime(mime_message)
        if draft_uid:
            return {"status": "success", "draft_uid": draft_uid}
        return {"status": "error", "message": "Failed to save draft"}

    @mcp.tool(
        title="Move Email",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )
    async def move_email(
        folder: str,
        uid: int,
        target_folder: str,
        ctx: Context,
    ) -> str:
        """Move an email from one IMAP folder to another.

        Copies to the target folder and deletes from the source. Destructive —
        the email no longer exists in the original folder. Requires user
        confirmation. Both folders must be in the allowed folders list.

        Args:
            folder: Source folder
            uid: Email UID
            target_folder: Target folder
            ctx: MCP context

        Returns:
            Success message or error message
        """
        confirmation = await require_confirmation(
            ctx, "move", folder, uid, target_folder=target_folder
        )
        if confirmation != ConfirmationResult.CONFIRMED:
            if confirmation == ConfirmationResult.ERROR:
                return "Action aborted: confirmation system error for move"
            return "Action cancelled: move not confirmed by user"

        client = get_client_from_context(ctx)

        try:
            success = client.move_email(uid, folder, target_folder)
            if success:
                return f"Email moved from {folder} to {target_folder}"
            else:
                return "Failed to move email"
        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error moving email: {e}")
            return f"Error: {e}"
        except Exception:
            logger.error("Unexpected error moving email", exc_info=True)
            return "Error: an unexpected error occurred"

    @mcp.tool(
        title="Mark as Read",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    )
    async def mark_as_read(
        folder: str,
        uid: int,
        ctx: Context,
    ) -> str:
        r"""Mark an email as read by setting the IMAP \Seen flag.

        Idempotent — marking an already-read email has no additional effect.

        Args:
            folder: Folder name
            uid: Email UID
            ctx: MCP context

        Returns:
            Success message or error message
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        try:
            success = client.mark_email(uid, folder, r"\Seen", True)
            if success:
                return "Email marked as read"
            else:
                return "Failed to mark email as read"
        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error marking email as read: {e}")
            return f"Error: {e}"
        except Exception:
            logger.error("Unexpected error marking email as read", exc_info=True)
            return "Error: an unexpected error occurred"

    @mcp.tool(
        title="Mark as Unread",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    )
    async def mark_as_unread(
        folder: str,
        uid: int,
        ctx: Context,
    ) -> str:
        r"""Mark an email as unread by removing the IMAP \Seen flag.

        Idempotent — marking an already-unread email has no additional effect.

        Args:
            folder: Folder name
            uid: Email UID
            ctx: MCP context

        Returns:
            Success message or error message
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        try:
            success = client.mark_email(uid, folder, r"\Seen", False)
            if success:
                return "Email marked as unread"
            else:
                return "Failed to mark email as unread"
        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error marking email as unread: {e}")
            return f"Error: {e}"
        except Exception:
            logger.error("Unexpected error marking email as unread", exc_info=True)
            return "Error: an unexpected error occurred"

    @mcp.tool(
        title="Flag/Unflag Email",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        ),
    )
    async def flag_email(
        folder: str,
        uid: int,
        ctx: Context,
        flag: bool = True,
    ) -> str:
        r"""Set or remove the IMAP \Flagged flag (star/important marker).

        Pass flag=True to star, flag=False to unstar. Idempotent.

        Args:
            folder: Folder name
            uid: Email UID
            flag: True to flag (star), False to unflag (unstar)
            ctx: MCP context

        Returns:
            Success message or error message
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        try:
            success = client.mark_email(uid, folder, r"\Flagged", flag)
            if success:
                return f"Email {'flagged' if flag else 'unflagged'}"
            else:
                return f"Failed to {'flag' if flag else 'unflag'} email"
        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error flagging email: {e}")
            return f"Error: {e}"
        except Exception:
            logger.error("Unexpected error flagging email", exc_info=True)
            return "Error: an unexpected error occurred"

    @mcp.tool(
        title="Delete Email",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )
    async def delete_email(
        folder: str,
        uid: int,
        ctx: Context,
    ) -> str:
        r"""Permanently delete an email from the IMAP server.

        Sets \Deleted flag and expunges. Irreversible. Requires user
        confirmation. For soft delete, use move_email to move to Trash instead.

        Args:
            folder: Folder name
            uid: Email UID
            ctx: MCP context

        Returns:
            Success message or error message
        """
        confirmation = await require_confirmation(ctx, "delete", folder, uid)
        if confirmation != ConfirmationResult.CONFIRMED:
            if confirmation == ConfirmationResult.ERROR:
                return "Action aborted: confirmation system error for delete"
            return "Action cancelled: delete not confirmed by user"

        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        try:
            success = client.delete_email(uid, folder)
            if success:
                return "Email deleted"
            else:
                return "Failed to delete email"
        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error deleting email: {e}")
            return f"Error: {e}"
        except Exception:
            logger.error("Unexpected error deleting email", exc_info=True)
            return "Error: an unexpected error occurred"

    @mcp.tool(
        title="Search Emails",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
    )
    async def search_emails(
        query: str,
        ctx: Context,
        folder: Optional[str] = None,
        criteria: str = "text",
        limit: int = 10,
        offset: int = 0,
    ) -> str:
        """Search for emails across one or more IMAP folders.

        Supports text search, sender/recipient/subject filtering, and status
        filters (seen/unseen/today/week/month). Returns paginated results sorted
        by date (newest first) with UID, folder, sender, subject, date, flags,
        and attachment indicator.

        Args:
            query: Search query
            folder: Folder to search in (None for all allowed folders)
            criteria: Search criteria — "text" (full-text), "from", "to",
                "subject", "all" (list all), "unseen", "seen", "today", "week", "month"
            limit: Maximum number of results (default 10)
            offset: Number of results to skip for pagination (default 0)
            ctx: MCP context

        Returns:
            JSON-formatted search results with pagination metadata
        """
        client = get_client_from_context(ctx)
        if folder is not None:
            error = _validate_tool_folder(client, folder)
            if error:
                return error

        empty_response = {"total": 0, "offset": offset, "limit": limit, "results": []}
        if offset < 0:
            return json.dumps(
                {**empty_response, "error": "offset must be >= 0"}, indent=2
            )
        if limit <= 0:
            return json.dumps(
                {**empty_response, "error": "limit must be > 0"}, indent=2
            )

        # Define search criteria
        search_criteria_map = {
            "text": ["TEXT", query],
            "from": ["FROM", query],
            "to": ["TO", query],
            "subject": ["SUBJECT", query],
            "all": "ALL",
            "unseen": "UNSEEN",
            "seen": "SEEN",
            "today": "today",
            "week": "week",
            "month": "month",
        }

        if criteria.lower() not in search_criteria_map:
            return f"Invalid search criteria: {criteria}"

        search_criteria = search_criteria_map[criteria.lower()]

        folders_to_search = [folder] if folder else client.list_folders()
        results = []
        total_count = 0

        for current_folder in folders_to_search:
            try:
                # Search for emails
                uids = client.search(search_criteria, folder=current_folder)
                total_count += len(uids)

                # Limit results and sort by newest first
                uids = sorted(uids, reverse=True)[: offset + limit]

                if uids:
                    # Fetch emails
                    emails = client.fetch_emails(uids, folder=current_folder)

                    # Create summaries
                    for uid, email_obj in emails.items():
                        results.append(
                            {
                                "uid": uid,
                                "folder": current_folder,
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
                logger.warning(f"Error searching folder {current_folder}: {e}")
            except Exception:
                logger.warning(
                    "Unexpected error searching folder %s",
                    current_folder,
                    exc_info=True,
                )

        # Sort results by date (newest first)
        results.sort(key=lambda x: str(x.get("date") or "0"), reverse=True)

        # Apply pagination
        results = results[offset : offset + limit]

        return json.dumps(
            {
                "total": total_count,
                "offset": offset,
                "limit": limit,
                "results": results,
            },
            indent=2,
        )

    @mcp.tool(
        title="Process Email Action",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )
    async def process_email(
        folder: str,
        uid: int,
        action: str,
        ctx: Context,
        notes: Optional[str] = None,
        target_folder: Optional[str] = None,
    ) -> str:
        """Perform an action on an email: read, unread, flag, unflag, move, or delete.

        Higher-level tool combining multiple operations. Destructive actions
        (move, delete) require user confirmation; others execute immediately.
        Optional notes parameter records the reason for the action.

        Args:
            folder: Folder name
            uid: Email UID
            action: Action to take — "read", "unread", "flag", "unflag", "move", "delete"
            notes: Optional notes about the decision
            target_folder: Target folder (required for "move" action)
            ctx: MCP context

        Returns:
            Success message or error message
        """
        # Require confirmation for destructive actions
        destructive_actions = {"delete", "move"}
        if action.lower() in destructive_actions:
            confirmation = await require_confirmation(
                ctx,
                action.lower(),
                folder,
                uid,
                target_folder=target_folder if action.lower() == "move" else None,
            )
            if confirmation != ConfirmationResult.CONFIRMED:
                if confirmation == ConfirmationResult.ERROR:
                    return f"Action aborted: confirmation system error for {action}"
                return f"Action cancelled: {action} not confirmed by user"

        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error
        if target_folder:
            error = _validate_tool_folder(client, target_folder)
            if error:
                return error

        # Fetch the email first to have context for learning
        email_obj = client.fetch_email(uid, folder)
        if not email_obj:
            return f"Email with UID {uid} not found in folder {folder}"

        # Process the action
        result = ""
        try:
            if action.lower() == "move":
                if not target_folder:
                    return "Target folder must be specified for move action"
                success = client.move_email(uid, folder, target_folder)
                if success:
                    result = f"Email moved from {folder} to {target_folder}"
                else:
                    result = f"Failed to move email from {folder} to {target_folder}"
            elif action.lower() == "read":
                success = client.mark_email(uid, folder, r"\Seen", True)
                if success:
                    result = "Email marked as read"
                else:
                    result = "Failed to mark email as read"
            elif action.lower() == "unread":
                success = client.mark_email(uid, folder, r"\Seen", False)
                if success:
                    result = "Email marked as unread"
                else:
                    result = "Failed to mark email as unread"
            elif action.lower() == "flag":
                success = client.mark_email(uid, folder, r"\Flagged", True)
                if success:
                    result = "Email flagged"
                else:
                    result = "Failed to flag email"
            elif action.lower() == "unflag":
                success = client.mark_email(uid, folder, r"\Flagged", False)
                if success:
                    result = "Email unflagged"
                else:
                    result = "Failed to unflag email"
            elif action.lower() == "delete":
                success = client.delete_email(uid, folder)
                if success:
                    result = "Email deleted"
                else:
                    result = "Failed to delete email"
            else:
                return f"Invalid action: {action}"

            # TODO: Record the action for learning in a separate module

            return result
        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error processing email: {e}")
            return f"Error: {e}"
        except Exception:
            logger.error("Unexpected error processing email", exc_info=True)
            return "Error: an unexpected error occurred"

    @mcp.tool(
        title="Process Meeting Invite",
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        ),
    )
    async def process_meeting_invite(
        folder: str,
        uid: int,
        ctx: Context,
        availability_mode: str = "random",
    ) -> dict:
        """Analyze a meeting invite, check availability, and save a draft reply.

        Full workflow: identify invite, check calendar, generate reply, save draft.
        Requires user confirmation. Additive — creates a new draft without
        modifying the original email.

        Steps:
        1. Fetches the email and identifies meeting invite details
        2. Checks calendar availability for the proposed time
        3. Generates an accept or decline reply based on availability
        4. Creates a MIME reply message with proper threading headers
        5. Saves the reply as a draft on the IMAP server

        Args:
            folder: Folder containing the invite email
            uid: UID of the invite email
            ctx: MCP context
            availability_mode: Mode for availability check — "random",
                "always_available", "always_busy", "business_hours", "weekdays"

        Returns:
            Dictionary with the processing result:
              - status: "success", "not_invite", "cancelled", or "error"
              - message: Description of the result
              - draft_uid: UID of the saved draft (if successful)
              - draft_folder: Folder where the draft was saved (if successful)
              - availability: Whether the time slot was available
        """
        confirmation = await require_confirmation(
            ctx, "process meeting invite and save draft", folder, uid
        )
        if confirmation != ConfirmationResult.CONFIRMED:
            if confirmation == ConfirmationResult.ERROR:
                status = "error"
                msg = "Confirmation system error for meeting invite processing"
            else:
                status = "cancelled"
                msg = "Meeting invite processing not confirmed by user"
            return {
                "status": status,
                "message": msg,
                "draft_uid": None,
                "draft_folder": None,
                "availability": None,
            }

        from imap_mcp.smtp_client import create_reply_mime
        from imap_mcp.workflows.calendar_mock import check_mock_availability
        from imap_mcp.workflows.invite_parser import identify_meeting_invite_details
        from imap_mcp.workflows.meeting_reply import generate_meeting_reply_content

        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return {
                "status": "error",
                "message": error,
                "draft_uid": None,
                "draft_folder": None,
                "availability": None,
            }
        result: Dict[str, Any] = {
            "status": "error",
            "message": "An error occurred during processing",
            "draft_uid": None,
            "draft_folder": None,
            "availability": None,
        }

        try:
            # Step 1: Fetch the original email
            logger.info(f"Fetching email UID {uid} from folder {folder}")
            email_obj = client.fetch_email(uid, folder)

            if not email_obj:
                result["message"] = f"Email with UID {uid} not found in folder {folder}"
                return result

            # Step 2: Identify if it's a meeting invite
            logger.info(
                "Analyzing email UID %d in folder %s for meeting invite details",
                uid,
                folder,
            )
            invite_result = identify_meeting_invite_details(email_obj)

            if not invite_result["is_invite"]:
                result["status"] = "not_invite"
                result["message"] = "The email is not a meeting invite"
                return result

            invite_details = invite_result["details"]

            # Step 3: Check calendar availability
            logger.info("Checking calendar availability for meeting time slot")
            availability_result = check_mock_availability(
                invite_details.get("start_time"),
                invite_details.get("end_time"),
                availability_mode,
            )

            result["availability"] = availability_result["available"]

            # Step 4: Generate reply content
            logger.info(
                f"Generating {'accept' if availability_result['available'] else 'decline'} reply"
            )
            reply_content = generate_meeting_reply_content(
                invite_details, availability_result
            )

            # Step 5: Create MIME message for reply
            logger.info("Creating MIME message for reply")
            # Create EmailAddress object for the reply sender
            reply_from = EmailAddress(name="", address=client.config.username)

            # Create the reply MIME message - using the standalone function
            mime_message = create_reply_mime(
                original_email=email_obj,
                reply_to=reply_from,
                body=reply_content["reply_body"],
                subject=reply_content["reply_subject"],
                # Don't use reply_all for meeting responses
                reply_all=False,
            )

            # Step 6: Save as draft
            logger.info("Saving reply as draft")
            draft_uid = client.save_draft_mime(mime_message)

            if draft_uid:
                drafts_folder = client._get_drafts_folder()
                result["status"] = "success"
                result["message"] = (
                    f"Draft reply created: {reply_content['reply_type']}"
                )
                result["draft_uid"] = draft_uid
                result["draft_folder"] = drafts_folder
                logger.info(
                    f"Draft saved successfully with UID {draft_uid} in folder {drafts_folder}"
                )
            else:
                result["message"] = "Failed to save draft"

        except (IMAPClientError, OSError, ValueError) as e:
            logger.error(f"Error processing meeting invite: {e}")
            result["message"] = f"Error: {e}"
        except Exception:
            logger.error("Unexpected error processing meeting invite", exc_info=True)
            result["message"] = "Error: an unexpected error occurred"

        return result
