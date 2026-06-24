"""MCP tools implementation for email operations."""

import json
import logging
import os
import time
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple

import anyio
from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]
from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from imap_mcp.imap_client import ImapClient
from imap_mcp.models import EmailAddress
from imap_mcp.resources import get_client_from_context

logger = logging.getLogger(__name__)

# Wall-clock budget (seconds) for a multi-folder ``search_emails`` fan-out. With
# ``folder=None`` the tool searches every allowed folder in turn; on accounts
# with many folders or large mailboxes the sequential SEARCH + summary fetches
# can blow past the MCP client's tool-call timeout, so the whole call fails and
# returns nothing. Once this budget is spent the remaining folders are skipped
# and the response is flagged ``truncated`` (with the searched/skipped folder
# lists) instead of hanging. A single explicitly-named folder is NOT bounded by
# this — that request is the caller's deliberate choice and the per-operation
# socket timeout still applies. Overridable via ``IMAP_MCP_SEARCH_BUDGET``.
DEFAULT_SEARCH_BUDGET_SECONDS = 60.0


def _search_budget_seconds() -> float:
    """Return the multi-folder search budget in seconds (env-overridable).

    Reads ``IMAP_MCP_SEARCH_BUDGET``; falls back to
    :data:`DEFAULT_SEARCH_BUDGET_SECONDS` when unset, and warns (without
    failing) on a non-numeric or non-positive value.
    """
    raw = os.environ.get("IMAP_MCP_SEARCH_BUDGET")
    if raw is None:
        return DEFAULT_SEARCH_BUDGET_SECONDS
    try:
        value = float(raw)
    except ValueError:
        logger.warning(
            "Invalid IMAP_MCP_SEARCH_BUDGET %r; using default %.0fs",
            raw,
            DEFAULT_SEARCH_BUDGET_SECONDS,
        )
        return DEFAULT_SEARCH_BUDGET_SECONDS
    if value <= 0:
        logger.warning(
            "IMAP_MCP_SEARCH_BUDGET must be > 0 (got %s); using default %.0fs",
            value,
            DEFAULT_SEARCH_BUDGET_SECONDS,
        )
        return DEFAULT_SEARCH_BUDGET_SECONDS
    return value


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


def register_tools(mcp: FastMCP) -> None:
    """Register MCP tools.

    The connected IMAP client is retrieved per-request from the lifespan
    context via ``get_client_from_context``.

    Args:
        mcp: MCP server
    """

    # Using decorator pattern to register tools
    @mcp.tool(
        title="Generate Meeting Reply",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    async def draft_meeting_reply_tool(
        invite_details: Annotated[
            Dict[str, Any],
            Field(
                description=(
                    "Meeting invite details, typically the 'details' object returned by "
                    "identify_meeting_invite_tool. Recognized keys: subject, start_time, "
                    "end_time, organizer, location."
                )
            ),
        ],
        availability_status: Annotated[
            bool,
            Field(
                description=(
                    "True to generate an acceptance reply, False to generate a "
                    "decline reply."
                )
            ),
        ],
        ctx: Context,
    ) -> Dict[str, str]:
        """Generate meeting reply text (accept or decline) — preview only.

        Returns the reply text and metadata. Does NOT save a draft or send
        anything, so it is safe to call to preview wording. To check the
        calendar, generate the reply, and save it as a draft in one step, use
        process_meeting_invite instead.

        Returns:
            Dictionary with the generated reply text (subject, body) and metadata.
        """
        from imap_mcp.workflows.meeting_reply import generate_meeting_reply_content

        availability = {"available": availability_status}
        return generate_meeting_reply_content(invite_details, availability)

    @mcp.tool(
        title="Identify Meeting Invite",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
    )
    async def identify_meeting_invite_tool(
        folder: Annotated[
            str,
            Field(description='IMAP folder containing the email (e.g. "INBOX").'),
        ],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email to inspect — a positive integer taken from a "
                    "list or search result."
                ),
            ),
        ],
        ctx: Context,
    ) -> Dict[str, Any]:
        """Analyze an email to determine if it contains a meeting/calendar invite.

        Fetches the email and inspects it for iCalendar (.ics) data. If found,
        extracts the subject, organizer, start/end times, and location. Read-only:
        does not modify any server state.

        Returns:
            Dictionary with ``is_invite`` (bool); when true, ``details`` holds the
            extracted invite fields, otherwise an ``error``/status message.
        """
        from imap_mcp.workflows.invite_parser import identify_meeting_invite_details

        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return {"is_invite": False, "details": {}, "error": error}

        def _do_identify() -> Dict[str, Any]:
            email_obj = client.fetch_email(uid, folder)
            if not email_obj:
                return {
                    "is_invite": False,
                    "details": {},
                    "error": f"Email UID {uid} not found",
                }
            return identify_meeting_invite_details(email_obj)

        return await anyio.to_thread.run_sync(_do_identify)

    @mcp.tool(
        title="Check Calendar Availability",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    async def check_calendar_availability_tool(
        start_time: Annotated[
            str,
            Field(
                description=(
                    "Proposed start time in ISO 8601 format, e.g. "
                    '"2024-01-15T10:00:00Z".'
                )
            ),
        ],
        end_time: Annotated[
            str,
            Field(
                description=(
                    "Proposed end time in ISO 8601 format; must be after start_time."
                )
            ),
        ],
        ctx: Context,
    ) -> Dict[str, Any]:
        """Check calendar availability for a proposed meeting time slot.

        Returns whether the time range is free. NOTE: this is a mock calendar
        implementation (no real calendar is queried) — results are illustrative
        and not authoritative.

        Returns:
            Dictionary with ``available`` (bool) plus a human-readable reason.
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
        folder: Annotated[
            str,
            Field(description="IMAP folder containing the email being replied to."),
        ],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email being replied to — a positive integer from a "
                    "list or search result."
                ),
            ),
        ],
        reply_body: Annotated[
            str,
            Field(
                description=(
                    "Plain-text body of the reply. The original message is quoted "
                    "automatically beneath it."
                )
            ),
        ],
        ctx: Context,
        reply_all: Annotated[
            bool,
            Field(
                description=(
                    "If true, reply to the sender plus all original To/Cc recipients; "
                    "if false, reply only to the sender."
                )
            ),
        ] = False,
        cc: Annotated[
            Optional[List[str]],
            Field(
                description=(
                    "Extra Cc recipients as RFC 5322 addresses, e.g. "
                    '["Jane Doe <jane@example.com>"].'
                )
            ),
        ] = None,
        body_html: Annotated[
            Optional[str],
            Field(
                description=(
                    "Optional HTML version of the reply, sent as a multipart/"
                    "alternative alongside reply_body."
                )
            ),
        ] = None,
    ) -> Dict[str, Any]:
        """Compose a reply to an email and save it as a draft on the IMAP server.

        Builds a MIME reply with correct threading headers (In-Reply-To,
        References) so the draft stays in the original conversation. Additive —
        creates a new draft and never modifies or sends the original. Requires
        user confirmation. This drafts a free-form reply; for replying to a
        calendar invite, prefer process_meeting_invite.

        Returns:
            Dictionary with ``status`` and ``draft_uid`` (None when the server
            lacks the UIDPLUS extension and cannot report the new UID).
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return {"status": "error", "message": error}

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

        def _do_draft_reply() -> Dict[str, Any]:
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
            try:
                draft_uid = client.save_draft_mime(mime_message)
            except (IMAPClientError, OSError) as e:
                return {
                    "status": "error",
                    "message": f"Failed to save draft: {e}",
                    "reply_body": reply_body,
                }
            if draft_uid:
                return {"status": "success", "draft_uid": draft_uid}
            return {
                "status": "success",
                "draft_uid": None,
                "message": "Draft saved (UID not available)",
                "reply_body": reply_body,
            }

        return await anyio.to_thread.run_sync(_do_draft_reply)

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
        folder: Annotated[
            str, Field(description="Source folder the email currently lives in.")
        ],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email to move — a positive integer from a list or "
                    "search result."
                ),
            ),
        ],
        target_folder: Annotated[
            str,
            Field(
                description=(
                    "Destination folder. Must also be in the allowed folders list."
                )
            ),
        ],
        ctx: Context,
    ) -> str:
        """Move an email from one IMAP folder to another.

        Copies the message to the target folder and deletes it from the source.
        Destructive — afterwards the email no longer exists in the original
        folder. Requires user confirmation. Both folders must be in the allowed
        folders list. Use this (move to a Trash folder) for a recoverable
        "soft delete"; use delete_email only for permanent removal.

        Returns:
            Success message, or an error message on failure.
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error
        error = _validate_tool_folder(client, target_folder)
        if error:
            return error

        confirmation = await require_confirmation(
            ctx, "move", folder, uid, target_folder=target_folder
        )
        if confirmation != ConfirmationResult.CONFIRMED:
            if confirmation == ConfirmationResult.ERROR:
                return "Action aborted: confirmation system error for move"
            return "Action cancelled: move not confirmed by user"

        def _do_move() -> str:
            try:
                success = client.move_email(uid, folder, target_folder)
                if success:
                    return f"Email moved from {folder} to {target_folder}"
                else:
                    return "Failed to move email"
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error moving email: {e}")
                return f"Error: {e}"
            except Exception as e:
                logger.error("Unexpected error moving email", exc_info=True)
                return f"Error: an unexpected error occurred ({type(e).__name__})"

        # Offload blocking IMAP work to a worker thread so the event loop
        # (and thus other concurrent sessions) is not blocked (issue #65).
        return await anyio.to_thread.run_sync(_do_move)

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
        folder: Annotated[str, Field(description="Folder containing the email.")],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email — a positive integer from a list or search "
                    "result."
                ),
            ),
        ],
        ctx: Context,
    ) -> str:
        r"""Mark an email as read by setting the IMAP \Seen flag.

        Idempotent — marking an already-read email has no additional effect.

        Returns:
            Success message, or an error message on failure.
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        def _do_mark_read() -> str:
            try:
                success = client.mark_email(uid, folder, r"\Seen", True)
                if success:
                    return "Email marked as read"
                else:
                    return "Failed to mark email as read"
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error marking email as read: {e}")
                return f"Error: {e}"
            except Exception as e:
                logger.error("Unexpected error marking email as read", exc_info=True)
                return f"Error: an unexpected error occurred ({type(e).__name__})"

        return await anyio.to_thread.run_sync(_do_mark_read)

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
        folder: Annotated[str, Field(description="Folder containing the email.")],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email — a positive integer from a list or search "
                    "result."
                ),
            ),
        ],
        ctx: Context,
    ) -> str:
        r"""Mark an email as unread by removing the IMAP \Seen flag.

        Idempotent — marking an already-unread email has no additional effect.

        Returns:
            Success message, or an error message on failure.
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        def _do_mark_unread() -> str:
            try:
                success = client.mark_email(uid, folder, r"\Seen", False)
                if success:
                    return "Email marked as unread"
                else:
                    return "Failed to mark email as unread"
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error marking email as unread: {e}")
                return f"Error: {e}"
            except Exception as e:
                logger.error("Unexpected error marking email as unread", exc_info=True)
                return f"Error: an unexpected error occurred ({type(e).__name__})"

        return await anyio.to_thread.run_sync(_do_mark_unread)

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
        folder: Annotated[str, Field(description="Folder containing the email.")],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email — a positive integer from a list or search "
                    "result."
                ),
            ),
        ],
        ctx: Context,
        flag: Annotated[
            bool,
            Field(
                description=("True to flag/star the email, False to unflag/unstar it.")
            ),
        ] = True,
    ) -> str:
        r"""Set or remove the IMAP \Flagged flag (the star / important marker).

        Pass flag=True to star, flag=False to unstar. Idempotent.

        Returns:
            Success message, or an error message on failure.
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        def _do_flag() -> str:
            try:
                success = client.mark_email(uid, folder, r"\Flagged", flag)
                if success:
                    return f"Email {'flagged' if flag else 'unflagged'}"
                else:
                    return f"Failed to {'flag' if flag else 'unflag'} email"
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error flagging email: {e}")
                return f"Error: {e}"
            except Exception as e:
                logger.error("Unexpected error flagging email", exc_info=True)
                return f"Error: an unexpected error occurred ({type(e).__name__})"

        return await anyio.to_thread.run_sync(_do_flag)

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
        folder: Annotated[str, Field(description="Folder containing the email.")],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email to delete — a positive integer from a list or "
                    "search result."
                ),
            ),
        ],
        ctx: Context,
    ) -> str:
        r"""Permanently delete an email from the IMAP server.

        Sets the \Deleted flag and expunges the folder. IRREVERSIBLE — the
        message cannot be recovered. Requires user confirmation. Prefer
        move_email to a Trash folder for a recoverable soft delete; use this only
        when permanent removal is intended.

        Returns:
            Success message, or an error message on failure.
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error

        confirmation = await require_confirmation(ctx, "delete", folder, uid)
        if confirmation != ConfirmationResult.CONFIRMED:
            if confirmation == ConfirmationResult.ERROR:
                return "Action aborted: confirmation system error for delete"
            return "Action cancelled: delete not confirmed by user"

        def _do_delete() -> str:
            try:
                success = client.delete_email(uid, folder)
                if success:
                    return "Email deleted"
                else:
                    return "Failed to delete email"
            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error deleting email: {e}")
                return f"Error: {e}"
            except Exception as e:
                logger.error("Unexpected error deleting email", exc_info=True)
                return f"Error: an unexpected error occurred ({type(e).__name__})"

        return await anyio.to_thread.run_sync(_do_delete)

    @mcp.tool(
        title="Search Emails",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True),
    )
    async def search_emails(
        query: Annotated[
            str,
            Field(
                description=(
                    'Search term. For criteria "text"/"from"/"to"/"subject" this is '
                    "the text to match. For the status criteria (all/unseen/seen/"
                    "today/week/month) the query is ignored — pass an empty string."
                )
            ),
        ],
        ctx: Context,
        folder: Annotated[
            Optional[str],
            Field(
                description=(
                    "Folder to search. Omit (null) to search every allowed folder."
                )
            ),
        ] = None,
        criteria: Annotated[
            Literal[
                "text",
                "from",
                "to",
                "subject",
                "all",
                "unseen",
                "seen",
                "today",
                "week",
                "month",
            ],
            Field(
                description=(
                    'What to match: "text" full-text body/headers; "from"/"to"/'
                    '"subject" the matching header; "all" every message; "unseen"/'
                    '"seen" by read state; "today"/"week"/"month" by recency.'
                )
            ),
        ] = "text",
        limit: Annotated[
            int,
            Field(
                description=(
                    "Maximum number of results to return after sorting by date "
                    "(newest first). Must be >= 1."
                )
            ),
        ] = 10,
        offset: Annotated[
            int,
            Field(
                description=(
                    "Number of results to skip before returning, for pagination. "
                    "Must be >= 0."
                )
            ),
        ] = 0,
    ) -> str:
        """Search for emails across one or more IMAP folders.

        Supports full-text search, sender/recipient/subject filtering, and status
        filters (seen/unseen/today/week/month). Results are gathered across the
        searched folders, sorted globally by date (newest first), then paginated.
        Each row carries UID, folder, sender, recipients, subject, date, flags,
        and an attachment indicator — but not the body. Fetch the
        ``email://{folder}/{uid}`` resource to read a specific message.

        When searching every folder (``folder`` omitted), the fan-out is bounded
        by a wall-clock budget so a slow server cannot exhaust the tool-call
        timeout. If the budget is hit, the remaining folders are skipped and the
        response is flagged ``truncated`` — narrow ``folder`` to search them.

        Returns:
            JSON object with ``total``, ``offset``, ``limit``, and a ``results``
            array of email summaries. When a multi-folder search did not cover
            every folder, extra keys report the partial coverage:
            ``folders_searched`` (folders actually searched), ``truncated: true``
            with ``folders_skipped`` when the wall-clock budget was hit, and
            ``folders_errored`` for any folder whose search raised. ``total``
            then counts only ``folders_searched`` — a partial total whenever
            coverage is partial.
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

        def _do_search() -> Tuple[
            List[Dict[str, Any]], int, List[str], List[str], List[str]
        ]:
            folders_to_search = [folder] if folder else client.list_folders()
            # Bound the wall-clock cost of a multi-folder fan-out so a slow
            # server cannot exhaust the client's tool-call timeout and fail the
            # whole call. A single explicit folder is the caller's choice and is
            # left unbounded (the per-operation socket timeout still applies).
            budget = None if folder is not None else _search_budget_seconds()
            start = time.monotonic()

            results: List[Dict[str, Any]] = []
            total_count = 0
            searched: List[str] = []
            skipped: List[str] = []
            errored: List[str] = []

            for index, current_folder in enumerate(folders_to_search):
                # Check the budget between folders (never before the first, so
                # at least one folder is always searched even if misconfigured).
                if (
                    budget is not None
                    and index > 0
                    and (time.monotonic() - start) >= budget
                ):
                    skipped = list(folders_to_search[index:])
                    logger.warning(
                        "search_emails budget %.0fs exceeded after %d folder(s); "
                        "skipping %d remaining folder(s)",
                        budget,
                        len(searched),
                        len(skipped),
                    )
                    break

                try:
                    # Search for emails
                    uids = client.search(search_criteria, folder=current_folder)

                    folder_rows: List[Dict[str, Any]] = []
                    if uids:
                        # Fetch lightweight summaries (envelope/flags/structure)
                        # — never download bodies just to build result rows.
                        summaries = client.fetch_summaries(uids, folder=current_folder)

                        # Create summaries
                        for uid, summary in summaries.items():
                            folder_rows.append(
                                {
                                    "uid": uid,
                                    "folder": current_folder,
                                    "from": str(summary.from_),
                                    "to": [str(to) for to in summary.to],
                                    "subject": summary.subject,
                                    "date": summary.date.isoformat()
                                    if summary.date
                                    else None,
                                    "flags": summary.flags,
                                    "has_attachments": summary.has_attachments,
                                }
                            )
                except (IMAPClientError, OSError, ValueError) as e:
                    logger.warning(f"Error searching folder {current_folder}: {e}")
                    errored.append(current_folder)
                    continue
                except Exception:
                    logger.warning(
                        "Unexpected error searching folder %s",
                        current_folder,
                        exc_info=True,
                    )
                    errored.append(current_folder)
                    continue

                # Record the folder only once it has fully completed (search +
                # summary fetch) so ``total``/``results``/``folders_searched``
                # stay mutually consistent; a folder that raised is tracked in
                # ``errored`` instead of being silently dropped.
                results.extend(folder_rows)
                total_count += len(uids)
                searched.append(current_folder)

            return results, total_count, searched, skipped, errored

        (
            results,
            total_count,
            searched,
            skipped,
            errored,
        ) = await anyio.to_thread.run_sync(_do_search)

        # Sort results by date (newest first)
        results.sort(key=lambda x: str(x.get("date") or "0"), reverse=True)

        # Apply pagination
        results = results[offset : offset + limit]

        response: Dict[str, Any] = {
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "results": results,
        }
        # Surface partial coverage explicitly — never silently drop folders.
        # These keys appear only on a multi-folder fan-out that did not cover
        # every folder, so the normal (fully covered) response shape is
        # unchanged. ``total`` then counts only ``folders_searched`` and is a
        # partial total whenever coverage is partial.
        if folder is None and (skipped or errored):
            response["folders_searched"] = searched
            if skipped:
                response["truncated"] = True
                response["folders_skipped"] = skipped
            if errored:
                response["folders_errored"] = errored

        return json.dumps(response, indent=2)

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
        folder: Annotated[str, Field(description="Folder containing the email.")],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the email — a positive integer from a list or search "
                    "result."
                ),
            ),
        ],
        action: Annotated[
            Literal["read", "unread", "flag", "unflag", "move", "delete"],
            Field(
                description=(
                    'Action to perform. "move" requires target_folder; "move" and '
                    '"delete" are destructive and prompt for user confirmation, the '
                    "rest apply immediately."
                )
            ),
        ],
        ctx: Context,
        notes: Annotated[
            Optional[str],
            Field(
                description=(
                    "Optional free-text note recording why the action was taken. "
                    "Not sent to the server."
                )
            ),
        ] = None,
        target_folder: Annotated[
            Optional[str],
            Field(
                description=(
                    'Destination folder; required only when action is "move", '
                    "ignored otherwise."
                )
            ),
        ] = None,
    ) -> str:
        """Perform one action on an email: read, unread, flag, unflag, move, or delete.

        A convenience dispatcher over the single-purpose tools, handy when the
        action is chosen dynamically. Destructive actions (move, delete) require
        user confirmation; the others execute immediately. When the action is
        fixed, prefer the dedicated tool (mark_as_read, flag_email, move_email,
        delete_email) for clearer intent and accurate per-tool annotations.

        Returns:
            Success message, or an error message on failure.
        """
        client = get_client_from_context(ctx)
        error = _validate_tool_folder(client, folder)
        if error:
            return error
        if target_folder:
            error = _validate_tool_folder(client, target_folder)
            if error:
                return error

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

        def _do_process() -> str:
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
                        result = (
                            f"Failed to move email from {folder} to {target_folder}"
                        )
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
            except Exception as e:
                logger.error("Unexpected error processing email", exc_info=True)
                return f"Error: an unexpected error occurred ({type(e).__name__})"

        return await anyio.to_thread.run_sync(_do_process)

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
        folder: Annotated[
            str, Field(description="Folder containing the invite email.")
        ],
        uid: Annotated[
            int,
            Field(
                ge=1,
                description=(
                    "UID of the invite email — a positive integer from a list or "
                    "search result."
                ),
            ),
        ],
        ctx: Context,
        availability_mode: Annotated[
            Literal[
                "random",
                "always_available",
                "always_busy",
                "business_hours",
                "weekdays",
            ],
            Field(
                description=(
                    "How the mock calendar decides availability: "
                    '"random" (~70% available), "always_available", "always_busy", '
                    '"business_hours" (free 09:00–17:00), or "weekdays" (free Mon–Fri).'
                )
            ),
        ] = "random",
    ) -> dict:
        """Analyze a meeting invite, check availability, and save a draft reply.

        End-to-end workflow combining the meeting tools. Additive — creates a new
        draft and never modifies or sends the original email. Requires user
        confirmation. Availability is decided by a mock calendar (see
        availability_mode), not a real one.

        Steps:
        1. Fetches the email and identifies meeting invite details
        2. Checks (mock) calendar availability for the proposed time
        3. Generates an accept or decline reply based on availability
        4. Creates a MIME reply message with proper threading headers
        5. Saves the reply as a draft on the IMAP server

        Returns:
            Dictionary with the processing result:
              - status: "success", "not_invite", "cancelled", or "error"
              - message: Description of the result
              - draft_uid: UID of the saved draft (None if server lacks UIDPLUS)
              - draft_folder: Folder where the draft was saved (if successful)
              - availability: Whether the time slot was available
        """
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

        def _do_process_meeting_invite() -> Dict[str, Any]:
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
                    result["message"] = (
                        f"Email with UID {uid} not found in folder {folder}"
                    )
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
                try:
                    draft_uid = client.save_draft_mime(mime_message)
                except (IMAPClientError, OSError) as e:
                    result["message"] = f"Failed to save draft: {e}"
                    result["reply_body"] = reply_content["reply_body"]
                    return result

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
                    drafts_folder = client._get_drafts_folder()
                    result["status"] = "success"
                    result["message"] = "Draft saved (UID not available)"
                    result["draft_folder"] = drafts_folder
                    result["reply_body"] = reply_content["reply_body"]

            except (IMAPClientError, OSError, ValueError) as e:
                logger.error(f"Error processing meeting invite: {e}")
                result["message"] = f"Error: {e}"
            except Exception as e:
                logger.error(
                    "Unexpected error processing meeting invite", exc_info=True
                )
                result["message"] = (
                    f"Error: an unexpected error occurred ({type(e).__name__})"
                )

            return result

        return await anyio.to_thread.run_sync(_do_process_meeting_invite)
