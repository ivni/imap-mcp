"""IMAP client implementation."""

import email
import functools
import logging
import re
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import (
    Any,
    Callable,
    Concatenate,
    Dict,
    Iterator,
    List,
    Optional,
    ParamSpec,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

import imapclient  # type: ignore[import-untyped]
from imapclient.exceptions import IMAPClientError  # type: ignore[import-untyped]

from imap_mcp.config import ImapConfig, create_ssl_context
from imap_mcp.models import Email, EmailAddress, EmailSummary, decode_mime_header

logger = logging.getLogger(__name__)


def _bytes_to_str(value: Any) -> str:
    """Decode a (possibly bytes) IMAP atom to str without MIME-word decoding.

    Used for the ASCII-ish ENVELOPE address parts (mailbox/host). Falls back
    to latin-1 so malformed 8-bit data never raises.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.decode("latin-1", errors="replace")
    return str(value)


def _decode_header_bytes(value: Any) -> str:
    """Decode an ENVELOPE header byte string, resolving MIME encoded-words.

    ENVELOPE subjects and address display names arrive as raw header bytes
    (often RFC 2047 ``=?utf-8?...?=`` encoded-words). This converts to str and
    runs the same MIME decoding used for full-message headers so summaries
    show human-readable text.
    """
    return decode_mime_header(_bytes_to_str(value))


def _envelope_addresses(
    addrs: Optional[Sequence[Any]],
) -> List[EmailAddress]:
    """Convert a tuple of imapclient ENVELOPE ``Address`` objects to models.

    Skips RFC 3501 group-syntax markers (entries with neither an address nor a
    name). Returns an empty list when *addrs* is falsy (header absent).
    """
    if not addrs:
        return []
    result: List[EmailAddress] = []
    for addr in addrs:
        mailbox = _bytes_to_str(getattr(addr, "mailbox", None))
        host = _bytes_to_str(getattr(addr, "host", None))
        if mailbox and host:
            address = f"{mailbox}@{host}"
        else:
            address = mailbox or host or ""
        name = _decode_header_bytes(getattr(addr, "name", None))
        if not address and not name:
            # Group-syntax start/end marker — not a real address.
            continue
        result.append(EmailAddress(name=name, address=address))
    return result


def _part_is_attachment(part: Any) -> bool:
    """Whether a single (non-multipart) BODYSTRUCTURE part is an attachment.

    Mirrors ``Email.from_message``'s attachment detection using only structure
    metadata: a part is treated as an attachment when its top-level MIME type
    is ``image``/``application`` (matching ``Email.from_message`` exactly — not
    ``audio``/``video``, so the list-row flag agrees with what opening the
    message yields), when it carries a ``name``/``filename`` parameter, or when
    it has an ``attachment``/``inline`` Content-Disposition. Never raises.
    """
    try:
        maintype = part[0]
        if isinstance(maintype, bytes):
            maintype = maintype.decode("ascii", errors="replace")
        if (maintype or "").lower() in ("image", "application"):
            return True

        # NAME parameter in the content-type parameter list (index 2),
        # a flat tuple of alternating key/value byte strings.
        params = part[2] if len(part) > 2 else None
        if isinstance(params, (tuple, list)):
            for token in params:
                if isinstance(token, bytes) and token.lower() in (b"name", b"filename"):
                    return True

        # Content-Disposition extension data — a 2-element
        # (disp-type, disp-params) structure, e.g.
        # (b"attachment", (b"filename", b"doc.pdf")) or (b"inline", NIL).
        # Match only that exact shape so a body-fld-lang list like
        # (b"attachment",) or other extension fields can't false-trigger.
        for item in part:
            if (
                isinstance(item, (tuple, list))
                and len(item) == 2
                and isinstance(item[0], bytes)
                and item[0].lower() in (b"attachment", b"inline")
                and isinstance(item[1], (tuple, list, type(None)))
            ):
                return True
    except (IndexError, AttributeError, TypeError):
        return False
    return False


def _bodystructure_has_attachments(body: Any) -> bool:
    """Detect attachments from a fetched BODYSTRUCTURE without bodies.

    Recurses into multipart structures and applies ``_part_is_attachment`` to
    each leaf part. Returns False for ``None`` or on any parse error so a
    malformed structure can never break a search/list.
    """
    if body is None:
        return False
    try:
        is_multipart = getattr(body, "is_multipart", None)
        if is_multipart is None:
            is_multipart = bool(body) and isinstance(body[0], list)
        if is_multipart:
            for part in body[0]:
                if _bodystructure_has_attachments(part):
                    return True
            return False
        return _part_is_attachment(body)
    except (IndexError, AttributeError, TypeError):
        return False


# Regex pattern for IMAP-significant characters that must be rejected in folder names.
# Prevents IMAP command injection via crafted folder names.
_INVALID_FOLDER_CHARS = re.compile(r'[\x00\r\n"\\{}]')
_MAX_FOLDER_NAME_LENGTH = 255
MAX_FETCH_UIDS = 500
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25 MB
_FOLDER_CACHE_TTL_SECONDS = 300  # 5 minutes

# Bounded retry with exponential backoff for transparent reconnection after a
# dropped connection (idle timeout, server restart, transient network blip).
_RECONNECT_MAX_ATTEMPTS = 3
_RECONNECT_BACKOFF_BASE_SECONDS = 0.5  # doubled each retry: 0.5s, 1.0s

# Skip the liveness NOOP probe when the socket was used within this window. A
# recently exercised connection is almost certainly still alive, so probing on
# every call — and on every sub-call of a composite operation — would only add
# redundant round-trips. After a longer idle gap (where a server-side idle
# timeout could have dropped the link) the probe runs and reconnects if needed.
_CONNECTION_PROBE_INTERVAL_SECONDS = 30.0


_P = ParamSpec("_P")
_R = TypeVar("_R")


def _synchronized(
    method: Callable[Concatenate["ImapClient", _P], _R],
) -> Callable[Concatenate["ImapClient", _P], _R]:
    """Serialize access to the shared IMAP socket.

    When blocking IMAP calls are offloaded to threads via ``to_thread``
    (issue #65), concurrent requests within the same MCP session may reach the
    single ``imapclient`` connection simultaneously. ``imapclient`` is NOT
    thread-safe on one socket: interleaved commands would corrupt the protocol
    stream. This decorator guards every socket-touching method with a
    re-entrant lock held for the duration of the (possibly composite) call.

    Re-entrancy (``RLock``) is essential because composite operations such as
    ``fetch_thread`` or ``save_draft_mime`` themselves call other decorated
    methods — the outer call keeps the lock, so the whole sequence is atomic.

    Pure helpers (``_validate_folder_name``, ``_validate_uid``,
    ``_is_folder_allowed``, ``_should_probe``) intentionally are NOT
    synchronized: they touch no socket and are cheap.
    """

    @functools.wraps(method)
    def wrapper(self: "ImapClient", *args: _P.args, **kwargs: _P.kwargs) -> _R:
        with self._lock:
            result = method(self, *args, **kwargs)
            # Record successful socket activity so ensure_connected can skip the
            # liveness probe while the connection is being actively used.
            self._last_activity = time.monotonic()
            return result

    return wrapper


@contextmanager
def _time_op(operation: str, folder: Optional[str] = None) -> Iterator[None]:
    """Log the wall-clock duration of a single IMAP network round-trip at DEBUG.

    Wrap only the ``imapclient`` socket call (not validation or parsing) so the
    emitted ``duration_ms`` reflects time on the wire — the signal needed to see
    which folder/operation is slow when a search or fetch approaches the client's
    tool-call timeout. The log is content-safe by construction: it carries only
    the operation name, the (non-sensitive) folder name, and the elapsed
    milliseconds — never criteria, subjects, addresses, or bodies.

    Does nothing measurable unless DEBUG is enabled (``IMAP_MCP_DEBUG=true`` or
    ``--debug``): the timing and log are skipped entirely otherwise.

    Args:
        operation: Short operation label (e.g. ``"search"``, ``"fetch_summaries"``).
        folder: Folder the operation targets, if any.
    """
    if not logger.isEnabledFor(logging.DEBUG):
        yield
        return
    start = time.monotonic()
    status = "ok"
    try:
        yield
    except BaseException:
        status = "error"
        raise
    finally:
        duration_ms = (time.monotonic() - start) * 1000.0
        logger.debug(
            "imap op=%s folder=%s status=%s duration_ms=%.1f",
            operation,
            folder if folder is not None else "-",
            status,
            duration_ms,
        )


class ImapClient:
    """IMAP client for interacting with email servers.

    Thread-safe: every socket-touching method is serialized via an internal
    re-entrant lock (see ``_synchronized``). This makes the client safe to call
    from worker threads after async handlers offload blocking IMAP work with
    ``anyio.to_thread.run_sync``.
    """

    def __init__(self, config: ImapConfig, allowed_folders: Optional[List[str]] = None):
        """Initialize IMAP client.

        Args:
            config: IMAP configuration
            allowed_folders: List of allowed folders. None means all folders are allowed.
                An empty list means no folders are allowed.
        """
        self.config = config
        self.allowed_folders = (
            set(allowed_folders) if allowed_folders is not None else None
        )
        self.client: Optional[imapclient.IMAPClient] = None
        self.folder_cache: Dict[str, List[str]] = {}
        self._folder_cache_timestamp: Optional[datetime] = None
        self.connected = False
        self.current_folder: Optional[str] = None
        self._hierarchy_delimiter: str = "/"
        # Re-entrant lock serializing all access to the single IMAP socket.
        # See ``_synchronized`` for why RLock (composite operations) and which
        # methods are guarded.
        self._lock: threading.RLock = threading.RLock()
        # Monotonic timestamp of the last successful socket operation, used by
        # ``_should_probe`` to avoid a liveness NOOP on every call.
        self._last_activity: Optional[float] = None

    @_synchronized
    def connect(self) -> None:
        """Connect to IMAP server.

        Creates an explicit SSL context (with optional custom CA bundle)
        for TLS connections instead of relying on the library default. A
        socket timeout (``config.timeout``) bounds how long connect and
        subsequent reads can block on an unresponsive server.

        Raises:
            ConnectionError: If connection fails
        """
        try:
            ssl_context: Optional[ssl.SSLContext] = None
            if self.config.use_ssl:
                ssl_context = create_ssl_context(self.config.tls_ca_bundle)

            self.client = imapclient.IMAPClient(
                self.config.host,
                port=self.config.port,
                ssl=self.config.use_ssl,
                ssl_context=ssl_context,
                timeout=self.config.timeout,
            )

            self.client.login(self.config.username, self.config.password)

            self.connected = True
            logger.info("Connected to IMAP server %s", self.config.host)
        except (IMAPClientError, OSError) as e:
            self.connected = False
            logger.error("Failed to connect to IMAP server: %s", e)
            raise ConnectionError(f"Failed to connect to IMAP server: {e}")

    @_synchronized
    def verify_connection(self) -> List[str]:
        """Verify the IMAP connection is working by checking server capabilities.

        Returns:
            List of server capabilities.

        Raises:
            ConnectionError: If verification fails.
        """
        try:
            capabilities = self.get_capabilities()
            logger.info("IMAP connection verified (%d capabilities)", len(capabilities))
            logger.debug("IMAP capabilities: %s", capabilities)
            return capabilities
        except (IMAPClientError, OSError) as e:
            self.connected = False
            raise ConnectionError(f"IMAP connection verification failed: {e}")

    @_synchronized
    def disconnect(self) -> None:
        """Disconnect from IMAP server."""
        if self.client:
            try:
                self.client.logout()
            except Exception as e:
                logger.warning("Error during IMAP logout: %s", e, exc_info=True)
            finally:
                self.client = None
                self.connected = False
                logger.info("Disconnected from IMAP server")

    def _should_probe(self) -> bool:
        """Whether to liveness-probe before reusing an established connection.

        Returns True when the socket has been idle longer than
        ``_CONNECTION_PROBE_INTERVAL_SECONDS`` (or has no recorded activity
        yet). Skipping the probe on a recently used connection avoids a
        redundant NOOP round-trip on every call — including each sub-call of a
        composite operation — without risking a stale socket: a longer idle gap
        (where a server-side timeout could have dropped the link) still triggers
        the probe and a transparent reconnect.
        """
        if self._last_activity is None:
            return True
        return (
            time.monotonic() - self._last_activity
        ) >= _CONNECTION_PROBE_INTERVAL_SECONDS

    def _connection_alive(self) -> bool:
        """Probe the live connection with a lightweight NOOP.

        A server-side or idle disconnect leaves ``self.connected`` True while
        the underlying socket is already dead. Issuing a cheap NOOP detects
        this so the caller can transparently reconnect instead of failing the
        next real operation.

        Returns:
            True if the connection responds, False if the socket is dead.
        """
        if self.client is None:
            return False
        try:
            self.client.noop()
            return True
        except (IMAPClientError, OSError) as e:
            logger.info("IMAP connection probe failed, will reconnect: %s", e)
            return False

    def _reconnect(self) -> None:
        """Tear down a dead connection and establish a fresh one.

        Drops the (presumed dead) client without a doomed logout round-trip,
        then reconnects with a small bounded retry and exponential backoff to
        ride out transient network failures.

        Raises:
            ConnectionError: If reconnection fails after all attempts.
        """
        # Abandon the dead client; selection state does not survive a new session.
        self.client = None
        self.connected = False
        self.current_folder = None

        last_error: Optional[ConnectionError] = None
        for attempt in range(1, _RECONNECT_MAX_ATTEMPTS + 1):
            try:
                self.connect()
                return
            except ConnectionError as e:
                last_error = e
                if attempt < _RECONNECT_MAX_ATTEMPTS:
                    backoff = _RECONNECT_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "Reconnect attempt %d/%d failed, retrying in %.1fs",
                        attempt,
                        _RECONNECT_MAX_ATTEMPTS,
                        backoff,
                    )
                    time.sleep(backoff)
        raise ConnectionError(
            f"Failed to reconnect after {_RECONNECT_MAX_ATTEMPTS} attempts: {last_error}"
        )

    @_synchronized
    def ensure_connected(self) -> None:
        """Ensure that we have a live connection to the IMAP server.

        When not connected, connects. When already connected but idle longer
        than the probe interval, probes the socket with a lightweight NOOP and
        transparently reconnects if the connection has dropped (idle timeout,
        server restart, or a transient network blip) — without this, a dead
        socket would surface as an error on the next operation instead of
        recovering.

        Synchronized: mutates connection state, so it must hold the socket lock.
        Re-entrant callers (every socket-touching method reaches it via
        ``_get_client``) already hold the lock; the RLock makes that safe.

        Raises:
            ConnectionError: If connection (or reconnection) fails
        """
        if not self.connected:
            self.connect()
        elif (
            self.client is not None
            and self._should_probe()
            and not self._connection_alive()
        ):
            logger.info("IMAP connection dropped, reconnecting")
            self._reconnect()
        if self.client is None:
            raise ConnectionError("Not connected to IMAP server")

    def _get_client(self) -> imapclient.IMAPClient:
        """Return the connected IMAP client, raising if not connected.

        Raises:
            ConnectionError: If not connected to the IMAP server.
        """
        self.ensure_connected()
        if self.client is None:
            raise ConnectionError("Not connected to IMAP server")
        return self.client

    @_synchronized
    def get_capabilities(self) -> List[str]:
        """Get IMAP server capabilities.

        Returns:
            List of server capabilities

        Raises:
            ConnectionError: If not connected and connection fails
        """
        client = self._get_client()
        raw_capabilities = client.capabilities()

        # Convert byte strings to regular strings and normalize case
        capabilities = []
        for cap in raw_capabilities:
            if isinstance(cap, bytes):
                cap = cap.decode("utf-8")
            capabilities.append(cap.upper())

        return capabilities

    def _is_folder_cache_valid(self) -> bool:
        """Check if folder cache is populated and not expired."""
        if not self.folder_cache or self._folder_cache_timestamp is None:
            return False
        elapsed = (datetime.now() - self._folder_cache_timestamp).total_seconds()
        return elapsed < _FOLDER_CACHE_TTL_SECONDS

    @_synchronized
    def list_folders(self, refresh: bool = False) -> List[str]:
        """List available folders.

        Args:
            refresh: Force refresh folder list cache

        Returns:
            List of folder names

        Raises:
            ConnectionError: If not connected and connection fails
        """
        self.ensure_connected()

        # Check cache first
        if not refresh and self._is_folder_cache_valid():
            return list(self.folder_cache.keys())

        # Get folders from server
        folders = []
        client = self._get_client()
        self.folder_cache.clear()
        with _time_op("list_folders"):
            raw_folders = client.list_folders()
        for flags, delimiter, name in raw_folders:
            if delimiter is not None:
                if isinstance(delimiter, bytes):
                    self._hierarchy_delimiter = delimiter.decode("utf-8")
                else:
                    self._hierarchy_delimiter = delimiter
            if isinstance(name, bytes):
                # Convert bytes to string if necessary
                name = name.decode("utf-8")

            # Filter folders if allowed_folders is set
            if self.allowed_folders is not None and name not in self.allowed_folders:
                continue

            folders.append(name)
            self.folder_cache[name] = flags

        self._folder_cache_timestamp = datetime.now()
        logger.debug(f"Listed {len(folders)} folders")
        return folders

    def _is_folder_allowed(self, folder: str) -> bool:
        """Check if a folder is allowed.

        Args:
            folder: Folder to check

        Returns:
            True if folder is allowed, False otherwise
        """
        # If no allowed_folders specified, all folders are allowed
        if self.allowed_folders is None:
            return True

        # If allowed_folders is specified, check if folder is in it
        return folder in self.allowed_folders

    def _validate_folder_name(self, folder: str) -> None:
        """Validate folder name against IMAP injection characters.

        Rejects folder names containing IMAP protocol-significant characters
        that could be used for command injection: double quotes, backslashes,
        curly braces, newlines (CR/LF), and NUL bytes.

        Args:
            folder: Folder name to validate.

        Raises:
            ValueError: If folder name contains invalid characters or is empty.
        """
        if not folder or not folder.strip():
            raise ValueError("Folder name must not be empty")

        if len(folder) > _MAX_FOLDER_NAME_LENGTH:
            raise ValueError(
                f"Folder name exceeds maximum length of {_MAX_FOLDER_NAME_LENGTH} characters"
            )

        if _INVALID_FOLDER_CHARS.search(folder):
            raise ValueError(
                "Folder name contains invalid characters "
                "(rejected: '\"', '\\', '{', '}', newlines, NUL)"
            )

    def _validate_uid(self, uid: int) -> None:
        """Validate that a UID is a positive integer.

        IMAP UIDs are unsigned 32-bit integers (RFC 3501 section 2.3.1.1).

        Args:
            uid: UID value to validate.

        Raises:
            ValueError: If uid is not a positive integer or exceeds 32-bit range.
        """
        if not isinstance(uid, int):
            raise ValueError(f"UID must be an integer, got {type(uid).__name__}")
        if uid <= 0:
            raise ValueError(f"UID must be a positive integer, got {uid}")
        if uid > 0xFFFFFFFF:
            raise ValueError(f"UID exceeds maximum 32-bit value: {uid}")

    @_synchronized
    def select_folder(self, folder: str, readonly: bool = False) -> Dict[str, Any]:
        """Select folder on IMAP server.

        Args:
            folder: Folder to select
            readonly: If True, select folder in read-only mode

        Returns:
            Dictionary with folder information

        Raises:
            ValueError: If folder is not allowed or contains invalid characters
            ConnectionError: If connection error occurs
        """
        self._validate_folder_name(folder)

        # Make sure the folder is allowed
        if not self._is_folder_allowed(folder):
            raise ValueError(f"Folder '{folder}' is not allowed")

        client = self._get_client()

        try:
            with _time_op("select_folder", folder):
                result: Dict[str, Any] = client.select_folder(folder, readonly=readonly)
            self.current_folder = folder
            logger.debug(f"Selected folder '{folder}'")
            return result
        except IMAPClientError as e:
            logger.error(f"Error selecting folder {folder}: {e}")
            raise ConnectionError(f"Failed to select folder {folder}: {e}")

    @_synchronized
    def search(
        self,
        criteria: Union[str, List[Any], Tuple[Any, ...], Sequence[Any]],
        folder: str = "INBOX",
        charset: Optional[str] = None,
    ) -> List[int]:
        """Search for messages.

        Args:
            criteria: Search criteria
            folder: Folder to search in
            charset: Character set for search criteria

        Returns:
            List of message UIDs

        Raises:
            ConnectionError: If not connected and connection fails
        """
        self.select_folder(folder, readonly=True)
        client = self._get_client()

        resolved_criteria = self._resolve_search_criteria(criteria)

        with _time_op("search", folder):
            results = client.search(resolved_criteria, charset=charset)
        logger.debug(f"Search returned {len(results)} results")
        return list(results)

    def _resolve_search_criteria(
        self,
        criteria: Union[str, List[Any], Tuple[Any, ...], Sequence[Any]],
    ) -> Union[str, List[Any], Tuple[Any, ...], Sequence[Any]]:
        """Translate a predefined criteria keyword into IMAP search criteria.

        Pure helper (touches no socket): maps a keyword such as ``"all"`` or
        ``"week"`` to the corresponding IMAP criteria, building the date-relative
        ones (``today``/``week``/``month``/``yesterday``) against the current date
        on each call. A non-string criteria, or an unknown keyword, is returned
        unchanged so callers may pass an explicit criteria list straight through.
        """
        if not isinstance(criteria, str):
            return criteria
        criteria_map: Dict[str, Union[str, List[Any]]] = {
            "all": "ALL",
            "unseen": "UNSEEN",
            "seen": "SEEN",
            "answered": "ANSWERED",
            "unanswered": "UNANSWERED",
            "deleted": "DELETED",
            "undeleted": "UNDELETED",
            "flagged": "FLAGGED",
            "unflagged": "UNFLAGGED",
            "recent": "RECENT",
            "today": ["SINCE", datetime.now().date()],
            "yesterday": [
                "SINCE",
                (datetime.now() - timedelta(days=1)).date(),
                "BEFORE",
                datetime.now().date(),
            ],
            "week": ["SINCE", (datetime.now() - timedelta(days=7)).date()],
            "month": ["SINCE", (datetime.now() - timedelta(days=30)).date()],
        }
        return criteria_map.get(criteria.lower(), criteria)

    @_synchronized
    def _supports_sort(self) -> bool:
        """Whether the server advertises the SORT extension (RFC 5256).

        Capability-based feature detection (never a hostname check) so behavior
        stays provider-agnostic. Returns False on any capability-query error
        rather than raising, so a probe failure degrades gracefully to a plain
        SEARCH instead of failing the operation.
        """
        try:
            client = self._get_client()
            return bool(client.has_capability("SORT"))
        except (IMAPClientError, OSError):
            return False

    @_synchronized
    def search_newest(
        self,
        criteria: Union[str, List[Any], Tuple[Any, ...], Sequence[Any]],
        folder: str = "INBOX",
        limit: Optional[int] = None,
        charset: Optional[str] = None,
    ) -> Tuple[List[int], int]:
        """Find matching UIDs newest-first, returning at most ``limit`` of them.

        Returns a ``(uids, total)`` pair where ``uids`` holds the newest matching
        message UIDs (at most ``limit``, ordered newest-first) and ``total`` is
        the full number of matches in the folder. Fetching summaries for only
        these UIDs — instead of every match — is what keeps ``search_emails``
        from downloading hundreds of envelopes (tens of seconds on a slow
        server) and blowing the MCP client's tool-call timeout on large
        mailboxes.

        Ordering is exact by the message Date header when the server advertises
        the SORT extension (RFC 5256: ``SORT (REVERSE DATE)`` evaluated on the
        server). When SORT is unavailable (e.g. Yandex), it falls back to a plain
        SEARCH ordered by UID descending — an arrival-time proxy that matches
        Date order for the common case but can diverge when messages were
        imported or appended out of order.

        Args:
            criteria: Search criteria (keyword such as ``"all"`` / ``"week"`` or
                an explicit IMAP criteria list).
            folder: Folder to search in.
            limit: Maximum number of (newest) UIDs to return. ``None`` or a
                non-positive value returns all matches, still newest-first.
            charset: Character set for the search/sort criteria.

        Returns:
            Tuple of (newest-first UID list capped at ``limit``, total match
            count).

        Raises:
            ConnectionError: If not connected and connection fails.
            IMAPClientError: If the IMAP search/sort fails.
        """
        self.select_folder(folder, readonly=True)
        client = self._get_client()
        resolved_criteria = self._resolve_search_criteria(criteria)

        # Prefer server-side date ordering so we transfer only the page we need.
        if self._supports_sort():
            try:
                with _time_op("sort", folder):
                    ordered = client.sort(
                        ["REVERSE", "DATE"],
                        resolved_criteria,
                        charset=charset or "UTF-8",
                    )
                ordered_uids = list(ordered)
                total = len(ordered_uids)
                if limit is not None and limit > 0:
                    ordered_uids = ordered_uids[:limit]
                logger.debug("Sort returned %d results (newest-first)", total)
                return ordered_uids, total
            except (IMAPClientError, OSError) as e:
                # Some servers advertise SORT but reject specific criteria or
                # charsets; degrade to SEARCH rather than failing the call.
                logger.info("SORT failed (%s); falling back to SEARCH", e)

        with _time_op("search", folder):
            results = client.search(resolved_criteria, charset=charset)
        uids = list(results)
        total = len(uids)
        # No SORT: approximate newest-first by UID descending (arrival proxy).
        newest = sorted(uids, reverse=True)
        if limit is not None and limit > 0:
            newest = newest[:limit]
        logger.debug("Search returned %d results", total)
        return newest, total

    @_synchronized
    def fetch_email(self, uid: int, folder: str = "INBOX") -> Optional[Email]:
        """Fetch a single email by UID.

        Args:
            uid: Email UID
            folder: Folder to fetch from

        Returns:
            Email object or None if not found

        Raises:
            ValueError: If uid is not a positive integer
            ConnectionError: If not connected and connection fails
        """
        self._validate_uid(uid)
        self.select_folder(folder, readonly=True)
        client = self._get_client()

        # Fetch message data with BODY.PEEK[] to get all parts including headers
        # Using BODY.PEEK[] instead of RFC822 to avoid setting the \Seen flag
        with _time_op("fetch_email", folder):
            result = client.fetch([uid], ["BODY.PEEK[]", "FLAGS"])

        if not result or uid not in result:
            logger.warning(f"Message with UID {uid} not found in folder {folder}")
            return None

        # Parse message
        message_data = result[uid]
        raw_message = message_data[b"BODY[]"]
        flags = message_data[b"FLAGS"]

        # Convert flags to strings
        str_flags = [f.decode("utf-8") if isinstance(f, bytes) else f for f in flags]

        # Parse email
        message = email.message_from_bytes(raw_message)
        email_obj = Email.from_message(message, uid=uid, folder=folder)
        email_obj.flags = str_flags

        return email_obj

    @_synchronized
    def fetch_emails(
        self,
        uids: List[int],
        folder: str = "INBOX",
        limit: Optional[int] = None,
    ) -> Dict[int, Email]:
        """Fetch multiple emails by UIDs.

        Args:
            uids: List of email UIDs
            folder: Folder to fetch from
            limit: Maximum number of emails to fetch

        Returns:
            Dictionary mapping UIDs to Email objects

        Raises:
            ValueError: If any uid is not a positive integer
            ConnectionError: If not connected and connection fails
        """
        for uid in uids:
            self._validate_uid(uid)

        # Enforce maximum fetch count to prevent DoS
        if len(uids) > MAX_FETCH_UIDS:
            logger.warning(
                "Truncating fetch from %d to %d UIDs (MAX_FETCH_UIDS limit)",
                len(uids),
                MAX_FETCH_UIDS,
            )
            uids = uids[:MAX_FETCH_UIDS]

        self.select_folder(folder, readonly=True)

        # Apply limit if specified
        if limit is not None and limit > 0:
            uids = uids[:limit]

        # Fetch message data
        if not uids:
            return {}

        # Use BODY.PEEK[] to get full message including all parts and headers
        client = self._get_client()
        with _time_op("fetch_emails", folder):
            result = client.fetch(uids, ["BODY.PEEK[]", "FLAGS"])

        # Parse emails
        emails = {}
        for uid, message_data in result.items():
            raw_message = message_data[b"BODY[]"]
            flags = message_data[b"FLAGS"]

            # Convert flags to strings
            str_flags = [
                f.decode("utf-8") if isinstance(f, bytes) else f for f in flags
            ]

            # Parse email
            message = email.message_from_bytes(raw_message)
            email_obj = Email.from_message(message, uid=uid, folder=folder)
            email_obj.flags = str_flags

            emails[uid] = email_obj

        return emails

    @_synchronized
    def fetch_summaries(
        self,
        uids: List[int],
        folder: str = "INBOX",
        limit: Optional[int] = None,
    ) -> Dict[int, EmailSummary]:
        """Fetch lightweight message summaries WITHOUT downloading bodies.

        Fetches only ``ENVELOPE``, ``FLAGS`` and ``BODYSTRUCTURE`` — the data a
        search/list result row needs (sender, recipients, subject, date, flags,
        attachment indicator). Unlike :meth:`fetch_emails`, it never transfers
        message bodies or attachments, so listing or searching a folder with
        many (or large) messages moves kilobytes instead of hundreds of
        megabytes. This is what keeps ``search_emails`` / ``list_emails`` from
        blocking until the client's tool-call timeout on large mailboxes.

        Args:
            uids: List of email UIDs.
            folder: Folder to fetch from.
            limit: Maximum number of summaries to fetch.

        Returns:
            Dictionary mapping UIDs to EmailSummary objects.

        Raises:
            ValueError: If any uid is not a positive integer.
            ConnectionError: If not connected and connection fails.
        """
        for uid in uids:
            self._validate_uid(uid)

        # Enforce the same upper bound as fetch_emails to prevent DoS.
        if len(uids) > MAX_FETCH_UIDS:
            logger.warning(
                "Truncating summary fetch from %d to %d UIDs (MAX_FETCH_UIDS limit)",
                len(uids),
                MAX_FETCH_UIDS,
            )
            uids = uids[:MAX_FETCH_UIDS]

        self.select_folder(folder, readonly=True)

        if limit is not None and limit > 0:
            uids = uids[:limit]

        if not uids:
            return {}

        client = self._get_client()
        # ENVELOPE + FLAGS + BODYSTRUCTURE only — no BODY[]/RFC822, so bodies
        # and attachments are never downloaded.
        with _time_op("fetch_summaries", folder):
            result = client.fetch(uids, ["ENVELOPE", "FLAGS", "BODYSTRUCTURE"])

        summaries: Dict[int, EmailSummary] = {}
        for uid, message_data in result.items():
            envelope = message_data.get(b"ENVELOPE")
            flags = message_data.get(b"FLAGS", ())
            bodystructure = message_data.get(b"BODYSTRUCTURE")

            str_flags = [
                f.decode("utf-8") if isinstance(f, bytes) else f for f in flags
            ]

            if envelope is not None:
                from_list = _envelope_addresses(envelope.from_)
                from_ = from_list[0] if from_list else EmailAddress(name="", address="")
                to = _envelope_addresses(envelope.to)
                subject = _decode_header_bytes(envelope.subject)
                date = envelope.date
            else:
                from_ = EmailAddress(name="", address="")
                to = []
                subject = ""
                date = None

            summaries[uid] = EmailSummary(
                uid=uid,
                folder=folder,
                from_=from_,
                to=to,
                subject=subject,
                date=date,
                flags=str_flags,
                has_attachments=_bodystructure_has_attachments(bodystructure),
            )

        return summaries

    @_synchronized
    def fetch_thread(self, uid: int, folder: str = "INBOX") -> List[Email]:
        """Fetch all emails in a thread.

        This method retrieves the initial email identified by the UID, and then
        searches for all related emails that belong to the same thread using
        Message-ID, In-Reply-To, References headers, and Subject matching as a fallback.

        Args:
            uid: UID of any email in the thread
            folder: Folder to fetch from

        Returns:
            List of Email objects in the thread, sorted chronologically

        Raises:
            ValueError: If uid is not a positive integer or initial email cannot be found
            ConnectionError: If not connected and connection fails
        """
        self._validate_uid(uid)
        self.ensure_connected()
        self.select_folder(folder, readonly=True)

        # Fetch the initial email
        initial_email = self.fetch_email(uid, folder)
        if not initial_email:
            raise ValueError(
                f"Initial email with UID {uid} not found in folder {folder}"
            )

        # Get thread identifiers from the initial email
        message_id = initial_email.headers.get("Message-ID", "")
        subject = initial_email.subject

        # Strip "Re:", "Fwd:", etc. from the subject for better matching
        clean_subject = re.sub(
            r"^(?:Re|Fwd|Fw|FWD|RE|FW):\s*", "", subject, flags=re.IGNORECASE
        )

        # Set to store all UIDs that belong to the thread
        thread_uids = {uid}

        # Search for emails with this Message-ID in the References or In-Reply-To headers
        if message_id:
            # Look for emails that reference this message ID
            references_query = ["HEADER", "References", message_id]
            try:
                references_results = self.search(references_query, folder)
                thread_uids.update(references_results)
            except (IMAPClientError, OSError, ValueError) as e:
                logger.warning(f"Error searching for References: {e}")

            # Look for direct replies to this message
            inreplyto_query = ["HEADER", "In-Reply-To", message_id]
            try:
                inreplyto_results = self.search(inreplyto_query, folder)
                thread_uids.update(inreplyto_results)
            except (IMAPClientError, OSError, ValueError) as e:
                logger.warning(f"Error searching for In-Reply-To: {e}")

            # If the initial email has References or In-Reply-To, fetch those messages too
            initial_references = initial_email.headers.get("References", "")
            initial_inreplyto = initial_email.headers.get("In-Reply-To", "")

            # Extract all message IDs from the References header
            if initial_references:
                for ref_id in re.findall(r"<[^>]+>", initial_references):
                    query = ["HEADER", "Message-ID", ref_id]
                    try:
                        results = self.search(query, folder)
                        thread_uids.update(results)
                    except (IMAPClientError, OSError, ValueError) as e:
                        logger.warning(
                            f"Error searching for Referenced message {ref_id}: {e}"
                        )

            # Look for the message that this is a reply to
            if initial_inreplyto:
                query = ["HEADER", "Message-ID", initial_inreplyto]
                try:
                    results = self.search(query, folder)
                    thread_uids.update(results)
                except (IMAPClientError, OSError, ValueError) as e:
                    logger.warning(f"Error searching for In-Reply-To message: {e}")

        # If we still have only the initial email or a small thread, try subject-based matching
        if len(thread_uids) <= 2 and clean_subject:
            # Look for emails with the same or related subject (Re: Subject)
            # This is a fallback for email clients that don't properly use References/In-Reply-To
            subject_query = ["SUBJECT", clean_subject]
            try:
                subject_results = self.search(subject_query, folder)

                # Filter out emails that are unlikely to be part of the thread
                # For example, avoid including all emails with a common subject like "Hello"
                if len(subject_results) < 20:  # Set a reasonable limit
                    thread_uids.update(subject_results)
                else:
                    # If there are too many results, try a more strict approach
                    # Look for exact subject match or common Re: pattern
                    strict_matches = []
                    strict_subjects = [
                        clean_subject,
                        f"Re: {clean_subject}",
                        f"RE: {clean_subject}",
                        f"Fwd: {clean_subject}",
                        f"FWD: {clean_subject}",
                        f"Fw: {clean_subject}",
                        f"FW: {clean_subject}",
                    ]

                    # Fetch subjects for all candidate emails
                    candidate_emails = self.fetch_emails(subject_results, folder)
                    for candidate_uid, candidate_email in candidate_emails.items():
                        if candidate_email.subject in strict_subjects:
                            strict_matches.append(candidate_uid)

                    thread_uids.update(strict_matches)
            except (IMAPClientError, OSError, ValueError) as e:
                logger.warning(f"Error searching by subject: {e}")

        # Fetch all discovered thread emails
        thread_emails = self.fetch_emails(list(thread_uids), folder)

        # Sort emails by date (chronologically)
        sorted_emails = sorted(
            thread_emails.values(), key=lambda e: e.date if e.date else datetime.min
        )

        return sorted_emails

    @_synchronized
    def mark_email(
        self,
        uid: int,
        folder: str,
        flag: str,
        value: bool = True,
    ) -> bool:
        """Mark email with flag.

        Args:
            uid: Email UID
            folder: Folder containing the email
            flag: Flag to set or remove
            value: True to set, False to remove

        Returns:
            True if successful

        Raises:
            ValueError: If uid is not a positive integer
            ConnectionError: If not connected and connection fails
            IMAPClientError: If the IMAP operation fails
            OSError: If a network/socket error occurs
        """
        self._validate_uid(uid)
        self.select_folder(folder)
        client = self._get_client()

        if value:
            client.add_flags([uid], flag)
            logger.debug(f"Added flag {flag} to message {uid}")
        else:
            client.remove_flags([uid], flag)
            logger.debug(f"Removed flag {flag} from message {uid}")
        return True

    @_synchronized
    def move_email(self, uid: int, source_folder: str, target_folder: str) -> bool:
        """Move email to another folder.

        Performs a copy-then-delete sequence. If copy succeeds but delete
        fails, raises with a message indicating the email may exist in
        both folders.

        Args:
            uid: Email UID
            source_folder: Source folder
            target_folder: Target folder

        Returns:
            True if successful

        Raises:
            ValueError: If uid is not a positive integer, or folder is not allowed or contains invalid characters
            ConnectionError: If not connected and connection fails
            IMAPClientError: If the IMAP operation fails (includes partial-state info if copy succeeded but delete failed)
            OSError: If a network/socket error occurs
        """
        self._validate_uid(uid)
        self._validate_folder_name(source_folder)
        self._validate_folder_name(target_folder)

        self.ensure_connected()

        # Check if folders are allowed
        if self.allowed_folders is not None:
            if source_folder not in self.allowed_folders:
                raise ValueError(f"Source folder '{source_folder}' is not allowed")
            if target_folder not in self.allowed_folders:
                raise ValueError(f"Target folder '{target_folder}' is not allowed")

        # Select source folder
        self.select_folder(source_folder)
        client = self._get_client()

        # Step 1: Copy to target (if this fails, no state change)
        client.copy([uid], target_folder)

        # Step 2: Delete from source (if this fails, email is duplicated)
        try:
            client.add_flags([uid], r"\Deleted")
            client.expunge()
        except (IMAPClientError, OSError) as e:
            raise IMAPClientError(
                f"Move partially completed: email was copied to '{target_folder}' "
                f"but could not be deleted from '{source_folder}': {e}"
            ) from e

        logger.debug(f"Moved message {uid} from {source_folder} to {target_folder}")
        return True

    @_synchronized
    def delete_email(self, uid: int, folder: str) -> bool:
        """Delete email.

        Args:
            uid: Email UID
            folder: Folder containing the email

        Returns:
            True if successful

        Raises:
            ValueError: If uid is not a positive integer
            ConnectionError: If not connected and connection fails
            IMAPClientError: If the IMAP operation fails
            OSError: If a network/socket error occurs
        """
        self._validate_uid(uid)
        self.select_folder(folder)
        client = self._get_client()

        client.add_flags([uid], r"\Deleted")
        client.expunge()
        logger.debug(f"Deleted message {uid} from {folder}")
        return True

    @_synchronized
    def _get_drafts_folder(self) -> str:
        """Get the drafts folder name for the current server.

        Returns:
            The name of the drafts folder, or "INBOX" as fallback
        """
        self.ensure_connected()
        folders = self.list_folders(refresh=True)

        # Look for standard drafts folder names (case-insensitive)
        drafts_folder_names = [
            "Drafts",
            "Draft",
            "Brouillons",
            "Borradores",
            "Entwürfe",
        ]
        lower_names = [name.lower() for name in drafts_folder_names]
        for folder in folders:
            # Check exact match and basename match (for paths like [Gmail]/Drafts)
            folder_lower = folder.lower()
            basename = folder_lower.rsplit(self._hierarchy_delimiter, 1)[-1]
            if folder_lower in lower_names or basename in lower_names:
                logger.debug(f"Using drafts folder: {folder}")
                return folder

        # Fallback to INBOX if no drafts folder found
        logger.warning("No drafts folder found, using INBOX as fallback")
        return "INBOX"

    @_synchronized
    def save_draft_mime(self, message: Any) -> Optional[int]:
        """Save a MIME message as a draft.

        Args:
            message: email.message.Message object to save as draft

        Returns:
            UID of the saved draft if available, None otherwise

        Raises:
            ConnectionError: If not connected and connection fails
            IMAPClientError: If the IMAP append operation fails
            OSError: If a network/socket error occurs
        """
        self.ensure_connected()

        # Get the drafts folder
        drafts_folder = self._get_drafts_folder()

        # Convert message to bytes if it's not already
        if hasattr(message, "as_bytes"):
            message_bytes = message.as_bytes()
        else:
            message_bytes = message.as_string().encode("utf-8")

        # Save the draft with Draft flag
        client = self._get_client()
        response = client.append(drafts_folder, message_bytes, flags=(r"\Draft",))

        # Try to extract the UID from the response
        uid = None
        if isinstance(response, bytes) and b"APPENDUID" in response:
            # Parse the APPENDUID response (format: [APPENDUID <uidvalidity> <uid>])
            try:
                # Use a more robust parsing approach
                match = re.search(rb"APPENDUID\s+\d+\s+(\d+)", response)
                if match:
                    uid = int(match.group(1))
                    logger.debug(f"Draft saved with UID: {uid}")
            except (IndexError, ValueError) as e:
                logger.warning(f"Could not parse UID from response: {e}")

        if uid is None:
            logger.warning(f"Could not extract UID from append response: {response}")

        return uid
