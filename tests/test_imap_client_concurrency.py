"""Tests for IMAP client thread-safety (issue #65).

Async MCP handlers offload blocking IMAP work to worker threads via
``anyio.to_thread.run_sync``. Within a single MCP session the worker threads
share one ``imapclient`` socket, which is not thread-safe. ``ImapClient``
guards every socket-touching method with an internal re-entrant lock
(``_synchronized``). These tests verify that guard:

* concurrent calls to a socket-touching method never interleave;
* composite operations (a decorated method calling another) do not deadlock;
* the key socket-touching methods are actually decorated.
"""

import threading
import time
from typing import Any

import pytest

from imap_mcp.config import ImapConfig
from imap_mcp.imap_client import ImapClient


def _make_config() -> ImapConfig:
    return ImapConfig(
        host="imap.example.com",
        port=993,
        username="test@example.com",
        password="password",
        use_ssl=True,
    )


@pytest.fixture
def connected_client() -> ImapClient:
    """An ImapClient wired to a fake live connection.

    ``client`` is a stand-in for an ``imapclient.IMAPClient`` instance whose
    ``noop()`` succeeds (so ``_connection_alive`` reports the socket as live and
    no reconnect is attempted).
    """
    client = ImapClient(_make_config())
    fake_conn = _FakeConnection()
    client.client = fake_conn  # type: ignore[assignment]
    client.connected = True
    return client


class _FakeConnection:
    """Minimal stand-in for imapclient.IMAPClient used in serialization tests.

    ``capabilities()`` records how many threads are inside it simultaneously so
    a test can assert the lock serializes access. ``noop()`` is a no-op so the
    liveness probe in ``ensure_connected`` reports the socket as alive.
    """

    def __init__(self) -> None:
        self._active = 0
        self.max_concurrent = 0
        self._counter_lock = threading.Lock()

    def noop(self) -> None:
        return None

    def capabilities(self) -> tuple[bytes, ...]:
        with self._counter_lock:
            self._active += 1
            self.max_concurrent = max(self.max_concurrent, self._active)
        # Hold the "socket" briefly so overlapping callers would be detected.
        time.sleep(0.02)
        with self._counter_lock:
            self._active -= 1
        return (b"IMAP4REV1", b"IDLE")


class TestImapClientThreadSafety:
    """Verify the re-entrant lock serializes shared-socket access."""

    def test_has_reentrant_lock(self) -> None:
        """The client exposes an RLock instance for socket serialization."""
        client = ImapClient(_make_config())
        # threading.RLock() returns an instance of an internal lock type; the
        # robust check is that it supports the context-manager protocol and is
        # re-entrant (acquiring twice from one thread does not block).
        assert client._lock.acquire()
        assert client._lock.acquire()  # re-entrant: would block on a plain Lock
        client._lock.release()
        client._lock.release()

    def test_concurrent_socket_calls_do_not_interleave(
        self, connected_client: ImapClient
    ) -> None:
        """Many threads calling a decorated method never overlap on the socket."""
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                connected_client.get_capabilities()
            except BaseException as exc:  # noqa: BLE001 - re-raised in main thread
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"worker threads raised: {errors}"
        fake_conn: Any = connected_client.client
        # The lock must have serialized every call: at most one thread was ever
        # inside the socket operation at a time.
        assert fake_conn.max_concurrent == 1

    def test_reentrant_composite_call_does_not_deadlock(
        self, connected_client: ImapClient
    ) -> None:
        """A decorated method calling another decorated method must not deadlock.

        ``verify_connection`` is itself ``_synchronized`` and internally calls
        ``get_capabilities`` (also ``_synchronized``). With a plain ``Lock`` the
        nested acquisition would deadlock; ``RLock`` allows it.
        """
        done = threading.Event()
        result: list[list[str]] = []

        def call() -> None:
            result.append(connected_client.verify_connection())
            done.set()

        thread = threading.Thread(target=call)
        thread.start()
        # If the lock were non-reentrant this would never complete.
        assert done.wait(timeout=5.0), (
            "verify_connection deadlocked (non-reentrant lock?)"
        )
        thread.join()
        assert result == [["IMAP4REV1", "IDLE"]]


class TestSynchronizedDecoratorCoverage:
    """Guard against new socket methods being added without ``_synchronized``."""

    # Methods that touch the shared socket and must be serialized.
    SOCKET_METHODS = (
        "connect",
        "verify_connection",
        "disconnect",
        "ensure_connected",
        "get_capabilities",
        "list_folders",
        "select_folder",
        "search",
        "search_newest",
        "_supports_sort",
        "fetch_email",
        "fetch_emails",
        "fetch_summaries",
        "fetch_thread",
        "mark_email",
        "move_email",
        "delete_email",
        "_get_drafts_folder",
        "save_draft_mime",
    )

    # Pure, cheap helpers intentionally NOT synchronized (see _synchronized doc).
    UNSYNCHRONIZED_HELPERS = (
        "_validate_folder_name",
        "_validate_uid",
        "_is_folder_allowed",
        "_should_probe",
        "_resolve_search_criteria",
    )

    @pytest.mark.parametrize("method_name", SOCKET_METHODS)
    def test_socket_method_is_synchronized(self, method_name: str) -> None:
        method = getattr(ImapClient, method_name)
        # functools.wraps in _synchronized sets __wrapped__ on the wrapper.
        assert hasattr(method, "__wrapped__"), (
            f"{method_name} touches the IMAP socket but is not @_synchronized"
        )

    @pytest.mark.parametrize("method_name", UNSYNCHRONIZED_HELPERS)
    def test_pure_helper_is_not_synchronized(self, method_name: str) -> None:
        method = getattr(ImapClient, method_name)
        assert not hasattr(method, "__wrapped__"), (
            f"{method_name} is a pure helper and should not be @_synchronized"
        )
