"""Pytest bootstrap: give Windows an isolated, per-run temp base.

On Windows, pytest's default base temp dir is the *shared*
``%LOCALAPPDATA%/Temp/pytest-of-<user>``. On a OneDrive/Defender machine a run
that is killed mid-flight (long runs get auto-backgrounded and stopped) can
leave that shared dir with an ACL that denies even the owner — removable only
from an elevated shell. Every later run, and the pre-push hook's test step,
then fails at ``tmp_path`` setup with ``PermissionError: [WinError 5]``.

Pointing ``tempfile`` at a unique *per-process* root makes pytest derive its
base dir there instead, so a poisoned leftover from an earlier run can never
block a new one. Leftovers from killed runs are swept best-effort on the next
start (files held open by a concurrent run can't be deleted on Windows, so a
live session is never disturbed).

Non-Windows platforms (e.g. CI) are deliberately left untouched.
"""

import glob
import os
import shutil
import sys
import tempfile

if sys.platform == "win32":
    _tmp_root = tempfile.gettempdir()
    _run_base = os.path.join(_tmp_root, f"imap-mcp-pytest-{os.getpid()}")

    for _leftover in glob.glob(os.path.join(_tmp_root, "imap-mcp-pytest-*")):
        if _leftover != _run_base:
            shutil.rmtree(_leftover, ignore_errors=True)

    os.makedirs(_run_base, exist_ok=True)
    tempfile.tempdir = _run_base
