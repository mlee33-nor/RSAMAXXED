"""The rename at the end of every atomic write, made to survive Windows.

WHY THIS EXISTS
---------------
Every state file here is written temp-then-rename, so a crash can never leave
one half-written. On Windows the rename (MoveFileEx) fails with
``[WinError 5] Access is denied`` whenever any other process has the target
open without FILE_SHARE_DELETE -- and this project lives on a Desktop that
Google Drive for Desktop syncs. Drive hard-links each changed file into
``Desktop\\.tmp.driveupload`` and holds it open while it uploads, so a trade
that saves the journal once per account runs straight into it. On 2026-09-25 a
16-account Public buy died on account 13 with exactly that error, and the rest
of the fills were never journaled.

The lock is always brief (an upload, an antivirus scan, the indexer), so the
answer is to wait it out rather than fail. PermissionError only: anything else
(disk full, missing directory) is a real error and is raised at once.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]

# Drive's upload of a 2 MB journal takes well under a second; the budget is
# generous because the alternative is losing a record of a real fill.
_RETRY_SECONDS = 15.0


def replace(src: PathLike, dst: PathLike, *, timeout: float = _RETRY_SECONDS) -> None:
    """os.replace, retried while another process briefly holds `dst` open."""
    deadline = time.monotonic() + timeout
    delay = 0.05
    while True:
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.5)
