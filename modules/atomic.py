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

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Union

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


# ---------------------------------------------------------------------------
# Whole-file writers
# ---------------------------------------------------------------------------
#
# Every writer used to stage its bytes in a FIXED `<file>.tmp` and rename it
# over the target. Two threads saving the same file (a mirror tick and a button
# press, two broker workers finishing at once) then share one temp file: the
# first rename moves it away and the second raises FileNotFoundError -- and
# most call sites swallow OSError, so that save was silently dropped. A stress
# run lost 97 of 160 concurrent writes that way.
#
# So: one lock per target path (same-process writers queue instead of racing),
# a UNIQUE temp name from mkstemp in the same directory (so the rename stays
# inside one filesystem and is atomic), fsync before the rename, and the
# Drive-tolerant `replace` above. A failed write removes its temp file and
# raises; the previous contents of `path` are untouched.

_path_locks: Dict[str, threading.RLock] = {}
_path_locks_guard = threading.Lock()


def lock_for(path: PathLike) -> threading.RLock:
    """The in-process lock that serialises writes to `path`."""
    key = os.path.normcase(os.path.abspath(str(path)))
    with _path_locks_guard:
        lk = _path_locks.get(key)
        if lk is None:
            lk = _path_locks[key] = threading.RLock()
        return lk


def write_text(path: PathLike, text: str, *, encoding: str = "utf-8") -> None:
    """Replace `path` with `text`, atomically. Raises on failure."""
    path = Path(path)
    with lock_for(path):
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp",
                                   dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding=encoding) as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


def write_json(path: PathLike, data: Any, *, indent: int = 2, **dumps_kw: Any) -> None:
    """`write_text(path, json.dumps(data))`. Serialised before any file is
    touched, so data that cannot be encoded never costs the old file.

    Refuses (StateUnreadable, an OSError) to write over a file load_state()
    found unreadable this session -- see there."""
    guard_write(path)
    write_text(path, json.dumps(data, indent=indent, **dumps_kw))


# ---------------------------------------------------------------------------
# Reading state files: BOM-tolerant, and never "empty, then overwritten"
# ---------------------------------------------------------------------------
#
# Every loader used to be `json.loads(read_text("utf-8"))` with `except: return
# default`. Two things were wrong with that. A file saved by Notepad or
# PowerShell 5.1 starts with a UTF-8 BOM, which "utf-8" refuses -- so a valid
# file read as unreadable. And "unreadable" read as "empty": the next save
# wrote `default + one change` over it. sells.json lost every locally imported
# exit that way, and those shares were never sold.
#
# Now a file that EXISTS but will not parse (after a few retries, for Drive or
# antivirus holding it) is copied aside once, recorded here, and write_json
# refuses to replace it for the rest of the session -- the app runs on the
# default and says so (see unreadable_files / on_unreadable). A later read that
# succeeds (someone fixed or moved the file) lifts the block.

class StateUnreadable(OSError):
    """A write over a state file that could not be read this session."""


_UNREADABLE: Dict[str, str] = {}
_UNREADABLE_LOCK = threading.Lock()
#: Called with (path, message) the first time a file is found unreadable. The
#: GUI sets it to put the message on screen; it must not raise.
on_unreadable = None


def _key_of(path: PathLike) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def guard_write(path: PathLike) -> None:
    why = _UNREADABLE.get(_key_of(path))
    if why:
        raise StateUnreadable(why)


def unreadable_files() -> Dict[str, str]:
    """path -> why, for every state file this session refused to overwrite."""
    with _UNREADABLE_LOCK:
        return dict(_UNREADABLE)


def is_unreadable(path: PathLike) -> bool:
    """`path`'s last load_state failed, so its writes are blocked right now."""
    with _UNREADABLE_LOCK:
        return _key_of(path) in _UNREADABLE


#: path key -> {sha256 of the content: the copy kept of it}. One quarantine
#: copy per distinct content: a transient lock (Drive, antivirus) that fails a
#: read, lifts, and fails again must not leave a new copy every time.
_QUARANTINED: Dict[str, Dict[str, "Path | None"]] = {}


def _quarantine_once(p: Path, key: str) -> "Path | None":
    import hashlib
    try:
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        digest = None
    seen = _QUARANTINED.setdefault(key, {})
    if digest is not None and digest in seen:
        return seen[digest]
    kept = quarantine(p)
    if digest is not None:
        seen[digest] = kept
    return kept


def load_state(path: PathLike, default: Any, *, tries: int = 3,
               pause: float = 0.05) -> Any:
    """Parse a JSON state file as utf-8-sig. `default` when it does not exist.

    Exists but unreadable: quarantined once (see quarantine), blocked from
    being overwritten, reported through `on_unreadable`, and `default` is
    returned so the caller can still run.
    """
    p = Path(path)
    last: Exception = ValueError("unreadable")
    for attempt in range(max(1, tries)):
        try:
            data = json.loads(p.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            with _UNREADABLE_LOCK:
                _UNREADABLE.pop(_key_of(p), None)
            return default
        except (OSError, ValueError) as exc:
            last = exc
            if attempt + 1 < tries:
                time.sleep(pause)
            continue
        with _UNREADABLE_LOCK:
            _UNREADABLE.pop(_key_of(p), None)
        return data
    key = _key_of(p)
    with _UNREADABLE_LOCK:
        first = key not in _UNREADABLE
        if first:
            kept = _quarantine_once(p, key)
            # Not "this session ... restart": the next read that succeeds
            # lifts the block on its own, so a passing lock needs nothing.
            _UNREADABLE[key] = (
                f"{p.name} could not be read ({last}); it is left as it is"
                + (f" (a copy is kept as {kept.name})" if kept else "")
                + " and nothing will be saved over it until it reads cleanly "
                  "again — the app retries on its next read. If it stays "
                  "unreadable, fix it or move it aside.")
        msg = _UNREADABLE[key]
    if first and callable(on_unreadable):
        try:
            on_unreadable(p, msg)
        except Exception:
            pass
    return default


# ---------------------------------------------------------------------------
# Cross-process lock
# ---------------------------------------------------------------------------
#
# lock_for() above only serialises THREADS. trades.json also has writers in
# other processes -- reconcile.py, backfill_basis.py, runner.py, a second copy
# of the GUI -- and each does read-modify-write: parse the journal, append a
# row, save the whole list. Two of those interleaved is a lost row: both read
# N rows, both save N+1, and the second save silently drops the first one's
# fill. A unique temp name keeps the FILE whole; only a lock held across the
# read AND the write keeps the ROWS.
#
# An OS byte-range lock on a sidecar `<file>.lock`, not on the data file
# itself: the data file is replaced by rename on every save, so a lock on it
# would be a lock on a file that no longer exists. The OS drops the lock when
# the process dies, so a crash can never leave the journal locked.

try:                                         # Windows
    import msvcrt as _msvcrt
except ImportError:                          # pragma: no cover - POSIX
    _msvcrt = None
    import fcntl as _fcntl

#: A journal save takes well under a second; a writer queued behind another
#: process for longer than this is better told so than left hanging forever.
_LOCK_SECONDS = 30.0


class LockTimeout(TimeoutError):
    """Another process held the lock for longer than the budget."""


def _try_lock(fh) -> bool:
    try:
        if _msvcrt is not None:
            fh.seek(0)
            _msvcrt.locking(fh.fileno(), _msvcrt.LK_NBLCK, 1)
        else:                                # pragma: no cover - POSIX
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX | _fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fh) -> None:
    try:
        if _msvcrt is not None:
            fh.seek(0)
            _msvcrt.locking(fh.fileno(), _msvcrt.LK_UNLCK, 1)
        else:                                # pragma: no cover - POSIX
            _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
    except OSError:
        pass


def lock_path(path: PathLike) -> Path:
    """The sidecar file the cross-process lock for `path` is taken on."""
    p = Path(path)
    return p.with_name(p.name + ".lock")


class file_lock:
    """Exclusive lock on `path` across PROCESSES (and threads). Context manager.

        with atomic.file_lock(JOURNAL):
            rows = read(); rows.append(new); write(rows)

    Not re-entrant: a thread already holding it that asks again waits on
    itself until the timeout, then raises LockTimeout. Callers that nest take
    it once at the outermost read-modify-write.
    """

    def __init__(self, path: PathLike, timeout: float = _LOCK_SECONDS) -> None:
        self._path = lock_path(path)
        self._timeout = timeout
        self._fh = None

    def __enter__(self) -> "file_lock":
        deadline = time.monotonic() + self._timeout
        delay = 0.02
        while True:
            fh = None
            try:
                fh = open(self._path, "a+b")
                if _try_lock(fh):
                    self._fh = fh
                    return self
            except PermissionError:
                # Drive / antivirus holding the sidecar itself. Brief.
                pass
            if fh is not None:
                fh.close()
            if time.monotonic() >= deadline:
                raise LockTimeout(
                    f"{self._path.name} is held by another process; nothing "
                    f"was written")
            time.sleep(delay)
            delay = min(delay * 2, 0.25)

    def __exit__(self, *exc: Any) -> None:
        fh, self._fh = self._fh, None
        if fh is not None:
            _unlock(fh)
            fh.close()


def quarantine(path: PathLike) -> "Path | None":
    """Copy an unreadable file to `<stem>.unreadable-<stamp><suffix>` beside
    it, before anything can overwrite it. Returns the copy, or None."""
    import shutil
    from datetime import datetime, timezone

    path = Path(path)
    stamp = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    dest = path.with_name(f"{path.stem}.unreadable-{stamp}{path.suffix}")
    n = 1
    while dest.exists():
        dest = path.with_name(f"{path.stem}.unreadable-{stamp}-{n}{path.suffix}")
        n += 1
    try:
        shutil.copy2(path, dest)
        return dest
    except OSError:
        return None
