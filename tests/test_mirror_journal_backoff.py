"""The mirror journal's writer must back off on a failing write, never spin.

A write that raised left the journal dirty, and the writer only sleeps while
the journal is clean, so it went straight round again: a background thread
pinned at 100% CPU for as long as the failure lasted.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mirror_journal as mj


def test_a_failing_write_is_retried_with_a_backoff_not_a_busy_loop(monkeypatch):
    calls = []
    sleeps = []

    def failing_write(timeout=-1):
        calls.append(time.perf_counter())
        if len(calls) >= 4:
            monkeypatch.setattr(mj, "_dirty", False)   # "recovered": go idle
            raise SystemExit                           # end the loop for the test
        raise OSError("disk is read-only")

    monkeypatch.setattr(mj, "_write_now", failing_write)
    monkeypatch.setattr(mj, "_dirty", True)
    monkeypatch.setattr(mj, "_last_error", None)
    monkeypatch.setattr(mj.time, "sleep", lambda s: sleeps.append(s))

    t = threading.Thread(target=lambda: _run_until_exit(), daemon=True)
    t.start()
    t.join(timeout=5)
    assert not t.is_alive()
    assert len(calls) == 4
    assert sleeps == [1.0, 2.0, 4.0]                   # then capped at 5.0
    assert mj._last_error == "OSError: disk is read-only"


def _run_until_exit():
    try:
        mj._writer_loop()
    except SystemExit:
        pass


def test_the_backoff_is_capped():
    assert mj._RETRY_MAX_S == 5.0 and mj._RETRY_FIRST_S == 1.0


def test_a_failed_disk_write_stays_owed(tmp_path, monkeypatch):
    """An OSError used to clear the dirty flag, silently dropping the write."""
    monkeypatch.setattr(mj, "_FILE", tmp_path / "mirror_runs.json")
    monkeypatch.setattr(mj, "_cache", {"runs": [], "scans": []})
    monkeypatch.setattr(mj, "_dirty", True)

    def refuse(_tmp, _dst):
        raise OSError("locked")
    monkeypatch.setattr(mj.atomic, "replace", refuse)
    try:
        mj._write_locked()
    except OSError:
        pass
    assert mj._dirty is True
