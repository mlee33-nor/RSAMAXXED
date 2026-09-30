"""The test suite must not write into the user's real logs.

`import app` installs logs/crash.log at import time -- before any fixture runs
-- so conftest sets RSA_NO_CRASH_LOG before anything imports it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


def test_the_suite_runs_with_the_crash_log_off():
    assert A._crash_log_disabled()
    assert A._CRASH_FH is None                 # never opened on import


def test_crash_notes_are_dropped_when_off_and_written_when_on(tmp_path, monkeypatch):
    log = tmp_path / "crash.log"
    monkeypatch.setattr(A, "CRASH_LOG", log)
    monkeypatch.setattr(A, "LOG_DIR", tmp_path)
    A._crash_note("TEST")
    assert not log.exists()
    monkeypatch.setenv("RSA_NO_CRASH_LOG", "")
    A._crash_note("TEST")
    assert "TEST" in log.read_text(encoding="utf-8")
