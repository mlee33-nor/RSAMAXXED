"""Last-gate fixes: a recycled pid in a profile lock, a sells.json that isn't
a list."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import atomic, proc  # noqa: E402

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows process times")


def _sleeper():
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def test_started_after_tells_a_newer_process_from_an_older_lock():
    child = _sleeper()
    try:
        time.sleep(0.3)
        assert proc.started_after(child.pid, time.time() - 3600) is True
        assert proc.started_after(child.pid, time.time() + 3600) is False
        assert proc.started_after(os.getpid(), 0) is None
        assert child.poll() is None          # probing never touched it
    finally:
        child.kill()


@pytest.mark.parametrize("modname", ["fidelity", "wellsfargo"])
def test_a_lock_naming_a_recycled_pid_is_taken_over(modname, tmp_path, monkeypatch):
    """Crash + reboot: the lock's pid now belongs to an unrelated process that
    started after the lock was written. It is not the owner; the profile must
    not stay locked forever."""
    mod = __import__(modname)
    child = _sleeper()
    try:
        time.sleep(0.3)
        assert mod._lock_owner_alive(child.pid) is True
        assert mod._lock_owner_alive(child.pid, time.time() - 3600) is False
        # An owner that started BEFORE its lock was written is still the owner.
        assert mod._lock_owner_alive(child.pid, time.time() + 3600) is True
        assert mod._lock_owner_alive(os.getpid(), 0) is True
        assert child.poll() is None
    finally:
        child.kill()


def test_a_sells_file_that_is_not_a_list_is_never_overwritten(tmp_path, monkeypatch):
    import app as A
    f = tmp_path / "sells.json"
    f.write_text(json.dumps({"oops": "a dict"}), encoding="utf-8")
    monkeypatch.setattr(A, "SELLS_FILE", f)
    monkeypatch.setattr(atomic, "_UNREADABLE", {})
    assert A._load_sells() == []
    assert A._save_sells([{"symbol": "NEW"}]) is False
    assert json.loads(f.read_text(encoding="utf-8")) == {"oops": "a dict"}


@pytest.mark.parametrize("modname", ["fidelity", "wellsfargo"])
def test_acquire_takes_over_a_3h_old_lock_on_a_recycled_live_pid(modname, tmp_path, monkeypatch):
    """The auditor's repro end to end: a 3-hour-old lock whose pid is now a
    live, unrelated process. Acquire must succeed and leave that process be."""
    mod = __import__(modname)
    monkeypatch.setattr(mod, "_sessions_dir", lambda: tmp_path)
    lock = mod._lock_file(1) if modname == "fidelity" else mod._lock_file()
    child = _sleeper()
    try:
        time.sleep(0.3)
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text(str(child.pid))
        old = time.time() - 3 * 3600
        os.utime(lock, (old, old))
        got = (mod._acquire_profile_lock(1, timeout_s=5) if modname == "fidelity"
               else mod._acquire_profile_lock(timeout_s=5))
        assert Path(got).read_text().strip() == str(os.getpid())
        assert child.poll() is None
        mod._release_profile_lock(got)
    finally:
        child.kill()


@pytest.mark.parametrize("modname", ["fidelity", "wellsfargo"])
def test_acquire_still_waits_on_a_live_owner(modname, tmp_path, monkeypatch):
    """The owner started before its lock was written: never stolen."""
    mod = __import__(modname)
    monkeypatch.setattr(mod, "_sessions_dir", lambda: tmp_path)
    lock = mod._lock_file(1) if modname == "fidelity" else mod._lock_file()
    child = _sleeper()
    try:
        time.sleep(0.5)
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text(str(child.pid))          # written after the child started
        with pytest.raises(Exception, match="nothing was sent"):
            if modname == "fidelity":
                mod._acquire_profile_lock(1, timeout_s=1)
            else:
                mod._acquire_profile_lock(timeout_s=1)
        assert child.poll() is None
    finally:
        child.kill()
