"""modules.atomic.write_text / write_json under concurrency.

Every writer used a FIXED `<file>.tmp`. Two threads saving the same file shared
it: the first rename moved it away and the second raised FileNotFoundError,
which most callers swallowed -- 97 of 160 concurrent writes vanished.
"""

from __future__ import annotations

import inspect
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import atomic


def test_concurrent_writes_to_one_file_all_succeed(tmp_path):
    target = tmp_path / "state.json"
    errors: list = []

    def worker(n):
        try:
            for i in range(20):
                atomic.write_json(target, {"writer": n, "i": i})
        except Exception as e:          # the failure mode being fixed
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert set(json.loads(target.read_text("utf-8"))) == {"writer", "i"}
    assert list(tmp_path.glob("*.tmp")) == []


def test_a_failed_write_keeps_the_old_file_and_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    atomic.write_json(target, {"v": 1})

    def die(src, dst, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(atomic, "replace", die)
    with pytest.raises(OSError):
        atomic.write_json(target, {"v": 2})
    assert json.loads(target.read_text("utf-8")) == {"v": 1}
    assert list(tmp_path.glob("*.tmp")) == []


def test_unserialisable_data_never_touches_the_file(tmp_path):
    target = tmp_path / "state.json"
    atomic.write_json(target, {"v": 1})
    with pytest.raises(TypeError):
        atomic.write_json(target, {"v": object()})
    assert json.loads(target.read_text("utf-8")) == {"v": 1}


def test_app_state_writers_use_the_atomic_helper(tmp_path, monkeypatch):
    import app as A
    for name, fn, arg in (("SELLS_CONFIRMED_FILE", A._save_confirmed_sells, {"X"}),
                          ("PICKS_DONE_FILE", A._save_done_picks, {("X", "d")}),
                          ("COVERAGE_READ_FILE", A._save_coverage_read, "abc")):
        path = tmp_path / f"{name}.json"
        monkeypatch.setattr(A, name, path)
        fn(arg)
        assert json.loads(path.read_text("utf-8"))
    assert list(tmp_path.glob("*.tmp")) == []
    assert "PICKS_FILE.write_text(" not in inspect.getsource(A)


def test_module_writers_use_the_atomic_helper():
    import balances
    import lifecycle
    for fn in (balances.save, lifecycle.save_state):
        src = inspect.getsource(fn)
        assert "atomic.write_json" in src and ".tmp" not in src
