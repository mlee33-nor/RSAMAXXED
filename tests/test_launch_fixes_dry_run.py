"""A dry run's claims are released when dry run is switched off.

A dry run settles a play like a live one, so the sold-once record called every
play it had walked through "handled" — and switching to live sold none of them.
The fix records which claims were dry and frees exactly those on the switch.

Pure logic against a stand-in: no App, no Tk, no broker.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle


class _Var:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v

    def set(self, v):
        self.v = v


class _Auto:
    def __init__(self, dry=True, sold=()):
        self._autosell_enabled = _Var(True)
        self._autosell_dry_run = _Var(dry)
        self._autosell_fracs = _Var(True)
        self._autosell_sold = set(sold)
        self._autosell_queue = []
        self._trade_in_flight = False
        self._queue_busy = True
        self.logs, self.notes, self.fired = [], [], []
        cls = A.App
        for name in ("_autosell_toggled", "_save_autosell_state", "_reading_keys",
                     "_autosell_fire", "_autosell_read_done", "_autosell_key"):
            setattr(self, name, types.MethodType(getattr(cls, name), self))

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _journal_shortfalls(self, resolved):
        return []

    def _pump_later(self, ms):
        pass

    def _exit_fire(self, resolved, dry_run=False, autosell=False):
        self.fired.append(dry_run)


@pytest.fixture(autouse=True)
def _state_file(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", tmp_path / "autosell_state.json")
    return tmp_path / "autosell_state.json"


def _task(sym="GRNQ"):
    return lifecycle.SellTask(symbol=sym, alert_symbol=sym, alert_date="2026-10-01",
                              status="exit_called", brokers=("Robinhood",), accounts=1)


def _resolved(task):
    return types.SimpleNamespace(task=task, ok=True, missing=(), errors=(),
                                 legs=(), describe=lambda: "Robinhood x1")


def test_release_frees_only_dry_claims():
    sold = {"a", "b", "live"}
    dry = {"a", "b", "gone"}
    assert A._release_dry_claims(sold, dry) == ["a", "b"]
    assert sold == {"live"} and dry == set()


def test_a_dry_fire_is_recorded_and_persisted(_state_file):
    app = _Auto(dry=True)
    key = app._autosell_key(_task())
    app._autosell_sold.add(key)
    app._autosell_fire(_resolved(_task()))
    assert app.fired == [True]
    state = json.loads(_state_file.read_text())
    assert key in state["sold"] and state["dry_sold"] == [key]


def test_switching_dry_run_off_releases_what_the_dry_run_claimed(_state_file):
    app = _Auto(dry=True, sold={"live-key"})
    key = app._autosell_key(_task())
    app._autosell_sold.add(key)
    app._autosell_fire(_resolved(_task()))

    app._autosell_dry_run.set(False)
    app._autosell_toggled()
    assert key not in app._autosell_sold
    assert "live-key" in app._autosell_sold          # a live sale stays sold
    state = json.loads(_state_file.read_text())
    assert key not in state["sold"] and state["dry_sold"] == []


def test_a_live_fire_is_never_released(_state_file):
    app = _Auto(dry=False)
    key = app._autosell_key(_task())
    app._autosell_sold.add(key)
    A._autosell_dry_claims(app).add(key)              # stale mark from earlier
    app._autosell_fire(_resolved(_task()))
    assert app.fired == [False]
    app._autosell_toggled()
    assert key in app._autosell_sold


def test_turning_dry_run_on_releases_nothing():
    app = _Auto(dry=True)
    app._autosell_sold.add("k")
    A._autosell_dry_claims(app).add("k")
    app._autosell_toggled()
    assert "k" in app._autosell_sold


def test_a_state_file_from_before_this_loads_unchanged():
    sold, released = A._autosell_restore({"sold": ["a"]})
    assert sold == {"a"} and released == []
