"""NEEDS ATTENTION on the Mirror page lists only what still needs a human.

It used to list every run that filled nowhere for 30 days — including picks a
later run or a Trade Desk buy had since bought — with no way to clear one. And
a run the app closed under (RETO, 2026-09-29) was not listed at all.
"""
from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


def _app(trades=(), dismissed=(), active=()):
    app = types.SimpleNamespace(
        _mirror_attention_dismissed=set(dismissed),
        _mirror_active=[{"mirror_run": i} for i in active])
    app._local_stamp = A.App._local_stamp
    app._mirror_needs_attention = types.MethodType(A.App._mirror_needs_attention, app)
    A.trade_journal.get_trades = lambda broker=None: list(trades)
    return app


def _at(minutes_ago):
    return (datetime.now() - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")


def _run(id_, sym, started, finished=True, **kw):
    return dict(id=id_, symbol=sym, side="buy", started_at=started,
                finished_at=started if finished else "", ok_accounts=0,
                fail_accounts=5, brokers=["chase"], **kw)


def _buy(sym, when_local):
    utc = datetime.fromisoformat(when_local).astimezone(timezone.utc)
    return {"symbol": sym, "side": "buy", "timestamp": utc.isoformat()}


def test_a_pick_bought_later_leaves_the_list(monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", A.trade_journal.get_trades)
    failed = _run("r1", "BGM", _at(120))
    app = _app(trades=[_buy("BGM", _at(60))])
    assert app._mirror_needs_attention([failed], [failed]) == []


def test_a_buy_from_before_the_run_does_not_clear_it(monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", A.trade_journal.get_trades)
    failed = _run("r1", "BGM", _at(120))
    app = _app(trades=[_buy("BGM", _at(600))])
    assert [r["id"] for r in app._mirror_needs_attention([failed], [failed])] == ["r1"]


def test_a_dismissed_run_stays_gone(monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", A.trade_journal.get_trades)
    failed = _run("r1", "BGM", _at(120))
    app = _app(dismissed={"r1"})
    assert app._mirror_needs_attention([failed], [failed]) == []


def test_a_run_the_app_closed_under_is_listed(monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", A.trade_journal.get_trades)
    dead = _run("r2", "RETO", _at(90), finished=False)
    out = _app()._mirror_needs_attention([dead], [])
    assert [r["symbol"] for r in out] == ["RETO"]
    assert out[0]["_interrupted"]


def test_a_run_still_going_is_not_listed(monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", A.trade_journal.get_trades)
    live = _run("r3", "KUST", _at(90), finished=False)
    fresh = _run("r4", "SHFS", _at(5), finished=False)
    app = _app(active={"r3"})
    assert app._mirror_needs_attention([live, fresh], []) == []


def test_journal_utc_stamps_compare_in_local_time():
    local = "2026-09-29T08:59:13"
    utc = datetime.fromisoformat(local).astimezone(timezone.utc).isoformat()
    assert A.App._local_stamp(utc) == local
    assert A.App._local_stamp(local) == local


def test_an_interrupted_run_stays_until_every_broker_bought(monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", A.trade_journal.get_trades)
    dead = _run("r5", "RETO", _at(90), finished=False)
    dead["brokers"] = ["public", "fidelity"]
    part = [dict(_buy("RETO", _at(80)), broker="public")]
    assert _app(trades=part)._mirror_needs_attention([dead], [])
    full = part + [dict(_buy("RETO", _at(70)), broker="fidelity")]
    assert _app(trades=full)._mirror_needs_attention([dead], []) == []
