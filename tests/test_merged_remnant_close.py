"""A leg the broker reads EMPTY, after we already sold there once, is closed.

2026-11-09, from the owner's own board. NCT, ZCMD, VIVK (Robinhood) and CPOP
(Wells Fargo) were bought twice into the same accounts; FRGT was bought 5 at a
time. A reverse split merged each lot into ONE share, that share was sold, and
the journal kept counting the rest. Auto-sell then read every account empty,
called it a dispute, retried three times and gave up -- and the leg sat on
Sell now waiting for a manual Resolve.

The close is driven by the broker's answer, never by the journal alone. The
guard that keeps the SMTK parser bug (ten held accounts read as empty) from
closing real shares: an account must ALREADY have been exited here.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A

TJ = A.trade_journal


@pytest.fixture
def jfile(tmp_path, monkeypatch):
    monkeypatch.setattr(TJ, "_FILE", tmp_path / "trades.json")
    TJ._cache.update({"rows": None, "key": None})
    with A._SELL_ROWS_LOCK:
        A._SELL_ROWS_CACHE.clear()
    monkeypatch.setattr(A, "_known_renames", lambda *a, **k: {})

    def row(sym, broker, side, qty, acct, day):
        TJ.record_trade(broker=broker, account_id=acct, side=side, symbol=sym,
                        qty=qty, fill_price=1.0, when=f"{day}T12:00:00+00:00")
    return row


def task(sym):
    return SimpleNamespace(symbol=sym, alert_symbol=sym)


def open_accounts(broker, sym):
    return A._leg_open_accounts(broker, (sym,))


def test_two_buys_one_sell_read_empty_is_closed(jfile):
    for a in ("r1", "r2", "r3"):
        jfile("NCT", "robinhood", "buy", 1, a, "2026-03-31")
        jfile("NCT", "robinhood", "buy", 1, a, "2026-09-15")
        jfile("NCT", "robinhood", "sell", 1, a, "2026-09-30")
    assert len(open_accounts("robinhood", "NCT")) == 3

    lines = A._close_merged_remnants(task("NCT"), ["Robinhood"])

    assert open_accounts("robinhood", "NCT") == []
    assert len(lines) == 1 and "3 accounts" in lines[0]
    closes = [t for t in TJ.get_trades() if t["side"] == TJ.SIDE_CLOSE]
    assert len(closes) == 3
    assert all(c["fill_price"] is None for c in closes)      # never P/L
    assert all(c["close_reason"] == TJ.CLOSE_RECONCILED for c in closes)


def test_a_five_share_lot_merged_to_one_is_closed(jfile):
    jfile("FRGT", "fidelity", "buy", 5, "f1", "2026-10-15")
    jfile("FRGT", "fidelity", "sell", 1, "f1", "2026-10-30")
    A._close_merged_remnants(task("FRGT"), ["Fidelity"])
    assert open_accounts("fidelity", "FRGT") == []


def test_never_sold_accounts_read_empty_are_not_closed(jfile):
    """The SMTK shape: a bad read says empty, nothing was ever sold. Untouched."""
    for a in ("f1", "f2"):
        jfile("SMTK", "fidelity", "buy", 1, a, "2026-09-01")
    assert A._close_merged_remnants(task("SMTK"), ["Fidelity"]) == []
    assert len(open_accounts("fidelity", "SMTK")) == 2


def test_a_buy_after_the_last_sell_is_not_closed(jfile):
    """Re-bought after exiting: the open share is a NEW position, not a remnant."""
    jfile("ABC", "robinhood", "buy", 1, "r1", "2026-01-01")
    jfile("ABC", "robinhood", "sell", 1, "r1", "2026-02-01")
    jfile("ABC", "robinhood", "buy", 1, "r1", "2026-03-01")
    assert A._close_merged_remnants(task("ABC"), ["Robinhood"]) == []
    assert open_accounts("robinhood", "ABC") == [("r1", 1.0)]


def test_only_the_accounts_that_qualify_are_closed(jfile):
    jfile("VIVK", "robinhood", "buy", 1, "r1", "2026-07-15")
    jfile("VIVK", "robinhood", "buy", 1, "r1", "2026-10-01")
    jfile("VIVK", "robinhood", "sell", 1, "r1", "2026-10-19")
    jfile("VIVK", "robinhood", "buy", 1, "r2", "2026-07-15")   # never sold
    A._close_merged_remnants(task("VIVK"), ["Robinhood"])
    assert open_accounts("robinhood", "VIVK") == [("r2", 1.0)]


def test_a_fractional_exit_is_left_for_the_late_round_up(jfile):
    """Public can credit 0.2, then round up to 0.98 weeks later."""
    jfile("GRNQ", "public", "buy", 1, "p1", "2026-07-01")
    jfile("GRNQ", "public", "buy", 1, "p1", "2026-07-20")
    jfile("GRNQ", "public", "sell", 0.2, "p1", "2026-08-01")
    assert A._close_merged_remnants(task("GRNQ"), ["Public"]) == []


def test_only_brokers_the_read_called_empty_are_touched(jfile):
    jfile("CPOP", "wellsfargo", "buy", 2, "w1", "2026-07-09")
    jfile("CPOP", "wellsfargo", "sell", 1, "w1", "2026-09-29")
    jfile("CPOP", "robinhood", "buy", 2, "r1", "2026-07-09")
    jfile("CPOP", "robinhood", "sell", 1, "r1", "2026-09-29")
    A._close_merged_remnants(task("CPOP"), ["Wells Fargo"])
    assert open_accounts("wellsfargo", "CPOP") == []
    assert open_accounts("robinhood", "CPOP") == [("r1", 1.0)]


def test_a_closed_leg_is_no_longer_disputed(jfile):
    """What stops the retry loop: the dispute check reads the journal as it now is."""
    jfile("ZCMD", "robinhood", "buy", 2, "r1", "2026-09-01")
    jfile("ZCMD", "robinhood", "sell", 1, "r1", "2026-10-15")
    t = task("ZCMD")
    assert A.App._journal_disputes(SimpleNamespace(), t, ["Robinhood"])
    A._close_merged_remnants(t, ["Robinhood"])
    assert A.App._journal_disputes(SimpleNamespace(), t, ["Robinhood"]) == []
