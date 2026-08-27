"""The one branch that keeps ETF buys out of the RSA journal.

`_trade_worker` is shared by every origin — desk, mirror, exit, retry and now
etf — and a single `if` at the record site decides which journal a fill lands
in. If that branch ever inverts, ETF rows flow into trades.json, which
cloud_sync uploads wholesale to the paid public Plays board with the
identifying fields stripped. So it is exercised here against the real worker
rather than trusted by inspection.

The App class cannot be instantiated headlessly (CustomTkinter's DPI tracker
takes the process down), so the worker is called unbound against a stub that
supplies only the handful of attributes it touches.
"""

from __future__ import annotations

import sys
import threading
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import etf_journal
import trade_journal
from modules.outputs import AccountOutput, BrokerOutput


class StubApp:
    """Just enough App for _trade_worker to run to completion."""

    def __init__(self):
        self.logs = []
        self.completed = []
        self._quick_picks = []
        self.rendered_picks = 0

    # App.after is thread-safe and runs callbacks later; here, run them now so
    # the assertions see the finished state.
    def after(self, _ms, func=None, *args):
        if callable(func):
            func(*args)
        return None

    def _log(self, msg, tag=None):
        self.logs.append(msg)

    def _fetch_quote_price(self, broker, symbol, side="buy"):
        return 770.56

    def _trade_result_write(self, text, tag=None):
        self.logs.append(text)

    def _render_quick_picks(self, picks):
        self.rendered_picks += 1

    def _trade_broker_complete(self, batch, summary):
        self.completed.append((batch, summary))


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Isolate both journals and hand the worker a broker that always fills."""
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf_trades.json")
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")

    fake = types.SimpleNamespace(
        execute_trade=lambda **kw: BrokerOutput(
            broker="public", state="success",
            accounts=[
                AccountOutput(account_id="p1", ok=True, message="filled",
                              order_id="ord-1"),
                AccountOutput(account_id="p2", ok=True, message="filled",
                              order_id="ord-2"),
            ]),
    )
    monkeypatch.setattr(A, "_load_broker", lambda b: fake)
    monkeypatch.setattr(A, "_browser_slot", lambda b: None)
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)
    return StubApp()


def run(stub, batch, qty="1", symbol="SPY"):
    A.App._trade_worker(stub, "public", "buy", symbol, qty, False, batch)


ETF_BATCH = {"origin": "etf", "exposure": "sp500", "plan_id": "plan-7",
             "pending": {"public"}}
DESK_BATCH = {"origin": "desk", "pending": {"public"}}


# ------------------------------------------------------------------ routing

def test_an_etf_batch_records_only_to_the_etf_journal(wired):
    run(wired, dict(ETF_BATCH))
    assert len(etf_journal.get_trades()) == 2
    assert trade_journal.get_trades() == []


def test_a_desk_batch_still_records_to_the_rsa_journal(wired):
    run(wired, dict(DESK_BATCH), symbol="AIFA")
    assert len(trade_journal.get_trades()) == 2
    assert etf_journal.get_trades() == []


def test_the_two_origins_do_not_bleed_into_each_other(wired):
    run(wired, dict(DESK_BATCH), symbol="AIFA")
    run(wired, dict(ETF_BATCH), symbol="SPY")
    assert {t["symbol"] for t in trade_journal.get_trades()} == {"AIFA"}
    assert {t["symbol"] for t in etf_journal.get_trades()} == {"SPY"}


@pytest.mark.parametrize("origin", ["desk", "mirror", "exit", "retry", ""])
def test_every_non_etf_origin_goes_to_the_rsa_journal(wired, origin):
    """Only the exact string "etf" diverts. A typo elsewhere must not silently
    start writing investments into the RSA record."""
    run(wired, {"origin": origin, "pending": {"public"}})
    assert len(trade_journal.get_trades()) == 2
    assert etf_journal.get_trades() == []


# ------------------------------------------------------------------ payload

def test_the_etf_row_carries_its_exposure_and_plan(wired):
    run(wired, dict(ETF_BATCH))
    row = etf_journal.get_trades()[0]
    assert row["exposure"] == "sp500"
    assert row["plan_id"] == "plan-7"


def test_one_row_per_filled_account(wired):
    run(wired, dict(ETF_BATCH))
    assert {t["account_id"] for t in etf_journal.get_trades()} == {"p1", "p2"}


def test_the_brokers_order_id_survives(wired):
    run(wired, dict(ETF_BATCH))
    assert {t["order_id"] for t in etf_journal.get_trades()} == {"ord-1", "ord-2"}


def test_the_price_is_marked_as_a_quote_not_a_fill(wired):
    """It is one lookup stamped onto every account, exactly as on the RSA
    side — recording it as a fill would be a lie about all but one row."""
    run(wired, dict(ETF_BATCH))
    assert {t["price_source"] for t in etf_journal.get_trades()} == {
        etf_journal.PRICE_QUOTE}


def test_a_fractional_quantity_is_recorded_intact(wired):
    run(wired, dict(ETF_BATCH), qty="0.15573")
    assert {t["qty"] for t in etf_journal.get_trades()} == {0.15573}


# ------------------------------------------------------------------ side effects

def test_a_failed_account_is_not_recorded(wired, monkeypatch):
    mixed = types.SimpleNamespace(execute_trade=lambda **kw: BrokerOutput(
        broker="public", state="partial",
        accounts=[AccountOutput(account_id="p1", ok=True, message="filled"),
                  AccountOutput(account_id="p2", ok=False,
                                message="insufficient funds")]))
    monkeypatch.setattr(A, "_load_broker", lambda b: mixed)
    run(wired, dict(ETF_BATCH))
    assert [t["account_id"] for t in etf_journal.get_trades()] == ["p1"]


def test_a_dry_run_records_nothing_anywhere(wired):
    A.App._trade_worker(wired, "public", "buy", "SPY", "1", True, dict(ETF_BATCH))
    assert etf_journal.get_trades() == []
    assert trade_journal.get_trades() == []


def test_an_etf_buy_does_not_redraw_the_rsa_pick_list(wired):
    run(wired, dict(ETF_BATCH))
    assert wired.rendered_picks == 0


def test_a_desk_buy_still_redraws_the_pick_list(wired):
    run(wired, dict(DESK_BATCH), symbol="AIFA")
    assert wired.rendered_picks == 1


def test_the_batch_is_reported_back_so_the_guard_can_release(wired):
    """_trade_batch_finish clears _trade_in_flight, and an origin that takes
    the guard without reporting back would brick trading until restart."""
    batch = dict(ETF_BATCH)
    run(wired, batch)
    assert len(wired.completed) == 1
    reported_batch, summary = wired.completed[0]
    assert reported_batch is batch
    assert summary["broker"] == "public"
    assert summary["ok_accounts"] == 2


class Finisher:
    """Just enough App for _trade_batch_finish to run to completion.

    Nothing here is a widget: no _live_card and no _trade_execute_btn, so the
    strip and the button are skipped and what is left is the bookkeeping.
    """

    def __init__(self, in_flight):
        self._brokers_in_flight = set(in_flight)
        self._trade_in_flight = True
        self._live_batches = []
        self.invest_done = 0
        self.notes = []

    # Real, not stubbed — releasing a broker is bookkeeping this test asserts.
    _release_broker = A.App._release_broker

    def _invest_batch_done(self):
        self.invest_done += 1

    def _log(self, *_a, **_k):
        pass

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _render_done_receipt(self, **_k):
        pass

    def _trade_result_write(self, *_a, **_k):
        pass

    def _refresh_trade_busy(self):
        pass

    def _live_hide(self):
        pass


def etf_batch(brokers, symbol):
    return {"results": [{"broker": b, "ok_accounts": 1, "fail_accounts": 0,
                         "shares": 1.0, "errors": [], "state": "success",
                         "accounts": [], "fill_price": None} for b in brokers],
            "side": "buy", "symbol": symbol, "qty": "1", "dry_run": True,
            "origin": "etf", "all_brokers": sorted(brokers),
            "pending": set(), "finished": False, "started": datetime.now()}


def test_an_etf_batch_does_not_borrow_the_desk_guard():
    """An invest run can be several batches — the fractional brokers buy SPY
    while the whole-share ones buy SCHX. Borrowing _trade_in_flight would let
    the first batch to land re-arm the button while the second was still
    running, and the next click would buy the rest of the plan a second time.

    The flag is derived from _brokers_in_flight rather than cleared by whichever
    batch lands first, so this asks the behaviour directly. It used to grep the
    source for the origin branch that derivation replaced, which made it fail
    against the very rewrite that fixed the bug it describes.
    """
    f = Finisher(["public", "robinhood", "fidelity"])

    A.App._trade_batch_finish(f, etf_batch(["public", "robinhood"], "SPY"))
    assert f._brokers_in_flight == {"fidelity"}
    assert f._trade_in_flight is True       # the SCHX leg is still out
    assert f.invest_done == 1

    A.App._trade_batch_finish(f, etf_batch(["fidelity"], "SCHX"))
    assert f._brokers_in_flight == set()
    assert f._trade_in_flight is False
    assert f.invest_done == 2


def test_only_an_etf_batch_touches_the_invest_counter():
    """The desk shares _trade_batch_finish. If origin stopped being checked, a
    plain sell would decrement a counter no invest run is waiting on."""
    f = Finisher(["public"])
    desk = etf_batch(["public"], "AIFA")
    desk["origin"] = "desk"

    A.App._trade_batch_finish(f, desk)
    assert f._trade_in_flight is False
    assert f.invest_done == 0


def test_the_invest_counter_only_releases_once_every_batch_has_landed():
    class Counter:
        _invest_in_flight = 2
        _frames = {"invest": object()}
        def _invalidate_page(self, *names):
            pass
        def _render_invest(self, *sections):
            raise AssertionError("should not re-render while a batch is live")

    c = Counter()
    A.App._invest_batch_done(c)
    assert c._invest_in_flight == 1        # first of two batches home

    c._render_invest = lambda *sections: setattr(c, "rendered", True)
    A.App._invest_batch_done(c)
    assert c._invest_in_flight == 0
    assert getattr(c, "rendered", False) is True


def test_the_counter_never_goes_negative():
    class Counter:
        _invest_in_flight = 0
        _frames = {}
        def _invalidate_page(self, *names):
            pass
        def _render_invest(self, *sections):
            pass

    c = Counter()
    A.App._invest_batch_done(c)
    assert c._invest_in_flight == 0
