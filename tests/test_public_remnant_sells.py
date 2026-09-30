"""Public exits sold at what each account holds, and Public remnants cleared.

IPDN, 2026-09-24: an exit at Robinhood and Schwab (rounded up there) while
Public returned 1/30 of a share per account. Nothing ever sold those 21
remnants. These pin the three pieces that fix it: which plays produce a
remnant task, how the exit batch tells Public to size from holdings, and that
the journal records the quantity each account actually sold.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle
import trade_journal
from modules.outputs import AccountOutput, BrokerOutput


def leg(broker, state, called=""):
    return A.SellLeg(broker=broker, bought=1.0, sold=0.0,
                     left=0.0 if state == A.SELL_DONE else 1.0,
                     state=state, alert_date=called)


def play(*legs, symbol="IPDN"):
    return A.SellPlay(symbol=symbol, exit_price=4.48, legs=tuple(legs),
                      last_alert="2026-09-24T13:33:44")


@pytest.fixture(autouse=True)
def _accounts(monkeypatch):
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: [(f"a{i}", 1.0) for i in range(21)])
    # Never the real journal: the caps are pinned in tests of their own.
    monkeypatch.setattr(A, "_public_sell_caps",
                        lambda symbols, rows=None: {"Public 1 BROKERAGE (0001)": 1.0})
    # The exit-elsewhere remnant clear is OFF pending the owner's decision
    # (see PUBLIC_REMNANT_CLEAR). These tests exercise it, so switch it on.
    monkeypatch.setattr(A, "PUBLIC_REMNANT_CLEAR", True)


def test_the_remnant_clear_is_off_by_default_and_then_makes_no_tasks(monkeypatch):
    monkeypatch.setattr(A, "PUBLIC_REMNANT_CLEAR", False)
    p = play(leg("robinhood", A.SELL_DONE, "2026-09-24"),
             leg("public", A.SELL_WAIT))
    assert A._public_remnant_tasks([p]) == []


# ------------------------------------------------------------ remnant tasks

def test_an_exit_elsewhere_leaves_a_public_remnant_task():
    p = play(leg("robinhood", A.SELL_DONE, "2026-09-24"),
             leg("public", A.SELL_WAIT))
    (t,) = A._public_remnant_tasks([p])
    assert t.status == A.REMNANT_STATUS
    assert t.brokers == ("Public",)
    assert t.alert_date == "2026-09-24"
    assert t.accounts == 21


def test_no_exit_called_anywhere_means_no_remnant_task():
    p = play(leg("robinhood", A.SELL_WAIT), leg("public", A.SELL_WAIT))
    assert A._public_remnant_tasks([p]) == []


def test_an_exit_called_at_public_itself_is_the_exit_not_a_remnant():
    p = play(leg("robinhood", A.SELL_NOW, "2026-09-24"),
             leg("public", A.SELL_NOW, "2026-09-24"))
    assert A._public_remnant_tasks([p]) == []


def test_public_already_out_needs_no_remnant_task():
    p = play(leg("robinhood", A.SELL_DONE, "2026-09-24"),
             leg("public", A.SELL_DONE))
    assert A._public_remnant_tasks([p]) == []


def test_the_renamed_ticker_is_carried_for_the_holdings_read():
    p = play(leg("robinhood", A.SELL_DONE, "2026-09-24"),
             leg("public", A.SELL_WAIT), symbol="AIFA")
    (t,) = A._public_remnant_tasks([p], {"AIFA": "AGAE"})
    assert (t.symbol, t.alert_symbol) == ("AIFA", "AGAE")


def test_a_remnant_key_never_blocks_a_later_exit_at_public():
    rem = lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                             alert_date="2026-09-24", status=A.REMNANT_STATUS,
                             brokers=("Public",))
    ext = lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                             alert_date="2026-09-24", status="exit_called",
                             brokers=("Public",))
    assert A.App._autosell_key(None, rem) != A.App._autosell_key(None, ext)


# ------------------------------------------------ exit batch -> Public kwargs

class FireStub:
    def __init__(self):
        self.started = []
        self.logs = []

    def _push_notification(self, *a, **k):
        pass

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _live_start(self, batch):
        self.batch = batch

    def _run_in_thread(self, fn, *args):
        self.started.append(args)

    def _trade_worker(self, *a, **k):   # never called: _run_in_thread is stubbed
        pass


def resolved(status, legs):
    task = lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                              alert_date="2026-09-24", status=status,
                              brokers=tuple(l.broker for l in legs))
    return lifecycle.ResolvedExit(task=task, legs=tuple(legs))


def bleg(name, key, qty="0.03333"):
    return lifecycle.BrokerLeg(broker=name, key=key, qty=qty, accounts=1,
                               low=float(qty), high=float(qty))


def test_an_exit_sizes_public_from_holdings_and_leaves_others_alone():
    s = FireStub()
    A.App._exit_fire(s, resolved("exit_called", [bleg("Public", "public", "1"),
                                                 bleg("Robinhood", "robinhood", "1")]))
    kw = s.batch["broker_kwargs"]
    assert kw == {"public": {"size_from_holdings": True, "remnant_only": False,
                             "also_symbols": ("IPDN",),
                             "max_by_account": {"Public 1 BROKERAGE (0001)": "1"}}}


def test_a_remnant_task_asks_public_for_remnants_only():
    s = FireStub()
    A.App._exit_fire(s, resolved(A.REMNANT_STATUS, [bleg("Public", "public")]))
    assert s.batch["broker_kwargs"]["public"]["remnant_only"] is True


# ------------------------------------------- worker passes kwargs, journals qty

class WorkerStub:
    def __init__(self):
        self._quick_picks = []

    def after(self, _ms, func=None, *args):
        if callable(func):
            func(*args)

    def _log(self, *a, **k):
        pass

    def _fetch_quote_price(self, *a, **k):
        return 4.26

    def _trade_result_write(self, *a, **k):
        pass

    def _render_quick_picks(self, *a):
        pass

    def _trade_broker_complete(self, batch, summary):
        self.summary = summary


def test_the_worker_passes_public_its_options_and_journals_each_accounts_qty(
        tmp_path, monkeypatch):
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    seen = {}

    def execute_trade(**kw):
        seen.update(kw)
        return BrokerOutput(broker="public", state="success", accounts=[
            AccountOutput(account_id="Public 1 BROKERAGE (0001)", ok=True,
                          message="order placed (0.98 sh)", order_id="o1",
                          extra={"qty": "0.98"}),
            AccountOutput(account_id="Public 1 BROKERAGE (0002)", ok=True,
                          message="order placed (0.03333 sh)", order_id="o2",
                          extra={"qty": "0.03333"}),
        ])

    monkeypatch.setattr(A, "_load_broker",
                        lambda b: types.SimpleNamespace(execute_trade=execute_trade))
    monkeypatch.setattr(A, "_browser_slot", lambda b: None)
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)

    batch = {"origin": "exit", "pending": {"public"},
             "broker_kwargs": {"public": {"size_from_holdings": True,
                                          "remnant_only": False,
                                          "also_symbols": ("IPDN",)}}}
    stub = WorkerStub()
    A.App._trade_worker(stub, "public", "sell", "IPDN", "1", False, batch)

    assert seen["size_from_holdings"] is True
    rows = trade_journal.get_trades()
    assert sorted(r["qty"] for r in rows) == [0.03333, 0.98]
    assert stub.summary["shares"] == pytest.approx(1.01333)
