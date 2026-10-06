"""Auto-sell at a one-quantity broker never sells more than this tool bought.

lifecycle.resolve sizes a non-Public leg at the smallest LIVE balance and the
module sends that to every account. A live balance includes the customer's own
shares, so one account holding 100 of his and 1 of ours read as "sell 101".
The cap is the same rule Public uses: the gross raw buy, which a reverse split
can only shrink below, never above.

Pure logic: the real _exit_fire runs against a stand-in; no order is placed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle


def _t(side, qty, acct="R1", broker="robinhood", sym="IPDN"):
    return {"broker": broker, "symbol": sym, "account_id": acct,
            "side": side, "qty": qty}


def test_cap_is_the_smallest_gross_buy_among_open_accounts():
    rows = [_t("buy", 1, "R1"), _t("buy", 2, "R2"),
            _t("buy", 1, "R3"), _t("sell", 1, "R3"),      # out of R3
            _t("buy", 5, "C1", broker="chase")]
    assert A._broker_sell_cap("robinhood", ("IPDN",), rows) == (1.0, 2)


def test_cap_sums_the_alert_and_current_ticker():
    rows = [_t("buy", 1, "R1", sym="AGAE"), _t("buy", 1, "R1", sym="AIFA")]
    assert A._broker_sell_cap("robinhood", ("AIFA", "AGAE"), rows) == (2.0, 1)


def test_no_open_account_means_no_cap():
    assert A._broker_sell_cap("robinhood", ("IPDN",),
                              [_t("buy", 1), _t(A.trade_journal.SIDE_CLOSE, 1)]) == (None, 0)


@pytest.mark.parametrize("live,cap,sent,cut", [
    ("101", 1.0, "1", True),          # customer's own 100 are not ours
    ("1", 1.0, "1", False),           # rounded up: whole share, ours
    ("0.05", 1.0, "0.05", False),     # un-rounded remnant
    ("6", None, "6", False),          # nothing to cap against: unchanged
])
def test_capped_leg_qty(live, cap, sent, cut):
    leg = lifecycle.BrokerLeg(broker="Robinhood", key="robinhood", qty=live,
                              accounts=1, low=float(live), high=float(live))
    assert A._capped_leg_qty(leg, cap) == (sent, cut)


class _Fire:
    def __init__(self):
        self.started, self.logs, self.notes = [], [], []

    def _push_notification(self, msg, kind="info"):
        self.notes.append(msg)

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _live_start(self, batch):
        self.batch = batch

    def _run_in_thread(self, fn, *args):
        self.started.append(args)

    def _trade_worker(self, *a, **k):
        pass


def _resolved(qty="101", accounts=1):
    task = lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                              alert_date="2026-10-01", status="exit_called",
                              brokers=("Robinhood",))
    leg = lifecycle.BrokerLeg(broker="Robinhood", key="robinhood", qty=qty,
                              accounts=accounts, low=float(qty), high=float(qty))
    return lifecycle.ResolvedExit(task=task, legs=(leg,))


@pytest.fixture()
def journal(monkeypatch):
    rows = []
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda *a, **k: list(rows))
    return rows


def test_autosell_sends_the_capped_quantity(journal):
    journal.append(_t("buy", 1))
    s = _Fire()
    A.App._exit_fire(s, _resolved("101"), autosell=True)
    (args,) = s.started
    assert args[0] == "robinhood" and args[3] == "1"
    assert any("more than this tool bought" in m for m in s.logs)


def test_a_manual_exit_keeps_its_size_but_warns(journal):
    journal.append(_t("buy", 1))
    s = _Fire()
    A.App._exit_fire(s, _resolved("101"))
    assert s.started[0][3] == "101"
    assert any("may be your own shares" in m for m in s.logs)


def test_an_ordinary_exit_is_untouched_and_silent(journal):
    journal.append(_t("buy", 1))
    s = _Fire()
    A.App._exit_fire(s, _resolved("1"), autosell=True)
    assert s.started[0][3] == "1" and not s.logs[1:] and not s.notes


def test_more_holding_accounts_than_we_bought_in_is_called_out(journal):
    journal.append(_t("buy", 1))
    s = _Fire()
    A.App._exit_fire(s, _resolved("1", accounts=3), autosell=True)
    assert any("this tool bought in 1" in m for m in s.logs)
