"""The sells card is organised by PLAY, and a play is measured in SHARES.

Two separate complaints, one model.

1. An exit is called per brokerage and they arrive days apart, so one ticker
   produced up to four alert rows spread across three tabs. On 2026-08-27 BYAH
   sat under Sell Alerts, Partial and Sold simultaneously, and VMAR — 28 shares
   still held across five brokerages at a $9.73 exit — rendered as one row
   reading "0/4". Nothing on screen answered "where do I stand on this play".

2. Counting accounts instead of shares made LBGJ at Robinhood read "3/3 sold"
   while three shares were still open there: six were bought across three
   accounts and three were sold, so the account sets matched exactly and the
   arithmetic looked finished.

`_sell_plays` folds the exit feed and the journal into one row per ticker, with
a line per brokerage. These are plain functions, so no App instance is needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


def exit_alert(symbol, *brokers, date="2026-08-27", price=1.5, posted=None):
    """An exit as the feed writes it: one ticker, the brokerages it names."""
    return {"symbol": symbol, "sell_date": date, "exit_price": price,
            "posted_at": posted or f"{date}T17:40:18+00:00",
            "legs": [{"broker": b, "accounts_low": 1} for b in brokers]}


def trade(symbol, broker, side, qty=1.0, account="a1"):
    return {"symbol": symbol, "broker": broker, "side": side, "qty": qty,
            "account_id": account, "fill_price": 1.0, "timestamp": "2026-08-07T00:00:00"}


@pytest.fixture
def journal(monkeypatch):
    """Point the model at a journal we control, and at no trade log."""
    def _set(rows):
        monkeypatch.setattr(A.trade_journal, "split_adjusted", lambda *a, **k: rows)
        monkeypatch.setattr(A, "_load_trade_attempts", lambda: {})
    return _set


def leg(play, broker):
    return next(l for l in play.legs if l.broker == broker)


# ------------------------------------------------------- the VMAR shape

def test_a_play_shows_every_brokerage_not_just_the_one_that_was_called(journal):
    """VMAR: sold at Public, called at Chase, still held at four others.

    The old card showed one row ("0/4") and left you thinking you were out.
    """
    journal([trade("VMAR", "public", "buy", 20), trade("VMAR", "public", "sell", 20)]
            + [trade("VMAR", "chase", "buy", 4)]
            + [trade("VMAR", "wellsfargo", "buy", 10)]
            + [trade("VMAR", "fennel", "buy", 1)])

    play, = A._sell_plays([exit_alert("VMAR", "Chase", price=9.73)])

    assert play.bought == 35 and play.left == 15 and play.sold == 20
    assert play.bucket == "now"
    assert leg(play, "chase").state == A.SELL_NOW
    assert leg(play, "public").state == A.SELL_DONE
    # The whole point: these are visible, not implied by absence.
    assert {l.broker for l in play.of(A.SELL_WAIT)} == {"wellsfargo", "fennel"}
    assert play.ready_value == pytest.approx(4 * 9.73)


# ------------------------------------------------------- the LBGJ shape

def test_a_part_sold_brokerage_counts_shares_not_accounts(journal):
    """Six bought across three accounts, three sold: three shares are still there."""
    journal([trade("LBGJ", "robinhood", "buy", 1, f"acct{i}") for i in range(3)]
            + [trade("LBGJ", "robinhood", "buy", 1, f"acct{i}") for i in range(3)]
            + [trade("LBGJ", "robinhood", "sell", 1, f"acct{i}") for i in range(3)])

    play, = A._sell_plays([exit_alert("LBGJ", "Robinhood")])
    rh = leg(play, "robinhood")

    assert (rh.bought, rh.sold, rh.left) == (6, 3, 3)
    assert rh.state == A.SELL_NOW      # NOT "sold", and NOT filed under Partial
    assert play.bucket == "now"


# ------------------------------------------------------- the three buckets

def test_a_play_with_anything_sellable_is_actionable_even_if_others_wait(journal):
    journal([trade("X", "chase", "buy", 1), trade("X", "fennel", "buy", 1)])
    play, = A._sell_plays([exit_alert("X", "Chase")])
    assert play.bucket == "now"
    assert leg(play, "fennel").state == A.SELL_WAIT


def test_held_with_no_exit_called_for_those_brokers_is_holding(journal):
    journal([trade("X", "public", "buy", 5), trade("X", "public", "sell", 5),
             trade("X", "fennel", "buy", 1)])
    play, = A._sell_plays([exit_alert("X", "Public")])
    assert play.bucket == "holding"
    assert play.left == 1
    assert play.ready_value == 0


def test_out_everywhere_is_closed(journal):
    journal([trade("X", "public", "buy", 5), trade("X", "public", "sell", 5)])
    play, = A._sell_plays([exit_alert("X", "Public")])
    assert play.bucket == "closed"
    assert play.left == 0


# ------------------------------------------------------- edges

def test_a_brokerage_we_never_held_is_not_a_leg(journal):
    """The exit named Fennel, we never bought there. Listing it as 'sold'
    claimed an exit that never happened."""
    journal([trade("X", "public", "buy", 5)])
    play, = A._sell_plays([exit_alert("X", "Public", "Fennel")])
    assert {l.broker for l in play.legs} == {"public"}


def test_a_failed_buy_is_not_reported_as_a_rejected_sell(monkeypatch):
    """A buy that failed months ago says nothing about getting out."""
    monkeypatch.setattr(A.trade_journal, "split_adjusted",
                        lambda *a, **k: [trade("X", "chase", "buy", 1)])
    monkeypatch.setattr(A, "_load_trade_attempts", lambda: {
        ("X", "chase", "1"): {"ok": False, "msg": "no funds", "side": "buy"},
    })
    play, = A._sell_plays([exit_alert("X", "Chase")])
    assert leg(play, "chase").failed_accounts == 0


def test_a_rejected_sell_is_carried_onto_the_leg(monkeypatch):
    """ONFO at Fidelity has been rejected ten times; that must be on the row."""
    monkeypatch.setattr(A.trade_journal, "split_adjusted",
                        lambda *a, **k: [trade("ONFO", "fidelity", "buy", 10)])
    monkeypatch.setattr(A, "_load_trade_attempts", lambda: {
        ("ONFO", "fidelity", str(i)): {
            "ok": False, "side": "sell",
            "msg": "(011999) You do not have sufficient ONFO shares to sell."}
        for i in range(10)})
    play, = A._sell_plays([exit_alert("ONFO", "Fidelity")])
    fid = leg(play, "fidelity")
    assert fid.failed_accounts == 10
    assert "sufficient ONFO" in fid.fail_reason


def test_the_worklist_leads_with_the_most_money_ready(journal):
    journal([trade("BIG", "chase", "buy", 4), trade("SMALL", "chase", "buy", 1)])
    plays = A._sell_plays([exit_alert("SMALL", "Chase", price=1.0),
                           exit_alert("BIG", "Chase", price=9.73)])
    assert [p.symbol for p in plays] == ["BIG", "SMALL"]


def test_an_empty_feed_produces_no_plays(journal):
    journal([trade("X", "public", "buy", 1)])
    assert A._sell_plays([]) == []


def test_shares_are_formatted_without_a_pointless_decimal():
    assert A._qty_text(3.0) == "3"
    assert A._qty_text(0.1) == "0.1"
    assert A._qty_text(0) == "0"
