"""Reverse splits, and the profit they used to invent.

A reverse split changes your share count with nothing to record, so the journal
never sees it happen. Every figure in the app subtracts a buy price from a sell
price, and after a split those two are in different units — which is how one
GRNQ exit that took $24.70 and gave back $19.00 came to be reported as a $16.53
profit.

The rule under test is deliberately narrow: only a sell of a FRACTION of a share
is treated as a split remnant. A whole-share sell smaller than the position is an
ordinary partial exit, and the old arithmetic was always right about it.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import lifecycle  # noqa: E402
import trade_journal  # noqa: E402


def _t(side, qty, price, symbol="GRNQ", broker="public", account="acct-1", ts="2026-08-04"):
    return {"id": f"{ts}-{side}-{account}", "timestamp": f"{ts}T16:00:00+00:00",
            "broker": broker, "account_id": account, "side": side,
            "symbol": symbol, "qty": qty, "fill_price": price}


def _realized(rows):
    """The app's own formula, longhand: all-time average buy against the sells.

    Restated here rather than imported because app.py drags in customtkinter.
    If this and _portfolio_summary ever disagree, this is the one to trust —
    it is four lines and has no UI attached.
    """
    buys = {}
    sells = {}
    for t in rows:
        s = t["symbol"]
        q, p = float(t["qty"]), (t["fill_price"] or 0)
        d = (buys if t["side"] == "buy" else sells).setdefault(s, {"q": 0.0, "v": 0.0})
        d["q"] += q
        d["v"] += p * q
    total = 0.0
    for s, sd in sells.items():
        b = buys.get(s)
        if not b or not b["q"] or not sd["q"]:
            continue
        total += (sd["v"] / sd["q"] - b["v"] / b["q"]) * sd["q"]
    return total


# ------------------------------------------------------- the restatement

def test_a_fractional_sell_is_restated_into_the_shares_it_came_from():
    """Bought 1 share at $1.30; a 1-for-10 split left 0.1 of it; sold that for
    $10.00. The sale disposed of one whole share's worth of position, and that
    is the quantity the cost basis has to be charged against."""
    out = trade_journal.split_adjusted([_t("buy", 1.0, 1.30), _t("sell", 0.1, 10.0)])
    sell = out[1]
    assert sell["qty"] == pytest.approx(1.0)
    assert sell["fill_price"] == pytest.approx(1.0)
    assert sell["split_ratio"] == pytest.approx(10.0)


def test_the_cash_is_never_changed_by_the_restatement():
    """The only thing that actually happened is $1.00 of proceeds. Quantity and
    price are units of account; their product is the fact."""
    out = trade_journal.split_adjusted([_t("buy", 1.0, 1.30), _t("sell", 0.1, 10.0)])
    sell = out[1]
    assert sell["qty"] * sell["fill_price"] == pytest.approx(0.1 * 10.0)


def test_a_loss_stops_reporting_itself_as_a_profit():
    """The bug, in one assertion. $1.30 out, $1.00 back, on 19 accounts."""
    rows = []
    for i in range(19):
        rows.append(_t("buy", 1.0, 1.30, account=f"acct-{i}"))
    for i in range(19):
        rows.append(_t("sell", 0.1, 10.0, account=f"acct-{i}", ts="2026-08-06"))

    assert _realized(rows) == pytest.approx(16.53, abs=0.01)      # what it said
    assert _realized(trade_journal.split_adjusted(rows)) == pytest.approx(-5.70, abs=0.01)


def test_the_executed_fill_survives_for_the_trade_history():
    """A history that showed '1.0 @ $1.00' for an order that really sold 0.1 at
    $10.00 would be a nicer number and a false one."""
    sell = trade_journal.split_adjusted([_t("buy", 1.0, 1.30), _t("sell", 0.1, 10.0)])[1]
    assert sell["executed_qty"] == pytest.approx(0.1)
    assert sell["executed_price"] == pytest.approx(10.0)


def test_the_journal_on_disk_is_never_rewritten():
    """This is a lens, not a migration — so it stays correct for trades recorded
    before it existed, and a bad rule can be changed instead of recovered from."""
    rows = [_t("buy", 1.0, 1.30), _t("sell", 0.1, 10.0)]
    snapshot = json.dumps(rows, sort_keys=True)
    trade_journal.split_adjusted(rows)
    assert json.dumps(rows, sort_keys=True) == snapshot


# --------------------------------------------------- what it must NOT touch

def test_an_ordinary_partial_exit_is_left_alone():
    """13 of 26 accounts sold their whole share. Nothing split; the old
    arithmetic is right; widening the rule to cover this would charge the whole
    position's basis to the first account that sold."""
    rows = [_t("buy", 1.0, 0.06, account=f"a{i}") for i in range(26)]
    rows += [_t("sell", 1.0, 3.80, account=f"a{i}", ts="2026-08-06") for i in range(13)]
    out = trade_journal.split_adjusted(rows)
    assert not any("executed_qty" in t for t in out)
    assert _realized(out) == pytest.approx(_realized(rows))


def test_a_clean_round_up_is_unchanged():
    """The case the product is built on: buy 1 at $0.25, the split rounds it
    back up to 1 whole share, sell at $4.75. Same shares both sides, so there is
    nothing to restate and the answer must not move."""
    rows = [_t("buy", 1.0, 0.25), _t("sell", 1.0, 4.75, ts="2026-08-06")]
    assert _realized(trade_journal.split_adjusted(rows)) == pytest.approx(4.50)


def test_a_fraction_sold_out_of_nothing_is_left_alone():
    """No recorded buy means no basis to restate against. Guessing one would
    book the entire proceeds as profit."""
    out = trade_journal.split_adjusted([_t("sell", 0.1, 10.0)])
    assert out[0]["qty"] == pytest.approx(0.1)
    assert "executed_qty" not in out[0]


def test_an_unpriced_fill_stays_unpriced():
    """None is not zero. A $0.00 sell price would book the whole position as a
    total loss — the mirror of the bug this rule exists to fix."""
    out = trade_journal.split_adjusted([_t("buy", 1.0, 1.30), _t("sell", 0.1, None)])
    assert out[1]["fill_price"] is None
    assert out[1]["qty"] == pytest.approx(1.0)


# ------------------------------------------------------------- positions

def test_a_sold_off_remnant_closes_the_position():
    """Without this the account nets 1.0 - 0.1 and holds 0.9 of a share that no
    longer exists — forever, in the allocation donut."""
    rows = [_t("buy", 1.0, 1.30), _t("sell", 0.1, 10.0, ts="2026-08-06")]
    net = {}
    for t in trade_journal.split_adjusted(rows):
        k = (t["broker"], t["symbol"])
        net[k] = net.get(k, 0.0) + (t["qty"] if t["side"] == "buy" else -t["qty"])
    assert net[("public", "GRNQ")] == pytest.approx(0.0)


def test_the_sell_worklist_stops_offering_the_same_position_twice():
    """held_accounts promises that a position sold on the last pass drops out.
    Against the raw journal a sold-off remnant still nets 0.9 and reads as open,
    which is exactly how it gets offered for sale a second time."""
    rows = [_t("buy", 1.0, 1.30, account=f"a{i}") for i in range(3)]
    rows += [_t("sell", 0.1, 10.0, account=f"a{i}", ts="2026-08-06") for i in range(3)]
    assert lifecycle.held_accounts(rows).get("GRNQ", {}) == {}

    # And one account that did NOT sell is still held, so the rule closes
    # positions rather than simply forgetting them.
    rows.append(_t("buy", 1.0, 1.30, account="a9"))
    assert lifecycle.held_accounts(rows)["GRNQ"] == {"Public": 1}
