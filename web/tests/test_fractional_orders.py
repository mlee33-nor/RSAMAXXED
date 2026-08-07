"""Selling the fraction a reverse split leaves behind.

Three brokers actually hold fractions (rsa_feed.FRACTIONAL_BROKERS: Public,
Robinhood, SoFi). The other seven settle them to cash, so they never have one to
sell. Robinhood parsed its quantity with `int(float(qty))` — and int(0.1) is 0,
which failed its own "invalid quantity" guard and returned before ever reaching
an order. The broker most likely to be holding a fraction was the only one of
the three that could never sell it.

Nothing here talks to a broker: `rh` is stubbed and the assertions are about
which endpoint the module chose and what it passed.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import robinhood  # noqa: E402


class _Stub:
    """Records the call instead of placing it."""

    def __init__(self):
        self.calls = []

    def order(self, **kw):
        self.calls.append(("order", kw))
        return {"id": "whole"}

    def order_sell_fractional_by_quantity(self, symbol, quantity, **kw):
        self.calls.append(("sell_fractional", symbol, quantity, kw))
        return {"id": "frac-sell"}

    def order_buy_fractional_by_quantity(self, symbol, quantity, **kw):
        self.calls.append(("buy_fractional", symbol, quantity, kw))
        return {"id": "frac-buy"}

    def order_sell_market(self, symbol, quantity, **kw):
        self.calls.append(("sell_market", symbol, quantity, kw))
        return {"id": "market"}


@pytest.fixture()
def rh(monkeypatch):
    stub = _Stub()
    monkeypatch.setattr(robinhood, "_ensure_session", lambda: (True, ""))
    monkeypatch.setattr(robinhood, "_RH", stub)
    monkeypatch.setattr(robinhood, "_ACCOUNTS", [("Roth IRA", "12345678", "rh1")])
    monkeypatch.setattr(robinhood, "login_with_cache", lambda **kw: None)
    return stub


def test_a_split_remnant_can_be_sold_at_all(rh):
    """The bug: 0.1 truncated to 0 and the order was never attempted."""
    out = robinhood.execute_trade(side="sell", qty="0.1", symbol="GRNQ")
    assert out.state == "success"
    assert rh.calls, "no order was placed at all"


def test_a_fraction_goes_to_the_fractional_endpoint(rh):
    """Robinhood's ordinary market order rejects a quantity below one share, so
    routing a fraction there would trade an unplaced order for an API error."""
    robinhood.execute_trade(side="sell", qty="0.1", symbol="GRNQ")
    kind, symbol, quantity, kw = rh.calls[0]
    assert kind == "sell_fractional"
    assert symbol == "GRNQ"
    assert quantity == pytest.approx(0.1)          # and not 0, and not 1
    assert kw["account_number"] == "12345678"


def test_buying_a_fraction_routes_the_same_way(rh):
    robinhood.execute_trade(side="buy", qty="0.25", symbol="GRNQ")
    assert rh.calls[0][0] == "buy_fractional"
    assert rh.calls[0][2] == pytest.approx(0.25)


def test_a_whole_share_is_submitted_exactly_as_before(rh):
    """The fix must be invisible to every order that already works — same
    endpoint, and an int rather than 1.0, which is what the API was sent for
    years and what the dry-run ticket prints."""
    robinhood.execute_trade(side="sell", qty="1", symbol="GRNQ")
    kind, kw = rh.calls[0]
    assert kind == "order"
    assert kw["quantity"] == 1 and isinstance(kw["quantity"], int)


def test_a_whole_number_written_as_a_decimal_is_still_whole(rh):
    """'2.0' from a text box is two shares, not a fraction."""
    robinhood.execute_trade(side="sell", qty="2.0", symbol="GRNQ")
    assert rh.calls[0][0] == "order"
    assert rh.calls[0][1]["quantity"] == 2


@pytest.mark.parametrize("bad", ["0", "-1", "abc", ""])
def test_a_quantity_that_is_not_a_trade_is_still_refused(rh, bad):
    """Widening int to float must not widen this guard: zero and junk still
    have to stop before an order, or the fix trades one bug for a worse one."""
    out = robinhood.execute_trade(side="sell", qty=bad, symbol="GRNQ")
    assert out.state == "failed"
    assert "Invalid qty" in out.message
    assert not rh.calls


def test_the_dry_run_ticket_tells_you_it_is_fractional(rh):
    """A ticket that says MARKET for an order that cannot be a plain market
    order is the kind of small lie that costs an afternoon."""
    out = robinhood.execute_trade(side="sell", qty="0.1", symbol="GRNQ", dry_run=True)
    assert "MARKET (fractional)" in out.accounts[0].message
    assert "quantity: 0.1" in out.accounts[0].message
    assert not rh.calls, "a dry run must not place anything"
