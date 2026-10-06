"""Robinhood must never send a market order after order() came back None.

robin_stocks' request_post swallows timeouts, 5xx and non-JSON bodies and
returns None even when Robinhood accepted the order. The old code read that
None as "nothing happened" and fell through to order_buy_market — a second
order. Only a missing order() or a signature mismatch (TypeError: nothing was
sent) may fall back. Stub module only: no network, no login, no robin_stocks.
"""

from __future__ import annotations

import pytest

import robinhood


class _StubRH:
    def __init__(self, order_result=None, order_exc=None, has_order=True):
        self.order_result = order_result
        self.order_exc = order_exc
        self.order_calls = []
        self.market_calls = []
        self.frac_calls = []
        self.orders = None
        if not has_order:
            self.order = None

    def order(self, **kw):
        self.order_calls.append(kw)
        if self.order_exc is not None:
            raise self.order_exc
        return self.order_result

    def order_buy_market(self, sym, q, account_number=None):
        self.market_calls.append((sym, q, account_number))
        return {"id": "mkt-1", "state": "queued"}

    def order_sell_market(self, sym, q, account_number=None):
        self.market_calls.append((sym, q, account_number))
        return {"id": "mkt-2", "state": "queued"}

    def order_sell_fractional_by_quantity(self, sym, q, account_number=None, timeInForce=None):
        self.frac_calls.append((sym, q, account_number))
        return None


@pytest.fixture
def run(monkeypatch):
    def _run(rh, *, side="buy", qty="1"):
        monkeypatch.setattr(robinhood, "_ensure_session", lambda: (True, ""))
        monkeypatch.setattr(robinhood, "_RH", rh)
        monkeypatch.setattr(robinhood, "_ACCOUNTS",
                            [("INDIVIDUAL (****1234)", "5QR11234", "rh_test")])
        monkeypatch.setattr(robinhood, "login_with_cache", lambda **kw: None)
        monkeypatch.setattr(robinhood, "_max_trade_accounts", lambda: 0)
        monkeypatch.setattr(robinhood.time, "sleep", lambda s: None)
        return robinhood.execute_trade(side=side, qty=qty, symbol="abcd")
    return _run


def test_order_none_never_falls_through_to_market_helper(run):
    rh = _StubRH(order_result=None)
    out = run(rh)

    assert len(rh.order_calls) == 1
    assert rh.market_calls == []
    assert out.state == "failed"
    [acct] = out.accounts  # reported once, not also as "order rejected"
    assert not acct.ok
    msg = acct.message.lower()
    assert "verify" in msg and "submitted" in msg


def test_type_error_still_falls_back_to_market_helper(run):
    rh = _StubRH(order_exc=TypeError("unexpected keyword argument 'account_number'"))
    out = run(rh)

    assert len(rh.market_calls) == 1
    [acct] = out.accounts
    assert acct.ok and acct.order_id == "mkt-1"


def test_missing_order_fn_uses_market_helper(run):
    rh = _StubRH(has_order=False)
    out = run(rh, side="sell")

    assert rh.order_calls == []
    assert len(rh.market_calls) == 1
    assert out.accounts[0].ok


def test_order_accepted_is_ok(run):
    rh = _StubRH(order_result={"id": "ord-9", "state": "queued"})
    out = run(rh)

    assert rh.market_calls == []
    [acct] = out.accounts
    assert acct.ok and acct.order_id == "ord-9"


def test_order_rejection_still_reported_as_rejected(run):
    rh = _StubRH(order_result={"detail": "Not enough buying power."})
    out = run(rh)

    assert rh.market_calls == []
    [acct] = out.accounts
    assert not acct.ok
    assert acct.message == "order rejected: Not enough buying power."


def test_fractional_none_reads_as_may_be_submitted(run):
    rh = _StubRH()
    out = run(rh, side="sell", qty="0.25")

    assert len(rh.frac_calls) == 1
    assert rh.market_calls == []
    [acct] = out.accounts
    assert not acct.ok and "verify" in acct.message.lower()
