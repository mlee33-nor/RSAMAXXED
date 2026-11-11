"""The Public fee guard: a sale fee stops every Public sell until cleared.

Public charges an administrative fee on a sale of reverse-split stock within
90 days of the split. Every play here is one, so the first fee seen -- in a
preflight before an order, or in the account history after one -- halts Public
selling (buys go on), and a refused sell must read as "nothing was sent".
"""
from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import public  # noqa: E402
import public_fees  # noqa: E402


ZERO_FEES = {"estimatedCommission": "0.00",
             "regulatoryFees": {"secFee": "0.01", "tafFee": "0.01", "orfFee": None},
             "orderValue": "4.75", "estimatedCost": "4.73"}
RS_FEE = {**ZERO_FEES, "estimatedCommission": "0.99"}


class FakeClient:
    def __init__(self, preflight=None, history=None, positions=None):
        self.preflight = preflight or {}     # acct -> response | Exception
        self.history = history or {}         # acct -> [tx, ...]
        self.on_sale = {}                    # acct -> tx that posts after its order
        self.positions = positions or {}
        self.orders = []

    def preflight_equity_market_order(self, *, account_id, **_kw):
        r = self.preflight.get(account_id, ZERO_FEES)
        if isinstance(r, Exception):
            raise r
        return r

    def get_history(self, account_id, *, start=None, next_token=None):
        return {"transactions": list(self.history.get(account_id, []))}

    def get_portfolio_v2(self, account_id):
        return {"positions": [{"instrument": {"symbol": s}, "quantity": q}
                              for s, q in self.positions.get(account_id, [])]}

    def place_equity_market_order(self, *, account_id, side, symbol, quantity, **_kw):
        self.orders.append((account_id, side, symbol, quantity))
        if account_id in self.on_sale:
            self.history.setdefault(account_id, []).append(self.on_sale[account_id])
        return f"oid-{account_id}"


def label(i):
    return f"Public 1 BROKERAGE ({i[-4:]})"


@pytest.fixture()
def run(monkeypatch):
    monkeypatch.setattr(public.time, "sleep", lambda *_a: None)
    events = []
    monkeypatch.setattr(public_fees, "_listeners", [events.append])

    def _run(client, ids, side="sell", **kw):
        accounts = [{"accountId": i, "accountType": "BROKERAGE"} for i in ids]
        monkeypatch.setattr(public, "_ensure_clients",
                            lambda: (True, "", [(1, client, accounts)]))
        return public.execute_trade(side=side, qty=kw.pop("qty", "1"),
                                    symbol="IPDN", **kw)
    _run.events = events
    return _run


def _nothing_sent(msg):
    t = msg.lower()
    return ("nothing was sent" in t and "skipped" in t
            and not any(w in t for w in ("verify", "may have", "may exist")))


def test_state_file_is_not_the_users(tmp_path):
    assert public_fees.STATE_FILE != public_fees.ROOT_DIR / "public_fee_halt.json"


def test_clean_sells_go_through(run):
    c = FakeClient()
    out = run(c, ["A0001", "A0002"])
    assert out.state == "success" and len(c.orders) == 2
    assert public_fees.halt_status() is None


def test_preflight_commission_stops_the_sell_before_it_is_sent(run):
    c = FakeClient(preflight={"A0002": RS_FEE})
    out = run(c, ["A0001", "A0002", "A0003"])
    # A0001 sold; A0002 refused at preflight; A0003 never attempted.
    assert [o[0] for o in c.orders] == ["A0001"]
    assert out.accounts[0].ok
    for row in out.accounts[1:]:
        assert not row.ok and _nothing_sent(row.message)
    h = public_fees.halt_status()
    assert h and "0.99" in h["reason"] and "0002" in h["reason"]
    assert any(e["kind"] == "halt" and e["first"] for e in run.events)


def test_fee_in_history_after_a_sale_stops_the_rest(run):
    c = FakeClient()
    c.on_sale["A0001"] = {"id": "t1", "type": "TRADE", "subType": "SELL",
                          "symbol": "IPDN", "netAmount": "3.76", "fees": "0.99"}
    out = run(c, ["A0001", "A0002"])
    assert [o[0] for o in c.orders] == ["A0001"]
    assert not out.accounts[1].ok and _nothing_sent(out.accounts[1].message)
    assert public_fees.halt_status() is not None


def test_fee_on_the_last_account_is_still_caught(run):
    c = FakeClient()
    c.on_sale["A0002"] = {"id": "t2", "type": "TRADE", "fees": "0.99"}
    run(c, ["A0001", "A0002"])
    assert len(c.orders) == 2 and public_fees.halt_status() is not None


def test_separate_fee_transaction_is_caught(run):
    c = FakeClient()
    c.on_sale["A0001"] = {"id": "f1", "type": "FEE", "subType": "REVERSE_SPLIT_FEE",
                          "symbol": "IPDN", "netAmount": "-0.99", "fees": "0"}
    run(c, ["A0001"])
    assert public_fees.halt_status() is not None


def test_a_halt_refuses_every_later_sell_but_not_buys(run):
    public_fees.trip("test fee", source="test")
    c = FakeClient()
    out = run(c, ["A0001", "A0002"])
    assert c.orders == [] and out.state == "failed"
    assert len(out.accounts) == 2
    assert all(_nothing_sent(a.message) for a in out.accounts)
    out = run(c, ["A0001"], side="buy")
    assert out.state == "success" and c.orders == [("A0001", "BUY", "IPDN", "1")]


def test_a_fee_already_in_history_halts_before_the_first_order(run):
    c = FakeClient(history={"A0002": [{"id": "old", "type": "FEE",
                                       "netAmount": "-0.99"}]})
    out = run(c, ["A0001", "A0002"])
    assert c.orders == [] and public_fees.halt_status() is not None
    assert all(_nothing_sent(a.message) for a in out.accounts)


def test_clearing_acknowledges_the_old_fee(run):
    c = FakeClient(history={"A0001": [{"id": "old", "type": "FEE",
                                       "netAmount": "-0.99"}]})
    run(c, ["A0001"])
    assert public_fees.halt_status() is not None
    public_fees.clear()
    out = run(c, ["A0001"])
    assert out.state == "success" and len(c.orders) == 1
    assert public_fees.halt_status() is None


def test_regulatory_cents_do_not_trip(run):
    c = FakeClient()
    c.on_sale["A0001"] = {"id": "t1", "type": "TRADE", "subType": "SELL",
                          "netAmount": "4.74", "fees": "0.01"}
    out = run(c, ["A0001", "A0002"])
    assert out.state == "success" and public_fees.halt_status() is None


def test_fractional_sell_is_guarded_too(run):
    c = FakeClient(preflight={"A0001": RS_FEE},
                   positions={"A0001": [("IPDN", "0.98")]})
    out = run(c, ["A0001"], size_from_holdings=True,
              max_by_account={label("A0001"): "1"})
    assert c.orders == [] and _nothing_sent(out.accounts[0].message)
    assert public_fees.halt_status() is not None


def test_buy_preflight_notice_is_reported_not_blocking(run):
    c = FakeClient(preflight={"A0001": {**ZERO_FEES, "estimatedCommission": "0.99",
                                        "warnings": ["Subject to reverse split fee"]}})
    out = run(c, ["A0001"], side="buy")
    assert out.state == "success" and len(c.orders) == 1
    assert "preflight" in out.accounts[0].message
    assert public_fees.halt_status() is None
    assert any(e["kind"] == "notice" for e in run.events)


def test_preflight_failure_does_not_block_a_sell(run):
    c = FakeClient(preflight={"A0001": RuntimeError("HTTP 404")})
    out = run(c, ["A0001"])
    assert out.state == "success" and len(c.orders) == 1


def test_dry_run_still_trips_on_a_preflight_fee(run):
    c = FakeClient(preflight={"A0001": RS_FEE})
    run(c, ["A0001"], dry_run=True)
    assert c.orders == [] and public_fees.halt_status() is not None


def test_preflight_check_parsing():
    assert public_fees.preflight_check(ZERO_FEES)["trip"] == ""
    assert "commission" in public_fees.preflight_check(RS_FEE)["trip"]
    odd = {**ZERO_FEES, "reverseSplitFee": "0.49"}
    assert "fee" in public_fees.preflight_check(odd)["trip"]
    assert public_fees.transaction_fee({"fees": "0.49"})[0] == Decimal("0.49")
    assert public_fees.transaction_fee({"fees": "0.02"})[0] is None


# ------------------------------------------------ QA 2026-11-09 follow-ups

def test_halt_survives_the_state_file_vanishing(run):
    public_fees.trip("fee $0.99", source="test")
    public_fees.STATE_FILE.unlink()
    assert public_fees.halt_status() is not None
    c = FakeClient()
    run(c, ["A0001"])
    assert c.orders == []


def test_an_unreadable_state_file_fails_closed(run, monkeypatch):
    from modules import atomic
    monkeypatch.setattr(atomic, "is_unreadable", lambda p: True)
    h = public_fees.halt_status()
    assert h and h.get("unreadable")
    c = FakeClient()
    out = run(c, ["A0001"])
    assert c.orders == [] and _nothing_sent(out.accounts[0].message)
    assert public_fees.clear() is False


def test_a_scan_never_overwrites_an_unreadable_file(monkeypatch):
    from modules import atomic
    public_fees.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    public_fees.STATE_FILE.write_text('{"halted": true, "reason": "x"}',
                                      encoding="utf-8")
    monkeypatch.setattr(atomic, "is_unreadable", lambda p: True)
    public_fees.scan_accounts([])
    assert '"halted": true' in public_fees.STATE_FILE.read_text(encoding="utf-8")


def test_regulatory_fees_on_a_big_sale_do_not_trip():
    big = {"estimatedCommission": "0.00",
           "regulatoryFees": {"secFee": "0.28", "tafFee": "0.33", "catFee": "0.01"}}
    assert public_fees.preflight_check(big)["trip"] == ""
    # 2,000 shares at $5: ~$0.33 TAF + ~$0.28 SEC in the trade's fees.
    tx = {"type": "TRADE", "quantity": "2000", "principalAmount": "10000",
          "fees": "0.61"}
    assert public_fees.transaction_fee(tx)[0] is None
    # The same sale plus a $0.99 fee is caught.
    assert public_fees.transaction_fee(dict(tx, fees="1.60"))[0] is not None


def test_refunds_and_transfer_fees_do_not_trip():
    assert public_fees.transaction_fee(
        {"type": "FEE", "subType": "FEE_REFUND", "netAmount": "0.99"})[0] is None
    assert public_fees.transaction_fee(
        {"type": "FEE", "description": "ACAT transfer fee", "netAmount": "-75"})[0] is None
    assert public_fees.transaction_fee(
        {"type": "FEE", "description": "Reverse split fee", "netAmount": "0.99"})[0] \
        == Decimal("0.99")


def test_account_numbers_are_redacted():
    out = public_fees.redact({"accountNumber": "5PX12345678", "tx": [{"accountId": "ABC9876"}]})
    assert out["accountNumber"] == "…5678" and out["tx"][0]["accountId"] == "…9876"


def test_the_halt_message_names_the_monitor_page(run):
    public_fees.trip("fee $0.99", source="test")
    out = run(FakeClient(), ["A0001"])
    assert "MONITOR" in out.accounts[0].message


def test_a_trip_during_preflight_stops_that_order(run, monkeypatch):
    c = FakeClient()
    real = c.preflight_equity_market_order

    def pf(**kw):
        public_fees.trip("tripped elsewhere", source="test")
        return real(**kw)
    c.preflight_equity_market_order = pf
    run(c, ["A0001"])
    assert c.orders == []
