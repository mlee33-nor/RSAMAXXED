"""Public sells sized from what each account actually holds.

A reverse split credits every account its own fraction and a fractional sell
can leave 0.98 behind, so one quantity for all accounts either strands shares
or is rejected. These pin the per-account behaviour of
public.execute_trade(size_from_holdings=True) against a fake client.

And what each account holds is not what WE bought: an account that held 100
IPDN of its own before RSAMAXXED bought 1 must sell 1, not 101. Every sized sell
is capped per account by `max_by_account`, and an account missing from it is
not ours to sell.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import public  # noqa: E402


class FakeClient:
    def __init__(self, positions, fail_reads=()):
        self.positions = positions          # acct_id -> [(symbol, "qty"), ...]
        self.fail_reads = set(fail_reads)
        self.orders = []                    # (acct_id, side, symbol, quantity)
        self.reads = []

    def get_portfolio_v2(self, account_id):
        self.reads.append(account_id)
        if account_id in self.fail_reads:
            raise RuntimeError("503 from Public")
        return {"positions": [
            {"instrument": {"symbol": s}, "quantity": q}
            for s, q in self.positions.get(account_id, [])
        ]}

    def place_equity_market_order(self, *, account_id, side, symbol, quantity, **_kw):
        self.orders.append((account_id, side, symbol, quantity))
        return f"oid-{account_id}"


def label(acct_id):
    return f"Public 1 BROKERAGE ({acct_id[-4:]})"


def caps(*ids, cap="1"):
    """Every named account bought `cap` through the tool."""
    return {label(i): cap for i in ids}


@pytest.fixture()
def run(monkeypatch):
    monkeypatch.setattr(public.time, "sleep", lambda *_a: None)

    def _run(client, ids, **kw):
        accounts = [{"accountId": i, "accountType": "BROKERAGE"} for i in ids]
        monkeypatch.setattr(public, "_ensure_clients",
                            lambda: (True, "", [(1, client, accounts)]))
        if kw.get("size_from_holdings") and "max_by_account" not in kw:
            kw["max_by_account"] = caps(*ids)
        return public.execute_trade(side=kw.pop("side", "sell"),
                                    qty=kw.pop("qty", "1"),
                                    symbol=kw.pop("symbol", "IPDN"), **kw)
    return _run


def test_each_account_sells_exactly_what_it_holds(run):
    c = FakeClient({"A0001": [("IPDN", "0.98")], "A0002": [("IPDN", "1")],
                    "A0003": [("IPDN", "0.03333")]})
    out = run(c, ["A0001", "A0002", "A0003"], size_from_holdings=True)
    assert out.state == "success"
    assert [o[3] for o in c.orders] == ["0.98", "1", "0.03333"]
    assert [a.extra["qty"] for a in out.accounts] == ["0.98", "1", "0.03333"]


# ------------------------------------------------ B1: capped at what we bought

def test_an_account_holding_its_own_shares_sells_only_ours(run):
    """101 held, 1 bought through the tool -> 1, never 101."""
    c = FakeClient({"A0001": [("IPDN", "101")]})
    out = run(c, ["A0001"], size_from_holdings=True,
              max_by_account=caps("A0001", cap="1"))
    assert c.orders == [("A0001", "SELL", "IPDN", "1")]
    assert out.accounts[0].extra["qty"] == "1"


def test_a_late_round_up_sells_the_098_that_arrived(run):
    """Bought 1, sold 0.2, Public later rounded up to 0.98: cap 1 -> 0.98."""
    c = FakeClient({"A0001": [("IPDN", "0.98")]})
    run(c, ["A0001"], size_from_holdings=True, max_by_account=caps("A0001"))
    assert c.orders == [("A0001", "SELL", "IPDN", "0.98")]


def test_an_unrounded_remnant_sells_the_remnant(run):
    c = FakeClient({"A0001": [("IPDN", "0.0333")]})
    run(c, ["A0001"], size_from_holdings=True, max_by_account=caps("A0001"))
    assert c.orders == [("A0001", "SELL", "IPDN", "0.0333")]


def test_an_account_the_tool_never_bought_in_is_skipped_unread(run):
    c = FakeClient({"A0001": [("IPDN", "1")], "A0002": [("IPDN", "50")]})
    out = run(c, ["A0001", "A0002"], size_from_holdings=True,
              max_by_account=caps("A0001"))
    assert [o[0] for o in c.orders] == ["A0001"]
    assert "A0002" not in c.reads                  # not even read
    assert "not bought through RSAMAXXED" in out.message
    assert out.extra == {"skipped": {"not_ours": 1}}


def test_a_sized_sell_without_caps_is_refused_outright(run):
    c = FakeClient({"A0001": [("IPDN", "101")]})
    out = run(c, ["A0001"], size_from_holdings=True, max_by_account=None)
    assert out.state == "failed"
    assert c.orders == [] and c.reads == []


# ----------------------------------------------------------- existing cases

def test_an_account_holding_nothing_is_skipped_not_rejected(run):
    c = FakeClient({"A0001": [("IPDN", "0.5")], "A0002": [("OTHER", "3")]})
    out = run(c, ["A0001", "A0002"], size_from_holdings=True)
    assert [o[0] for o in c.orders] == ["A0001"]
    assert out.state == "success"
    assert "holds none" in out.message


def test_a_failed_read_is_a_failure_never_an_empty_account(run):
    c = FakeClient({"A0001": [("IPDN", "1")]}, fail_reads={"A0002"})
    out = run(c, ["A0001", "A0002"], size_from_holdings=True)
    assert out.state == "partial"
    bad = [a for a in out.accounts if not a.ok]
    assert len(bad) == 1 and "Could not read" in bad[0].message
    assert [o[0] for o in c.orders] == ["A0001"]


def test_remnant_only_leaves_whole_shares_for_their_own_exit(run):
    c = FakeClient({"A0001": [("IPDN", "0.03333")], "A0002": [("IPDN", "1")],
                    "A0003": [("IPDN", "1.5")]})
    out = run(c, ["A0001", "A0002", "A0003"], size_from_holdings=True,
              remnant_only=True)
    assert c.orders == [("A0001", "SELL", "IPDN", "0.03333")]
    assert "whole share" in out.message
    assert out.extra == {"skipped": {"whole": 2}}


def test_every_account_skipped_is_success_with_the_reasons(run):
    c = FakeClient({"A0001": [("IPDN", "1")], "A0002": [("IPDN", "2")]})
    out = run(c, ["A0001", "A0002"], size_from_holdings=True, remnant_only=True)
    assert out.state == "success" and out.accounts == []
    assert out.extra == {"skipped": {"whole": 2}}


# ------------------------------------------------ B6: renamed tickers

def test_the_new_ticker_is_sized_on_its_own_not_summed_with_the_old(run):
    """Holding under both names: sell what the NEW ticker holds, under it."""
    c = FakeClient({"A0001": [("AIFA", "0.05"), ("AGAE", "0.9")]})
    out = run(c, ["A0001"], symbol="AIFA", also_symbols=("AGAE",),
              size_from_holdings=True)
    assert c.orders == [("A0001", "SELL", "AIFA", "0.05")]
    assert out.accounts[0].extra == {"qty": "0.05", "symbol": "AIFA"}


def test_only_the_old_ticker_held_sells_under_the_old_ticker(run):
    c = FakeClient({"A0001": [("AGAE", "0.05")]})
    out = run(c, ["A0001"], symbol="AIFA", also_symbols=("AGAE",),
              size_from_holdings=True)
    assert c.orders == [("A0001", "SELL", "AGAE", "0.05")]
    assert out.accounts[0].extra == {"qty": "0.05", "symbol": "AGAE"}


# ------------------------------------------------ B7: validation unchanged

def test_buys_and_unsized_sells_are_unchanged(run):
    c = FakeClient({"A0001": [("IPDN", "0.2")]})
    run(c, ["A0001", "A0002"], side="buy", qty="1", size_from_holdings=True)
    assert [o[3] for o in c.orders] == ["1", "1"]
    c2 = FakeClient({"A0001": [("IPDN", "0.2")]})
    out = run(c2, ["A0001"], qty="2")
    assert c2.orders == [("A0001", "SELL", "IPDN", "2")]
    assert out.accounts[0].extra is None


@pytest.mark.parametrize("side,sized", [("buy", False), ("sell", False),
                                        ("buy", True)])
def test_a_blank_quantity_still_fails_validation_outside_sized_sells(run, side, sized):
    c = FakeClient({"A0001": [("IPDN", "1")]})
    out = run(c, ["A0001"], side=side, qty="", size_from_holdings=sized)
    assert out.state == "failed" and c.orders == []


def test_a_sized_sell_may_arrive_without_a_quantity(run):
    c = FakeClient({"A0001": [("IPDN", "0.5")]})
    run(c, ["A0001"], qty="", size_from_holdings=True)
    assert c.orders == [("A0001", "SELL", "IPDN", "0.5")]


def test_dry_run_reads_and_sizes_but_places_nothing(run, monkeypatch):
    monkeypatch.setattr(public, "_write_dry_run_log", lambda content: "dry.log")
    c = FakeClient({"A0001": [("IPDN", "0.98")]})
    out = run(c, ["A0001"], size_from_holdings=True, dry_run=True)
    assert c.orders == []
    assert out.accounts[0].extra == {"qty": "0.98", "symbol": "IPDN"}
