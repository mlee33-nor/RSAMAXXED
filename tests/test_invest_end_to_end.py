"""Cash -> plan -> orders -> journal -> Analytics, in one pass.

Each piece is tested on its own elsewhere. This checks they fit: that the
quantity the planner produces is one the broker module would accept, that it
survives the trip through _trade_worker as a string, and that what comes out
the far end values correctly and leaves the RSA journal alone.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import balances
import etf_journal
import etf_plan
import trade_journal
from modules.outputs import AccountOutput, BrokerOutput

PRICES = {"SPY": 770.56, "VOO": 708.42, "IVV": 774.23,
          "SPLG": 80.00, "SCHX": 30.43}

# The real fleet shape, from trades.json.
FLEET = {
    "public":     {f"Public 1 BROKERAGE ({4150 + i})": 420.0 for i in range(20)},
    "wellsfargo": {f"WELLSTRADE (****{1000 + i})": 260.0 for i in range(20)},
    "fidelity":   {f"Fidelity 1 - Individual (Z{31914316 + i})": 950.0
                   for i in range(11)},
    "robinhood":  {"individual (****2561)": 700.0,
                   "ira_roth (****7689)": 700.0,
                   "ira_traditional (****2012)": 700.0},
}


class Recorder:
    """A broker module that fills every account and remembers the order."""

    def __init__(self, accounts):
        self.accounts = accounts
        self.seen = []

    def execute_trade(self, **kw):
        self.seen.append(kw)
        return BrokerOutput(
            broker=kw.get("symbol", ""), state="success",
            accounts=[AccountOutput(account_id=a, ok=True, message="filled")
                      for a in self.accounts])


class StubApp:
    def __init__(self):
        self.completed = []
        self._quick_picks = []

    def after(self, _ms, func=None, *args):
        if callable(func):
            func(*args)

    def _log(self, *a, **k):
        pass

    def _fetch_quote_price(self, broker, symbol, side="buy"):
        return PRICES.get(symbol)

    def _trade_result_write(self, *a, **k):
        pass

    def _render_quick_picks(self, *a, **k):
        raise AssertionError("an ETF buy must not redraw the RSA pick list")

    def _trade_broker_complete(self, batch, summary):
        self.completed.append(summary)


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    monkeypatch.setattr(balances, "BALANCES_FILE", tmp_path / "balances.json")
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf_trades.json")
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    monkeypatch.setattr(A, "_browser_slot", lambda b: None)
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)

    # Public reports its own cash; the rest are typed in, which is the
    # live-where-available / manual-elsewhere split the feature ships with.
    balances.record_broker_output("public", [
        AccountOutput(account_id=aid, ok=True,
                      extra={"cash_only_buying_power": cash})
        for aid, cash in FLEET["public"].items()])
    for broker in ("wellsfargo", "fidelity", "robinhood"):
        for aid, cash in FLEET[broker].items():
            balances.set_manual(broker, aid, cash)
    return tmp_path


def build_plan(mode="max", target=None):
    return etf_plan.plan_exposure(
        etf_plan.exposure_by_key("sp500"), balances.for_planner(), PRICES,
        mode=mode, target_per_account=target, market_open=True)


def execute(plan, recorders, dry_run=False):
    """Run every leg of the plan through the real _trade_worker."""
    stub = StubApp()
    for bp in plan.actionable:
        batch = {"origin": "etf", "exposure": plan.exposure.key,
                 "plan_id": "e2e", "pending": {bp.broker}}
        A._load_broker = lambda b, _r=recorders: _r[b]
        A.App._trade_worker(stub, bp.broker, "buy", bp.ticker,
                            etf_plan.qty_text(bp.qty), dry_run, batch)
    return stub


def test_the_whole_flow_from_typed_cash_to_a_valued_holding(fleet):
    plan = build_plan()
    recorders = {b: Recorder(list(FLEET[b])) for b in FLEET}

    # --- the plan reaches every broker and picks a tier per capability -----
    by_broker = {b.broker: b for b in plan.brokers}
    assert by_broker["public"].ticker == "SPY"      # fractional keeps headline
    assert by_broker["robinhood"].ticker == "SPY"
    assert by_broker["fidelity"].ticker in ("SPLG", "SCHX")
    assert by_broker["wellsfargo"].ticker in ("SPLG", "SCHX")

    execute(plan, recorders)

    # --- every broker got exactly one order, in the shape it accepts -------
    for broker, rec in recorders.items():
        assert len(rec.seen) == 1, broker
        kw = rec.seen[0]
        assert set(kw) == {"side", "qty", "symbol", "dry_run"}
        assert isinstance(kw["qty"], str) and "E" not in kw["qty"]
        cap = etf_plan.capability_for(broker)
        if not etf_plan.buys_fractional(cap):
            assert float(kw["qty"]) == int(float(kw["qty"])), broker

    # --- one journal row per account, and the RSA journal is untouched -----
    rows = etf_journal.get_trades()
    assert len(rows) == sum(len(v) for v in FLEET.values()) == 54
    assert trade_journal.get_trades() == []

    # --- and it values -----------------------------------------------------
    s = etf_journal.summary(PRICES)
    assert s["pl"] == pytest.approx(0.0, abs=0.01)   # bought at the quote
    assert s["market_value"] == pytest.approx(float(plan.deployed), abs=0.5)


def test_a_whole_share_broker_is_never_sent_a_fraction_end_to_end(fleet):
    """fidelity.py does int(float(qty)); a fraction arriving there becomes 0
    and comes back "Invalid qty" after the plan said it would buy."""
    plan = build_plan()
    recorders = {b: Recorder(list(FLEET[b])) for b in FLEET}
    execute(plan, recorders)
    for broker in ("fidelity", "wellsfargo"):
        qty = recorders[broker].seen[0]["qty"]
        assert "." not in qty or float(qty).is_integer()


def test_a_dry_run_places_the_order_but_records_nothing(fleet):
    plan = build_plan()
    recorders = {b: Recorder(list(FLEET[b])) for b in FLEET}
    execute(plan, recorders, dry_run=True)
    assert all(r.seen[0]["dry_run"] is True for r in recorders.values())
    assert etf_journal.get_trades() == []
    assert trade_journal.get_trades() == []


def test_the_deployed_figure_matches_what_is_actually_ordered(fleet):
    """The number on the button has to be the number that gets spent."""
    plan = build_plan()
    spent = 0.0
    for bp in plan.actionable:
        spent += float(bp.qty) * float(bp.price) * len(bp.participating)
    assert spent == pytest.approx(float(plan.deployed), abs=0.01)


def test_no_account_is_asked_to_spend_more_than_it_holds(fleet):
    for mode, target in (("max", None), ("target", 200), ("target", 900)):
        plan = build_plan(mode, target)
        for bp in plan.brokers:
            for a in bp.participating:
                assert a.deployed <= a.cash, (bp.broker, a.account_id)


def test_the_analytics_card_reflects_the_run(fleet, monkeypatch, tk_root):
    import tkinter as tk
    plan = build_plan()
    execute(plan, {b: Recorder(list(FLEET[b])) for b in FLEET})

    root = tk_root
    try:
        class Stub(tk.Frame):
            _render_investments = A.App._render_investments
            _make_kpi_tile = A.App._make_kpi_tile

        host = Stub(root, bg=A.BG_PRIMARY)
        host.pack()
        host._inv_before = tk.Frame(host)
        host._inv_before.pack()
        host._inv_card = A.RoundedFrame(host, bg_color=A.BG_CARD,
                                        border_color=A.BORDER)
        grid = tk.Frame(host._inv_card.inner, bg=A.BG_CARD)
        grid.pack()
        host._inv_cost = host._make_kpi_tile(grid, "INVESTED", "", 0, 0)
        host._inv_value = host._make_kpi_tile(grid, "MARKET VALUE", "", 0, 1)
        host._inv_pl = host._make_kpi_tile(grid, "UNREALIZED P/L", "", 0, 2)
        host._inv_holdings = host._make_kpi_tile(grid, "HOLDINGS", "", 0, 3)
        host._inv_note = tk.Label(host._inv_card.inner, text="")
        host._etf_quotes = PRICES
        host._render_investments()
        assert host._inv_card.winfo_manager() == "pack"
        assert host._inv_cost.cget("text") != "—"
        assert int(host._inv_holdings.cget("text")) >= 2   # SPY plus a tier
    finally:
        host.destroy()
