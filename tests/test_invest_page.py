"""Render tests for the Invest page.

The App class cannot be instantiated headlessly, so these build the page's
methods onto a plain Tk root with the handful of attributes they read. That is
enough to catch what unit tests on the planner cannot: a widget option Tk
rejects, a missing attribute, a crash on the empty state — and, since the page
was rebuilt into independent sections, that picking a fund does not rebuild the
whole page.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import balances
import etf_journal
import etf_plan
from modules.outputs import AccountOutput

PRICES = {"SPY": 770.56, "QQQ": 718.45, "VOO": 708.42, "VTI": 380.65,
          "QQQM": 295.83, "VT": 160.82, "SPLG": 80.00, "SCHD": 34.27,
          "SCHX": 30.43}

_PAGE_METHODS = [
    "_invest_section", "_render_invest", "_invest_brokers", "_invest_prices",
    "_invest_target", "_invest_recompute",
    "_render_invest_pull", "_render_invest_picker", "_render_invest_detail",
    "_render_invest_cash", "_render_invest_holdings",
    "_invest_fund_card", "_invest_chart", "_invest_ticket",
    "_invest_cash_row", "_invest_broker_row", "_invest_toggle_broker",
    "_invest_set_cash", "_invest_clear_cash", "_invest_edit_cash",
    "_set_invest_tier", "_set_invest_symbol", "_set_invest_mode",
    "_draw_etf_chart", "_redraw_etf_chart", "_queue_etf_chart_redraw",
    "_make_chip", "_style_chip", "_empty_state",
]


@pytest.fixture
def page(tmp_path, monkeypatch, tk_root):
    monkeypatch.setattr(balances, "BALANCES_FILE", tmp_path / "balances.json")
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf_trades.json")
    monkeypatch.setattr(A, "_broker_has_creds",
                        lambda b: b in ("public", "fidelity", "wellsfargo"))
    monkeypatch.setattr(A, "_fetch_history", lambda *a, **k: [10.0, 11.0, 12.0])

    attrs = {n: getattr(A.App, n) for n in _PAGE_METHODS}
    attrs.update({
        "_INVEST_SECTIONS": A.App._INVEST_SECTIONS,
        "_log": lambda self, *a, **k: None,
        "_push_notification": lambda self, *a, **k: setattr(self, "notified", True),
        "_invest_refresh_balances": lambda self: setattr(self, "pulled", True),
        "_invest_refresh_quotes": lambda self: None,
        "_invest_execute": lambda self: None,
        "_invest_fetch_history": lambda self, sym: None,
        "_run_in_thread": lambda self, fn, *a: None,
    })
    Page = type("Page", (tk.Frame,), attrs)

    p = Page(tk_root, bg=A.BG_PRIMARY)
    p.pack(fill="both", expand=True)
    p._invest_body = p
    p._invest_sections = {}
    for name in A.App._INVEST_SECTIONS:
        holder = tk.Frame(p, bg=A.BG_PRIMARY)
        holder.pack(fill="x")
        p._invest_sections[name] = holder
    # detail is filled into persistent shells rather than rebuilt
    det = p._invest_sections["detail"]
    p._invest_chart_head = tk.Frame(det, bg=A.BG_CARD)
    p._invest_chart_head.pack(fill="x")
    p._etf_chart_canvas = tk.Canvas(det, bg=A.BG_CARD, height=170,
                                    highlightthickness=0)
    p._etf_chart_canvas.pack(fill="x")
    p._invest_chart_foot = tk.Frame(det, bg=A.BG_CARD)
    p._invest_chart_foot.pack(fill="x")
    p._invest_ticket_box = tk.Frame(det, bg=A.BG_HERO)
    p._invest_ticket_box.pack(fill="x")

    p._etf_quotes = {s: {"price": v, "pct": 0.5} for s, v in PRICES.items()}
    p._etf_history = {}
    p._etf_history_busy = set()
    p._etf_cash_status = {}
    p._etf_cash_busy = False
    p._etf_quotes_busy = False
    p._etf_tier = "low"
    p._etf_symbol = "SPLG"
    p._etf_auto = tk.BooleanVar(value=False)
    p._etf_mode = "max"
    p._etf_target = tk.StringVar(value="100")
    p._etf_dry = tk.BooleanVar(value=False)
    p._etf_plan = None
    p._etf_fund = None
    p._etf_reco = None
    p._invest_expanded = set()
    p._invest_editing = None
    p._etf_chart_pending = False
    yield p
    p.destroy()


def widget_text(w):
    out = []
    for child in w.winfo_children():
        try:
            t = child.cget("text")
            if t:
                out.append(str(t))
        except Exception:
            pass
        out.extend(widget_text(child))
    return out


def section_text(page, name):
    return " ".join(widget_text(page._invest_sections[name]))


def cash_account_rows(page):
    """Account-level rows currently drawn (the list collapses by broker)."""
    return [t for t in widget_text(page._invest_sections["cash"])
            if t.startswith("      ")]


# ---------------------------------------------------------------- rendering

def test_the_page_renders_with_nothing_on_record(page):
    """First launch: no cash, no holdings. It must explain itself, not crash,
    and it must say how to get started."""
    page._render_invest()
    assert "Pull balances" in section_text(page, "pull")
    assert "No accounts on record" in section_text(page, "cash")
    assert "Nothing invested yet" in section_text(page, "holdings")


def test_the_pull_section_leads_with_the_cash_figure(page):
    """'How do I find out what I can invest' has to be answerable at a glance."""
    balances.set_manual("public", "p1", 420.0)
    page._render_invest()
    text = section_text(page, "pull")
    assert "CASH AVAILABLE TO INVEST" in text
    assert "$420.00" in text
    assert "Pull balances" in text


def test_the_menu_is_filed_by_share_price(page):
    page._render_invest()
    text = section_text(page, "picker")
    for _key, label, _blurb in etf_plan.TIERS:
        assert label in text


def test_each_tier_offers_three_funds(page):
    for tier in ("high", "mid", "low"):
        page._set_invest_tier(tier)
        text = section_text(page, "picker")
        syms = [f.symbol for f in etf_plan.funds_in_tier(tier)]
        assert len(syms) == 3
        for s in syms:
            assert s in text


def test_a_fund_card_says_how_many_accounts_can_buy_it(page):
    """The share price is only meaningful next to the balances, so the card
    does the comparison for you."""
    balances.set_manual("fidelity", "f1", 95.0)
    balances.set_manual("fidelity", "f2", 95.0)
    page._set_invest_tier("low")
    assert "accounts can buy it" in section_text(page, "picker")


def test_picking_a_fund_shows_its_chart_and_ticket(page):
    balances.set_manual("public", "p1", 500.0)
    page._etf_history["SCHX"] = [28.0, 29.0, 30.43]
    page._set_invest_symbol("SCHX")
    text = section_text(page, "detail")
    assert "SCHX" in text
    assert "ORDER TICKET" in text
    assert "6 months" in text


def test_picking_a_fund_turns_off_the_recommendation(page):
    page._etf_auto.set(True)
    page._set_invest_symbol("SCHD")
    assert page._etf_auto.get() is False
    assert page._etf_symbol == "SCHD"


# ------------------------------------------------- the reload complaint

def test_picking_a_fund_does_not_rebuild_the_cash_list(page):
    """The page used to redraw everything on every click, including one row
    per account across the whole fleet. That is what made it feel slow."""
    for i in range(30):
        balances.set_manual("fidelity", f"f{i}", 500.0)
    page._render_invest()
    before = page._invest_sections["cash"].winfo_children()[0]
    page._set_invest_symbol("SCHD")
    after = page._invest_sections["cash"].winfo_children()[0]
    assert after is before          # same widget: never destroyed


def test_switching_tier_does_not_rebuild_the_cash_list(page):
    balances.set_manual("public", "p1", 500.0)
    page._render_invest()
    before = page._invest_sections["cash"].winfo_children()[0]
    page._set_invest_tier("high")
    assert page._invest_sections["cash"].winfo_children()[0] is before


def test_editing_cash_does_rebuild_the_plan(page):
    """The other direction has to work: a balance change must reach the ticket."""
    page._render_invest()
    page._invest_set_cash("public", "p1", "5000")
    assert page._etf_plan is not None
    assert page._etf_plan.account_count == 1


# ---------------------------------------------------------------- recommend

def test_the_recommendation_picks_the_fund_that_reaches_most_accounts(page):
    for i in range(10):
        balances.set_manual("fidelity", f"f{i}", 95.0)     # too small for SPY
    page._etf_auto.set(True)
    page._render_invest("picker", "detail")
    assert page._etf_reco.fund.symbol in ("SCHX", "SCHD", "SPLG")
    assert page._etf_reco.reach == 10


def test_the_recommendation_explains_itself(page):
    balances.set_manual("fidelity", "f1", 95.0)
    page._etf_auto.set(True)
    page._render_invest("picker", "detail")
    text = section_text(page, "picker")
    assert "reaches" in text and "account" in text


def test_the_recommendation_says_when_nothing_is_affordable(page):
    balances.set_manual("fidelity", "f1", 2.0)
    page._etf_auto.set(True)
    page._render_invest("picker", "detail")
    assert "cheapest" in section_text(page, "picker").lower()


def test_the_ticket_is_labelled_recommended_or_your_pick(page):
    balances.set_manual("public", "p1", 500.0)
    page._etf_auto.set(True)
    page._render_invest("picker", "detail")
    assert "recommended" in section_text(page, "detail")
    page._set_invest_symbol("SPLG")
    assert "your pick" in section_text(page, "detail")


# ---------------------------------------------------------------- ticket

def test_the_ticket_totals_what_will_be_spent(page):
    for i in range(4):
        balances.set_manual("fidelity", f"f{i}", 100.0)
    page._set_invest_symbol("SPLG")            # $80, whole shares
    text = section_text(page, "detail")
    assert "TOTAL" in text
    assert "$320.00" in text                   # 4 accounts x 1 share
    assert "Review & Buy" in text


def test_the_ticket_names_accounts_that_are_short(page):
    balances.set_manual("fidelity", "rich", 5000.0)
    balances.set_manual("fidelity", "poor", 10.0)
    page._set_invest_symbol("SPLG")
    assert "short" in section_text(page, "detail")


def test_choosing_a_fund_never_substitutes_a_cheaper_one(page):
    """plan_ticker must not quietly buy something else. Being overruled
    without being told is worse than being told you cannot have it."""
    balances.set_manual("fidelity", "f1", 100.0)
    page._set_invest_symbol("SPY")
    assert page._etf_plan.brokers[0].ticker == "SPY"
    assert page._etf_plan.actionable == []


# ---------------------------------------------------------------- chart

def sized_canvas(page, w=300, h=170):
    c = tk.Canvas(page, width=w, height=h, highlightthickness=0)
    c.pack()
    c.update_idletasks()
    return c


def test_no_chart_draw_forces_a_layout_pass():
    """Every _draw_* runs from a <Configure> handler, and calling
    update_idletasks from inside a layout callback makes Tk re-lay-out the
    whole page mid-draw — it was costing about 100ms per interaction across
    the Analytics charts as well as this one. The size is read, never forced.
    """
    import inspect
    for name in ("_draw_etf_chart", "_draw_equity_curve", "_draw_symbol_bars",
                 "_draw_broker_donut", "_draw_daily_activity", "_draw_daily_pl",
                 "_draw_monthly_pl", "_draw_return_dist",
                 "_draw_allocation_pie"):
        src = inspect.getsource(getattr(A.App, name))
        code = " ".join(l for l in src.splitlines()
                        if not l.strip().startswith("#"))
        assert "update_idletasks" not in code, name


def test_the_chart_draws_once_the_canvas_has_a_size(page):
    canvas = sized_canvas(page)
    page._draw_etf_chart(canvas, [10.0, 12.0, 11.0, 15.0])
    assert canvas.find_all()


def test_the_chart_says_so_when_there_is_no_history(page):
    canvas = sized_canvas(page)
    page._draw_etf_chart(canvas, [])
    texts = [canvas.itemcget(i, "text") for i in canvas.find_all()
             if canvas.type(i) == "text"]
    assert any("no price history" in t for t in texts)


def test_a_flat_series_does_not_divide_by_zero(page):
    canvas = sized_canvas(page)
    page._draw_etf_chart(canvas, [50.0, 50.0, 50.0])
    assert canvas.find_all()


def test_resize_redraws_are_coalesced(page):
    """Packing the ticket beside the chart resizes it repeatedly; only the
    last size matters."""
    drawn = []
    page._draw_etf_chart = lambda c, s: drawn.append(1)
    page._etf_fund = etf_plan.fund_by_symbol("SPLG")
    page._etf_history["SPLG"] = [79.0, 80.0]
    for _ in range(10):
        page._queue_etf_chart_redraw()
    assert drawn == []                  # nothing yet: it is queued
    page.update_idletasks()
    assert len(drawn) == 1              # ...and runs once, not ten times


# ---------------------------------------------------------------- cash edits

def test_typing_a_balance_stores_it_as_manual(page):
    balances.record_broker_output("wellsfargo", [
        AccountOutput(account_id="w1", ok=True, extra={"balance": 500.0})])
    page._invest_set_cash("wellsfargo", "w1", "750")
    row = balances.rows()[0]
    assert row["cash"] == 750.0
    assert row["source"] == balances.SOURCE_MANUAL


def test_a_currency_formatted_entry_is_accepted(page):
    page._invest_set_cash("wellsfargo", "w1", " $1,250.50 ")
    assert balances.rows()[0]["cash"] == 1250.50


def test_rubbish_in_the_cash_box_is_rejected_not_stored(page):
    page._invest_set_cash("wellsfargo", "w1", "abc")
    assert balances.rows() == []
    assert getattr(page, "notified", False) is True


def test_a_negative_balance_is_rejected(page):
    page._invest_set_cash("wellsfargo", "w1", "-50")
    assert balances.rows() == []


def test_leaving_a_live_figure_untouched_does_not_make_it_manual(page):
    """The entry fires on focus-out too, so simply tabbing through a live
    figure must not silently convert it into a typed-in one."""
    balances.record_broker_output("public", [
        AccountOutput(account_id="p1", ok=True,
                      extra={"cash_only_buying_power": 400.0})])
    page._invest_set_cash("public", "p1", "400.00", quiet=True)
    assert balances.rows()[0]["source"] == balances.SOURCE_LIVE


def test_clearing_a_manual_figure_falls_back_to_live(page):
    balances.record_broker_output("public", [
        AccountOutput(account_id="p1", ok=True,
                      extra={"cash_only_buying_power": 400.0})])
    page._invest_set_cash("public", "p1", "999")
    assert balances.rows()[0]["cash"] == 999.0
    page._invest_clear_cash("public", "p1")
    assert balances.rows()[0]["cash"] == 400.0


# ---------------------------------------------------------------- wiring

def test_the_page_only_plans_brokers_that_have_credentials(page):
    balances.set_manual("public", "p1", 500.0)
    balances.set_manual("schwab", "s1", 500.0)      # no credentials in this test
    assert "schwab" not in page._invest_brokers()
    page._set_invest_symbol("SPLG")
    assert {b.broker for b in page._etf_plan.brokers} == {
        "public", "fidelity", "wellsfargo"}


def test_prices_are_taken_from_the_etf_cache_not_the_rsa_one(page):
    """self._quotes is rewritten every 45s from the pick list and would evict
    SPY; the ETF cache is separate on purpose."""
    assert set(page._invest_prices()) == set(etf_plan.catalog_tickers())
    assert page._invest_prices()["SPY"] == 770.56


def test_every_fund_in_the_catalog_renders(page):
    balances.set_manual("public", "p1", 5000.0)
    balances.set_manual("fidelity", "f1", 5000.0)
    for fund in etf_plan.CATALOG:
        page._set_invest_symbol(fund.symbol)     # renders; must not raise
        assert fund.symbol in section_text(page, "detail")
