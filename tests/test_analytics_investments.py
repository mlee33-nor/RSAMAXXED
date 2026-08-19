"""The Investments card on Analytics.

The point of this card is what it does NOT do. The hero above it is realized
profit on reverse-split plays; this is unrealized market value on held ETFs.
Both are right about different things and neither is a component of the other,
so the tests here mostly check that they stay apart.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import etf_journal
import trade_journal


@pytest.fixture
def card(tmp_path, monkeypatch, tk_root):
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf_trades.json")

    class Stub(tk.Frame):
        _render_investments = A.App._render_investments
        _make_kpi_tile = A.App._make_kpi_tile

    host = Stub(tk_root, bg=A.BG_PRIMARY)
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
    host._inv_note = tk.Label(host._inv_card.inner, text="", bg=A.BG_CARD)
    host._etf_quotes = {"SPY": {"price": 770.56}}
    yield host
    host.destroy()


def buy(symbol="SPY", qty=2, price=700.0):
    return etf_journal.record_trade(broker="public", account_id="p1",
                                    side="buy", symbol=symbol, qty=qty,
                                    fill_price=price, exposure="sp500")


# ---------------------------------------------------------------- visibility

def test_the_card_is_absent_until_something_is_invested(card):
    """A user who never opens Invest should not carry an empty card around."""
    card._render_investments()
    assert not card._inv_card.winfo_ismapped()


def test_the_card_appears_once_there_is_a_holding(card):
    buy()
    card._render_investments()
    card.update_idletasks()
    assert card._inv_card.winfo_manager() == "pack"


def test_the_card_disappears_again_if_everything_is_sold(card):
    buy()
    card._render_investments()
    etf_journal.record_trade(broker="public", account_id="p1", side="sell",
                             symbol="SPY", qty=2, fill_price=800.0)
    card._render_investments()
    assert card._inv_card.winfo_manager() == ""


# ---------------------------------------------------------------- figures

def test_it_shows_cost_value_and_unrealized_pl(card):
    buy(qty=2, price=700.0)                       # cost 1400, value 1541.12
    card._render_investments()
    assert card._inv_cost.cget("text") == "$1,400.00"
    assert card._inv_value.cget("text") == "$1,541.12"
    assert card._inv_pl.cget("text").startswith("$+141.12")
    assert card._inv_holdings.cget("text") == "1"


def test_a_loss_is_coloured_red_and_a_gain_green(card):
    buy(qty=1, price=900.0)                       # bought above the quote
    card._render_investments()
    assert card._inv_pl.cget("fg") == A.RED

    etf_journal.record_trade(broker="public", account_id="p2", side="buy",
                             symbol="SPY", qty=10, fill_price=100.0)
    card._render_investments()
    assert card._inv_pl.cget("fg") == A.GREEN


def test_an_unquoted_holding_is_explained_not_shown_as_a_loss(card):
    buy("ZZZZ", 1, 50.0)
    card._render_investments()
    assert "No quote for ZZZZ" in card._inv_note.cget("text")
    assert card._inv_value.cget("text") == "$0.00"     # value unknown, not -50


def test_an_unpriced_buy_is_called_out(card):
    buy()
    etf_journal.record_trade(broker="public", account_id="p2", side="buy",
                             symbol="SPY", qty=1, fill_price=None)
    card._render_investments()
    assert "no recorded fill price" in card._inv_note.cget("text")


def test_the_note_is_empty_when_there_is_nothing_to_qualify(card):
    buy()
    card._render_investments()
    assert card._inv_note.cget("text") == ""


# ---------------------------------------------------------------- separation

def test_etf_holdings_do_not_reach_the_rsa_realized_figure(card):
    """The hero on this page is computed from trade_journal alone. An ETF
    position must not appear in it under any circumstances."""
    before = trade_journal.split_adjusted()
    buy(qty=100, price=1.0)
    assert trade_journal.split_adjusted() == before


def test_the_two_totals_are_never_summed_in_the_source():
    """Cheap structural guard: the Investments renderer must not touch the
    hero labels, and nothing should add a realized figure to an unrealized
    one."""
    src = Path(A.__file__).read_text(encoding="utf-8")
    start = src.index("def _render_investments")
    body = src[start:src.index("def _refresh_stats")]
    for forbidden in ("_hero_pl", "realized_pl", "_dash_value"):
        assert forbidden not in body


def test_the_card_uses_the_etf_quote_cache_not_the_rsa_one(card):
    """self._quotes is rewritten every 45s from the pick list, so SPY would
    disappear from it; the ETF cache is separate for that reason."""
    import ast
    import inspect

    src = inspect.getsource(A.App._render_investments)
    tree = ast.parse(src.lstrip())
    # Compare against the code only — the docstring names self._quotes on
    # purpose, to say why it is not the one being read.
    ast.get_docstring(tree.body[0]) and tree.body[0].body.pop(0)
    code = ast.dump(tree)
    assert "_etf_quotes" in code
    assert "_quotes'" not in code.replace("_etf_quotes", "")
