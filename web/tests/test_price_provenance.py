"""Whether a recorded price is an execution or a guess.

The app called its price lookup `_fetch_fill_price`, and it never read a fill:
it asks get_holdings() for the CURRENT market price and falls back to Yahoo.
Worse, it is called once per batch and the answer stamped onto every account —
so the journal holds nine Wells Fargo orders placed across 7.4 minutes all
priced at exactly $0.08, and six Robinhood orders across 3.3 minutes all at
$0.7187, to four decimals.

Nothing here makes those numbers right. It makes them HONEST: a row now says
where its price came from, and carries the broker's order id so the real fill
stays recoverable instead of being returned by the API and dropped.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import trade_journal  # noqa: E402


@pytest.fixture()
def journal(tmp_path, monkeypatch):
    """A journal in tmp. Without this the test appends to the real trades.json."""
    f = tmp_path / "trades.json"
    monkeypatch.setattr(trade_journal, "_FILE", f)
    return f


def test_a_trade_keeps_the_brokers_order_id(journal):
    """The only thing that makes a fill recoverable after the fact. Public's API
    returns one, AccountOutput carried it, and record_trade dropped it."""
    trade_journal.record_trade(
        broker="public", account_id="a1", side="sell", symbol="GRNQ",
        qty=0.1, fill_price=10.0, order_id="pub-order-77",
        price_source=trade_journal.PRICE_FILL,
    )
    assert trade_journal.get_trades()[0]["order_id"] == "pub-order-77"


def test_a_price_says_whether_it_is_a_fill_or_a_quote(journal):
    trade_journal.record_trade(broker="public", account_id="a1", side="sell",
                               symbol="GRNQ", qty=0.1, fill_price=10.0,
                               price_source=trade_journal.PRICE_FILL)
    trade_journal.record_trade(broker="public", account_id="a2", side="sell",
                               symbol="GRNQ", qty=0.1, fill_price=10.0,
                               price_source=trade_journal.PRICE_QUOTE)
    real, guess = trade_journal.get_trades()
    assert not trade_journal.is_estimated(real)
    assert trade_journal.is_estimated(guess)


def test_an_unmarked_price_is_assumed_to_be_a_guess(journal):
    """Fail safe. A caller that forgets to say gets 'quote', because treating an
    unknown price as an execution is how this went unnoticed for so long."""
    trade_journal.record_trade(broker="public", account_id="a1", side="buy",
                               symbol="GRNQ", qty=1.0, fill_price=1.3)
    assert trade_journal.is_estimated(trade_journal.get_trades()[0])


def test_every_row_written_before_this_field_existed_counts_as_estimated(journal):
    """The whole existing journal predates it, and all of it IS estimated."""
    journal.write_text(json.dumps([{
        "id": "old", "timestamp": "2026-08-04T16:55:02+00:00", "broker": "public",
        "account_id": "a1", "side": "buy", "symbol": "GRNQ", "qty": 1.0,
        "fill_price": 1.3,
    }]), encoding="utf-8")
    assert trade_journal.is_estimated(trade_journal.get_trades()[0])


def test_the_split_lens_keeps_provenance(journal):
    """A restated fractional sell is still a quote — the restatement changes the
    units, and cannot turn a guessed price into a known one."""
    trade_journal.record_trade(broker="public", account_id="a1", side="buy",
                               symbol="GRNQ", qty=1.0, fill_price=1.3)
    trade_journal.record_trade(broker="public", account_id="a1", side="sell",
                               symbol="GRNQ", qty=0.1, fill_price=10.0)
    sell = trade_journal.split_adjusted()[1]
    assert sell["qty"] == pytest.approx(1.0)          # restated
    assert trade_journal.is_estimated(sell)           # still a guess


def test_the_app_never_calls_its_quote_a_fill():
    """The name was the accomplice: nobody audits a function called
    _fetch_fill_price for whether it returns a fill."""
    src = (REPO_ROOT / "app.py").read_text(encoding="utf-8", errors="ignore")
    # The old name survives in one place on purpose — the docstring explaining
    # what it used to be called and why that mattered. What must be gone is any
    # definition of it or call to it.
    assert "def _fetch_fill_price" not in src
    assert "self._fetch_fill_price(" not in src
    assert "def _fetch_quote_price" in src
