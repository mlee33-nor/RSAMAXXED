"""Tests for the ETF journal, and for its separation from the RSA one.

The separation tests are the important ones. `cloud_sync.push_trades` uploads
the whole of trades.json to the web app, which serves the paid public Plays
board, and `_ALLOWED` silently drops any field it does not recognise. So a
single ETF row landing in the wrong file would be published as a reverse-split
pick with no tag left on it to say otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import etf_journal
import trade_journal


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf_trades.json")
    yield


def buy(symbol="SPY", qty=1.0, price=770.56, broker="public",
        account="p1", exposure="sp500"):
    return etf_journal.record_trade(
        broker=broker, account_id=account, side="buy", symbol=symbol,
        qty=qty, fill_price=price, exposure=exposure)


# ------------------------------------------------------------- separation

def test_the_etf_journal_writes_a_different_file():
    buy()
    assert etf_journal.ETF_FILE.exists()
    assert etf_journal.ETF_FILE.name != trade_journal._FILE.name


def test_recording_an_etf_trade_leaves_trades_json_untouched():
    """The whole point. trade_journal is the RSA record and must not move."""
    before = trade_journal._FILE.read_bytes()
    buy()
    buy("SCHX", 3, 30.43, broker="fidelity", account="f1")
    assert trade_journal._FILE.read_bytes() == before


def test_an_etf_row_never_reaches_the_cloud_whitelist():
    """cloud_sync loads trades.json and nothing else, so an ETF row cannot be
    uploaded unless someone writes it to the wrong file."""
    import cloud_sync
    buy()
    uploaded = {t["id"] for t in cloud_sync.CloudSync._load_trades()}
    assert {t["id"] for t in etf_journal.get_trades()}.isdisjoint(uploaded)


def test_the_cloud_whitelist_would_strip_the_etf_fields():
    """Documents WHY the separation exists rather than a category flag: the
    two fields that identify an ETF buy do not survive `_clean`."""
    import cloud_sync
    row = buy()
    cleaned = cloud_sync._clean(row)
    assert "exposure" not in cleaned
    assert "plan_id" not in cleaned
    assert cleaned["symbol"] == "SPY"      # ...and it would publish as a pick


def test_etf_trades_are_absent_from_the_rsa_portfolio():
    buy("SPY", 10)
    assert "SPY" not in {sym for _b, sym in trade_journal.get_portfolio()}


# ------------------------------------------------------------- rows

def test_a_recorded_row_has_the_shape_the_page_expects():
    row = buy()
    assert row["symbol"] == "SPY"
    assert row["side"] == "buy"
    assert row["exposure"] == "sp500"
    assert row["price_source"] == etf_journal.PRICE_QUOTE
    assert row["id"] and row["timestamp"]


def test_symbol_and_broker_are_normalised():
    row = etf_journal.record_trade(broker="Public", account_id="p1",
                                   side="BUY", symbol="spy", qty=1)
    assert (row["broker"], row["side"], row["symbol"]) == ("public", "buy", "SPY")


def test_an_unknown_fill_price_stays_none():
    row = etf_journal.record_trade(broker="public", account_id="p1", side="buy",
                                   symbol="SPY", qty=1, fill_price=None)
    assert row["fill_price"] is None
    raw = json.loads(etf_journal.ETF_FILE.read_text())
    assert raw[0]["fill_price"] is None      # null, not 0.0


# ------------------------------------------------------------- positions

def test_positions_net_across_brokers_and_accounts():
    buy("SPY", 1, 770.56, broker="public", account="p1")
    buy("SPY", 1, 770.56, broker="public", account="p2")
    buy("SPY", 2, 700.00, broker="robinhood", account="r1")
    pos = etf_journal.positions()["SPY"]
    assert pos["qty"] == 4
    assert pos["accounts"] == 3
    assert pos["brokers"] == ["public", "robinhood"]
    assert abs(pos["avg_cost"] - (770.56 + 770.56 + 1400.0) / 4) < 1e-9


def test_a_sell_removes_basis_at_the_running_average():
    buy("SPY", 2, 100.0)
    buy("SPY", 2, 200.0)                       # avg 150
    etf_journal.record_trade(broker="public", account_id="p1", side="sell",
                             symbol="SPY", qty=2, fill_price=300.0)
    pos = etf_journal.positions()["SPY"]
    assert pos["qty"] == 2
    assert abs(pos["avg_cost"] - 150.0) < 1e-9   # selling high does not move it


def test_a_fully_sold_position_disappears():
    buy("SPY", 1, 100.0)
    etf_journal.record_trade(broker="public", account_id="p1", side="sell",
                             symbol="SPY", qty=1, fill_price=120.0)
    assert "SPY" not in etf_journal.positions()


def test_an_unpriced_buy_is_counted_so_the_cost_can_be_flagged():
    buy("SPY", 1, 100.0)
    etf_journal.record_trade(broker="public", account_id="p1", side="buy",
                             symbol="SPY", qty=1, fill_price=None)
    pos = etf_journal.positions()["SPY"]
    assert pos["qty"] == 2
    assert pos["unpriced"] == 1
    assert pos["cost"] == 100.0                 # the unpriced share adds none


# ------------------------------------------------------------- valuation

def test_unrealized_pl_is_market_value_against_cost():
    """The opposite of the RSA rule, on purpose — a held ETF is worth what it
    is worth."""
    buy("SPY", 2, 700.00)
    s = etf_journal.summary({"SPY": 800.00})
    assert s["cost"] == 1400.0
    assert s["market_value"] == 1600.0
    assert s["pl"] == 200.0
    assert abs(s["pl_pct"] - 14.2857) < 0.001


def test_a_loss_reports_as_a_loss():
    buy("SPY", 1, 800.00)
    assert etf_journal.summary({"SPY": 700.00})["pl"] == -100.0


def test_a_symbol_with_no_quote_is_excluded_from_pl_not_valued_at_zero():
    buy("SPY", 1, 700.0)
    buy("SCHX", 1, 30.0, broker="fidelity", account="f1")
    s = etf_journal.summary({"SPY": 800.0})       # no SCHX quote
    assert s["unquoted"] == ["SCHX"]
    assert s["cost"] == 730.0                    # cost still counts it
    assert s["market_value"] == 800.0
    assert s["pl"] == 100.0                      # 800 - 700, not 800 - 730


def test_summary_accepts_the_apps_quote_dicts():
    buy("SPY", 1, 700.0)
    s = etf_journal.summary({"SPY": {"price": 800.0, "pct": 1.2}})
    assert s["market_value"] == 800.0


def test_summary_of_an_empty_journal_is_zero_not_an_error():
    s = etf_journal.summary({"SPY": 800.0})
    assert s["symbols"] == 0 and s["cost"] == 0 and s["pl"] == 0


def test_by_exposure_groups_the_tiers_of_one_goal():
    """A plan that buys SPY at Public and SCHX at Fidelity is one S&P holding."""
    buy("SPY", 1, 770.0, broker="public", account="p1", exposure="sp500")
    buy("SCHX", 3, 30.43, broker="fidelity", account="f1", exposure="sp500")
    assert etf_journal.by_exposure()["sp500"] == ["SCHX", "SPY"]


# ------------------------------------------------------------- durability

def test_writes_are_atomic_and_leave_no_temp_file():
    buy()
    assert list(etf_journal.ETF_FILE.parent.glob("*.tmp")) == []


def test_a_corrupt_file_reads_as_empty_rather_than_raising():
    etf_journal.ETF_FILE.write_text("{not json", encoding="utf-8")
    assert etf_journal.get_trades() == []


def test_version_changes_when_a_trade_is_recorded():
    before = etf_journal.version()
    buy()
    assert etf_journal.version() != before


def test_delete_removes_one_row():
    a = buy()
    buy("SCHX", 1, 30.0)
    assert etf_journal.delete_trade(a["id"]) is True
    assert [t["symbol"] for t in etf_journal.get_trades()] == ["SCHX"]
    assert etf_journal.delete_trade("nope") is False
