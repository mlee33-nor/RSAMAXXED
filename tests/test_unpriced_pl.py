"""A row with fill_price None must not move realized P/L.

Counted at $0, an unpriced BUY dragged the average basis down (fake profit) and
an unpriced SELL booked the whole basis as a loss. The Command Center hero
(`_portfolio_summary`) and the website (web/app/analytics.py) must agree, so
both are checked against the same journal here.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as A
import trade_journal

_spec = importlib.util.spec_from_file_location(
    "web_analytics", ROOT / "web" / "app" / "analytics.py")
analytics = importlib.util.module_from_spec(_spec)
sys.modules["web_analytics"] = analytics
_spec.loader.exec_module(analytics)


def _r(i, side, sym, qty, price, broker="public"):
    return {"id": f"r{i}", "timestamp": f"2026-07-{i:02d}T14:00:00+00:00",
            "broker": broker, "account_id": "Public 1", "side": side,
            "symbol": sym, "qty": qty, "fill_price": price}


ROWS = [
    # AAA: two priced buys at $1, one unpriced; all three sold at $2.
    _r(1, "buy", "AAA", 1, 1.0), _r(2, "buy", "AAA", 1, 1.0),
    _r(3, "buy", "AAA", 1, None), _r(4, "sell", "AAA", 3, 2.0),
    # BBB: priced buy, one priced and one unpriced sell.
    _r(5, "buy", "BBB", 2, 1.0), _r(6, "sell", "BBB", 1, 3.0),
    _r(7, "sell", "BBB", 1, None),
    # CCC: no priced buy at all -- no basis, left out.
    _r(8, "buy", "CCC", 1, None), _r(9, "sell", "CCC", 1, 5.0),
]


@pytest.fixture()
def journal(tmp_path, monkeypatch):
    p = tmp_path / "trades.json"
    p.write_text(json.dumps(ROWS), encoding="utf-8")
    monkeypatch.setattr(trade_journal, "_FILE", p)
    trade_journal._cache.clear()
    yield p
    trade_journal._cache.clear()


def test_desktop_hero_ignores_unpriced_rows(journal):
    s = A.App._portfolio_summary(None)
    # AAA (2-1)*3 = 3.00; BBB (3-1)*1 = 2.00; CCC excluded.
    assert s["realized"] == pytest.approx(5.0)
    assert (s["wins"], s["losses"]) == (2, 0)
    assert s["open_count"] == 0


def test_web_analytics_agrees_with_the_desktop(journal):
    desktop = A.App._portfolio_summary(None)
    web = analytics.summarize(analytics.to_tradelike(ROWS))
    assert web.realized == pytest.approx(desktop["realized"])
    assert (web.wins, web.losses) == (desktop["wins"], desktop["losses"])
    assert web.zero_basis_symbols == ["CCC"]
    assert analytics.equity_curve(analytics.to_tradelike(ROWS))[-1][1] == \
        pytest.approx(web.realized)


def test_refresh_stats_maths_uses_priced_quantity_only():
    """Structural guard on _refresh_stats: every average there divides by a
    priced quantity. (The method needs the whole Analytics page to run.)"""
    import inspect
    src = inspect.getsource(A.App._refresh_stats)
    assert 'ab["cost"] / ab["qty"]' not in src
    assert 'ab["buy_cost"] / ab["bought"]' not in src
    assert 'buy_d["buy_cost"] / buy_d["bought"]' not in src
    assert 'd["buy_cost"] / d["bought"]' not in src
    assert '(t["fill_price"] or 0) - avg_b' not in src
