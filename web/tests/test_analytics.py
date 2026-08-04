"""Guards the one invariant that matters: the website's realized P/L equals
the desktop app's realized P/L.

`_app_py_reference` is a verbatim transcription of `App._portfolio_summary`
from app.py:3048. If someone edits the GUI's math, this test fails and tells
them to edit web/app/analytics.py to match (or vice versa).
"""
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import analytics  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TRADES_JSON = REPO_ROOT / "trades.json"


def _app_py_reference(trades):
    """Verbatim copy of App._portfolio_summary (app.py:3048)."""
    buys, sells, open_qty = {}, {}, {}
    for t in trades:
        sym = t["symbol"]
        qty = float(t.get("qty", 0) or 0)
        price = t.get("fill_price")
        key = (t["broker"], sym)
        if t["side"] == "buy":
            b = buys.setdefault(sym, {"qty": 0.0, "cost": 0.0})
            b["qty"] += qty
            b["cost"] += (price or 0) * qty
            open_qty[key] = open_qty.get(key, 0.0) + qty
        elif t["side"] == "sell":
            s = sells.setdefault(sym, {"qty": 0.0, "rev": 0.0})
            s["qty"] += qty
            s["rev"] += (price or 0) * qty
            open_qty[key] = open_qty.get(key, 0.0) - qty

    realized = 0.0
    wins = losses = 0
    for sym, s in sells.items():
        b = buys.get(sym)
        if not b or not b["qty"] or not s["qty"]:
            continue
        avg_b = b["cost"] / b["qty"]
        avg_s = s["rev"] / s["qty"]
        profit = (avg_s - avg_b) * s["qty"]
        realized += profit
        if profit > 0:
            wins += 1
        elif profit < 0:
            losses += 1

    sym_open = {}
    for (_b, sym), q in open_qty.items():
        if q > 1e-9:
            sym_open[sym] = sym_open.get(sym, 0.0) + q
    deployed = 0.0
    for sym, q in sym_open.items():
        b = buys.get(sym)
        if b and b["qty"]:
            deployed += (b["cost"] / b["qty"]) * q
    return {
        "realized": realized, "wins": wins, "losses": losses,
        "closed": wins + losses, "open_count": len(sym_open), "deployed": deployed,
    }


def _synthetic():
    t0 = datetime(2026, 1, 5, tzinfo=timezone.utc)
    def tr(days, broker, side, sym, qty, px):
        return {
            "timestamp": (t0 + timedelta(days=days)).isoformat(),
            "broker": broker, "account_id": broker + "-1",
            "side": side, "symbol": sym, "qty": qty, "fill_price": px,
        }
    return [
        tr(0, "fidelity", "buy", "HERZ", 1, 2.00),
        tr(0, "chase", "buy", "HERZ", 1, 2.20),
        tr(9, "fidelity", "sell", "HERZ", 1, 11.00),
        tr(9, "chase", "sell", "HERZ", 1, 10.00),
        tr(2, "public", "buy", "AIFA", 3, 1.50),
        tr(20, "public", "sell", "AIFA", 1, 0.90),   # a loser
        tr(4, "sofi", "buy", "OPEN", 2, 5.00),       # never sold -> open
    ]


def _cases():
    cases = [("synthetic", _synthetic())]
    if TRADES_JSON.exists():
        cases.append(("real trades.json", json.loads(TRADES_JSON.read_text("utf-8"))))
    return cases


def test_matches_app_py_reference():
    for label, raw in _cases():
        ref = _app_py_reference(raw)
        got = analytics.summarize(analytics.to_tradelike(raw))
        assert abs(got.realized - ref["realized"]) < 1e-6, f"{label}: realized"
        assert got.wins == ref["wins"], f"{label}: wins"
        assert got.losses == ref["losses"], f"{label}: losses"
        assert got.closed == ref["closed"], f"{label}: closed"
        assert got.open_count == ref["open_count"], f"{label}: open_count"
        assert abs(got.deployed - ref["deployed"]) < 1e-6, f"{label}: deployed"


def test_breakdowns_sum_to_grand_total():
    """Per-sell attribution telescopes back to the per-symbol total. If this
    breaks, the charts will disagree with the hero number."""
    for label, raw in _cases():
        trades = analytics.to_tradelike(raw)
        total = analytics.summarize(trades).realized
        for name, series in (
            ("broker", analytics.realized_by_broker(trades)),
            ("month", analytics.realized_by_month(trades)),
        ):
            assert abs(sum(v for _k, v in series) - total) < 1e-6, f"{label}: by-{name}"
        curve = analytics.equity_curve(trades)
        if curve:
            assert abs(curve[-1][1] - total) < 1e-6, f"{label}: equity curve endpoint"


def test_zero_basis_symbols_are_flagged():
    """A buy with no fill price yields a 0 cost basis, so its sell books the
    full proceeds as profit. That must be surfaced, not silently trusted."""
    trades = analytics.to_tradelike([
        {"timestamp": "2026-01-01T00:00:00+00:00", "broker": "bbae", "account_id": "a",
         "side": "buy", "symbol": "GHOST", "qty": 1, "fill_price": None},
        {"timestamp": "2026-01-09T00:00:00+00:00", "broker": "bbae", "account_id": "a",
         "side": "sell", "symbol": "GHOST", "qty": 1, "fill_price": 9.0},
    ])
    s = analytics.summarize(trades)
    assert s.zero_basis_symbols == ["GHOST"]
    assert abs(s.realized - 9.0) < 1e-9  # inflated, and correctly reported as such


def test_open_position_never_counted_as_profit():
    trades = analytics.to_tradelike(_synthetic())
    s = analytics.summarize(trades)
    assert [p["symbol"] for p in s.open_positions if p["symbol"] == "OPEN"] == ["OPEN"]
    assert s.closed == 2  # HERZ (win) + AIFA (loss); OPEN contributes nothing
