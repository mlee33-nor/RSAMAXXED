"""Guards the one invariant that matters: the website's realized P/L equals
the desktop app's realized P/L.

`_app_py_reference` is a verbatim transcription of `App._portfolio_summary`
in app.py, including the lens it reads the journal through
(trade_journal.split_adjusted over get_trades' canonical rows). If someone
edits the GUI's math, this test fails and tells them to edit
web/app/analytics.py to match (or vice versa).

It used to transcribe the OLD loop -- unpriced rows counted at $0, no split
lens -- after app.py had moved on, so it failed on the real journal by $0.87
while the website was in fact $836 away from the desktop.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import analytics  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
# RSA_TRADES_JSON points the real-journal case at a copy kept elsewhere (the
# worktree a fix is made in has no trades.json of its own).
TRADES_JSON = pathlib.Path(os.environ.get("RSA_TRADES_JSON") or REPO_ROOT / "trades.json")
sys.path.insert(0, str(REPO_ROOT))

import trade_journal  # noqa: E402


def _app_py_reference(raw):
    """Verbatim copy of App._portfolio_summary (no renames: the website has
    no TRACK board, and the desktop with an empty board folds nothing)."""
    trades = trade_journal.split_adjusted(trade_journal._canonical_rows(list(raw)))
    buys, sells, open_qty = {}, {}, {}
    for t in trades:
        sym = t["symbol"]
        qty = float(t.get("qty", 0) or 0)
        price = t.get("fill_price")
        key = (t["broker"], sym)
        if t["side"] == "buy":
            b = buys.setdefault(sym, {"qty": 0.0, "cost": 0.0})
            if price is not None:
                b["qty"] += qty
                b["cost"] += price * qty
            open_qty[key] = open_qty.get(key, 0.0) + qty
        elif t["side"] == "sell":
            s = sells.setdefault(sym, {"qty": 0.0, "rev": 0.0})
            if price is not None:
                s["qty"] += qty
                s["rev"] += price * qty
            open_qty[key] = open_qty.get(key, 0.0) - qty
        elif t["side"] == trade_journal.SIDE_CLOSE:
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


def _synthetic_edges():
    t0 = datetime(2026, 1, 5, tzinfo=timezone.utc)
    def tr(days, broker, side, sym, qty, px):
        return {
            "timestamp": (t0 + timedelta(days=days)).isoformat(),
            "broker": broker, "account_id": broker + "-1",
            "side": side, "symbol": sym, "qty": qty, "fill_price": px,
        }
    return [
        # A 1-for-10 remnant: bought 1 @ $1.30, 0.1 sold @ $10.00. Split-
        # adjusted that is -$0.30, not +$0.87 -- and the sell is journaled
        # under a drifted label of the same account number.
        dict(tr(1, "fidelity", "buy", "GRNQ", 1, 1.30),
             account_id="Fidelity 1 · Individual (Z1)"),
        dict(tr(12, "fidelity", "sell", "GRNQ", 0.1, 10.00),
             account_id="Fidelity 1 · FinTec (Z1)"),
        # Unpriced rows move the position, never the money.
        tr(5, "chase", "buy", "MASK", 2, 1.00),
        tr(6, "chase", "buy", "MASK", 2, None),
        tr(15, "chase", "sell", "MASK", 1, None),
        tr(16, "chase", "sell", "MASK", 1, 3.00),
    ]


def _cases():
    cases = [("synthetic", _synthetic()), ("edges", _synthetic_edges())]
    if TRADES_JSON.exists():
        cases.append(("real trades.json",
                      json.loads(TRADES_JSON.read_text("utf-8-sig"))))
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
    """A symbol with no priced buy has no cost basis. Its sale is left out of
    realized (not booked as pure profit) and the symbol is surfaced."""
    trades = analytics.to_tradelike([
        {"timestamp": "2026-01-01T00:00:00+00:00", "broker": "fennel", "account_id": "a",
         "side": "buy", "symbol": "GHOST", "qty": 1, "fill_price": None},
        {"timestamp": "2026-01-09T00:00:00+00:00", "broker": "fennel", "account_id": "a",
         "side": "sell", "symbol": "GHOST", "qty": 1, "fill_price": 9.0},
    ])
    s = analytics.summarize(trades)
    assert s.zero_basis_symbols == ["GHOST"]
    assert s.realized == 0.0  # excluded, not $9 of invented profit


def test_open_position_never_counted_as_profit():
    trades = analytics.to_tradelike(_synthetic())
    s = analytics.summarize(trades)
    assert [p["symbol"] for p in s.open_positions if p["symbol"] == "OPEN"] == ["OPEN"]
    assert s.closed == 2  # HERZ (win) + AIFA (loss); OPEN contributes nothing


def _row(day, side, sym, qty, price, broker="fennel"):
    return {"timestamp": f"2026-01-{day:02d}T00:00:00+00:00", "broker": broker,
            "account_id": "a", "side": side, "symbol": sym, "qty": qty,
            "fill_price": price}


def test_an_unpriced_buy_does_not_drag_the_average_down():
    """Two buys at $1.00, one unpriced: the basis is $1.00, not $0.67."""
    trades = analytics.to_tradelike([
        _row(1, "buy", "AAA", 1, 1.0), _row(2, "buy", "AAA", 1, 1.0),
        _row(3, "buy", "AAA", 1, None),
        _row(9, "sell", "AAA", 3, 2.0)])
    s = analytics.summarize(trades)
    assert abs(s.realized - 3.0) < 1e-9          # (2.00 - 1.00) x 3
    assert s.zero_basis_symbols == []
    assert abs(analytics.equity_curve(trades)[-1][1] - s.realized) < 1e-9


def test_an_unpriced_sell_is_not_a_fake_loss():
    trades = analytics.to_tradelike([
        _row(1, "buy", "BBB", 2, 1.0),
        _row(5, "sell", "BBB", 1, 3.0), _row(6, "sell", "BBB", 1, None)])
    s = analytics.summarize(trades)
    assert abs(s.realized - 2.0) < 1e-9          # only the priced sell counts
    assert s.wins == 1 and s.losses == 0
    assert s.open_count == 0                     # the position still closed
    total = sum(v for _k, v in analytics.realized_by_broker(trades))
    assert abs(total - s.realized) < 1e-9


def test_split_remnant_and_unpriced_rows_match_the_desktop():
    """The edge rows on their own: the remnant books -$0.30 (not +$0.87) even
    though its sell carries a drifted label, and the unpriced MASK rows move
    neither side of the money."""
    s = analytics.summarize(analytics.to_tradelike(_synthetic_edges()))
    # GRNQ: 1.00 proceeds - 1.30 paid = -0.30. MASK: (3 - 1) * 1 = +2.00.
    assert abs(s.realized - 1.70) < 1e-9
    assert (s.wins, s.losses) == (1, 1)
    assert [p["symbol"] for p in s.open_positions] == ["MASK"]
