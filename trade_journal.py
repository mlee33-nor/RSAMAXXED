"""Persistent trade journal backed by trades.json.

Records every trade executed through this tool so we can distinguish
"shares I bought" from pre-existing holdings and compute P/L.

EXE packaging: pip install pyinstaller && pyinstaller --onefile --windowed app.py
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_FILE = Path(__file__).resolve().parent / "trades.json"
_lock = threading.Lock()


def _load() -> List[Dict[str, Any]]:
    if not _FILE.exists():
        return []
    try:
        return json.loads(_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _save(trades: List[Dict[str, Any]]) -> None:
    _FILE.write_text(json.dumps(trades, indent=2), encoding="utf-8")


def record_trade(
    broker: str,
    account_id: str,
    side: str,
    symbol: str,
    qty: float,
    fill_price: Optional[float] = None,
) -> Dict[str, Any]:
    """Append a trade entry and return it."""
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "broker": broker.lower(),
        "account_id": account_id,
        "side": side.lower(),
        "symbol": symbol.upper(),
        "qty": float(qty),
        "fill_price": fill_price,
    }
    with _lock:
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def version() -> tuple:
    """A cheap fingerprint of the journal: (mtime_ns, size). No parse, no lock.

    Exists so the GUI can ask "has anything changed?" without reading and
    parsing ~2000 rows on every tab switch, which is what it used to do.
    Returns (0, 0) when the file is missing, so an empty journal has a stable
    identity rather than a changing one.
    """
    try:
        st = _FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


def get_trades(broker: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all recorded trades, optionally filtered by broker."""
    with _lock:
        trades = _load()
    if broker:
        trades = [t for t in trades if t["broker"] == broker.lower()]
    return trades


def split_adjusted(trades: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """The journal restated in PRE-SPLIT shares. For P/L and position maths.

    A reverse split changes your share count with no trade to record, so the
    journal never sees it happen. That quietly breaks any profit computed from
    per-share prices. Buy 1 share of GRNQ at $1.30, let a 1-for-10 split turn it
    into 0.1 of a share, sell that for $10.00, and

        (sell price - buy price) x shares sold  =  (10.00 - 1.30) x 0.1  =  +$0.87

    reports a profit on a trade that took $1.30 and gave back $1.00. It charges a
    tenth of what was paid against the whole of the proceeds. Across 19 Public
    accounts that was +$16.53 where the truth is -$5.70 — and it is wrong in the
    flattering direction on exactly the plays that did NOT round up, which are
    the ones worth reporting honestly.

    THE RULE, and it is deliberately narrow:

        a sell whose quantity is a FRACTION of a share is what a reverse split
        left of whole shares already held. That fraction was never bought, so it
        does not get a fraction's cost basis — it gets the basis of the shares
        it came from.

    So the sell is restated into the units the buy was recorded in: the same
    cash, spread across the shares that actually produced it.

        sold 0.1 @ $10.00   ->   sold 1.0 @ $1.00      ($1.00 of proceeds either way)

    Both sides of the subtraction are finally in the same units, so every figure
    downstream corrects itself — including the open position, which now closes
    to zero instead of leaving 0.9 phantom shares that no longer exist.

    Only FRACTIONAL sells are touched. A sell of whole shares smaller than the
    position is an ordinary partial exit (13 of 26 accounts sold), the existing
    arithmetic is right about it, and widening this rule to cover that case
    would charge a whole position's basis to the first account that sold.

    The executed quantity and price stay on the row as `executed_qty` and
    `executed_price`: a trade history has to show the fill that really happened.
    Rows are copies and trades.json is never rewritten — this is a lens, not a
    migration, so it stays correct for trades recorded before it existed.
    """
    # Processed in file order, which is chronological: record_trade only ever
    # appends. Sorting here would be a no-op that also reordered the caller's
    # list out from under a display that expects newest-last.
    rows = get_trades() if trades is None else list(trades)
    held: Dict[tuple, float] = {}
    out: List[Dict[str, Any]] = []
    for t in rows:
        row = dict(t)
        key = (row.get("broker"), row.get("account_id"), row.get("symbol"))
        try:
            qty = float(row.get("qty") or 0.0)
        except (TypeError, ValueError):
            out.append(row)
            continue
        side = str(row.get("side") or "").lower()

        if side == "buy":
            held[key] = held.get(key, 0.0) + qty
        elif side == "sell":
            have = held.get(key, 0.0)
            # A whole-share sell is an ordinary exit; only a fraction of a share
            # can be a split remnant, and only if there was something to split.
            if abs(qty - round(qty)) > 1e-9 and 0 < qty < have:
                price = row.get("fill_price")
                proceeds = (price or 0.0) * qty
                row["executed_qty"] = qty
                row["executed_price"] = price
                row["split_ratio"] = have / qty
                row["qty"] = have
                # None stays None: an unpriced fill has no basis, and inventing
                # $0.00 here would book the whole position as a total loss.
                row["fill_price"] = (proceeds / have) if price is not None else None
                qty = have
            held[key] = max(0.0, have - qty)
        out.append(row)
    return out


def get_portfolio() -> Dict[tuple, Dict[str, Any]]:
    """Aggregate trades into net positions.

    Returns {(broker, symbol): {qty, avg_cost, total_cost}}.
    Buys add to position; sells reduce it (FIFO-style average).

    Split-adjusted, because a position is exactly what the raw journal gets
    wrong: a sold-off split remnant nets 1.0 - 0.1 and leaves 0.9 of a share
    that no longer exists sitting in the portfolio forever.
    """
    positions: Dict[tuple, Dict[str, Any]] = {}
    for t in split_adjusted():
        key = (t["broker"], t["symbol"])
        pos = positions.setdefault(key, {"qty": 0.0, "avg_cost": 0.0, "total_cost": 0.0})
        price = t["fill_price"] if t["fill_price"] is not None else 0.0
        if t["side"] == "buy":
            pos["total_cost"] += price * t["qty"]
            pos["qty"] += t["qty"]
            pos["avg_cost"] = pos["total_cost"] / pos["qty"] if pos["qty"] else 0.0
        elif t["side"] == "sell":
            if pos["qty"] > 0:
                # reduce position, keep avg_cost the same
                sold_qty = min(t["qty"], pos["qty"])
                pos["total_cost"] -= pos["avg_cost"] * sold_qty
                pos["qty"] -= sold_qty
                if pos["qty"] <= 0:
                    pos["qty"] = 0.0
                    pos["total_cost"] = 0.0
                    pos["avg_cost"] = 0.0
    # filter out zero-quantity positions
    return {k: v for k, v in positions.items() if v["qty"] > 0}


def delete_trade(trade_id: str) -> bool:
    """Remove a trade entry by ID. Returns True if found and deleted."""
    with _lock:
        trades = _load()
        before = len(trades)
        trades = [t for t in trades if t["id"] != trade_id]
        if len(trades) < before:
            _save(trades)
            return True
    return False
