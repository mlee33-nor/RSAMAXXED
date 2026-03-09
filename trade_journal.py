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


def get_trades(broker: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all recorded trades, optionally filtered by broker."""
    with _lock:
        trades = _load()
    if broker:
        trades = [t for t in trades if t["broker"] == broker.lower()]
    return trades


def get_portfolio() -> Dict[tuple, Dict[str, Any]]:
    """Aggregate trades into net positions.

    Returns {(broker, symbol): {qty, avg_cost, total_cost}}.
    Buys add to position; sells reduce it (FIFO-style average).
    """
    positions: Dict[tuple, Dict[str, Any]] = {}
    for t in get_trades():
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
