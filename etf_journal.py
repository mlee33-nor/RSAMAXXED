"""
The ETF investment log — deliberately not `trade_journal`.

Two journals in one app invites the obvious question, so the answer is written
down here. There are three separate reasons, and any one of them alone would be
enough:

1. `cloud_sync._ALLOWED` whitelists the eight fields it uploads and drops the
   rest, so a `category` field added to a trades.json row would be stripped in
   transit. ETF buys would arrive at the web app — and at the paid public Plays
   board — indistinguishable from reverse-split picks. There is even a test
   guarding that whitelist (web/tests/test_client_contract.py) precisely so a
   new field cannot start uploading by accident. Nothing here is ever uploaded.

2. Every figure on the Analytics page folds the whole of trades.json: the
   realized hero, total volume, trade counts, the per-broker and per-symbol
   tables. A few hundred SPY shares would swamp all of it.

3. The P/L definitions are opposites. For a reverse-split play, only realized
   profit means anything — half the names have no real quote and not every one
   rounds up, so market value is noise. For a long-held ETF, market value is
   the entire point. Those two cannot share a computation, and a shared file
   would keep tempting one to be computed like the other.

So: same row shape, same helper names, different file, no cloud, and P/L that
is unapologetically unrealized.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent
ETF_FILE = ROOT_DIR / "etf_trades.json"

_lock = threading.RLock()

#: Mirrors trade_journal's vocabulary so the two read alike where they overlap.
PRICE_FILL = "fill"
PRICE_QUOTE = "quote"

__all__ = [
    "ETF_FILE", "PRICE_FILL", "PRICE_QUOTE",
    "record_trade", "get_trades", "delete_trade", "version",
    "positions", "summary", "by_exposure",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> List[Dict[str, Any]]:
    try:
        data = json.loads(ETF_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def _save(trades: List[Dict[str, Any]]) -> None:
    """Atomic. trade_journal writes straight over the file and a crash
    mid-write costs the lot; there is no reason to repeat that here."""
    try:
        tmp = ETF_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(trades, indent=2), encoding="utf-8")
        tmp.replace(ETF_FILE)
    except OSError:
        pass


def version() -> tuple:
    """(mtime_ns, size) — cheap change-detection for the page signature."""
    try:
        st = ETF_FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


def record_trade(broker: str, account_id: str, side: str, symbol: str,
                 qty: float, fill_price: Optional[float] = None,
                 order_id: Optional[str] = None, price_source: str = "",
                 exposure: str = "", plan_id: str = "") -> Dict[str, Any]:
    """Append one ETF fill.

    `fill_price` stays None when it is genuinely unknown rather than becoming
    0.0 — the same rule trade_journal follows, and for the same reason: a zero
    basis reports the entire position as profit.
    """
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": _now(),
        "broker": str(broker).lower(),
        "account_id": str(account_id),
        "side": str(side).lower(),
        "symbol": str(symbol).upper(),
        "qty": float(qty),
        "fill_price": fill_price,
        "order_id": order_id or None,
        "price_source": price_source or PRICE_QUOTE,
        "exposure": exposure or "",
        "plan_id": plan_id or "",
    }
    with _lock:
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def get_trades(broker: Optional[str] = None) -> List[Dict[str, Any]]:
    with _lock:
        trades = _load()
    if broker:
        b = broker.lower()
        trades = [t for t in trades if t.get("broker") == b]
    return trades


def delete_trade(trade_id: str) -> bool:
    with _lock:
        trades = _load()
        keep = [t for t in trades if t.get("id") != trade_id]
        if len(keep) == len(trades):
            return False
        _save(keep)
        return True


def positions(trades: Optional[Iterable[Dict[str, Any]]] = None
              ) -> Dict[str, Dict[str, Any]]:
    """Open ETF positions by symbol, netted across every broker and account.

    A sell reduces the quantity and removes basis at the current average, so
    the average cost of what is still held does not move when part of it is
    sold. Positions that net to nothing are dropped rather than lingering at
    zero.
    """
    rows = list(get_trades() if trades is None else trades)
    book: Dict[str, Dict[str, Any]] = {}
    for t in rows:
        sym = str(t.get("symbol") or "").upper()
        if not sym:
            continue
        qty = float(t.get("qty") or 0.0)
        price = t.get("fill_price")
        d = book.setdefault(sym, {
            "symbol": sym, "qty": 0.0, "cost": 0.0,
            "brokers": set(), "accounts": set(),
            "unpriced": 0, "exposure": "",
        })
        d["brokers"].add(t.get("broker") or "")
        d["accounts"].add((t.get("broker") or "", t.get("account_id") or ""))
        if t.get("exposure"):
            d["exposure"] = t["exposure"]
        if str(t.get("side") or "").lower() == "sell":
            avg = (d["cost"] / d["qty"]) if d["qty"] else 0.0
            sold = min(qty, d["qty"])
            d["qty"] -= sold
            d["cost"] -= avg * sold
        else:
            if price is None:
                # Counts toward the position but contributes no basis, so the
                # page can say the cost is understated instead of quietly
                # reporting the shortfall as profit.
                d["unpriced"] += 1
            d["qty"] += qty
            d["cost"] += (price or 0.0) * qty

    out: Dict[str, Dict[str, Any]] = {}
    for sym, d in book.items():
        if d["qty"] <= 1e-9:
            continue
        d["avg_cost"] = d["cost"] / d["qty"] if d["qty"] else 0.0
        d["brokers"] = sorted(b for b in d["brokers"] if b)
        d["accounts"] = len(d["accounts"])
        out[sym] = d
    return out


def summary(prices: Optional[Dict[str, Any]] = None,
            trades: Optional[Iterable[Dict[str, Any]]] = None
            ) -> Dict[str, Any]:
    """Cost, market value and UNREALIZED P/L across every ETF position.

    Unrealized is the right measure here and the wrong one two screens over.
    A held ETF is worth what it is worth; a reverse-split play is worth nothing
    until it is sold, because not every one rounds up. The rule is opposite in
    the two places on purpose, so neither total is ever added to the other.

    A symbol with no quote contributes its cost to `cost` and nothing to
    `market_value`; it is counted in `unquoted` so the caller can say the
    valuation is partial rather than showing a loss that is really a missing
    price.
    """
    px = {str(k).upper(): v for k, v in (prices or {}).items()}
    pos = positions(trades)
    cost = 0.0
    value = 0.0
    unquoted: List[str] = []
    rows: List[Dict[str, Any]] = []
    for sym, d in sorted(pos.items()):
        quote = px.get(sym)
        if isinstance(quote, dict):
            quote = quote.get("price")
        cost += d["cost"]
        row = dict(d)
        if quote is None:
            unquoted.append(sym)
            row["price"] = None
            row["market_value"] = None
            row["pl"] = None
            row["pl_pct"] = None
        else:
            mv = float(quote) * d["qty"]
            value += mv
            row["price"] = float(quote)
            row["market_value"] = mv
            row["pl"] = mv - d["cost"]
            row["pl_pct"] = ((mv - d["cost"]) / d["cost"] * 100.0
                             if d["cost"] else None)
        rows.append(row)

    quoted_cost = sum(r["cost"] for r in rows if r["market_value"] is not None)
    return {
        "positions": rows,
        "symbols": len(rows),
        "cost": cost,
        "market_value": value,
        "pl": value - quoted_cost,
        "pl_pct": ((value - quoted_cost) / quoted_cost * 100.0
                   if quoted_cost else None),
        "unquoted": unquoted,
        "unpriced_buys": sum(r["unpriced"] for r in rows),
    }


def by_exposure(trades: Optional[Iterable[Dict[str, Any]]] = None
                ) -> Dict[str, List[str]]:
    """{exposure_key: [symbols]} — which tickers were bought for which goal,
    so a plan that bought SPY at Public and SCHX at Fidelity still reads as one
    S&P 500 holding."""
    out: Dict[str, List[str]] = {}
    for sym, d in positions(trades).items():
        out.setdefault(d.get("exposure") or "", []).append(sym)
    for k in out:
        out[k].sort()
    return out
