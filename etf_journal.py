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
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from modules import atomic

ROOT_DIR = Path(__file__).resolve().parent
ETF_FILE = ROOT_DIR / "etf_trades.json"

_lock = threading.RLock()
_log = logging.getLogger(__name__)


class JournalUnreadable(RuntimeError):
    """etf_trades.json exists but could not be read (nor its .bak).

    Raised instead of returning [] so record_trade can never save
    `[] + new row` over every investment recorded so far. The trade worker in
    app.py catches it per account and reports the fill as NOT JOURNALED.
    """


_READ_ATTEMPTS = 4
_READ_DELAY = 0.05

#: Why the last read failed, or None.
_last_error: Optional[str] = None

#: Last rows read successfully, keyed by the file they came from -- what the
#: read-only pages fall back to.
_last_good: Dict[str, Any] = {"path": None, "rows": []}


def _remember(rows: List[Dict[str, Any]]) -> None:
    _last_good["path"], _last_good["rows"] = str(ETF_FILE), list(rows)

#: Mirrors trade_journal's vocabulary so the two read alike where they overlap.
PRICE_FILL = "fill"
PRICE_QUOTE = "quote"

__all__ = [
    "ETF_FILE", "PRICE_FILL", "PRICE_QUOTE", "JournalUnreadable",
    "record_trade", "set_fill_prices", "get_trades", "delete_trade", "version",
    "last_error",
    "positions", "summary", "by_exposure",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def last_error() -> Optional[str]:
    """Why the ETF log could not be read on the last attempt, or None."""
    return _last_error


def _bak() -> Path:
    return ETF_FILE.with_suffix(".bak")


def _read_file(path: Path) -> List[Dict[str, Any]]:
    """Parse one log file, retrying briefly. Raises OSError / ValueError.

    Same rules as trade_journal._read_file: utf-8-sig (an editor's BOM is not
    corruption), a few retries for a Drive/antivirus lock or a torn read, and
    FileNotFoundError at once.
    """
    err: Exception = OSError(f"could not read {path.name}")
    for attempt in range(_READ_ATTEMPTS):
        if attempt:
            time.sleep(_READ_DELAY * (2 ** (attempt - 1)))
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            raise
        except (OSError, ValueError) as e:
            err = e
            continue
        if not isinstance(data, list):
            raise ValueError(f"{path.name} is not a list of trades")
        return data
    raise err


def _load() -> List[Dict[str, Any]]:
    """Parse etf_trades.json for a read-modify-write.

    It used to return [] on ANY error, and record_trade then saved `[new row]`
    over the whole log -- while _save swallowed its own failures, so a fill
    could vanish without a word either way. Now [] means only "no file yet";
    a corrupt file is recovered from the .bak (and kept aside for a human), and
    anything else raises JournalUnreadable.
    """
    global _last_error
    try:
        rows = _read_file(ETF_FILE)
    except FileNotFoundError:
        _last_error = None
        _remember([])
        return []
    except ValueError as e:
        primary: Exception = e
    except OSError as e:
        _last_error = f"{ETF_FILE.name} could not be opened: {e}"
        _log.error("ETF JOURNAL UNREADABLE: %s", _last_error)
        raise JournalUnreadable(_last_error) from e
    else:
        _last_error = None
        _remember(rows)
        return rows

    try:
        rows = _read_file(_bak())
    except (OSError, ValueError) as e:
        _last_error = (f"{ETF_FILE.name} is corrupt ({primary}) and its backup "
                       f"could not be used ({e}). Nothing will be written "
                       f"until it is repaired.")
        _log.error("ETF JOURNAL UNREADABLE: %s", _last_error)
        raise JournalUnreadable(_last_error) from primary
    kept = atomic.quarantine(ETF_FILE)
    _last_error = (f"{ETF_FILE.name} is corrupt ({primary}); recovered "
                   f"{len(rows)} trades from {_bak().name}. The damaged file "
                   f"was kept as {kept.name if kept else '(copy failed)'}.")
    _log.warning("ETF JOURNAL RECOVERED FROM BACKUP: %s", _last_error)
    _remember(rows)
    return rows


def _save(trades: List[Dict[str, Any]], shrink_ok: bool = False) -> None:
    """Atomic, and LOUD: a failure raises, so the caller can say the fill was
    not journaled instead of the row quietly not existing.

    The .bak is refreshed after the write to the same contents, unless that
    would leave it with fewer rows than it already holds and the shrink is not
    an intentional delete -- a truncated log must not take its backup with it.
    """
    payload = json.dumps(trades, indent=2)
    atomic.write_text(ETF_FILE, payload)
    _remember(trades)
    try:
        if not shrink_ok and _bak().exists():
            try:
                backed_up = len(_read_file(_bak()))
            except (OSError, ValueError):
                backed_up = -1
            if len(trades) < backed_up:
                _log.warning("%s has %d rows but its backup has %d; keeping "
                             "the backup", ETF_FILE.name, len(trades), backed_up)
                return
        atomic.write_text(_bak(), payload)
    except Exception:
        _log.warning("%s saved but its backup could not be refreshed",
                     ETF_FILE.name, exc_info=True)


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
    with _lock, atomic.file_lock(ETF_FILE):
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def set_fill_prices(ids: List[str], fill_price: Optional[float],
                    price_source: str = PRICE_QUOTE) -> int:
    """Price rows journaled before their quote came back -- the same
    write-first, price-later order as trade_journal.set_fill_prices, so a
    crash during the slow quote lookup costs a price, never a fill."""
    if fill_price is None or not ids:
        return 0
    want = {str(i) for i in ids if i}
    with _lock, atomic.file_lock(ETF_FILE):
        trades = _load()
        n = 0
        for i, t in enumerate(trades):
            if t.get("id") in want:
                trades[i] = dict(t, fill_price=fill_price,
                                 price_source=price_source or PRICE_QUOTE)
                n += 1
        if n:
            _save(trades)
    return n


def get_trades(broker: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every ETF row. Never raises: the Invest page and the dashboard card
    render off this, so an unreadable log serves the last rows read (and
    last_error says why) instead of crashing them."""
    with _lock:
        try:
            trades = list(_load())
        except JournalUnreadable:
            trades = (list(_last_good["rows"])
                      if _last_good["path"] == str(ETF_FILE) else [])
    if broker:
        b = broker.lower()
        trades = [t for t in trades if t.get("broker") == b]
    return trades


def delete_trade(trade_id: str) -> bool:
    with _lock, atomic.file_lock(ETF_FILE):
        trades = _load()
        keep = [t for t in trades if t.get("id") != trade_id]
        if len(keep) == len(trades):
            return False
        _save(keep, shrink_ok=True)
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
