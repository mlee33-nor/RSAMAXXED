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
    """Parse trades.json. Raw read — no cache, for read-modify-write callers."""
    if not _FILE.exists():
        return []
    try:
        return json.loads(_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


#: Parsed journal, keyed by the file fingerprint it was parsed from.
#:
#: The journal is 4,500+ rows and ~1.4MB, so a parse costs ~10ms. Nothing
#: cached it, and the read paths call in far more often than that suggests:
#: one Quick Picks render alone went through five full parses, because
#: _purchased_pick_keys and _partial_pick_keys each recompute the same
#: coverage from scratch. That is ~50ms of blocked UI thread per render, on
#: a file that only changes when we place a trade.
#:
#: Keyed on version() — the same (mtime_ns, size) fingerprint the GUI already
#: trusts for its page cache — so an external writer (reconcile.py, a restore
#: from backup) is picked up on the next call rather than being served stale.
_cache: Dict[str, Any] = {"key": None, "rows": []}


def _load_shared() -> List[Dict[str, Any]]:
    """The parsed journal, reused while the file underneath is unchanged.

    Returns the SHARED list — callers must not mutate it. `get_trades` hands
    out a copy; the read-modify-write paths deliberately use `_load` instead.
    """
    key = version()
    if _cache["key"] != key:
        _cache["rows"] = _load()
        _cache["key"] = key
    return _cache["rows"]


def _save(trades: List[Dict[str, Any]]) -> None:
    _FILE.write_text(json.dumps(trades, indent=2), encoding="utf-8")
    # Refresh rather than merely invalidate: we already hold the rows, and the
    # very next thing a writer does is re-render off them.
    _cache["rows"] = list(trades)
    _cache["key"] = version()


#: What `fill_price` on a row actually is.
#:
#: "fill"  the broker told us what the order executed at. Trustworthy.
#: "quote" the market price at the moment we placed it, which is NOT the same
#:         thing and can be far from it on a thin post-split name.
#: ""      recorded before this field existed, so unknown — treat as "quote".
PRICE_FILL = "fill"
PRICE_QUOTE = "quote"

#: A position that LEFT an account without a sale this tool placed.
#:
#: The journal only learns about trades it executes, so a position can vanish
#: for reasons it never sees — most often a reverse split settling to CASH IN
#: LIEU at a broker that does not hold fractions. Seven of the ten do exactly
#: that, and the shares stop existing the moment the split runs.
#:
#: It is its own side because neither existing one can say this honestly:
#:
#:   a sell at no price     books the entire cost basis as a loss. $198 of
#:                          dissolved positions would become $198 of invented
#:                          losses.
#:   a sell at some price   invents proceeds nobody received.
#:   leaving it open        is what produces a $428 "deployed" figure of which
#:                          $198 is shares that have not existed for weeks.
#:
#: So a close records the ONE thing actually known — the position is gone — and
#: stays out of the profit arithmetic entirely, where `unaccounted()` reports it
#: rather than letting it quietly become a number.
SIDE_CLOSE = "close"

#: Why a position was closed. Free text, but these are the ones that recur.
CLOSE_CASH_IN_LIEU = "cash_in_lieu"
CLOSE_RECONCILED = "reconciled"     # the broker simply does not have it



def is_estimated(trade: Dict[str, Any]) -> bool:
    """True when this row's price is a quote rather than an executed fill.

    Every row written before 2026-08-06 is estimated: the app called what it
    named `_fetch_fill_price`, which asks get_holdings() for the CURRENT market
    price and falls back to Yahoo — it never read an execution. One lookup per
    batch was then stamped onto every account in it, which is why the journal
    contains nine Wells Fargo orders placed across 7.4 minutes all priced at
    exactly $0.08.
    """
    return trade.get("price_source") != PRICE_FILL


def record_trade(
    broker: str,
    account_id: str,
    side: str,
    symbol: str,
    qty: float,
    fill_price: Optional[float] = None,
    order_id: Optional[str] = None,
    price_source: str = "",
) -> Dict[str, Any]:
    """Append a trade entry and return it.

    `order_id` is the broker's own identifier for the order. It was previously
    returned by the API, carried as far as AccountOutput.order_id, and then
    dropped here — which is why no trade in the journal can be checked against
    the broker that placed it. Keeping it costs one field and is the only thing
    that makes a fill recoverable after the fact.
    """
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "broker": broker.lower(),
        "account_id": account_id,
        "side": side.lower(),
        "symbol": symbol.upper(),
        "qty": float(qty),
        "fill_price": fill_price,
        "order_id": order_id or None,
        "price_source": price_source or PRICE_QUOTE,
    }
    with _lock:
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def record_close(
    broker: str,
    account_id: str,
    symbol: str,
    qty: float,
    reason: str = CLOSE_RECONCILED,
    note: str = "",
) -> Dict[str, Any]:
    """Record that a position is gone, without claiming it was sold.

    See SIDE_CLOSE. This is the only honest entry for a holding that a
    corporate action dissolved: it removes the position so the sell worklist
    and the deployed figure stop counting shares that do not exist, and it
    carries NO price, so nothing downstream can turn it into profit or loss.
    """
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "broker": broker.lower(),
        "account_id": account_id,
        "side": SIDE_CLOSE,
        "symbol": symbol.upper(),
        "qty": float(qty),
        "fill_price": None,
        "order_id": None,
        "price_source": "",
        "close_reason": reason,
        "note": note,
    }
    with _lock:
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def unaccounted(trades: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Cost basis removed by closes rather than by sales.

    Reported, never folded in. Cash in lieu DID pay something, so this money is
    not lost -- it is unknown, and a figure the app calls realized must not
    pretend either way.
    """
    rows = get_trades() if trades is None else list(trades)
    cost: Dict[str, Dict[str, float]] = {}
    for t in rows:
        if t.get("side") == "buy":
            b = cost.setdefault(t["symbol"], {"qty": 0.0, "cost": 0.0})
            b["qty"] += float(t.get("qty") or 0)
            b["cost"] += (t.get("fill_price") or 0) * float(t.get("qty") or 0)

    total = 0.0
    by_reason: Dict[str, float] = {}
    n = 0
    for t in rows:
        if t.get("side") != SIDE_CLOSE:
            continue
        b = cost.get(t["symbol"])
        if not b or not b["qty"]:
            continue
        v = (b["cost"] / b["qty"]) * float(t.get("qty") or 0)
        total += v
        n += 1
        r = t.get("close_reason") or CLOSE_RECONCILED
        by_reason[r] = by_reason.get(r, 0.0) + v
    return {"total": total, "positions": n, "by_reason": by_reason}


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
    """Return all recorded trades, optionally filtered by broker.

    The returned list is a copy, so callers can filter and sort it freely; the
    row dicts inside are shared with the cache and must be treated as read-only
    (nothing mutates them today — split_adjusted copies every row it restates).
    """
    with _lock:
        trades = _load_shared()
        if broker:
            return [t for t in trades if t["broker"] == broker.lower()]
        return list(trades)


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
        elif side == SIDE_CLOSE:
            # Reduces the position and nothing else. Never restated: a close
            # carries no price, so there is no proceeds figure to put back into
            # pre-split units, and a fractional close is simply the fraction
            # that dissolved.
            held[key] = max(0.0, held.get(key, 0.0) - qty)
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
        elif t["side"] in ("sell", SIDE_CLOSE):
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
