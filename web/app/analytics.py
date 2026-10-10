"""Realized P/L, ported from the desktop app's `_portfolio_summary()`
(app.py:3048). The numbers here MUST equal the numbers in the GUI, so the
core loop below is a deliberate line-for-line mirror. Do not "improve" the
math in one place without changing the other.

Why realized-only: this is reverse-split round-up arbitrage. Live prices tell
you nothing about whether a name rounded up, and many OTC picks have no real
quote. The only true profit is a recorded buy matched with a confirmed sell.

Per-symbol basis, all-time, over PRICED rows only (fill_price not None):
    avg_buy  = priced buy cost / priced buy qty
    avg_sell = priced sell rev / priced sell qty
    profit   = (avg_sell - avg_buy) * priced sell qty

An unpriced row still moves the open position, but never the money. Counting
it at $0 made an unpriced buy a fake profit and an unpriced sell a fake loss of
its whole basis; a symbol with no priced buy at all has no basis and is left
out of realized (and listed in `zero_basis_symbols`).

Split-adjusted first, like the desktop (trade_journal.split_adjusted): a sell
of a FRACTION of a share is a reverse-split remnant, and is restated into the
pre-split shares it came from (same proceeds, the whole position's quantity).
Without that, a 0.1-share remnant sold at $10 is charged a tenth of what was
paid for it -- the website reported ~$836 more realized profit than the app on
the real journal. `split_adjust` below is a port of that lens and the two must
stay in step.

Attribution note: because `profit` telescopes, we can attribute each individual
sell as (sell_price - avg_buy) * qty and the per-broker, per-month, and
cumulative series all sum back to exactly the same grand total. That identity is
covered by tests in web/tests/test_analytics.py.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Iterable, Sequence


@dataclass
class TradeLike:
    """Structural shape shared by an ORM Trade row and a raw trades.json dict."""
    timestamp: datetime
    broker: str
    account_id: str
    side: str
    symbol: str
    qty: float
    fill_price: float | None


def to_tradelike(rows: Iterable[Any]) -> list[TradeLike]:
    out: list[TradeLike] = []
    for r in rows:
        get = r.get if isinstance(r, dict) else lambda k, d=None: getattr(r, k, d)
        ts = get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        out.append(
            TradeLike(
                timestamp=ts,
                broker=str(get("broker", "") or "").lower(),
                account_id=str(get("account_id", "") or ""),
                side=str(get("side", "") or "").lower(),
                symbol=str(get("symbol", "") or "").upper(),
                qty=float(get("qty", 0) or 0),
                fill_price=get("fill_price"),
            )
        )
    return out


_ACCT_NUM_RE = re.compile(r"\(([^)]*\d[^)]*)\)\s*$")
# The salted token cloud_sync.mask_account_id puts where the number was.
_MASK_TOKEN_RE = re.compile(r"#([a-z]{6})\s*$")
_LOGIN_RE = re.compile(r"^\s*[A-Za-z][A-Za-z .&'-]*?\s+(\d{1,2})(?=\D|$)")


def account_key(label: str) -> str:
    """Port of trade_journal.account_key: the trailing "(number)" when there
    is one (the label drifts, the number does not), else the label itself.

    A MASKED label ("Fidelity 1 · FinTec #kqzvbm") keys on its token: since
    mask version 2 the desktop hashes the account itself, so the token is the
    number's stand-in and survives the label drifting around it. Login 2+
    prefixes the key exactly as the desktop does ('Public 2 ...').
    """
    text = str(label or "").split(" = ")[0].strip()
    t = _MASK_TOKEN_RE.search(text)
    if t:
        return "#" + t.group(1)
    m = _ACCT_NUM_RE.search(text)
    if m:
        key = "".join(c for c in m.group(1) if c.isalnum()).upper()
        if key:
            lm = _LOGIN_RE.match(text[:m.start()])
            idx = int(lm.group(1)) if lm else 1
            return f"L{idx}:{key}" if idx > 1 else key
    return text.casefold()


def split_adjust(trades: Sequence[TradeLike]) -> list[TradeLike]:
    """Port of trade_journal.split_adjusted, for P/L. Idempotent.

    Walks rows in the order given (the dashboard loads them by timestamp). A
    sell of a fraction of a share, smaller than the account's holding, is
    restated as selling the whole holding for the same proceeds. Whole-share
    sells and closes are left alone; an unpriced remnant stays unpriced.
    """
    held: dict[tuple, float] = {}
    out: list[TradeLike] = []
    for t in trades:
        key = (t.broker, account_key(t.account_id), t.symbol)
        qty = float(t.qty or 0)
        if t.side == "buy":
            held[key] = held.get(key, 0.0) + qty
        elif t.side == "close":
            held[key] = max(0.0, held.get(key, 0.0) - qty)
        elif t.side == "sell":
            have = held.get(key, 0.0)
            if abs(qty - round(qty)) > 1e-9 and 0 < qty < have:
                price = t.fill_price
                t = replace(t, qty=have,
                            fill_price=(price * qty / have) if price is not None else None)
                qty = have
            held[key] = max(0.0, have - qty)
        out.append(t)
    return out


@dataclass
class Summary:
    realized: float = 0.0
    wins: int = 0
    losses: int = 0
    closed: int = 0
    open_positions: list[dict] = field(default_factory=list)
    open_count: int = 0
    deployed: float = 0.0
    trade_count: int = 0
    broker_count: int = 0
    account_count: int = 0
    # Data quality: symbols that were SOLD but have no priced buy, so they have
    # no cost basis and are left out of realized. Surface it, never hide it.
    zero_basis_symbols: list[str] = field(default_factory=list)

    @property
    def win_rate(self) -> float:
        return (self.wins / self.closed * 100.0) if self.closed else 0.0

    @property
    def expectancy(self) -> float:
        return (self.realized / self.closed) if self.closed else 0.0


def summarize(trades: Sequence[TradeLike]) -> Summary:
    trades = split_adjust(trades)
    buys: dict[str, dict[str, float]] = {}
    sells: dict[str, dict[str, float]] = {}
    open_qty: dict[tuple, float] = {}
    missing_price: set[str] = set()

    for t in trades:
        sym = t.symbol
        qty = float(t.qty or 0)
        price = t.fill_price
        key = (t.broker, sym)
        if t.side == "buy":
            b = buys.setdefault(sym, {"qty": 0.0, "cost": 0.0})
            if price is None:
                missing_price.add(sym)
            else:
                b["qty"] += qty
                b["cost"] += price * qty
            open_qty[key] = open_qty.get(key, 0.0) + qty
        elif t.side == "close":
            # A position a corporate action dissolved. It closes the holding and
            # stays out of realized entirely -- see trade_journal.SIDE_CLOSE.
            open_qty[key] = open_qty.get(key, 0.0) - qty
        elif t.side == "sell":
            s = sells.setdefault(sym, {"qty": 0.0, "rev": 0.0})
            if price is not None:
                s["qty"] += qty
                s["rev"] += price * qty
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

    sym_open: dict[str, float] = {}
    for (_b, sym), q in open_qty.items():
        if q > 1e-9:
            sym_open[sym] = sym_open.get(sym, 0.0) + q

    deployed = 0.0
    for sym, q in sym_open.items():
        b = buys.get(sym)
        if b and b["qty"]:
            deployed += (b["cost"] / b["qty"]) * q

    open_positions = sorted(
        ({"symbol": s, "qty": q} for s, q in sym_open.items()),
        key=lambda d: -d["qty"],
    )

    # Sold, but no priced buy: no basis, so left out of realized above.
    sold = set(sells)
    zero_basis = sorted(
        s for s in missing_price
        if s in sold and not buys.get(s, {}).get("qty", 0)
    )

    return Summary(
        realized=realized,
        wins=wins,
        losses=losses,
        closed=wins + losses,
        open_positions=open_positions,
        open_count=len(open_positions),
        deployed=deployed,
        trade_count=len(trades),
        broker_count=len({t.broker for t in trades}),
        account_count=len({(t.broker, account_key(t.account_id)) for t in trades}),
        zero_basis_symbols=zero_basis,
    )


def _avg_buy_by_symbol(trades: Sequence[TradeLike]) -> dict[str, float]:
    """Average PRICED buy per symbol; a symbol with no priced buy is absent."""
    buys: dict[str, dict[str, float]] = {}
    for t in trades:
        if t.side != "buy" or t.fill_price is None:
            continue
        b = buys.setdefault(t.symbol, {"qty": 0.0, "cost": 0.0})
        b["qty"] += float(t.qty or 0)
        b["cost"] += t.fill_price * float(t.qty or 0)
    return {s: (v["cost"] / v["qty"]) for s, v in buys.items() if v["qty"]}


def _sell_profits(trades: Sequence[TradeLike]) -> list[tuple[TradeLike, float]]:
    """Attribute realized profit to each individual sell. Sums to `realized`."""
    trades = split_adjust(trades)
    avg_buy = _avg_buy_by_symbol(trades)
    out = []
    for t in trades:
        if t.side != "sell" or t.fill_price is None or t.symbol not in avg_buy:
            continue
        profit = (t.fill_price - avg_buy[t.symbol]) * float(t.qty or 0)
        out.append((t, profit))
    out.sort(key=lambda p: p[0].timestamp)
    return out


def equity_curve(trades: Sequence[TradeLike]) -> list[tuple[datetime, float]]:
    """Cumulative realized P/L over time. Final value == summarize().realized."""
    running = 0.0
    curve = []
    for t, profit in _sell_profits(trades):
        running += profit
        curve.append((t.timestamp, running))
    return curve


def realized_by_broker(trades: Sequence[TradeLike]) -> list[tuple[str, float]]:
    agg: dict[str, float] = defaultdict(float)
    for t, profit in _sell_profits(trades):
        agg[t.broker] += profit
    return sorted(agg.items(), key=lambda kv: -kv[1])


def realized_by_month(trades: Sequence[TradeLike]) -> list[tuple[str, float]]:
    agg: dict[str, float] = defaultdict(float)
    for t, profit in _sell_profits(trades):
        agg[t.timestamp.strftime("%Y-%m")] += profit
    return sorted(agg.items())


def realized_by_symbol(trades: Sequence[TradeLike], limit: int = 10) -> list[tuple[str, float]]:
    agg: dict[str, float] = defaultdict(float)
    for t, profit in _sell_profits(trades):
        agg[t.symbol] += profit
    ranked = sorted(agg.items(), key=lambda kv: -abs(kv[1]))
    return ranked[:limit]


def max_drawdown(trades: Sequence[TradeLike]) -> float:
    """Largest peak-to-trough fall of the cumulative realized equity curve."""
    peak = 0.0
    worst = 0.0
    for _ts, equity in equity_curve(trades):
        peak = max(peak, equity)
        worst = min(worst, equity - peak)
    return worst


def allocation(summary: Summary) -> list[tuple[str, float, float]]:
    """(symbol, qty, pct_of_open_shares) for the donut, matching the app's
    Positions tab: share-count weighted, not dollar weighted."""
    total = sum(p["qty"] for p in summary.open_positions)
    if not total:
        return []
    return [(p["symbol"], p["qty"], p["qty"] / total * 100.0) for p in summary.open_positions]
