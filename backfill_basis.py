#!/usr/bin/env python3
"""Supply a cost basis the journal never captured.

WHY THIS EXISTS

Profit is what you sold for minus what you paid. The second half goes missing
in two ways, and they break the total in opposite directions:

    no buy row at all       the symbol is skipped, so real proceeds vanish from
                            realized P/L.                       UNDERSTATES.
    a buy row with no price  cost divides out to zero, so the whole of the
                            proceeds books as profit.           OVERSTATES.

Neither is recoverable from anything the app stored — a trade placed outside
this tool leaves no trace here, and a fill the broker never priced cannot be
invented. Only the person who placed it knows, so this is how they say.

WHAT IT WILL NOT DO

It never touches a row that already has a price. A recorded fill is evidence and
this is testimony; overwriting the first with the second would quietly destroy
the only real data in the file.

Rows it writes are stamped `price_source: "manual"` and `backfilled: true`, so a
reconstructed basis is distinguishable from a recorded one forever. That matters
more than it looks: a manual figure that reads as a broker fill is exactly the
confusion that made `_fetch_fill_price` invisible for so long.

USAGE

    # See what is missing, and do nothing.
    python backfill_basis.py

    # A buy that WAS recorded but never priced (MASK: 15c a share).
    python backfill_basis.py --symbol MASK --price 0.15

    # A buy that was never recorded at all. Creates one row per SELL,
    # matching its broker, account and quantity (TOPT: 10 accounts).
    python backfill_basis.py --symbol TOPT --price 33.245 --create-buys

    # Nothing is written without --apply. trades.json is backed up first.
    python backfill_basis.py --symbol MASK --price 0.15 --apply
"""
from __future__ import annotations

import argparse
import collections
import json
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import trade_journal

FILE = trade_journal._FILE


def _load() -> list[dict]:
    if not FILE.exists():
        sys.exit(f"no journal at {FILE}")
    return json.loads(FILE.read_text(encoding="utf-8"))


def audit(trades: list[dict]) -> None:
    """Every symbol that has been sold but cannot be fully priced."""
    buys: dict = collections.defaultdict(lambda: {"n": 0, "unpriced": 0, "cost": 0.0, "qty": 0.0})
    sells: dict = collections.defaultdict(lambda: {"qty": 0.0, "rev": 0.0})
    for t in trades:
        s = t["symbol"]
        q = float(t.get("qty") or 0)
        p = t.get("fill_price")
        if t["side"] == "buy":
            b = buys[s]
            b["n"] += 1
            b["qty"] += q
            b["cost"] += (p or 0) * q
            if p is None:
                b["unpriced"] += 1
        else:
            sells[s]["qty"] += q
            sells[s]["rev"] += (p or 0) * q

    print(f"{'SYMBOL':8}{'SOLD':>10}  WHAT IS MISSING")
    print("-" * 78)
    found = False
    for sym in sorted(sells):
        b = buys.get(sym)
        rev = sells[sym]["rev"]
        if not b or not b["n"]:
            found = True
            print(f"{sym:8}{rev:10.2f}  no buy recorded at all — dropped from realized P/L")
            print(f"{'':18}  fix: --symbol {sym} --price <what you paid> --create-buys")
        elif b["cost"] <= 0:
            found = True
            per = rev / sells[sym]["qty"] if sells[sym]["qty"] else 0
            print(f"{sym:8}{rev:10.2f}  {b['n']} buys, none priced — counts as 100% profit")
            print(f"{'':18}  fix: --symbol {sym} --price <what you paid>   (sold ~{per:,.4f})")
        elif b["unpriced"]:
            found = True
            print(f"{sym:8}{rev:10.2f}  {b['unpriced']} of {b['n']} buys unpriced — "
                  f"average cost too low, profit too high")
            print(f"{'':18}  fix: --symbol {sym} --price <what you paid>")
    if not found:
        print("nothing missing — every sold symbol has a real cost basis.")


def price_existing(trades: list[dict], symbol: str, price: float) -> list[dict]:
    """Fill in the price on buys that were recorded without one."""
    hits = [t for t in trades
            if t["symbol"] == symbol and t["side"] == "buy" and t.get("fill_price") is None]
    for t in hits:
        t["fill_price"] = price
        t["price_source"] = "manual"
        t["backfilled"] = True
    return hits


def create_buys(trades: list[dict], symbol: str, price: float) -> list[dict]:
    """Synthesize the buy that was never recorded, one row per sell.

    Shaped from the SELLS rather than guessed: same broker, same account, same
    quantity. That is what makes the reconstructed position close to zero
    instead of leaving a phantom holding behind, and it means the per-account
    arithmetic still works out.

    Dated a day before the earliest sell, so it sorts ahead of it — the split
    lens in trade_journal walks rows in file order and a buy that lands after
    its own sell would not be seen as opening the position.
    """
    sells = [t for t in trades if t["symbol"] == symbol and t["side"] == "sell"]
    if not sells:
        return []
    if any(t["symbol"] == symbol and t["side"] == "buy" for t in trades):
        sys.exit(f"{symbol} already has buy rows — use --price without --create-buys")

    earliest = min(t["timestamp"] for t in sells)
    when = (datetime.fromisoformat(earliest) - timedelta(days=1)).isoformat()

    made = []
    for s in sells:
        made.append({
            "id": str(uuid.uuid4()),
            "timestamp": when,
            "broker": s["broker"],
            "account_id": s["account_id"],
            "side": "buy",
            "symbol": symbol,
            # The quantity that was SOLD. For a post-split remnant this is the
            # fraction, and the split lens will restate the sell against it.
            "qty": float(s.get("qty") or 0),
            "fill_price": price,
            "order_id": None,
            "price_source": "manual",
            "backfilled": True,
        })
    return made


def record_sale(trades: list[dict], symbol: str, broker: str,
                price: float) -> list[dict]:
    """Record a sale you placed yourself, in the broker's own app.

    The journal only learns about trades this tool executes. Sell four SoFi
    accounts by hand and nothing here knows: the position stays "held", the
    sell worklist keeps offering it, auto-sell keeps queuing it, and each
    attempt drives another broker login against a position that is already
    gone. AEMD and GRNQ are both sitting in exactly that state.

    One row per account that still shows a net position at that broker, for
    the quantity still showing. Marked manual, like everything else here — it
    is your word, not a broker fill.
    """
    net: dict[str, float] = {}
    for t in trade_journal.split_adjusted(trades):
        if t["symbol"] != symbol or t["broker"] != broker:
            continue
        q = float(t.get("qty") or 0)
        acct = t["account_id"]
        net[acct] = net.get(acct, 0.0) + (q if t["side"] == "buy" else -q)

    open_accounts = {a: q for a, q in net.items() if q > 1e-9}
    if not open_accounts:
        sys.exit(f"no open {symbol} position at {broker} — nothing to close")

    when = datetime.now(timezone.utc).isoformat()
    return [{
        "id": str(uuid.uuid4()),
        "timestamp": when,
        "broker": broker,
        "account_id": acct,
        "side": "sell",
        "symbol": symbol,
        "qty": qty,
        "fill_price": price,
        "order_id": None,
        "price_source": "manual",
        "backfilled": True,
    } for acct, qty in sorted(open_accounts.items())]


def _write(trades: list[dict]) -> None:
    """Back up, then write. Never overwrites a previous backup.

    Two runs a second apart — fixing MASK and then TOPT, which is the normal way
    to use this — collided on a to-the-second stamp, and the second copy
    captured the file AFTER the first had already changed it. The true original
    was gone, which is the one thing a backup exists to prevent.
    """
    stamp = f"{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    backup = FILE.with_suffix(f".{stamp}.bak.json")
    n = 1
    while backup.exists():
        backup = FILE.with_suffix(f".{stamp}-{n}.bak.json")
        n += 1
    shutil.copy2(FILE, backup)
    # Sorted by time: the split lens in trade_journal walks rows in file order,
    # and a created buy appended after its own sell would never be seen opening
    # the position it pays for.
    trades.sort(key=lambda t: str(t.get("timestamp") or ""))
    FILE.write_text(json.dumps(trades, indent=2), encoding="utf-8")
    print(f"\nwritten. backup: {backup.name}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--symbol", help="ticker to fix")
    ap.add_argument("--price", type=float, help="what one share cost you")
    ap.add_argument("--create-buys", action="store_true",
                    help="no buy was ever recorded; build one per sell")
    ap.add_argument("--sell", action="store_true",
                    help="record a sale you placed yourself, in the broker's app")
    ap.add_argument("--broker", help="broker key for --sell, e.g. sofi, robinhood")
    ap.add_argument("--apply", action="store_true",
                    help="write it. Without this, nothing changes.")
    args = ap.parse_args(argv)

    trades = _load()

    if not args.symbol:
        audit(trades)
        return 0
    if args.price is None:
        sys.exit("--price is required with --symbol")
    if args.price <= 0:
        sys.exit("--price must be positive; a zero basis is the bug being fixed")

    symbol = args.symbol.upper()
    sold = sum(float(t.get("qty") or 0) * (t.get("fill_price") or 0)
               for t in trades if t["symbol"] == symbol and t["side"] == "sell")

    if args.sell:
        if not args.broker:
            sys.exit("--sell needs --broker (e.g. --broker sofi)")
        made = record_sale(trades, symbol, args.broker.lower().strip(), args.price)
        trades.extend(made)
        qty = sum(t["qty"] for t in made)
        cost = sum(
            float(t.get("qty") or 0) * (t.get("fill_price") or 0)
            for t in trades
            if t["symbol"] == symbol and t["side"] == "buy"
            and t["broker"] == args.broker.lower().strip()
        )
        print(f"{symbol}: recorded your own sale of {qty:g} share(s) across "
              f"{len(made)} {args.broker} account(s) at ${args.price:,.4f}")
        print(f"  proceeds     ${qty * args.price:>10,.2f}")
        print(f"  what you paid ${cost:>9,.2f}")
        print(f"  realized     ${qty * args.price - cost:>+10,.2f}")
        for t in made[:4]:
            print(f"    {t['account_id'][:34]:34} {t['qty']:g} @ ${args.price:,.4f}")
        if len(made) > 4:
            print(f"    …and {len(made) - 4} more")
        if not args.apply:
            print("\nDRY RUN — nothing written. Re-run with --apply.")
            return 0
        _write(trades)
        return 0

    if args.create_buys:
        made = create_buys(trades, symbol, args.price)
        if not made:
            sys.exit(f"no {symbol} sells to build a basis against")
        trades.extend(made)
        qty = sum(t["qty"] for t in made)
        changed = made
        what = f"created {len(made)} buy row(s), {qty:g} share(s)"
    else:
        changed = price_existing(trades, symbol, args.price)
        if not changed:
            sys.exit(f"no unpriced {symbol} buys to fill in "
                     f"(--create-buys if none were ever recorded)")
        qty = sum(float(t.get("qty") or 0) for t in changed)
        what = f"priced {len(changed)} existing buy row(s), {qty:g} share(s)"

    cost = qty * args.price
    print(f"{symbol}: {what} at ${args.price:,.4f}")
    print(f"  cost basis   ${cost:>10,.2f}")
    print(f"  proceeds     ${sold:>10,.2f}")
    print(f"  realized     ${sold - cost:>+10,.2f}"
          + (f"   ({(sold - cost) / cost * 100:+.1f}%)" if cost else ""))
    for t in changed[:3]:
        print(f"    {t['broker']:11} {t['account_id']:28} {t['qty']:g} @ ${args.price:,.4f}")
    if len(changed) > 3:
        print(f"    …and {len(changed) - 3} more")

    if not args.apply:
        print("\nDRY RUN — nothing written. Re-run with --apply.")
        return 0

    _write(trades)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
