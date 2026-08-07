#!/usr/bin/env python3
"""Ask each broker what it actually holds, and close what it doesn't.

WHY

The journal only learns about trades this tool executes. A reverse split that
settles to CASH IN LIEU dissolves the position with no trade to record, and
seven of the ten brokers do exactly that — they do not hold fractions at all.
So every such split since day one has quietly left its cost basis on the books.

The visible symptom is a DEPLOYED figure of $428.48 across 90 symbols, of which
$198.39 sits at Wells Fargo, Fidelity and Chase in plays the board says came
back fractional or cash-in-lieu. Those shares stopped existing weeks ago. The
same gap is why AEMD keeps appearing on the sell worklist while Public reports
no AEMD in any of nineteen accounts.

OBSERVATION, NOT INFERENCE

The rule "a non-fractional broker cannot hold a fractional play, so close it"
is almost always right and is still a guess. This asks instead. A position is
closed only when the broker was read successfully AND does not report it —
which is a fact, and which also catches the cases a rule would miss (a manual
sale, a broker liquidating a stub, a transfer).

THE ONE THING IT MUST NEVER DO

Close a position because a broker could not be read. A dead session, a timeout,
a Turnstile check — none of those say anything about whether the shares are
there, and treating silence as absence would erase real holdings. A broker that
errors is skipped entirely and reported, every time.

USAGE

    python reconcile.py                       # every broker, report only
    python reconcile.py --broker public       # just one
    python reconcile.py --apply               # write the closes
"""
from __future__ import annotations

import argparse
import collections
import re
import sys
from typing import Any

from dotenv import load_dotenv

load_dotenv(".env")

import trade_journal  # noqa: E402

BROKERS = ("bbae", "chase", "dspac", "fennel", "fidelity",
           "public", "robinhood", "schwab", "sofi", "wellsfargo")


def _open_positions() -> dict[tuple[str, str, str], float]:
    """(broker, account, symbol) -> shares the journal believes are held."""
    net: dict[tuple[str, str, str], float] = collections.defaultdict(float)
    for t in trade_journal.split_adjusted():
        key = (t["broker"], t["account_id"], t["symbol"])
        q = float(t.get("qty") or 0)
        if t["side"] == "buy":
            net[key] += q
        else:                       # sell or close: both remove the position
            net[key] -= q
    return {k: v for k, v in net.items() if v > 1e-9}


def _acct_keys(label: str) -> set[str]:
    """Every form of an account label worth matching on.

    Brokers do not agree with themselves about this. Public's get_holdings()
    returns 'Public 1 ROTH_IRA (7989) = $61.32' — the label WITH the account's
    current value glued on — while the journal stored 'Public 1 ROTH_IRA
    (7989)' when the trade was placed. Matched literally, not one of nineteen
    Public accounts lines up, every real position looks gone, and a reconcile
    would close all 308 of them.

    So: the whole label, the label before any ' = ', and the digits in the last
    parenthesis. Any one matching is enough, and the last is the stable one —
    an account number does not change when its balance does.
    """
    out = {label.strip().casefold()}
    head = label.split(" = ")[0].strip()
    out.add(head.casefold())
    m = re.findall(r"\(([^)]*\d[^)]*)\)", head)
    if m:
        out.add(m[-1].strip().casefold())
    return {k for k in out if k}


def _live_holdings(broker: str) -> tuple[dict[str, dict[str, float]], str]:
    """{account_id: {SYMBOL: shares}} as the broker reports it, plus an error.

    An empty dict with no error means "read fine, holds nothing" — which is a
    real answer. An error means we learned nothing at all, and the caller must
    treat that completely differently.
    """
    try:
        mod = __import__(broker)
        out = mod.get_holdings()
    except Exception as exc:                      # noqa: BLE001
        return {}, f"{type(exc).__name__}: {exc}"

    if getattr(out, "state", "") == "failed":
        return {}, (getattr(out, "message", "") or "read failed")[:120]

    live: dict[str, dict[str, float]] = {}
    for acct in out.accounts:
        book: dict[str, float] = {}
        for h in acct.holdings:
            sym = (h.symbol or "").upper()
            if sym:
                book[sym] = book.get(sym, 0.0) + float(getattr(h, "shares", 0) or 0)
        # Filed under every alias, so the journal's older spelling of the same
        # account still finds it.
        for key in _acct_keys(acct.account_id):
            live[key] = book
    return live, ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--broker", action="append",
                    help="limit to one broker (repeatable)")
    ap.add_argument("--apply", action="store_true",
                    help="record the closes. Without this, nothing changes.")
    args = ap.parse_args(argv)

    want = [b.lower() for b in (args.broker or BROKERS)]
    unknown = [b for b in want if b not in BROKERS]
    if unknown:
        sys.exit(f"unknown broker(s): {', '.join(unknown)}")

    open_pos = _open_positions()
    by_broker: dict[str, list] = collections.defaultdict(list)
    for (broker, acct, sym), qty in open_pos.items():
        by_broker[broker].append((acct, sym, qty))

    to_close: list[tuple[str, str, str, float]] = []
    skipped: dict[str, str] = {}

    for broker in want:
        mine = by_broker.get(broker, [])
        if not mine:
            continue
        live, err = _live_holdings(broker)
        if err:
            # NEVER close on a failed read. Silence is not absence.
            skipped[broker] = err
            print(f"{broker:12} SKIPPED — could not read ({err})")
            continue

        def _book(acct: str) -> dict[str, float] | None:
            for key in _acct_keys(acct):
                if key in live:
                    return live[key]
            return None

        # If NOT ONE of this broker's journal accounts matches a live account,
        # the labels have drifted -- that is a matching bug, not an empty
        # brokerage. Public renders 'Public 1 ROTH_IRA (7989) = $61.32' and the
        # journal holds 'Public 1 ROTH_IRA (7989)'; matched literally, all 308
        # positions read as gone and a reconcile would close every one. Refuse.
        matched = sum(1 for acct, _s, _q in mine if _book(acct) is not None)
        if live and not matched:
            why = ("none of the journal's account labels match any the broker "
                   "reported -- refusing to close anything")
            skipped[broker] = why
            print(f"{broker:12} SKIPPED -- {why}")
            print(f"{'':12}   journal: {mine[0][0]!r}")
            print(f"{'':12}   broker : {next(iter(live))!r}")
            continue

        gone = []
        for acct, sym, qty in mine:
            book = _book(acct)
            if book is None:
                continue          # account we cannot place: leave it alone
            if not book.get(sym):
                gone.append((acct, sym, qty))
        print(f"{broker:12} journal says {len(mine):3} open, "
              f"broker confirms {len(mine) - len(gone):3}, "
              f"{len(gone):3} not there")
        to_close.extend((broker, a, s, q) for a, s, q in gone)

    if not to_close:
        print("\nnothing to close." if not skipped else
              "\nnothing to close among the brokers that could be read.")
        return 0

    # What the closes are worth, using the same average-cost basis the
    # deployed figure uses, so the two numbers can be compared directly.
    buys: dict[str, dict[str, float]] = {}
    for t in trade_journal.get_trades():
        if t["side"] == "buy":
            b = buys.setdefault(t["symbol"], {"qty": 0.0, "cost": 0.0})
            b["qty"] += float(t.get("qty") or 0)
            b["cost"] += (t.get("fill_price") or 0) * float(t.get("qty") or 0)

    freed = 0.0
    per_symbol: dict[str, float] = collections.defaultdict(float)
    for broker, acct, sym, qty in to_close:
        b = buys.get(sym)
        if b and b["qty"]:
            v = (b["cost"] / b["qty"]) * qty
            freed += v
            per_symbol[sym] += v

    print(f"\n{len(to_close)} position(s) the broker does not have — "
          f"${freed:,.2f} of cost basis currently counted as deployed")
    for sym, v in sorted(per_symbol.items(), key=lambda kv: -kv[1])[:12]:
        print(f"    {sym:8} ${v:8,.2f}")
    if len(per_symbol) > 12:
        print(f"    …and {len(per_symbol) - 12} more symbols")

    if skipped:
        print(f"\n{len(skipped)} broker(s) skipped and NOT reconciled — a read "
              f"that fails says nothing about whether the shares are there:")
        for b, why in skipped.items():
            print(f"    {b}: {why}")

    if not args.apply:
        print("\nDRY RUN — nothing written. Re-run with --apply.")
        return 0

    for broker, acct, sym, qty in to_close:
        trade_journal.record_close(
            broker=broker, account_id=acct, symbol=sym, qty=qty,
            reason=trade_journal.CLOSE_RECONCILED,
            note="broker reported no position",
        )
    print(f"\nrecorded {len(to_close)} close(s). These carry NO price, so none "
          f"of it becomes profit or loss — see Analytics for the unaccounted total.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
