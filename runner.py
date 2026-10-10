#!/usr/bin/env python3
"""CLI entry point for broker automation.

Usage:
    python runner.py bootstrap <broker>
    python runner.py holdings <broker>
    python runner.py trade <broker> <side> <symbol> <qty> [--dry-run]
    python runner.py dashboard [--port 8000]
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from modules.outputs import BrokerOutput, log_event
import trade_journal

# Credentials live in .env and the broker modules read them straight off the
# environment. The GUI loads that file before every operation; this CLI never
# did, so every command here failed with "Missing <BROKER>_USERNAME" even though
# the credentials were sitting right there. Load it once at import, from the
# file next to this script rather than the current working directory, so the
# commands work from anywhere.
ENV_FILE = Path(__file__).resolve().parent / ".env"
load_dotenv(ENV_FILE, override=True, interpolate=False)


BROKER_MODULES = {
    "chase": "chase",
    "fennel": "fennel",
    "fidelity": "fidelity",
    "ibkr": "ibkr",
    "public": "public",
    "robinhood": "robinhood",
    "schwab": "schwab",
    "sofi": "sofi",
    "wellsfargo": "wellsfargo",
}


def _load_broker(name: str) -> Any:
    name = name.lower().strip()
    if name not in BROKER_MODULES:
        print(f"Unknown broker: {name!r}")
        print(f"Available: {', '.join(sorted(BROKER_MODULES))}")
        sys.exit(1)
    return importlib.import_module(BROKER_MODULES[name])


def _print_output(output: BrokerOutput) -> None:
    state_color = {
        "success": "\033[92m",  # green
        "failed": "\033[91m",   # red
        "partial": "\033[93m",  # yellow
    }
    reset = "\033[0m"
    color = state_color.get(output.state, "")

    print(f"\n{'='*60}")
    print(f"  Broker:  {output.broker}")
    print(f"  State:   {color}{output.state}{reset}")
    if output.message:
        print(f"  Message: {output.message}")
    print(f"{'='*60}")

    for acct in output.accounts:
        status = f"{'\033[92m'}OK{reset}" if acct.ok else f"{'\033[91m'}FAIL{reset}"
        print(f"\n  Account: {acct.account_id}  [{status}]")
        if acct.message:
            print(f"    {acct.message}")
        if acct.holdings:
            print(f"    Holdings ({len(acct.holdings)}):")
            for h in acct.holdings:
                parts = [f"      {h.symbol}"]
                if h.shares is not None:
                    parts.append(f"shares={h.shares}")
                if h.price is not None:
                    parts.append(f"price=${h.price:.2f}")
                print("  ".join(parts))
    print()


def cmd_bootstrap(args: argparse.Namespace) -> None:
    mod = _load_broker(args.broker)
    print(f"Bootstrapping {args.broker}...")
    output = mod.bootstrap()
    log_event(broker=args.broker, action="bootstrap", output=output)
    _print_output(output)


def cmd_holdings(args: argparse.Namespace) -> None:
    mod = _load_broker(args.broker)
    print(f"Fetching holdings for {args.broker}...")
    output = mod.get_holdings()
    log_event(broker=args.broker, action="holdings", output=output)
    _print_output(output)


#: Same guard as the GUI's Trade Desk: a reverse-split round-up is one share
#: per account, so anything over this is far more likely a typo than a plan.
LARGE_QTY = 5


def _holdings_price(mod: Any, symbol: str) -> float | None:
    """The market price get_holdings() reports for `symbol`. A QUOTE, not a
    fill -- recorded as such (trade_journal.PRICE_QUOTE)."""
    try:
        h_output = mod.get_holdings()
        for a in h_output.accounts:
            for h in a.holdings:
                if h.symbol and h.symbol.upper() == symbol and h.price is not None:
                    return h.price
    except Exception:
        pass
    return None


def journal_fills(broker: str, side: str, symbol: str, qty: float,
                  output: BrokerOutput,
                  price: float | None = None) -> tuple[list[str], list[str]]:
    """Journal every account the broker filled. Returns (row ids, failures).

    Matches the GUI's trade worker: every ok account is journaled whatever the
    batch state says (a "failed" batch can still have filled accounts), one
    bad write costs that one row and not the rest, the broker's order_id is
    kept, and the price is marked as a quote. Rows go in unpriced -- the price
    lookup is a slow broker round trip and comes after, so a crash during it
    can cost a price but never a fill. A SELL passes the quote it read before
    the order (`price`) and its rows go in with it, as the GUI's do.
    """
    ids: list[str] = []
    failed: list[str] = []
    for acct in output.accounts:
        if not acct.ok:
            continue
        extra = getattr(acct, "extra", None) or {}
        acct_qty = qty
        try:
            acct_qty = float(extra.get("qty") or qty)
        except (TypeError, ValueError):
            pass
        try:
            row = trade_journal.record_trade(
                broker=broker,
                account_id=acct.account_id,
                side=side,
                symbol=str(extra.get("symbol") or symbol).upper(),
                qty=acct_qty,
                fill_price=price,
                order_id=getattr(acct, "order_id", None),
                price_source=trade_journal.PRICE_QUOTE,
            )
            ids.append(row["id"])
        except Exception as exc:                  # noqa: BLE001
            failed.append(f"{acct.account_id} (order "
                          f"{getattr(acct, 'order_id', None) or '?'}): {exc}")
    return ids, failed


def cmd_trade(args: argparse.Namespace) -> None:
    symbol = args.symbol.upper()
    if args.qty <= 0:
        print(f"Quantity must be at least 1 share (got {args.qty}). Nothing was sent.")
        sys.exit(2)
    if args.qty > LARGE_QTY and not args.dry_run and not args.yes:
        print(f"{args.qty} shares per account is unusually large for a "
              f"reverse-split round-up play (standard is 1). Nothing was sent; "
              f"re-run with --yes to execute anyway.")
        sys.exit(2)
    mod = _load_broker(args.broker)
    # A sell is priced BEFORE it goes out, like the GUI's trade worker: once
    # the shares are sold the position is gone from get_holdings() and the
    # lookup afterwards found nothing, so every CLI sell was journaled
    # unpriced -- and an unpriced sell never reaches realized P/L.
    pre_price = None
    if args.side == "sell" and not args.dry_run:
        pre_price = _holdings_price(mod, symbol)
    print(f"Executing trade: {args.side} {args.qty} {symbol} on {args.broker}" +
          (" [DRY RUN]" if args.dry_run else ""))
    output = mod.execute_trade(
        side=args.side,
        qty=str(args.qty),
        symbol=symbol,
        dry_run=args.dry_run,
    )
    log_event(broker=args.broker, action="trade", output=output)

    failed: list[str] = []
    if not args.dry_run:
        ids, failed = journal_fills(args.broker.lower(), args.side, symbol,
                                    float(args.qty), output, price=pre_price)
        if ids and pre_price is None:
            price = _holdings_price(mod, symbol)
            if price is not None:
                try:
                    trade_journal.set_fill_prices(ids, price,
                                                  trade_journal.PRICE_QUOTE)
                except Exception as exc:          # noqa: BLE001
                    print(f"!! quoted price ${price:.4f} not saved; "
                          f"{len(ids)} journaled fill(s) stay unpriced: {exc}")

    _print_output(output)
    if failed:
        print(f"!! {len(failed)} filled order(s) NOT saved to the journal - "
              f"add them by hand:")
        for f in failed:
            print(f"     {f}")
        sys.exit(1)


def cmd_dashboard(args: argparse.Namespace) -> None:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Run: py -3.13 -m pip install uvicorn")
        sys.exit(1)
    print(f"Starting dashboard on http://127.0.0.1:{args.port}")
    uvicorn.run("dashboard:app", host="127.0.0.1", port=args.port, reload=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Broker automation CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_boot = sub.add_parser("bootstrap", help="Authenticate with a broker")
    p_boot.add_argument("broker", help="Broker name")
    p_boot.set_defaults(func=cmd_bootstrap)

    p_hold = sub.add_parser("holdings", help="Fetch holdings from a broker")
    p_hold.add_argument("broker", help="Broker name")
    p_hold.set_defaults(func=cmd_holdings)

    p_trade = sub.add_parser("trade", help="Execute a trade")
    p_trade.add_argument("broker", help="Broker name")
    p_trade.add_argument("side", choices=["buy", "sell"], help="Buy or sell")
    p_trade.add_argument("symbol", help="Ticker symbol")
    p_trade.add_argument("qty", type=int, help="Quantity (whole shares)")
    p_trade.add_argument("--dry-run", action="store_true", help="Simulate without placing order")
    p_trade.add_argument("--yes", action="store_true",
                         help=f"confirm a quantity over {LARGE_QTY} shares per account")
    p_trade.set_defaults(func=cmd_trade)

    p_dash = sub.add_parser("dashboard", help="Launch web dashboard")
    p_dash.add_argument("--port", type=int, default=8000, help="Port (default 8000)")
    p_dash.set_defaults(func=cmd_dashboard)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
