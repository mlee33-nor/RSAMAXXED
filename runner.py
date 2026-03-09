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
from typing import Any

from modules.outputs import BrokerOutput, log_event
import trade_journal


BROKER_MODULES = {
    "bbae": "bbae",
    "chase": "chase",
    "dspac": "dspac",
    "fennel": "fennel",
    "fidelity": "fidelity",
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


def cmd_trade(args: argparse.Namespace) -> None:
    mod = _load_broker(args.broker)
    print(f"Executing trade: {args.side} {args.qty} {args.symbol} on {args.broker}" +
          (" [DRY RUN]" if args.dry_run else ""))
    output = mod.execute_trade(
        side=args.side,
        qty=str(args.qty),
        symbol=args.symbol.upper(),
        dry_run=args.dry_run,
    )
    log_event(broker=args.broker, action="trade", output=output)

    # Record successful trades to persistent journal (skip dry runs)
    if output.state in ("success", "partial") and not args.dry_run:
        # try to get fill price from holdings
        fill_price = None
        if any(a.ok for a in output.accounts):
            try:
                h_output = mod.get_holdings()
                for a in h_output.accounts:
                    for h in a.holdings:
                        if h.symbol and h.symbol.upper() == args.symbol.upper() and h.price is not None:
                            fill_price = h.price
                            break
                    if fill_price is not None:
                        break
            except Exception:
                pass

        for acct in output.accounts:
            if acct.ok:
                trade_journal.record_trade(
                    broker=args.broker,
                    account_id=acct.account_id,
                    side=args.side,
                    symbol=args.symbol.upper(),
                    qty=float(args.qty),
                    fill_price=fill_price,
                )

    _print_output(output)


def cmd_dashboard(args: argparse.Namespace) -> None:
    try:
        import uvicorn
    except ImportError:
        print("uvicorn not installed. Run: pip install uvicorn")
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
    p_trade.set_defaults(func=cmd_trade)

    p_dash = sub.add_parser("dashboard", help="Launch web dashboard")
    p_dash.add_argument("--port", type=int, default=8000, help="Port (default 8000)")
    p_dash.set_defaults(func=cmd_dashboard)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
