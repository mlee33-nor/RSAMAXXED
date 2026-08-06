#!/usr/bin/env python3
"""Pull the RSA alert channels and publish them to the cloud feed. Headless.

This is the daily job that feeds every subscriber. It does the same thing the
desktop app's Discord auto-import does, minus the GUI — so plays keep arriving
when the operator's machine is asleep, which was the single biggest reason a
customer would open the terminal to an empty Quick Picks list.

    python publish_feed.py                # pull both channels, publish
    python publish_feed.py --dry-run      # parse and report, publish nothing
    python publish_feed.py --limit 100    # look further back than the default 50

Environment (a .env beside this file is loaded automatically):

    DISCORD_TOKEN               required   the user token that reads the channels
    DISCORD_CHANNEL             required   BUY channel: a name ('BUY') or numeric id
    DISCORD_SELL_CHANNEL        optional   SELL channel; omit and exits are skipped
    DISCORD_SERVER              optional   narrows a name lookup to one server
    RSAMAXXED_FEED_KEY          required   operator ingest key; without it nothing publishes
    RSAMAXXED_CLOUD_URL         optional   override the cloud base URL

Deliberately stateless: it re-reads the tail of each channel every run instead
of tracking a last-seen id. Ingest is insert-only and keyed on each row's
source_id, so re-publishing the same messages inserts nothing. That means the
job can run anywhere with no writable disk, can be run twice by accident, and
recovers from a missed day on its own — the properties that matter far more for
a scheduled job than saving a few hundred bytes of traffic.

Exit codes: 0 = published (or nothing new), 1 = misconfigured, 2 = a pull or
publish failed. Non-zero is what a scheduler should alert on.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:      # dotenv is optional — a scheduler usually injects real env vars
    pass

import discord_feed
import rsa_feed
from cloud_sync import CloudError, CloudSync


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _channel(role: str) -> str:
    """The configured channel for 'buy'/'sell'/'lifecycle', id preferred.

    Same precedence the GUI uses: the numeric *_CHANNEL_ID wins, because the
    GUI caches a resolved id there and the *_CHANNEL name it was resolved FROM
    is often unresolvable on its own — the real channels are named with styled
    unicode ('📫│𝙱𝚄𝚈'), so a plain 'BUY' matches nothing.
    """
    prefix = {"buy": "DISCORD_CHANNEL", "sell": "DISCORD_SELL_CHANNEL",
              "lifecycle": "DISCORD_LIFECYCLE_CHANNEL"}[role]
    return _env(f"{prefix}_ID") or _env(prefix)


def _resolve(token: str, raw: str, server: str, label: str) -> tuple[str, str]:
    """(channel_id, error). A numeric id passes straight through."""
    if not raw:
        return "", f"{label} channel not configured"
    cid, guild, err = discord_feed.resolve_channel(token, raw, server)
    if err or not cid:
        return "", f"{label} channel '{raw}': {err or 'not found'}"
    if guild:
        print(f"{label}: #{raw} -> {cid} (in {guild})")
    return cid, ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=50,
                    help="messages to read per channel (default 50, max 100)")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report, but publish nothing")
    args = ap.parse_args(argv)

    # Discord rejects a limit above 100 outright. Clamping (loudly) beats
    # handing back a 400 that reads like the channel is broken — and a run that
    # silently fetched nothing is exactly how a day's alerts go missing.
    if args.limit > 100:
        print(f"note: --limit {args.limit} exceeds Discord's cap; reading 100")
        args.limit = 100
    args.limit = max(1, args.limit)

    token = _env("DISCORD_TOKEN")
    if not token:
        print("DISCORD_TOKEN is not set", file=sys.stderr)
        return 1

    cloud = CloudSync()
    if not args.dry_run and not cloud.can_publish_feed:
        print("RSAMAXXED_FEED_KEY is not set — this machine cannot publish the "
              "feed. Set it, or pass --dry-run.", file=sys.stderr)
        return 1

    server = _env("DISCORD_SERVER")
    buy_cid, err = _resolve(token, _channel("buy"), server, "BUY")
    if err:
        print(err, file=sys.stderr)
        return 1

    # The SELL channel is optional: without it we still publish plays to open,
    # we just don't publish exits or round-up confirmations.
    sell_cid, sell_err = _resolve(token, _channel("sell"), server, "SELL")
    if sell_err:
        print(f"note: {sell_err} — exits will be skipped")

    buy_msgs, err = discord_feed.fetch(buy_cid, token, limit=args.limit)
    if err:
        print(f"BUY channel: {err}", file=sys.stderr)
        return 2

    sell_msgs: list = []
    if sell_cid:
        sell_msgs, serr = discord_feed.fetch(sell_cid, token, limit=args.limit)
        if serr:
            # A readable BUY channel is worth publishing on its own; don't lose
            # today's plays because the sell channel was rate limited.
            print(f"SELL channel: {serr} — continuing without exits", file=sys.stderr)
            sell_msgs = []

    batch = rsa_feed.parse_messages(buy_msgs, sell_msgs)

    # The TRACK board is what tells a subscriber whether their own position
    # resolved, and they cannot read it themselves — it needs a Discord token
    # with channel access. Publishing it is the only way they ever see it.
    lifecycle = []
    track_cid, track_err = _resolve(token, _channel("lifecycle"), server, "TRACK")
    if track_err:
        print(f"note: {track_err} — the board will not be published")
    else:
        track_msgs, terr = discord_feed.fetch(track_cid, token, limit=5)
        if terr:
            print(f"TRACK channel: {terr} — continuing without the board",
                  file=sys.stderr)
        else:
            lifecycle = rsa_feed.parse_lifecycle_messages(track_msgs)

    payload = batch.to_json()
    payload["lifecycle"] = [row.to_json() for row in lifecycle]

    print(f"read {len(buy_msgs)} buy / {len(sell_msgs)} sell message(s) -> "
          f"{len(batch.buys)} plays, {len(batch.sells)} exits, "
          f"{len(batch.roundups)} round-ups, {len(lifecycle)} board rows")

    if not (batch or lifecycle):
        print("nothing to publish")
        return 0

    if args.dry_run:
        for b in batch.buys:
            print(f"  BUY  {b.symbol:<8} {b.alert_date}  {b.kind}")
        for s in batch.sells:
            print(f"  SELL {s.symbol:<8} {s.sell_date}  {s.proceeds_text}")
        for r in batch.roundups:
            print(f"  ROUNDUP {r.symbol}")
        for row in lifecycle:
            if row.is_sellable:
                name = f"{row.symbol}->{row.sell_symbol}" if row.renamed else row.symbol
                print(f"  BOARD {name:<14} {row.alert_date}  {row.status}")
        print("dry run — nothing published")
        return 0

    try:
        sent = cloud.publish_feed(payload)
    except CloudError as exc:
        print(f"publish failed: {exc}", file=sys.stderr)
        return 2

    print(f"published — {sent.get('buys', 0)} new plays, {sent.get('sells', 0)} new "
          f"exits, {sent.get('roundups', 0)} new round-ups, "
          f"{sent.get('lifecycle', 0)} board changes "
          f"(anything already current on the feed was skipped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
