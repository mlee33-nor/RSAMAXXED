#!/usr/bin/env python3
"""Pull the RSA alert channels and publish them to the cloud feed. Headless.

This is the daily job that feeds every subscriber. It does the same thing the
desktop app's Discord auto-import does, minus the GUI — so plays keep arriving
when the operator's machine is asleep, which was the single biggest reason a
customer would open the terminal to an empty Quick Picks list.

    python publish_feed.py                # pull both channels, publish
    python publish_feed.py --dry-run      # parse and report, publish nothing
    python publish_feed.py --limit 100    # look further back than the default 50
    python publish_feed.py --limit 600    # repair history after a parser fix

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
import json
import os
import re
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


# A line carrying a money figure, which is what a sell total looks like.
_HAS_MONEY = re.compile(r"\$\s*[\d,]+")


def _flat(text: str) -> str:
    """One line, so a preview cannot break the log it is printed into."""
    return " | ".join(l.strip() for l in (text or "").splitlines() if l.strip())


def _warn_unparsed(sell_msgs: list, buy_msgs: list) -> None:
    """Say out loud when a message with money in it produced nothing.

    Every format this parser handles was added AFTER it had silently dropped
    something: a total written without a "+", a bare ticker with no price, a
    broker with no account count, two tickers sharing one total, an alert typed
    out instead of sent as an embed. Each one cost real money off the board, and
    each stayed invisible until somebody happened to compare a month against
    Discord by hand.

    The formats will drift again. This cannot parse the next one, but it can
    refuse to be quiet about it — which turns "June looks low" into a line in
    the publisher's own output on the first run that sees it.
    """
    missed = []
    for m in sell_msgs:
        got, _ = rsa_feed.parse_sell_message(m)
        content = m.get("content") or ""

        if not got:
            if _HAS_MONEY.search(content):
                missed.append(("SELL", (m.get("timestamp") or "")[:10],
                               _flat(content)[:88]))
            continue

        # It parsed. That is not the same as parsing CORRECTLY, and the two
        # ways it can be wrong both cost money without producing an empty
        # result, so neither is caught by the check above.

        # 1. The arithmetic inside one exit. Every exit the channel has ever
        #    published has proceeds equal to exit_price x accounts, to the cent.
        #    When it does not, the figure belongs to something else — WXM was
        #    stored at $66.48 against 3 accounts at $4.24, because it had been
        #    handed CETX's share of a shared total as well.
        for e in got:
            legs = sum(l.accounts_low for l in e.legs)
            if not (legs and e.exit_price and e.proceeds_low):
                continue
            # Compared PER ACCOUNT, not on the total. The channel writes the
            # price rounded to the cent, so across 21 accounts an honest figure
            # is already 6c off the product — EDBL published $40.80 against
            # $1.94 x 21 = $40.74 and is perfectly correct. A cent per account
            # is the rounding; anything past it is a different number.
            if abs(e.proceeds_low / legs - e.exit_price) > 0.01:
                missed.append(("SUM", (m.get("timestamp") or "")[:10],
                               f"{e.symbol} ${e.proceeds_low:.2f} / {legs} accounts "
                               f"= ${e.proceeds_low / legs:.2f}, but the price "
                               f"published was ${e.exit_price:.2f}"))

        # 2. A ticker the message names that no exit came back for. The shared
        #    total dropped CETX entirely while WXM parsed fine, so the message
        #    looked handled and half of it was gone.
        named = {h.group(1).upper() for line in content.splitlines()
                 if (h := rsa_feed._SELL_HEAD.match(line.strip()))}
        parsed = {e.symbol.upper() for e in got}
        for lost in sorted(named - parsed):
            missed.append(("DROP", (m.get("timestamp") or "")[:10],
                           f"{lost} is named but produced no exit — "
                           f"{_flat(content)[:50]}"))
    for m in buy_msgs:
        if rsa_feed.parse_buy_message(m):
            continue
        blob = (m.get("content") or "") + json.dumps(m.get("embeds") or [])
        if "RSA Alert" in blob:
            missed.append(("BUY", (m.get("timestamp") or "")[:10],
                           _flat(m.get("content") or "")[:88]))

    if not missed:
        return
    print(f"WARNING: {len(missed)} problem(s) found — money may be wrong on "
          f"the board. SELL/BUY = parsed to nothing, SUM = the arithmetic "
          f"inside an exit disagrees, DROP = a named ticker produced no exit:")
    for kind, when, preview in missed[:10]:
        print(f"   {kind:4} {when}  {preview}")
    if len(missed) > 10:
        print(f"   ...and {len(missed) - 10} more")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=50,
                    help="messages to read per channel (default 50; over 100 pages back)")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and report, but publish nothing")
    args = ap.parse_args(argv)

    # Above 100 we page instead of clamping. Discord rejects a single request
    # over 100, but the whole point of a big --limit is repairing history: a
    # parser fix only reaches messages that get read again, so a cap of 100 left
    # everything older permanently wrong. See discord_feed.fetch_back.
    if args.limit > 100:
        print(f"reading back {args.limit} messages per channel (paged)")
    # Discord rejects a limit above 100 outright. Clamping (loudly) beats
    # handing back a 400 that reads like the channel is broken — and a run that
    # silently fetched nothing is exactly how a day's alerts go missing.
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

    buy_msgs, err = discord_feed.fetch_back(buy_cid, token, args.limit)
    if err:
        print(f"BUY channel: {err}", file=sys.stderr)
        return 2

    sell_msgs: list = []
    if sell_cid:
        sell_msgs, serr = discord_feed.fetch_back(sell_cid, token, args.limit)
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

    _warn_unparsed(sell_msgs, buy_msgs)

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
