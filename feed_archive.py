#!/usr/bin/env python3
"""Keep a local archive of the published feed, and put it back after a wipe.

The cloud runs on container-local SQLite until Postgres is attached, which means
every deploy replaces the disk and the whole feed with it. `publish_feed.py`
recovers most of that on its next run — but only as far back as the last 100
Discord messages, because that is all the channel tail holds. Everything older
is gone for good.

This closes that hole for nothing: every run merges the live feed into a local
JSON archive that only ever grows, and `--restore` republishes the whole thing.

    python feed_archive.py                 # merge the live feed into the archive
    python feed_archive.py --restore       # republish the archive to the cloud
    python feed_archive.py --status        # what the archive holds

Run it beside publish_feed.py on the same schedule; it is idempotent and keyed
on the same source_ids, so extra runs cost one round trip and change nothing.

Environment (a .env beside this file is loaded automatically):

    RSAMAXXED_PLAYS_KEY   required to READ the feed
    RSAMAXXED_FEED_KEY    required only for --restore
    RSAMAXXED_CLOUD_URL   optional override

Exit codes: 0 = fine, 1 = misconfigured, 2 = a read or publish failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "feed_archive.json"

try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:      # a scheduler usually injects real env vars
    pass

from cloud_sync import CloudError, CloudSync

# The four streams, and the key each one is identified by. Play/exit/round-up
# rows are events and never change; lifecycle rows are statuses, so a newer copy
# of one REPLACES the archived copy rather than being skipped.
STREAMS = ("buys", "sells", "roundups", "lifecycle")


def _load() -> dict:
    if not ARCHIVE.exists():
        return {k: {} for k in STREAMS}
    try:
        raw = json.loads(ARCHIVE.read_text("utf-8"))
    except (OSError, ValueError):
        # A corrupt archive must not stop today's run from starting a new one,
        # but it must not be silently overwritten either.
        backup = ARCHIVE.with_suffix(".corrupt.json")
        try:
            ARCHIVE.replace(backup)
            print(f"archive was unreadable; kept it at {backup.name}", file=sys.stderr)
        except OSError:
            pass
        return {k: {} for k in STREAMS}
    return {k: dict(raw.get(k) or {}) for k in STREAMS}


def _save(store: dict) -> None:
    tmp = ARCHIVE.with_suffix(".tmp")
    tmp.write_text(json.dumps(store, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(ARCHIVE)          # atomic; a crash mid-write can't truncate it


def _key(row: dict, stream: str) -> str:
    """Identity, matching the server's. Exits and lifecycle rows carry their own
    source_id; plays and round-ups are keyed the way ingest keys them."""
    sid = str(row.get("source_id") or "").strip()
    if sid:
        return sid
    sym = str(row.get("symbol") or "").upper()
    when = str(row.get("alert_date") or row.get("confirmed_date") or "")[:10]
    return f"{stream}:{sym}:{when}"


def merge(cloud: CloudSync, store: dict) -> dict[str, int]:
    """Fold the live feed into the archive. Returns what was new per stream.

    Reads the operator export, not the ordinary feed: the feed is windowed for a
    terminal (open plays, 45 days of exits), and an archive built from it loses
    everything older than the window — which is the part worth archiving.
    """
    feed = cloud.fetch_export() or {}
    added = {k: 0 for k in STREAMS}
    incoming = {k: list(feed.get(k) or []) for k in STREAMS}

    for stream, rows in incoming.items():
        for row in rows:
            if not isinstance(row, dict):
                continue
            k = _key(row, stream)
            if not k:
                continue
            if stream == "lifecycle":
                # A status is meant to change; keep the newest we have seen.
                if store[stream].get(k) != row:
                    store[stream][k] = row
                    added[stream] += 1
            elif k not in store[stream]:
                store[stream][k] = row
                added[stream] += 1
    return added


def restore(cloud: CloudSync, store: dict) -> dict[str, int]:
    """Republish everything in the archive. Ingest is insert-only on source_id,
    so rows the cloud still has are skipped and only the missing ones land."""
    payload = {
        "buys": [r for r in store["buys"].values() if r.get("source_id")],
        "sells": [r for r in store["sells"].values() if r.get("source_id")],
        "roundups": [r for r in store["roundups"].values() if r.get("source_id")],
        "lifecycle": [r for r in store["lifecycle"].values()],
    }
    # Lifecycle rows come back from the API without their source_id (it is the
    # 'date:SYMBOL' key), so rebuild it rather than dropping the whole stream.
    for row in payload["lifecycle"]:
        row.setdefault("source_id", f"{row.get('alert_date','')}:{row.get('symbol','')}")
    return cloud.publish_feed(payload)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--restore", action="store_true",
                    help="republish the archive to the cloud")
    ap.add_argument("--status", action="store_true",
                    help="report what the archive holds and exit")
    args = ap.parse_args(argv)

    store = _load()
    if args.status:
        for k in STREAMS:
            print(f"{k:>10}: {len(store[k])}")
        print(f"     file: {ARCHIVE}")
        return 0

    cloud = CloudSync()

    if args.restore:
        if not cloud.can_publish_feed:
            print("RSAMAXXED_FEED_KEY is not set — restoring needs the operator "
                  "key.", file=sys.stderr)
            return 1
        if not any(store[k] for k in STREAMS):
            print("archive is empty; nothing to restore", file=sys.stderr)
            return 1
        try:
            sent = restore(cloud, store)
        except CloudError as exc:
            print(f"restore failed: {exc}", file=sys.stderr)
            return 2
        print(f"restored — {sent.get('buys', 0)} plays, {sent.get('sells', 0)} exits, "
              f"{sent.get('roundups', 0)} round-ups, {sent.get('lifecycle', 0)} board rows "
              f"(anything already present was skipped)")
        return 0

    try:
        added = merge(cloud, store)
    except CloudError as exc:
        print(f"archive failed: {exc}", file=sys.stderr)
        return 2

    _save(store)
    total = {k: len(store[k]) for k in STREAMS}
    print(f"archived — +{added['buys']} plays, +{added['sells']} exits, "
          f"+{added['roundups']} round-ups, +{added['lifecycle']} board rows; "
          f"holding {total['buys']}/{total['sells']}/{total['roundups']}/{total['lifecycle']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
