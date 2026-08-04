"""Reading the play feed: queries, grouping and the board summary.

The routes stay thin — they ask for a `Board` and render it. All the shaping
lives here so the web page, the JSON API and the tests agree on what "open"
means without three copies of the rule.

The organising idea the whole Plays page rests on: a play has a **life**, and
the feed reports it in three separate places.

    BUY alert  ─►  (you buy, the split happens)  ─►  round-up confirmed  ─►  EXIT

So an entry in the feed is not one row, it is up to three rows joined on the
ticker. `link_lifecycle()` does that join, which is what turns a wall of alerts
into something a customer can act on: *this one is still open and expires in
two days*, *that one rounded up and here is what it exited at*.
"""
from __future__ import annotations

import json
import os
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Play, PlayExit, PlayRoundUp

# How far back the page looks. Exits older than this are still in the database
# and still in the API; they just don't belong on a screen about what to trade.
EXIT_WINDOW_DAYS = 45
# A closed buy stays visible this long so you can see what you just missed.
CLOSED_GRACE_DAYS = 10


# ------------------------------------------------------------------ lifecycle

@dataclass
class PlayLife:
    """One ticker's whole story: the alert, whether it rounded up, how it exited."""

    play: Play
    rounded_up: bool = False
    exits: list[PlayExit] = field(default_factory=list)

    @property
    def symbol(self) -> str:
        return self.play.symbol

    @property
    def booked_low(self) -> float:
        return sum(e.proceeds_low or 0.0 for e in self.exits)

    @property
    def booked_high(self) -> float:
        return sum(e.proceeds_high or e.proceeds_low or 0.0 for e in self.exits)

    @property
    def stage(self) -> str:
        """Where this play is in its life. Drives the badge on the page."""
        if self.exits:
            return "closed"
        if self.rounded_up:
            return "rounded"
        if not self.play.is_open():
            return "expired"
        return "open"


def link_lifecycle(
    plays: Sequence[Play],
    roundups: Iterable[PlayRoundUp],
    exits: Iterable[PlayExit],
) -> list[PlayLife]:
    """Join the three streams on ticker.

    Ticker is the only key the feed gives us — the sell message never names the
    alert it closes. That is good enough because the same name rarely reverse
    splits twice inside one window, and a wrong link shows a customer MORE
    information about a symbol they hold, not less.
    """
    confirmed = {r.symbol for r in roundups}
    by_symbol: dict[str, list[PlayExit]] = defaultdict(list)
    for e in exits:
        by_symbol[e.symbol].append(e)

    lives = []
    for p in plays:
        life = PlayLife(play=p, rounded_up=p.symbol in confirmed)
        # Only exits at or after the alert: an exit that predates the alert
        # belongs to that ticker's previous split, not this one.
        life.exits = sorted(
            (e for e in by_symbol.get(p.symbol, ()) if e.sell_date >= (p.alert_date or "")),
            key=lambda e: e.sell_date,
        )
        lives.append(life)
    return lives


# --------------------------------------------------------------------- boards

@dataclass
class Board:
    """Everything the Plays page renders, already divided and ordered."""

    open_plays: list[PlayLife] = field(default_factory=list)
    closed_plays: list[PlayLife] = field(default_factory=list)
    exits: list[PlayExit] = field(default_factory=list)
    exits_by_date: "OrderedDict[str, list[PlayExit]]" = field(default_factory=OrderedDict)
    roundup_symbols: set[str] = field(default_factory=set)
    generated_at: datetime | None = None

    # ---- summary numbers, all derived, none stored
    @property
    def open_count(self) -> int:
        return len(self.open_plays)

    @property
    def expiring_today(self) -> list[PlayLife]:
        return [l for l in self.open_plays if (l.play.days_left() or 99) <= 0]

    @property
    def urgent(self) -> list[PlayLife]:
        """Open, actionable, and the buy window shuts within two days."""
        return [
            l for l in self.open_plays
            if l.play.is_actionable and (l.play.days_left() if l.play.days_left() is not None else 99) <= 2
        ]

    @property
    def booked_low(self) -> float:
        return sum(e.proceeds_low or 0.0 for e in self.exits)

    @property
    def booked_high(self) -> float:
        return sum(e.proceeds_high or e.proceeds_low or 0.0 for e in self.exits)

    @property
    def exit_count(self) -> int:
        return len(self.exits)

    @property
    def has_anything(self) -> bool:
        return bool(self.open_plays or self.closed_plays or self.exits)


def _by_date_desc(rows: Iterable, key: str) -> "OrderedDict[str, list]":
    buckets: dict[str, list] = defaultdict(list)
    for r in rows:
        buckets[getattr(r, key) or "—"].append(r)
    return OrderedDict(sorted(buckets.items(), key=lambda kv: kv[0], reverse=True))


def load_board(db: Session, *, today: date | None = None) -> Board:
    """The whole page in one call: three queries, joined in memory.

    Three queries rather than one join because the streams have no foreign key
    between them — they're joined on ticker, and doing that in Python keeps the
    rule (see `link_lifecycle`) readable instead of buried in SQL.
    """
    today = today or date.today()
    exit_floor = (today - timedelta(days=EXIT_WINDOW_DAYS)).isoformat()
    play_floor = (today - timedelta(days=EXIT_WINDOW_DAYS)).isoformat()

    plays = list(db.scalars(
        select(Play).where(Play.alert_date >= play_floor).order_by(Play.alert_date.desc(), Play.id.desc())
    ))
    exits = list(db.scalars(
        select(PlayExit).where(PlayExit.sell_date >= exit_floor).order_by(PlayExit.sell_date.desc(), PlayExit.id.desc())
    ))
    roundups = list(db.scalars(select(PlayRoundUp).order_by(PlayRoundUp.id.desc())))

    lives = link_lifecycle(plays, roundups, exits)

    board = Board(exits=exits, generated_at=datetime.now())
    board.roundup_symbols = {r.symbol for r in roundups}
    closed_floor = (today - timedelta(days=CLOSED_GRACE_DAYS)).isoformat()

    for life in lives:
        if life.play.is_open(today):
            board.open_plays.append(life)
        elif (life.play.last_buy_date or life.play.alert_date or "") >= closed_floor:
            board.closed_plays.append(life)

    # Soonest deadline first — that is the order you'd work the list in.
    board.open_plays.sort(key=lambda l: (l.play.days_left() if l.play.days_left() is not None else 999,
                                         l.play.symbol))
    board.exits_by_date = _by_date_desc(exits, "sell_date")
    return board


# ----------------------------------------------------------------- API shapes

def play_json(p: Play) -> dict:
    return {
        "symbol": p.symbol,
        "kind": p.kind,
        "alert_date": p.alert_date,
        "ratio": p.ratio,
        "ratio_n": p.ratio_n,
        "entry_price": p.entry_price,
        "est_profit": p.est_profit,
        "last_buy_date": p.last_buy_date,
        "days_left": p.days_left(),
        "roundup_history": p.roundup_history,
        "strategy": p.strategy,
        "actionable": p.is_actionable,
        "open": p.is_open(),
    }


def exit_json(e: PlayExit) -> dict:
    # source_id and posted_at are here for the desktop, which merges these into
    # its local sells.json and dedupes on source_id — the same ticker
    # legitimately exits more than once, so symbol is not an identity.
    return {
        "source_id": e.source_id,
        "symbol": e.symbol,
        "sell_date": e.sell_date,
        "exit_price": e.exit_price,
        "proceeds_low": e.proceeds_low,
        "proceeds_high": e.proceeds_high,
        "accounts": e.accounts,
        "legs": e.legs,
        "note": e.note,
        "posted_at": e.posted_at.isoformat() if e.posted_at else "",
    }


def feed_json(board: Board) -> dict:
    """What `GET /api/v1/plays` returns — the same division the page shows."""
    return {
        "generated_at": (board.generated_at or datetime.now()).isoformat(),
        "buys": [play_json(l.play) for l in board.open_plays],
        "closed": [play_json(l.play) for l in board.closed_plays],
        "sells": [exit_json(e) for e in board.exits],
        "roundups": sorted(board.roundup_symbols),
    }


# ---------------------------------------------------- load from the desktop file

def _kind_from_note(note: str) -> str:
    """The desktop app's pick `note` -> our `kind`. Mirrors `_rsa_note` in app.py:
    'Reg Alert' is a standard listed alert, 'OTC' an OTC name, and a note that
    mentions 'conditional' is watch-only."""
    n = (note or "").lower()
    if "otc" in n:
        return "otc"
    if "conditional" in n:
        return "conditional"
    return "standard"


def import_picks_file(db: Session, path: str) -> int:
    """Load the desktop app's picks.json into the play feed and return how many
    NEW alerts were added.

    picks.json is a list of ``{"symbol", "note", "date"}`` — exactly what the
    software persists. This is the same insert-only, source_id-keyed upsert as
    ``POST /api/v1/plays/ingest`` (see routes/api.py), so calling it on every
    startup and every page load is idempotent: re-reading the same file inserts
    nothing. Any read/parse problem is swallowed to a 0 — a malformed picks.json
    must never take the whole page down.
    """
    if not path or not os.path.exists(path):
        return 0
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return 0
    if not isinstance(data, list):
        return 0

    rows: list[tuple[str, str, str, str]] = []  # (source_id, symbol, kind, date)
    for item in data:
        if not isinstance(item, dict):
            continue
        sym = str(item.get("symbol") or "").upper().strip()
        if not sym:
            continue
        d = str(item.get("date") or "").strip()[:10]
        rows.append((f"picks:{sym}:{d}", sym, _kind_from_note(item.get("note")), d))
    if not rows:
        return 0

    existing = set(db.scalars(select(Play.source_id).where(
        Play.source_id.in_([r[0] for r in rows])
    )))
    added = 0
    for source_id, sym, kind, d in rows:
        if source_id in existing:
            continue
        existing.add(source_id)  # dedupe within the same file too
        db.add(Play(source_id=source_id, symbol=sym, kind=kind, alert_date=d))
        added += 1
    if added:
        db.commit()
    return added
