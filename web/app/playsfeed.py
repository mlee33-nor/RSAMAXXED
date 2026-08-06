"""Reading the play feed: queries, grouping and the board summary.

The routes stay thin — they ask for a `Board` and render it. All the shaping
lives here so the web page, the JSON API and the tests agree on what "open"
means without three copies of the rule.

The organising idea the whole Plays page rests on: a play has a **life**, and
the feed reports it in four separate places.

    BUY alert ─► (you buy, the split happens) ─► TRACK status ─► round-up ─► EXIT

So an entry in the feed is not one row, it is up to four rows joined on the
ticker. `link_lifecycle()` does that join, which is what turns a wall of alerts
into something a customer can act on: *this one is still open and expires in
two days*, *that one rounded up and here is what it exited at*.

The join is also why the board carries a **history**: once the four streams are
linked, every alert the feed has ever carried can state its own outcome — what
the split did, whether the fraction rounded up, what it exited at — and that
record is the only honest evidence the mechanism works at all.
"""
from __future__ import annotations

import calendar
import json
import os
import re
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Play, PlayExit, PlayLifecycle, PlayRoundUp

# How far back the page looks. Exits older than this are still in the database
# and still in the API; they just don't belong on a screen about what to trade.
EXIT_WINDOW_DAYS = 45
# A closed buy stays visible this long so you can see what you just missed.
CLOSED_GRACE_DAYS = 10
# Ceiling on the all-time history section. Generous enough that nothing real is
# hidden today, low enough that one page can't try to render five years at once.
# When it bites, the page says so rather than quietly showing a subset.
HISTORY_LIMIT = 400

# What each TRACK status means in plain words. The board publishes glyphs
# (⏳ ✅ 🧩 💵); nobody outside the alert channel knows what they stand for, so
# the page never shows one without the sentence next to it.
STATUS_LABELS = {
    "new": "Alerted",
    "pending": "Split pending",
    "rounded_up": "Rounded up",
    "fractional": "Came back fractional",
    "cash_in_lieu": "Cash in lieu",
    "canceled": "Split canceled",
    "low_odds": "Low odds",
    "unknown": "Unconfirmed",
}
# Statuses that mean the split has happened and there is nothing left to wait
# for. Anything else is still in flight.
RESOLVED_STATUSES = frozenset({"rounded_up", "fractional", "cash_in_lieu", "canceled"})

# WHERE a resolved play actually left something behind. Mirrors
# `lifecycle.brokers_for()` and `rsa_feed.FRACTIONAL_BROKERS` in the desktop
# app, duplicated rather than imported because this package deploys on its own
# (Railway root = web/) and cannot see the terminal's modules. Same arrangement
# as analytics.py mirroring app.py — if the desktop's list changes, change both.
#
# This is the distinction the whole profit calculation turns on:
#
#   rounded_up   a WHOLE share exists everywhere, so every account paid.
#   fractional   a fraction came back only at the three brokers that hold
#                fractions at all; the other seven settled it to cash, so
#                there is nothing left in them to sell.
#
# Multiplying every alert by "how many accounts do you have" ignores that, and
# overstates the fractional ones by more than three times.
FRACTIONAL_BROKERS = ("Public", "Robinhood", "SoFi")

# The ten the terminal executes in, in the order the settings panel lists them.
# Mirrors rsa_feed.SUPPORTED_BROKERS.
SUPPORTED_BROKERS = (
    "BBAE", "Chase", "DSPAC", "Fennel", "Fidelity",
    "Public", "Robinhood", "Schwab", "SoFi", "Wells Fargo",
)


def broker_key(name: str) -> str:
    """'Wells Fargo' -> 'wellsfargo'. Mirrors lifecycle.app_key().

    The feed writes display names; the settings panel and the profit maths key
    on the squashed lowercase form, so the two meet here and nowhere else.
    """
    return (name or "").strip().lower().replace(" ", "").replace("*", "")


# ------------------------------------------------------------------ lifecycle

@dataclass
class PlayLife:
    """One ticker's whole story: the alert, what the split did to it, whether
    the fraction rounded up, and how it exited."""

    play: Play
    rounded_up: bool = False
    exits: list[PlayExit] = field(default_factory=list)
    roundups: list[PlayRoundUp] = field(default_factory=list)
    life: PlayLifecycle | None = None

    @property
    def symbol(self) -> str:
        return self.play.symbol

    @property
    def booked_low(self) -> float:
        return sum(e.proceeds_low or 0.0 for e in self.exits)

    @property
    def booked_high(self) -> float:
        return sum(e.proceeds_high or e.proceeds_low or 0.0 for e in self.exits)

    # ---- what the split did, straight off the TRACK board

    @property
    def status(self) -> str:
        """The TRACK status, or the best thing we can say without one.

        A confirmed round-up outranks a missing board row: the round-up message
        is direct evidence, the absent board row is only silence.
        """
        if self.life and self.life.status:
            return self.life.status
        if self.rounded_up:
            return "rounded_up"
        return "unknown"

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status.replace("_", " ").title())

    @property
    def resolved(self) -> bool:
        """The split has run and the outcome is known."""
        return self.status in RESOLVED_STATUSES

    @property
    def paid_everywhere(self) -> bool:
        """A whole share came back, in every account at every broker."""
        return self.status == "rounded_up"

    @property
    def fraction_only(self) -> bool:
        """Something is left to sell, but only at the three fractional brokers.
        Accounts at the other seven were settled to cash and hold nothing."""
        return self.status == "fractional"

    @property
    def paying_brokers(self) -> tuple[str, ...]:
        """The brokers this play paid out in, from the TRACK board and nothing
        else. The whole profit model, in three lines:

        * **rounded_up** — a whole share came back, and a whole share is a whole
          share everywhere, so every broker you hold pays.
        * **fractional** — a fraction came back only at the three brokers that
          hold fractions; the other seven settled it to cash and hold nothing.
        * **anything else** — pending, cash in lieu, canceled, unknown — paid
          nowhere and contributes nothing to any total.

        The question this answers is "if I had bought every alert, in my
        accounts, what would the splits have paid me?" — so it deliberately does
        NOT narrow to the brokers the alerter's own sell message happened to
        name. That list is which accounts THEY held, not which accounts rounded;
        it stays on the Sells tab as reporting, and out of the arithmetic.

        Returned as display names; pair with `broker_key()` to match settings.
        """
        if self.paid_everywhere:
            return SUPPORTED_BROKERS
        if self.fraction_only:
            return FRACTIONAL_BROKERS
        return ()

    @property
    def sold(self) -> bool:
        """The feed published an exit for this play, so the brokers above are
        the ones it was really sold at rather than the ones that were eligible."""
        return bool(self.exits)

    @property
    def paid_in(self) -> str:
        """Where this play left anything behind, in words."""
        brokers = self.paying_brokers
        if not brokers:
            return "nothing to sell"
        if len(brokers) >= len(SUPPORTED_BROKERS):
            return "every broker"
        return ", ".join(brokers)

    @property
    def sold_at(self) -> str:
        """The brokers the sell alert named, for the record. Reporting only —
        see `paying_brokers` for why this is not what the money is based on."""
        legs = dict.fromkeys(l.get("broker") for e in self.exits for l in e.legs)
        return ", ".join(b for b in legs if b)

    @property
    def resolved_on(self) -> str:
        """The date this play's outcome was established, best evidence first.

        Profit belongs to the month it was booked in, not the month the alert
        went out — those are routinely weeks apart, and bucketing by the alert
        would credit a July payout to June.
        """
        if self.exits:
            return self.exits[-1].sell_date or ""
        return (self.confirmed_date or self.play.last_buy_date
                or self.play.alert_date or "")

    @property
    def sell_symbol(self) -> str:
        """The ticker an order can actually be placed in.

        A reverse split usually renames the company (AGAE -> AIFA). Holdings sit
        under the old symbol; only the new one is tradeable, and a customer who
        doesn't know that types the wrong ticker.
        """
        return (self.life.sell_symbol if self.life else "") or self.play.symbol

    @property
    def renamed(self) -> bool:
        return self.sell_symbol != self.play.symbol

    @property
    def confirmed_date(self) -> str:
        """When the round-up was confirmed, if it ever was."""
        for r in self.roundups:
            if r.confirmed_date:
                return r.confirmed_date
        return ""

    @property
    def ratio_n(self) -> int | None:
        """The N in a 1-for-N split.

        Prefers the parsed column, then reads it back out of the ratio string
        the alert published ('1:20', '1-for-20'). Worth the fallback: a play
        with a ratio nobody parsed is still a play whose payout is knowable, and
        dropping it would quietly shrink every total on the page.
        """
        p = self.play
        if p.ratio_n and p.ratio_n > 1:
            return p.ratio_n
        nums = re.findall(r"\d+", p.ratio or "")
        if nums:
            n = int(nums[-1])
            if n > 1:
                return n
        return None

    @property
    def per_account_profit(self) -> float | None:
        """What ONE account would have made on this play, in theory.

            entry x (ratio - 1)

        The site's one formula (see site.js `RSA`): you paid `entry` for a share
        that a round-up hands back whole at `entry x ratio`. Falls back to the
        alert's own estimate when the ratio or the entry price wasn't published,
        and returns None when neither is knowable — a play we cannot price must
        drop out of the arithmetic rather than count as zero.
        """
        p = self.play
        n = self.ratio_n
        if p.entry_price and n:
            return p.entry_price * (n - 1)
        if p.est_profit:
            return p.est_profit
        return None

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


def _life_key(alert_date: str, symbol: str) -> str:
    """The lifecycle identity, matching `rsa_feed.LifecycleRow.key`."""
    return f"{alert_date or ''}:{(symbol or '').upper()}"


def link_lifecycle(
    plays: Sequence[Play],
    roundups: Iterable[PlayRoundUp],
    exits: Iterable[PlayExit],
    lifecycle: Iterable[PlayLifecycle] = (),
) -> list[PlayLife]:
    """Join the four streams on ticker.

    Ticker is the only key the feed gives us — the sell message never names the
    alert it closes. That is good enough because the same name rarely reverse
    splits twice inside one window, and a wrong link shows a customer MORE
    information about a symbol they hold, not less.

    The TRACK board is the exception: it is keyed 'date:SYMBOL', so it is matched
    on the exact alert first and only falls back to the ticker. The fallback
    matters because the board and the alert sometimes disagree by a day, and the
    status is worth more than the strictness.
    """
    confirmed = {r.symbol for r in roundups}
    ru_by_symbol: dict[str, list[PlayRoundUp]] = defaultdict(list)
    for r in roundups:
        ru_by_symbol[r.symbol].append(r)

    by_symbol: dict[str, list[PlayExit]] = defaultdict(list)
    for e in exits:
        by_symbol[e.symbol].append(e)

    life_by_key: dict[str, PlayLifecycle] = {}
    life_by_symbol: dict[str, PlayLifecycle] = {}
    for row in lifecycle:
        life_by_key[row.source_id or _life_key(row.alert_date, row.symbol)] = row
        # Newest alert_date wins the ticker-only fallback.
        prev = life_by_symbol.get(row.symbol)
        if prev is None or (row.alert_date or "") >= (prev.alert_date or ""):
            life_by_symbol[row.symbol] = row

    lives = []
    for p in plays:
        life = PlayLife(play=p, rounded_up=p.symbol in confirmed)
        # Only exits at or after the alert: an exit that predates the alert
        # belongs to that ticker's previous split, not this one.
        life.exits = sorted(
            (e for e in by_symbol.get(p.symbol, ()) if e.sell_date >= (p.alert_date or "")),
            key=lambda e: e.sell_date,
        )
        life.roundups = ru_by_symbol.get(p.symbol, [])
        life.life = (life_by_key.get(_life_key(p.alert_date, p.symbol))
                     or life_by_symbol.get(p.symbol))
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

    # Every alert the feed has ever carried, newest first, each one stating its
    # own outcome. The window above is about what to trade; this is the record.
    history: list[PlayLife] = field(default_factory=list)
    # TRACK rows we hold a status for but no matching BUY alert — usually a play
    # alerted before the feed existed, or one whose alert message was edited.
    # Surfaced rather than dropped: a customer may still be holding it, and
    # "your position resolved" is the whole job of the board.
    orphan_lifecycle: list[PlayLifecycle] = field(default_factory=list)
    # True when older alerts exist beyond HISTORY_LIMIT. The page says so out
    # loud: a silently-cut list reads as "this is everything" when it isn't.
    history_truncated: bool = False
    # When the feed itself last changed — not when this page was rendered. The
    # difference is the whole question "is this thing still being updated?".
    last_update: datetime | None = None

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
        return bool(self.open_plays or self.closed_plays or self.exits or self.history)

    # ---- the round-up record, over everything the feed has ever carried
    @property
    def resolved_history(self) -> list[PlayLife]:
        """Alerts whose split has actually run. The only fair denominator: a
        play still waiting on its split has neither won nor lost yet."""
        return [l for l in self.history if l.resolved]

    @property
    def rounded_history(self) -> list[PlayLife]:
        return [l for l in self.resolved_history if l.status == "rounded_up"]

    @property
    def roundup_rate(self) -> float | None:
        """Share of resolved alerts that rounded up, 0..1. None when nothing has
        resolved — a rate off two data points is noise dressed as evidence."""
        resolved = self.resolved_history
        if len(resolved) < 3:
            return None
        return len(self.rounded_history) / len(resolved)

    # ---- the theoretical-profit basis, for the calculator on the page
    #
    # Two buckets, because the tracker says they paid in two different places.
    # Adding them together and multiplying by one account count is the mistake
    # this split exists to prevent.
    @property
    def profit_basis(self) -> list[PlayLife]:
        """Confirmed round-ups we can price. These paid in EVERY account: the
        tracker says a whole share came back, and a whole share is a whole share
        at all ten brokers."""
        return [l for l in self.rounded_history if l.per_account_profit]

    @property
    def fractional_basis(self) -> list[PlayLife]:
        """Plays that came back as a fraction. Sellable ONLY at the three
        brokers that hold fractions — the other seven paid cash in lieu and hold
        nothing. Priced separately for that reason, and never folded into the
        round-up total."""
        return [l for l in self.history if l.fraction_only and l.per_account_profit]

    @property
    def per_account_profit(self) -> float:
        """One account, one share in each confirmed round-up on this board."""
        return sum(l.per_account_profit or 0.0 for l in self.profit_basis)

    @property
    def per_fractional_account(self) -> float:
        """The same figure for the fraction-only plays, per account held at one
        of the three. Upper bound, not profit: a fraction that stays a fraction
        is worth roughly what was paid for it, and only moves with the price."""
        return sum(l.per_account_profit or 0.0 for l in self.fractional_basis)

    @property
    def profit_unpriced(self) -> int:
        """Round-ups left OUT of the number above for want of a price. Shown on
        the page: a total that quietly drops rows overstates its own coverage."""
        return len(self.rounded_history) - len(self.profit_basis)

    # ---- what the dashboard computes from
    @property
    def payout_rows(self) -> list[dict]:
        """Every play that paid something, as plain data for the browser.

        The money is finished on the CLIENT, not here, and that is deliberate:
        the multiplier is the reader's own per-broker account counts, which live
        in their browser and are never sent to us. The server ships what it
        knows — when it paid, how much per account, and WHICH BROKERS it paid in
        — and the page does the arithmetic against their numbers.
        """
        rows = []
        for l in self.history:
            per = l.per_account_profit
            brokers = l.paying_brokers
            if not per or not brokers:
                continue
            rows.append({
                "sym": l.play.symbol,
                # The ALERT month, not the month the split resolved. The page
                # asks "if I had bought everything, what did each month make",
                # and you buy on the alert — so the payout belongs to the month
                # you would have put the money in. Booking it to the resolution
                # date instead drains a month of its own plays and piles them
                # into the next one, which is what made June read as empty.
                "on": l.play.alert_date or l.resolved_on,
                "booked": l.resolved_on,
                "per": round(per, 4),
                "brokers": [broker_key(b) for b in brokers],
                "status": l.status,
                "sold": l.sold,
            })
        return sorted(rows, key=lambda r: r["on"])

    @property
    def payout_json(self) -> str:
        return json.dumps(self.payout_rows, separators=(",", ":"))

    @property
    def broker_slots(self) -> list[tuple[str, str, bool]]:
        """(display name, key, holds fractions) for the settings panel."""
        return [(b, broker_key(b), b in FRACTIONAL_BROKERS) for b in SUPPORTED_BROKERS]

    def totals(self, accounts: dict[str, int] | None = None) -> dict:
        """Money, against an account profile. Same rule the browser applies.

        `accounts` maps broker key -> how many accounts you hold there. Default
        is one at each broker, which is what the page renders before anyone has
        opened the settings panel — a real figure with a stated basis beats a
        blank, and beats a made-up ten.
        """
        # `is None` and not a truthiness test: an empty map, or one with every
        # broker set to zero, is a REAL answer — "I hold nothing anywhere" —
        # and must total zero. Falling back to the default there would show
        # someone numbers from accounts they told us they don't have.
        acc = ({broker_key(b): 1 for b in SUPPORTED_BROKERS}
               if accounts is None else accounts)
        by_month: dict[str, dict] = {}
        total = 0.0
        paid = 0
        for r in self.payout_rows:
            n = sum(acc.get(k, 0) for k in r["brokers"])
            if not n:
                continue
            amount = r["per"] * n
            total += amount
            paid += 1
            key = (r["on"] or "")[:7] or "—"
            bucket = by_month.setdefault(key, {"key": key, "total": 0.0, "plays": 0})
            bucket["total"] += amount
            bucket["plays"] += 1
        months = [by_month[k] for k in sorted(by_month)]
        best = max(months, key=lambda m: m["total"], default=None)
        return {
            "total": total,
            "plays": paid,
            "months": months,
            "best": best,
            "per_month": (total / len(months)) if months else 0.0,
        }

    # ---- the calendar
    @property
    def by_deadline(self) -> "OrderedDict[str, list[PlayLife]]":
        """Open plays grouped by the day their buy window shuts.

        Keyed on last_buy_date because that is the date that can be missed. An
        alert with no deadline published lands under '' and the page lists it
        separately rather than inventing a day for it.
        """
        buckets: dict[str, list[PlayLife]] = defaultdict(list)
        for l in self.open_plays:
            buckets[l.play.last_buy_date or ""].append(l)
        return OrderedDict(sorted(buckets.items(), key=lambda kv: (kv[0] == "", kv[0])))

    def calendar_months(self, today: date | None = None, months: int = 2) -> list[dict]:
        """Month grids of buy deadlines, starting with the current month.

        The current month always, and a later one only if something actually
        shuts in it — a grid of 30 blank squares is furniture, not information.
        Days outside the range still appear in the day list under the grid, so a
        far-off deadline is never hidden, only un-gridded.
        """
        today = today or date.today()
        counts = {d: len(v) for d, v in self.by_deadline.items() if d}
        out = []
        y, m = today.year, today.month
        for i in range(max(1, months)):
            if i and not any(k[:7] == f"{y:04d}-{m:02d}" for k in counts):
                break
            weeks = []
            # Monday-first, matching how the rest of the site reads dates.
            for week in calendar.Calendar(firstweekday=0).monthdatescalendar(y, m):
                row = []
                for d in week:
                    iso = d.isoformat()
                    row.append({
                        "iso": iso,
                        "day": d.day,
                        "in_month": d.month == m,
                        "count": counts.get(iso, 0),
                        "today": d == today,
                        "past": d < today,
                    })
                weeks.append(row)
            out.append({"label": f"{calendar.month_name[m]} {y}", "weeks": weeks})
            m += 1
            if m > 12:
                m, y = 1, y + 1
        return out

    @property
    def history_by_status(self) -> list[tuple[str, str, int]]:
        """(status, human label, count), in the order a split actually happens.

        Carries the label with it so the template never has to know the
        vocabulary — the words for these statuses belong next to the statuses.
        """
        counts: dict[str, int] = defaultdict(int)
        for l in self.history:
            counts[l.status] += 1
        order = list(STATUS_LABELS)
        return [
            (s, STATUS_LABELS.get(s, s.replace("_", " ").title()), counts[s])
            for s in sorted(counts, key=lambda s: order.index(s) if s in order else 99)
        ]


def _by_date_desc(rows: Iterable, key: str) -> "OrderedDict[str, list]":
    buckets: dict[str, list] = defaultdict(list)
    for r in rows:
        buckets[getattr(r, key) or "—"].append(r)
    return OrderedDict(sorted(buckets.items(), key=lambda kv: kv[0], reverse=True))


def _newest(rows: Iterable, *attrs: str) -> datetime | None:
    """The latest timestamp across some rows, ignoring the ones that have none."""
    stamps = [
        v for r in rows for a in attrs
        if isinstance(v := getattr(r, a, None), datetime)
    ]
    # Every column here is a UtcDateTime, so they come back aware on both
    # backends (see types.py) and max() over the mix is safe.
    return max(stamps) if stamps else None


def load_board(db: Session, *, today: date | None = None,
               history_limit: int = HISTORY_LIMIT) -> Board:
    """The whole page in one call: four queries, joined in memory.

    Four queries rather than one join because the streams have no foreign key
    between them — they're joined on ticker, and doing that in Python keeps the
    rule (see `link_lifecycle`) readable instead of buried in SQL.

    Everything is read once and then windowed in Python: the trading board wants
    the last few weeks, the history section wants all of it, and they must agree
    about every play they both show. Two queries with two different floors is
    how they'd stop agreeing.
    """
    today = today or date.today()

    plays = list(db.scalars(
        select(Play).order_by(Play.alert_date.desc(), Play.id.desc()).limit(history_limit + 1)
    ))
    board_truncated = len(plays) > history_limit
    if board_truncated:
        plays = plays[:history_limit]

    exits = list(db.scalars(
        select(PlayExit).order_by(PlayExit.sell_date.desc(), PlayExit.id.desc())
    ))
    roundups = list(db.scalars(select(PlayRoundUp).order_by(PlayRoundUp.id.desc())))
    lifecycle = list(db.scalars(select(PlayLifecycle)))

    lives = link_lifecycle(plays, roundups, exits, lifecycle)

    exit_floor = (today - timedelta(days=EXIT_WINDOW_DAYS)).isoformat()
    play_floor = exit_floor
    closed_floor = (today - timedelta(days=CLOSED_GRACE_DAYS)).isoformat()
    recent_exits = [e for e in exits if (e.sell_date or "") >= exit_floor]

    board = Board(exits=recent_exits, generated_at=datetime.now())
    board.roundup_symbols = {r.symbol for r in roundups}
    board.history = lives                       # already newest-alert-first
    board.history_truncated = board_truncated
    claimed = {id(l.life) for l in lives if l.life is not None}
    board.orphan_lifecycle = sorted(
        (row for row in lifecycle if id(row) not in claimed),
        key=lambda r: (r.alert_date or "", r.symbol), reverse=True,
    )
    board.last_update = _newest(
        [*plays, *exits, *roundups], "posted_at", "created_at",
    ) or _newest(lifecycle, "updated_at", "status_changed_at")

    for life in lives:
        if (life.play.alert_date or "") < play_floor:
            continue                            # history only, not the trading board
        if life.play.is_open(today):
            board.open_plays.append(life)
        elif (life.play.last_buy_date or life.play.alert_date or "") >= closed_floor:
            board.closed_plays.append(life)

    # Soonest deadline first — that is the order you'd work the list in.
    board.open_plays.sort(key=lambda l: (l.play.days_left() if l.play.days_left() is not None else 999,
                                         l.play.symbol))
    board.exits_by_date = _by_date_desc(recent_exits, "sell_date")
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
