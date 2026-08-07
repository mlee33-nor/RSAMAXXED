"""Canonical parser for the RSA alert feed.

One place that knows how the alert channels are written, so the desktop app,
the cloud ingest and the tests can never drift apart.

The feed is three streams, and they are NOT the same shape:

  BUY   — an "Alert Bot" rich embed. Structured, one ticker per embed:
              title  '🔔 RSA Alert'    description 'STANDARD' | 'OTC' | 'CONDITIONAL'
              fields '🎟️ Ticker', '📅 Alert Date', '⚖️ Ratio',
                     '🏷️ Current Share Price', '💸 Potential Profit/Acct',
                     '⌛ Last Day to Buy', '📊 Round-Up History', '🧠 Strategy'

  SELL  — a human typing plain text, several exits per message:
              TICKER $3.59
              - Robinhood x3
              - Schwab x1
              **+$14.36**
          with all the variation humans produce: 'Broker: x4', 'wells x10',
          'Swchab x1', ranges ('Public x9-21' -> '**+$22-46**'), a bolded
          amount with no '$', a trailing 'Total:' block, and free-text notes.

  ROUND-UP — a bare green embed in the SELL channel:
              title 'Round Up Successful'   description 'HCWB'
          The single most valuable field in the product: proof the fraction
          actually rounded up for that ticker.

Nothing here touches the network or the filesystem, and it imports nothing
outside the standard library — it is pure text in, dataclasses out.
"""
from __future__ import annotations

import difflib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from typing import Any, Iterable, Sequence

__all__ = [
    "BuyAlert", "SellAlert", "RoundUp", "SellLeg",
    "parse_buy_message", "parse_sell_message", "parse_messages",
    "normalize_broker", "parse_rsa_date", "to_pick", "to_picks", "from_pick",
    "FeedBatch",
    "BUY_KINDS", "SUPPORTED_BROKERS",
    "LifecycleRow", "parse_lifecycle_message", "parse_lifecycle_messages",
    "LIFECYCLE_STATUSES", "SELLABLE_STATUSES", "FRACTIONAL_STATUSES",
    "FRACTIONAL_BROKERS", "CASH_IN_LIEU_BROKERS", "returns_fraction",
]

# --------------------------------------------------------------------- brokers

# The ten the terminal can actually execute in. Anything else still parses —
# it is real information about the play — it just can't be automated here.
SUPPORTED_BROKERS = (
    "BBAE", "Chase", "DSPAC", "Fennel", "Fidelity",
    "Public", "Robinhood", "Schwab", "SoFi", "Wells Fargo",
)

# Written aliases seen in the channel, lowercased. The fuzzy pass below catches
# the typos ('Swchab'); this table catches the deliberate shorthand ('wells').
_BROKER_ALIASES = {
    "bbae": "BBAE",
    "chase": "Chase", "jpmorgan": "Chase", "jpm": "Chase",
    "dspac": "DSPAC",
    "fennel": "Fennel",
    "fidelity": "Fidelity", "fid": "Fidelity",
    "public": "Public",
    "robinhood": "Robinhood", "rh": "Robinhood", "hood": "Robinhood",
    "schwab": "Schwab", "charles schwab": "Schwab",
    "sofi": "SoFi",
    "wells": "Wells Fargo", "wellsfargo": "Wells Fargo", "wells fargo": "Wells Fargo",
    "wf": "Wells Fargo",
    # Named in the feed, not automated by this tool.
    "webull": "Webull", "wb": "Webull",
    "tradier": "Tradier", "firstrade": "Firstrade", "tastytrade": "Tastytrade",
    "vanguard": "Vanguard", "etrade": "E*TRADE", "e*trade": "E*TRADE",
    "merrill": "Merrill", "ally": "Ally", "tornado": "Tornado",
}


def normalize_broker(raw: str) -> str:
    """'Swchab' -> 'Schwab', 'wells' -> 'Wells Fargo', 'dSPAC' -> 'DSPAC'.

    Falls back to a title-cased version of whatever was written rather than
    dropping the leg: an unknown broker is still a real fill we should show.
    """
    cleaned = re.sub(r"[^a-z0-9*\s]", "", (raw or "").strip().lower()).strip()
    if not cleaned:
        return ""
    if cleaned in _BROKER_ALIASES:
        return _BROKER_ALIASES[cleaned]
    squashed = cleaned.replace(" ", "")
    if squashed in _BROKER_ALIASES:
        return _BROKER_ALIASES[squashed]
    # Typo tolerance. 0.75 accepts 'swchab'->'schwab' and rejects unrelated words.
    near = difflib.get_close_matches(squashed, _BROKER_ALIASES, n=1, cutoff=0.75)
    if near:
        return _BROKER_ALIASES[near[0]]
    return cleaned.title()


# ------------------------------------------------------------------- utilities

BUY_KINDS = ("standard", "otc", "conditional")

# Deliberately not \d{1,5}: a bare number is never a ticker, and 'x10' below
# must not be mistaken for one.
_TICKER = r"[A-Z]{1,6}(?:\.[A-Z])?"


def parse_rsa_date(value: str, *, today: date | None = None) -> str | None:
    """'6/18/26 (Thu)' -> '2026-06-18'. Returns None if there's no date in there."""
    m = re.search(r"(\d{1,2})/(\d{1,2})/(\d{2,4})", value or "")
    if not m:
        return None
    mo, da, yr = (int(x) for x in m.groups())
    if yr < 100:
        yr += 2000
    try:
        return date(yr, mo, da).isoformat()
    except ValueError:
        return None


def _money(value: str) -> float | None:
    """'$0.1205' -> 0.1205. '$4.76' -> 4.76. '' / 'N/A' -> None."""
    m = re.search(r"-?\d[\d,]*\.?\d*", (value or "").replace("$", ""))
    if not m:
        return None
    try:
        return float(m.group(0).replace(",", ""))
    except ValueError:
        return None


def _money_range(value: str) -> tuple[float | None, float | None]:
    """'+$22-46' -> (22.0, 46.0). '+$14.36' -> (14.36, 14.36).

    Public reports a span because its account count varies per customer, so a
    single number would be a lie in both directions.
    """
    nums = re.findall(r"\d[\d,]*\.?\d*", (value or "").replace("$", ""))
    vals = []
    for n in nums:
        try:
            vals.append(float(n.replace(",", "")))
        except ValueError:
            pass
    if not vals:
        return None, None
    return vals[0], vals[-1]


def _iso(ts: str | None) -> str:
    """Discord hands back RFC3339. Keep it as a plain UTC ISO string."""
    if not ts:
        return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    return str(ts)


def _msg_date(msg: dict) -> str:
    return (msg.get("timestamp") or "")[:10] or date.today().isoformat()


# ----------------------------------------------------------------- dataclasses

@dataclass(frozen=True)
class BuyAlert:
    """One RSA buy alert — a play to open."""

    source_id: str
    symbol: str
    kind: str = "standard"              # standard | otc | conditional
    alert_date: str = ""                # YYYY-MM-DD, the date the alert is for
    ratio: str = ""                     # '1:15' as written
    ratio_n: int | None = None          # 15 — the round-up multiple
    entry_price: float | None = None    # price when the alert fired
    est_profit: float | None = None     # the feed's own per-account estimate
    last_buy_date: str | None = None    # YYYY-MM-DD; after this the play is shut
    roundup_history: str = ""           # 'N/A' or a broker history blurb
    strategy: str = "1 Share/Account"
    posted_at: str = ""

    @property
    def is_actionable(self) -> bool:
        """Conditional alerts are watch-only: the split may not be declared yet,
        so the terminal must not fire on them."""
        return self.kind in ("standard", "otc")

    def days_left(self, today: date | None = None) -> int | None:
        if not self.last_buy_date:
            return None
        try:
            last = date.fromisoformat(self.last_buy_date)
        except ValueError:
            return None
        return (last - (today or date.today())).days

    def is_open(self, today: date | None = None) -> bool:
        """Still buyable. Undated alerts are treated as open — we can't prove
        otherwise, and hiding a live play is worse than showing a stale one."""
        left = self.days_left(today)
        return True if left is None else left >= 0


@dataclass(frozen=True)
class SellLeg:
    """'Public x9-21' — one broker and how many accounts it covered."""

    broker: str
    accounts_low: int = 0
    accounts_high: int = 0

    @property
    def is_range(self) -> bool:
        return self.accounts_high > self.accounts_low

    @property
    def supported(self) -> bool:
        return self.broker in SUPPORTED_BROKERS

    def __str__(self) -> str:
        n = f"{self.accounts_low}-{self.accounts_high}" if self.is_range else str(self.accounts_low)
        return f"{self.broker} ×{n}"


@dataclass(frozen=True)
class SellAlert:
    """One exit — a play closed at a price, across a set of brokers."""

    source_id: str
    symbol: str
    exit_price: float | None = None
    proceeds_low: float | None = None
    proceeds_high: float | None = None
    legs: tuple[SellLeg, ...] = ()
    note: str = ""
    posted_at: str = ""
    sell_date: str = ""

    @property
    def accounts(self) -> int:
        return sum(l.accounts_low for l in self.legs)

    @property
    def is_range(self) -> bool:
        return (self.proceeds_high or 0) > (self.proceeds_low or 0)

    @property
    def proceeds_text(self) -> str:
        lo, hi = self.proceeds_low, self.proceeds_high
        if lo is None:
            return "—"
        if self.is_range:
            return f"+${lo:,.2f}–${hi:,.2f}"
        return f"+${lo:,.2f}"


@dataclass(frozen=True)
class RoundUp:
    """'Round Up Successful — HCWB'. Proof the fraction actually rounded up."""

    source_id: str
    symbol: str
    posted_at: str = ""
    confirmed_date: str = ""


@dataclass
class FeedBatch:
    """What one pull produced. Ordered oldest-first within each stream."""

    buys: list[BuyAlert] = field(default_factory=list)
    sells: list[SellAlert] = field(default_factory=list)
    roundups: list[RoundUp] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.buys or self.sells or self.roundups)

    def __len__(self) -> int:
        return len(self.buys) + len(self.sells) + len(self.roundups)

    def extend(self, other: "FeedBatch") -> "FeedBatch":
        self.buys.extend(other.buys)
        self.sells.extend(other.sells)
        self.roundups.extend(other.roundups)
        return self

    def to_json(self) -> dict[str, list[dict[str, Any]]]:
        """Wire format for the cloud ingest endpoint."""
        return {
            "buys": [asdict(b) for b in self.buys],
            "sells": [_sell_json(s) for s in self.sells],
            "roundups": [asdict(r) for r in self.roundups],
        }


def _sell_json(s: SellAlert) -> dict[str, Any]:
    d = asdict(s)
    d["legs"] = [asdict(l) for l in s.legs]
    return d


# ------------------------------------------------------------------- BUY parse

def _kind_from(desc: str, title: str) -> str:
    blob = f"{desc or ''} {title or ''}".lower()
    if "otc" in blob:
        return "otc"
    if "conditional" in blob:
        return "conditional"
    return "standard"


def _field_map(embed: dict) -> dict[str, str]:
    """Field names carry emoji ('🎟️ Ticker'), so match on a substring of the
    lowercased name rather than equality."""
    return {
        (f.get("name") or "").lower(): (f.get("value") or "").strip()
        for f in (embed.get("fields") or [])
    }


def _pick_field(fields: dict[str, str], *needles: str) -> str:
    for needle in needles:
        for name, value in fields.items():
            if needle in name:
                return value
    return ""


def parse_buy_message(msg: dict) -> list[BuyAlert]:
    """Every RSA Alert embed in one BUY-channel message.

    Falls back to plain text — a `(TICKER)` or `$CASHTAG` — so a channel that
    is not driven by the bot still produces plays.
    """
    mid = str(msg.get("id") or "")
    posted = _iso(msg.get("timestamp"))
    default_date = _msg_date(msg)
    out: list[BuyAlert] = []

    for i, embed in enumerate(msg.get("embeds") or []):
        title = embed.get("title") or ""
        desc = embed.get("description") or ""
        fields = _field_map(embed)

        raw_ticker = _pick_field(fields, "ticker")
        tm = re.search(r"[A-Za-z]{1,6}", raw_ticker)
        if not tm:
            continue

        ratio_raw = _pick_field(fields, "ratio")
        # '1:15' / '1-for-15' / '1 for 15' -> 15
        rm = re.search(r"1\s*(?::|-?\s*for\s*-?|/)\s*(\d+)", ratio_raw, re.I)

        out.append(BuyAlert(
            source_id=f"{mid}:{i}" if mid else f"{raw_ticker}:{default_date}",
            symbol=tm.group(0).upper(),
            kind=_kind_from(desc, title),
            alert_date=parse_rsa_date(_pick_field(fields, "alert date", "date")) or default_date,
            ratio=ratio_raw,
            ratio_n=int(rm.group(1)) if rm else None,
            entry_price=_money(_pick_field(fields, "share price", "price")),
            est_profit=_money(_pick_field(fields, "profit")),
            last_buy_date=parse_rsa_date(_pick_field(fields, "last day")),
            roundup_history=_pick_field(fields, "round-up history", "round up history"),
            strategy=_pick_field(fields, "strategy") or "1 Share/Account",
            posted_at=posted,
        ))

    if out:
        return out
    return _buys_from_text(msg.get("content") or "", mid, default_date, posted)


def _buys_from_text(text: str, mid: str, day: str, posted: str) -> list[BuyAlert]:
    """Non-embed channels: '(TICKER)' first, then '$CASHTAG'."""
    seen: set[str] = set()
    out: list[BuyAlert] = []
    symbols = re.findall(rf"\(({_TICKER})\)", text or "")
    if not symbols:
        symbols = [s.upper() for s in re.findall(r"\$([A-Za-z]{1,5})\b", text or "")]
    for sym in symbols:
        sym = sym.upper()
        if sym in seen or sym in ("A", "I"):
            continue
        seen.add(sym)
        out.append(BuyAlert(
            source_id=f"{mid}:{sym}" if mid else f"{sym}:{day}",
            symbol=sym, alert_date=day, posted_at=posted,
        ))
    return out


# ------------------------------------------------------------------ SELL parse

# 'EDBL $3.59' — the line that opens an exit block. The price is required:
# without it the line is prose, not an exit.
_SELL_HEAD = re.compile(rf"^\s*({_TICKER})\s*[@:]?\s*\$?\s*(\d+(?:\.\d+)?)\s*$")

# '- Robinhood x3' / '- Robinhood: x3' / '- Public x9-21' / '- wells  x10'
_SELL_LEG = re.compile(
    r"^\s*[-•*]\s*(?P<broker>[A-Za-z][A-Za-z0-9 .*&\-]*?)\s*:?\s*"
    r"[x×]\s*(?P<low>\d+)(?:\s*-\s*(?P<high>\d+))?\s*$",
    re.I,
)

# '**+$14.36**' / '**+ $22-46**' / '**+23.80**'
# The proceeds line that closes a block. The leading "+" is OPTIONAL, and that
# is not cosmetic: it was mandatory, and on 2026-08-07 an alert whose three
# blocks ended
#
#     **+$19.32**      BYAH
#     **+$40.80**      EDBL
#     **$159.84**      FFAI   <- no plus
#
# lost FFAI entirely. Its block never closed, so no exit was emitted, and the
# orphaned line then fell through to the commentary branch and was hung on the
# other two as a note. One character the alerter happened not to type cost the
# largest of the three exits, and produced a phantom "$159.84**" caption on the
# other two. A human reads all three of those lines as a total; so does this.
_SELL_TOTAL = re.compile(r"^\s*\*{0,2}\s*\+?\s*\$?\s*(?P<amt>[\d,.]+(?:\s*-\s*\$?[\d,.]+)?)\s*\*{0,2}\s*$")

# A line that is only money (and possibly markdown). Never commentary — see the
# note branch below.
_BARE_MONEY = re.compile(r"^[\s*+$]*[\d,.]+(?:\s*-\s*\$?[\d,.]+)?[\s*]*$")


def _strip_noise(text: str) -> str:
    """Drop role pings and custom emoji — they only ever confuse the line rules."""
    text = re.sub(r"<@[!&]?\d+>", "", text or "")
    text = re.sub(r"<a?:\w+:\d+>", "", text)
    return text


def parse_sell_message(msg: dict) -> tuple[list[SellAlert], list[RoundUp]]:
    """Exits and round-up confirmations from one SELL-channel message.

    A message holds one block per ticker::

        GDC $1.58            <- head: symbol + exit price
        - Wells x10          <- legs, one per broker
        **+ $15.80**         <- proceeds, sometimes a range

    A trailing 'Total:' block sums the message and is deliberately skipped —
    it is not an exit, and counting it would double every number.
    """
    mid = str(msg.get("id") or "")
    posted = _iso(msg.get("timestamp"))
    day = _msg_date(msg)

    roundups = [
        RoundUp(source_id=f"{mid}:ru:{i}", symbol=sym.upper(), posted_at=posted, confirmed_date=day)
        for i, sym in enumerate(
            (e.get("description") or "").strip()
            for e in (msg.get("embeds") or [])
            if "round up" in (e.get("title") or "").lower()
        )
        if re.fullmatch(_TICKER, sym.upper() or "-")
    ]

    sells: list[SellAlert] = []
    symbol = ""
    price: float | None = None
    legs: list[SellLeg] = []
    notes: list[str] = []
    in_total = False

    def flush() -> None:
        nonlocal symbol, price, legs
        symbol, price, legs = "", None, []

    for raw in _strip_noise(msg.get("content") or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        if re.match(r"^\*{0,2}total\b", line, re.I):
            in_total = True          # everything after this is a message-level sum
            flush()
            continue

        head = _SELL_HEAD.match(line)
        if head:
            in_total = False
            flush()
            symbol, price = head.group(1).upper(), float(head.group(2))
            continue

        leg = _SELL_LEG.match(line)
        if leg and symbol:
            broker = normalize_broker(leg.group("broker"))
            if broker:
                low = int(leg.group("low"))
                high = int(leg.group("high") or low)
                legs.append(SellLeg(broker, low, max(low, high)))
            continue

        total = _SELL_TOTAL.match(line)
        if total:
            if in_total or not symbol:
                continue         # the message-level 'Total:' sum — not an exit
            lo, hi = _money_range(total.group("amt"))
            sells.append(SellAlert(
                source_id=f"{mid}:{len(sells)}" if mid else f"{symbol}:{day}",
                symbol=symbol, exit_price=price,
                proceeds_low=lo, proceeds_high=hi if hi is not None else lo,
                legs=tuple(legs), posted_at=posted, sell_date=day,
            ))
            flush()
            continue

        # Anything else on its own line is commentary. The fraction warning on
        # VMAR is exactly the kind of thing a customer needs to read.
        #
        # A bare money figure never is. It is a proceeds line this parser failed
        # to claim, and hanging it on every exit in the message publishes a
        # caption like "$159.84**" against two unrelated tickers — which is
        # exactly what happened while the "+" above was mandatory. Belt and
        # braces: the regex now claims that line, and if a future format ever
        # slips past it again the result is a dropped note rather than a wrong
        # one attached to somebody else's exit.
        if _BARE_MONEY.match(line):
            continue
        if line.startswith("*") or len(line) > 40:
            # Discord bold/italic is markup, not content. Left in, a note reads
            # as "**mind the fraction**" on a page that renders no markdown.
            notes.append(line.strip("*_` ").strip())

    if notes and sells:
        # The note applies to the message, so hang it on every exit in it.
        blurb = " ".join(notes)[:400]
        sells = [
            SellAlert(**{**_sell_fields(s), "note": blurb, "legs": s.legs})
            for s in sells
        ]
    return sells, roundups


def _sell_fields(s: SellAlert) -> dict[str, Any]:
    d = asdict(s)
    d.pop("legs", None)
    return d


# ------------------------------------------------------------- LIFECYCLE parse
#
# The TRACK channel: one message, edited in place forever, holding the whole
# board inside a ```text fence. One row per play:
#
#     🔔 6̶/̶1̶1̶ - AGAE ↔️ AIFA ✅
#     └ kind    └ date  └ sym  └ alias  └ status
#
# Three things about the real messages that are easy to get wrong:
#
#   1. The dates carry U+0336 COMBINING LONG STROKE OVERLAY between every
#      character — '6/11' is really '6̶/̶1̶1̶'. The strike marks a date that has
#      passed. Strip combining marks first or every single row fails to match.
#   2. There is no year on the board. A row is dated relative to now, so a
#      12/28 seen in early January belongs to last year.
#   3. The leading glyph is the ALERT TYPE (🔔 standard, 💊 OTC, 📝 conditional).
#      The STATUS is the trailing token, and the two are unrelated.
#
# This is the only stream that reports what a split actually *did*. Holdings can
# tell you a fraction came back; they cannot tell you cash-in-lieu from a buy
# that never filled, and they cannot tell you that AGAE is now called AIFA.

LIFECYCLE_STATUSES = (
    "new", "pending", "rounded_up", "fractional",
    "cash_in_lieu", "canceled", "low_odds", "unknown",
)

# Statuses where the position is finished doing whatever it was going to do and
# there is something left to sell.
SELLABLE_STATUSES = frozenset({"rounded_up", "fractional", "canceled"})

# The fraction came back as a fraction rather than rounding up.
FRACTIONAL_STATUSES = frozenset({"fractional"})

# WHO ACTUALLY RETURNS A FRACTION. Only these three hand back a fractional
# share on a 🧩 play; every other broker settles it as cash-in-lieu and there is
# nothing left in the account to sell.
#
# This is the routing rule for fractional auto-sell, and getting it wrong is
# expensive in both directions: fan out to all ten and seven of them reject an
# order for shares that were never there, every single time. Skip these three
# and the fraction sits unsold.
#
# It does NOT apply to a round-up (✅) — that leaves a whole share, and every
# broker can sell one.
FRACTIONAL_BROKERS = ("Public", "Robinhood", "SoFi")

# The other seven. Named rather than derived so the reason is written down:
# these settle to cash automatically, so a 🧩 play needs no action on them.
CASH_IN_LIEU_BROKERS = tuple(
    b for b in SUPPORTED_BROKERS if b not in FRACTIONAL_BROKERS
)


def returns_fraction(broker: str) -> bool:
    """True if `broker` hands back a fractional share rather than cash."""
    return normalize_broker(broker) in FRACTIONAL_BROKERS

_STATUS_GLYPHS = {
    "\U0001f195": "new",           # 🆕 alerted, nothing has happened yet
    "⏳": "pending",           # ⏳ split declared, not executed
    "✅": "rounded_up",        # ✅ the fraction rounded up to a whole share
    "\U0001f9e9": "fractional",    # 🧩 a fraction came back as a fraction
    "\U0001f4b5": "cash_in_lieu",  # 💵 the broker paid cash instead
}

# Written, not glyphed. 'canceled' and 'cancelled' both appear.
_CANCEL_RE = re.compile(r"\[\s*cancell?ed\s*\]", re.I)
_LOW_ODDS_RE = re.compile(r"\[\s*low\s+odds\s*\]", re.I)

# '↔️ AIFA' / '-> AIFA' / '→ AIFA' — the post-split ticker.
_ALIAS_RE = re.compile(r"(?:↔|<->|->|→)️?\s*(?P<symbol>[A-Z][A-Z0-9.\-]{0,11})\b")

# '🔔 6/11 - AGAE ↔️ AIFA ✅'. The leading token is any non-space run, because
# the type glyphs are an open set (🔔 💊 📝 🚧 🚫 have all been seen).
_ROW_RE = re.compile(
    r"^(?P<kind>\S+)\s+(?P<date>\d{1,2}/\d{1,2}(?:/\d{2,4})?)\s*-\s*"
    r"(?P<symbol>[A-Z][A-Z0-9.\-]{0,11})(?P<tail>.*)$"
)

# Only the three the BUY embeds also declare. Anything else keeps its glyph and
# is treated as standard — guessing a kind we've never seen documented would put
# a play in the wrong bucket, which is worse than calling it standard.
_KIND_GLYPHS = {
    "\U0001f514": "standard",     # 🔔
    "\U0001f48a": "otc",          # 💊
    "\U0001f4dd": "conditional",  # 📝
}


def _strip_marks(text: Any) -> str:
    """Drop combining marks — the board strikes through past dates with U+0336."""
    try:
        import unicodedata
        return "".join(ch for ch in str(text or "")
                       if unicodedata.category(ch) != "Mn")
    except Exception:
        return str(text or "")


def _lifecycle_date(raw: str, today: date | None = None) -> str:
    """'6/11' -> '2026-06-11', picking the year the board means.

    The board is undated, so a month/day is read as the most recent occurrence:
    anything landing more than 60 days ahead is last year's, which is what makes
    a December row still parse correctly on January 3rd.
    """
    today = today or date.today()
    m = re.search(r"(\d{1,2})/(\d{1,2})(?:/(\d{2,4}))?", _strip_marks(raw))
    if not m:
        return ""
    mo, da, yr = m.group(1), m.group(2), m.group(3)
    try:
        if yr:
            year = int(yr)
            return date(year + 2000 if year < 100 else year, int(mo), int(da)).isoformat()
        guess = date(today.year, int(mo), int(da))
        if (guess - today).days > 60:
            guess = date(today.year - 1, int(mo), int(da))
        return guess.isoformat()
    except ValueError:
        return ""


@dataclass(frozen=True)
class LifecycleRow:
    """One row of the TRACK board — a play and what the split did to it."""

    symbol: str                 # the ticker as originally alerted
    sell_symbol: str            # what it trades as now; differs after a rename
    alert_date: str             # YYYY-MM-DD
    status: str                 # one of LIFECYCLE_STATUSES
    kind: str = "standard"      # standard | otc | conditional
    kind_glyph: str = ""        # the raw leading glyph, for anything unmapped
    raw: str = ""

    @property
    def key(self) -> str:
        """Stable identity for a play: the same key the BUY alert would make.

        Built from the ORIGINAL ticker, never the renamed one — the customer's
        journal recorded AGAE, and a key that changed to AIFA mid-life would
        orphan the position it is supposed to identify.
        """
        return f"{self.alert_date}:{self.symbol}" if self.symbol and self.alert_date else ""

    # The cloud calls the same thing source_id, so publishing needs no mapping.
    @property
    def source_id(self) -> str:
        return self.key

    @property
    def is_sellable(self) -> bool:
        return self.status in SELLABLE_STATUSES

    @property
    def renamed(self) -> bool:
        return self.sell_symbol != self.symbol

    def to_json(self) -> dict[str, str]:
        """Wire shape for /plays/ingest. `raw` is deliberately dropped — it is
        a debugging aid, and shipping the board's literal text to every
        subscriber would leak channel formatting for no benefit."""
        return {
            "source_id": self.source_id,
            "symbol": self.symbol,
            "sell_symbol": self.sell_symbol,
            "alert_date": self.alert_date,
            "status": self.status,
            "kind": self.kind,
        }

    @classmethod
    def from_json(cls, row: dict) -> "LifecycleRow | None":
        """Rebuild from what GET /plays/lifecycle returns. None if unusable.

        An unknown status is preserved rather than coerced: a client running an
        older build must not silently reclassify a status it does not recognise
        as something sellable.
        """
        symbol = str((row or {}).get("symbol") or "").upper().strip()
        alert_date = str(row.get("alert_date") or "").strip()[:10]
        if not symbol or not alert_date:
            return None
        return cls(
            symbol=symbol,
            sell_symbol=str(row.get("sell_symbol") or symbol).upper().strip(),
            alert_date=alert_date,
            status=str(row.get("status") or "unknown"),
            kind=str(row.get("kind") or "standard"),
        )


def parse_lifecycle_message(msg: dict, *, today: date | None = None) -> list[LifecycleRow]:
    """Every readable row of one TRACK-board message.

    Unparseable lines (the header, the code fence, blank lines) are skipped in
    silence — the board is written for humans and always carries some.
    """
    content = msg.get("content") or ""
    if not content.strip():
        content = "\n".join(
            (e.get("description") or "") for e in (msg.get("embeds") or []))

    rows: list[LifecycleRow] = []
    for raw_line in content.splitlines():
        line = _strip_marks(raw_line).strip()
        if not line:
            continue
        m = _ROW_RE.match(line)
        if not m:
            continue

        symbol = m.group("symbol").upper()
        day = _lifecycle_date(m.group("date"), today)
        if not day:
            continue

        tail = m.group("tail") or ""
        alias = _ALIAS_RE.search(tail)

        status = "unknown"
        if _CANCEL_RE.search(tail):
            status = "canceled"
        elif _LOW_ODDS_RE.search(tail):
            status = "low_odds"
        else:
            # Scan the whole tail: the status glyph trails the alias when a
            # ticker was renamed ('↔️ AIFA ✅').
            for glyph, name in _STATUS_GLYPHS.items():
                if glyph in tail:
                    status = name
                    break

        glyph = m.group("kind")
        rows.append(LifecycleRow(
            symbol=symbol,
            sell_symbol=(alias.group("symbol").upper() if alias else symbol),
            alert_date=day,
            status=status,
            kind=_KIND_GLYPHS.get(glyph, "standard"),
            kind_glyph=glyph,
            raw=line[:300],
        ))
    return rows


def parse_lifecycle_messages(messages: Iterable[dict],
                             *, today: date | None = None) -> list[LifecycleRow]:
    """Parse a channel pull, newest message winning.

    The board is ONE message edited in place, so a pull is normally a single
    row-set. When more than one is present the newest is authoritative, and
    earlier ones only fill in plays it has since dropped.
    """
    out: dict[str, LifecycleRow] = {}
    for msg in reversed(_oldest_first(messages)):   # newest first
        for row in parse_lifecycle_message(msg, today=today):
            if row.key and row.key not in out:
                out[row.key] = row
    return sorted(out.values(), key=lambda r: (r.alert_date, r.symbol))


# ---------------------------------------------------------------- batch driver

def parse_messages(
    buy_messages: Iterable[dict] = (),
    sell_messages: Iterable[dict] = (),
) -> FeedBatch:
    """Parse both channels into one batch, oldest-first."""
    batch = FeedBatch()
    for msg in _oldest_first(buy_messages):
        batch.buys.extend(parse_buy_message(msg))
    for msg in _oldest_first(sell_messages):
        sells, roundups = parse_sell_message(msg)
        batch.sells.extend(sells)
        batch.roundups.extend(roundups)
    return batch


def _oldest_first(messages: Iterable[dict]) -> list[dict]:
    """Discord returns newest-first; every consumer here wants the reverse."""
    msgs = list(messages or [])
    try:
        return sorted(msgs, key=lambda m: int(m.get("id") or 0))
    except (TypeError, ValueError):
        return msgs


# ------------------------------------------------------------- legacy bridging

_PICK_NOTES = {"standard": "Reg Alert", "otc": "OTC", "conditional": "conditional"}


def to_pick(buy: BuyAlert) -> dict[str, str]:
    """The three-key shape picks.json has always held, so the existing mirror
    queue and watchlist keep working untouched."""
    return {
        "symbol": buy.symbol,
        "note": _PICK_NOTES.get(buy.kind, "Reg Alert"),
        "date": buy.alert_date,
    }


def from_pick(pick: dict[str, str]) -> BuyAlert | None:
    """The inverse of `to_pick`: a stored three-key row back into an alert.

    Lossy by nature — a pick never carried the ratio or the entry price — but
    enough to publish a hand-entered play to the cloud feed. The source_id
    matches the one `playsfeed.import_picks_file` mints for the same row, so a
    pick that arrives by both routes is inserted once, not twice.

    Returns None for a row with no symbol; those are not plays.
    """
    symbol = str((pick or {}).get("symbol") or "").upper().strip()
    if not symbol:
        return None
    day = str(pick.get("date") or "").strip()[:10]
    return BuyAlert(
        source_id=f"picks:{symbol}:{day}",
        symbol=symbol,
        kind=_kind_from(str(pick.get("note") or ""), ""),
        alert_date=day,
    )


def to_picks(buys: Sequence[BuyAlert]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for b in buys:
        pick = to_pick(b)
        key = (pick["date"], pick["symbol"])
        if key not in seen:
            seen.add(key)
            out.append(pick)
    return out


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    import sys
    payload = json.load(sys.stdin)
    batch = parse_messages(payload.get("buy", []), payload.get("sell", []))
    print(json.dumps(batch.to_json(), indent=2))
