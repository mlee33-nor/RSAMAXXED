"""The NYSE trading calendar, small enough to read in one sitting.

Mirror trading used to treat every weekday as a session and every day as a
day: an alert posted on Friday was "3 days old" by Monday and aged out of a
2-day limit before the market had opened on it even once, and a check on Good
Friday or after a 13:00 half-day close would happily send orders into a shut
market. Everything here answers in New York time and in SESSIONS.

Full closures and 13:00 ET early closes are computed by the exchange's own
rules for any year (`rule_holidays`, `rule_early_closes`). The hand-checked
tables below are the override for the years they list: a one-off closure (a
national day of mourning) goes there, and the tests hold the rules to them.
`covered()` still says whether a year is in the hand-checked table. The table
used to be the only source, and on 2028-01-01 every holiday would have read as
a session.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Optional, Tuple

#: Days the exchange is shut all day.
NYSE_HOLIDAYS = frozenset({
    # 2026
    date(2026, 1, 1),    # New Year's Day
    date(2026, 1, 19),   # Martin Luther King Jr. Day
    date(2026, 2, 16),   # Washington's Birthday
    date(2026, 4, 3),    # Good Friday
    date(2026, 5, 25),   # Memorial Day
    date(2026, 6, 19),   # Juneteenth
    date(2026, 7, 3),    # Independence Day (observed; the 4th is a Saturday)
    date(2026, 9, 7),    # Labor Day
    date(2026, 11, 26),  # Thanksgiving
    date(2026, 12, 25),  # Christmas
    # 2027
    date(2027, 1, 1),    # New Year's Day
    date(2027, 1, 18),   # Martin Luther King Jr. Day
    date(2027, 2, 15),   # Washington's Birthday
    date(2027, 3, 26),   # Good Friday
    date(2027, 5, 31),   # Memorial Day
    date(2027, 6, 18),   # Juneteenth (observed; the 19th is a Saturday)
    date(2027, 7, 5),    # Independence Day (observed; the 4th is a Sunday)
    date(2027, 9, 6),    # Labor Day
    date(2027, 11, 25),  # Thanksgiving
    date(2027, 12, 24),  # Christmas (observed; the 25th is a Saturday)
})

#: Sessions that end at 13:00 ET instead of 16:00.
NYSE_EARLY_CLOSES = frozenset({
    date(2026, 11, 27),  # day after Thanksgiving
    date(2026, 12, 24),  # Christmas Eve
    date(2027, 11, 26),  # day after Thanksgiving
})

COVERED_YEARS = frozenset({2026, 2027})


def _easter(year: int) -> date:
    """Western (Gregorian) Easter Sunday -- the anonymous computus."""
    a = year % 19
    b, c = divmod(year, 100)
    d, e = divmod(b, 4)
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month, day = divmod(h + l - 7 * m + 114, 31)
    return date(year, month, day + 1)


def _nth_weekday(year: int, month: int, weekday: int, n: int) -> date:
    """The n-th `weekday` (Mon=0) of the month; n=-1 is the last one."""
    if n > 0:
        d = date(year, month, 1)
        d += timedelta(days=(weekday - d.weekday()) % 7)
        return d + timedelta(weeks=n - 1)
    nxt = date(year + (month == 12), month % 12 + 1, 1)
    d = nxt - timedelta(days=1)
    return d - timedelta(days=(d.weekday() - weekday) % 7)


def _observed(d: date) -> date:
    """A fixed-date holiday on a weekend: Saturday -> Friday, Sunday -> Monday."""
    if d.weekday() == 5:
        return d - timedelta(days=1)
    if d.weekday() == 6:
        return d + timedelta(days=1)
    return d


def rule_holidays(year: int) -> frozenset:
    """NYSE full closures for `year`, by rule.

    New Year's Day on a Saturday is NOT moved back to Friday 31 December (the
    exchange's own rule: it would close the year's last session); on a Sunday
    it is observed Monday. Juneteenth is a holiday from 2022."""
    out = set()
    ny = date(year, 1, 1)
    if ny.weekday() == 6:
        out.add(ny + timedelta(days=1))
    elif ny.weekday() < 5:
        out.add(ny)
    out.add(_nth_weekday(year, 1, 0, 3))        # Martin Luther King Jr. Day
    out.add(_nth_weekday(year, 2, 0, 3))        # Washington's Birthday
    out.add(_easter(year) - timedelta(days=2))  # Good Friday
    out.add(_nth_weekday(year, 5, 0, -1))       # Memorial Day
    if year >= 2022:
        out.add(_observed(date(year, 6, 19)))   # Juneteenth
    out.add(_observed(date(year, 7, 4)))        # Independence Day
    out.add(_nth_weekday(year, 9, 0, 1))        # Labor Day
    out.add(_nth_weekday(year, 11, 3, 4))       # Thanksgiving
    out.add(_observed(date(year, 12, 25)))      # Christmas
    return frozenset(out)


def rule_early_closes(year: int) -> frozenset:
    """13:00 ET closes for `year`, by rule: 3 July when both it and the 4th
    are weekdays, the day after Thanksgiving, and Christmas Eve when it is a
    weekday session (not itself the observed Christmas)."""
    hol = rule_holidays(year)
    out = set()
    j3, j4 = date(year, 7, 3), date(year, 7, 4)
    if j3.weekday() < 5 and j4.weekday() < 5 and j3 not in hol:
        out.add(j3)
    out.add(_nth_weekday(year, 11, 3, 4) + timedelta(days=1))
    eve = date(year, 12, 24)
    if eve.weekday() < 5 and eve not in hol:
        out.add(eve)
    return frozenset(out)


_RULE_CACHE: dict = {}


def _year_tables(year: int) -> Tuple[frozenset, frozenset]:
    """(holidays, early closes) for `year`: the hand-checked table when it
    covers the year, the rules otherwise."""
    hit = _RULE_CACHE.get(year)
    if hit is None:
        if year in COVERED_YEARS:
            hit = (frozenset(d for d in NYSE_HOLIDAYS if d.year == year),
                   frozenset(d for d in NYSE_EARLY_CLOSES if d.year == year))
        else:
            hit = (rule_holidays(year), rule_early_closes(year))
        _RULE_CACHE[year] = hit
    return hit


def is_holiday(d: date) -> bool:
    return d in _year_tables(d.year)[0]


def is_early_close(d: date) -> bool:
    return d in _year_tables(d.year)[1]

OPEN = time(9, 30)
CLOSE = time(16, 0)
EARLY_CLOSE = time(13, 0)

NY_TZ_NAME = "America/New_York"


def covered(d: date) -> bool:
    """True when this year is in the hand-checked table. Every other year is
    still answered, from the rules."""
    return d.year in COVERED_YEARS


def is_trading_day(d: date) -> bool:
    """A weekday the exchange is open, at least for part of the day."""
    return d.weekday() < 5 and not is_holiday(d)


def close_time(d: date) -> Optional[time]:
    """When the regular session ends on `d`, or None if there is no session."""
    if not is_trading_day(d):
        return None
    return EARLY_CLOSE if is_early_close(d) else CLOSE


def session(d: date) -> Optional[Tuple[int, int]]:
    """(open, close) as minutes after midnight ET, or None on a closed day."""
    end = close_time(d)
    if end is None:
        return None
    return (OPEN.hour * 60 + OPEN.minute, end.hour * 60 + end.minute)


def is_regular_hours(now_et: datetime) -> bool:
    """True inside the regular session. `now_et` must already be New York time."""
    span = session(now_et.date())
    if span is None:
        return False
    mins = now_et.hour * 60 + now_et.minute
    return span[0] <= mins < span[1]


def now_et() -> Optional[datetime]:
    """Current New York time, or None when the tz database is unavailable.

    None rather than a local-time fallback: a caller deciding whether to send
    an order must not mistake 09:30 in Los Angeles for the open.
    """
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo(NY_TZ_NAME))
    except Exception:
        return None


def trading_days_since(start: date, today: date) -> int:
    """Sessions that have opened since `start`, not counting today.

    Counts trading days d with start <= d < today. An alert on Friday is 0 on
    Friday and 1 on Monday — however long the weekend or holiday in between.
    An alert dated on a weekend is 0 on the Monday after: that Monday is its
    first chance to be bought. A date in the future is 0.
    """
    if today <= start:
        return 0
    n = 0
    d = start
    # Bounded: a pick from years ago needs only to be "old", not counted
    # exactly, and this runs on the Tk thread.
    while d < today and n < 400:
        if is_trading_day(d):
            n += 1
        d += timedelta(days=1)
    return n


def next_trading_day(d: date) -> date:
    """The first trading day strictly after `d`."""
    d += timedelta(days=1)
    for _ in range(14):
        if is_trading_day(d):
            return d
        d += timedelta(days=1)
    return d
