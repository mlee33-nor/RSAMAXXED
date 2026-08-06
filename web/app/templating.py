from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import security

_HERE = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(_HERE, "templates"))


def _asset_version() -> str:
    """A cache-busting stamp for the stylesheet and script.

    Without this, a browser that cached site.css keeps using it after a deploy —
    and a page whose CSS is a version behind is not "slightly stale", it is
    broken: tabs stop hiding panes, so every section renders at once as one long
    list, and a popover becomes a slab down the middle of the page. That is a
    real bug report we already got, and no amount of server-side correctness
    fixes it. Derived from the files' own size+mtime, so it changes exactly when
    they do and never needs remembering.
    """
    stamp = 0
    for rel in ("static/css/site.css", "static/js/site.js"):
        try:
            st = os.stat(os.path.join(_HERE, rel))
            stamp ^= int(st.st_mtime) ^ (st.st_size << 8)
        except OSError:
            pass
    return format(stamp & 0xFFFFFFF, "x")


ASSET_V = _asset_version()


def money(v: float | None, sign: bool = False) -> str:
    if v is None:
        return "—"
    return f"${v:+,.2f}" if sign else f"${v:,.2f}"


def qty(v: float) -> str:
    return f"{v:g}"


def price(v: float | None) -> str:
    """A share price, not a P/L figure.

    These names trade below a dollar — that is the entire premise — so rounding
    $0.1205 to $0.12 throws away the digits that decide whether the play is
    worth taking. Sub-$1 keeps four decimals; above that, two is plenty.
    """
    if v is None:
        return "—"
    if abs(v) < 1:
        return f"${v:.4f}".rstrip("0").rstrip(".")
    return f"${v:,.2f}"


def ago(v: datetime | None) -> str:
    """How long ago, in words. The Plays board's honesty check.

    A timestamp tells a reader nothing about whether the feed is still alive;
    "4 hours ago" tells them immediately, and "3 days ago" tells them something
    has broken. Days are deliberately not smoothed into weeks — on a board where
    the publisher runs hourly, a number of days IS the alarm.
    """
    if v is None:
        return "never"
    now = datetime.now(timezone.utc)
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    secs = (now - v).total_seconds()
    if secs < 0:
        return "just now"          # clock skew; don't print "in -3 minutes"
    if secs < 90:
        return "just now"
    mins = secs / 60
    if mins < 60:
        return f"{int(mins)} minutes ago"
    hours = mins / 60
    if hours < 24:
        n = int(hours)
        return "1 hour ago" if n == 1 else f"{n} hours ago"
    days = int(hours / 24)
    return "1 day ago" if days == 1 else f"{days} days ago"


def pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.0f}%"


templates.env.filters["money"] = money
templates.env.filters["qty"] = qty
templates.env.filters["price"] = price
templates.env.filters["ago"] = ago
templates.env.filters["pct"] = pct


def csrf_for(request: Request) -> str:
    """One token per session, minted lazily."""
    token = request.session.get("csrf")
    if not token:
        token = security.new_csrf()
        request.session["csrf"] = token
    return token


def render(request: Request, name: str, **ctx):
    ctx.setdefault("user", None)
    ctx["csrf_token"] = csrf_for(request)
    ctx["asset_v"] = ASSET_V
    return templates.TemplateResponse(request, name, ctx)
