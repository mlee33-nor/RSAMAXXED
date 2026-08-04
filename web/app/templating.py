from __future__ import annotations

import os

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import security

_HERE = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(_HERE, "templates"))


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


templates.env.filters["money"] = money
templates.env.filters["qty"] = qty
templates.env.filters["price"] = price


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
    return templates.TemplateResponse(request, name, ctx)
