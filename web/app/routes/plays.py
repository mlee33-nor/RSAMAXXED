"""The public Plays board at `/plays`, behind one shared password.

Why this is not `/app/plays` any more: the plays ARE the product's front door.
Making someone create an account, pick a plan and confirm an email before they
can see a single alert put four screens between a stranger and the one thing
worth showing them. So the board moved out of the customer dashboard and onto
the public site, and the only thing in front of it is a password anyone we hand
it to can type.

The trade that buys:

    an ACCOUNT  identifies who is reading, and can be revoked one at a time.
    a PASSWORD  identifies nobody, and is revoked for everyone at once by
                changing it. It also travels — whoever you give it to can give
                it to someone else, and you will not know.

That is a real cost, accepted deliberately for a board whose contents are
already published unauthenticated at `/api/v1/public/plays` for the desktop app
to read. This gate keeps the page from being casually browsable and indexed; it
is not, and cannot be, a claim that the data is secret.

The password lives in the environment (`PLAYS_PASSWORD`), never in this file —
the repository is public.
"""
from __future__ import annotations

import hmac
import time

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .. import config, playsfeed, plans, security
from ..db import get_db
from ..deps import current_user
from ..models import User
from ..templating import render

router = APIRouter()

SESSION_KEY = "plays_unlocked"

# Typing the password on every visit is the kind of friction that makes a
# subscriber stop opening the page, so the answer is remembered for a year in
# its own cookie rather than riding the session cookie (14 days, and shared with
# real logins — nobody should stay signed in to an account for a year because
# the plays board wanted to be convenient).
#
# The value is a hash of the password PEPPERED with SECRET_KEY. Two properties
# come free from that: it can't be precomputed by someone who guesses the
# password, and changing PLAYS_PASSWORD invalidates every remembered browser at
# once — which is exactly what changing a shared password has to mean.
PLAYS_COOKIE = "rsamaxxed_plays"
REMEMBER_SECONDS = 365 * 24 * 3600

# Wrong-guess throttle, in process memory rather than a table.
#
# Deliberate: it must survive nothing. A restart clearing it costs an attacker
# nothing they couldn't get by waiting, and one shared password on one small
# service does not justify a migration and a row per guess. If this ever runs on
# more than one replica, each replica throttles its own share — still fine,
# because the point is to make a script slow, not to make it impossible.
_attempts: dict[str, list[float]] = {}


def _client(request: Request) -> str:
    """Best available caller identity. Behind Railway's proxy the socket peer is
    the proxy, so trust the forwarded address it sets — uvicorn runs with
    --proxy-headers (see Procfile), and a spoofed value only throttles a
    fictional address, never lets one through."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def _throttled(key: str) -> bool:
    now = time.monotonic()
    window = config.PLAYS_ATTEMPT_WINDOW_SECONDS
    recent = [t for t in _attempts.get(key, ()) if now - t < window]
    _attempts[key] = recent
    return len(recent) >= config.PLAYS_MAX_ATTEMPTS


def _record_failure(key: str) -> None:
    _attempts.setdefault(key, []).append(time.monotonic())


def remember_token() -> str:
    """The value of the remember-me cookie for the CURRENT password."""
    if not config.PLAYS_PASSWORD:
        return ""
    return security.hash_token(f"{config.SECRET_KEY}:{config.PLAYS_PASSWORD}")


def remembered(request: Request) -> bool:
    """This browser typed the password before, and the password hasn't changed."""
    expected = remember_token()
    if not expected:
        return False
    return hmac.compare_digest(request.cookies.get(PLAYS_COOKIE, ""), expected)


def _remember(response, request: Request) -> None:
    """Keep this browser unlocked for a year."""
    token = remember_token()
    if not token:
        return
    response.set_cookie(
        PLAYS_COOKIE, token,
        max_age=REMEMBER_SECONDS,
        httponly=True,              # no script needs it; XSS can't lift it
        samesite="lax",
        secure=config.IS_PROD,      # would break plain-HTTP local dev
        path="/",
    )
    request.session[SESSION_KEY] = True


def unlocked(request: Request, user: User | None) -> bool:
    """Who gets to see the board.

    A signed-in customer whose plan includes the feed never meets the gate —
    they already identified themselves, and asking them for a second, weaker
    secret would be pure friction.
    """
    if plans.can(user, plans.FEED):
        return True
    return bool(request.session.get(SESSION_KEY)) or remembered(request)


def _board_page(request: Request, user: User | None, db: Session):
    # Keep the feed current with the desktop app's picks.json (idempotent — only
    # brand-new alerts insert). No-op when PICKS_FILE is unset or missing, which
    # is the normal state on the deploy: there the feed arrives by ingest.
    if config.PICKS_FILE:
        playsfeed.import_picks_file(db, config.PICKS_FILE)

    board = playsfeed.load_board(db)
    return render(
        request, "plays.html",
        user=user,
        board=board,
        # Rendered against one account per broker. The browser rewrites these
        # from the reader's own profile — see the note in plays.html.
        totals=board.totals(),
        # The vocabulary for TRACK statuses lives with the feed, not in the
        # template — the page renders rows the board didn't get to wrap.
        status_labels=playsfeed.STATUS_LABELS,
        fractional_brokers=playsfeed.FRACTIONAL_BROKERS,
        plan=plans.resolve(user.plan) if user else None,
        can_automate=plans.can(user, plans.TERMINAL),
    )


@router.get("/plays")
def plays_page(
    request: Request,
    user: User | None = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not unlocked(request, user):
        return render(request, "plays_gate.html", user=user,
                      configured=bool(config.PLAYS_PASSWORD))
    return _board_page(request, user, db)


@router.post("/plays")
def unlock(
    request: Request,
    password: str = Form(""),
    csrf_token: str = Form(""),
    user: User | None = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Check the shared password and, if it matches, remember it in the session.

    Renders the board directly on success instead of redirecting, so the person
    who just typed it lands on what they asked for in one round trip.
    """
    def gate(error: str):
        return render(request, "plays_gate.html", user=user, error=error,
                      configured=bool(config.PLAYS_PASSWORD))

    if not security.csrf_ok(request.session.get("csrf"), csrf_token):
        return gate("That form went stale. Try again.")

    if not config.PLAYS_PASSWORD:
        # Fail closed, and say which knob is missing — this message is only ever
        # seen by whoever is deploying it.
        return gate("The board is not configured yet (PLAYS_PASSWORD is unset).")

    key = _client(request)
    if _throttled(key):
        return gate("Too many attempts. Wait 15 minutes.")

    if not hmac.compare_digest(password.strip(), config.PLAYS_PASSWORD):
        _record_failure(key)
        return gate("Wrong password.")

    response = _board_page(request, user, db)
    _remember(response, request)
    return response


@router.post("/plays/lock")
def lock(request: Request, csrf_token: str = Form("")):
    """Forget the password on this browser. For a shared or borrowed machine."""
    response = RedirectResponse("/plays", status_code=303)
    if security.csrf_ok(request.session.get("csrf"), csrf_token):
        request.session.pop(SESSION_KEY, None)
        response.delete_cookie(PLAYS_COOKIE, path="/")
    return response
