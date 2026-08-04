"""Runtime configuration, read from the environment.

Railway injects DATABASE_URL and PORT for you. Everything else you set as a
service variable in the Railway dashboard.
"""
from __future__ import annotations

import os
import secrets


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


ENV = os.environ.get("ENV", "development").strip().lower()
IS_PROD = ENV in {"production", "prod"}

# In prod a missing SECRET_KEY is fatal: an ephemeral key would silently
# invalidate every session on each redeploy and make cookies forgeable across
# restarts. In dev we generate a throwaway one so `uvicorn` just works.
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    if IS_PROD:
        raise RuntimeError(
            "SECRET_KEY is required when ENV=production. Generate one with:\n"
            '  python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
    SECRET_KEY = secrets.token_urlsafe(48)

# Optional. When unset we derive the origin from the incoming request, which is
# right far more often than a hand-typed constant — and a wrong constant here
# silently tells every customer to open http://127.0.0.1:8000 to pair.
# Set it explicitly once you have a custom domain you want shown.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")

OPEN_SIGNUP = _bool("OPEN_SIGNUP", default=True)
INVITE_CODE = os.environ.get("INVITE_CODE", "").strip()

# Pairing
PAIRING_TTL_SECONDS = 10 * 60          # code is dead after 10 minutes
PAIRING_MAX_ATTEMPTS = 5               # wrong-code guesses per user per window
PAIRING_ATTEMPT_WINDOW_SECONDS = 15 * 60

# Sync limits — keeps a buggy or hostile client from filling the database.
MAX_TRADES_PER_REQUEST = 500
MAX_HOLDING_ROWS_PER_SNAPSHOT = 2000
SNAPSHOTS_RETAINED_PER_USER = 30

# The shared secret that lets ONE machine — the operator's, the only one with
# Discord access — publish the play feed. Customers never hold this and never
# need it: they read the feed, they don't write it.
#
# Unset means the ingest endpoint refuses everything. That is the correct
# failure: an open ingest would let anyone publish alerts to every subscriber.
FEED_INGEST_KEY = os.environ.get("FEED_INGEST_KEY", "").strip()

MAX_PLAYS_PER_INGEST = 500

# The desktop app persists its current RSA picks to picks.json ({symbol, note,
# date}). On a single-machine setup the web app can read that same file and load
# those picks straight into the play feed — no ingest key, no round trip — so the
# free Plays page is populated the moment the software has picks. Defaults to the
# repo-root picks.json beside this checkout; unset it (PICKS_FILE="") on a deploy
# where the feed arrives through POST /api/v1/plays/ingest instead.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_WEB_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../web
# Local dev has the desktop app's live picks.json at the repo root and uses it
# directly. On Railway the deploy is only the `web/` dir, so that path doesn't
# exist there — fall back to the picks.json BUNDLED inside web/ (kept fresh by
# publish_picks.py, which the daily job commits + pushes). Explicit PICKS_FILE
# overrides both.
_default_picks = os.path.join(_REPO_ROOT, "picks.json")
if not os.path.exists(_default_picks):
    _default_picks = os.path.join(_WEB_ROOT, "picks.json")
PICKS_FILE = os.environ.get("PICKS_FILE", _default_picks).strip()

# How often the web app re-reads PICKS_FILE in the background, so the free feed
# tracks the desktop app's daily Discord pull even when nobody opens the page.
# Hourly by default (the import is idempotent and cheap, so a frequent poll costs
# almost nothing and keeps it near-live); set to 0 to disable the loop.
try:
    PICKS_RELOAD_SECONDS = int(os.environ.get("PICKS_RELOAD_SECONDS", "3600"))
except ValueError:
    PICKS_RELOAD_SECONDS = 3600


def database_url() -> str:
    """Normalize whatever Railway/Heroku hands us into a SQLAlchemy 2.x URL.

    Railway sets `postgresql://`; SQLAlchemy needs an explicit driver or it
    reaches for psycopg2, which we don't install.
    """
    raw = os.environ.get("DATABASE_URL", "").strip()
    if not raw:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return "sqlite:///" + os.path.join(here, "local.db")
    if raw.startswith("postgres://"):
        raw = "postgresql://" + raw[len("postgres://"):]
    if raw.startswith("postgresql://"):
        raw = "postgresql+psycopg://" + raw[len("postgresql://"):]
    return raw
