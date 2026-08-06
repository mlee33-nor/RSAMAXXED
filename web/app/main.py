from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import config, playsfeed
from .db import SessionLocal, init_db
from .routes import api, auth, dashboard, plays, site

_HERE = os.path.dirname(os.path.abspath(__file__))


def _reload_picks_once() -> int:
    """Read PICKS_FILE into the play feed once. Own DB session, swallows errors —
    a bad picks.json must never crash startup or the background loop."""
    if not config.PICKS_FILE:
        return 0
    db = SessionLocal()
    try:
        return playsfeed.import_picks_file(db, config.PICKS_FILE)
    except Exception:
        return 0
    finally:
        db.close()


async def _picks_reload_loop() -> None:
    """Keep the free feed live: re-read picks.json on a fixed interval so the
    desktop app's daily Discord pull shows up without anyone loading the page.
    The import is idempotent, so each tick only inserts genuinely-new alerts."""
    interval = config.PICKS_RELOAD_SECONDS
    while True:
        await asyncio.sleep(interval)
        await asyncio.to_thread(_reload_picks_once)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Fine for a single-service deploy. If this ever runs on more than one
    # Railway replica, move to Alembic migrations instead.
    init_db()
    # Seed the free play feed from the operator's local picks.json now, then keep
    # it current in the background. A no-op on a deploy where the file doesn't
    # exist (the feed arrives via the ingest API there); the /app/plays route
    # also re-reads it so an on-page visit is always live too.
    task: asyncio.Task | None = None
    if config.PICKS_FILE:
        _reload_picks_once()
        if config.PICKS_RELOAD_SECONDS > 0:
            task = asyncio.create_task(_picks_reload_loop())
    try:
        yield
    finally:
        if task is not None:
            task.cancel()


app = FastAPI(title="RSAMAXXED Cloud", docs_url=None, redoc_url=None, lifespan=lifespan)

app.add_middleware(
    SessionMiddleware,
    secret_key=config.SECRET_KEY,
    # Renaming this invalidates every existing session cookie, so everyone
    # signed in at deploy time is logged out once. Deliberate: the old brand
    # should not survive in something sent on every request.
    session_cookie="rsamaxxed_session",
    https_only=config.IS_PROD,   # Secure flag; would break plain-HTTP local dev
    same_site="lax",             # blocks cross-site POSTs, keeps normal links working
    max_age=14 * 24 * 3600,
)

app.mount("/static", StaticFiles(directory=os.path.join(_HERE, "static")), name="static")

app.include_router(site.router)
app.include_router(plays.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(api.router)


@app.exception_handler(HTTPException)
async def _auth_redirect(request: Request, exc: HTTPException):
    """Browsers hitting a logged-out page get sent to /login; API clients still
    get a clean 401 JSON body."""
    if exc.status_code == 401 and not request.url.path.startswith("/api/"):
        return RedirectResponse("/login", status_code=303)
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    # Everything is inlined or same-origin; no external fetches anywhere.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    )
    if config.IS_PROD:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response
