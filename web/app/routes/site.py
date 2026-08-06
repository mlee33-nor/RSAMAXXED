from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import PlainTextResponse

from .. import config, plans
from ..db import engine
from ..deps import current_user
from ..models import User
from ..templating import render

router = APIRouter()


@router.get("/")
def home(request: Request, user: User | None = Depends(current_user)):
    return render(request, "index.html", user=user)


@router.get("/how-it-works")
def how_it_works(request: Request, user: User | None = Depends(current_user)):
    return render(request, "how_it_works.html", user=user)


@router.get("/pricing")
def pricing(request: Request, user: User | None = Depends(current_user)):
    # Prices come from plans.py, which is also what gates the app. A price on
    # this page and an entitlement in the code can't drift apart if there is
    # only one of them.
    return render(request, "pricing.html", user=user,
                  plays=plans.PLANS["plays"], automation=plans.PLANS["automation"])


@router.get("/robots.txt", response_class=PlainTextResponse)
def robots(request: Request) -> str:
    """What a crawler may index.

    The marketing pages and the /plays gate are the front door and should be
    found. Everything below is either a form, an authenticated surface, or an
    API — indexing them wastes crawl budget and puts URLs in results that
    return a redirect or a 401 to whoever clicks them.

    The board itself needs no rule: it is behind the password, so a crawler
    reaches the gate and nothing else. This file is a courtesy to well-behaved
    bots and never a security control.
    """
    base = config.PUBLIC_BASE_URL or str(request.base_url).rstrip("/")
    return "\n".join((
        "User-agent: *",
        "Allow: /",
        "Disallow: /api/",
        "Disallow: /app/",
        "Disallow: /login",
        "Disallow: /signup",
        "Disallow: /healthz",
        "",
        f"Sitemap: {base}/sitemap.xml",
        "",
    ))


@router.get("/sitemap.xml", response_class=PlainTextResponse)
def sitemap(request: Request) -> Response:
    """The three public pages, so a launch does not wait on discovery."""
    base = config.PUBLIC_BASE_URL or str(request.base_url).rstrip("/")
    urls = "".join(
        f"<url><loc>{base}{path}</loc><changefreq>{freq}</changefreq></url>"
        for path, freq in (("/", "weekly"), ("/how-it-works", "monthly"),
                           ("/pricing", "monthly"), ("/plays", "daily"))
    )
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{urls}</urlset>",
        media_type="application/xml",
    )


@router.get("/healthz")
def healthz():
    """Reports the storage backend by name only — never the connection string.

    `db: "sqlite"` in production means the container's local disk, which Railway
    replaces on every deploy: accounts and synced trades would vanish silently.
    Worth being able to check from outside.
    """
    return {
        "ok": True,
        "db": engine.dialect.name,
        "env": "production" if config.IS_PROD else "development",
        "durable": engine.dialect.name != "sqlite",
    }
