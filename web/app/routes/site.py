from __future__ import annotations

from fastapi import APIRouter, Depends, Request

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
