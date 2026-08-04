from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import security
from .db import get_db
from .models import Device, User, utcnow


def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    return db.get(User, uid)


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        # 303 so the browser re-issues as GET; handled by the exception handler.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")
    return user


def require_device(request: Request, db: Session = Depends(get_db)) -> Device:
    """Resolve `Authorization: Bearer <device_token>` to an active device.

    Every sync write is scoped to `device.user_id`, which is the only reason
    one customer's data can never reach another's dashboard.
    """
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="missing bearer token")

    device = db.scalar(select(Device).where(Device.token_hash == security.hash_token(token)))
    if device is None or not device.is_active:
        # Same message either way: don't reveal whether a token ever existed.
        raise HTTPException(status_code=401, detail="invalid or revoked device token")

    device.last_seen_at = utcnow()
    db.commit()
    return device


def csrf_guard(request: Request, csrf_token: str = "") -> None:
    if not security.csrf_ok(request.session.get("csrf"), csrf_token):
        raise HTTPException(status_code=400, detail="bad csrf token")
