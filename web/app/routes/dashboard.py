from __future__ import annotations

import csv
import io
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import analytics, charts, config, security
from ..db import get_db
from ..deps import require_user
from ..models import (
    Device, HoldingSnapshot, PairingAttempt, PairingCode, Trade, User, utcnow,
)
from ..templating import render

router = APIRouter(prefix="/app")


def _load_trades(db: Session, user: User) -> list[analytics.TradeLike]:
    rows = db.scalars(
        select(Trade).where(Trade.user_id == user.id).order_by(Trade.timestamp)
    ).all()
    return analytics.to_tradelike(rows)


@router.get("")
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    trades = _load_trades(db, user)
    s = analytics.summarize(trades)
    alloc = analytics.allocation(s)

    snap = db.scalar(
        select(HoldingSnapshot)
        .where(HoldingSnapshot.user_id == user.id)
        .order_by(HoldingSnapshot.captured_at.desc())
        .limit(1)
    )
    devices = db.scalars(select(Device).where(Device.user_id == user.id)).all()
    linked = [d for d in devices if d.is_active]

    return render(
        request, "dashboard.html",
        user=user, s=s,
        has_data=bool(trades),
        linked_devices=linked,
        snapshot=snap,
        eq_svg=charts.equity_line(analytics.equity_curve(trades)),
        month_svg=charts.month_bars(analytics.realized_by_month(trades)),
        broker_svg=charts.broker_bars(analytics.realized_by_broker(trades)),
        donut_svg=charts.allocation_donut(alloc),
        legend=charts.donut_legend(alloc),
        top_symbols=analytics.realized_by_symbol(trades, limit=8),
        drawdown=analytics.max_drawdown(trades),
    )


@router.get("/plays")
def plays_page():
    """Moved to /plays, which anyone with the password can open.

    Kept as a permanent redirect rather than deleted: this URL is in the wild —
    old bookmarks, the signup redirect, and every link a customer was ever sent.
    A signed-in reader passes straight through the gate (see routes/plays.py).
    """
    return RedirectResponse("/plays", status_code=301)


@router.get("/trades")
def trades_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(Trade).where(Trade.user_id == user.id).order_by(Trade.timestamp.desc()).limit(500)
    ).all()
    return render(request, "trades.html", user=user, trades=rows)


@router.get("/trades.csv")
def trades_csv(user: User = Depends(require_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(Trade).where(Trade.user_id == user.id).order_by(Trade.timestamp)
    ).all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "broker", "account_id", "side", "symbol", "qty", "fill_price"])
    for t in rows:
        w.writerow([t.timestamp.isoformat(), t.broker, t.account_id, t.side,
                    t.symbol, t.qty, "" if t.fill_price is None else t.fill_price])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="rsamaxxed-trades.csv"'},
    )


@router.get("/holdings")
def holdings_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    snap = db.scalar(
        select(HoldingSnapshot)
        .where(HoldingSnapshot.user_id == user.id)
        .order_by(HoldingSnapshot.captured_at.desc())
        .limit(1)
    )
    by_account: dict[tuple[str, str], list] = {}
    if snap:
        for r in sorted(snap.rows, key=lambda r: (r.broker, r.account_id, r.symbol)):
            by_account.setdefault((r.broker, r.account_id), []).append(r)
    return render(request, "holdings.html", user=user, snapshot=snap, by_account=by_account)


# ------------------------------------------------------------------ devices

@router.get("/devices")
def devices_page(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    devices = db.scalars(
        select(Device).where(Device.user_id == user.id).order_by(Device.created_at.desc())
    ).all()
    return render(
        request, "devices.html", user=user, devices=devices,
        welcome=request.query_params.get("welcome") == "1",
        flash=request.session.pop("flash", None),
        flash_kind=request.session.pop("flash_kind", "ok"),
    )


def _flash(request: Request, msg: str, kind: str = "ok") -> RedirectResponse:
    request.session["flash"] = msg
    request.session["flash_kind"] = kind
    return RedirectResponse("/app/devices", status_code=303)


@router.post("/devices/claim")
def claim_device(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Bind a pending pairing code to THIS logged-in account, and mint the
    device token the desktop app will collect on its next poll."""
    if not security.csrf_ok(request.session.get("csrf"), csrf_token):
        return _flash(request, "Session expired. Try again.", "err")

    # Throttle guessing. 729M codes and a 10-minute window make this mostly
    # theatre, but the cost of getting it wrong is someone else's device.
    window_start = utcnow() - timedelta(seconds=config.PAIRING_ATTEMPT_WINDOW_SECONDS)
    recent = db.scalars(
        select(PairingAttempt.id).where(
            PairingAttempt.user_id == user.id, PairingAttempt.created_at >= window_start
        )
    ).all()
    if len(recent) >= config.PAIRING_MAX_ATTEMPTS:
        return _flash(request, "Too many failed attempts. Wait 15 minutes.", "err")

    normalized = security.normalize_code(code)
    row = db.scalar(select(PairingCode).where(PairingCode.code_hash == security.hash_code(normalized)))

    if row is None or row.expires_at <= utcnow():
        db.add(PairingAttempt(user_id=user.id))
        db.commit()
        return _flash(request, "That code is wrong or has expired. Generate a new one.", "err")

    if row.claimed_at is not None:
        return _flash(request, "That code was already used.", "err")

    token = security.new_token()
    device = Device(
        user_id=user.id,
        name=row.device_name or "Desktop",
        machine_id=row.machine_id,
        token_hash=security.hash_token(token),
    )
    db.add(device)
    db.flush()  # need device.id before we reference it

    row.claimed_by_user_id = user.id
    row.claimed_at = utcnow()
    row.device_id = device.id
    row.device_token_once = token
    db.commit()

    return _flash(request, f"Linked “{device.name}”. It should start syncing within a few seconds.")


@router.post("/devices/{device_id}/revoke")
def revoke_device(
    request: Request,
    device_id: int,
    csrf_token: str = Form(""),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    if not security.csrf_ok(request.session.get("csrf"), csrf_token):
        return _flash(request, "Session expired. Try again.", "err")

    # Scope by user_id: an attacker guessing device ids gets nothing.
    device = db.scalar(select(Device).where(Device.id == device_id, Device.user_id == user.id))
    if device is None:
        return _flash(request, "Device not found.", "err")
    if device.is_active:
        device.revoked_at = utcnow()
        db.commit()
    return _flash(request, f"Revoked “{device.name}”. Its token no longer works.")
