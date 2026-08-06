"""Machine-facing API consumed by the desktop app (cloud_sync.py).

Pairing, in order:
  1. device  -> POST /api/v1/devices/pair/start  {machine_id, device_name}
                <- {code, poll_token, expires_at}      (server invents the code)
  2. human   -> types `code` on the website while logged in
  3. device  -> POST /api/v1/devices/pair/poll   {poll_token}
                <- {status: "claimed", device_token}   (once, then cleared)
  4. device  -> Authorization: Bearer <device_token> on every sync call

Step 1 is why a customer never needs a custom build: the EXE ships with no
secret, only the public base URL. Identity is established by whoever types the
code into a logged-in browser session.
"""
from __future__ import annotations

import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import config, playsfeed, plans, security
from ..db import get_db
from ..deps import current_user, require_device
from ..models import (
    Device, HoldingRow, HoldingSnapshot, PairingCode, Play, PlayExit,
    PlayLifecycle, PlayRoundUp, Trade, User, utcnow,
)

router = APIRouter(prefix="/api/v1")

MAX_PAIRING_TRIES = 20  # per start-request, so a poll loop can't be used to fish


def _base_url(request: Request) -> str:
    """Where we tell the customer to type their pairing code.

    Prefer the configured origin. Otherwise derive it from the request, which
    behind Railway's proxy requires uvicorn's --proxy-headers so that
    X-Forwarded-Proto is honoured and we don't hand out an http:// URL.
    """
    if config.PUBLIC_BASE_URL:
        return config.PUBLIC_BASE_URL
    return str(request.base_url).rstrip("/")


# ------------------------------------------------------------------ schemas

class PairStartIn(BaseModel):
    machine_id: str = Field(default="", max_length=128)
    device_name: str = Field(default="Desktop", max_length=120)


class PairPollIn(BaseModel):
    poll_token: str = Field(min_length=8, max_length=128)


class TradeIn(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    timestamp: datetime
    broker: str = Field(max_length=40)
    account_id: str = Field(default="", max_length=160)
    side: str
    symbol: str = Field(max_length=24)
    qty: float
    fill_price: float | None = None

    @field_validator("side")
    @classmethod
    def _side(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"buy", "sell"}:
            raise ValueError("side must be 'buy' or 'sell'")
        return v

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        # trades.json is written with an explicit UTC offset, but be forgiving.
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)


class TradesIn(BaseModel):
    trades: list[TradeIn]


class HoldingIn(BaseModel):
    broker: str = Field(max_length=40)
    account_id: str = Field(default="", max_length=160)
    symbol: str = Field(max_length=24)
    qty: float = 0.0
    value: float | None = None


class HoldingsIn(BaseModel):
    captured_at: datetime | None = None
    holdings: list[HoldingIn]


# ------------------------------------------------------------------ pairing

@router.post("/devices/pair/start")
def pair_start(request: Request, body: PairStartIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    # Opportunistically sweep expired rows so the table can't grow without bound.
    db.execute(delete(PairingCode).where(PairingCode.expires_at < utcnow() - timedelta(hours=1)))

    for _ in range(MAX_PAIRING_TRIES):
        code = security.new_pairing_code()
        code_hash = security.hash_code(code)
        # A live, unclaimed code must stay unique or two devices would collide.
        clash = db.scalar(
            select(PairingCode.id).where(
                PairingCode.code_hash == code_hash, PairingCode.expires_at > utcnow()
            )
        )
        if not clash:
            break
    else:
        raise HTTPException(status_code=503, detail="could not allocate a pairing code")

    # Delete any dead row holding this hash, so the unique index accepts ours.
    db.execute(delete(PairingCode).where(PairingCode.code_hash == code_hash))

    poll_token = security.new_token()
    expires_at = utcnow() + timedelta(seconds=config.PAIRING_TTL_SECONDS)
    db.add(
        PairingCode(
            code_hash=code_hash,
            poll_token_hash=security.hash_token(poll_token),
            machine_id=body.machine_id[:128],
            device_name=(body.device_name or "Desktop")[:120],
            expires_at=expires_at,
        )
    )
    db.commit()
    return {
        "code": code,
        "poll_token": poll_token,
        "expires_at": expires_at.isoformat(),
        "pair_url": f"{_base_url(request)}/app/devices",
    }


@router.post("/devices/pair/poll")
def pair_poll(body: PairPollIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    row = db.scalar(
        select(PairingCode).where(PairingCode.poll_token_hash == security.hash_token(body.poll_token))
    )
    if row is None:
        raise HTTPException(status_code=404, detail="unknown pairing session")

    if row.claimed_at is None:
        if row.expires_at <= utcnow():
            return {"status": "expired"}
        return {"status": "pending"}

    if row.consumed_at is not None or row.device_token_once is None:
        # Already handed over. Replaying the poll must not re-issue the token.
        return {"status": "consumed"}

    token = row.device_token_once
    row.device_token_once = None
    row.consumed_at = utcnow()
    db.commit()
    return {"status": "claimed", "device_token": token, "device_id": row.device_id}


# --------------------------------------------------------------------- sync

@router.post("/sync/trades")
def sync_trades(
    body: TradesIn,
    device: Device = Depends(require_device),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if len(body.trades) > config.MAX_TRADES_PER_REQUEST:
        raise HTTPException(
            status_code=413,
            detail=f"send at most {config.MAX_TRADES_PER_REQUEST} trades per request",
        )
    if not body.trades:
        return {"inserted": 0, "skipped": 0, "total": 0}

    incoming = {t.id: t for t in body.trades}  # dedupe within the batch itself
    existing = set(
        db.scalars(
            select(Trade.client_id).where(
                Trade.user_id == device.user_id, Trade.client_id.in_(list(incoming))
            )
        )
    )

    inserted = 0
    for cid, t in incoming.items():
        if cid in existing:
            continue
        db.add(
            Trade(
                user_id=device.user_id,
                device_id=device.id,
                client_id=cid,
                timestamp=t.timestamp,
                broker=t.broker.lower(),
                account_id=t.account_id,
                side=t.side,
                symbol=t.symbol.upper(),
                qty=t.qty,
                fill_price=t.fill_price,
            )
        )
        inserted += 1
    db.commit()

    total = db.scalar(
        select(func.count()).select_from(Trade).where(Trade.user_id == device.user_id)
    )
    return {"inserted": inserted, "skipped": len(incoming) - inserted, "total": total}


@router.post("/sync/holdings")
def sync_holdings(
    body: HoldingsIn,
    device: Device = Depends(require_device),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if len(body.holdings) > config.MAX_HOLDING_ROWS_PER_SNAPSHOT:
        raise HTTPException(status_code=413, detail="snapshot too large")

    snap = HoldingSnapshot(
        user_id=device.user_id,
        device_id=device.id,
        captured_at=body.captured_at or utcnow(),
    )
    for h in body.holdings:
        snap.rows.append(
            HoldingRow(
                broker=h.broker.lower(),
                account_id=h.account_id,
                symbol=h.symbol.upper(),
                qty=h.qty,
                value=h.value,
            )
        )
    db.add(snap)
    db.commit()

    # Keep only the most recent N snapshots per user.
    stale = list(
        db.scalars(
            select(HoldingSnapshot.id)
            .where(HoldingSnapshot.user_id == device.user_id)
            .order_by(HoldingSnapshot.captured_at.desc())
            .offset(config.SNAPSHOTS_RETAINED_PER_USER)
        )
    )
    if stale:
        db.execute(delete(HoldingRow).where(HoldingRow.snapshot_id.in_(stale)))
        db.execute(delete(HoldingSnapshot).where(HoldingSnapshot.id.in_(stale)))
        db.commit()

    return {"snapshot_id": snap.id, "rows": len(body.holdings), "pruned": len(stale)}


@router.get("/me")
def whoami(device: Device = Depends(require_device)) -> dict[str, Any]:
    """Lets the desktop app confirm its token is still good and show the email."""
    plan = plans.resolve(device.user.plan)
    return {
        "device_id": device.id,
        "device_name": device.name,
        "user_email": device.user.email,
        "linked_at": device.created_at.isoformat(),
        "plan": plan.key,
        "plan_name": plan.name,
        "features": sorted(plan.features),
    }


# =========================================================== THE PLAY FEED ===
# Two directions, three doors:
#
#   WRITE  one operator machine, holding FEED_INGEST_KEY, publishes what it
#          parsed out of the alert channels. Locked, always.
#   READ   a paired device or a signed-in browser on a plan that includes the
#          feed uses /plays. Everyone else uses /public/plays with the shared
#          board password (PLAYS_PASSWORD) — same bytes, no account.
#
# The write asymmetry is the point: the feed cannot be forged, and nobody but
# the operator ever needs Discord credentials.
#
# Reading used to be wide open, on the reasoning that the alert feed was a free
# funnel rather than the product. It is now a paid tier (plans.py), so an
# unauthenticated mirror would have given away the thing being sold — the
# password door replaced it. The onboarding cost stays near zero, which was the
# original point: one secret, no signup, no pairing, and a fresh checkout works
# the moment its owner is told the password.

class PlayIn(BaseModel):
    source_id: str = Field(min_length=1, max_length=80)
    symbol: str = Field(min_length=1, max_length=24)
    kind: str = "standard"
    alert_date: str = Field(default="", max_length=10)
    ratio: str = Field(default="", max_length=24)
    ratio_n: int | None = None
    entry_price: float | None = None
    est_profit: float | None = None
    last_buy_date: str | None = Field(default=None, max_length=10)
    roundup_history: str = Field(default="", max_length=200)
    strategy: str = Field(default="", max_length=80)
    posted_at: datetime | None = None

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        v = (v or "").lower().strip()
        return v if v in {"standard", "otc", "conditional"} else "standard"

    @field_validator("symbol")
    @classmethod
    def _sym(cls, v: str) -> str:
        return v.upper().strip()


class LegIn(BaseModel):
    broker: str = Field(default="", max_length=40)
    accounts_low: int = 0
    accounts_high: int = 0


class ExitIn(BaseModel):
    source_id: str = Field(min_length=1, max_length=80)
    symbol: str = Field(min_length=1, max_length=24)
    exit_price: float | None = None
    proceeds_low: float | None = None
    proceeds_high: float | None = None
    legs: list[LegIn] = Field(default_factory=list)
    note: str = ""
    sell_date: str = Field(default="", max_length=10)
    posted_at: datetime | None = None

    @field_validator("symbol")
    @classmethod
    def _sym(cls, v: str) -> str:
        return v.upper().strip()


class RoundUpIn(BaseModel):
    source_id: str = Field(min_length=1, max_length=80)
    symbol: str = Field(min_length=1, max_length=24)
    confirmed_date: str = Field(default="", max_length=10)
    posted_at: datetime | None = None

    @field_validator("symbol")
    @classmethod
    def _sym(cls, v: str) -> str:
        return v.upper().strip()


class LifecycleIn(BaseModel):
    source_id: str = Field(min_length=1, max_length=80)
    symbol: str = Field(min_length=1, max_length=24)
    sell_symbol: str = Field(default="", max_length=24)
    alert_date: str = Field(default="", max_length=10)
    status: str = Field(default="unknown", max_length=24)
    kind: str = Field(default="standard", max_length=16)

    @field_validator("symbol", "sell_symbol")
    @classmethod
    def _sym(cls, v: str) -> str:
        return v.upper().strip()


class FeedIn(BaseModel):
    buys: list[PlayIn] = Field(default_factory=list)
    sells: list[ExitIn] = Field(default_factory=list)
    roundups: list[RoundUpIn] = Field(default_factory=list)
    lifecycle: list[LifecycleIn] = Field(default_factory=list)


def require_ingest_key(x_feed_key: str = Header(default="")) -> None:
    """Constant-time check of the publisher's key.

    A missing FEED_INGEST_KEY is a hard 503, never an open door: the failure
    mode of "we forgot to set the variable" must be *nobody can publish*, not
    *anybody can*.
    """
    if not config.FEED_INGEST_KEY:
        raise HTTPException(status_code=503, detail="feed ingest is not configured")
    if not hmac.compare_digest(x_feed_key or "", config.FEED_INGEST_KEY):
        raise HTTPException(status_code=401, detail="bad feed key")


def require_feed_reader(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Either a paired device or a logged-in browser, so long as the plan
    includes the feed. Both paths land on the same User."""
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() == "bearer" and token:
        device = db.scalar(select(Device).where(Device.token_hash == security.hash_token(token)))
        if device is None or not device.is_active:
            raise HTTPException(status_code=401, detail="invalid or revoked device token")
        device.last_seen_at = utcnow()
        db.commit()
        user = device.user
    else:
        uid = request.session.get("uid")
        user = db.get(User, uid) if uid else None
        if user is None:
            raise HTTPException(status_code=401, detail="login required")

    if not plans.can(user, plans.FEED):
        raise HTTPException(status_code=403, detail="your plan does not include the play feed")
    return user


@router.post("/plays/ingest", dependencies=[Depends(require_ingest_key)])
def ingest_plays(body: FeedIn, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Publish a parsed pull. Idempotent on `source_id`, so re-sending the same
    50 messages every day inserts nothing and costs one round trip.

    Lifecycle rows are the exception and are UPSERTED. They are statuses rather
    than events — a play moves pending -> fractional on the same key — so the
    insert-only rule that makes the other three streams idempotent would freeze
    every play at whatever we first saw and never tell anyone it resolved.
    """
    total = (len(body.buys) + len(body.sells) + len(body.roundups)
             + len(body.lifecycle))
    if total > config.MAX_PLAYS_PER_INGEST:
        raise HTTPException(
            status_code=413, detail=f"send at most {config.MAX_PLAYS_PER_INGEST} rows per request"
        )

    counts = {"buys": 0, "sells": 0, "roundups": 0, "lifecycle": 0}

    def _fresh(model, ids: list[str]) -> set[str]:
        if not ids:
            return set()
        return set(db.scalars(select(model.source_id).where(model.source_id.in_(ids))))

    seen = _fresh(Play, [b.source_id for b in body.buys])
    for b in body.buys:
        if b.source_id in seen:
            continue
        seen.add(b.source_id)          # dedupe within the batch too
        db.add(Play(
            source_id=b.source_id, symbol=b.symbol, kind=b.kind,
            alert_date=b.alert_date, ratio=b.ratio, ratio_n=b.ratio_n,
            entry_price=b.entry_price, est_profit=b.est_profit,
            last_buy_date=b.last_buy_date, roundup_history=b.roundup_history,
            strategy=b.strategy, posted_at=_aware(b.posted_at),
        ))
        counts["buys"] += 1

    seen = _fresh(PlayExit, [s.source_id for s in body.sells])
    for s in body.sells:
        if s.source_id in seen:
            continue
        seen.add(s.source_id)
        db.add(PlayExit(
            source_id=s.source_id, symbol=s.symbol, exit_price=s.exit_price,
            proceeds_low=s.proceeds_low, proceeds_high=s.proceeds_high,
            legs_json=json.dumps([l.model_dump() for l in s.legs]),
            note=s.note[:2000], sell_date=s.sell_date, posted_at=_aware(s.posted_at),
        ))
        counts["sells"] += 1

    seen = _fresh(PlayRoundUp, [r.source_id for r in body.roundups])
    for r in body.roundups:
        if r.source_id in seen:
            continue
        seen.add(r.source_id)
        db.add(PlayRoundUp(
            source_id=r.source_id, symbol=r.symbol,
            confirmed_date=r.confirmed_date, posted_at=_aware(r.posted_at),
        ))
        counts["roundups"] += 1

    # --- lifecycle: upsert, and only count a row when something actually moved
    if body.lifecycle:
        now = utcnow()
        existing = {
            row.source_id: row
            for row in db.scalars(select(PlayLifecycle).where(
                PlayLifecycle.source_id.in_([l.source_id for l in body.lifecycle])))
        }
        seen_ids: set[str] = set()
        for l in body.lifecycle:
            if l.source_id in seen_ids:
                continue                      # same board sent twice in one batch
            seen_ids.add(l.source_id)
            row = existing.get(l.source_id)
            if row is None:
                db.add(PlayLifecycle(
                    source_id=l.source_id, symbol=l.symbol,
                    sell_symbol=l.sell_symbol or l.symbol,
                    alert_date=l.alert_date, status=l.status, kind=l.kind,
                    first_seen_at=now, updated_at=now, status_changed_at=now,
                ))
                counts["lifecycle"] += 1
                continue

            row.updated_at = now
            if row.status != l.status:
                row.status = l.status
                row.status_changed_at = now
                counts["lifecycle"] += 1      # a status move is the only news
            # A rename can land after the row exists, and it is what decides
            # which ticker a customer can actually place an order in.
            row.sell_symbol = l.sell_symbol or l.symbol
            row.kind = l.kind or row.kind

    db.commit()
    return {"inserted": counts, "received": total}


@router.get("/plays")
def read_plays(
    user: User = Depends(require_feed_reader),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """The feed, already divided into buys / closed / sells / round-ups."""
    return playsfeed.feed_json(playsfeed.load_board(db))


@router.get("/plays/picks")
def read_picks(
    user: User = Depends(require_feed_reader),
    db: Session = Depends(get_db),
) -> list[dict[str, str]]:
    """The three-key shape the desktop's picks.json has always held.

    Exists so the terminal can move off the public JSON blob and onto an
    authenticated feed without a single change to its mirror queue.
    """
    notes = {"standard": "Reg Alert", "otc": "OTC", "conditional": "conditional"}
    board = playsfeed.load_board(db)
    return [
        {"symbol": l.play.symbol,
         "note": notes.get(l.play.kind, "Reg Alert"),
         "date": l.play.alert_date}
        for l in board.open_plays
    ]


@router.get("/plays/lifecycle")
def read_lifecycle(
    user: User = Depends(require_feed_reader),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """The TRACK board, in the shape rsa_feed.LifecycleRow serialises to.

    This is what lets a subscriber who is not in the alert Discord see which of
    their positions actually resolved. Without it the desktop's Exits page only
    works for someone holding a personal Discord token with access to the
    channel — which is nobody we sell to.

    Ordered oldest-first so a client folding it into local state processes the
    board in the same order the desktop's own poll would.
    """
    rows = db.scalars(
        select(PlayLifecycle).order_by(
            PlayLifecycle.alert_date.asc(), PlayLifecycle.symbol.asc())
    )
    return [
        {"symbol": r.symbol,
         "sell_symbol": r.sell_symbol or r.symbol,
         "alert_date": r.alert_date,
         "status": r.status,
         "kind": r.kind,
         "status_changed_at": (r.status_changed_at.isoformat()
                               if r.status_changed_at else "")}
        for r in rows
    ]


# ------------------------------------------------ the account-free front door
# Byte-identical payloads to the three routes above, for a caller who has the
# shared board password instead of an account. They exist so a copy of the
# terminal can read the feed its owner pays for without signing up, pairing, or
# holding a device token — which is the state most installs are in.
#
# `public` in the path is now a misnomer kept for compatibility: these used to
# be open, and were closed when Plays became a paid tier. One secret gates the
# web board and this API, so "here is the password" is the whole of onboarding.
#
# Keep these read-only and keep them in sync with their authenticated twins —
# the desktop cannot tell which one answered it, and must not be able to.

def require_plays_key(
    request: Request,
    x_plays_key: str = Header(default=""),
    db: Session = Depends(get_db),
) -> None:
    """The shared board password, as a header or a `?key=`.

    Fail closed when nothing is configured, exactly like `require_ingest_key`:
    an unset variable must never mean an open feed.

    Two callers skip the password, and both already proved more than it does:
    a browser that typed it on /plays, and a signed-in customer whose plan
    includes the feed. The second is not a nicety — anyone who passes the HTML
    gate must pass this one, or the page renders from data its own session is
    forbidden to fetch.
    """
    from .plays import remembered      # local import: plays.py imports no routes

    if request.session.get("plays_unlocked") or remembered(request):
        return
    uid = request.session.get("uid")
    if uid and plans.can(db.get(User, uid), plans.FEED):
        return
    if not config.PLAYS_PASSWORD:
        raise HTTPException(status_code=503, detail="the play feed is not configured")
    supplied = x_plays_key or request.query_params.get("key", "")
    if not hmac.compare_digest(supplied.strip(), config.PLAYS_PASSWORD):
        raise HTTPException(status_code=401, detail="the play feed needs the board password")


@router.get("/public/plays", dependencies=[Depends(require_plays_key)])
def read_plays_public(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Buys, closed plays, exits and round-ups. Board password required."""
    return playsfeed.feed_json(playsfeed.load_board(db))


@router.get("/public/plays/picks", dependencies=[Depends(require_plays_key)])
def read_picks_public(db: Session = Depends(get_db)) -> list[dict[str, str]]:
    """Open plays in the shape picks.json holds. Board password required."""
    notes = {"standard": "Reg Alert", "otc": "OTC", "conditional": "conditional"}
    board = playsfeed.load_board(db)
    return [
        {"symbol": l.play.symbol,
         "note": notes.get(l.play.kind, "Reg Alert"),
         "date": l.play.alert_date}
        for l in board.open_plays
    ]


@router.get("/public/plays/lifecycle", dependencies=[Depends(require_plays_key)])
def read_lifecycle_public(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """The TRACK board — what each split actually did. Board password required.

    Served on this door for the same reason as the rest: without it a terminal
    that was never paired shows an empty Exits page, and 'which of my positions
    resolved' is the one question the customer cannot answer from anywhere else.
    """
    rows = db.scalars(
        select(PlayLifecycle).order_by(
            PlayLifecycle.alert_date.asc(), PlayLifecycle.symbol.asc())
    )
    return [
        {"symbol": r.symbol,
         "sell_symbol": r.sell_symbol or r.symbol,
         "alert_date": r.alert_date,
         "status": r.status,
         "kind": r.kind,
         "status_changed_at": (r.status_changed_at.isoformat()
                               if r.status_changed_at else "")}
        for r in rows
    ]


def _aware(v: datetime | None) -> datetime | None:
    if v is None:
        return None
    return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
