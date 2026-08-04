"""Database schema.

Multi-tenancy rule, enforced everywhere: every row that holds CUSTOMER data
carries a `user_id`, and every read filters on it. A device token resolves to
exactly one user; there is no path from one customer's token to another's rows.

The one deliberate exception is the play feed at the bottom of this file
(`Play`, `PlayExit`, `PlayRoundUp`). Those rows are CATALOG data — the same
alerts every subscriber buys access to — so they carry no `user_id` by design.
Access is gated at the route, by plan, not by row ownership. Keep it that way:
copying the feed per user would multiply it by the customer count for no gain.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import (
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .types import UtcDateTime


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    display_name: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    # Which tier this account is entitled to. See plans.py — that module owns
    # what each value unlocks; this column only stores the name.
    plan: Mapped[str] = mapped_column(String(24), default="plays")

    devices: Mapped[list["Device"]] = relationship(back_populates="user")


class Device(Base):
    """A paired copy of the desktop app. `token_hash` is a SHA-256 of the
    bearer token; the plaintext is shown to the device exactly once."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(120), default="Desktop")
    machine_id: Mapped[str] = mapped_column(String(128), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)

    user: Mapped[User] = relationship(back_populates="devices")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None


class PairingCode(Base):
    """Short-lived claim ticket. The desktop app asks the server for one, shows
    the 6-char code, and polls with `poll_token` until a logged-in user claims
    it. Both the code and the poll token are stored hashed."""

    __tablename__ = "pairing_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    poll_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    machine_id: Mapped[str] = mapped_column(String(128), default="")
    device_name: Mapped[str] = mapped_column(String(120), default="Desktop")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)

    claimed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)

    # The device token is held here in plaintext only between the moment the
    # user claims the code and the moment the device's next poll collects it.
    # Cleared on pickup; the row is useless afterwards.
    device_token_once: Mapped[str | None] = mapped_column(Text, nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)


class PairingAttempt(Base):
    """One row per wrong-code guess, used to throttle brute force."""

    __tablename__ = "pairing_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)


class Trade(Base):
    """Mirror of one row of the desktop app's trades.json.

    `client_id` is the UUID the desktop already assigns in trade_journal.py,
    which is what makes re-pushing the same trade idempotent.
    """

    __tablename__ = "trades"
    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_trade_user_client"),
        Index("ix_trades_user_ts", "user_id", "timestamp"),
        Index("ix_trades_user_symbol", "user_id", "symbol"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    client_id: Mapped[str] = mapped_column(String(64))

    timestamp: Mapped[datetime] = mapped_column(UtcDateTime)
    broker: Mapped[str] = mapped_column(String(40))
    account_id: Mapped[str] = mapped_column(String(160), default="")
    side: Mapped[str] = mapped_column(String(8))
    symbol: Mapped[str] = mapped_column(String(24))
    qty: Mapped[float] = mapped_column(Float)
    fill_price: Mapped[float | None] = mapped_column(Float, nullable=True)

    synced_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class HoldingSnapshot(Base):
    """A point-in-time capture of get_holdings() across every linked broker."""

    __tablename__ = "holding_snapshots"
    __table_args__ = (Index("ix_snap_user_captured", "user_id", "captured_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    rows: Mapped[list["HoldingRow"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class HoldingRow(Base):
    __tablename__ = "holding_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("holding_snapshots.id", ondelete="CASCADE"), index=True
    )
    broker: Mapped[str] = mapped_column(String(40))
    account_id: Mapped[str] = mapped_column(String(160), default="")
    symbol: Mapped[str] = mapped_column(String(24))
    qty: Mapped[float] = mapped_column(Float, default=0.0)
    value: Mapped[float | None] = mapped_column(Float, nullable=True)

    snapshot: Mapped[HoldingSnapshot] = relationship(back_populates="rows")


# ============================================================== THE PLAY FEED
# Catalog data, shared by every subscriber. No `user_id` — see the module
# docstring. `source_id` is the Discord message id (plus an index when one
# message carries several alerts), which is what makes re-ingesting the same
# pull a no-op instead of a duplicate.

class Play(Base):
    """One BUY alert: a play to open.

    Everything here comes off the alert embed verbatim — we store what the feed
    said, not what we think it meant, so a bad alert stays traceable.
    """

    __tablename__ = "plays"
    __table_args__ = (
        UniqueConstraint("source_id", name="uq_play_source"),
        Index("ix_plays_alert_date", "alert_date"),
        Index("ix_plays_symbol", "symbol"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(80))

    symbol: Mapped[str] = mapped_column(String(24))
    kind: Mapped[str] = mapped_column(String(16), default="standard")  # standard|otc|conditional
    alert_date: Mapped[str] = mapped_column(String(10), default="")     # YYYY-MM-DD
    ratio: Mapped[str] = mapped_column(String(24), default="")          # '1:15', as written
    ratio_n: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 15
    entry_price: Mapped[float | None] = mapped_column(Float, nullable=True)
    est_profit: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_buy_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    roundup_history: Mapped[str] = mapped_column(String(200), default="")
    strategy: Mapped[str] = mapped_column(String(80), default="")

    posted_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    @property
    def is_actionable(self) -> bool:
        """Conditional alerts are watch-only — the split isn't declared yet."""
        return self.kind in ("standard", "otc")

    def days_left(self, today: date | None = None) -> int | None:
        if not self.last_buy_date:
            return None
        try:
            return (date.fromisoformat(self.last_buy_date) - (today or date.today())).days
        except ValueError:
            return None

    def is_open(self, today: date | None = None) -> bool:
        """Undated alerts count as open: we can't prove they're closed, and
        hiding a live play costs the customer more than showing a stale one."""
        left = self.days_left(today)
        return True if left is None else left >= 0


class PlayExit(Base):
    """One SELL alert: a play closed at a price, across a set of brokers."""

    __tablename__ = "play_exits"
    __table_args__ = (
        UniqueConstraint("source_id", name="uq_exit_source"),
        Index("ix_exits_sell_date", "sell_date"),
        Index("ix_exits_symbol", "symbol"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(80))

    symbol: Mapped[str] = mapped_column(String(24))
    exit_price: Mapped[float | None] = mapped_column(Float, nullable=True)
    # A range, because Public's account count varies per customer. When the
    # feed quotes one number both columns hold it, so callers never branch.
    proceeds_low: Mapped[float | None] = mapped_column(Float, nullable=True)
    proceeds_high: Mapped[float | None] = mapped_column(Float, nullable=True)
    # JSON: [{"broker": "Robinhood", "accounts_low": 3, "accounts_high": 3}, ...]
    legs_json: Mapped[str] = mapped_column(Text, default="[]")
    note: Mapped[str] = mapped_column(Text, default="")

    sell_date: Mapped[str] = mapped_column(String(10), default="")
    posted_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)

    @property
    def legs(self) -> list[dict]:
        import json
        try:
            rows = json.loads(self.legs_json or "[]")
        except ValueError:
            return []
        return rows if isinstance(rows, list) else []

    @property
    def accounts(self) -> int:
        return sum(int(l.get("accounts_low") or 0) for l in self.legs)

    @property
    def is_range(self) -> bool:
        return (self.proceeds_high or 0) > (self.proceeds_low or 0)


class PlayLifecycle(Base):
    """One row of the TRACK board: what the split actually DID to a play.

    The stream a subscriber cannot reconstruct on their own. A BUY alert says
    what to open and a SELL alert says what the alerter closed, but neither says
    whether YOUR fraction rounded up, came back as a fraction, or was paid out
    as cash — and that decides whether there is anything left to sell at all.

    THE ONE MUTABLE TABLE IN THE FEED. Every other row here is a fact that
    happened once, so ingest is insert-only and keyed on source_id. A lifecycle
    row is a *status*, and its whole purpose is to change: a play goes pending
    -> fractional -> nothing, in place, on the same key. Ingesting it with the
    insert-only rule would freeze every play at whatever it was the first time
    we saw it, which is precisely the wrong answer. See `ingest_plays`.

    `source_id` is the lifecycle key, 'YYYY-MM-DD:SYMBOL', built from the alert
    date and the ORIGINAL ticker — the one the customer's journal recorded. It
    matches the key rsa_feed.LifecycleRow.key produces, so the desktop and the
    cloud agree on identity without a translation table.
    """

    __tablename__ = "play_lifecycle"
    __table_args__ = (
        UniqueConstraint("source_id", name="uq_lifecycle_source"),
        Index("ix_lifecycle_symbol", "symbol"),
        Index("ix_lifecycle_alert_date", "alert_date"),
        Index("ix_lifecycle_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(80))

    symbol: Mapped[str] = mapped_column(String(24))
    # After a reverse split the ticker often changes (AGAE -> AIFA). Holdings
    # are found under `symbol`, but only `sell_symbol` can be traded.
    sell_symbol: Mapped[str] = mapped_column(String(24), default="")
    alert_date: Mapped[str] = mapped_column(String(10), default="")
    status: Mapped[str] = mapped_column(String(24), default="unknown")
    kind: Mapped[str] = mapped_column(String(16), default="standard")

    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    # When the STATUS last changed, as opposed to when we last saw the row.
    # This is what lets a client show "went fractional today".
    status_changed_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class PlayRoundUp(Base):
    """'Round Up Successful — HCWB'. Proof a fraction actually rounded up.

    The most load-bearing row in the product: it is the only evidence that the
    mechanism the whole site describes did what it claims, for that ticker.
    """

    __tablename__ = "play_roundups"
    __table_args__ = (
        UniqueConstraint("source_id", name="uq_roundup_source"),
        Index("ix_roundups_symbol", "symbol"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[str] = mapped_column(String(80))
    symbol: Mapped[str] = mapped_column(String(24))
    confirmed_date: Mapped[str] = mapped_column(String(10), default="")
    posted_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
