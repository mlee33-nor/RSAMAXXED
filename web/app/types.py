"""A DateTime column that is always timezone-aware UTC, on every backend.

Postgres `timestamptz` returns aware datetimes; SQLite has no timezone type and
returns naive ones. Without this, `row.expires_at <= utcnow()` raises
TypeError on SQLite and quietly works on Postgres — a bug that hides until you
change database.

Store: coerce to UTC, hand the driver a naive UTC value.
Load:  stamp UTC back on.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            # A naive value from a caller is taken to mean UTC, never local time.
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
