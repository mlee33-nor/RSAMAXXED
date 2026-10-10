from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from . import config

_url = config.database_url()
_engine_kwargs: dict = {"pool_pre_ping": True, "future": True}
if _url.startswith("sqlite"):
    # Uvicorn serves requests from a threadpool; the default SQLite check
    # rejects cross-thread reuse of a connection.
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(_url, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from . import models  # noqa: F401  (import registers the mappers)

    Base.metadata.create_all(engine)
    _add_missing_columns()
    _mask_stored_account_ids()


# Columns added to a table that already exists in a deployed database.
# `create_all` only ever CREATEs, so without this a new column is invisible in
# production and every query on it fails. Single-replica, additive, and
# idempotent by construction — the moment this list needs a DROP, a rename or a
# backfill, it has outgrown itself and the answer is Alembic.
_ADDED_COLUMNS: tuple[tuple[str, str, str], ...] = (
    # (table, column, DDL type + default)
    ("users", "plan", "VARCHAR(24) DEFAULT 'plays'"),
)


def _add_missing_columns() -> None:
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table, column, ddl in _ADDED_COLUMNS:
            if table not in existing_tables:
                continue  # create_all just made it, with the column already on it
            if column in {c["name"] for c in inspector.get_columns(table)}:
                continue
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))


# Tables whose `account_id` came from a desktop's trades.json / get_holdings().
_ACCOUNT_ID_TABLES: tuple[str, ...] = ("trades", "holding_rows")


def _mask_stored_account_ids() -> int:
    """Strip account numbers out of every stored account label. Returns rows changed.

    Until desktop clients masked labels before upload, Fidelity rows arrived
    with the FULL account number and every other broker with a last-4. This
    rewrites any stored label with a 4+ digit run into the masked shape
    (app.privacy). Idempotent by construction -- a masked label has no digit
    run, so the SELECT finds nothing on every later boot -- and data-only, so
    it sits beside _add_missing_columns rather than needing a schema tool.
    """
    from sqlalchemy import bindparam, inspect, text

    from .privacy import mask_account_id, needs_mask

    dialect = engine.dialect.name
    if dialect == "postgresql":
        where = "account_id ~ '[0-9]{4}'"
    elif dialect == "sqlite":
        where = "account_id GLOB '*[0-9][0-9][0-9][0-9]*'"
    else:                                   # filtered in Python below
        where = "account_id <> ''"

    tables = set(inspect(engine).get_table_names())
    changed = 0
    with engine.begin() as conn:
        for table in _ACCOUNT_ID_TABLES:
            if table not in tables:
                continue
            rows = conn.execute(
                text(f"SELECT id, account_id FROM {table} WHERE {where}")).all()
            updates = [{"i": rid, "a": mask_account_id(acct)}
                       for rid, acct in rows if needs_mask(acct)]
            if updates:
                conn.execute(
                    text(f"UPDATE {table} SET account_id = :a WHERE id = :i")
                    .bindparams(bindparam("a"), bindparam("i")),
                    updates)
                changed += len(updates)
    return changed
