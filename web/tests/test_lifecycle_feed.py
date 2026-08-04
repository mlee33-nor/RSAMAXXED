"""The TRACK board over the cloud feed, driven through the real desktop client.

The point of this path: reading the board off Discord needs a personal user
token with access to a private channel. A paying subscriber has neither, so
without these endpoints their Exits page is permanently empty. These tests pin
the two things that make it work — the board is published by the operator, and
lifecycle rows UPSERT rather than insert-only, because a status is meant to
change.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile

import pytest

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = WEB_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(WEB_ROOT))

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_lifecycle.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

import rsa_feed  # noqa: E402
from app import config  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402

KEY = {"X-Feed-Key": "test-feed-key"}


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield
    engine.dispose()
    _TMP_DB.unlink(missing_ok=True)


@pytest.fixture()
def client(monkeypatch):
    # config reads the environment once, at import — and whichever test module
    # imports the app first wins, so setting os.environ here would be too late.
    # Patch the resolved value instead, which is order-independent.
    monkeypatch.setattr(config, "FEED_INGEST_KEY", "test-feed-key")
    return TestClient(app)


def test_an_unset_ingest_key_locks_publishing_rather_than_opening_it(monkeypatch):
    """The failure mode of forgetting the env var must be 'nobody can publish',
    never 'anybody can'."""
    monkeypatch.setattr(config, "FEED_INGEST_KEY", "")
    r = TestClient(app).post("/api/v1/plays/ingest",
                             json={"lifecycle": [_row("X", "pending")]}, headers=KEY)
    assert r.status_code == 503


def _row(symbol, status, date="2026-07-17", sell_symbol="", kind="standard"):
    return {"source_id": f"{date}:{symbol}", "symbol": symbol,
            "sell_symbol": sell_symbol or symbol, "alert_date": date,
            "status": status, "kind": kind}


def _ingest(client, rows):
    r = client.post("/api/v1/plays/ingest", json={"lifecycle": rows}, headers=KEY)
    assert r.status_code == 200, r.text
    return r.json()["inserted"]["lifecycle"]


def _subscriber(email: str) -> TestClient:
    browser = TestClient(app)
    page = browser.get("/signup?plan=automation")
    csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    browser.post("/signup", data={"email": email, "password": "correct-horse-battery",
                                  "plan": "automation", "csrf_token": csrf})
    return browser


# ------------------------------------------------------------------- ingest

def test_publishing_the_board_requires_the_operator_key(client):
    """Anyone able to write the board could tell every subscriber a play
    resolved, and they would sell into it."""
    r = client.post("/api/v1/plays/ingest", json={"lifecycle": [_row("TOMZ", "fractional")]})
    assert r.status_code == 401
    r = client.post("/api/v1/plays/ingest", json={"lifecycle": [_row("TOMZ", "fractional")]},
                    headers={"X-Feed-Key": "wrong"})
    assert r.status_code == 401


def test_a_status_change_updates_in_place(client):
    """THE reason lifecycle is not insert-only. Keeping the first value would
    freeze every play at 'pending' and never tell anyone it became sellable."""
    assert _ingest(client, [_row("TOMZ", "pending")]) == 1
    assert _ingest(client, [_row("TOMZ", "fractional")]) == 1

    rows = {r["symbol"]: r for r in _read(client)}
    assert rows["TOMZ"]["status"] == "fractional"
    # Updated, not duplicated.
    assert sum(1 for r in _read(client) if r["symbol"] == "TOMZ") == 1


def test_republishing_an_unchanged_board_counts_nothing(client):
    """The publisher re-sends the whole board every run, so an unchanged board
    must be free — otherwise 'changes' is noise and nobody reads it."""
    _ingest(client, [_row("QUIET", "fractional")])
    assert _ingest(client, [_row("QUIET", "fractional")]) == 0


def test_the_same_row_twice_in_one_batch_is_handled(client):
    assert _ingest(client, [_row("DUPE", "pending"), _row("DUPE", "pending")]) == 1


def test_a_rename_lands_even_after_the_row_exists(client):
    """The rename decides which ticker a customer can place an order in, and it
    is often announced after the play is already on the board."""
    _ingest(client, [_row("AGAE", "pending", date="2026-06-11")])
    _ingest(client, [_row("AGAE", "rounded_up", date="2026-06-11", sell_symbol="AIFA")])
    row = next(r for r in _read(client) if r["symbol"] == "AGAE")
    assert row["sell_symbol"] == "AIFA"
    assert row["status"] == "rounded_up"


def test_identity_is_keyed_on_the_original_ticker(client):
    """A key that followed the rename would orphan the position it identifies —
    the customer's journal recorded the pre-split ticker."""
    row = rsa_feed.LifecycleRow(symbol="AGAE", sell_symbol="AIFA",
                                alert_date="2026-06-11", status="rounded_up")
    assert row.source_id == "2026-06-11:AGAE"


# --------------------------------------------------------------------- read

def _read(client):
    """Read as a subscriber, through the real desktop client's auth path."""
    browser = _subscriber(f"reader{_read.counter}@example.com")
    _read.counter += 1
    r = browser.get("/api/v1/plays/lifecycle")
    assert r.status_code == 200, r.text
    return r.json()


_read.counter = 0


def test_the_board_is_not_public(client):
    """It is the thing being sold; an unauthenticated read would give it away."""
    assert client.get("/api/v1/plays/lifecycle").status_code == 401


def test_a_subscriber_reads_the_board_without_any_discord_access(client):
    """The whole point. No token, no channel membership, still gets the board."""
    _ingest(client, [_row("CSAI", "fractional", date="2026-07-30"),
                     _row("CLDI", "rounded_up", date="2026-07-30")])
    got = {r["symbol"]: r["status"] for r in _read(client)}
    assert got["CSAI"] == "fractional"
    assert got["CLDI"] == "rounded_up"


def test_the_wire_shape_round_trips_back_into_a_LifecycleRow(client):
    """The desktop rebuilds rows from this endpoint, so the shapes must agree
    or the Exits page silently shows nothing."""
    _ingest(client, [_row("ZNB", "fractional", date="2026-07-24")])
    payload = next(r for r in _read(client) if r["symbol"] == "ZNB")
    row = rsa_feed.LifecycleRow.from_json(payload)
    assert row is not None
    assert row.symbol == "ZNB" and row.status == "fractional"
    assert row.is_sellable
    # And it survives a full publish -> read -> rebuild loop unchanged.
    assert rsa_feed.LifecycleRow.from_json(row.to_json()) == row


def test_an_unusable_row_is_dropped_not_guessed(client):
    assert rsa_feed.LifecycleRow.from_json({"symbol": "", "alert_date": "2026-07-01"}) is None
    assert rsa_feed.LifecycleRow.from_json({"symbol": "X", "alert_date": ""}) is None


def test_an_unknown_status_is_preserved_and_not_sellable():
    """An older client must never reclassify a status it does not recognise
    into something it will place an order on."""
    row = rsa_feed.LifecycleRow.from_json(
        {"symbol": "NEW", "alert_date": "2026-07-01", "status": "some_future_state"})
    assert row.status == "some_future_state"
    assert not row.is_sellable
