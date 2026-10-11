"""A picks:SYM:DATE copy of a published alert is never a second play.

The operator's terminal republishes its picks.json through ingest. Keyed only
on source_id, every alert the publisher had already sent was stored again as
a bare "picks:" row, and the board showed 130 of 407 plays twice.
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
from datetime import date

import pytest

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEB_ROOT))

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_picks_copies.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP_DB.as_posix()}")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from app import config, playsfeed  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Play  # noqa: E402

KEY = {"X-Feed-Key": "test-feed-key"}


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(config, "FEED_INGEST_KEY", "test-feed-key")
    monkeypatch.setattr(config, "PICKS_FILE", "")
    with SessionLocal() as db:
        db.execute(delete(Play))
        db.commit()
    return TestClient(app)


def _day() -> str:
    return date.today().isoformat()


def _buy(sid: str, sym: str, **kw) -> dict:
    return {"source_id": sid, "symbol": sym, "kind": "standard",
            "alert_date": _day(), **kw}


def _ingest(client, *buys) -> dict:
    r = client.post("/api/v1/plays/ingest", json={"buys": list(buys)}, headers=KEY)
    assert r.status_code == 200, r.text
    return r.json()


def _rows() -> list[Play]:
    with SessionLocal() as db:
        return list(db.scalars(select(Play)))


def _board_symbols() -> list[str]:
    with SessionLocal() as db:
        board = playsfeed.load_board(db)
        return [l.play.symbol for l in board.open_plays]


def test_copy_after_message_is_not_stored(client):
    _ingest(client, _buy("1557:0", "ZBAO", ratio="1:10"))
    _ingest(client, _buy(f"picks:ZBAO:{_day()}", "ZBAO"))
    assert [p.source_id for p in _rows()] == ["1557:0"]
    assert _board_symbols() == ["ZBAO"]


def test_copy_in_same_batch_is_not_stored(client):
    _ingest(client, _buy(f"picks:RYDE:{_day()}", "RYDE"), _buy("1558:0", "RYDE"))
    assert [p.source_id for p in _rows()] == ["1558:0"]


def test_hand_entered_pick_without_message_is_kept(client):
    _ingest(client, _buy(f"picks:NIVF:{_day()}", "NIVF"))
    assert [p.symbol for p in _rows()] == ["NIVF"]
    assert _board_symbols() == ["NIVF"]


def test_copy_of_a_different_day_is_a_different_play(client):
    _ingest(client, _buy("1559:0", "KIDZ", alert_date="2026-01-05"))
    _ingest(client, _buy(f"picks:KIDZ:{_day()}", "KIDZ"))
    assert len(_rows()) == 2


def test_board_hides_copies_already_stored(client):
    # Rows stored before the ingest guard existed: both are in the table.
    with SessionLocal() as db:
        db.add(Play(source_id="1560:0", symbol="DFLI", kind="standard",
                    alert_date=_day(), ratio="1:20"))
        db.add(Play(source_id=f"picks:DFLI:{_day()}", symbol="DFLI",
                    kind="standard", alert_date=_day()))
        db.commit()
    assert _board_symbols() == ["DFLI"]
    with SessionLocal() as db:
        board = playsfeed.load_board(db)
    assert [l.play.source_id for l in board.history] == ["1560:0"]
    r = client.get("/api/v1/plays/export", headers=KEY)
    assert len(r.json()["buys"]) == 2      # nothing was deleted
