"""/plays/picks fails closed, and carries `last_buy` to customer terminals.

The note a pick is served with is what every customer's mirror decides to
auto-buy on: "Reg Alert" buys at every account. So only an alert that said
STANDARD may ever be served that way — blank, missing or never-seen alert
types must reach the terminal as something its mirror will not buy.

`last_buy` is the alert's last day to buy; the desktop keeps a pick buyable
through it (a Friday-evening alert is not "too old" on Monday). It used to be
stored and then dropped by the three-key response.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import tempfile
from datetime import date, timedelta

import pytest

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = WEB_ROOT.parent
sys.path.insert(0, str(WEB_ROOT))

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_picks_fail_closed.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP_DB.as_posix()}")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app import config, playsfeed  # noqa: E402
from app.db import SessionLocal, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Play  # noqa: E402
from app.routes.api import PlayIn  # noqa: E402

KEY = {"X-Feed-Key": "test-feed-key"}
PICKS = ("/api/v1/public/plays/picks",)


def _mirror_notes() -> tuple[str, ...]:
    """app.MIRROR_NOTES, read from source: importing the GUI is not an option."""
    src = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    m = re.search(r"^MIRROR_NOTES\s*=\s*\(([^)]*)\)", src, re.M)
    assert m, "app.MIRROR_NOTES moved; update this test"
    return tuple(re.findall(r'"([^"]+)"', m.group(1)))


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(config, "FEED_INGEST_KEY", "test-feed-key")
    monkeypatch.setattr(config, "PICKS_FILE", "")
    return TestClient(app)


def _today() -> str:
    return date.today().isoformat()


def _soon(days: int = 5) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _picks(client) -> dict[str, dict]:
    r = client.get(PICKS[0])
    assert r.status_code == 200, r.text
    return {p["symbol"]: p for p in r.json()}


# ------------------------------------------------------------ ingest kinds

@pytest.mark.parametrize("kind", ["", "  ", "CANCELLED", "update", "regular"])
def test_an_unreadable_kind_is_never_standard(kind):
    assert PlayIn(source_id="x", symbol="ABCD", kind=kind).kind == "unknown"


def test_a_missing_kind_is_never_standard():
    assert PlayIn(source_id="x", symbol="ABCD").kind == "unknown"


@pytest.mark.parametrize("kind,want", [("standard", "standard"), ("STANDARD", "standard"),
                                       ("otc", "otc"), ("Conditional", "conditional"),
                                       ("unverified", "conditional")])
def test_known_kinds_still_file_as_before(kind, want):
    assert PlayIn(source_id="x", symbol="ABCD", kind=kind).kind == want


def test_a_garbled_last_buy_is_dropped_not_served():
    assert PlayIn(source_id="x", symbol="A", kind="standard",
                  last_buy_date="6/18/26").last_buy_date is None
    assert PlayIn(source_id="x", symbol="A", kind="standard",
                  last_buy_date="2026-06-18").last_buy_date == "2026-06-18"


# --------------------------------------------------------- the served note

def test_only_a_standard_play_is_served_as_reg_alert(client):
    client.post("/api/v1/plays/ingest", headers=KEY, json={"buys": [
        {"source_id": "fc:std", "symbol": "FCSTD", "kind": "standard",
         "alert_date": _today(), "last_buy_date": _soon()},
        {"source_id": "fc:blank", "symbol": "FCBLANK", "kind": "",
         "alert_date": _today()},
        {"source_id": "fc:none", "symbol": "FCNONE", "alert_date": _today()},
        {"source_id": "fc:new", "symbol": "FCNEW", "kind": "CANCELLED",
         "alert_date": _today()},
        {"source_id": "fc:otc", "symbol": "FCOTC", "kind": "otc", "alert_date": _today()},
    ]})
    picks = _picks(client)
    buys = set(_mirror_notes())
    assert picks["FCSTD"]["note"] == "Reg Alert"
    assert picks["FCSTD"]["note"].lower() in buys
    for sym in ("FCBLANK", "FCNONE", "FCNEW"):
        assert picks[sym]["note"] == "unknown alert type", sym
        assert picks[sym]["note"].lower() not in buys, f"{sym} would be auto-bought"
    assert picks["FCOTC"]["note"] == "OTC"


def test_a_stored_kind_nobody_mapped_is_served_unknown(client):
    """A row already in the database under a kind this build never heard of
    (written by a newer build, or by hand) must not fall back to Reg Alert."""
    with SessionLocal() as db:
        db.add(Play(source_id="fc:odd", symbol="FCODD", kind="mystery",
                    alert_date=_today()))
        db.commit()
    assert _picks(client)["FCODD"]["note"] == "unknown alert type"


def test_the_desktop_reads_the_served_note_as_unbuyable(client):
    """The receiving side: rsa_feed.from_pick must not turn it back into a buy."""
    sys.path.insert(0, str(REPO_ROOT))
    import rsa_feed

    client.post("/api/v1/plays/ingest", headers=KEY, json={"buys": [
        {"source_id": "fc:rt", "symbol": "FCRT", "kind": "", "alert_date": _today()},
        {"source_id": "fc:rts", "symbol": "FCRTS", "kind": "standard",
         "alert_date": _today(), "last_buy_date": _soon(3)},
    ]})
    picks = _picks(client)
    unknown = rsa_feed.from_pick(picks["FCRT"])
    assert unknown.kind == rsa_feed.UNKNOWN_KIND and not unknown.is_actionable
    std = rsa_feed.from_pick(picks["FCRTS"])
    assert std.kind == "standard" and std.last_buy_date == _soon(3)
    # And the server's unknown note is exactly the desktop's.
    assert picks["FCRT"]["note"] == rsa_feed.to_pick(unknown)["note"]


# ------------------------------------------------------------------ last_buy

def test_last_buy_reaches_the_terminal(client):
    client.post("/api/v1/plays/ingest", headers=KEY, json={"buys": [
        {"source_id": "lb:1", "symbol": "LBONE", "kind": "standard",
         "alert_date": _today(), "last_buy_date": _soon(2)},
        {"source_id": "lb:2", "symbol": "LBNONE", "kind": "standard",
         "alert_date": _today()},
    ]})
    picks = _picks(client)
    assert picks["LBONE"]["last_buy"] == _soon(2)
    # Old rows and undated alerts omit the key; older clients see three keys.
    assert "last_buy" not in picks["LBNONE"]
    assert set(picks["LBNONE"]) == {"symbol", "note", "date"}


def test_authenticated_and_public_picks_share_one_shape():
    """Both routes go through playsfeed.picks_json — the desktop can't tell
    which door answered and must not be able to."""
    from app.routes import api
    import inspect
    for fn in (api.read_picks, api.read_picks_public):
        assert "picks_json" in inspect.getsource(fn)


# ----------------------------------------------------- the picks.json seeding

def test_the_picks_file_fails_closed_and_keeps_last_buy(tmp_path):
    path = tmp_path / "picks.json"
    path.write_text(json.dumps([
        {"symbol": "PFREG", "note": "Reg Alert", "date": _today(), "last_buy": _soon(4)},
        {"symbol": "PFBLANK", "note": "", "date": _today()},
        {"symbol": "PFUNK", "note": "unknown alert type", "date": _today()},
        {"symbol": "PFCOTC", "note": "CONDITIONAL - OTC", "date": _today()},
        {"symbol": "PFBAD", "note": "Reg Alert", "date": _today(), "last_buy": "soon"},
    ]), encoding="utf-8")
    with SessionLocal() as db:
        assert playsfeed.import_picks_file(db, str(path)) == 5
        rows = {p.symbol: p for p in db.query(Play).filter(Play.symbol.like("PF%"))}
    assert rows["PFREG"].kind == "standard" and rows["PFREG"].last_buy_date == _soon(4)
    assert rows["PFBLANK"].kind == "unknown"
    assert rows["PFUNK"].kind == "unknown"
    assert rows["PFCOTC"].kind == "conditional"
    assert rows["PFBAD"].last_buy_date is None


@pytest.mark.parametrize("note,kind", [
    ("Reg Alert", "standard"), ("alert", "standard"), ("Early Access", "standard"),
    ("OTC", "otc"), ("conditional", "conditional"), ("unverified", "conditional"),
    ("", "unknown"), ("unknown alert type", "unknown"), ("whatever", "unknown"),
])
def test_kind_from_note(note, kind):
    assert playsfeed._kind_from_note(note) == kind


# ------------------------------------------------------- the alert's detail

def test_the_alert_detail_reaches_the_terminal(client):
    client.post("/api/v1/plays/ingest", headers=KEY, json={"buys": [
        {"source_id": "dt:1", "symbol": "DTFULL", "kind": "standard",
         "alert_date": _today(), "last_buy_date": _soon(2), "ratio": "1:16",
         "ratio_n": 16, "entry_price": 0.25, "est_profit": 4.75,
         "roundup_history": "100% (2/2)", "posted_at": "2026-10-09T21:30:00+00:00"},
        # What the desktop publisher sends for an alert missing everything:
        # BuyAlert's own defaults, posted_at "" included.
        {"source_id": "dt:2", "symbol": "DTBARE", "kind": "standard",
         "alert_date": _today(), "ratio": "", "ratio_n": None, "entry_price": None,
         "est_profit": None, "last_buy_date": None, "roundup_history": "",
         "posted_at": ""},
    ]})
    picks = _picks(client)
    full = picks["DTFULL"]
    assert full["last_buy"] == _soon(2)
    assert full["ratio"] == "1:16"
    assert full["entry_price"] == pytest.approx(0.25)
    assert full["est_profit"] == pytest.approx(4.75)
    assert full["roundup_history"] == "100% (2/2)"
    assert full["posted_at"].startswith("2026-10-09T21:30:00")
    # Null-safe: a bare row is exactly the old three keys, no nulls.
    assert picks["DTBARE"] == {"symbol": "DTBARE", "note": "Reg Alert", "date": _today()}


def test_the_desktop_publisher_payload_ingests_with_its_detail(client):
    """rsa_feed.FeedBatch.to_json is what publish_feed.py posts: its field
    names must be the ones /plays/ingest stores."""
    sys.path.insert(0, str(REPO_ROOT))
    import rsa_feed

    buy = rsa_feed.BuyAlert(source_id="dt:pub", symbol="DTPUB", kind="standard",
                            alert_date=_today(), ratio="1:20", ratio_n=20,
                            entry_price=0.5, est_profit=9.5, last_buy_date=_soon(1),
                            roundup_history="N/A", posted_at="2026-10-09T22:00:00+00:00")
    odd = rsa_feed.BuyAlert(source_id="dt:odd", symbol="DTODD",
                            kind=rsa_feed.UNKNOWN_KIND, alert_date=_today())
    payload = rsa_feed.FeedBatch(buys=[buy, odd]).to_json()
    r = client.post("/api/v1/plays/ingest", headers=KEY, json=payload)
    assert r.status_code == 200, r.text
    picks = _picks(client)
    assert "DTODD" not in picks, "the publisher must not send unknown-type buys"
    p = picks["DTPUB"]
    assert (p["note"], p["ratio"], p["roundup_history"], p["last_buy"]) == \
        ("Reg Alert", "1:20", "N/A", _soon(1))
    assert p["entry_price"] == 0.5 and p["est_profit"] == 9.5
    assert p["posted_at"].startswith("2026-10-09T22:00:00")
