"""Pre-launch QA fixes: buy-alert parsing, the throttles' caller identity,
HEAD on page routes, and the broker count in the site copy.

The parsing half pins the one that costs money: loose chat in the buy channel
must never come out as a play the mirror would buy.
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
sys.path.insert(0, str(WEB_ROOT))
sys.path.append(str(REPO_ROOT))  # after web/: app.py must not shadow the app package

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_qa_feed.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

import rsa_feed  # noqa: E402
from app import config  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.routes import auth as auth_routes  # noqa: E402
from app.routes import plays as plays_routes  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield
    engine.dispose()
    _TMP_DB.unlink(missing_ok=True)


@pytest.fixture(autouse=True)
def _fresh_throttles():
    plays_routes._attempts.clear()
    auth_routes._login_attempts.clear()
    yield
    plays_routes._attempts.clear()
    auth_routes._login_attempts.clear()


def _embed(ticker: str, desc: str = "STANDARD", date_: str = "6/18/26 (Thu)") -> dict:
    return {"id": "1", "timestamp": "2026-06-18T13:00:00+00:00", "embeds": [{
        "title": "\U0001f514 RSA Alert", "description": desc,
        "fields": [{"name": "\U0001f39f️ Ticker", "value": ticker},
                   {"name": "\U0001f4c5 Alert Date", "value": date_}]}]}


def _chat(text: str) -> dict:
    return {"id": "2", "timestamp": "2026-06-18T13:00:00+00:00", "content": text}


# ------------------------------------------------------------- 1. text fallback

@pytest.mark.parametrize("text, symbol", [
    ("Market opens 9:30 (ET)", "ET"),
    ("(ABCD) cancelled its reverse split - do NOT buy", "ABCD"),
    ("look at $NVDA https://example.com/nvda", "NVDA"),
])
def test_loose_chat_is_never_an_actionable_buy(text, symbol):
    buys = rsa_feed.parse_buy_message(_chat(text))
    assert [b.symbol for b in buys] == [symbol]          # still visible...
    b = buys[0]
    assert b.kind == rsa_feed.UNVERIFIED_KIND            # ...but not a play
    assert not b.is_actionable
    pick = rsa_feed.to_pick(b)
    assert pick["note"] == "unverified"


def test_unverified_note_is_not_one_the_mirror_buys():
    # Mirrors app.MIRROR_NOTES without importing the GUI module here.
    src = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    m = re.search(r"^MIRROR_NOTES = \((.*)\)$", src, re.M)
    assert m, "MIRROR_NOTES moved"
    notes = {n.strip().strip('"').lower() for n in m.group(1).split(",") if n.strip()}
    assert "unverified" not in notes
    assert rsa_feed._PICK_NOTES["standard"].lower() in notes   # sanity


def test_unverified_buys_are_not_published_to_the_cloud_feed():
    batch = rsa_feed.parse_messages(
        [_chat("Market opens 9:30 (ET)"), _embed("SBFM")], [])
    assert {b.symbol for b in batch.buys} == {"ET", "SBFM"}
    assert [b["symbol"] for b in batch.to_json()["buys"]] == ["SBFM"]


def test_a_stored_unverified_pick_round_trips_as_unverified():
    back = rsa_feed.from_pick({"symbol": "ET", "note": "unverified", "date": "2026-06-18"})
    assert back.kind == rsa_feed.UNVERIFIED_KIND
    assert rsa_feed.FeedBatch(buys=[back]).to_json()["buys"] == []


def test_real_alerts_are_still_actionable():
    (embed,) = rsa_feed.parse_buy_message(_embed("SBFM"))
    assert embed.kind == "standard" and embed.is_actionable
    typed = _chat("\U0001f514 RSA Alert\nSTANDARD\nAlert Date\n5/29/26\nTicker\nSBFM")
    (b,) = rsa_feed.parse_buy_message(typed)
    assert (b.symbol, b.kind, b.alert_date) == ("SBFM", "standard", "2026-05-29")


# ------------------------------------------------------ 2. ticker + date parsing

@pytest.mark.parametrize("raw, want", [
    ("SBFM", "SBFM"),
    ("$sbfm", "SBFM"),
    ("**SBFM**", "SBFM"),
    ("NASDAQ: ABCD", "ABCD"),
    ("NYSE:ABCD", "ABCD"),
    ("OTC: ABCD", "ABCD"),
    ("OTCMKTS: ABCDF", "ABCDF"),
    ("BRK.B", "BRK.B"),
    ("ABCD (OTC)", "ABCD"),
    ("N/A", None),
    ("n/a", None),
    ("TBD", None),
    ("None", None),
    ("", None),
    ("   ", None),
    ("ABCDEFG", None),          # 7 letters: rejected, not cut to ABCDEF
    ("TOOLONGNAME", None),
])
def test_ticker_field(raw, want):
    assert rsa_feed._ticker_from_field(raw) == want
    got = rsa_feed.parse_buy_message(_embed(raw))
    assert [b.symbol for b in got if b.kind != rsa_feed.UNVERIFIED_KIND] == ([want] if want else [])


@pytest.mark.parametrize("raw, want", [
    ("6/18/26 (Thu)", "2026-06-18"),
    ("6/18/2026", "2026-06-18"),
    ("6/18/202", None),          # 3-digit year is a typo, not the year 202
    ("6/18/20261", None),
    ("6/18/2", None),
    ("no date", None),
])
def test_rsa_date_needs_a_two_or_four_digit_year(raw, want):
    assert rsa_feed.parse_rsa_date(raw) == want


# --------------------------------------------------------------- 3. kind order

def test_conditional_wins_over_otc():
    assert rsa_feed._kind_from("CONDITIONAL - OTC", "") == "conditional"
    assert rsa_feed._kind_from("OTC", "") == "otc"
    assert rsa_feed._kind_from("STANDARD", "RSA Alert") == "standard"
    (b,) = rsa_feed.parse_buy_message(_embed("ABCD", desc="OTC CONDITIONAL"))
    assert b.kind == "conditional" and not b.is_actionable


# ------------------------------------------------------------- 6. throttles

def test_caller_identity_is_the_proxy_appended_hop():
    class R:
        def __init__(self, xff, host="10.0.0.1"):
            self.headers = {"x-forwarded-for": xff} if xff is not None else {}
            self.client = type("C", (), {"host": host})()
    assert plays_routes._client(R("6.6.6.6, 203.0.113.9")) == "203.0.113.9"
    assert plays_routes._client(R("203.0.113.9")) == "203.0.113.9"
    assert plays_routes._client(R(None)) == "10.0.0.1"


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m
    return m.group(1)


def test_plays_throttle_cannot_be_dodged_by_rotating_x_forwarded_for(monkeypatch):
    monkeypatch.setattr(config, "PLAYS_PASSWORD", "right-password")
    monkeypatch.setattr(config, "PICKS_FILE", "")
    monkeypatch.setattr(config, "PLAYS_MAX_ATTEMPTS", 3)
    c = TestClient(app)
    token = _csrf(c.get("/plays").text)
    for i in range(3):
        r = c.post("/plays", data={"password": "nope", "csrf_token": token},
                   headers={"X-Forwarded-For": f"1.2.3.{i}, 198.51.100.7"})
        assert "Wrong password" in r.text
    r = c.post("/plays", data={"password": "right-password", "csrf_token": token},
               headers={"X-Forwarded-For": "9.9.9.9, 198.51.100.7"})
    assert "Too many attempts" in r.text


def test_login_is_throttled(monkeypatch):
    monkeypatch.setattr(auth_routes, "LOGIN_MAX_ATTEMPTS", 3)
    c = TestClient(app)
    token = _csrf(c.get("/login").text)
    for i in range(3):
        r = c.post("/login", data={"email": "nobody@example.com", "password": "x",
                                   "csrf_token": token},
                   headers={"X-Forwarded-For": f"1.2.3.{i}, 198.51.100.8"})
        assert "Wrong email or password" in r.text
    r = c.post("/login", data={"email": "nobody@example.com", "password": "x",
                               "csrf_token": token},
               headers={"X-Forwarded-For": "5.5.5.5, 198.51.100.8"})
    assert "Too many attempts" in r.text
    # A different real caller is unaffected.
    r = c.post("/login", data={"email": "nobody@example.com", "password": "x",
                               "csrf_token": token},
               headers={"X-Forwarded-For": "198.51.100.99"})
    assert "Wrong email or password" in r.text


# ------------------------------------------------------------------ 7. HEAD

@pytest.mark.parametrize("path", ["/", "/pricing", "/how-it-works", "/login", "/plays"])
def test_page_routes_answer_head(path):
    c = TestClient(app)
    get = c.get(path, follow_redirects=False)
    head = c.head(path, follow_redirects=False)
    assert head.status_code == get.status_code == 200
    assert head.content == b""
    assert head.headers.get("content-type") == get.headers.get("content-type")


def test_head_on_a_post_only_route_is_still_refused():
    assert TestClient(app).head("/plays/lock").status_code == 405


# ------------------------------------------------------------- 8. broker count

def test_site_copy_counts_eleven_brokerages():
    # Only claims about what is SUPPORTED. "Ten accounts" in the worked
    # example ($47.50) is the scenario, not the broker count, and stays.
    c = TestClient(app)
    stale = ("across ten brokerages at once", "Ten brokerages, one button",
             "Ten brokerages. Ten shots", "across all ten", "All ten brokerages",
             "Ten brokerages supported", "ten brokers, buy")
    for path in ("/", "/pricing", "/how-it-works"):
        html = c.get(path).text
        for phrase in stale:
            assert phrase not in html, (path, phrase)
    assert "IBKR" in c.get("/pricing").text
    assert "<span>IBKR</span>" in c.get("/").text


# ---------------------------------------------- server never promotes a kind

def test_server_files_unknown_kind_as_watch_only():
    from app.routes.api import PlayIn
    from app.playsfeed import _kind_from_note
    assert PlayIn(source_id="a", symbol="ABCD", kind="unverified").kind == "conditional"
    assert PlayIn(source_id="a", symbol="ABCD", kind="").kind == "unknown"
    assert PlayIn(source_id="a", symbol="ABCD").kind == "unknown"
    assert PlayIn(source_id="a", symbol="ABCD", kind="OTC").kind == "otc"
    assert _kind_from_note("unverified") == "conditional"
    assert _kind_from_note("Reg Alert") == "standard"
