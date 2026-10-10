"""fix4 N5/N6: /plays/picks serves ONE row per play, its latest post.

One play can be stored several times (insert-only ingest): the CONDITIONAL and
the STANDARD that upgraded it, a STANDARD and the cancel that called it off
(published as watch-only "conditional"), the message row and the desktop's
picks:SYM:DATE copy. Every row used to be served, and a terminal kept
whichever it read first.
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEB_ROOT))

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_fix4_collapse.sqlite3"
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP_DB.as_posix()}")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from app import playsfeed  # noqa: E402
from app.models import Play  # noqa: E402

DAY = date.today().isoformat()
LAST = (date.today() + timedelta(days=3)).isoformat()


def _play(i, source, kind, minutes, symbol="BTOC", last=LAST):
    return Play(id=i, source_id=source, symbol=symbol, kind=kind, alert_date=DAY,
                last_buy_date=last,
                posted_at=datetime(2026, 10, 9, 21, 0, tzinfo=timezone.utc)
                + timedelta(minutes=minutes))


def _board(*plays):
    lives = [playsfeed.PlayLife(play=p) for p in plays]
    b = playsfeed.Board()
    b.history = list(lives)
    b.open_plays = list(lives)
    return b


def test_a_later_cancel_is_served_not_the_reg_alert():
    board = _board(_play(1, "100:0", "standard", 0), _play(2, "200:0", "conditional", 30))
    out = playsfeed.picks_json(board)
    assert [(p["symbol"], p["note"]) for p in out] == [("BTOC", "conditional")]


def test_a_conditional_upgraded_to_standard_serves_the_standard():
    # Order in the list must not matter: open_plays is sorted by deadline.
    board = _board(_play(2, "200:0", "standard", 30), _play(1, "100:0", "conditional", 0))
    assert [p["note"] for p in playsfeed.picks_json(board)] == ["Reg Alert"]
    board = _board(_play(1, "100:0", "conditional", 0), _play(2, "200:0", "standard", 30))
    assert [p["note"] for p in playsfeed.picks_json(board)] == ["Reg Alert"]


def test_a_stale_picks_row_never_outranks_the_message_rows():
    # The picks: copy was frozen at "conditional"; the message upgraded it.
    board = _board(_play(1, "100:0", "conditional", 0),
                   _play(3, f"picks:BTOC:{DAY}", "conditional", 90),
                   _play(2, "200:0", "standard", 30))
    assert [p["note"] for p in playsfeed.picks_json(board)] == ["Reg Alert"]


def test_other_plays_are_untouched():
    board = _board(_play(1, "100:0", "standard", 0),
                   _play(2, "101:0", "standard", 0, symbol="ZZZ"))
    assert sorted(p["symbol"] for p in playsfeed.picks_json(board)) == ["BTOC", "ZZZ"]


def test_a_latest_post_that_is_closed_closes_the_play():
    closed = _play(2, "200:0", "conditional", 30,
                   last=(date.today() - timedelta(days=1)).isoformat())
    std = _play(1, "100:0", "standard", 0)
    lives = [playsfeed.PlayLife(play=std), playsfeed.PlayLife(play=closed)]
    b = playsfeed.Board()
    b.history = list(lives)
    b.open_plays = [lives[0]]
    assert playsfeed.picks_json(b) == []
