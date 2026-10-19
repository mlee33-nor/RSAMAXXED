"""The LOW ODDS alert type and a conditional's share count, server side.

'🚧 RSA Alert' / 'LOW ODDS' is filed as its own kind (it used to be unknown),
served to terminals as the "Low Odds" note -- which a mirror buys only when its
owner ticked "Buy low odds" -- and shown on the board with its own tag. A
conditional's Strategy ('5 Shares/Account') is served as `shares`.
"""

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from app.models import LOW_ODDS_KIND, Play, pick_note, shares_per_account
from app.playsfeed import _kind_from_note
from app.routes.api import PlayIn


def test_low_odds_is_filed_and_served_as_its_own_kind():
    assert PlayIn(source_id="x", symbol="KNDI", kind="low_odds").kind == LOW_ODDS_KIND
    assert pick_note(LOW_ODDS_KIND) == "Low Odds"
    assert _kind_from_note("Low Odds") == LOW_ODDS_KIND
    assert _kind_from_note("conditional") == "conditional"


def test_low_odds_is_not_actionable_for_everyone():
    assert not Play(symbol="KNDI", kind=LOW_ODDS_KIND).is_actionable


def test_shares_come_from_the_strategy():
    assert Play(symbol="ALP", kind="conditional", strategy="25 Shares/Account").shares == 25
    assert Play(symbol="AAA", kind="standard", strategy="1 Share/Account").shares == 1
    assert Play(symbol="AAA", kind="standard", strategy="").shares is None
    assert shares_per_account("1.5 Shares/Account") is None


def test_picks_feed_sends_a_share_count_for_conditionals_only():
    """QA #3: a row first stored CONDITIONAL '5 Shares/Account' and served
    as anything else must never carry 5 to a terminal."""
    from test_fix4_picks_collapse import _board, _play
    from app import playsfeed

    cond = _play(1, "1:0", "conditional", 0, symbol="ALP")
    cond.strategy = "5 Shares/Account"
    std = _play(2, "2:0", "standard", 0, symbol="AAA")
    std.strategy = "5 Shares/Account"
    low = _play(3, "3:0", LOW_ODDS_KIND, 0, symbol="KNDI")
    low.strategy = "1 Share/Account"
    out = {p["symbol"]: p for p in playsfeed.picks_json(_board(cond, std, low))}
    assert out["ALP"]["shares"] == 5 and out["ALP"]["note"] == "conditional"
    assert "shares" not in out["AAA"] and "shares" not in out["KNDI"]
    assert out["KNDI"]["note"] == "Low Odds"
