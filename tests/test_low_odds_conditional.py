"""LOW ODDS is its own alert type; conditionals are hand buys at their size.

The BUY channel posts several kinds of RSA Alert. Two of them were misread:

  * '🚧 RSA Alert' / 'LOW ODDS' (BTOC 10/9, KNDI 10/13) fell through to
    "unknown alert type", and BTOC ended up labelled conditional. It is a
    declared split with a poor round-up record, not a conditional. Mirror
    buys it (1 share) only while "Buy low odds" is ticked.
  * '📝 RSA Alert' / 'CONDITIONAL' says '5 Shares/Account' (or 25, or 75) in
    its Strategy field. Mirror never buys it; the app tells the user how many
    shares to buy by hand and pre-fills that count.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as A
import rsa_feed
from test_mirror_fixes_2026_10 import Mirror, Var, env, pick, _sync_threads  # noqa: F401


def _embed(desc, title, ticker, strategy="1 Share/Account", price="$0.2151"):
    return {"id": "1558235336100806719",
            "timestamp": "2026-10-09T21:50:54.739000+00:00",
            "embeds": [{"title": title, "description": desc, "fields": [
                {"name": "📅 Alert Date", "value": "10/9/26 (Fri)"},
                {"name": "🎟️ Ticker", "value": ticker},
                {"name": "⚖️ Ratio", "value": "1:16"},
                {"name": "🏷️ Current Share Price", "value": price},
                {"name": "💸 Potential Profit/Acct", "value": "$3.23"},
                {"name": "⌛ Last Day to Buy", "value": "10/14/26 (Wed)"},
                {"name": "📉 Low Odds Round-Up Tracker", "value": "2.00% (1/50)"},
                {"name": "🧠 Strategy", "value": strategy},
            ]}]}


# ------------------------------------------------------------------ parsing

def test_low_odds_alert_is_its_own_kind_not_conditional_or_unknown():
    [b] = rsa_feed.parse_buy_message(_embed("LOW ODDS", "🚧 RSA Alert", "BTOC"))
    assert b.kind == rsa_feed.LOW_ODDS_KIND
    p = rsa_feed.to_pick(b)
    assert p["note"] == "Low Odds" and p["shares"] == 1
    # Published to the cloud (it is a real alert), unlike unknown types.
    assert [x["kind"] for x in rsa_feed.FeedBatch(buys=[b]).to_json()["buys"]] == ["low_odds"]


def test_conditional_carries_its_share_count():
    [b] = rsa_feed.parse_buy_message(
        _embed("CONDITIONAL", "📝 RSA Alert", "ALP", strategy="25 Shares/Account"))
    assert b.kind == "conditional" and b.shares == 25
    p = rsa_feed.to_pick(b)
    assert p["note"] == "conditional" and p["shares"] == 25
    # Round trip: the share count survives picks.json -> BuyAlert.
    assert rsa_feed.from_pick(p).shares == 25


@pytest.mark.parametrize("text,want", [
    ("1 Share/Account", 1), ("5 Shares/Account", 5), ("75 shares / account", 75),
    ("buy 3 shares", 3), ("", None), ("N/A", None), ("0 Shares/Account", None),
    ("1.5 Shares/Account", None),
])
def test_shares_per_account(text, want):
    assert rsa_feed.shares_per_account(text) == want


def test_the_track_board_construction_glyph_is_low_odds():
    rows = rsa_feed.parse_lifecycle_message(
        {"content": "🚧 10/9 - BTOC 🆕\n📝 9/3 - ALP ⏳"})
    kinds = {r.symbol: r.kind for r in rows}
    assert kinds == {"BTOC": "low_odds", "ALP": "conditional"}


def test_conditional_otc_stays_conditional_and_low_odds_beats_otc():
    assert rsa_feed._kind_from("CONDITIONAL - OTC", "") == "conditional"
    assert rsa_feed._kind_from("LOW ODDS", "OTC") == "low_odds"


# ------------------------------------------------------------- mirror gate

LOW = {"symbol": "KNDI", "date": "2026-10-09", "note": "Low Odds", "shares": 1}
COND = {"symbol": "ALP", "date": "2026-10-09", "note": "conditional", "shares": 5}


@pytest.mark.parametrize("p,low,want", [
    (LOW, False, False), (LOW, True, True),
    (COND, False, False), (COND, True, False),          # never auto-bought
    ({"note": "Reg Alert"}, False, True),
    ({"note": "OTC"}, True, False),
    ({"note": "unknown alert type"}, True, False),
    (dict(LOW, held="Reg Alert"), True, False),
])
def test_mirror_wants_pick(p, low, want):
    assert A._mirror_wants_pick(p, low) is want


def test_mirror_only_ever_buys_one_share():
    assert A._mirror_buy_qty({"note": "Reg Alert"}) == (1, "")
    assert A._mirror_buy_qty({"note": "Reg Alert", "shares": 1}) == (1, "")
    assert A._mirror_buy_qty(LOW) == (1, "")
    # A count other than 1 on anything mirror would buy is a hand buy.
    n, why = A._mirror_buy_qty({"note": "Reg Alert", "shares": 5})
    assert n is None and "by hand" in why


def test_conditional_tells_the_user_how_many_to_buy():
    assert A._conditional_buy_text(COND) == "buy 5 shares/account by hand"
    assert A._conditional_buy_text(dict(COND, shares=1)) == "buy 1 share/account by hand"
    assert "no share count" in A._conditional_buy_text({"note": "conditional"})
    assert "5 shares/account" in A._mirror_skip_reason("conditional", 5)
    # Only a conditional is sized: a Reg Alert's stray count is ignored.
    assert A._conditional_shares({"note": "Reg Alert", "shares": 5}) is None


def test_opt_in_reads_missing_or_broken_vars_as_off():
    class Broken:
        def get(self):
            raise RuntimeError
    app = type("X", (), {})()
    assert A._mirror_opt_in(app) is False
    app._mirror_buy_low_odds = Broken()
    assert A._mirror_opt_in(app) is False


# ------------------------------------------------------------- check + launch

def _check(m, monkeypatch, picks):
    _sync_threads(monkeypatch)
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: list(picks))
    scans = []
    monkeypatch.setattr(A.mirror_journal, "record_scan", lambda **kw: scans.append(kw))
    queued = []
    m._mirror_execute = lambda new, *a, **k: queued.extend(new)
    Mirror._mirror_check_now(m, "10:45")
    m.run_lambdas()
    return [p["symbol"] for p in queued], scans[-1]["skipped"]


def test_check_buys_low_odds_only_when_ticked_and_never_a_conditional(env, monkeypatch):
    picks = [pick("AAA"), pick("KNDI", note="Low Odds"),
             dict(pick("ALP", note="conditional"), shares=5)]
    m = Mirror(brokers=("public",))
    got, skipped = _check(m, monkeypatch, picks)
    assert got == ["AAA"]
    reasons = {s["symbol"]: s["reason"] for s in skipped}
    assert "Buy low odds" in reasons["KNDI"]
    assert "buy 5 shares/account by hand" in reasons["ALP"]

    m = Mirror(brokers=("public",))
    m._mirror_buy_low_odds = Var(True)
    got, _ = _check(m, monkeypatch, picks)
    assert got == ["AAA", "KNDI"]


def test_check_skips_a_reg_alert_that_asks_for_more_than_one(env, monkeypatch):
    m = Mirror(brokers=("public",))
    got, skipped = _check(m, monkeypatch, [dict(pick("AAA"), shares=5)])
    assert got == [] and "mirror only buys 1" in skipped[0]["reason"]


def _launch(m, p, current=None):
    sent = []
    m._run_in_thread = lambda _t, broker, _side, symbol, qty, *a: sent.append((broker, symbol, qty))
    m._quick_picks = [current if current is not None else p]
    Mirror._mirror_launch_pick(m, dict(p, _when="10:45"))
    return sent


def test_a_low_odds_pick_launches_one_share(env):
    m = Mirror(brokers=("public",))
    m._mirror_buy_low_odds = Var(True)
    assert _launch(m, dict(pick("KNDI", note="Low Odds"), shares=1)) == [("public", "KNDI", "1")]
    assert m.batches[-1]["mirror_note"] == "Low Odds"


def test_unticking_the_box_stops_a_queued_pick(env):
    m = Mirror(brokers=("public",))
    m._mirror_buy_low_odds = Var(False)
    assert _launch(m, dict(pick("KNDI", note="Low Odds"), shares=1)) == []
    assert any("Buy low odds" in line for line in m.logs)


def test_a_queued_pick_turned_conditional_is_not_sent(env):
    """Queued as a Reg Alert, re-posted CONDITIONAL 5 Shares/Account: held,
    and never sent at 1 or at 5."""
    m = Mirror(brokers=("public",))
    queued = pick("ALP")
    live = dict(queued, note="conditional", shares=5)
    assert _launch(m, queued, current=live) == []


def test_a_reg_alert_is_never_sent_at_a_count_from_the_queue(env):
    """The live row is a Reg Alert; a stale queued entry carrying 5 must not
    size the order (QA #1)."""
    m = Mirror(brokers=("public",))
    live = pick("ALP")
    queued = dict(live, shares=5)
    assert _launch(m, queued, current=live) == [("public", "ALP", "1")]


# ------------------------------------------------------------- merge + state

def test_shares_is_only_carried_between_rows_of_the_same_type():
    std = {"symbol": "ALP", "date": "2026-10-09", "note": "Reg Alert"}
    cond = dict(COND)
    assert "shares" not in A._carry_pick_extras([std], [cond])[0]
    same = {"symbol": "ALP", "date": "2026-10-09", "note": "conditional"}
    assert A._carry_pick_extras([same], [cond])[0]["shares"] == 5


def test_the_low_odds_box_persists(env, tmp_path):
    m = Mirror()
    m._mirror_buy_low_odds = Var(True)
    Mirror._save_mirror_state(m)
    saved = Mirror._load_mirror_state(m)
    assert saved["buy_low_odds"] is True and "buy_conditional" not in saved


def test_row_status():
    today = A._mirror_today()
    off = (True, frozenset(), (), (), frozenset(), 2, False)
    on = off[:6] + (True,)
    p = dict(LOW, date=today.isoformat())
    assert "Buy low odds" in A.App._pick_mirror_status(p, "KNDI", p["date"], 0, off, today)[0]
    assert "low odds" not in A.App._pick_mirror_status(p, "KNDI", p["date"], 0, on, today)[0].lower()
    # An older 6-field snapshot still works and reads as "box off".
    assert (A.App._pick_mirror_status(p, "KNDI", p["date"], 0, off[:6], today)
            == A.App._pick_mirror_status(p, "KNDI", p["date"], 0, off, today))
    # A conditional says how many to buy -- with mirror OFF too.
    c = dict(COND, date=today.isoformat())
    mirror_off = (False,) + off[1:]
    txt, _col = A.App._pick_mirror_status(c, "ALP", c["date"], 0, mirror_off, today)
    assert txt == "conditional — buy 5 shares/account by hand"
    # ...but not once it is bought somewhere.
    assert A.App._pick_mirror_status(c, "ALP", c["date"], 2, mirror_off, today) == ("", "")


def test_note_badges_tell_low_odds_and_conditional_apart():
    styles = A.App._NOTE_STYLE
    assert styles["low odds"][0] == "LOW ODDS" and styles["conditional"][0] == "CONDITIONAL"
    assert styles["low odds"][1] != styles["conditional"][1]


def test_paste_box_reads_low_odds_and_a_conditional_size():
    got = A.App._parse_alert_picks("LOW ODDS (KNDI)\nCONDITIONAL - buy 5 shares (ALP)")
    by = {p["symbol"]: p for p in got}
    assert by["KNDI"]["note"] == "Low Odds"
    assert A._pick_is_conditional(by["ALP"]) and by["ALP"]["shares"] == 5


# ------------------------------------------------------------- re-import

def test_a_stored_unknown_or_conditional_is_relabelled_low_odds(monkeypatch):
    """BTOC was stored as "conditional", KNDI as "unknown alert type": the
    next pull reads both as LOW ODDS and the stored rows follow."""
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    m = Mirror()
    m._quick_picks = [{"symbol": "BTOC", "date": "2026-10-09", "note": "conditional"},
                      {"symbol": "KNDI", "date": "2026-10-13", "note": "unknown alert type"}]
    m._extract_picks_from_message = lambda msg: [msg]
    Mirror._import_picks_from_messages(m, [
        {"symbol": "BTOC", "date": "2026-10-09", "note": "Low Odds", "shares": 1},
        {"symbol": "KNDI", "date": "2026-10-13", "note": "Low Odds", "shares": 1}])
    assert {p["symbol"]: p["note"] for p in m.persisted[-1]} == {
        "BTOC": "Low Odds", "KNDI": "Low Odds"}


def test_relabelling_never_touches_a_hold_or_a_bought_play(monkeypatch):
    m = Mirror()
    held = {"symbol": "HLD", "date": "2026-10-09", "note": "unknown alert type",
            "held": "Reg Alert"}
    bought = {"symbol": "BOT", "date": "2026-10-09", "note": "conditional", "shares": 5}
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: {("BOT", "2026-10-09")})
    m._quick_picks = [held, bought]
    m._extract_picks_from_message = lambda msg: [msg]
    Mirror._import_picks_from_messages(m, [
        {"symbol": "HLD", "date": "2026-10-09", "note": "Low Odds"},
        {"symbol": "BOT", "date": "2026-10-09", "note": "Low Odds"}])
    assert m.persisted == []          # nothing changed, nothing written
