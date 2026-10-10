"""fix4: round-2 adversarial audit of the BUY path, one test (or more) per
finding. Ported from the auditor's repros, each flipped to assert the right
behaviour.

N1  whole pick handed back while a wedged broker still owed it: the owed
    launch re-marked it executed and the other brokers were never retried.
N2  feed refresh vs alert import: unlocked read-merge-write of picks.json.
N3  _prune_stale_picks aged by the calendar while mirror ages in sessions.
N4  the failed note said "not retried, handle it manually" about owed legs.
N5  a later CANCELLED / conditional post never held a stored Reg Alert.
N6  duplicate rows for one play; the desktop merge kept whichever came first.
N7  whole-pick re-send on a permanent refusal.
N8  last_buy overrides the age limit: the UI says so.
N9  NYSE holidays by rule for any year.
LOW an offline cloud fetch spent the scheduled slot.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A  # noqa: E402
import rsa_feed  # noqa: E402
import test_mirror_fixes_2026_10 as MF  # noqa: E402
from test_mirror_fixes_2026_10 import env  # noqa: E402,F401
from modules import market_calendar as mc  # noqa: E402


class M(MF.Mirror):
    _mirror_nudge_drain = A.App._mirror_nudge_drain
    _mirror_pick_needs = A.App._mirror_pick_needs
    _mirror_slot_failed = A.App._mirror_slot_failed
    _mirror_stop_retrying = A.App._mirror_stop_retrying
    _extract_picks_from_message = A.App._extract_picks_from_message

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._mirror_owed = []
        self._mirror_wedged = {}
        self.cancelled = []

    def after_cancel(self, h):
        self.cancelled.append(h)

    def _save_mirror_state(self):
        pass


def _res(broker, ok=0, errors=(), accounts=()):
    return {"broker": broker, "ok_accounts": ok,
            "fail_accounts": 0 if ok else 1, "shares": float(ok),
            "errors": list(errors), "accounts": list(accounts)}


def _run_all(m):
    """Fire every scheduled callback (after(0, fn) included), repeatedly."""
    for _ in range(10):
        due, m.scheduled = m.scheduled, []
        if not due:
            return
        for _ms, cb in due:
            if callable(cb) and getattr(cb, "__name__", "") != "_mirror_drain":
                cb()


# ===================================================================== N1

def test_owed_launch_never_buries_the_other_brokers_retry(env):
    m = M(brokers=("public", "robinhood", "fidelity"))
    stuck = {"symbol": "OLD", "pending": {"fidelity"}, "finished": False}
    m._mirror_wedged = {"fidelity": stuck}
    p = {"symbol": "AAA", "date": MF.TODAY.isoformat(), "note": "Reg Alert"}
    key = A.App._mirror_key(p)
    A.App._mirror_launch_pick(m, dict(p))
    assert sorted(m.launched) == [("public", "AAA"), ("robinhood", "AAA")]
    assert [o["broker"] for o in m._mirror_owed] == ["fidelity"]
    b1 = m.batches[-1]
    assert b1["mirror_split"] is True
    b1["results"] = [_res("public", errors=["Login failed"]),
                     _res("robinhood", errors=["Login failed"])]
    A.App._mirror_record_outcome(m, b1, 0, 2)
    # The whole pick is NOT handed back: fidelity still owes it.
    assert key in m._mirror_executed
    assert not any("try again at the next check" in l for l in m.logs)
    owed = {o["broker"]: o for o in m._mirror_owed}
    assert set(owed) == {"fidelity", "public", "robinhood"}
    assert owed["public"]["attempts"] == "1" and owed["public"].get("after")

    # fidelity reports back on OLD; the drain releases ITS owed leg only.
    stuck["finished"] = True
    b1["finished"] = True
    m._mirror_active = []
    m._brokers_in_flight = set()
    A.App._mirror_drain(m)
    assert m.launched[-1] == ("fidelity", "AAA")
    b2 = m.batches[-1]
    b2["results"] = [_res("fidelity", ok=1)]
    b2["finished"] = True
    A.App._mirror_record_outcome(m, b2, 1, 0)
    # public / robinhood are still owed -- not forfeited behind "already executed".
    assert {o["broker"] for o in m._mirror_owed} == {"public", "robinhood"}

    # Their back-off passes: the next drain sends them, one broker each.
    for o in m._mirror_owed:
        o["after"] = "2000-01-01T00:00:00"
    m._mirror_active = []
    m._brokers_in_flight = set()
    sent = []
    for _ in range(4):
        A.App._mirror_drain(m)
        for b in m._mirror_active:
            b["finished"] = True
        m._brokers_in_flight = set()
        sent = [x for x in m.launched if x[1] == "AAA" and x[0] != "fidelity"]
        if len(sent) >= 4:
            break
    assert sorted(sent[-2:]) == [("public", "AAA"), ("robinhood", "AAA")]


def test_an_owed_leg_whose_order_may_exist_is_never_sent_again(env):
    m = M(brokers=("public", "fidelity"))
    key = (MF.TODAY.isoformat(), "AAA")
    m._mirror_executed.add(key)
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["fidelity"],
         "mirror_skipped": [], "mirror_owed": "fidelity", "mirror_owed_attempts": 0,
         "mirror_run": "r",
         "results": [_res("fidelity", accounts=[{
             "account_id": "X1", "ok": False,
             "message": "order submitted but not confirmed — verify at the broker"}])]}
    A.App._mirror_record_outcome(m, b, 0, 1)
    assert m._mirror_owed == []
    assert key in m._mirror_executed and key in m._mirror_failed
    assert "verify" in m._mirror_failed_notes[key]


def test_a_lone_launch_that_sent_nothing_is_still_handed_back(env):
    """No owed leg anywhere: the old whole-pick hand-back still applies."""
    m = M(brokers=("public", "robinhood"))
    p = {"symbol": "AAA", "date": MF.TODAY.isoformat(), "note": "Reg Alert"}
    key = A.App._mirror_key(p)
    A.App._mirror_launch_pick(m, dict(p))
    b = m.batches[-1]
    assert b["mirror_split"] is False
    b["results"] = [_res("public", errors=["Login failed"]),
                    _res("robinhood", errors=["Login failed"])]
    A.App._mirror_record_outcome(m, b, 0, 2)
    assert key not in m._mirror_executed
    assert m._mirror_owed == []


# ===================================================================== N2

def test_refresh_racing_an_import_keeps_the_new_pick(monkeypatch, tmp_path):
    pf = tmp_path / "picks.json"
    monkeypatch.setattr(A, "PICKS_FILE", pf)
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    old = {"symbol": "OLD", "note": "Reg Alert", "date": A._mirror_today().isoformat()}
    new = {"symbol": "NEW", "note": "Reg Alert", "date": A._mirror_today().isoformat()}
    pf.write_text(json.dumps([old]))

    def cloud():          # the GET is in flight; the import lands meanwhile
        pf.write_text(json.dumps([old, new]))
        return [old]
    monkeypatch.setattr(A, "_cloud_picks", cloud)
    A._fetch_quick_picks()
    on_disk = json.loads(pf.read_text())
    assert sorted(p["symbol"] for p in on_disk) == ["NEW", "OLD"]


def test_one_lock_guards_both_writers():
    import inspect
    assert "_PICKS_LOCK" in inspect.getsource(A._fetch_quick_picks)
    assert "_PICKS_LOCK" in inspect.getsource(A.App._persist_picks)
    assert "_PICKS_LOCK" in inspect.getsource(A.App._import_picks_from_messages)


# ===================================================================== N3

def test_prune_counts_trading_days(monkeypatch):
    """A Thursday alert is 4 sessions old the next Wednesday -- which mirror
    may still buy -- and must not be deleted first by the calendar."""
    pk = {"symbol": "THU", "date": "2026-10-08", "note": "Reg Alert"}
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    for today, kept in ((date(2026, 10, 13), True), (date(2026, 10, 14), True),
                        (date(2026, 10, 15), False)):
        monkeypatch.setattr(A, "_mirror_today", lambda t=today: t)
        out, removed = A._prune_stale_picks([pk])
        assert (out == [pk]) is kept and removed == (0 if kept else 1), today
    assert A._pick_fresh_trading(pk, 4, date(2026, 10, 14))


def test_prune_keeps_a_pick_until_its_last_day(monkeypatch):
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    monkeypatch.setattr(A, "_mirror_today", lambda: date(2026, 10, 16))
    pk = {"symbol": "LB", "date": "2026-10-08", "note": "Reg Alert",
          "last_buy": "2026-10-16"}
    assert A._prune_stale_picks([pk]) == ([pk], 0)
    monkeypatch.setattr(A, "_mirror_today", lambda: date(2026, 10, 19))
    assert A._prune_stale_picks([pk]) == ([], 1)


# ======================================================= last_buy (kept)

def test_customer_btoc_monday_once(env, monkeypatch):
    srv = [{"symbol": "BTOC", "note": "Reg Alert", "date": "2026-10-09",
            "last_buy": "2026-10-14"}]
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: [dict(x) for x in srv])
    monkeypatch.setattr(A, "_mirror_today", lambda: date(2026, 10, 12))
    monkeypatch.setattr(A.mirror_journal, "record_scan", lambda **k: None)

    class T:
        def __init__(self, target, daemon=True):
            self.t = target

        def start(self):
            self.t()
    monkeypatch.setattr(A.threading, "Thread", T)
    m = M(brokers=("public", "robinhood"))
    A.App._mirror_check_now(m, "09:45", slot_key="2026-10-12@09:45")
    m.run_lambdas()
    assert sorted(m.launched) == [("public", "BTOC"), ("robinhood", "BTOC")]
    m.launched.clear()
    m._mirror_active = []
    A.App._mirror_check_now(m, "10:45", slot_key="2026-10-12@10:45")
    m.run_lambdas()
    assert m.launched == []
    assert A._pick_fresh_trading(srv[0], 2, date(2026, 10, 14))
    assert not A._pick_fresh_trading(srv[0], 2, date(2026, 10, 15))


def test_btoc_without_last_buy_monday(env):
    pk = {"symbol": "BTOC", "note": "Reg Alert", "date": "2026-10-09"}
    assert A._pick_fresh_trading(pk, 2, date(2026, 10, 12))
    assert A._pick_fresh_trading(pk, 2, date(2026, 10, 13))
    assert not A._pick_fresh_trading(pk, 2, date(2026, 10, 14))


# ===================================================================== N4

def test_failed_note_leaves_out_the_owed_leg(env):
    m = M(brokers=("public", "sofi"))
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["public", "sofi"],
         "mirror_skipped": [], "mirror_owed": "", "mirror_owed_attempts": 0,
         "mirror_run": "r", "results": [_res("public", errors=["Login failed"]),
                                         _res("sofi", errors=["HTTP 502: Bad Gateway"])]}
    A.App._mirror_record_outcome(m, b, 0, 2)
    assert [o["broker"] for o in m._mirror_owed] == ["public"]
    assert key in m._mirror_failed
    pub = rsa_feed.normalize_broker("public")
    sofi = rsa_feed.normalize_broker("sofi")
    [detail] = [l for l in m.logs if "not retried" in l]
    head = detail.split("not retried")[0]
    assert sofi in head and pub not in head, detail
    assert f"{pub}: no order was placed there" in detail
    assert "retries it automatically" in detail and "Stop retrying" in detail
    assert "retrying automatically" in m._mirror_failed_notes[key]


def test_stop_retrying_and_mark_done_cancel_the_owed_retry(env, monkeypatch):
    m = M(brokers=("public", "sofi"))
    A._mirror_owe(m, "public", {"symbol": "AAA", "date": "2026-10-09"}, attempts=1)
    A._mirror_owe(m, "sofi", {"symbol": "BBB", "date": "2026-10-09"}, attempts=1)
    A.App._mirror_stop_retrying(m, ("2026-10-09", "AAA"))
    assert [o["symbol"] for o in m._mirror_owed] == ["BBB"]

    # Mark done (the Partial tab's escape hatch) does the same.
    m._log = lambda *a, **k: None
    m._render_quick_picks = lambda *a: None
    m._switch_picks_tab = lambda *a: None
    monkeypatch.setattr(A, "_save_done_picks", lambda done: None)
    A.App._mark_pick_done(m, "BBB", "2026-10-09")
    assert m._mirror_owed == []


# ===================================================================== N5

def _emb(mid, desc, ts="2026-10-09T21:50:00+00:00"):
    return {"id": mid, "timestamp": ts,
            "embeds": [{"title": "RSA Alert", "description": desc,
                        "fields": [{"name": "Ticker", "value": "BTOC"},
                                   {"name": "Alert Date", "value": "10/9/26 (Fri)"}]}]}


@pytest.mark.parametrize("order", ["oldest_first", "newest_first"])
def test_a_later_cancel_holds_the_reg_alert(env, monkeypatch, order):
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: [])
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    m = M()
    msgs = [_emb("1", "STANDARD", "2026-10-09T21:50:00+00:00"),
            _emb("2", "CANCELLED", "2026-10-09T22:10:00+00:00")]
    if order == "newest_first":
        msgs.reverse()                       # what the API actually returns
    added = A.App._import_picks_from_messages(m, msgs)
    assert added == []                       # nothing buyable was imported
    [final] = m.persisted[-1]
    assert final["note"] != "Reg Alert" and not A._pick_actionable(final)
    assert final["held"] == "Reg Alert"
    assert m._feed_held_keys == {("2026-10-09", "BTOC")}
    _run_all(m)
    assert any(kind == "error" and "ON HOLD" in msg for msg, kind in m.notes)


def test_a_reread_of_the_older_conditional_changes_nothing(env, monkeypatch):
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    m = M()
    m._quick_picks = [{"symbol": "BTOC", "date": "2026-10-09", "note": "Reg Alert",
                       "posted_at": "2026-10-09T22:00:00+00:00"}]
    A.App._import_picks_from_messages(
        m, [_emb("1", "CONDITIONAL", "2026-10-09T20:00:00+00:00")])
    assert m.persisted == []


def test_a_bought_play_is_not_rewritten_but_the_user_is_told(env, monkeypatch):
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: {("BTOC", "2026-10-09")})
    m = M()
    m._quick_picks = [{"symbol": "BTOC", "date": "2026-10-09", "note": "Reg Alert",
                       "posted_at": "2026-10-09T21:00:00+00:00"}]
    A.App._import_picks_from_messages(
        m, [_emb("2", "CANCELLED", "2026-10-09T22:00:00+00:00")])
    assert m.persisted == []
    _run_all(m)
    assert any("already bought" in msg for msg, _k in m.notes)


def test_a_hold_stops_owed_legs_and_queued_launches(env, monkeypatch):
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    m = M(brokers=("public",))
    key = ("2026-10-09", "BTOC")
    m._quick_picks = [{"symbol": "BTOC", "date": "2026-10-09", "note": "Reg Alert",
                       "posted_at": "2026-10-09T21:00:00+00:00"}]
    A._mirror_owe(m, "public", {"symbol": "BTOC", "date": "2026-10-09"}, attempts=1)
    m._mirror_queue = [{"symbol": "BTOC", "date": "2026-10-09", "note": "Reg Alert"}]
    A.App._import_picks_from_messages(
        m, [_emb("2", "CANCELLED", "2026-10-09T22:00:00+00:00")])
    _run_all(m)
    assert m._mirror_owed == [] and m._mirror_queue == []
    # And a launch that got there anyway reads the current (held) pick.
    m._quick_picks = m.persisted[-1]
    assert A.App._mirror_launch_pick(m, {"symbol": "BTOC", "date": "2026-10-09",
                                          "note": "Reg Alert"}) is None
    assert m.launched == []
    assert key not in m._mirror_executed


def test_a_later_standard_lifts_a_hold(env, monkeypatch):
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    m = M()
    m._quick_picks = [{"symbol": "BTOC", "date": "2026-10-09", "note": "unknown alert type",
                       "held": "Reg Alert", "posted_at": "2026-10-09T22:00:00+00:00"}]
    added = A.App._import_picks_from_messages(
        m, [_emb("3", "STANDARD", "2026-10-10T13:00:00+00:00")])
    assert [p["note"] for p in added] == ["Reg Alert"]
    assert "held" not in m.persisted[-1][0]


def test_the_hold_is_published_watch_only():
    buys = [rsa_feed.BuyAlert(source_id="2:0", symbol="BTOC", kind=rsa_feed.UNKNOWN_KIND,
                              alert_date="2026-10-09"),
            rsa_feed.BuyAlert(source_id="3:0", symbol="ODD", kind=rsa_feed.UNKNOWN_KIND,
                              alert_date="2026-10-09")]
    batch = A._feed_batch_with_holds(rsa_feed.FeedBatch(buys=buys),
                                     {("2026-10-09", "BTOC")})
    sent = batch.to_json()["buys"]
    # The hold goes as "conditional" (an older server coerces "unknown" to
    # standard); an unknown post that held nothing still stays local.
    assert [(b["symbol"], b["kind"]) for b in sent] == [("BTOC", "conditional")]


# ===================================================================== N6

def test_desktop_merge_keeps_the_latest_post_per_play():
    early = {"symbol": "X", "date": "2026-10-09", "note": "conditional",
             "posted_at": "2026-10-09T20:00:00+00:00"}
    late = {"symbol": "X", "date": "2026-10-09", "note": "Reg Alert",
            "posted_at": "2026-10-09T21:00:00+00:00"}
    assert A._merge_picks([early, late]) == [late]
    assert A._merge_picks([late, early]) == [late]
    # Undated duplicates: the first still wins, as before.
    a = {"symbol": "Y", "date": "2026-10-09", "note": "Reg Alert"}
    b = {"symbol": "Y", "date": "2026-10-09", "note": "conditional"}
    assert A._merge_picks([a, b]) == [a]


def test_a_stale_local_reg_alert_never_rearms_a_later_remote_hold():
    remote = {"symbol": "X", "date": "2026-10-09", "note": "conditional",
              "posted_at": "2026-10-09T22:00:00+00:00"}
    local = {"symbol": "X", "date": "2026-10-09", "note": "Reg Alert",
             "posted_at": "2026-10-09T21:00:00+00:00"}
    assert A._prefer_actionable([remote], [local]) == [remote]
    # Only the remote row is dated: no upgrade either.
    assert A._prefer_actionable([remote], [{k: v for k, v in local.items()
                                            if k != "posted_at"}]) == [remote]


def test_a_local_hold_stands_over_an_undated_remote_reg_alert():
    remote = {"symbol": "X", "date": "2026-10-09", "note": "Reg Alert"}
    hold = {"symbol": "X", "date": "2026-10-09", "note": "unknown alert type",
            "held": "Reg Alert", "posted_at": "2026-10-09T22:00:00+00:00"}
    assert A._prefer_actionable([remote], [hold]) == [hold]


def test_the_original_upgrade_still_works():
    remote = {"symbol": "X", "date": "2026-10-09", "note": "conditional"}
    local = {"symbol": "X", "date": "2026-10-09", "note": "Reg Alert"}
    assert A._prefer_actionable([remote], [local]) == [local]


# ===================================================================== N7

@pytest.mark.parametrize("why", ["Order rejected: not eligible", "insufficient buying power"])
def test_a_permanent_refusal_never_rearms_the_whole_pick(env, why):
    m = M(brokers=("public", "robinhood"))
    p = {"symbol": "AAA", "date": MF.TODAY.isoformat(), "note": "Reg Alert"}
    key = A.App._mirror_key(p)
    A.App._mirror_launch_pick(m, dict(p))
    b = m.batches[-1]
    b["results"] = [_res("public", errors=[why]), _res("robinhood", errors=["Login failed"])]
    A.App._mirror_record_outcome(m, b, 0, 2)
    assert key in m._mirror_executed                  # no whole-pick re-send
    assert not any("try again at the next check" in l for l in m.logs)
    assert [o["broker"] for o in m._mirror_owed] == ["robinhood"]   # login retried alone
    assert key in m._mirror_failed                    # the refusal reaches the user


# ===================================================================== N8

def test_the_automation_page_says_last_buy_wins():
    import inspect
    src = inspect.getsource(A.App)
    assert "unless the " in src and "alert names its own last day to buy" in src
    assert "last day named" in inspect.getsource(A.App._render_mirror_age_note)


# ===================================================================== N9

@pytest.mark.parametrize("year", [2026, 2027])
def test_rules_match_the_hand_checked_table(year):
    assert mc.rule_holidays(year) == {d for d in mc.NYSE_HOLIDAYS if d.year == year}
    assert mc.rule_early_closes(year) == {d for d in mc.NYSE_EARLY_CLOSES if d.year == year}


def test_years_past_the_table_still_know_their_holidays():
    assert not mc.is_trading_day(date(2028, 7, 4))         # Independence Day
    assert not mc.is_trading_day(date(2028, 4, 14))        # Good Friday
    assert not mc.is_trading_day(date(2028, 11, 23))       # Thanksgiving
    assert mc.is_trading_day(date(2028, 1, 3))             # 1/1 Sat: not observed Fri
    assert mc.is_trading_day(date(2027, 12, 31))           # NY 2028 not moved back
    assert mc.close_time(date(2028, 7, 3)).hour == 13
    assert mc.close_time(date(2028, 11, 24)).hour == 13
    assert not mc.is_trading_day(date(2023, 1, 2))         # NY Sunday -> Monday
    assert not mc.is_trading_day(date(2021, 12, 24))       # Christmas Sat -> Fri
    assert mc.is_trading_day(date(2021, 6, 18))            # no Juneteenth before 2022
    assert not mc.is_trading_day(date(2022, 6, 20))        # 2022: Sun -> Mon


# ============================================== LOW: offline fetch, slot

@pytest.mark.parametrize("fresh", [False, True])
def test_an_offline_fetch_hands_the_slot_back(env, monkeypatch, tmp_path, fresh):
    pf = tmp_path / "picks.json"
    pf.write_text("[]")
    if not fresh:
        old = datetime.now().timestamp() - 3 * 3600
        os.utime(pf, (old, old))
    monkeypatch.setattr(A, "PICKS_FILE", pf)
    monkeypatch.setattr(A, "CLOUD_AVAILABLE", True)
    monkeypatch.setattr(A, "_cloud_picks", lambda: None)
    monkeypatch.setattr(A.mirror_journal, "record_scan", lambda **k: None)

    class T:
        def __init__(self, target, daemon=True):
            self.t = target

        def start(self):
            self.t()
    monkeypatch.setattr(A.threading, "Thread", T)
    m = M()
    m._mirror_last_slot = "2026-10-09@10:45"
    A.App._mirror_check_now(m, "10:45", slot_key="2026-10-09@10:45")
    m.run_lambdas()
    if fresh:
        assert m._mirror_last_slot == "2026-10-09@10:45"
    else:
        assert m._mirror_last_slot == ""
        assert any("feed unreachable" in l for l in m.logs)


# ===================================== sim BUG-A: launch marker vs repair

def test_repair_never_releases_a_pick_with_a_launch_marker(env, monkeypatch):
    """mirror_runs.json lost the run (locked file, then a kill): the launch
    marker saved in mirror_state.json keeps the pick executed."""
    monkeypatch.setattr(A.mirror_journal, "read_error", lambda: None)
    monkeypatch.setattr(A.mirror_journal, "runs", lambda: [])
    m = M()
    m._mirror_repaired = False
    pk = MF.pick("KIL")
    key = A.App._mirror_key(pk)
    m._quick_picks = [pk]
    m._mirror_executed = {key}
    m._mirror_launched = {key: {"at": "2026-10-09T10:00:00", "brokers": ["fidelity"]}}
    A.App._repair_mirror_executed(m)
    assert key in m._mirror_executed
    # Without the marker it is the old enable-bug case and is released.
    m._mirror_repaired = False
    m._mirror_launched = {}
    A.App._repair_mirror_executed(m)
    assert key not in m._mirror_executed


def test_the_launch_marker_is_saved_before_any_worker(env, monkeypatch, tmp_path):
    seen = []

    class S(M):
        _save_mirror_state = A.App._save_mirror_state

        def _run_in_thread(self, _t, broker, _side, symbol, *_a):
            state = json.loads(A.MIRROR_STATE_FILE.read_text(encoding="utf-8"))
            seen.append((broker, state.get("launched")))
            super()._run_in_thread(_t, broker, _side, symbol, *_a)

        def _mirror_max_age_days(self):
            return 2
    m = S(brokers=("public",))
    m._mirror_unlinked_kept = set()
    pk = MF.pick("AAA")
    A.App._mirror_launch_pick(m, dict(pk))
    assert seen and seen[0][1][0][:2] == [pk["date"], "AAA"]
    saved = json.loads(A.MIRROR_STATE_FILE.read_text(encoding="utf-8"))
    assert A._mirror_launched_from(saved)[(pk["date"], "AAA")]["brokers"] == ["public"]


def test_an_unwritable_state_file_sends_nothing(env):
    class S(M):
        def _save_mirror_state(self):
            return False
    m = S(brokers=("public",))
    pk = MF.pick("AAA")
    A.App._mirror_launch_pick(m, dict(pk))
    assert m.launched == []
    assert A.App._mirror_key(pk) not in m._mirror_executed


def test_a_lost_run_shows_on_needs_attention(env, monkeypatch):
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda: [])
    m = M()
    m._local_stamp = A.App._local_stamp
    at = (datetime.now() - timedelta(hours=2)).isoformat(timespec="seconds")
    m._mirror_launched = {("2026-10-09", "KIL"): {"at": at, "brokers": ["wellsfargo"]}}
    rows = A.App._mirror_needs_attention(m, [], [])
    assert [r["symbol"] for r in rows] == ["KIL"]


# ============================ sim BUG-C: accounts that sent nothing

class Acc(M):
    def _run_in_thread(self, _t, broker, _side, symbol, *a):
        self.launched.append((broker, symbol))
        self.thread_args = getattr(self, "thread_args", []) + [(broker, a)]


def _acct(aid, ok, msg="order placed"):
    return {"account_id": aid, "ok": ok, "message": msg}


def test_unsent_accounts_at_an_aimable_broker_are_owed_by_account(env):
    m = Acc(brokers=("fidelity",))
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    res = {"broker": "fidelity", "ok_accounts": 2, "fail_accounts": 1,
           "errors": ["Fidelity 2: Login failed: login 2 rejected the password"],
           "accounts": [_acct("Fidelity 2", False, "Login failed: login 2 rejected the password"),
                        _acct("Z1", True), _acct("Z2", True)]}
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["fidelity"],
         "mirror_skipped": [], "mirror_owed": "", "mirror_run": "r", "results": [res]}
    A.App._mirror_record_outcome(m, b, 2, 1)
    [o] = m._mirror_owed
    assert o["broker"] == "fidelity" and o["accounts"] == ["Fidelity 2"]
    # It survives a restart with its account list...
    assert A._mirror_owed_from({"owed": [o]})[0]["accounts"] == ["Fidelity 2"]
    # ...and a list that can't be read is dropped, never widened to "all".
    assert A._mirror_owed_from({"owed": [dict(o, accounts="Fidelity 2")]}) == []
    # Released and launched aimed at that login only, though fidelity "holds" AAA.
    o["after"] = "2000-01-01T00:00:00"
    A._mirror_release_owed(m, set())
    q = m._mirror_queue[0]
    assert q["_accounts"] == ["Fidelity 2"]
    A.App._mirror_launch_pick(m, q)
    assert m.thread_args[-1] == ("fidelity", ("1", False, m.batches[-1], ["Fidelity 2"]))
    assert m.batches[-1]["mirror_owed_accounts"] == ["Fidelity 2"]


def test_unsent_accounts_at_robinhood_go_on_the_failed_list(env):
    m = M(brokers=("robinhood",))
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    res = {"broker": "robinhood", "ok_accounts": 1, "fail_accounts": 1, "errors": [],
           "accounts": [_acct("ind", True),
                        _acct("roth", False, "Session expired (HTTP 401) — this account's order was not sent")]}
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["robinhood"],
         "mirror_skipped": [], "mirror_owed": "", "mirror_run": "r", "results": [res]}
    A.App._mirror_record_outcome(m, b, 1, 1)
    assert m._mirror_owed == []                      # never a whole-broker re-send
    assert "short at" in m._mirror_failed_notes[key] and "roth" in m._mirror_failed_notes[key]


# ===================== sim BUG-D: may-exist legs beside a fill are loud

def test_a_maybe_live_leg_beside_a_fill_reaches_the_failed_list(env):
    m = M(brokers=("public", "schwab"))
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["public", "schwab"],
         "mirror_skipped": [], "mirror_owed": "", "mirror_run": "r",
         "results": [_res("public", ok=1),
                     {"broker": "schwab", "ok_accounts": 0, "fail_accounts": 1, "errors": [],
                      "accounts": [_acct("S1", False, "Order submitted but the confirmation "
                                                     "page didn't load — verify in Schwab")]}]}
    A.App._mirror_record_outcome(m, b, 1, 1)
    assert key in m._mirror_failed and "verify" in m._mirror_failed_notes[key]
    assert any("verify at" in msg for msg, _k in m.notes)
    assert m._mirror_owed == []                      # and never re-sent


def test_a_pick_waiting_on_a_stuck_broker_is_on_needs_attention_until_it_fills(env):
    m = M(brokers=("public", "fidelity"))
    m._mirror_wedged = {"fidelity": {"symbol": "OLD", "pending": {"fidelity"},
                                     "finished": False}}
    p = {"symbol": "BBB", "date": MF.TODAY.isoformat(), "note": "Reg Alert"}
    key = A.App._mirror_key(p)
    A.App._mirror_launch_pick(m, dict(p))
    assert m._mirror_failed_notes[key].startswith(A.MIRROR_HELD_FOR_NOTE)
    b1 = m.batches[-1]
    b1["results"] = [_res("public", ok=1)]
    A.App._mirror_record_outcome(m, b1, 1, 0)
    assert key in m._mirror_failed                 # public filling doesn't answer it
    m._mirror_wedged = {}
    m._mirror_active, m._brokers_in_flight = [], set()
    A.App._mirror_drain(m)
    b2 = m.batches[-1]
    assert b2["mirror_owed"] == "fidelity"
    b2["results"] = [_res("fidelity", ok=1)]
    A.App._mirror_record_outcome(m, b2, 1, 0)
    assert key not in m._mirror_failed
