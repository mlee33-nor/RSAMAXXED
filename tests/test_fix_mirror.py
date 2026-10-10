"""Mirror BUY-path audit fixes, 2026-10-10. One test (or more) per finding.

 1. Re-alert double-buy: a re-posted split with a new Alert Date is covered by
    the buys made for the earlier alert (MIRROR_REALERT_LOOKBACK_DAYS).
 2. A Friday-after-close alert survives the weekend, and a pick that names its
    last day to buy is gated on that day instead of its age.
 3. NYSE holidays and 13:00 half-days have no mirror slots (2026 and 2027).
 4. A broker whose leg failed with nothing sent, while another broker filled,
    is owed that pick on its own -- bounded, then surfaced.
 5. An alert whose type isn't an explicit STANDARD is never auto-bought.
 6. Scheduler housekeeping: a slot or a day is only spent once its check or
    pull actually ran; the drain never forks; a run with no journal entry still
    wakes the drain.

Same headless approach as test_mirror_fixes_2026_10: the real methods,
unbound, against a stub. Nothing here touches a broker, the network or a real
state file.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as A
import rsa_feed
import trade_journal
import test_mirror_fixes_2026_10 as MF
from test_mirror_fixes_2026_10 import env  # noqa: F401  (the shared fixture)


class _Mirror(MF.Mirror):
    _mirror_slot_failed = A.App._mirror_slot_failed
    _mirror_poll = A.App._mirror_poll
    _mirror_nudge_drain = A.App._mirror_nudge_drain

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.cancelled: list = []
        self.saves = 0
        self._mirror_owed: list = []
        self._mirror_wedged: dict = {}

    def after_cancel(self, handle):
        self.cancelled.append(handle)

    def _save_mirror_state(self):
        self.saves += 1


def _res(broker, ok=0, errors=(), accounts=()):
    return {"broker": broker, "ok_accounts": ok,
            "fail_accounts": 0 if ok else max(1, len(accounts)),
            "shares": float(ok), "errors": list(errors), "accounts": list(accounts)}


def _batch(*results, key=("2026-10-09", "AAA"), owed="", owed_attempts=0, run="run-1"):
    return {"symbol": key[1], "mirror_key": key, "all_brokers": [r["broker"] for r in results],
            "mirror_skipped": [], "results": list(results), "mirror_owed": owed,
            "mirror_owed_attempts": owed_attempts, "mirror_run": run}


# ================================================ 1. re-alert double-buy

def test_a_realert_with_a_new_date_is_covered_by_the_earlier_buys(monkeypatch):
    """SFWL: bought 08-26 at every broker, re-alerted 09-02, bought AGAIN 09-03."""
    trades = [MF.trade("SFWL", "public", "buy", "2026-08-26"),
              MF.trade("SFWL", "chase", "buy", "2026-08-26")]
    monkeypatch.setattr(trade_journal, "get_trades", lambda: list(trades))
    held = A._pick_broker_map_uncached(
        [{"symbol": "SFWL", "date": "2026-09-02", "note": "Reg Alert"}])
    assert held[("SFWL", "2026-09-02")] == {"public", "chase"}


def test_a_new_play_long_after_the_old_one_is_not_blocked(monkeypatch):
    trades = [MF.trade("SFWL", "public", "buy", "2026-05-01"),
              MF.trade("SFWL", "public", "sell", "2026-05-20")]
    monkeypatch.setattr(trade_journal, "get_trades", lambda: list(trades))
    held = A._pick_broker_map_uncached(
        [{"symbol": "SFWL", "date": "2026-09-02", "note": "Reg Alert"}])
    assert held[("SFWL", "2026-09-02")] == set()


# ================================================ 2. weekend / last day to buy

def test_a_friday_after_close_alert_is_still_bought_on_monday():
    p = {"symbol": "BTOC", "date": "2026-10-09", "note": "Reg Alert"}
    assert A._pick_fresh_trading(p, A.MIRROR_MAX_AGE_DEFAULT, date(2026, 10, 12))
    assert A._pick_fresh_trading(p, A.MIRROR_MAX_AGE_DEFAULT, date(2026, 10, 13))


def test_the_last_day_to_buy_wins_over_the_age_limit():
    p = {"symbol": "BTOC", "date": "2026-10-09", "note": "Reg Alert",
         "last_buy": "2026-10-14"}
    # Three sessions old on Wednesday -- past the default 2 -- but still owed.
    assert A._pick_fresh_trading(p, 2, date(2026, 10, 14))
    assert not A._pick_fresh_trading(p, 2, date(2026, 10, 15))
    # ...and a play past its last day is shut however young.
    shut = dict(p, date="2026-10-14", last_buy="2026-10-13")
    assert not A._pick_fresh_trading(shut, 4, date(2026, 10, 14))


def test_a_mistyped_last_day_cannot_keep_a_play_alive_for_months():
    p = {"symbol": "X", "date": "2026-10-01", "note": "Reg Alert", "last_buy": "2027-10-14"}
    assert not A._pick_fresh_trading(p, 2, date(2026, 11, 20))


def test_the_alert_carries_its_last_day_to_buy_into_the_pick():
    buy = rsa_feed.BuyAlert(source_id="1", symbol="BTOC", kind="standard",
                            alert_date="2026-10-09", last_buy_date="2026-10-14")
    pick = rsa_feed.to_pick(buy)
    assert pick == {"symbol": "BTOC", "note": "Reg Alert", "date": "2026-10-09",
                    "last_buy": "2026-10-14"}
    assert rsa_feed.from_pick(pick).last_buy_date == "2026-10-14"
    # No last day: the three-key shape, unchanged.
    assert "last_buy" not in rsa_feed.to_pick(
        rsa_feed.BuyAlert(source_id="2", symbol="Y", alert_date="2026-10-09"))


def test_prune_keeps_a_pick_whose_last_day_has_not_passed(monkeypatch):
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    # Pruning counts trading days in New York (fix4 N3): a fixed Wednesday,
    # and an alert six sessions back.
    today = date(2026, 10, 14)
    monkeypatch.setattr(A, "_mirror_today", lambda: today)
    old = "2026-10-06"
    keep = {"symbol": "K", "date": old, "note": "Reg Alert", "last_buy": today.isoformat()}
    drop = {"symbol": "D", "date": old, "note": "Reg Alert"}
    kept, removed = A._prune_stale_picks([keep, drop])
    assert kept == [keep] and removed == 1


# ================================================ 3. holidays / half-days

@pytest.mark.parametrize("day", [date(2026, 11, 26), date(2026, 12, 25),
                                 date(2027, 3, 26), date(2027, 7, 5), date(2027, 12, 24)])
def test_no_mirror_slot_on_an_nyse_holiday(day):
    assert A._mirror_due_slot(datetime.combine(day, datetime.min.time()).replace(hour=11)) is None


@pytest.mark.parametrize("day", [date(2026, 11, 27), date(2026, 12, 24), date(2027, 11, 26)])
def test_no_mirror_slot_after_a_half_day_close(day):
    at = lambda h, m: datetime(day.year, day.month, day.day, h, m)
    assert A._mirror_due_slot(at(12, 50)) is not None
    assert A._mirror_due_slot(at(13, 45)) is None


# ================================================ 4. one broker short

def test_a_broker_that_sent_nothing_is_owed_while_the_others_filled():
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    b = _batch(_res("public", ok=5), _res("chase", errors=["Login failed: session expired"]))
    A.App._mirror_record_outcome(m, b, 5, 1)
    assert key in m._mirror_executed                    # never re-armed whole
    assert [(o["broker"], o["symbol"], o["attempts"]) for o in m._mirror_owed] == [
        ("chase", "AAA", "1")]
    assert any("chase" in line.lower() and "again" in line for line in m.logs)


def test_the_owed_leg_waits_out_its_back_off(monkeypatch):
    m = _Mirror()
    b = _batch(_res("public", ok=5), _res("chase", errors=["Login failed"]))
    A.App._mirror_record_outcome(m, b, 5, 1)
    A._mirror_release_owed(m, {})
    assert m._mirror_queue == []                        # 30 min back-off
    m._mirror_owed[0]["after"] = (datetime.now() - timedelta(seconds=1)).isoformat(
        timespec="seconds")
    A._mirror_release_owed(m, {})
    assert [(q["_only"], q["_attempts"]) for q in m._mirror_queue] == [("chase", "1")]


def test_an_owed_retry_is_bounded_then_surfaced():
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    login = _res("chase", errors=["Login failed"])
    A.App._mirror_record_outcome(m, _batch(login, owed="chase", owed_attempts=1), 0, 1)
    assert [o["attempts"] for o in m._mirror_owed] == ["2"]
    assert key not in m._mirror_failed
    m._mirror_owed = []
    A.App._mirror_record_outcome(m, _batch(login, owed="chase", owed_attempts=2), 0, 1)
    assert m._mirror_owed == []
    assert key in m._mirror_failed and "short Chase" in m._mirror_failed_notes[key]


def test_an_owed_fill_never_clears_another_brokers_note():
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_failed.add(key)
    m._mirror_failed_notes[key] = "short Chase"
    A.App._mirror_record_outcome(m, _batch(_res("sofi", ok=1), owed="sofi"), 1, 0)
    assert key in m._mirror_failed


@pytest.mark.parametrize("err", ["Order rejected: symbol restricted",
                                 "Insufficient buying power",
                                 "Submitted but unconfirmed — verify at the broker",
                                 "HTTP 502: Bad Gateway"])
def test_a_permanent_or_maybe_live_failure_is_not_owed(err):
    m = _Mirror()
    b = _batch(_res("public", ok=5), _res("chase", errors=[err]))
    A.App._mirror_record_outcome(m, b, 5, 1)
    assert m._mirror_owed == []


def test_a_launch_of_an_owed_pick_carries_its_attempt_count(env):
    m = _Mirror(brokers=("public", "chase"))
    p = {"symbol": "AAA", "date": MF.TODAY.isoformat(), "note": "Reg Alert"}
    m._mirror_executed.add(A.App._mirror_key(p))
    m._mirror_owed = [{"broker": "chase", "symbol": "AAA", "date": p["date"],
                       "note": "Reg Alert", "attempts": "1"}]
    A.App._mirror_launch_pick(m, dict(p, _only="chase", _attempts="1"))
    assert m.launched == [("chase", "AAA")]
    assert m.batches[0]["mirror_owed"] == "chase"
    assert m.batches[0]["mirror_owed_attempts"] == 1
    assert m._mirror_owed == []                         # settled at launch


# ================================================ 5. unknown alert types

def _embed(desc, title="🔔 RSA Alert"):
    return {"id": "9", "timestamp": "2026-10-09T14:00:00+00:00",
            "embeds": [{"title": title, "description": desc,
                        "fields": [{"name": "🎟️ Ticker", "value": "ABCD"},
                                   {"name": "📅 Alert Date", "value": "10/9/26 (Fri)"}]}]}


@pytest.mark.parametrize("desc", ["", "UPDATE", "CANCELLED", "EARLY"])
def test_an_unknown_alert_type_is_never_a_reg_alert(desc):
    buys = rsa_feed.parse_buy_message(_embed(desc))
    assert [b.kind for b in buys] == [rsa_feed.UNKNOWN_KIND]
    assert not buys[0].is_actionable
    pick = rsa_feed.to_pick(buys[0])
    assert pick["note"].lower() not in A.MIRROR_NOTES
    assert "not recognised" in A._mirror_skip_reason(pick["note"])
    # ...and never published, where ingest would coerce it to standard.
    assert rsa_feed.FeedBatch(buys=buys).to_json()["buys"] == []


def test_an_explicit_standard_is_still_a_reg_alert():
    buys = rsa_feed.parse_buy_message(_embed("**STANDARD**"))
    assert rsa_feed.to_pick(buys[0])["note"] == "Reg Alert"
    assert A.App._rsa_note("", "") != "Reg Alert"


def test_a_stored_reg_alert_round_trips_as_standard():
    assert rsa_feed.from_pick({"symbol": "A", "date": "2026-10-09",
                               "note": "Reg Alert"}).kind == "standard"
    assert rsa_feed.from_pick({"symbol": "A", "date": "2026-10-09",
                               "note": "OTC"}).kind == "otc"


def test_an_unknown_type_is_logged_on_import():
    m = _Mirror()
    A.App._extract_picks_from_message(m, _embed("UPDATE"))
    m.run_lambdas()
    assert any("ABCD" in line and "not recognised" in line for line in m.logs)


# ================================================ 6. housekeeping

def test_a_slot_is_not_spent_when_its_check_throws(monkeypatch):
    now = datetime(2026, 10, 9, 10, 50)
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "", now))
    m = _Mirror()

    def boom(*_a, **_k):
        raise RuntimeError("journal read failed")
    m._mirror_check_now = boom
    A.App._mirror_poll(m)
    assert m._mirror_last_slot == ""

    seen = []
    m._mirror_check_now = lambda when, slot_key="": seen.append(slot_key)
    A.App._mirror_poll(m)
    assert seen == ["2026-10-09@10:45"] and m._mirror_last_slot == "2026-10-09@10:45"


def test_a_check_whose_worker_failed_hands_its_slot_back():
    m = _Mirror()
    m._mirror_last_slot = "2026-10-09@10:45"
    A.App._mirror_slot_failed(m, "2026-10-09@10:45")
    assert m._mirror_last_slot == ""
    m._mirror_last_slot = "2026-10-09@11:45"            # a later slot already ran
    A.App._mirror_slot_failed(m, "2026-10-09@10:45")
    assert m._mirror_last_slot == "2026-10-09@11:45"


def test_the_check_reads_the_broker_set_on_the_tk_thread(monkeypatch):
    """The worker must not touch _mirror_selected_brokers while Tk edits it."""
    m = _Mirror(brokers=("public",))
    got = []

    def bought(self, picks, selected=None):
        got.append(selected)
        return set()
    monkeypatch.setattr(_Mirror, "_mirror_bought_keys", bought)
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: [])
    monkeypatch.setattr(A, "_mirror_journal_problem", lambda: None)
    monkeypatch.setattr(A, "_mirror_market_gate", lambda: (True, ""))
    monkeypatch.setattr(A.mirror_journal, "record_scan", lambda **k: None)

    class T:
        def __init__(self, target, daemon=True):
            self.t = target

        def start(self):
            m._mirror_selected_brokers = {"chase"}      # Tk edits it meanwhile
            self.t()
    monkeypatch.setattr(A.threading, "Thread", T)
    A.App._mirror_check_now(m, "10:45")
    assert got == [{"public"}]


def test_execute_never_forks_the_drain(env):
    m = _Mirror()
    m._mirror_drain_id = "after#pending"
    A.App._mirror_execute(m, [MF.pick("AAA")])
    assert "after#pending" in m.cancelled


def test_two_nudges_leave_one_drain_tick():
    m = _Mirror()
    A.App._mirror_nudge_drain(m)
    first = m._mirror_drain_id
    A.App._mirror_nudge_drain(m)
    assert first and first in m.cancelled and m._mirror_drain_id != first


def test_a_batch_with_no_journal_run_still_wakes_the_drain():
    """start_run threw -> run_id "" -> _trade_batch_finish never nudged, and
    _mirror_ran stayed True with the sells waiting on it forever."""
    m = _Mirror()
    A.App._mirror_record_outcome(m, _batch(_res("public", ok=1), run=""), 1, 0)
    assert m._mirror_drain_id is not None


# --- alert feed: the day is spent only once the pull answered

class _Feed:
    _alerts_daily_check = A.App._alerts_daily_check
    _alerts_import_worker = A.App._alerts_import_worker
    _cancel_timer = A.App._cancel_timer

    def __init__(self):
        self._alerts_state = {"enabled": True}
        self._alerts_poll_id = None
        self.logs: list = []
        self.pulls: list = []

    def after(self, _ms, cb=None, *a):
        return "after#1"

    def after_cancel(self, _h):
        pass

    def _alerts_log_msg(self, msg):
        self.logs.append(msg)

    def _run_in_thread(self, target, *args):
        target(*args)

    def _ensure_alerts_channel_id(self, role="buy", required=True):
        return ("123", None) if role == "buy" else ("", None)


def test_the_daily_pull_is_not_marked_done_before_it_runs(monkeypatch):
    monkeypatch.setattr(A, "_save_feed_state", lambda st: None)
    f = _Feed()
    f._alerts_import_worker = lambda use_after, pull_date="": f.pulls.append(pull_date)
    A.App._alerts_daily_check(f)
    assert f.pulls == [datetime.now().strftime("%Y-%m-%d")]
    assert "last_pull_date" not in f._alerts_state      # the worker decides
    assert not getattr(f, "_alerts_pulling", False)


def test_a_failed_pull_leaves_the_day_open_and_a_good_one_closes_it(monkeypatch):
    monkeypatch.setattr(A, "_save_feed_state", lambda st: None)
    monkeypatch.setattr(A, "_env", lambda k: "x")
    f = _Feed()
    monkeypatch.setattr(A, "_feed_fetch", lambda *a, **k: ([], "HTTP 503"))
    A.App._alerts_import_worker(f, True, "2026-10-10")
    assert "last_pull_date" not in f._alerts_state

    monkeypatch.setattr(A, "_feed_fetch", lambda *a, **k: ([], None))
    A.App._alerts_import_worker(f, True, "2026-10-10")
    assert f._alerts_state["last_pull_date"] == "2026-10-10"


def test_a_pull_already_out_is_not_doubled(monkeypatch):
    monkeypatch.setattr(A, "_save_feed_state", lambda st: None)
    f = _Feed()
    f._alerts_pulling = True
    f._alerts_import_worker = lambda *a: f.pulls.append(a)
    A.App._alerts_daily_check(f, force=True)
    assert f.pulls == []
