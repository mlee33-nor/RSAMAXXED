"""Launch QA, 2026-10: mirror fixes, one regression test (or more) per finding.

 1. Re-alert double-buy (SFWL 08-26 -> re-alerted 09-02 -> bought again 09-03).
 2. A written-off batch left its broker claimed forever and the queue stalled
    behind it (10/02: 67 "Waiting — chase already mid-order", POAS never bought).
 3. The age gate counted calendar days, so Friday alerts died on Monday.
 4. trades.json unreadable -> mirror must fail closed.
 5. mirror_state.json unreadable -> defaults, then overwritten on the next save.
 6. mirror_runs.json unreadable -> cached as empty, then overwritten.
 7. A just-imported local pick missing from the cloud feed was dropped.
 8. Mirror fired while startup was still restoring broker sessions.
 9. No market-hours / holiday / half-day gate on what mirror sends.
10. A launch that sent nothing anywhere forfeited the pick forever.
11. A same-day CONDITIONAL -> STANDARD upgrade was thrown away by the dedupe.
12. _mirror_resume persisted a disarmed, broker-less state from a bad .env.

Same headless approach as test_mirror_pacing: the real methods, unbound,
against a stub that supplies only what they touch.
"""

from __future__ import annotations

import json
import pathlib
import sys
import types
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import mirror_journal as mj
import trade_journal
from modules import market_calendar as mc

TODAY = date(2026, 10, 9)   # a Friday


# --------------------------------------------------------------------- stub

class Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Widget:
    def __init__(self):
        self.text = ""

    def configure(self, **kw):
        self.text = kw.get("text", self.text)


class Mirror:
    _mirror_execute = A.App._mirror_execute
    _mirror_drain = A.App._mirror_drain
    _mirror_launch_pick = A.App._mirror_launch_pick
    _mirror_startup_hold = A.App._mirror_startup_hold
    _mirror_bought_keys = A.App._mirror_bought_keys
    _mirror_max_age_days = A.App._mirror_max_age_days
    _mirror_pick_age_ok = A.App._mirror_pick_age_ok
    _mirror_sync_toggle_ui = A.App._mirror_sync_toggle_ui
    _render_mirror_queue_lbl = A.App._render_mirror_queue_lbl
    _mirror_resume = A.App._mirror_resume
    _mirror_record_outcome = A.App._mirror_record_outcome
    _mirror_owe_failed_legs = A.App._mirror_owe_failed_legs
    _mirror_check_now = A.App._mirror_check_now
    _mirror_check_clicked = A.App._mirror_check_clicked
    _repair_mirror_executed = A.App._repair_mirror_executed
    _load_mirror_state = A.App._load_mirror_state
    _mirror_announce_state_unreadable = A.App._mirror_announce_state_unreadable
    _save_mirror_state = A.App._save_mirror_state
    _toggle_mirror_trading = A.App._toggle_mirror_trading
    _import_picks_from_messages = A.App._import_picks_from_messages
    _mirror_hold_pick = A.App._mirror_hold_pick
    _cancel_timer = A.App._cancel_timer
    _mirror_key = staticmethod(A.App._mirror_key)
    _mirror_journal_key = staticmethod(A.App._mirror_journal_key)

    def __init__(self, brokers=("public", "robinhood"), max_age=2, enabled=True):
        self._mirror_enabled = Var(enabled)
        self._mirror_max_age = Var(max_age)
        self._mirror_selected_brokers = set(brokers)
        self._mirror_executed: set = set()
        self._mirror_failed: set = set()
        self._mirror_failed_notes: dict = {}
        self._mirror_attempts: dict = {}
        self._mirror_attention_dismissed: set = set()
        self._mirror_queue: list = []
        self._mirror_active: list = []
        self._mirror_drain_id = None
        self._mirror_poll_id = None
        self._mirror_settled_at = None
        self._mirror_busy_logged = None
        self._mirror_last_slot = ""
        self._mirror_exec_count = Widget()
        self._mirror_queue_lbl = None
        self._quick_picks: list = []
        self._brokers_in_flight: set = set()
        self._live_batches: list = []
        self.launched: list = []
        self.batches: list = []
        self.logs: list = []
        self.scheduled: list = []
        self.notes: list = []
        self.persisted: list = []

    def after(self, ms, cb=None, *a):
        self.scheduled.append((ms, cb))
        return f"after#{len(self.scheduled)}"

    def after_cancel(self, _h):
        pass

    def _trade_worker(self, *_a, **_k):
        pass

    def _run_in_thread(self, _target, broker, _side, symbol, *_a):
        self.launched.append((broker, symbol))

    def _live_start(self, batch):
        self._live_batches.append(batch)
        self._brokers_in_flight.update(batch.get("all_brokers") or [])
        self.batches.append(batch)

    def _mirror_log_msg(self, msg):
        self.logs.append(msg)

    def _log(self, msg="", *_a, **_k):
        self.logs.append(str(msg))

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _invalidate_page(self, *_a):
        pass

    def _render_mirror_failed(self):
        pass

    def _render_mirror_age_note(self):
        pass

    def _show_frame(self, *_a):
        pass

    def _persist_picks(self, picks):
        self.persisted.append(list(picks))

    def run_lambdas(self):
        """Fire scheduled zero-arg callbacks (the worker's after(0, lambda))."""
        due, self.scheduled = self.scheduled, []
        for _ms, cb in due:
            if cb is not None and getattr(cb, "__name__", "") == "<lambda>":
                cb()


def pick(symbol, days_old=0, note="Reg Alert"):
    d = TODAY
    n = 0
    while n < days_old:
        d -= timedelta(days=1)
        if mc.is_trading_day(d):
            n += 1
    return {"symbol": symbol, "date": d.isoformat(), "note": note}


def trade(symbol, broker, side, when, qty=1.0, acct="A1"):
    return {"symbol": symbol, "broker": broker, "side": side, "qty": qty,
            "account_id": acct, "timestamp": f"{when}T15:00:00",
            "fill_price": 1.0}


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Open market, a healthy journal, fixed date, no real side effects."""
    # A wedged broker's owed pick is saved (see _mirror_owe): never into the
    # real mirror_state.json.
    monkeypatch.setattr(A, "MIRROR_STATE_FILE", tmp_path / "mirror_state.json")
    monkeypatch.setattr(A, "_mirror_today", lambda: TODAY)
    monkeypatch.setattr(A, "_mirror_market_gate", lambda: (True, ""))
    monkeypatch.setattr(A, "_mirror_journal_problem", lambda: None)
    monkeypatch.setattr(A, "_pick_broker_map", lambda picks: {})
    monkeypatch.setattr(A, "_load_done_picks", lambda: set())
    monkeypatch.setattr(A.mirror_journal, "start_run", lambda **kw: "run-1")
    monkeypatch.setattr(A, "MIRROR_PICK_GAP_MS", 0)
    monkeypatch.setattr(A, "winsound", types.SimpleNamespace(
        MessageBeep=lambda *_a: None, MB_ICONEXCLAMATION=0))
    return monkeypatch


# ================================================ 1. re-alert double-buy

def _holders(monkeypatch, trades, picks):
    monkeypatch.setattr(trade_journal, "get_trades", lambda broker=None: list(trades))
    return A._pick_broker_map_uncached(picks)


def test_a_re_alert_of_a_split_already_bought_is_not_bought_again(monkeypatch):
    """SFWL: bought 08-26 everywhere, re-alerted 09-02, bought again 09-03."""
    trades = [trade("SFWL", "public", "buy", "2026-08-26"),
              trade("SFWL", "wellsfargo", "buy", "2026-08-26")]
    re_alert = {"symbol": "SFWL", "date": "2026-09-02", "note": "Reg Alert"}
    held = _holders(monkeypatch, trades, [re_alert])
    assert held[("SFWL", "2026-09-02")] == {"public", "wellsfargo"}


def test_a_recent_buy_counts_even_after_it_was_sold(monkeypatch):
    """Within the look-back the play is the same split, open or not."""
    trades = [trade("SFWL", "public", "buy", "2026-08-26"),
              trade("SFWL", "public", "sell", "2026-08-31")]
    held = _holders(monkeypatch, trades,
                    [{"symbol": "SFWL", "date": "2026-09-02"}])
    assert held[("SFWL", "2026-09-02")] == {"public"}


def test_an_old_open_lot_from_an_earlier_split_does_not_block_a_new_play(monkeypatch):
    """M5: an open lot six months old is a leftover of an earlier split, not
    this play -- it used to skip the broker for every new alert on the name."""
    trades = [trade("ABCD", "chase", "buy", "2026-03-02")]
    held = _holders(monkeypatch, trades, [{"symbol": "ABCD", "date": "2026-09-02"}])
    assert held[("ABCD", "2026-09-02")] == set()


def test_an_open_lot_inside_the_window_still_counts(monkeypatch):
    """Past the 21-day re-alert look-back but inside the open-lot window."""
    trades = [trade("ABCD", "chase", "buy", "2026-07-25")]
    held = _holders(monkeypatch, trades, [{"symbol": "ABCD", "date": "2026-09-02"}])
    assert held[("ABCD", "2026-09-02")] == {"chase"}
    # ... and once it is sold, the re-alert look-back is all that is left.
    trades.append(trade("ABCD", "chase", "sell", "2026-08-01"))
    held = _holders(monkeypatch, trades, [{"symbol": "ABCD", "date": "2026-09-02"}])
    assert held[("ABCD", "2026-09-02")] == set()


def test_a_new_play_months_after_the_old_one_was_sold_still_buys(monkeypatch):
    trades = [trade("ABCD", "chase", "buy", "2026-03-02"),
              trade("ABCD", "chase", "sell", "2026-03-20")]
    held = _holders(monkeypatch, trades, [{"symbol": "ABCD", "date": "2026-09-02"}])
    assert held[("ABCD", "2026-09-02")] == set()


def test_a_sold_split_remnant_does_not_read_as_still_open(monkeypatch):
    """1 share, 1-for-15 split, 0.0667 sold: split-adjusted, that is closed."""
    trades = [trade("ABCD", "public", "buy", "2026-03-02"),
              trade("ABCD", "public", "sell", "2026-03-20", qty=0.0667)]
    held = _holders(monkeypatch, trades, [{"symbol": "ABCD", "date": "2026-09-02"}])
    assert held[("ABCD", "2026-09-02")] == set()


# ======================================== 2. stalled batch, wedged broker

def _stall(m, batch):
    batch["started"] = datetime.now() - timedelta(
        milliseconds=A.MIRROR_QUEUE_STALL_MS + 1000)


def test_a_written_off_broker_is_skipped_and_the_queue_moves(env):
    """POAS was never bought: 67 'Waiting — chase already mid-order'."""
    m = Mirror(brokers=("chase", "public"))
    Mirror._mirror_execute(m, [pick("AAA"), pick("POAS")], "10:45", "schedule")
    aaa = m.batches[0]
    aaa["pending"].discard("public")            # public reported, chase never
    m._brokers_in_flight.discard("public")
    _stall(m, aaa)

    Mirror._mirror_drain(m)

    assert ("public", "POAS") in m.launched
    assert ("chase", "POAS") not in m.launched, "second order on a wedged broker"
    assert "chase" in m._brokers_in_flight, "the wedged broker was released"
    assert not any("already mid-order" in line for line in m.logs)
    assert any("POAS" in msg and "chase" in msg for msg, _k in m.notes)
    assert any("AAA" in msg and "chase" in msg for msg, _k in m.notes)


def test_a_wedged_broker_rejoins_once_its_batch_reports(env):
    m = Mirror(brokers=("chase", "public"))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB"), pick("CCC")],
                           "10:45", "schedule")
    aaa = m.batches[0]
    aaa["pending"].discard("public")
    m._brokers_in_flight.discard("public")
    _stall(m, aaa)
    Mirror._mirror_drain(m)                     # BBB goes, public only
    assert "chase" in m._mirror_wedged

    # BBB lands; chase finally answers AAA.
    m.batches[1]["finished"] = True
    m._brokers_in_flight.discard("public")
    aaa["pending"].discard("chase")
    m._brokers_in_flight.discard("chase")
    Mirror._mirror_drain(m)

    assert m._mirror_wedged == {}
    assert ("chase", "CCC") in m.launched


def test_a_pick_owed_only_on_a_wedged_broker_waits_unmarked(env):
    m = Mirror(brokers=("chase",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")
    _stall(m, m.batches[0])

    Mirror._mirror_drain(m)

    assert [b["symbol"] for b in m.batches] == ["AAA"]
    assert [p["symbol"] for p in m._mirror_queue] == ["BBB"]
    assert A.App._mirror_key(pick("BBB")) not in m._mirror_executed


# ============================================== 3. trading-day age gate

def test_trading_days_skip_weekends_and_holidays():
    fri = date(2026, 10, 2)
    assert mc.trading_days_since(fri, date(2026, 10, 2)) == 0
    assert mc.trading_days_since(fri, date(2026, 10, 5)) == 1      # Monday
    assert mc.trading_days_since(fri, date(2026, 10, 7)) == 3
    # Good Friday 2026-04-03: Thursday's alert is 1 session old on Monday.
    assert mc.trading_days_since(date(2026, 4, 2), date(2026, 4, 6)) == 1
    # A weekend alert: Monday is its first chance, age 0.
    assert mc.trading_days_since(date(2026, 10, 3), date(2026, 10, 5)) == 0


def test_a_friday_alert_is_still_bought_on_monday(monkeypatch):
    monkeypatch.setattr(A, "_mirror_today", lambda: date(2026, 10, 5))
    m = Mirror(max_age=2)
    friday = {"symbol": "FRI", "date": "2026-10-02", "note": "Reg Alert"}
    assert Mirror._mirror_pick_age_ok(m, friday) is True
    # ... and Tuesday, but not Wednesday (3 sessions: Fri, Mon, Tue).
    monkeypatch.setattr(A, "_mirror_today", lambda: date(2026, 10, 7))
    assert Mirror._mirror_pick_age_ok(m, friday) is False


def test_the_calendar_knows_its_holidays_and_half_days():
    assert not mc.is_trading_day(date(2026, 11, 26))      # Thanksgiving
    assert not mc.is_trading_day(date(2027, 7, 5))        # July 4th observed
    assert mc.close_time(date(2026, 11, 27)).hour == 13   # half day
    assert mc.close_time(date(2026, 11, 30)).hour == 16
    assert mc.covered(date(2027, 1, 1)) and not mc.covered(date(2028, 1, 3))


# ================================================ 4. trades.json unreadable

def _sync_threads(monkeypatch):
    class T:
        def __init__(self, target=None, daemon=None, **_k):
            self.target = target

        def start(self):
            self.target()
    monkeypatch.setattr(A.threading, "Thread", T)


def test_the_check_fails_closed_when_the_journal_is_unreadable(env, monkeypatch):
    _sync_threads(monkeypatch)
    monkeypatch.setattr(A, "_mirror_journal_problem",
                        lambda: "trades.json could not be opened")
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: [pick("AAA")])
    monkeypatch.setattr(A.mirror_journal, "record_scan", lambda **kw: None)
    executed = []
    m = Mirror(brokers=("public",))
    m._mirror_execute = lambda *a, **k: executed.append(a)

    Mirror._mirror_check_now(m, "10:45")
    m.run_lambdas()

    assert executed == []
    assert any("trade journal" in msg.lower() for msg, kind in m.notes if kind == "error")


def test_a_launch_is_held_when_the_journal_goes_unreadable(env, monkeypatch):
    monkeypatch.setattr(A, "_mirror_journal_problem", lambda: "trades.json is corrupt")
    m = Mirror(brokers=("public",))
    Mirror._mirror_launch_pick(m, dict(pick("AAA"), _when="10:45"))
    assert m.launched == []
    assert A.App._mirror_key(pick("AAA")) not in m._mirror_executed


def test_the_journal_problem_reads_trade_journal_last_error(monkeypatch):
    monkeypatch.setattr(trade_journal, "get_trades", lambda broker=None: [])
    monkeypatch.setattr(trade_journal, "last_error", lambda: "trades.json could not be opened")
    assert "could not be opened" in A._mirror_journal_problem()
    monkeypatch.setattr(trade_journal, "last_error", lambda: None)
    assert A._mirror_journal_problem() is None


def test_repair_releases_nothing_when_the_journal_is_unreadable(env, monkeypatch):
    monkeypatch.setattr(A, "_mirror_journal_problem", lambda: "unreadable")
    m = Mirror()
    m._mirror_repaired = False
    m._quick_picks = [pick("AAA")]
    m._mirror_executed = {A.App._mirror_key(pick("AAA"))}
    Mirror._repair_mirror_executed(m)
    assert m._mirror_executed == {A.App._mirror_key(pick("AAA"))}
    assert m._mirror_repaired is False, "must look again once it reads"


# ============================================ 5. mirror_state.json unreadable

def test_an_unreadable_state_file_is_never_overwritten(tmp_path, monkeypatch):
    state = tmp_path / "mirror_state.json"
    state.write_text('{"enabled": true, "executed": [["2026-10-01", "AAA"]', encoding="utf-8")
    original = state.read_text(encoding="utf-8")
    monkeypatch.setattr(A, "MIRROR_STATE_FILE", state)
    m = Mirror()

    loaded = Mirror._load_mirror_state(m)
    assert loaded["enabled"] is False
    assert m._mirror_state_unreadable

    Mirror._save_mirror_state(m)
    assert state.read_text(encoding="utf-8") == original

    # Announced once the UI exists.
    m.scheduled[-1][1]()
    assert any(kind == "error" for _msg, kind in m.notes)


def test_mirror_cannot_be_enabled_over_an_unreadable_state(monkeypatch):
    shown = []
    monkeypatch.setattr(A.messagebox, "showerror", lambda *a, **k: shown.append(a))
    monkeypatch.setattr(A.messagebox, "askyesno",
                        lambda *a, **k: pytest.fail("offered to enable"))
    m = Mirror(enabled=False)
    m._mirror_state_unreadable = "mirror_state.json could not be read (x)"
    Mirror._toggle_mirror_trading(m)
    assert m._mirror_enabled.get() is False
    assert shown


def test_a_missing_state_file_is_a_fresh_install(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "MIRROR_STATE_FILE", tmp_path / "nope.json")
    m = Mirror()
    assert Mirror._load_mirror_state(m)["executed"] == []
    assert not m._mirror_state_unreadable


# ============================================= 6. mirror_runs.json unreadable

@pytest.fixture
def journal(tmp_path, monkeypatch):
    mj.flush()
    monkeypatch.setattr(mj, "_FILE", tmp_path / "mirror_runs.json")
    monkeypatch.setattr(mj, "_cache", None)
    monkeypatch.setattr(mj, "_cache_stat", None)
    monkeypatch.setattr(mj, "_dirty", False)
    monkeypatch.setattr(mj, "_inflight", False)
    monkeypatch.setattr(mj, "_read_error", None)
    monkeypatch.setattr(mj, "_READ_DELAY", 0)
    yield mj
    mj.flush()


def test_a_locked_run_journal_is_not_cached_as_empty_or_overwritten(journal, monkeypatch):
    run = {"id": "r1", "symbol": "AAA", "started_at": "2026-10-01T10:00:00",
           "finished_at": "x", "legs": []}
    journal._FILE.write_text(json.dumps({"version": 1, "runs": [run], "scans": []}),
                             encoding="utf-8")
    real = pathlib.Path.read_text
    locked = {"on": True}

    def read_text(self, *a, **k):
        if locked["on"] and self == journal._FILE:
            raise PermissionError("locked by sync")
        return real(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)

    assert journal.runs() == []
    assert journal.read_error()
    journal.record_scan(trigger="schedule")         # must not be written
    journal.flush()
    on_disk = json.loads(real(journal._FILE, encoding="utf-8"))
    assert [r["id"] for r in on_disk["runs"]] == ["r1"]
    assert on_disk["scans"] == []

    # Lock released: the real history comes back, and writes resume.
    locked["on"] = False
    assert [r["id"] for r in journal.runs()] == ["r1"]
    assert journal.read_error() is None
    journal.record_scan(trigger="schedule")
    journal.flush()
    on_disk = json.loads(real(journal._FILE, encoding="utf-8"))
    assert len(on_disk["scans"]) == 1 and len(on_disk["runs"]) == 1


def test_repair_skips_when_the_run_journal_cannot_be_read(env, monkeypatch):
    monkeypatch.setattr(A.mirror_journal, "read_error", lambda: "locked")
    m = Mirror()
    m._mirror_repaired = False
    m._quick_picks = [pick("AAA")]
    m._mirror_executed = {A.App._mirror_key(pick("AAA"))}
    Mirror._repair_mirror_executed(m)
    assert m._mirror_executed == {A.App._mirror_key(pick("AAA"))}


# ======================================== 7. just-imported pick not dropped

def test_a_local_pick_missing_from_the_feed_survives_the_merge(tmp_path, monkeypatch):
    today = date.today().isoformat()
    local = [{"symbol": "NEWP", "date": today, "note": "Reg Alert"},
             {"symbol": "COND", "date": today, "note": "Reg Alert"}]
    remote = [{"symbol": "COND", "date": today, "note": "conditional"},
              {"symbol": "REMO", "date": today, "note": "Reg Alert"}]
    f = tmp_path / "picks.json"
    f.write_text(json.dumps(local), encoding="utf-8")
    monkeypatch.setattr(A, "PICKS_FILE", f)
    monkeypatch.setattr(A, "_cloud_picks", lambda: list(remote))
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())

    out = A._fetch_quick_picks()
    by_sym = {p["symbol"]: p for p in out}
    assert set(by_sym) == {"NEWP", "COND", "REMO"}
    assert by_sym["COND"]["note"] == "Reg Alert", "the upgrade was thrown away"
    on_disk = {p["symbol"] for p in json.loads(f.read_text(encoding="utf-8"))}
    assert "NEWP" in on_disk


# ============================================== 8. startup session restore

def test_mirror_holds_until_startup_has_restored_sessions(env):
    m = Mirror(brokers=("fennel",))
    m._startup_sessions_done = False
    m._mirror_resumed = True
    m._startup_began_at = datetime.now()

    Mirror._mirror_execute(m, [pick("AAA")], "10:45", "import")
    assert m.launched == []
    assert A.App._mirror_key(pick("AAA")) not in m._mirror_executed
    assert any("restored" in line for line in m.logs)

    m._startup_sessions_done = True
    Mirror._mirror_drain(m)
    assert m.launched == [("fennel", "AAA")]


def test_the_startup_hold_is_bounded(env):
    m = Mirror(brokers=("fennel",))
    m._startup_sessions_done = False
    m._mirror_resumed = True
    m._startup_began_at = datetime.now() - timedelta(
        milliseconds=A.MIRROR_STARTUP_HOLD_MAX_MS + 1000)
    Mirror._mirror_execute(m, [pick("AAA")], "10:45", "schedule")
    assert m.launched == [("fennel", "AAA")]


def test_the_restore_worker_reports_done_even_when_it_throws():
    calls = []

    class S:
        _startup_refresh_guarded = A.App._startup_refresh_guarded

        def _startup_refresh_worker(self):
            raise RuntimeError("fennel blew up")

        def after(self, ms, cb):
            calls.append(cb)

        def _startup_sessions_settled(self):
            pass
    with pytest.raises(RuntimeError):
        S()._startup_refresh_guarded()
    assert calls, "mirror would wait for a restore that already died"


def test_resume_marks_mirror_resumed_even_when_off():
    m = Mirror(enabled=False)
    m._mirror_resumed = False
    Mirror._mirror_resume(m)
    assert m._mirror_resumed is True


# ===================================================== 9. market hours

def _ny(y, mo, d, h, mi):
    from zoneinfo import ZoneInfo
    return datetime(y, mo, d, h, mi, tzinfo=ZoneInfo("America/New_York"))


@pytest.mark.parametrize("now, ok", [
    (_ny(2026, 10, 5, 10, 0), True),
    (_ny(2026, 10, 5, 9, 0), False),          # pre-market
    (_ny(2026, 11, 26, 11, 0), False),        # Thanksgiving
    (_ny(2026, 11, 27, 12, 59), True),        # half day, still open
    (_ny(2026, 11, 27, 13, 30), False),       # half day, closed at 13:00
    (_ny(2026, 10, 3, 11, 0), False),         # Saturday
])
def test_the_market_gate(monkeypatch, now, ok):
    monkeypatch.setattr(mc, "now_et", lambda: now)
    assert A._mirror_market_gate()[0] is ok


def test_unknown_new_york_time_refuses_to_send(monkeypatch):
    monkeypatch.setattr(mc, "now_et", lambda: None)
    ok, why = A._mirror_market_gate()
    assert ok is False and "New York" in why


def test_no_scheduled_slot_on_a_holiday_or_after_a_half_day_close():
    assert A._mirror_due_slot(_ny(2026, 4, 3, 12, 0)) is None        # Good Friday
    assert A._mirror_due_slot(_ny(2026, 11, 27, 13, 50)) is None     # after 13:00
    assert A._mirror_due_slot(_ny(2026, 11, 27, 12, 50)) == "2026-11-27@12:45"


def test_a_closed_market_sends_nothing_and_buries_nothing(env, monkeypatch):
    monkeypatch.setattr(A, "_mirror_market_gate", lambda: (False, "market closed today"))
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "manual", "manual")
    assert m.launched == []
    assert m._mirror_queue == []
    assert m._mirror_executed == set()
    assert any("next scheduled check" in line for line in m.logs)


def test_check_now_outside_hours_imports_but_does_not_queue(env, monkeypatch):
    _sync_threads(monkeypatch)
    monkeypatch.setattr(A, "_mirror_market_gate", lambda: (False, "outside regular market hours"))
    fetched = []
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: fetched.append(1) or [pick("AAA")])
    monkeypatch.setattr(A.mirror_journal, "record_scan", lambda **kw: None)
    executed = []
    m = Mirror(brokers=("public",))
    m._mirror_execute = lambda *a, **k: executed.append(a)

    Mirror._mirror_check_clicked(m)
    m.run_lambdas()

    assert fetched, "the feed was not pulled"
    assert executed == []
    assert any("next scheduled check" in msg for msg, _k in m.notes)


# ======================================= 10. nothing sent -> try again

REJECT = {"account_id": "X1", "ok": False, "message": "Login failed"}
UNSURE = {"account_id": "X2", "ok": False,
          "message": "Order submitted but no confirmation seen — verify at the broker"}


def _failed_batch(*accounts, key=("2026-10-09", "AAA")):
    return {"symbol": "AAA", "mirror_key": key, "all_brokers": ["public"],
            "mirror_skipped": [],
            "results": [{"broker": "public", "ok_accounts": 0,
                         "fail_accounts": len(accounts), "errors": [],
                         "accounts": list(accounts)}]}


def test_a_launch_that_sent_nothing_is_handed_back(monkeypatch):
    monkeypatch.setattr(A, "_verify_manually_accounts", A._verify_manually_accounts)
    m = Mirror()
    key = ("2026-10-09", "AAA")
    for attempt in (1, 2):
        m._mirror_executed.add(key)
        Mirror._mirror_record_outcome(m, _failed_batch(REJECT), 0, 1)
        assert key not in m._mirror_executed, f"attempt {attempt} forfeited the pick"
        assert m._mirror_attempts[key] == attempt
        assert key not in m._mirror_failed

    m._mirror_executed.add(key)
    Mirror._mirror_record_outcome(m, _failed_batch(REJECT), 0, 1)
    assert key in m._mirror_executed, "gave up never"
    assert key in m._mirror_failed
    assert "gave up" in m._mirror_failed_notes[key]


def test_a_launch_whose_order_may_exist_is_never_handed_back():
    m = Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    Mirror._mirror_record_outcome(m, _failed_batch(REJECT, UNSURE), 0, 2)
    assert key in m._mirror_executed
    assert key in m._mirror_failed
    assert key not in m._mirror_attempts


def test_a_fill_clears_the_attempt_count():
    m = Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_attempts[key] = 2
    Mirror._mirror_record_outcome(m, _failed_batch(REJECT), 1, 0)
    assert key not in m._mirror_attempts


# ============================== 11. CONDITIONAL -> STANDARD same-day upgrade

def test_a_later_standard_replaces_the_conditional(monkeypatch):
    m = Mirror()
    m._quick_picks = [{"symbol": "UPG", "date": "2026-10-09", "note": "conditional"}]
    m._extract_picks_from_message = lambda msg: [msg]
    added = Mirror._import_picks_from_messages(
        m, [{"symbol": "UPG", "date": "2026-10-09", "note": "Reg Alert"}])
    assert [p["note"] for p in added] == ["Reg Alert"]
    assert [p["note"] for p in m.persisted[-1]] == ["Reg Alert"]


def test_a_later_conditional_holds_the_standard(monkeypatch):
    """fix4 N5 reversed the old "never downgraded" rule: a later post for the
    same play that isn't buyable HOLDS it (latest post wins), loudly."""
    monkeypatch.setattr(A, "_touched_pick_keys", lambda picks: set())
    m = Mirror()
    m._quick_picks = [{"symbol": "UPG", "date": "2026-10-09", "note": "Reg Alert"}]
    m._extract_picks_from_message = lambda msg: [msg]
    added = Mirror._import_picks_from_messages(
        m, [{"symbol": "UPG", "date": "2026-10-09", "note": "conditional"}])
    assert added == []
    [held] = m.persisted[-1]
    assert held["note"] == "conditional" and held["held"] == "Reg Alert"


# ======================================= 12. resume after a bad .env load

def test_resume_without_brokers_does_not_persist_the_disarm(tmp_path, monkeypatch):
    state = tmp_path / "mirror_state.json"
    monkeypatch.setattr(A, "MIRROR_STATE_FILE", state)
    m = Mirror(brokers=(), enabled=True)
    m._mirror_unlinked_kept = {"public", "chase"}     # pruned: .env didn't load
    m._mirror_poll = lambda: pytest.fail("armed with nothing to buy on")

    Mirror._mirror_resume(m)
    assert m._mirror_enabled.get() is False
    assert not state.exists(), "resume wrote the disarmed state"

    # Any later save keeps what the user actually chose.
    Mirror._save_mirror_state(m)
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["enabled"] is True
    assert saved["brokers"] == ["chase", "public"]


def test_an_explicit_toggle_off_is_saved_as_off(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "MIRROR_STATE_FILE", tmp_path / "s.json")
    m = Mirror(brokers=("public",), enabled=True)
    m._mirror_keep_enabled_on_disk = True
    Mirror._toggle_mirror_trading(m)
    saved = json.loads((tmp_path / "s.json").read_text(encoding="utf-8"))
    assert saved["enabled"] is False
