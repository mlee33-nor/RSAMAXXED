"""Mirror trading: pacing, the age gate, and surviving a restart.

Three separate complaints, one file, because they share a stub:

1. Mirror fired every eligible pick in the same instant. The run log for
   2026-08-27 has ten runs stamped 08:38:54 — ten picks across six brokers is
   ~56 execute_trade() calls at once, nine per broker, and within that second
   Chase filled 4/4 on one pick and 0/4 on another. Picks now drain one at a
   time.
2. Mirror came back OFF after every restart, while mirror_state.json said
   enabled:true — the loader threw the saved flag away.
3. There was no way to say "don't buy anything older than two days"; the only
   dial was PICK_MAX_AGE_DAYS, which also DELETES picks and pushes the deletion
   to the shared feed.

The App class cannot be instantiated headlessly (CustomTkinter's DPI tracker
takes the process down), so the real methods are called unbound against a stub
that supplies only what they touch — same approach as test_concurrent_orders.
"""

from __future__ import annotations

import sys
import types
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


# --------------------------------------------------------------------- stub

class Var:
    """tk.BooleanVar / IntVar, minus tk."""

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
    """Just enough App for the mirror queue, gate and toggle paths."""

    # Everything under test is the real implementation.
    _mirror_execute = A.App._mirror_execute
    _mirror_drain = A.App._mirror_drain
    _mirror_launch_pick = A.App._mirror_launch_pick
    _mirror_pending_picks = A.App._mirror_pending_picks
    _mirror_bought_keys = A.App._mirror_bought_keys
    _mirror_max_age_days = A.App._mirror_max_age_days
    _mirror_pick_age_ok = A.App._mirror_pick_age_ok
    _mirror_sync_toggle_ui = A.App._mirror_sync_toggle_ui
    _render_mirror_queue_lbl = A.App._render_mirror_queue_lbl
    _mirror_resume = A.App._mirror_resume
    _mirror_poll = A.App._mirror_poll
    # _mirror_poll is re-entrant now (resume and enable both call it), so it
    # cancels its own pending tick before scheduling the next one.
    _cancel_timer = A.App._cancel_timer
    _release_broker = A.App._release_broker
    # Static on App: re-wrapping keeps them static here too, otherwise the stub
    # would hand them `self` as the pick.
    _mirror_key = staticmethod(A.App._mirror_key)
    _mirror_journal_key = staticmethod(A.App._mirror_journal_key)

    def __init__(self, brokers=("public", "robinhood"), max_age=2, enabled=True):
        self._mirror_enabled = Var(enabled)
        self._mirror_max_age = Var(max_age)
        self._mirror_selected_brokers = set(brokers)
        self._mirror_executed: set = set()
        self._mirror_failed: set = set()
        self._mirror_queue: list = []
        self._mirror_active: list = []
        self._mirror_drain_id = None
        self._mirror_poll_id = None
        self._mirror_settled_at = None
        self._mirror_busy_logged = None
        self._mirror_last_slot = ""
        self._mirror_exec_count = Widget()
        self._mirror_queue_lbl = None
        self._mirror_age_chips: dict = {}
        self._quick_picks: list = []
        self._brokers_in_flight: set = set()
        self._live_batches: list = []
        # observations
        self.launched: list = []        # (broker, symbol)
        self.batches: list = []
        self.logs: list = []
        self.scheduled: list = []       # (ms, callback)
        self.notes: list = []
        self.saved = 0
        self.polled = 0

    # -- recorded, not performed --------------------------------------------
    def after(self, ms, cb=None, *a):
        self.scheduled.append((ms, cb))
        return f"after#{len(self.scheduled)}"

    def after_cancel(self, _handle):
        pass

    def _trade_worker(self, *_a, **_k):     # only ever passed, never called
        pass

    def _run_in_thread(self, _target, broker, _side, symbol, *_a):
        self.launched.append((broker, symbol))

    def _live_start(self, batch):
        self._live_batches.append(batch)
        self._brokers_in_flight.update(batch.get("all_brokers") or [])
        self.batches.append(batch)

    def _mirror_log_msg(self, msg):
        self.logs.append(msg)

    def _log(self, *_a, **_k):
        pass

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _invalidate_page(self, *_a):
        pass

    def _save_mirror_state(self):
        self.saved += 1

    def _render_mirror_age_note(self):
        pass

    def _style_chip(self, *_a, **_k):
        pass

    # -- drive the queue by hand --------------------------------------------
    def run_scheduled(self):
        """Fire every pending after() callback once, in order."""
        due, self.scheduled = self.scheduled, []
        for _ms, cb in due:
            if cb is not None:
                cb(self)

    def finish_all(self):
        """Mark every in-flight batch as landed, the way _trade_batch_finish does."""
        for b in self._mirror_active:
            b["finished"] = True
            for broker in b.get("all_brokers") or []:
                self._brokers_in_flight.discard(broker)
        self._live_batches = [b for b in self._live_batches if not b.get("finished")]


def pick(symbol, days_old=0, note="Reg Alert"):
    d = date.today() - timedelta(days=days_old)
    return {"symbol": symbol, "date": d.strftime("%Y-%m-%d"), "note": note}


@pytest.fixture(autouse=True)
def no_journal(monkeypatch):
    """Mirror's holdings lookups must not read the real trade journal."""
    monkeypatch.setattr(A, "_pick_broker_map", lambda picks: {})
    monkeypatch.setattr(A, "_load_done_picks", lambda: set())
    monkeypatch.setattr(A.mirror_journal, "start_run", lambda **kw: "run-1")
    monkeypatch.setattr(A, "winsound", types.SimpleNamespace(
        MessageBeep=lambda *_a: None, MB_ICONEXCLAMATION=0))


# ------------------------------------------------------------------ pacing

def test_ten_picks_do_not_all_fire_at_once():
    """The 2026-08-27 flood: ten picks, one second, ~56 concurrent orders.

    Only the first pick may go out; the rest wait their turn.
    """
    m = Mirror(brokers=("public", "robinhood", "chase"))
    picks = [pick(s) for s in "ABCDEFGHIJ"]

    Mirror._mirror_execute(m, picks, "10:45", "schedule")

    assert len(m.batches) == 1, "more than one pick went out at once"
    assert {b for b, _ in m.launched} == {"public", "robinhood", "chase"}
    assert len(m.launched) == 3, "one pick x three brokers, nothing more"
    assert len(m._mirror_queue) == 9


def test_the_next_pick_waits_for_the_previous_one_to_report(monkeypatch):
    monkeypatch.setattr(A, "MIRROR_PICK_GAP_MS", 0)
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")
    assert [b["symbol"] for b in m.batches] == ["AAA"]

    # Draining again while AAA is still out must not release BBB.
    Mirror._mirror_drain(m)
    assert [b["symbol"] for b in m.batches] == ["AAA"]

    m.finish_all()
    Mirror._mirror_drain(m)
    assert [b["symbol"] for b in m.batches] == ["AAA", "BBB"]
    assert m._mirror_queue == []


def test_a_gap_is_left_after_a_batch_lands(monkeypatch):
    """The breather is what stops a broker being re-entered the same second."""
    monkeypatch.setattr(A, "MIRROR_PICK_GAP_MS", 20_000)
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")
    m.finish_all()

    Mirror._mirror_drain(m)
    assert [b["symbol"] for b in m.batches] == ["AAA"], "no gap was left"
    assert m.scheduled, "the drain must come back for BBB"

    # Pretend the gap has elapsed.
    m._mirror_settled_at = datetime.now() - timedelta(milliseconds=25_000)
    Mirror._mirror_drain(m)
    assert [b["symbol"] for b in m.batches] == ["AAA", "BBB"]


def test_mirror_waits_for_a_broker_the_desk_is_already_using(monkeypatch):
    """_mirror_execute ignored the in-flight guard entirely."""
    monkeypatch.setattr(A, "MIRROR_PICK_GAP_MS", 0)
    m = Mirror(brokers=("public", "robinhood"))
    m._brokers_in_flight.add("robinhood")        # a desk ticket is out

    Mirror._mirror_execute(m, [pick("AAA")], "10:45", "schedule")
    assert m.batches == [], "mirror stepped on an order already in flight"
    assert any("already mid-order" in line for line in m.logs)

    m._brokers_in_flight.discard("robinhood")
    Mirror._mirror_drain(m)
    assert [b["symbol"] for b in m.batches] == ["AAA"]


def test_a_batch_that_never_reports_does_not_wedge_the_queue(monkeypatch):
    monkeypatch.setattr(A, "MIRROR_PICK_GAP_MS", 0)
    m = Mirror(brokers=("fidelity",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")

    # AAA's broker thread never comes back.
    m.batches[0]["started"] = datetime.now() - timedelta(
        milliseconds=A.MIRROR_QUEUE_STALL_MS + 1000)
    m._brokers_in_flight.clear()
    Mirror._mirror_drain(m)

    assert [b["symbol"] for b in m.batches] == ["AAA", "BBB"]
    assert any("moving on" in line for line in m.logs)


def test_a_queued_pick_is_not_marked_executed_until_it_goes_out():
    """Marking at queue time is what buried unbought picks forever."""
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")

    assert A.App._mirror_key(pick("AAA")) in m._mirror_executed
    assert A.App._mirror_key(pick("BBB")) not in m._mirror_executed


def test_disabling_drops_the_queue_without_burying_it():
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB"), pick("CCC")],
                           "10:45", "schedule")
    assert len(m._mirror_queue) == 2

    A.App._toggle_mirror_trading(m)

    assert m._mirror_enabled.get() is False
    assert m._mirror_queue == []
    # BBB and CCC were never sent, so they must stay eligible.
    assert A.App._mirror_key(pick("BBB")) not in m._mirror_executed
    assert A.App._mirror_key(pick("CCC")) not in m._mirror_executed


def test_a_landing_batch_nudges_the_queue_forward():
    """Waiting for the drain's own poll would leave the counter reading
    "buying 1" after the last batch of a run has already landed."""
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")
    m.scheduled.clear()

    A.App._mirror_nudge_drain(m)

    assert m.scheduled and m.scheduled[0][0] == 0


def test_the_queue_counter_says_what_is_happening():
    m = Mirror(brokers=("public",))
    m._mirror_queue_lbl = Widget()

    Mirror._mirror_execute(m, [pick("A"), pick("B"), pick("C")], "10:45", "s")
    assert m._mirror_queue_lbl.text == "buying 1 · 2 queued"

    m.finish_all()
    Mirror._mirror_drain(m)          # still inside the gap, but the label moves
    assert m._mirror_queue_lbl.text == "2 queued"


def test_the_same_pick_is_not_queued_twice():
    m = Mirror(brokers=("public",))
    Mirror._mirror_execute(m, [pick("AAA"), pick("BBB")], "10:45", "schedule")
    Mirror._mirror_execute(m, [pick("BBB"), pick("CCC")], "11:45", "schedule")
    assert [p["symbol"] for p in m._mirror_queue] == ["BBB", "CCC"]


# --------------------------------------------------------------- age gate

@pytest.mark.parametrize("days_old, allowed", [(0, True), (1, True),
                                               (2, True), (3, False), (9, False)])
def test_the_age_limit_is_inclusive(days_old, allowed):
    """"No older than 2 days" keeps a 2-day-old alert and drops a 3-day-old one."""
    m = Mirror(max_age=2)
    assert Mirror._mirror_pick_age_ok(m, pick("AAA", days_old)) is allowed


def test_the_limit_is_the_users_not_the_feeds():
    """PICK_MAX_AGE_DAYS also drives the prune that DELETES picks and pushes the
    deletion to the shared remote, so mirror must not read it."""
    assert A.PICK_MAX_AGE_DAYS == 4
    m = Mirror(max_age=2)
    three_day_old = pick("VMAR", 3)
    assert A._pick_is_fresh(three_day_old) is True      # still in the feed
    assert Mirror._mirror_pick_age_ok(m, three_day_old) is False   # but not bought


def test_a_broken_setting_fails_closed():
    m = Mirror()
    m._mirror_max_age = Var("not a number")
    assert Mirror._mirror_max_age_days(m) == A.MIRROR_MAX_AGE_DEFAULT


def test_the_limit_is_clamped_to_the_offered_choices():
    assert Mirror._mirror_max_age_days(Mirror(max_age=99)) == A.MIRROR_AGE_CHOICES[-1]
    assert Mirror._mirror_max_age_days(Mirror(max_age=0)) == A.MIRROR_AGE_CHOICES[0]


def test_pending_picks_honour_the_limit():
    m = Mirror(max_age=2)
    m._quick_picks = [pick("FRESH", 1), pick("STALE", 3),
                      pick("OTC1", 1, note="OTC")]
    pending = Mirror._mirror_pending_picks(m)
    assert [p["symbol"] for p in pending] == ["FRESH"]


def test_a_pick_that_ages_out_while_queued_is_not_bought(monkeypatch):
    """A queue can straddle midnight; the limit is re-checked at launch."""
    m = Mirror(brokers=("public",), max_age=2)
    stale = dict(pick("VMAR", 3), _when="10:45", _trigger="schedule")
    Mirror._mirror_launch_pick(m, stale)

    assert m.batches == []
    assert m.launched == []
    assert any("aged past" in line for line in m.logs)


# ------------------------------------------------------------ restart/resume

def test_the_saved_toggle_is_restored_not_discarded(tmp_path, monkeypatch):
    """mirror_state.json said enabled:true and the loader threw it away."""
    state = tmp_path / "mirror_state.json"
    state.write_text(
        '{"enabled": true, "brokers": ["public"], "executed": [], '
        '"last_slot": "", "failed": [], "max_age_days": 3}', encoding="utf-8")
    monkeypatch.setattr(A, "MIRROR_STATE_FILE", state)

    loaded = A.App._load_mirror_state(Mirror())
    assert loaded["enabled"] is True
    assert loaded["max_age_days"] == 3


def test_resume_re_arms_the_schedule():
    m = Mirror(brokers=("public",), enabled=True)
    m._mirror_poll = lambda: setattr(m, "polled", m.polled + 1)

    Mirror._mirror_resume(m)

    assert m.polled == 1
    assert any("Resumed after restart" in line for line in m.logs)
    assert m.notes, "a silent resume is worse than forgetting"


def test_resume_refuses_to_arm_against_no_brokers():
    m = Mirror(brokers=(), enabled=True)
    m._mirror_poll = lambda: pytest.fail("armed with nothing to buy on")

    Mirror._mirror_resume(m)

    assert m._mirror_enabled.get() is False


def test_the_heartbeat_survives_a_failure_in_its_own_body(monkeypatch):
    """The reschedule used to be the last statement, so anything that threw on
    the way there killed the after() chain while the badge still read ACTIVE."""
    def boom():
        raise RuntimeError("tz lookup failed")
    monkeypatch.setattr(A, "_market_status", boom)

    m = Mirror(enabled=True)
    Mirror._mirror_poll(m)

    assert m._mirror_poll_id is not None, "the heartbeat died"
    assert any(ms == A.MIRROR_HEARTBEAT_MS for ms, _ in m.scheduled)
    assert any("Heartbeat error" in line for line in m.logs)


def test_a_disabled_mirror_stops_rescheduling():
    m = Mirror(enabled=False)
    Mirror._mirror_poll(m)
    assert m.scheduled == []


# ------------------------------------------------ overlapping batch release

def test_a_broker_stays_claimed_while_another_batch_still_needs_it():
    """Releasing on the first batch to land handed the broker back while a
    second was still mid-order there — the duplicate the guard exists to stop."""
    m = Mirror()
    first = {"pending": set(), "all_brokers": ["public"], "finished": False}
    second = {"pending": {"public"}, "all_brokers": ["public"], "finished": False}
    m._live_batches = [first, second]
    m._brokers_in_flight = {"public"}

    Mirror._release_broker(m, "public", first)
    assert m._brokers_in_flight == {"public"}, "released while still in use"

    second["pending"].clear()
    Mirror._release_broker(m, "public", second)
    assert m._brokers_in_flight == set()
