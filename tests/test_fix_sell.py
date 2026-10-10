"""Sell-side audit fixes (fix2/sell), one block per finding.

  1  a may-exist leg is held per PLAY + brokerage, so a narrowed key cannot
     re-send it; the hold persists and lapses once its DAY order is dead
  3  a dead Public leg is handed back like any other
  4  renamed tickers: the stored board supplies renames before the first pull;
     journal checks net both names together
  5  a play mid-read or in a live batch is never unclaimed or re-queued
  7  plays over AUTOSELL_MAX_PER_PULL wait for a human
  10 a failed holdings read never wedges the Sell button
  11 market re-checked at fire; _exit_fire unwinds its in-flight flag; a play
     out of attempts stays out when its broker set narrows; Retry skipped
     keeps live claims

Pure logic against stand-ins: no window, no broker, no network, no order.
"""
from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle


def _task(brokers=("Robinhood", "Fidelity"), sym="IPDN", alert=None,
          date="2026-10-01"):
    return lifecycle.SellTask(symbol=sym, alert_symbol=alert or sym,
                              alert_date=date, status="exit_called",
                              brokers=tuple(brokers), accounts=1)


def _res(broker, ok=0, fail=(), errors=None, accounts=None):
    accts = [{"account_id": f"{broker}{i}", "ok": True, "message": "placed"}
             for i in range(ok)]
    accts += [{"account_id": f"{broker}x{i}", "ok": False, "message": m}
              for i, m in enumerate(fail)]
    if accounts is not None:
        accts = accounts
    return {"broker": broker, "ok_accounts": ok, "fail_accounts": len(fail),
            "errors": errors if errors is not None else [a["message"] for a in accts
                                                           if not a["ok"]],
            "accounts": accts}


class Var:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v


class Settle:
    _exit_batch_settle = A.App._exit_batch_settle
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key

    def __init__(self):
        self.handed_back, self.logs = [], []
        self.saved = 0

    def _autosell_retry(self, task, why):
        self.handed_back.append(why)

    def _save_autosell_state(self):
        self.saved += 1

    def _log(self, msg, *a, **k):
        self.logs.append(msg)


@pytest.fixture()
def journal(monkeypatch):
    rows: list = []
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda *a, **k: list(rows))
    monkeypatch.setattr(A.trade_journal, "split_adjusted", lambda *a, **k: list(rows))
    return rows


def _t(side, qty, acct, broker="robinhood", sym="IPDN"):
    return {"broker": broker, "symbol": sym, "account_id": acct,
            "side": side, "qty": qty}


# ------------------------------------------------ 1 narrowed-key re-send

VERIFY = "Order submitted but not confirmed — verify at the broker"


def test_a_maybe_placed_leg_is_held_per_play_and_broker():
    s = Settle()
    task = _task()
    s._exit_batch_settle({"exit_task": task, "autosell": True},
                         [_res("robinhood", ok=3), _res("fidelity", fail=[VERIFY])])
    assert s.handed_back == []                      # nothing is owed back
    # Keyed by TICKER since fix4 (a newer exit date must not step around it).
    assert set(s._autosell_may_exist["IPDN"]) == {"fidelity"}
    assert s.saved and any("may already be out" in m for m in s.logs)


def test_the_narrowed_key_cannot_step_around_the_hold():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True},
                         [_res("robinhood", ok=3), _res("fidelity", fail=[VERIFY])])
    narrowed = _task(("Fidelity",))
    # A different sold-once key from the one claimed...
    assert A.App._autosell_key(s, narrowed) != A.App._autosell_key(s, _task())
    # ...and still refused, because the hold is on the play + brokerage.
    assert A._autosell_strip_held(s, narrowed) is None
    both = _task(("Fidelity", "Schwab"))
    assert A._autosell_strip_held(s, both).brokers == ("Schwab",)


def test_an_unrecognized_failure_is_held_too():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Fidelity",)), "autosell": True},
                         [_res("fidelity", fail=["HTTP 502"])])
    assert s.handed_back == []
    assert A._autosell_held_brokers(s, _task(("Fidelity",))) == {"fidelity"}


def test_a_nothing_sent_failure_is_not_held():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Fidelity",)), "autosell": True},
                         [_res("fidelity", fail=["Login failed — nothing was sent"])])
    assert s.handed_back and A._autosell_held_brokers(s, _task(("Fidelity",))) == set()


def test_a_dry_run_holds_nothing():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True, "dry_run": True},
                         [_res("fidelity", fail=[VERIFY])])
    assert not getattr(s, "_autosell_may_exist", None)


def test_a_clean_later_batch_answers_the_hold():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Fidelity",))},
                         [_res("fidelity", fail=[VERIFY])])
    assert A._autosell_held_brokers(s, _task(("Fidelity",)))
    s._exit_batch_settle({"exit_task": _task(("Fidelity",))},
                         [_res("fidelity", ok=2)])
    assert A._autosell_held_brokers(s, _task(("Fidelity",))) == set()


def test_a_hold_lapses_once_its_day_order_is_long_dead():
    # A DAY-order brokerage only; see AUTOSELL_DAY_ORDER_BROKERS.
    s = types.SimpleNamespace()
    old = (datetime.now() - timedelta(days=10))
    A._autosell_hold(s, _task(("Schwab",)), ["schwab"], now=old)
    assert A._autosell_held_brokers(s, _task(("Schwab",))) == set()
    assert s._autosell_may_exist == {}


def test_holds_survive_a_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", tmp_path / "autosell_state.json")
    s = types.SimpleNamespace(
        _autosell_enabled=Var(True), _autosell_dry_run=Var(False),
        _autosell_fracs=Var(True), _autosell_sold=set(), _autosell_reading=set(),
        _log=lambda *a, **k: None)
    s._reading_keys = types.MethodType(A.App._reading_keys, s)
    A._autosell_hold(s, _task(("Fidelity",)), ["fidelity"])
    A.App._save_autosell_state(s)
    state = json.loads((tmp_path / "autosell_state.json").read_text())
    restored = A._autosell_restore_holds(state)
    assert set(restored["IPDN"]) == {"fidelity"}
    assert A._autosell_restore_holds({"may_exist": "junk"}) == {}


class Pump:
    _autosell_pump = A.App._autosell_pump
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key
    _reading_keys = A.App._reading_keys

    def __init__(self, queue):
        self._autosell_queue = list(queue)
        self._brokers_in_flight = set()
        self._autosell_sold: set = set()
        self._trade_in_flight = False
        self._queue_busy = False
        self.later, self.reads, self.logs = [], [], []

    def _render_sell_queue(self):
        pass

    def _mirror_busy(self):
        return False

    def _gate_idle_secs(self):
        return 0.0

    def _pump_later(self, ms):
        self.later.append(ms)

    def _save_autosell_state(self):
        pass

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _run_in_thread(self, fn, *args):
        self.reads.append(args)

    def _autosell_resolve(self, task):
        pass


def test_the_pump_reads_only_the_brokers_not_on_hold(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", None))
    p = Pump([_task(("Robinhood", "Fidelity"))])
    A._autosell_hold(p, _task(), ["fidelity"])
    p._autosell_pump()
    (task,) = p.reads[0]
    assert task.brokers == ("Robinhood",)
    assert A.App._autosell_key(p, task) in p._autosell_sold


def test_the_pump_drops_a_task_whose_every_broker_is_on_hold(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", None))
    p = Pump([_task(("Fidelity",))])
    A._autosell_hold(p, _task(), ["fidelity"])
    p._autosell_pump()
    assert p.reads == [] and p._autosell_sold == set()


# ------------------------------------------------ 3 dead Public leg

def test_a_public_worker_that_raised_with_no_rows_is_handed_back():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Public",)), "autosell": True},
                         [_res("public", errors=["ConnectionError: reset"],
                               accounts=[])])
    assert s.handed_back == ["the order failed at public"]


def test_a_public_leg_whose_logins_failed_is_handed_back():
    s = Settle()
    s._exit_batch_settle(
        {"exit_task": _task(("Public",)), "autosell": True},
        [_res("public", fail=["Public login 1 failed: Auth failed — nothing was sent"])])
    assert s.handed_back == ["the order failed at public"]


def test_a_public_leg_with_a_maybe_placed_order_stays_claimed():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Public",)), "autosell": True},
                         [_res("public", fail=["read timed out"])])
    assert s.handed_back == []
    assert A._autosell_held_brokers(s, _task(("Public",))) == {"public"}


def test_a_public_error_that_says_it_may_be_live_is_not_handed_back():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Public",)), "autosell": True},
                         [_res("public", errors=["order may have been placed"],
                               accounts=[])])
    assert s.handed_back == []


def test_a_partial_public_leg_is_handed_back():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(("Public",)), "autosell": True},
                         [_res("public", ok=3, fail=["rejected: insufficient"])])
    assert s.handed_back == ["the order failed in 1 account at public"]


# ------------------------------------------------ 4 renamed tickers

def _board(tmp_path, rows):
    p = tmp_path / "lifecycle_state.json"
    p.write_text(json.dumps({"rows": {r["symbol"]: r for r in rows}}))
    return p


def test_saved_renames_read_the_stored_board(tmp_path):
    p = _board(tmp_path, [{"symbol": "AGAE", "sell_symbol": "AIFA"},
                          {"symbol": "IPDN", "sell_symbol": "IPDN"}])
    assert lifecycle.saved_renames(p) == {"AIFA": "AGAE"}
    assert lifecycle.saved_renames(tmp_path / "missing.json") == {}


def test_renames_come_from_the_stored_board_before_the_first_pull(tmp_path, monkeypatch):
    p = _board(tmp_path, [{"symbol": "AGAE", "sell_symbol": "AIFA"}])
    monkeypatch.setattr(lifecycle, "STATE_FILE", p)
    s = types.SimpleNamespace(_track_rows=[])
    assert A.App._symbol_renames(s) == {"AIFA": "AGAE"}
    # Once a board is in memory it is laid OVER the stored one (fix4 N2):
    # a rename older than the live board's window must not vanish.
    row = types.SimpleNamespace(symbol="XYZ", sell_symbol="XYZB")
    s._track_rows = [row]
    assert A.App._symbol_renames(s) == {"AIFA": "AGAE", "XYZB": "XYZ"}


def test_a_renamed_play_is_sellable_from_the_stored_board(tmp_path, monkeypatch, journal):
    p = _board(tmp_path, [{"symbol": "AGAE", "sell_symbol": "AIFA"}])
    monkeypatch.setattr(lifecycle, "STATE_FILE", p)
    journal.append(_t("buy", 1, "R1", sym="AGAE"))
    monkeypatch.setattr(A, "_load_trade_attempts", lambda: {})
    sells = [{"symbol": "AIFA", "sell_date": "2026-10-01", "brokers": ["Robinhood"],
              "posted_at": "2026-10-01T14:00:00"}]
    monkeypatch.setattr(A, "_sell_leg_broker_keys", lambda sl: ["robinhood"])
    renames = A.App._symbol_renames(types.SimpleNamespace(_track_rows=[]))
    tasks = A._sellnow_tasks(sells, renames)
    assert [(t.symbol, t.alert_symbol, t.brokers) for t in tasks] == [
        ("AIFA", "AGAE", ("Robinhood",))]


def test_journal_disputes_net_both_names_together(journal):
    # Bought under the old name, sold under the new: nothing is open.
    journal += [_t("buy", 1, "R1", sym="AGAE"), _t("sell", 1, "R1", sym="AIFA")]
    s = types.SimpleNamespace()
    task = _task(("Robinhood",), sym="AIFA", alert="AGAE")
    assert A.App._journal_disputes(s, task, ["Robinhood"]) == []
    journal.append(_t("buy", 1, "R2", sym="AGAE"))
    assert A.App._journal_disputes(s, task, ["Robinhood"]) == ["Robinhood (1 account)"]


# ------------------------------------------------ 5 never unclaim a live play

class Claims:
    _autosell_unclaim = A.App._autosell_unclaim
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key
    _queue_sell = A.App._queue_sell

    def __init__(self):
        self._autosell_sold: set = set()
        self._autosell_fails: dict = {}
        self._autosell_reading: set = set()
        self._autosell_queue: list = []
        self._autosell_dry_run = Var(False)
        self.notes, self.logs, self.pumped = [], [], 0

    def _save_autosell_state(self):
        pass

    def _push_notification(self, msg, kind="info"):
        self.notes.append(msg)

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _render_sell_queue(self):
        pass

    def _autosell_pump(self):
        self.pumped += 1


def test_a_play_mid_read_is_not_unclaimed():
    c = Claims()
    key = A.App._autosell_key(c, _task())
    c._autosell_sold.add(key)
    c._autosell_reading.add(key)
    c._autosell_unclaim([_task(("Robinhood",))])      # narrowed: same play
    assert key in c._autosell_sold


def test_a_play_in_a_live_batch_is_not_unclaimed_or_requeued():
    c = Claims()
    key = A.App._autosell_key(c, _task())
    c._autosell_sold.add(key)
    c._trade_batch = {"exit_task": _task(), "finished": False}
    c._autosell_unclaim([_task()])
    assert key in c._autosell_sold
    assert c._queue_sell(_task()) is False and c._autosell_queue == []
    c._trade_batch["finished"] = True
    assert c._queue_sell(_task()) is True and len(c._autosell_queue) == 1


def test_queue_by_hand_leaves_a_held_broker_out():
    c = Claims()
    A._autosell_hold(c, _task(), ["fidelity"])
    assert c._queue_sell(_task()) is True
    assert c._autosell_queue[0].brokers == ("Robinhood",)
    assert any("may already be out" in n for n in c.notes)
    assert c._queue_sell(_task(("Fidelity",))) is False


# ------------------------------------------------ 7 the per-pull cap holds

class Consider:
    _autosell_consider = A.App._autosell_consider
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key
    _autosell_cooling = A.App._autosell_cooling
    _queue_extend = A.App._queue_extend

    def __init__(self, tasks):
        self.tasks = tasks
        self._autosell_enabled = Var(True)
        self._autosell_fracs = Var(False)
        self._autosell_dry_run = Var(False)
        self._autosell_sold: set = set()
        self._autosell_queue: list = []
        self.logs, self.notes, self.checks = [], [], []

    def _autosell_worklist(self):
        return list(self.tasks)

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append(msg)

    def _autosell_pump(self):
        pass

    def _autosell_schedule_check(self, reason, ms):
        self.checks.append((reason, ms))


def test_plays_over_the_cap_wait_for_a_human(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", None))
    tasks = [_task(("Robinhood",), sym=f"S{i}") for i in range(6)]
    c = Consider(tasks)
    c._autosell_consider("test")
    assert [t.symbol for t in c._autosell_queue] == ["S0", "S1", "S2", "S3"]
    # The queue drains (popped tasks are claimed) and the re-check runs.
    for t in c._autosell_queue:
        c._autosell_sold.add(A.App._autosell_key(c, t))
    c._autosell_queue.clear()
    c._autosell_consider("queue drained")
    assert c._autosell_queue == []
    # A sweep or Queue click is the human the cap was waiting for.
    cl = Claims()
    cl._autosell_capped = c._autosell_capped
    cl._autosell_unclaim([tasks[4]])
    c._autosell_consider("again")
    assert [t.symbol for t in c._autosell_queue] == ["S4"]


def test_a_play_out_of_attempts_stays_out_when_its_brokers_narrow(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", None))
    c = Consider([_task(("Fidelity",))])
    c._autosell_fails = {"2026-10-01:IPDN": A.AUTOSELL_MAX_ATTEMPTS}
    c._autosell_consider("test")
    assert c._autosell_queue == []
    p = Pump([_task(("Fidelity",))])
    p._autosell_fails = {"2026-10-01:IPDN": A.AUTOSELL_MAX_ATTEMPTS}
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", None))
    p._autosell_pump()
    assert p.reads == []


def test_a_closed_market_books_a_check_for_the_open(monkeypatch):
    now = datetime(2026, 10, 9, 9, 0, 0)
    monkeypatch.setattr(A, "_market_status", lambda: ("pre", "Pre-market", now))
    monkeypatch.setattr(A.market_calendar, "session", lambda d: (570, 960))
    c = Consider([_task(("Robinhood",))])
    c._autosell_consider("test")
    assert c.checks == [("market open", 30 * 60 * 1000 + 30000)]
    c._autosell_consider("again")
    assert len(c.notes) == 1                    # said once, not every hour


# ------------------------------------------------ 10 Sell button never wedges

def test_a_read_that_raises_frees_the_sell_button():
    class S:
        _exit_sell = A.App._exit_sell

        def __init__(self):
            self._exit_busy = False
            self._trade_in_flight = False
            self._queue_busy = False
            self.notes, self.logs = [], []

        def _push_notification(self, msg, kind="info"):
            self.notes.append(msg)

        def _log(self, msg, *a, **k):
            self.logs.append(msg)

        def _run_in_thread(self, fn, *args):
            fn(*args)

        def after(self, _ms, fn=None, *a):
            fn(*a)

        def _exit_resolve_worker(self, task, then=None):
            raise RuntimeError("module blew up")

    s = S()
    s._exit_sell(_task())
    assert s._exit_busy is False
    assert any("module blew up" in n for n in s.notes)


# ------------------------------------------------ 11 fire-time guards

class Auto:
    _autosell_fire = A.App._autosell_fire
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key
    _reading_keys = A.App._reading_keys
    _autosell_read_done = A.App._autosell_read_done

    def __init__(self):
        self._autosell_sold: set = set()
        self._autosell_queue: list = []
        self._autosell_dry_run = Var(False)
        self._trade_in_flight = False
        self.fired, self.logs, self.later = [], [], []

    def _save_autosell_state(self):
        pass

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _pump_later(self, ms):
        self.later.append(ms)

    def _exit_fire(self, *a, **k):
        self.fired.append(a)


def _resolved(task):
    leg = lifecycle.BrokerLeg(broker="Robinhood", key="robinhood", qty="1",
                              accounts=1, low=1.0, high=1.0)
    return lifecycle.ResolvedExit(task=task, legs=(leg,), missing=(), errors=())


def test_a_market_that_closed_during_the_read_holds_the_sell(monkeypatch):
    monkeypatch.setattr(A, "_market_status",
                        lambda: ("closed", "After hours", None))
    a = Auto()
    task = _task(("Robinhood",))
    a._autosell_sold.add(A.App._autosell_key(a, task))
    a._autosell_fire(_resolved(task))
    assert a.fired == [] and a._autosell_queue == [task]
    assert A.App._autosell_key(a, task) not in a._autosell_sold
    assert not getattr(a, "_autosell_fails", None)           # not an attempt


def test_a_dry_run_rehearses_after_hours(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("closed", "After hours", None))
    a = Auto()
    a._autosell_dry_run = Var(True)
    a._push_notification = lambda *x, **k: None
    a._journal_shortfalls = lambda r: []
    a._journal_disputes = lambda *x: []
    a._autosell_fire(_resolved(_task(("Robinhood",))))
    assert len(a.fired) == 1


class FireStub:
    _autosell_key = A.App._autosell_key
    _exit_fire_unwind = A.App._exit_fire_unwind

    def __init__(self):
        self.completed, self.logs = [], []
        self._brokers_in_flight: set = set()
        self._autosell_sold: set = set()

    def _push_notification(self, *a, **k):
        pass

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _save_autosell_state(self):
        pass

    def _live_start(self, batch):
        self._brokers_in_flight.update(batch["all_brokers"])
        raise RuntimeError("strip broke")

    def _run_in_thread(self, *a):
        raise AssertionError("no worker may start")

    def _trade_broker_complete(self, batch, summary):
        self.completed.append(summary)
        batch["pending"].discard(summary["broker"])
        self._brokers_in_flight.discard(summary["broker"])
        if not batch["pending"]:
            batch["finished"] = True
            self._trade_in_flight = False


def test_exit_fire_gives_the_in_flight_flag_back_when_it_raises(journal):
    journal.append(_t("buy", 1, "R1"))
    s = FireStub()
    batch = A.App._exit_fire(s, _resolved(_task(("Robinhood",))))
    assert s._trade_in_flight is False and batch["finished"]
    (summary,) = s.completed
    assert A._result_nothing_sent(summary)          # settles as nothing sent


def test_exit_fire_last_resort_when_the_batch_path_fails_too(journal):
    journal.append(_t("buy", 1, "R1"))
    s = FireStub()
    s._trade_broker_complete = lambda *a: (_ for _ in ()).throw(RuntimeError("x"))
    A.App._exit_fire(s, _resolved(_task(("Robinhood",))))
    assert s._trade_in_flight is False and s._brokers_in_flight == set()


def test_retry_skipped_keeps_live_claims_and_holds():
    class C:
        _autosell_clear_skipped = A.App._autosell_clear_skipped
        _autosell_key = A.App._autosell_key

        def __init__(self):
            self.said = []

        def _sweep_say(self, msg, hold_ms=0):
            self.said.append(msg)

        def _save_autosell_state(self):
            pass

        def _log(self, *a, **k):
            pass

    c = C()
    live = A.App._autosell_key(c, _task())
    old = "2026-09-01:OLD:robinhood"
    c._autosell_sold = {live, old}
    c._autosell_reading = {live}
    c._autosell_fails = {}
    A._autosell_hold(c, _task(), ["fidelity"])
    c._autosell_clear_skipped()
    assert c._autosell_sold == {live}
    assert A._autosell_held_brokers(c, _task()) == {"fidelity"}
