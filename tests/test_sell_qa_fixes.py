"""Pre-launch QA fixes on the sell side, one block per finding.

  1  one copy of the app at a time (named mutex / lock file)
  2  an exit sells only the accounts this tool bought in
  3  a broker that read empty against the journal is handed back, not dropped
  4  journal re-derived at fire time; no uncapped auto-sell; manual exits
     respect the queue and claim the play
  5  a partly failed leg is retried
  6  an exit we still hold is not aged out of sells.json
  7  the pump waits on brokers with an order out; reads take the browser slot
  8  a renamed ticker is netted against the journal of both names
  9  the sold-once record keeps the newest keys, deterministically
  10 an unreadable autosell_state.json blocks saving and auto-sell

Pure logic against stand-ins: no window, no broker, no network, no order.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import types
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as A
import lifecycle


@pytest.fixture(autouse=True)
def _market_open(monkeypatch):
    """A live auto-sell re-checks the market at fire time (it may have closed
    during the holdings read); these tests are about what happens next."""
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Markets open", None))


# ----------------------------------------------------------------- helpers

def _t(side, qty, acct, broker="robinhood", sym="IPDN"):
    return {"broker": broker, "symbol": sym, "account_id": acct,
            "side": side, "qty": qty}


@pytest.fixture()
def journal(monkeypatch):
    rows: list = []
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda *a, **k: list(rows))
    return rows


def _task(brokers=("Robinhood",), sym="IPDN", alert=None, date="2026-10-01"):
    return lifecycle.SellTask(symbol=sym, alert_symbol=alert or sym,
                              alert_date=date, status="exit_called",
                              brokers=tuple(brokers), accounts=1)


def _leg(broker, key, qty="1", accounts=1):
    return lifecycle.BrokerLeg(broker=broker, key=key, qty=qty, accounts=accounts,
                               low=float(qty), high=float(qty))


def _resolved(legs, brokers=None, missing=(), errors=(), sym="IPDN", alert=None):
    brokers = brokers or tuple(l.broker for l in legs) + tuple(missing) + tuple(errors)
    return lifecycle.ResolvedExit(task=_task(brokers, sym=sym, alert=alert),
                                  legs=tuple(legs), missing=tuple(missing),
                                  errors=tuple(errors))


class Var:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v


class Fire:
    """Just enough App for _exit_fire."""

    _autosell_key = A.App._autosell_key

    def __init__(self, **kw):
        self.started, self.logs, self.notes, self.retried = [], [], [], []
        self.saved = 0
        self.__dict__.update(kw)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _live_start(self, batch):
        self.batch = batch

    def _run_in_thread(self, fn, *args):
        self.started.append(args)

    def _trade_worker(self, *a, **k):
        pass

    def _autosell_retry(self, task, why):
        self.retried.append(why)

    def _save_autosell_state(self):
        self.saved += 1


# ------------------------------------------------------- 1 single instance

@pytest.mark.skipif(sys.platform != "win32", reason="named mutex is Windows-only")
def test_a_second_mutex_acquire_is_refused_until_released():
    name = f"Local\\RSAMAXXED-test-{uuid.uuid4().hex}"
    try:
        assert A._acquire_single_instance(name) is True
        assert A._acquire_single_instance(name) is False
    finally:
        A._release_single_instance(name)
    assert A._acquire_single_instance(name) is True
    A._release_single_instance(name)


@pytest.mark.skipif(sys.platform != "win32", reason="named mutex is Windows-only")
def test_another_process_cannot_take_the_mutex_we_hold():
    name = f"Local\\RSAMAXXED-test-{uuid.uuid4().hex}"
    assert A._acquire_single_instance(name) is True
    try:
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import app; "
                "print(app._acquire_single_instance(sys.argv[2]))")
        env = dict(os.environ, RSA_NO_CRASH_LOG="1")
        out = subprocess.run([sys.executable, "-c", code, str(ROOT), name],
                             capture_output=True, text=True, timeout=120,
                             env=env, cwd=str(ROOT))
        assert out.stdout.strip().splitlines()[-1] == "False", out.stderr
    finally:
        A._release_single_instance(name)


def test_the_lock_file_fallback_refuses_a_second_holder(tmp_path):
    lock = tmp_path / ".rsamaxxed.lock"
    a, b = f"a-{uuid.uuid4().hex}", f"b-{uuid.uuid4().hex}"
    try:
        assert A._acquire_single_instance(a, lock, use_mutex=False) is True
        assert A._acquire_single_instance(b, lock, use_mutex=False) is False
    finally:
        A._release_single_instance(a)
    assert A._acquire_single_instance(b, lock, use_mutex=False) is True
    A._release_single_instance(b)


def test_a_second_copy_exits_before_anything_is_built(monkeypatch):
    seen = []
    monkeypatch.setattr(A, "_acquire_single_instance", lambda *a, **k: False)
    monkeypatch.setattr(A, "_notify_already_running", lambda *a, **k: seen.append("told"))
    monkeypatch.setattr(A, "_crash_note", lambda *a, **k: None)
    monkeypatch.setattr(A, "App", lambda *a, **k: seen.append("BUILT"))
    with pytest.raises(SystemExit) as ex:
        A._single_instance_or_exit()
    assert ex.value.code == 0
    assert seen == ["told"]


def test_the_first_copy_carries_on(monkeypatch):
    monkeypatch.setattr(A, "_acquire_single_instance", lambda *a, **k: True)
    monkeypatch.setattr(A, "_notify_already_running",
                        lambda *a, **k: pytest.fail("must not notify"))
    assert A._single_instance_or_exit() is None


def test_the_guard_runs_before_the_window_and_matches_its_title():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    main = src[src.index('if __name__ == "__main__":'):]
    assert main.index("_single_instance_or_exit()") < main.index("App()")
    assert "self.title(APP_WINDOW_TITLE)" in src
    # One name per install folder, stable across runs.
    assert A._single_instance_name() == A._single_instance_name()
    assert A._single_instance_name(Path("C:/x")) != A._single_instance_name(Path("C:/y"))


# ------------------------------------- 2 exits sell only the accounts we own

def test_a_targetable_broker_is_aimed_at_the_journal_open_accounts(journal):
    journal += [_t("buy", 1, "F2", "fidelity"), _t("buy", 1, "F1", "fidelity"),
                _t("buy", 1, "F3", "fidelity"), _t("sell", 1, "F3", "fidelity")]
    s = Fire()
    A.App._exit_fire(s, _resolved([_leg("Fidelity", "fidelity", accounts=5)]),
                     autosell=True)
    (args,) = s.started
    assert args[0] == "fidelity" and args[3] == "1"
    assert args[6] == ["F1", "F2"]             # only_accounts, never F3 or theirs


def test_an_untargetable_broker_holding_more_accounts_is_left_for_a_human(journal):
    journal.append(_t("buy", 1, "R1"))
    s = Fire()
    out = A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood", accounts=3)]),
                           autosell=True)
    assert out is None and s.started == []
    assert s.retried == []                     # not a retry loop: a person's call
    assert any("this tool bought in 1" in m for m in s.logs)
    assert any(k == "warning" and "Robinhood" in m for m, k in s.notes)


def test_by_hand_the_same_leg_goes_but_is_warned_before_the_click(journal):
    journal.append(_t("buy", 1, "R1"))
    resolved = _resolved([_leg("Robinhood", "robinhood", accounts=3)])
    warns = A.App._exit_confirm_warnings(resolved)
    assert warns and "this tool bought in 1" in warns[0]
    s = Fire()
    A.App._exit_fire(s, resolved)
    assert len(s.started) == 1 and len(s.started[0]) == 6   # no only_accounts


def test_the_other_legs_still_sell_when_one_goes_to_a_human(journal):
    journal += [_t("buy", 1, "R1"), _t("buy", 1, "F1", "fidelity")]
    s = Fire()
    A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood", accounts=2),
                                   _leg("Fidelity", "fidelity", accounts=1)]),
                     autosell=True)
    assert [a[0] for a in s.started] == ["fidelity"]
    assert s.batch["all_brokers"] == ["fidelity"]


# ------------------------------------------------- 3 disputed brokers return

class Auto:
    """Just enough App for _autosell_fire, recording what _exit_fire got."""

    _autosell_fire = A.App._autosell_fire
    _autosell_retry = A.App._autosell_retry
    _reading_keys = A.App._reading_keys
    _autosell_read_done = A.App._autosell_read_done
    _autosell_play_key = A.App._autosell_play_key
    _autosell_key = A.App._autosell_key
    _journal_disputes = A.App._journal_disputes
    _journal_shortfalls = A.App._journal_shortfalls

    def __init__(self):
        self._queue_busy = True
        self._trade_in_flight = False
        self._brokers_in_flight: set = set()
        self._autosell_queue: list = []
        self._autosell_sold: set = set()
        self._autosell_fails: dict = {}
        self._autosell_dry_run = Var(False)
        self.logs, self.notes, self.fired = [], [], []

    def _pump_later(self, ms):
        pass

    def _log(self, msg, *_a, **_k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _save_autosell_state(self):
        pass

    def _exit_fire(self, resolved, dry_run=False, autosell=False, **kw):
        self.fired.append((resolved, kw))


def test_a_broker_read_empty_against_the_journal_rides_back_on_the_batch(monkeypatch):
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: ([("F1", 1.0)] * 10
                                             if broker == "fidelity" else [("R1", 1.0)]))
    app = Auto()
    resolved = _resolved([_leg("Robinhood", "robinhood")], missing=("Fidelity",))
    Auto._autosell_fire(app, resolved)
    ((got, kw),) = app.fired
    assert got is resolved
    assert any("Fidelity reported no position" in w for w in kw["handback"])
    assert any("journal says we hold" in m for m in app.logs)
    assert any("Fidelity" in m and k == "warning" for m, k in app.notes)


def test_an_agreed_empty_broker_is_not_handed_back(monkeypatch):
    monkeypatch.setattr(A, "_leg_open_accounts",
                        lambda broker, sym: [] if broker == "fidelity" else [("R1", 1.0)])
    app = Auto()
    Auto._autosell_fire(app, _resolved([_leg("Robinhood", "robinhood")],
                                       missing=("Fidelity",)))
    ((_r, kw),) = app.fired
    assert kw == {}


class Settle:
    _exit_batch_settle = A.App._exit_batch_settle

    def __init__(self):
        self.handed_back = []

    def _autosell_retry(self, task, why):
        self.handed_back.append(why)


def _res(broker, ok=0, fail=(), errors=None):
    accts = [{"account_id": f"{broker}{i}", "ok": True, "message": "placed"}
             for i in range(ok)]
    accts += [{"account_id": f"{broker}x{i}", "ok": False, "message": m}
              for i, m in enumerate(fail)]
    return {"broker": broker, "ok_accounts": ok, "fail_accounts": len(fail),
            "errors": errors if errors is not None else [a["message"] for a in accts
                                                           if not a["ok"]],
            "accounts": accts}


def test_settle_hands_back_what_the_batch_was_told_it_still_owes():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True,
                          "handback": ["Fidelity reported no position where the "
                                       "journal says we hold"]},
                         [_res("robinhood", ok=1)])
    assert len(s.handed_back) == 1 and "Fidelity" in s.handed_back[0]


def test_nothing_is_handed_back_on_a_dry_run():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True, "dry_run": True,
                          "handback": ["x"]}, [_res("robinhood", ok=1)])
    assert s.handed_back == []


# ---------------------------------- 4 fire-time journal, caps, manual claims

def test_a_leg_the_journal_now_shows_closed_is_dropped_at_fire_time(journal):
    journal += [_t("buy", 1, "R1"), _t("sell", 1, "R1")]
    s = Fire()
    assert A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood")]),
                            autosell=True) is None
    assert s.started == [] and s.retried == []
    assert any("no open IPDN account" in m for m in s.logs)


def test_auto_sell_refuses_an_uncapped_leg_and_hands_it_back(journal, monkeypatch):
    journal.append(_t("buy", 1, "R1"))
    monkeypatch.setattr(A, "_broker_sell_cap", lambda *a, **k: (None, 0))
    s = Fire()
    assert A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood", "101")]),
                            autosell=True) is None
    assert s.started == []
    assert s.retried and "no buy on record" in s.retried[0]


def test_an_uncapped_leg_beside_a_good_one_is_owed_on_the_batch(journal, monkeypatch):
    journal += [_t("buy", 1, "R1"), _t("buy", 1, "F1", "fidelity")]
    real = A._broker_sell_cap
    monkeypatch.setattr(A, "_broker_sell_cap", lambda b, *a, **k: (
        (None, 0) if b == "robinhood" else real(b, *a, **k)))
    s = Fire()
    batch = A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood"),
                                           _leg("Fidelity", "fidelity")]),
                             autosell=True, handback=("couldn't read Schwab",))
    assert [a[0] for a in s.started] == ["fidelity"]
    assert batch["handback"][0] == "couldn't read Schwab"
    assert "no buy on record" in batch["handback"][1]
    assert s.retried == []                     # the batch settle does it


def test_a_manual_exit_claims_the_play_so_the_queue_cannot_sell_it_again(journal):
    journal.append(_t("buy", 1, "R1"))
    s = Fire(_autosell_sold=set())
    resolved = _resolved([_leg("Robinhood", "robinhood")])
    A.App._exit_fire(s, resolved)
    assert A.App._autosell_key(s, resolved.task) in s._autosell_sold
    assert s.saved == 1


def test_a_manual_dry_run_claims_nothing(journal):
    journal.append(_t("buy", 1, "R1"))
    s = Fire(_autosell_sold=set())
    A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood")]), dry_run=True)
    assert s._autosell_sold == set()


def test_a_manual_exit_waits_for_the_queues_holdings_read(journal):
    journal.append(_t("buy", 1, "R1"))
    s = Fire(_queue_busy=True)
    assert A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood")])) is None
    assert s.started == [] and s.notes


def test_a_manual_exit_waits_for_an_order_out_at_the_same_broker(journal):
    journal.append(_t("buy", 1, "R1"))
    s = Fire(_brokers_in_flight={"robinhood"})
    assert A.App._exit_fire(s, _resolved([_leg("Robinhood", "robinhood")])) is None
    assert s.started == []


def test_the_sell_button_waits_for_the_queues_holdings_read():
    s = Fire(_queue_busy=True, _exit_busy=False, _trade_in_flight=False)
    A.App._exit_sell(s, _task())
    assert s.started == [] and s._exit_busy is False and s.notes


# ------------------------------------------------------- 5 partial failures

def test_a_partly_failed_leg_is_handed_back():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True},
                         [_res("fidelity", ok=7, fail=["rejected: halted"] * 3)])
    assert s.handed_back == ["the order failed in 3 accounts at fidelity"]


def test_a_partial_leg_with_a_maybe_placed_order_stays_claimed():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True},
                         [_res("fidelity", ok=7, fail=[
                             "rejected", "Order submitted but not confirmed — verify"])])
    assert s.handed_back == []


def test_a_clean_leg_is_not_handed_back():
    s = Settle()
    s._exit_batch_settle({"exit_task": _task(), "autosell": True},
                         [_res("fidelity", ok=10)])
    assert s.handed_back == []


# --------------------------------------------- 6 exits we hold do not age out

def _sell_row(days_ago, sym="IPDN", broker="Robinhood", sid=None):
    day = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    return {"symbol": sym, "sell_date": day, "source_id": sid or f"{sym}-{days_ago}",
            "legs": [{"broker": broker}]}


def test_an_old_exit_is_kept_while_the_journal_still_holds_it(journal):
    journal.append(_t("buy", 1, "R1"))
    rows = A._merge_sells([_sell_row(20)], [])
    assert [r["source_id"] for r in rows] == ["IPDN-20"]


def test_an_old_exit_we_are_out_of_ages_out(journal):
    journal += [_t("buy", 1, "R1"), _t("sell", 1, "R1")]
    assert A._merge_sells([_sell_row(20)], []) == []


def test_the_hard_ceiling_still_applies(journal):
    journal.append(_t("buy", 1, "R1"))
    assert A._merge_sells([_sell_row(A.SELL_OPEN_MAX_AGE_DAYS + 5)], []) == []


def test_an_old_exit_at_a_broker_we_never_held_ages_out(journal):
    journal.append(_t("buy", 1, "R1"))
    assert A._merge_sells([_sell_row(20, broker="Fidelity")], []) == []


def test_recent_exits_are_untouched(journal):
    assert len(A._merge_sells([_sell_row(2)], [_sell_row(3)])) == 2


# --------------------------------------------- 7 brokers in flight, slots

class Pump:
    _autosell_pump = A.App._autosell_pump
    _autosell_key = A.App._autosell_key
    _reading_keys = A.App._reading_keys

    def __init__(self, queue, in_flight):
        self._autosell_queue = list(queue)
        self._brokers_in_flight = set(in_flight)
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


def test_the_pump_holds_a_sell_at_a_broker_with_an_order_out(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", ""))
    p = Pump([_task(("Fidelity",))], {"fidelity"})
    p._autosell_pump()
    assert p.reads == [] and p._autosell_queue and p.later == [5000]
    assert any("fidelity still has an order out" in m for m in p.logs)


def test_the_pump_is_not_held_by_an_unrelated_broker(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", ""))
    p = Pump([_task(("Fidelity",))], {"wellsfargo"})
    p._autosell_pump()
    assert len(p.reads) == 1 and p._autosell_queue == []


def test_autosell_fire_requeues_when_its_broker_got_busy_mid_read(monkeypatch):
    app = Auto()
    app._brokers_in_flight = {"robinhood"}
    task_res = _resolved([_leg("Robinhood", "robinhood")])
    app._autosell_sold.add(app._autosell_key(task_res.task))
    Auto._autosell_fire(app, task_res)
    assert app.fired == [] and app._autosell_queue == [task_res.task]
    assert app._autosell_key(task_res.task) not in app._autosell_sold


class ResolveStub:
    def after(self, _ms, fn=None, *a):
        if callable(fn):
            fn(*a)

    def _log(self, *a, **k):
        pass


def test_a_browser_brokers_read_holds_its_browser_slot(monkeypatch):
    seen = []

    def holdings():
        seen.append(A._browser_slot("fidelity").locked())
        return None

    monkeypatch.setattr(A, "_load_broker",
                        lambda k: types.SimpleNamespace(get_holdings=holdings))
    A.App._exit_resolve_worker(ResolveStub(), _task(("Fidelity",)), then=lambda r: None)
    assert seen == [True]
    assert not A._browser_slot("fidelity").locked()


def test_a_read_waits_for_the_slot_and_gives_up_at_the_deadline(monkeypatch):
    monkeypatch.setattr(A, "EXIT_READ_TIMEOUT_S", 0.3)
    called = []
    monkeypatch.setattr(A, "_load_broker", lambda k: types.SimpleNamespace(
        get_holdings=lambda: called.append(k)))
    slot = A._browser_slot("fidelity")
    assert slot.acquire(timeout=1)
    try:
        got = []
        A.App._exit_resolve_worker(ResolveStub(), _task(("Fidelity",)), then=got.append)
    finally:
        slot.release()
    (resolved,) = got
    assert called == [] and resolved.errors == ("Fidelity",)


# --------------------------------------------------------- 8 renamed tickers

def test_a_renamed_play_reads_the_journal_under_both_names(journal):
    journal += [_t("buy", 1, "R1", sym="AGAE"), _t("buy", 1, "R2", sym="AGAE")]
    sells = [{"symbol": "AIFA", "sell_date": "2026-10-01", "source_id": "s1",
              "legs": [{"broker": "Robinhood"}]}]
    (blind,) = A._sell_plays(sells)
    assert blind.legs[0].state == A.SELL_NONE      # the bug: "never held"
    (play,) = A._sell_plays(sells, {"AIFA": "AGAE"})
    (leg,) = play.legs
    assert play.symbol == "AIFA" and leg.state == A.SELL_NOW and leg.left == 2
    (task,) = A._sellnow_tasks(sells, {"AIFA": "AGAE"})
    assert (task.symbol, task.alert_symbol, task.accounts) == ("AIFA", "AGAE", 2)


def test_a_sell_under_the_new_name_closes_a_buy_under_the_old(journal):
    journal += [_t("buy", 1, "R1", sym="AGAE"), _t("sell", 1, "R1", sym="AIFA")]
    sells = [{"symbol": "AIFA", "sell_date": "2026-10-01", "source_id": "s1",
              "legs": [{"broker": "Robinhood"}]}]
    (play,) = A._sell_plays(sells, {"AIFA": "AGAE"})
    assert play.legs[0].state == A.SELL_DONE
    assert A._sellnow_tasks(sells, {"AIFA": "AGAE"}) == []
    assert A._leg_open_accounts("robinhood", ("AIFA", "AGAE")) == []


def test_an_exit_called_under_the_old_name_folds_into_the_current_play(journal):
    journal.append(_t("buy", 1, "R1", sym="AGAE"))
    sells = [{"symbol": "AGAE", "sell_date": "2026-09-28", "source_id": "s0",
              "legs": [{"broker": "Robinhood"}]}]
    (play,) = A._sell_plays(sells, {"AIFA": "AGAE"})
    assert play.symbol == "AIFA" and play.legs[0].state == A.SELL_NOW


# ------------------------------------------------ 9 sold-once record order

def test_the_record_keeps_the_newest_keys_by_exit_date():
    keys = {"2026-09-03:B:public", "remnant:2026-09-01:A:public",
            "2026-09-02:C:fidelity", "remnant:2026-09-04:D:public"}
    assert A._autosell_keep_recent(keys, 2) == ["2026-09-03:B:public",
                                                "remnant:2026-09-04:D:public"]
    assert A._autosell_keep_recent(keys, 2) == A._autosell_keep_recent(set(keys), 2)


def test_saving_trims_to_the_newest_two_thousand(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", tmp_path / "autosell_state.json")
    start = datetime(2020, 1, 1)
    keys = {f"{(start + timedelta(days=i)):%Y-%m-%d}:S{i}:robinhood" for i in range(2500)}
    s = types.SimpleNamespace(
        _autosell_enabled=Var(True), _autosell_dry_run=Var(False),
        _autosell_fracs=Var(True), _autosell_sold=set(keys),
        _autosell_reading=set(), _log=lambda *a, **k: None)
    s._reading_keys = types.MethodType(A.App._reading_keys, s)
    A.App._save_autosell_state(s)
    saved = json.loads((tmp_path / "autosell_state.json").read_text())["sold"]
    assert len(saved) == A.AUTOSELL_SOLD_KEEP == 2000
    newest = f"{(start + timedelta(days=2499)):%Y-%m-%d}:S2499:robinhood"
    oldest_kept = f"{(start + timedelta(days=500)):%Y-%m-%d}:S500:robinhood"
    assert saved[-1] == newest and saved[0] == oldest_kept


# --------------------------------------------- 10 unreadable state file

class StateStub:
    _load_autosell_state = A.App._load_autosell_state
    _save_autosell_state = A.App._save_autosell_state
    _announce_autosell_state_blocked = A.App._announce_autosell_state_blocked
    _autosell_consider = A.App._autosell_consider
    _reading_keys = A.App._reading_keys

    def __init__(self):
        self.logs, self.notes = [], []
        self._autosell_enabled = Var(True)
        self._autosell_dry_run = Var(False)
        self._autosell_fracs = Var(True)
        self._autosell_sold = {"2026-10-01:X:robinhood"}

    def _log(self, msg, *a, **k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _autosell_worklist(self):
        raise AssertionError("auto-sell must not look at the board")


@pytest.fixture()
def no_pause(monkeypatch):
    monkeypatch.setattr(A, "AUTOSELL_STATE_READ_PAUSE_S", 0)
    monkeypatch.setattr(A, "_crash_note", lambda *a, **k: None)


def test_an_unreadable_record_is_never_overwritten(tmp_path, monkeypatch, no_pause):
    f = tmp_path / "autosell_state.json"
    f.write_text('{"sold": ["2026-09-01:A:robinhood"', encoding="utf-8")   # torn
    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", f)
    s = StateStub()
    state = s._load_autosell_state()
    assert s._autosell_state_blocked and state["enabled"] is False
    before = f.read_text(encoding="utf-8")
    s._save_autosell_state()
    s._save_autosell_state()
    assert f.read_text(encoding="utf-8") == before
    assert sum("not saving state" in m for m in s.logs) == 1
    s._autosell_consider("test")                # returns before the board
    s._announce_autosell_state_blocked()
    assert any(k == "error" and "Auto-sell is off" in m for m, k in s.notes)


def test_a_transient_failure_is_retried(tmp_path, monkeypatch, no_pause):
    good = json.dumps({"enabled": True, "sold": ["k"]})
    calls = []

    class Flaky:
        name = "autosell_state.json"

        def exists(self):
            return True

        def read_text(self, encoding=None):
            calls.append(1)
            if len(calls) == 1:
                raise PermissionError("[WinError 5] held by sync")
            return good

    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", Flaky())
    s = StateStub()
    assert s._load_autosell_state() == {"enabled": True, "sold": ["k"]}
    assert s._autosell_state_blocked is False and len(calls) == 2


def test_no_file_is_simply_the_defaults(tmp_path, monkeypatch, no_pause):
    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", tmp_path / "missing.json")
    s = StateStub()
    assert s._load_autosell_state()["enabled"] is False
    assert s._autosell_state_blocked is False
    s._save_autosell_state()
    assert (tmp_path / "missing.json").exists()
