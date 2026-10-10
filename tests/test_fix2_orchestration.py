"""Order-execution orchestration: what a hung or raising leg leaves behind.

Covers the 2026-10 audit's orchestration findings, all against fakes -- no
window, no broker, no network, no real state file:

  * an unanswered 2FA prompt is bounded and never wedges the next broker's;
  * an exception from INSIDE execute_trade reads as "may have been
    submitted -- verify", never as nothing-sent;
  * a leg that never reports is settled by the watchdog and its broker freed;
  * _trade_batch_finish releases its brokers even when the receipt fails;
  * mirror waits only on the brokers the front pick needs;
  * the ETF and desk launchers re-check the per-broker guard;
  * a .env reload mid fan-out cannot swap a login's credentials.
"""

from __future__ import annotations

import os
import sys
import threading
import time
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import broker_logins
import trade_journal
from modules import _2fa_prompt
from modules.outputs import AccountOutput, BrokerOutput


# ===================================================================== H1: 2FA

@pytest.fixture
def no_hook():
    _2fa_prompt.set_prompt_hook(None)
    yield
    _2fa_prompt.set_prompt_hook(None)


def test_a_held_prompt_lock_times_out_instead_of_hanging(no_hook):
    asked = []
    _2fa_prompt.set_prompt_hook(lambda b, p, t: asked.append(t) or "123456")
    assert _2fa_prompt._ask_lock.acquire()
    try:
        t0 = time.monotonic()
        assert _2fa_prompt.request_code("Fidelity", timeout_s=0.2) is None
        assert time.monotonic() - t0 < 5
    finally:
        _2fa_prompt._ask_lock.release()
    assert asked == []                    # never shown while another was up
    # and the lock is usable again
    assert _2fa_prompt.request_code("Fidelity", timeout_s=1) == "123456"


def test_the_hook_is_handed_the_timeout(no_hook):
    seen = []
    _2fa_prompt.set_prompt_hook(lambda b, p, t: seen.append(t) or "654321")
    _2fa_prompt.request_text("Robinhood", "code?", 42)
    _2fa_prompt.request_text("Robinhood", "code?", None)
    assert seen == [42, _2fa_prompt.DEFAULT_TIMEOUT_S]


def test_run_exclusive_takes_turns_and_is_bounded():
    assert _2fa_prompt._ask_lock.acquire()
    try:
        assert _2fa_prompt.run_exclusive(lambda: "x", 0.1) is None
    finally:
        _2fa_prompt._ask_lock.release()
    assert _2fa_prompt.run_exclusive(lambda: "x", 0.1) == "x"
    assert not _2fa_prompt._ask_lock.locked()


def test_concurrent_brokers_each_get_their_own_answer(no_hook):
    """L2: two brokers asking at once never see each other's prompt."""
    on_screen = []

    def hook(broker, prompt, timeout_s):
        on_screen.append(broker)
        assert len(on_screen) == 1, "two prompts up at once"
        time.sleep(0.05)
        on_screen.pop()
        return {"Fennel": "111111", "Fidelity": "222222"}[broker]

    _2fa_prompt.set_prompt_hook(hook)
    out = {}
    threads = [threading.Thread(target=lambda b=b: out.__setitem__(
        b, _2fa_prompt.request_code(b, 5))) for b in ("Fennel", "Fidelity")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert out == {"Fennel": "111111", "Fidelity": "222222"}


class NeverRunsUI:
    """An app whose UI loop never gets to the queued ask (wedged, or busy)."""

    def __init__(self):
        self.queued = []

    def after(self, _ms, fn=None, *a):
        self.queued.append((fn, a))


def test_ask_from_thread_gives_up_when_the_ui_never_answers(monkeypatch):
    monkeypatch.setattr(A, "_ASK_GRACE_S", 0)
    ui = NeverRunsUI()
    t0 = time.monotonic()
    assert A.App._ask_from_thread(ui, "Fidelity verification", "code?",
                                  timeout_s=0.2) is None
    assert time.monotonic() - t0 < 5
    # Run the ask the UI finally got round to: it shows nothing, because the
    # asker already left. Then the take-down, which has nothing to cancel.
    for fn, a in list(ui.queued):
        fn(*a)


def test_ask_from_thread_passes_the_timeout_to_the_dialog(monkeypatch):
    seen = {}

    class UI:
        def after(self, _ms, fn=None, *a):
            fn(*a)

        def _show_notification(self, *a, **k):
            pass

        def _hide_notification(self):
            pass

        def _log(self, *a, **k):
            pass

        def _ask_inline(self, title, prompt, timeout_s=None, dismiss=None):
            seen["timeout"] = timeout_s
            return "999999"

    assert A.App._ask_from_thread(UI(), "t", "p", timeout_s=30) == "999999"
    assert seen["timeout"] == 30


# ====================================================== H3: raised mid-order

class WorkerStub:
    def __init__(self):
        self.completed = []
        self.logs = []
        self._quick_picks = []

    def after(self, _ms, func=None, *args):
        if callable(func):
            func(*args)

    def _log(self, msg, tag=None):
        self.logs.append(msg)

    def _fetch_quote_price(self, *a, **k):
        return None

    def _trade_result_write(self, *a, **k):
        pass

    def _render_quick_picks(self, *a):
        pass

    def _trade_broker_complete(self, batch, summary):
        self.completed.append(summary)


@pytest.fixture
def worker(tmp_path, monkeypatch):
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    monkeypatch.setattr(A, "_browser_slot", lambda b: None)
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)
    return WorkerStub()


def _run(stub, monkeypatch, execute, dry=False, only=None):
    monkeypatch.setattr(A, "_load_broker",
                        lambda b: types.SimpleNamespace(execute_trade=execute))
    batch = {"origin": "desk", "pending": {"sofi"}}
    A.App._trade_worker(stub, "sofi", "buy", "AIFA", "1", dry, batch, only)
    (summary,) = stub.completed
    return summary, batch


def _boom(**_kw):
    raise RuntimeError("HTTP 502 from order endpoint")


def test_a_raise_inside_execute_trade_reads_as_may_exist(worker, monkeypatch):
    s, batch = _run(worker, monkeypatch, _boom)
    assert any(A._account_order_may_exist(a) for a in s["accounts"])
    assert not A._result_nothing_sent(s)
    assert A._order_may_exist(s)
    # Retry leaves it out entirely.
    assert A.App._failed_account_plan([s]) == {}
    assert "leg_started" in batch and "sofi" in batch["leg_started"]


def test_a_raise_before_execute_trade_adds_no_row(worker, monkeypatch):
    def bad_load(_b):
        raise RuntimeError("module import failed")
    monkeypatch.setattr(A, "_load_broker", bad_load)
    A.App._trade_worker(worker, "sofi", "buy", "AIFA", "1", False,
                        {"origin": "desk", "pending": {"sofi"}})
    (s,) = worker.completed
    # No row, and (round-2 audit) the error positively says nothing went out.
    assert s["accounts"] == [] and s["errors"] == ["module import failed — nothing was sent"]
    assert A._result_nothing_sent(s)


def test_a_raise_that_says_nothing_was_sent_keeps_the_positive_rule(worker, monkeypatch):
    def refused(**_kw):
        raise RuntimeError("login failed — nothing was sent")
    s, _ = _run(worker, monkeypatch, refused)
    assert s["accounts"] == []
    assert A._result_nothing_sent(s)


def test_a_module_that_cannot_narrow_is_still_nothing_sent(worker, monkeypatch):
    def no_narrow(*, side, qty, symbol, dry_run):
        raise AssertionError("not reached")
    s, _ = _run(worker, monkeypatch, no_narrow, only=["acct-1"])
    assert s["accounts"] == []
    assert "cannot trade specific accounts" in s["errors"][0]


def test_a_dry_run_raise_adds_no_row(worker, monkeypatch):
    s, _ = _run(worker, monkeypatch, _boom, dry=True)
    assert s["accounts"] == []


def test_fan_out_per_login_raise_reads_as_may_exist(monkeypatch):
    rows = [types.SimpleNamespace(idx=i, label=f"SoFi {i}", label_prefix=
                                  "" if i == 1 else f"SoFi {i} · ", broker="sofi",
                                  schema=types.SimpleNamespace(fields=()),
                                  get=lambda n: "") for i in (1, 2)]
    monkeypatch.setattr(broker_logins, "logins", lambda b: rows)
    module = types.SimpleNamespace(BROKER="sofi", BrokerOutput=BrokerOutput,
                                   AccountOutput=AccountOutput)

    def one(**kw):
        if broker_logins.active_idx("sofi") == 2:
            raise RuntimeError("socket closed")
        return BrokerOutput(broker="sofi", state="success", accounts=[
            AccountOutput(account_id="a1", ok=True, message="filled")])

    out = broker_logins.fan_out("sofi", module, one, side="buy", qty="1",
                                symbol="AIFA", dry_run=False)
    bad = [a for a in out.accounts if not a.ok]
    assert len(bad) == 1
    assert A._account_order_may_exist({"ok": False, "message": bad[0].message})

    # A read (no side) or a dry run keeps the plain error.
    out = broker_logins.fan_out("sofi", module, one)
    assert [a.message for a in out.accounts if not a.ok] == ["socket closed"]
    out = broker_logins.fan_out("sofi", module, one, side="buy", dry_run=True)
    assert [a.message for a in out.accounts if not a.ok] == ["socket closed"]


# ============================================== H2/L3: watchdog and release

class BatchApp:
    """Real batch bookkeeping, fake widgets."""

    def __init__(self, brokers):
        self._brokers_in_flight = set(brokers)
        self._trade_in_flight = True
        self._live_batches = []
        self.logs = []
        self.notes = []
        self.scheduled = []

    _release_broker = A.App._release_broker
    _trade_broker_complete = A.App._trade_broker_complete

    def after(self, ms, fn=None, *a):
        self.scheduled.append((ms, fn, a))

    def _refresh_trade_busy(self):
        pass

    def _log(self, msg, *_a, **_k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _render_done_receipt(self, **_k):
        pass

    def _trade_result_write(self, *_a, **_k):
        pass

    def _live_hide(self):
        pass

    def _refresh_sell_views(self):
        pass

    def _cloud_push_async(self):
        pass

    def _trade_batch_finish(self, batch):
        A.App._trade_batch_finish(self, batch)


def _batch(brokers, started):
    return {"pending": set(brokers), "all_brokers": sorted(brokers),
            "results": [], "side": "sell", "symbol": "AIFA", "qty": "1",
            "dry_run": False, "origin": "desk", "finished": False,
            "started": started}


def test_watchdog_settles_a_leg_that_never_reports(monkeypatch):
    monkeypatch.setattr(A, "_mirror_stall_ms", lambda: 60_000)
    monkeypatch.setattr(A, "TRADE_LEG_WATCHDOG_SLACK_S", 0)
    app = BatchApp(["fidelity", "robinhood"])
    now = datetime.now()
    batch = _batch(["fidelity", "robinhood"], now - timedelta(minutes=5))
    app._live_batches.append(batch)
    batch["leg_started"] = {"fidelity": now - timedelta(minutes=5),
                            "robinhood": now}
    A.App._trade_leg_watchdog(app, batch)

    # Fidelity is written off as may-exist and freed; Robinhood is still live.
    assert batch["pending"] == {"robinhood"}
    assert app._brokers_in_flight == {"robinhood"}
    (r,) = batch["results"]
    assert r["broker"] == "fidelity" and r["watchdog"]
    assert not A._result_nothing_sent(r)
    assert A.App._failed_account_plan([r]) == {}
    assert any("verify" in m for m, _ in app.notes)
    assert app.scheduled                  # re-armed for the leg still out

    # Robinhood lands normally: the batch finishes and the app is idle.
    A.App._trade_broker_complete(app, batch, {
        "broker": "robinhood", "ok_accounts": 1, "fail_accounts": 0,
        "shares": 1.0, "errors": [], "state": "success", "accounts": []})
    assert batch["finished"] and not app._brokers_in_flight
    assert app._trade_in_flight is False

    # Fidelity's thread finally answers: logged loudly, never double-counted.
    A.App._trade_broker_complete(app, batch, {
        "broker": "fidelity", "ok_accounts": 2, "fail_accounts": 0,
        "shares": 2.0, "errors": [], "state": "success", "accounts": []})
    assert len(batch["results"]) == 2
    assert any("reported after it was written off" in m for m in app.logs)


def test_watchdog_gives_a_leg_waiting_for_its_browser_the_lock_wait(monkeypatch):
    monkeypatch.setattr(A, "_mirror_stall_ms", lambda: 60_000)
    monkeypatch.setattr(A, "TRADE_LEG_WATCHDOG_SLACK_S", 0)
    app = BatchApp(["fidelity"])
    batch = _batch(["fidelity"], datetime.now() - timedelta(minutes=5))
    A.App._trade_leg_watchdog(app, batch)       # never got its browser
    assert batch["pending"] == {"fidelity"} and not batch["results"]


def test_watchdog_rearm_survives_a_synchronous_after(monkeypatch):
    """Stand-in apps run after() inline; the watchdog must not recurse."""
    app = BatchApp(["public"])
    app.after = lambda ms, fn=None, *a: fn(*a) if callable(fn) else None
    batch = _batch(["public"], datetime.now())
    A.App._trade_leg_watchdog(app, batch)
    assert batch["pending"] == {"public"}


def test_batch_release_runs_even_when_the_receipt_raises():
    app = BatchApp(["fidelity"])

    def broken(**_k):
        raise RuntimeError("widget gone")
    app._render_done_receipt = broken
    batch = _batch(["fidelity"], datetime.now())
    app._live_batches.append(batch)
    with pytest.raises(RuntimeError):
        A.App._trade_broker_complete(app, batch, {
            "broker": "fidelity", "ok_accounts": 1, "fail_accounts": 0,
            "shares": 1.0, "errors": [], "state": "success", "accounts": []})
    assert not app._brokers_in_flight
    assert app._trade_in_flight is False
    assert app._live_batches == []


def test_live_start_arms_the_watchdog():
    app = BatchApp([])
    batch = _batch(["sofi"], datetime.now())
    A.App._live_start(app, batch)
    assert "sofi" in app._brokers_in_flight
    assert any(fn is A.App._trade_leg_watchdog for _ms, fn, _a in app.scheduled)


# ========================================= H2: mirror busy check, front pick

def test_mirror_waits_only_on_brokers_the_front_pick_needs(monkeypatch):
    app = types.SimpleNamespace(
        _mirror_selected_brokers={"fidelity", "robinhood", "public"},
        _mirror_journal_key=lambda p: ("AIFA", "d"))
    monkeypatch.setattr(A, "_pick_broker_map",
                        lambda picks: {("AIFA", "d"): {"public"}})
    assert A.App._mirror_pick_needs(app, {"symbol": "AIFA"}) == {"fidelity", "robinhood"}
    assert A.App._mirror_pick_needs(app, {"symbol": "AIFA", "_only": "robinhood"}) == {"robinhood"}

    def unreadable(_p):
        raise OSError("journal locked")
    monkeypatch.setattr(A, "_pick_broker_map", unreadable)
    assert A.App._mirror_pick_needs(app, {"symbol": "AIFA"}) == app._mirror_selected_brokers


# ============================================ M1 / L1: launchers re-check

def test_invest_refuses_a_broker_with_an_order_out():
    notes = []
    app = types.SimpleNamespace(
        _brokers_in_flight={"fidelity"},
        _push_notification=lambda m, k="info": notes.append(m))
    plan = types.SimpleNamespace(actionable=[types.SimpleNamespace(broker="fidelity"),
                                             types.SimpleNamespace(broker="public")])
    assert A.App._invest_brokers_busy(app, plan) is True
    assert "fidelity" in notes[0]
    app._brokers_in_flight = {"robinhood"}
    assert A.App._invest_brokers_busy(app, plan) is False


class Var:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v


def test_desk_rechecks_the_guard_after_the_large_qty_dialog(monkeypatch):
    launched = []
    app = types.SimpleNamespace(
        _trade_selected_brokers={"fidelity"}, _trade_side=Var("buy"),
        _trade_symbol=Var("aifa"), _trade_qty=Var("10"), _trade_dry=Var(False),
        _brokers_in_flight=set(), notes=[],
        _push_notification=lambda m, k="info": app.notes.append(m),
        _log=lambda *a, **k: None,
        _trade_result_write=lambda *a, **k: None,
        _live_start=lambda b: launched.append(b),
        _run_in_thread=lambda *a: launched.append(a))

    def yes_but_mirror_claims_it(*_a, **_k):
        app._brokers_in_flight.add("fidelity")   # claimed while the box was up
        return True
    monkeypatch.setattr(A.messagebox, "askyesno", yes_but_mirror_claims_it)
    A.App._trade_execute(app)
    assert launched == []
    assert any("already running" in n for n in app.notes)


# ================================================ M2: env reload mid fan-out

def test_reload_mid_fan_out_keeps_the_active_login(tmp_path, monkeypatch):
    key = "FIX2_TEST_PASSWORD"
    monkeypatch.setenv(key, "login1-old")
    login2 = types.SimpleNamespace(
        broker="fix2test", idx=2,
        schema=types.SimpleNamespace(fields=(types.SimpleNamespace(
            env=key, name="password"),)),
        get=lambda n: "login2-secret")

    def fake_load(path, override=True, interpolate=False):
        os.environ[key] = "login1-new"          # what .env says now

    with broker_logins.activated(login2):
        assert os.environ[key] == "login2-secret"
        broker_logins.reload_env(tmp_path / ".env", load=fake_load)
        assert os.environ[key] == "login2-secret"       # not swapped mid-call
        broker_logins.set_env({key: "login1-saved"})
        assert os.environ[key] == "login2-secret"
    # Restored to the newest login-1 value, not the stale snapshot.
    assert os.environ[key] == "login1-saved"
    assert key not in broker_logins._pinned and not broker_logins._snapshots

    broker_logins.reload_env(tmp_path / ".env", load=fake_load)
    assert os.environ[key] == "login1-new"


def test_app_reload_goes_through_the_env_lock(monkeypatch):
    calls = []
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: calls.append(k))
    A._reload_env()
    assert calls == [{"override": True, "interpolate": False}]


# ======================================================= C1: one app copy

def test_single_instance_guard_runs_before_the_window():
    src = (Path(A.__file__)).read_text(encoding="utf-8")
    main = src[src.index('if __name__ == "__main__":'):]
    assert main.index("_single_instance_or_exit()") < main.index("App()")
    bat = (Path(A.__file__).parent / "RSAMAXXED.bat").read_text(encoding="utf-8")
    assert "app.py" in bat                       # the .bat runs this entry point
