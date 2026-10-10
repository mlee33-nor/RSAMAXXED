"""Cross-area gaps closed after the fix2 merges (fix3/desk), one block each.

  1  the requirements.txt drift check runs at startup, off the main thread,
     loudly (notification + Activity) and can never crash or stall it
  2  fidelity.py splits FIDELITY=... the way the login editor writes it, so a
     ':' in a password survives the round trip
  3  sell ledgers net per account NUMBER (trade_journal.account_key over
     canonical_account), not per label, and report the newest label
  4  a browser broker whose hung, written-off leg still holds its Chrome slot
     is owed mirror picks (not sent them) and holds auto-sell back
  5  the hand-fired Sell dialog warns about an auto-sell may-exist hold

Pure logic against stand-ins: no window, no broker, no network, no order.
"""
from __future__ import annotations

import sys
import threading
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as A
import broker_logins
import lifecycle
import trade_journal
from modules import depcheck
from test_mirror_fixes_2026_10 import env  # noqa: F401  (the shared fixture)


# ================================================= 1. startup dependency check

class _Inline:
    """Runs a 'thread' on the spot, so the test sees what it did."""

    def __init__(self, target=None, name=None, daemon=None, **_k):
        self.target, self.daemon = target, daemon

    def start(self):
        self.target()


class _Shell:
    def __init__(self, log_raises=False, notify_raises=False):
        self.logs, self.notes, self.scheduled = [], [], []
        self.log_raises, self.notify_raises = log_raises, notify_raises

    def after(self, ms, fn=None, *a):
        self.scheduled.append(ms)
        fn(*a)

    def _log(self, msg, tag=None):
        if self.log_raises:
            raise RuntimeError("log widget gone")
        self.logs.append((msg, tag))

    def _push_notification(self, msg, kind="info"):
        if self.notify_raises:
            raise RuntimeError("toast failed")
        self.notes.append((msg, kind))


def test_a_drift_is_said_loudly_in_both_places(monkeypatch):
    monkeypatch.setattr(A.threading, "Thread", _Inline)
    monkeypatch.setattr(depcheck, "startup_warning",
                        lambda *a, **k: "Installed libraries do not match — x")
    s = _Shell()
    A.App._startup_depcheck(s)
    assert s.notes == [("Installed libraries do not match — x", "error")]
    assert s.logs == [("Dependency check: Installed libraries do not match — x",
                       "error")]


def test_no_drift_says_nothing(monkeypatch):
    monkeypatch.setattr(A.threading, "Thread", _Inline)
    monkeypatch.setattr(depcheck, "startup_warning", lambda *a, **k: "")
    s = _Shell()
    A.App._startup_depcheck(s)
    assert s.notes == [] and s.logs == []


def test_the_check_can_never_take_startup_down(monkeypatch):
    monkeypatch.setattr(A.threading, "Thread", _Inline)
    monkeypatch.setattr(depcheck, "startup_warning", lambda *a, **k: "drift")
    A.App._startup_depcheck(_Shell(log_raises=True, notify_raises=True))

    def boom(*a, **k):
        raise RuntimeError("metadata exploded")
    monkeypatch.setattr(depcheck, "warn_at_startup", boom)
    A.App._startup_depcheck(_Shell())

    class NoThreads:
        def __init__(self, *a, **k):
            raise RuntimeError("can't start new thread")
    monkeypatch.setattr(A.threading, "Thread", NoThreads)
    A.App._startup_depcheck(_Shell())


def test_it_runs_on_a_daemon_thread_and_is_scheduled_at_startup(monkeypatch):
    made = []

    class Spy(_Inline):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            made.append(self)

        def start(self):
            pass                        # never runs: the window is not held up
    monkeypatch.setattr(A.threading, "Thread", Spy)
    A.App._startup_depcheck(_Shell())
    assert len(made) == 1 and made[0].daemon is True
    src = Path(A.__file__).read_text(encoding="utf-8")
    init = src[src.index("        self._build_shell()\n"):src.index("    # ---- Worker -> UI handoff")]
    assert "self.after(1500, self._startup_depcheck)" in init


# ================================================= 2. fidelity ':' passwords

def test_a_colon_in_a_fidelity_password_survives_the_round_trip(monkeypatch):
    import fidelity
    rows = [{"username": "u1", "password": "pa:ss", "totp": ""},
            {"username": "u2", "password": "a:b:c", "totp": "TOTP2"},
            {"username": "u3", "password": "plain", "totp": "TOTP3"}]
    blob = broker_logins.env_updates("fidelity", rows)["FIDELITY"]
    monkeypatch.setenv("FIDELITY", blob)
    creds = fidelity._load_creds()
    assert [(c.username, c.password, c.totp_secret) for c in creds] == [
        ("u1", "pa:ss", ""), ("u2", "a:b:c", "TOTP2"), ("u3", "plain", "TOTP3")]
    # Login 1's label (and with it its session/profile dir) is unchanged.
    assert [(c.idx_1based, c.label) for c in creds] == [
        (1, "Fidelity 1"), (2, "Fidelity 2"), (3, "Fidelity 3")]


def test_blobs_already_on_disk_read_exactly_as_before(monkeypatch):
    import fidelity
    monkeypatch.setenv("FIDELITY", "u1:p1:T1,u2:p2")
    creds = fidelity._load_creds()
    assert [(c.username, c.password, c.totp_secret) for c in creds] == [
        ("u1", "p1", "T1"), ("u2", "p2", "")]


# ================================================= 3. label drift, sell side

def _t(side, qty, acct, broker="fidelity", sym="IPDN"):
    return {"broker": broker, "symbol": sym, "account_id": acct,
            "side": side, "qty": qty}


@pytest.fixture()
def journal(monkeypatch):
    rows: list = []
    monkeypatch.setattr(trade_journal, "get_trades", lambda *a, **k: list(rows))
    return rows


OLD = "Fidelity 1 · Individual (Z12345678)"
NEW = "Fidelity 1 · FinTec (Z12345678)"


def test_a_sell_under_a_new_label_closes_the_buy_under_the_old(journal):
    journal += [_t("buy", 1, OLD), _t("sell", 1, NEW)]
    assert A._leg_open_accounts("fidelity", "IPDN") == []
    assert lifecycle.held_accounts() == {}
    assert A._broker_sell_cap("fidelity", ("IPDN",)) == (None, 0)


def test_an_open_account_is_one_account_under_its_newest_label(journal):
    journal += [_t("buy", 1, OLD), _t("buy", 1, NEW),
                _t("buy", 1, "Fidelity 1 · Roth (Z99999999)")]
    assert A._leg_open_accounts("fidelity", "IPDN") == [
        (NEW, 2.0), ("Fidelity 1 · Roth (Z99999999)", 1.0)]
    assert lifecycle.held_accounts() == {"IPDN": {"Fidelity": 2}}


def test_login1_alias_and_label_drift_net_together(journal):
    journal += [_t("buy", 1, "Robinhood 1 | Individual", "robinhood"),
                _t("sell", 1, "Individual", "robinhood")]
    assert A._leg_open_accounts("robinhood", "IPDN") == []
    assert lifecycle.held_accounts() == {}


def test_public_caps_follow_the_account_not_the_label(journal):
    journal += [_t("buy", 1, "Public 1 BROKERAGE (1234)", "public"),
                _t("sell", 0.2, "Public 1 Brokerage (1234)", "public"),
                _t("buy", 1, "Public 1 BROKERAGE (5678)", "public"),
                _t("sell", 1, "Public 1 Brokerage (5678)", "public")]
    caps = A._public_sell_caps(("IPDN",))
    assert caps == {"Public 1 Brokerage (1234)": 1.0}     # 5678 is closed


def test_different_accounts_never_merge(journal):
    # No number in the label: keyed on the label itself, as before.
    journal += [_t("buy", 1, "SoFi · Invest (manual entry)", "sofi"),
                _t("sell", 1, "SoFi · IRA (manual entry)", "sofi")]
    assert len(A._leg_open_accounts("sofi", "IPDN")) == 1


def test_only_accounts_carries_the_newest_label_and_the_broker_still_matches(journal):
    import fidelity
    journal += [_t("buy", 1, OLD)]
    journal += [_t("buy", 1, NEW), _t("sell", 1, NEW)]   # one share still open
    leg = lifecycle.BrokerLeg(broker="Fidelity", key="fidelity", qty="1",
                              accounts=1, low=1.0, high=1.0)
    task = lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                              alert_date="2026-10-01", status="exit_called",
                              brokers=("Fidelity",), accounts=1)
    plan = A._exit_leg_plan(lifecycle.ResolvedExit(task=task, legs=(leg,),
                                                   missing=(), errors=()),
                            autosell=True)
    assert plan["only"]["fidelity"] == [NEW]
    # Fidelity matches only_accounts on the account NUMBER, so whichever
    # label the journal holds, today's account is the one traded.
    live = {"acctNum": "Z12345678", "name": "Whatever Today"}
    for lbl in (OLD, NEW):
        assert fidelity._fid_account_matches(
            live, "Fidelity 1 · Whatever Today (Z12345678)", {lbl})


def test_wells_fargo_matches_only_accounts_on_the_mask():
    import wellsfargo
    live = {"mask": "****0012", "account_id": "WELLSTRADE (****0012)"}
    assert wellsfargo._account_matches(live, {"Old name (****0012)"})
    assert not wellsfargo._account_matches(live, {"Old name (****0099)"})


# ================================================= 4. hung browser slot

@pytest.fixture()
def holders(monkeypatch):
    d: dict = {}
    monkeypatch.setattr(A, "_slot_holders", d)
    return d


def test_only_a_written_off_leg_still_holding_the_slot_is_hung(holders):
    holders["fidelity"] = {"timed_out": {"fidelity"}}
    holders["chase"] = {"timed_out": set()}             # healthy, just slow
    assert A._hung_browser_brokers() == {"fidelity"}


def test_auto_sell_waits_on_a_hung_broker(holders):
    task = types.SimpleNamespace(brokers=("Fidelity", "Robinhood"))
    assert A._task_brokers_in_flight(task, set()) == []
    holders["fidelity"] = {"timed_out": {"fidelity"}}
    assert A._task_brokers_in_flight(task, set()) == ["fidelity"]


def test_the_worker_marks_and_clears_its_slot(monkeypatch, holders, tmp_path):
    import test_fix2_orchestration as O
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)
    lock = threading.Lock()
    monkeypatch.setattr(A, "_browser_slot", lambda b: lock)
    batch = {"origin": "desk", "pending": {"fidelity"}}
    seen = {}

    def execute(**_kw):
        seen["holder"] = A._slot_holders.get("fidelity")
        batch["timed_out"] = {"fidelity"}               # the watchdog fires
        seen["hung"] = A._hung_browser_brokers()
        raise RuntimeError("socket closed")
    monkeypatch.setattr(A, "_load_broker",
                        lambda b: types.SimpleNamespace(execute_trade=execute))
    stub = O.WorkerStub()
    A.App._trade_worker(stub, "fidelity", "buy", "AIFA", "1", False, batch)
    assert seen["holder"] is batch and seen["hung"] == {"fidelity"}
    assert holders == {} and not lock.locked()          # free again, and says so


def test_mirror_owes_a_hung_broker_instead_of_sending_into_it(holders, env):
    import test_fix_mirror as FM
    import test_mirror_fixes_2026_10 as MF
    m = FM._Mirror(brokers=("public", "fidelity"))
    holders["fidelity"] = {"timed_out": {"fidelity"}}
    p = {"symbol": "AAA", "date": MF.TODAY.isoformat(), "note": "Reg Alert"}
    A.App._mirror_launch_pick(m, dict(p))
    assert m.launched == [("public", "AAA")]
    assert [(o["broker"], o["symbol"]) for o in m._mirror_owed] == [("fidelity", "AAA")]

    # Still hung: the owed pick is not released to it.
    A._mirror_release_owed(m, set(m._mirror_wedged) | A._hung_browser_brokers())
    assert not any(q.get("_only") == "fidelity" for q in m._mirror_queue)
    # The hung thread lets go: the next drain sends it, to fidelity only.
    holders.clear()
    A._mirror_release_owed(m, set(m._mirror_wedged) | A._hung_browser_brokers())
    assert [(q["_only"], q["symbol"]) for q in m._mirror_queue] == [("fidelity", "AAA")]


def test_a_wedge_is_not_lifted_while_the_slot_is_still_held(holders, env):
    import test_fix_mirror as FM
    m = FM._Mirror(brokers=("public", "fidelity"))
    wb = {"symbol": "OLD", "pending": set(), "finished": False}   # watchdog settled
    m._mirror_wedged = {"fidelity": wb}
    holders["fidelity"] = {"timed_out": {"fidelity"}}
    A.App._mirror_drain(m)
    assert "fidelity" in m._mirror_wedged
    holders.clear()
    A.App._mirror_drain(m)
    assert m._mirror_wedged == {}


def test_a_late_report_wakes_the_mirror(monkeypatch):
    calls = []
    s = types.SimpleNamespace(
        _log=lambda *a, **k: None, _push_notification=lambda *a, **k: None,
        _mirror_nudge_drain=lambda: calls.append(1))
    A.App._trade_leg_late_report(s, {"symbol": "AAA"},
                                 {"broker": "fidelity", "ok_accounts": 1})
    assert calls == [1]


# ================================================= 5. hand sell vs may-exist

def _resolved(*brokers, status="exit_called"):
    legs = tuple(lifecycle.BrokerLeg(broker=b, key=lifecycle.app_key(b), qty="1",
                                     accounts=1, low=1.0, high=1.0) for b in brokers)
    task = lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                              alert_date="2026-10-01", status=status,
                              brokers=tuple(brokers), accounts=1)
    return lifecycle.ResolvedExit(task=task, legs=legs, missing=(), errors=())


class _Holds:
    _autosell_play_key = A.App._autosell_play_key


def test_a_hold_on_this_play_and_broker_is_warned():
    app = _Holds()
    r = _resolved("Fidelity", "Robinhood")
    A._autosell_hold(app, r.task, ["fidelity"])
    warns = A._exit_may_exist_warnings(app, r)
    assert len(warns) == 1
    assert warns[0].startswith("Fidelity:")
    assert "may still be open" in warns[0] and "check the broker first" in warns[0]


def test_no_hold_or_another_play_says_nothing():
    app = _Holds()
    assert A._exit_may_exist_warnings(app, _resolved("Fidelity")) == []
    other = _resolved("Fidelity")
    A._autosell_hold(app, lifecycle.SellTask(
        symbol="ZZZ", alert_symbol="ZZZ", alert_date="2026-10-01",
        status="exit_called", brokers=("Fidelity",), accounts=1), ["fidelity"])
    assert A._exit_may_exist_warnings(app, other) == []


def test_an_expired_hold_says_nothing():
    # Time only ends a hold at a DAY-order brokerage (fix4: Fidelity's ticket
    # time-in-force is unverified, so its holds wait for evidence).
    app = _Holds()
    r = _resolved("Schwab")
    A._autosell_hold(app, r.task, ["schwab"], now=datetime(2020, 1, 1))
    assert A._exit_may_exist_warnings(app, r) == []


def test_the_warning_never_blocks_the_sell():
    """Shown, not enforced: the confirm dialog still offers Sell, and the
    decision function never raises on a broken stand-in."""
    assert A._exit_may_exist_warnings(object(), object()) == []
    src = Path(A.__file__).read_text(encoding="utf-8")
    body = src[src.index("    def _exit_confirm(self, resolved)"):
               src.index("    def _exit_confirm_warnings(resolved)")]
    assert "_exit_may_exist_warnings(self, resolved)" in body
    assert body.index("_exit_may_exist_warnings") < body.index("Sell at {_plural")
