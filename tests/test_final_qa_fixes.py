"""Final launch QA (2026-10-05): one block per finding of the independent review.

  1  a 5xx/timeout on the ORDER request is "submitted ... verify"; hand-backs
     need POSITIVE evidence that nothing was sent
  2  one wedged mirror broker no longer blocks every sell
  3  the mirror stall limit covers the slowest broker; a wedged broker is owed
     the picks it missed, not told to buy them by hand
  4  a journal recovered from .bak is written back and does not pause mirror
  5  a hand-fired "Sell all" that sent nothing releases its sold-once claim
  6  (in test_mirror_fixes_2026_10) old open lots don't block a new play
  7  old "login 1" account labels net against the bare form
  8  Wells Fargo: a login holding none of only_accounts is a quiet skip
  9  Fidelity timeout rows / Retry never widen a narrowed run to a whole login
 10  a failed-login row is not an account
 11  CreateMutexW -> NULL + ERROR_ACCESS_DENIED means "already running"

Fake HTTP and stand-ins only: no window, no broker, no network, no order.
"""
from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as A
import balances
import chase
import fidelity
import lifecycle
import sofi
import trade_journal
import wellsfargo

import test_chase_no_double_order as CH
import test_mirror_fixes_2026_10 as MF
import test_sell_qa_fixes as SQ
import test_sofi_no_double_order as SO

run = SO.run                 # SoFi fake-HTTP runner fixture
chase_run = CH.run           # Chase fake-HTTP runner fixture
env = MF.env                 # mirror: open market, healthy journal, fixed date


def _may_exist(msg: str) -> bool:
    return A._account_order_may_exist({"ok": False, "message": msg})


# ===================================================== 1 nothing-sent evidence

def test_sofi_5xx_on_the_order_post_is_verify(run):
    req = SO._FakeReq([SO._ok(), SO._Resp(status=502, text="Bad Gateway"), SO._ok()])
    out = run(req)
    a, b, c = out.accounts
    assert a.ok and c.ok
    assert not b.ok and _may_exist(b.message) and "502" in b.message
    assert not A._nothing_was_sent(b.message)


def test_sofi_4xx_on_the_order_post_stays_a_plain_rejection(run):
    req = SO._FakeReq([SO._Resp(status=400, text="bad qty"), SO._ok(), SO._ok()])
    out = run(req)
    assert not out.accounts[0].ok and not _may_exist(out.accounts[0].message)


def test_chase_5xx_on_the_execute_post_is_verify(chase_run):
    req = CH._FakeReq({"1001": [CH._VAL_OK, CH._Resp(status=503, text="unavailable")]})
    (a,) = chase_run(req, ids=("1001",)).accounts
    assert not a.ok and _may_exist(a.message) and "503" in a.message


def test_chase_4xx_on_the_execute_post_is_verify_too(chase_run):
    # Round-2 audit: only the validate phase may say "Rejected". After the
    # execute POST a 4xx is not proof Chase did not act on it.
    req = CH._FakeReq({"1001": [CH._VAL_OK, CH._Resp(status=400, text="no")]})
    (a,) = chase_run(req, ids=("1001",)).accounts
    assert not a.ok and _may_exist(a.message) and "400" in a.message
    assert not A._nothing_was_sent(a.message)


@pytest.mark.parametrize("msg,sent_nothing", [
    ("HTTP 502: Bad Gateway", False),                  # SoFi's old 5xx text
    ("", False),
    ("something odd happened", False),
    ("Order submitted but SoFi's response was lost — verify in SoFi", False),
    ("Skipped: Fidelity run timed out — nothing was sent", True),
    ("Login failed: bad password", True),
    ("Public login 2 failed: Auth failed", True),
    ("Not sent — connection reset", True),
    ("Rejected — Execution HTTP 400: no", True),
    ("Insufficient shares", True),
    ("Schwab order check failed, nothing was sent: x", True),
    ("Skipped: but the order may have been placed", False),
])
def test_nothing_was_sent_needs_positive_words(msg, sent_nothing):
    assert A._nothing_was_sent(msg) is sent_nothing


class _Mirror(MF.Mirror):
    pass


def _mirror_batch(*results, key=("2026-10-09", "AAA")):
    return {"symbol": "AAA", "mirror_key": key, "all_brokers": ["sofi"],
            "mirror_skipped": [], "results": list(results)}


def _res(broker, accounts=(), errors=None):
    accounts = list(accounts)
    ok = sum(1 for a in accounts if a.get("ok"))
    if errors is None:
        errors = [f"{a['account_id']}: {a['message']}" for a in accounts if not a["ok"]]
    return {"broker": broker, "ok_accounts": ok,
            "fail_accounts": max(len(accounts) - ok, 1 if errors else 0),
            "errors": errors, "accounts": accounts}


def test_mirror_does_not_rearm_a_pick_after_an_unrecognized_failure():
    """SoFi's 'HTTP 502' used no may-exist word and re-armed the pick."""
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    bad = _res("sofi", [{"account_id": "IND (1234)", "ok": False,
                         "message": "HTTP 502: Bad Gateway"}])
    m._mirror_record_outcome(_mirror_batch(bad), 0, 1)
    assert key in m._mirror_executed and key in m._mirror_failed
    assert key not in m._mirror_attempts


def test_mirror_rearms_a_whole_broker_login_failure():
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    login = _res("robinhood", [], errors=["Login failed: device not approved"])
    m._mirror_record_outcome(_mirror_batch(login), 0, 1)
    assert key not in m._mirror_executed and m._mirror_attempts[key] == 1


def test_mirror_needs_every_broker_to_say_nothing_was_sent():
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    login = _res("robinhood", [], errors=["Login failed: x"])
    odd = _res("sofi", [], errors=["KeyError: 'orderId'"])
    m._mirror_record_outcome(_mirror_batch(login, odd), 0, 2)
    assert key in m._mirror_executed


def test_autosell_does_not_hand_back_a_leg_that_failed_unrecognized():
    s = SQ.Settle()
    s._exit_batch_settle({"exit_task": SQ._task(), "autosell": True},
                         [SQ._res("robinhood", fail=["HTTP 500: server error"])])
    assert s.handed_back == []


def test_autosell_hands_back_a_leg_that_says_nothing_was_sent():
    s = SQ.Settle()
    s._exit_batch_settle({"exit_task": SQ._task(), "autosell": True},
                         [SQ._res("robinhood", fail=["Login failed: expired"])])
    assert s.handed_back == ["the order failed at robinhood"]


def test_autosell_partial_needs_every_failed_account_to_say_nothing_sent():
    s = SQ.Settle()
    s._exit_batch_settle({"exit_task": SQ._task(), "autosell": True},
                         [SQ._res("fidelity", ok=7, fail=["rejected", "HTTP 504"])])
    assert s.handed_back == []


# ============================================ 2 a wedged broker blocks nothing

def test_trade_in_flight_leaves_out_wedged_brokers():
    app = types.SimpleNamespace(_brokers_in_flight={"chase"},
                                _mirror_wedged={"chase": {}}, _trade_in_flight=True)
    A._app_recompute_trade_in_flight(app)
    assert app._trade_in_flight is False
    app._brokers_in_flight.add("public")
    A._app_recompute_trade_in_flight(app)
    assert app._trade_in_flight is True


class _DrainMirror(MF.Mirror):
    def _autosell_schedule_check(self, *_a, **_k):
        pass


def test_writing_off_a_mirror_batch_frees_the_app_wide_flag(env):
    m = _DrainMirror(brokers=("chase",))
    MF.Mirror._mirror_execute(m, [MF.pick("AAA")], "10:45", "schedule")
    m._trade_in_flight = True                  # what a later batch landing set
    MF._stall(m, m.batches[0])
    MF.Mirror._mirror_drain(m)
    assert "chase" in m._mirror_wedged and "chase" in m._brokers_in_flight
    assert m._trade_in_flight is False


def test_the_sell_pump_skips_a_blocked_play_and_sells_the_next(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", ""))
    blocked = SQ._task(("Chase",), sym="AAAA")
    free = SQ._task(("Robinhood",), sym="BBBB")
    p = SQ.Pump([blocked, free], {"chase"})
    p._autosell_pump()
    assert len(p.reads) == 1 and p.reads[0][0] is free
    assert p._autosell_queue == [blocked]      # still queued, not dropped
    assert any("AAAA waits" in m and "BBBB first" in m for m in p.logs)


def test_the_sell_pump_still_waits_when_every_play_is_blocked(monkeypatch):
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Open", ""))
    p = SQ.Pump([SQ._task(("Chase",))], {"chase"})
    p._autosell_pump()
    assert p.reads == [] and p.later == [5000]


def test_a_manual_exit_goes_at_a_free_broker_and_not_at_the_wedged_one(monkeypatch):
    rows = [SQ._t("buy", 1, "R1"), SQ._t("buy", 1, "C1", "chase")]
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda *a, **k: list(rows))
    s = SQ.Fire(_trade_in_flight=False, _brokers_in_flight={"chase"},
                _mirror_wedged={"chase": {}})
    assert A.App._exit_fire(s, SQ._resolved([SQ._leg("Robinhood", "robinhood")]))
    assert [a[0] for a in s.started] == ["robinhood"]

    s2 = SQ.Fire(_trade_in_flight=False, _brokers_in_flight={"chase"},
                 _mirror_wedged={"chase": {}})
    assert A.App._exit_fire(s2, SQ._resolved([SQ._leg("Chase", "chase")])) is None
    assert s2.started == [] and any("chase" in m for m, _k in s2.notes)


# ================================= 3 stall limit; owed picks for a wedged broker

def test_the_stall_limit_covers_the_slowest_broker(monkeypatch):
    monkeypatch.setattr(A.broker_logins, "login_count", lambda b: 1)
    assert A._mirror_stall_ms() >= 1800 * 1000 + A.MIRROR_STALL_SLACK_S * 1000
    assert A._mirror_stall_ms() >= A.MIRROR_QUEUE_STALL_MS >= 3_600_000
    monkeypatch.setattr(A.broker_logins, "login_count",
                        lambda b: 4 if b == "fidelity" else 1)
    assert A._mirror_stall_ms() == (1800 + 900 * 3 + A.MIRROR_STALL_SLACK_S) * 1000


def test_a_wedged_broker_is_owed_the_pick_and_gets_it_when_back(env):
    m = MF.Mirror(brokers=("chase", "public"))
    MF.Mirror._mirror_execute(m, [MF.pick("AAA"), MF.pick("BBB")], "10:45", "schedule")
    aaa = m.batches[0]
    aaa["pending"].discard("public")
    m._brokers_in_flight.discard("public")
    MF._stall(m, aaa)
    MF.Mirror._mirror_drain(m)                 # BBB goes to public only

    assert ("public", "BBB") in m.launched and ("chase", "BBB") not in m.launched
    assert [(o["broker"], o["symbol"]) for o in m._mirror_owed] == [("chase", "BBB")]
    assert not any("by hand" in msg for msg, _k in m.notes if "BBB" in msg)

    # chase answers AAA at last; BBB's public batch lands.
    aaa["pending"].discard("chase")
    aaa["finished"] = True
    m.batches[1]["finished"] = True
    m._brokers_in_flight.clear()
    MF.Mirror._mirror_drain(m)

    assert ("chase", "BBB") in m.launched
    assert m.batches[-1]["all_brokers"] == ["chase"]
    assert m._mirror_owed == []


def test_owed_picks_survive_a_save_and_load(env, tmp_path):
    m = MF.Mirror(brokers=("chase",))
    A._mirror_owe(m, "chase", {"symbol": "bbb", "date": "2026-10-09", "note": "Reg Alert"})
    MF.Mirror._save_mirror_state(m)
    saved = json.loads(A.MIRROR_STATE_FILE.read_text(encoding="utf-8"))
    assert saved["owed"] == [{"broker": "chase", "symbol": "BBB",
                              "date": "2026-10-09", "note": "Reg Alert"}]


def test_an_owed_pick_already_bought_by_hand_settles_quietly(env, monkeypatch):
    m = MF.Mirror(brokers=("chase",))
    A._mirror_owe(m, "chase", MF.pick("BBB"))
    m._mirror_executed.add(A.App._mirror_key(MF.pick("BBB")))
    monkeypatch.setattr(A, "_pick_broker_map",
                        lambda picks: {(p["symbol"], p["date"]): {"chase"} for p in picks})
    A._mirror_release_owed(m, {})
    MF.Mirror._mirror_drain(m)
    assert m.launched == [] and m._mirror_owed == []


# ================================================ 4 journal restored from .bak

@pytest.fixture()
def jpath(tmp_path, monkeypatch):
    p = tmp_path / "trades.json"
    monkeypatch.setattr(trade_journal, "_FILE", p)
    monkeypatch.setattr(trade_journal, "_READ_DELAY", 0.0)
    monkeypatch.setattr(trade_journal, "_last_error", None)
    monkeypatch.setattr(trade_journal, "_last_recovery", None)
    trade_journal._cache.clear()
    yield p
    trade_journal._cache.clear()


def _row(i, acct="Public 1 (1234)", broker="public", side="buy", sym="SMTK"):
    return {"id": f"r{i}", "timestamp": f"2026-09-0{i}T00:00:00+00:00",
            "broker": broker, "account_id": acct, "side": side, "symbol": sym,
            "qty": 1.0, "fill_price": 0.25, "order_id": None, "price_source": "fill"}


def test_a_recovered_journal_is_rewritten_and_does_not_pause_mirror(jpath):
    rows = [_row(1), _row(2)]
    jpath.with_suffix(".bak").write_text(json.dumps(rows), encoding="utf-8")
    jpath.write_text('[{"id": "r1", "sym', encoding="utf-8")       # torn

    assert A._mirror_journal_problem() is None
    assert "recovered 2 trades" in trade_journal.last_recovery()
    assert json.loads(jpath.read_text(encoding="utf-8")) == rows   # good copy back
    assert list(jpath.parent.glob("trades.unreadable-*.json"))      # bad one kept


def test_an_unrecoverable_journal_still_pauses_mirror(jpath):
    jpath.write_text('[{"id": "r1", "sym', encoding="utf-8")
    assert "trades.json" in (A._mirror_journal_problem() or "")


def test_a_good_save_clears_a_stale_error(jpath, monkeypatch):
    monkeypatch.setattr(trade_journal, "_last_error", "trades.json could not be opened: x")
    trade_journal.record_trade(broker="public", account_id="P", side="buy",
                               symbol="TOPT", qty=1, fill_price=1.0)
    assert trade_journal.last_error() is None


def test_recovery_never_writes_over_a_journal_a_writer_just_fixed(jpath):
    """Write-back re-checks under the writer lock: only a still-bad file."""
    rows = [_row(1)]
    jpath.with_suffix(".bak").write_text(json.dumps(rows), encoding="utf-8")
    jpath.write_text("not json", encoding="utf-8")
    with trade_journal._lock:                  # a writer holds the lock
        assert trade_journal._load() == rows
    assert jpath.read_text(encoding="utf-8") == "not json"         # left to it


# ================================ 5 a hand-fired sell that sent nothing releases

class _Settle(SQ.Settle):
    _autosell_key = A.App._autosell_key

    def __init__(self):
        super().__init__()
        self._autosell_sold = set()
        self.saved = 0
        self.logs = []

    def _save_autosell_state(self):
        self.saved += 1

    def _log(self, msg, *a, **k):
        self.logs.append(msg)


def test_a_manual_sell_that_sent_nothing_releases_its_claim():
    s = _Settle()
    task = SQ._task()
    s._autosell_sold.add(A.App._autosell_key(s, task))
    s._exit_batch_settle({"exit_task": task, "autosell": False},
                         [SQ._res("robinhood", fail=["Login failed: expired"])])
    assert s._autosell_sold == set() and s.saved == 1


@pytest.mark.parametrize("results", [
    [SQ._res("robinhood", fail=["HTTP 502"])],                       # unknown
    [SQ._res("robinhood", ok=1), SQ._res("fidelity", fail=["Login failed"])],
    [SQ._res("robinhood", fail=["Order submitted — verify in Robinhood"])],
])
def test_a_manual_sell_keeps_its_claim_unless_nothing_was_sent_anywhere(results):
    s = _Settle()
    task = SQ._task()
    key = A.App._autosell_key(s, task)
    s._autosell_sold.add(key)
    s._exit_batch_settle({"exit_task": task, "autosell": False}, results)
    assert key in s._autosell_sold


def test_a_manual_dry_run_never_touches_the_claims():
    s = _Settle()
    task = SQ._task()
    key = A.App._autosell_key(s, task)
    s._autosell_sold.add(key)
    s._exit_batch_settle({"exit_task": task, "dry_run": True},
                         [SQ._res("robinhood", fail=["Login failed"])])
    assert key in s._autosell_sold


# ======================================================= 7 login-1 label aliases

@pytest.mark.parametrize("broker,old,new", [
    ("robinhood", "Robinhood 1 | Individual (1234)", "Individual (1234)"),
    ("schwab", "Schwab 1 (****1234)", "Schwab (****1234)"),
    ("fennel", "Fennel 1 · Main", "Fennel · Main"),
])
def test_old_login_one_labels_map_to_the_bare_form(broker, old, new):
    assert trade_journal.canonical_account(broker, old) == new
    assert trade_journal.canonical_account(broker, new) == new


@pytest.mark.parametrize("broker,acct", [
    ("robinhood", "Robinhood 2 | Individual (1234)"),     # login 2 keeps its prefix
    ("schwab", "Schwab 2 (****1234)"),
    ("fidelity", "Fidelity 1 · Brokerage (X1)"),          # other brokers untouched
    ("public", "Public 1 (1234)"),
])
def test_other_labels_are_left_alone(broker, acct):
    assert trade_journal.canonical_account(broker, acct) == acct


def test_an_old_prefixed_buy_nets_against_a_new_bare_sell(jpath):
    rows = [_row(1, "Robinhood 1 | Individual (1234)", "robinhood", sym="ABCD"),
            _row(2, "Individual (1234)", "robinhood", side="sell", sym="ABCD"),
            _row(3, "Robinhood 2 | Individual (9999)", "robinhood", sym="ABCD")]
    jpath.write_text(json.dumps(rows), encoding="utf-8")
    assert A._leg_open_accounts("robinhood", "ABCD") == [
        ("Robinhood 2 | Individual (9999)", 1.0)]
    # The file keeps what was journaled.
    assert json.loads(jpath.read_text(encoding="utf-8"))[0]["account_id"] \
        == "Robinhood 1 | Individual (1234)"


# ================================== 8 Wells Fargo only_accounts at other logins

def test_wellsfargo_reports_none_found_only_when_no_login_held_any(monkeypatch):
    monkeypatch.setattr(wellsfargo.broker_logins, "fan_out", lambda *a, **k:
                        wellsfargo.BrokerOutput(broker="Wells Fargo", state="success",
                                                accounts=[], message=""))
    out = wellsfargo.execute_trade(side="sell", qty="1", symbol="ABCD",
                                   only_accounts=["WELLSTRADE (****1234)"])
    assert out.state == "failed"
    (row,) = out.accounts
    assert "None of the requested accounts" in row.message
    assert A._nothing_was_sent(row.message)


def test_wellsfargo_passes_through_when_another_login_traded(monkeypatch):
    ok = wellsfargo.AccountOutput(account_id="Wells Fargo 2 · WELLSTRADE (****1234)",
                                  ok=True, message="placed")
    monkeypatch.setattr(wellsfargo.broker_logins, "fan_out", lambda *a, **k:
                        wellsfargo.BrokerOutput(broker="Wells Fargo", state="success",
                                                accounts=[ok], message=""))
    out = wellsfargo.execute_trade(side="sell", qty="1", symbol="ABCD",
                                   only_accounts=[ok.account_id])
    assert out.accounts == [ok] and out.state == "success"


def test_wellsfargo_unmatched_login_is_quiet_in_source():
    src = (ROOT / "wellsfargo.py").read_text(encoding="utf-8")
    block = src[src.index("wanted = [a for a in accts if _account_matches(a, only)]"):]
    block = block[:block.index("accts = wanted")]
    assert 'state="success", accounts=[]' in block and "ok=False" not in block


# ======================================= 9 timeouts and Retry never widen a run

def _progress(**kw):
    p = {"outs": [], "todo": [], "current": None, "clicking": None,
         "login": None, "logins_left": []}
    p.update(kw)
    return p


def test_fidelity_timeout_rows_name_only_the_requested_accounts():
    wanted = {"Fidelity 2 · Brokerage (X222)", "Fidelity 3 · IRA (X333)"}
    rows = fidelity._timeout_rows(
        _progress(login="Fidelity 2", logins_left=["Fidelity 3", "Fidelity 4"]),
        dry_run=False, timeout_s=1800, e=TimeoutError("t"), only_accounts=wanted)
    assert sorted(r.account_id for r in rows) == sorted(wanted)
    assert all(A._nothing_was_sent(r.message) for r in rows)


def test_fidelity_timeout_rows_keep_login_labels_for_a_whole_run():
    rows = fidelity._timeout_rows(_progress(login="Fidelity 2", logins_left=["Fidelity 3"]),
                                  dry_run=False, timeout_s=1800, e=TimeoutError("t"))
    assert [r.account_id for r in rows] == ["Fidelity 2", "Fidelity 3"]


def test_retry_after_an_exit_never_asks_for_a_whole_login():
    res = {"broker": "fidelity", "ok_accounts": 0, "fail_accounts": 2, "errors": [],
           "accounts": [{"account_id": "Fidelity 2", "ok": False,
                         "message": "Skipped: timed out — nothing was sent"},
                        {"account_id": "Fidelity 1 · Brokerage (X1)", "ok": False,
                         "message": "rejected"}]}
    assert A.App._failed_account_plan([res], narrowed=True) == {
        "fidelity": ["Fidelity 1 · Brokerage (X1)"]}
    # A desk order traded every account, so the whole login is what it asked.
    assert A.App._failed_account_plan([res]) == {
        "fidelity": ["Fidelity 2", "Fidelity 1 · Brokerage (X1)"]}


@pytest.mark.parametrize("acct,login", [
    ("Fidelity", True), ("Fidelity 2", True), ("Wells Fargo", True), ("IBKR", True),
    ("Fidelity 2 · Brokerage (X1)", False), ("WELLSTRADE (****1234)", False),
])
def test_login_label_detection(acct, login):
    assert A._is_login_label(acct) is login


# =============================================== 10 failed logins aren't accounts

def test_a_failed_login_row_is_not_counted():
    out = types.SimpleNamespace(accounts=[
        types.SimpleNamespace(account_id="Public 1 Brokerage (1)", ok=True),
        types.SimpleNamespace(account_id="Public 1 Brokerage (2)", ok=True),
        types.SimpleNamespace(account_id="Public 2", ok=False)])
    assert A._ok_account_count(out) == 2


def test_balances_does_not_stamp_a_failed_row_as_seen():
    st = {"brokers": {}}
    balances.record_broker_output("public", [
        {"account_id": "Public 1 Brokerage (1)", "ok": True},
        {"account_id": "Public 2", "ok": False}], st, persist=False)
    assert list(st["brokers"]["public"]) == ["Public 1 Brokerage (1)"]


# ================================================= 11 elevated copy holds mutex

@pytest.mark.skipif(sys.platform != "win32", reason="named mutex is Windows-only")
def test_access_denied_on_the_mutex_means_already_running(monkeypatch, tmp_path):
    import ctypes

    class K32:
        class _Fn:
            def __init__(self, fn):
                self.fn = fn

            def __call__(self, *a):
                return self.fn(*a)

        def __init__(self):
            self.CreateMutexW = self._Fn(lambda *a: None)     # NULL handle
            self.CloseHandle = self._Fn(lambda h: True)

    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **k: K32())
    monkeypatch.setattr(ctypes, "get_last_error", lambda: A._ERROR_ACCESS_DENIED)
    # The lock-file fallback would succeed here; it must never be reached.
    assert A._acquire_single_instance("Local\\RSAMAXXED-test-denied",
                                      tmp_path / ".lock") is False


def test_a_check_with_no_new_picks_still_sends_what_is_owed(env):
    """After a restart nothing is wedged; the next check must send the debt."""
    m = MF.Mirror(brokers=("chase", "public"))
    A._mirror_owe(m, "chase", MF.pick("BBB"))
    m._mirror_executed.add(A.App._mirror_key(MF.pick("BBB")))
    MF.Mirror._mirror_execute(m, [MF.pick("BBB")], "10:45", "schedule")
    assert m.launched == [("chase", "BBB")]
    assert m._mirror_owed == []


# ======================================== re-review: owed batches and retries

def test_an_owed_batch_failure_never_rearms_the_whole_pick():
    # The rest of the pick went out earlier, maybe as "submitted … verify".
    m = _Mirror()
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    login = _res("chase", [], errors=["Login failed: session expired"])
    batch = _mirror_batch(login)
    batch["mirror_owed"] = "chase"
    m._mirror_record_outcome(batch, 0, 1)
    assert key in m._mirror_executed
    assert key not in m._mirror_attempts


def test_an_owed_launch_is_marked_as_one(env):
    m = MF.Mirror(brokers=("chase", "public"))
    MF.Mirror._mirror_execute(m, [MF.pick("AAA"), MF.pick("BBB")], "10:45", "schedule")
    aaa = m.batches[0]
    aaa["pending"].discard("public")
    m._brokers_in_flight.discard("public")
    MF._stall(m, aaa)
    MF.Mirror._mirror_drain(m)
    assert not m.batches[1].get("mirror_owed")       # BBB's normal launch
    aaa["pending"].discard("chase")
    aaa["finished"] = True
    m.batches[1]["finished"] = True
    m._brokers_in_flight.clear()
    MF.Mirror._mirror_drain(m)
    assert m.batches[-1]["mirror_owed"] == "chase"


def test_a_normal_launch_to_a_broker_settles_its_debt_for_that_pick(env):
    m = MF.Mirror(brokers=("chase",))
    A._mirror_owe(m, "chase", MF.pick("BBB"))
    MF.Mirror._mirror_execute(m, [MF.pick("BBB")], "10:45", "schedule")
    assert ("chase", "BBB") in m.launched
    assert m._mirror_owed == []


def test_retry_waits_while_a_planned_broker_still_has_an_order_out():
    notes = []
    app = types.SimpleNamespace(
        _retry_plan={"chase": ["IND (1234)"]},
        _retry_order={"side": "buy", "qty": "1", "symbol": "AAA"},
        _trade_in_flight=False,                 # stuck mirror brokers are left out
        _brokers_in_flight={"chase"},
        _push_notification=lambda msg, kind="info": notes.append((msg, kind)),
    )
    started = []
    app._live_start = lambda batch: started.append(batch)
    A.App._retry_failed_accounts(app)
    assert started == []
    assert notes and "chase" in notes[0][0]
