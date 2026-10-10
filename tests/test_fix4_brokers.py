"""Round-2 adversarial audit, broker findings (fix4/brokers).

  1  Chase: after the execute POST nothing says "Rejected"; an order id with an
     accepted state is a placed order
  2  Fidelity: "Order notifications" / "Order no longer valid" are not an order
     number; an error alert or dialog is never a confirmation
  3  Fennel: a createOrder status other than "pending" may be live -> verify
  4  Schwab: the session cache is keyed by username, never inherited by
     another login
  5  Robinhood: a login whose account list fails to load is a failed row
  6  app: the leg watchdog clock restarts for each separately bounded phase
  7  Robinhood: a cancelled code prompt fails the login instead of re-POSTing
     an empty code every 5 seconds
  8  Wells Fargo: requested accounts no login holds get a row
  9  nothing-sent wording only where the code path proves it
 10  the smaller ones (busy desk, lock waits, profile lock owner, unmasked
     Chase account, per-login Schwab scoping, cancel rows, empty holdings)
 11  Public: sell caps follow the account, not the login's position in .env

Fake HTTP, stub clients and stand-in apps only: no window, no browser, no
network, no broker, no order.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import types
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as A
import chase
import fennel
import fidelity
import public
import robinhood as RH
import schwab
import sofi
import wellsfargo

import test_chase_no_double_order as CH
import test_concurrent_orders as CO
import test_fix2_orchestration as ORC
import test_sofi_no_double_order as SO

chase_run = CH.run
worker = ORC.worker


def _may_exist(msg: str) -> bool:
    return A._account_order_may_exist({"ok": False, "message": msg})


def _nothing(msg: str) -> bool:
    return A._nothing_was_sent(msg)


# ============================================================ 1 Chase execute

@pytest.mark.parametrize("body", [
    {"orderIdentifier": "O1", "orderStatus": "SUBMITTED"},
    {"orderIdentifier": "O1", "status": "SUBMITTED"},          # the audit's repro
    {"orderIdentifier": "O1", "orderStatus": "ACCEPTED",
     "messages": ["Your order has been placed"]},
    {"orderIdentifier": "O1", "orderStatus": "FILLED"},
])
def test_chase_an_order_id_with_an_accepted_state_is_placed(chase_run, body):
    req = CH._FakeReq({"1001": [CH._VAL_OK, CH._Resp(body=body)]})
    (a,) = chase_run(req, ids=("1001",)).accounts
    assert a.ok and a.order_id == "O1"
    assert req.executes == ["1001"]


@pytest.mark.parametrize("body", [
    {"orderIdentifier": "O1", "code": "ORDER_ACCEPTED"},       # unknown shape
    {"orderIdentifier": "O1", "orderStatus": "WEIRD"},
    {"orderIdentifier": "O1", "orderStatus": "REJECTED"},
    {"orderIdentifier": "O1", "orderStatus": "SUBMITTED", "errors": ["late"]},
    {"messages": ["Something went wrong"]},                    # no id at all
    {"code": "E123"},
])
def test_chase_anything_else_after_execute_is_verify_never_rejected(chase_run, body):
    req = CH._FakeReq({"1001": [CH._VAL_OK, CH._Resp(body=body)]})
    (a,) = chase_run(req, ids=("1001",)).accounts
    assert not a.ok
    assert _may_exist(a.message), a.message
    assert not _nothing(a.message)
    assert not a.message.lower().startswith("rejected")


@pytest.mark.parametrize("status", [400, 401, 403, 409, 422])
def test_chase_any_non_200_execute_is_verify(chase_run, status):
    req = CH._FakeReq({"1001": [CH._VAL_OK, CH._Resp(status=status, text="no")]})
    (a,) = chase_run(req, ids=("1001",)).accounts
    assert not a.ok and _may_exist(a.message) and not _nothing(a.message)


def test_chase_validate_phase_still_says_rejected(chase_run):
    req = CH._FakeReq({"1001": [CH._Resp(body={"errors": ["Not allowed"]})]})
    (a,) = chase_run(req, ids=("1001",)).accounts
    assert not a.ok and a.message.startswith("Rejected") and _nothing(a.message)
    assert req.executes == []


def test_chase_account_list_and_quote_failures_say_nothing_was_sent(monkeypatch):
    monkeypatch.setattr(chase, "ensure_session", lambda **k: chase.BrokerOutput(
        broker="Chase", state="success", accounts=[], message=""))
    monkeypatch.setattr(chase, "_require_session", lambda: ({"c": "1"}, None))

    def boom(_c):
        raise RuntimeError("HTTP 500: down")
    monkeypatch.setattr(chase, "_account_list", boom)
    out = chase._execute_trade_one(side="buy", qty="1", symbol="abcd")
    assert _nothing(out.accounts[0].message)

    class QuoteDown(CH._FakeReq):
        def get(self, url, **kw):
            return CH._Resp(status=503, text="quote down")
    monkeypatch.setattr(chase, "_account_list", lambda c: CH._accounts_payload(("1001",)))
    monkeypatch.setattr(chase, "_requests", lambda: QuoteDown({}))
    out = chase._execute_trade_one(side="buy", qty="1", symbol="abcd")
    assert _nothing(out.accounts[0].message) and "503" in out.accounts[0].message


def test_chase_failed_sign_in_says_nothing_was_sent(monkeypatch):
    monkeypatch.setattr(chase, "ensure_session", lambda **k: chase.BrokerOutput(
        broker="Chase", state="failed",
        accounts=[chase.AccountOutput(account_id="Chase", ok=False,
                                      message="Chase login did not finish within 8 min")],
        message="x"))
    out = chase._execute_trade_one(side="buy", qty="1", symbol="abcd")
    assert out.state == "failed" and _nothing(out.accounts[0].message)


def test_chase_account_without_a_mask_gets_a_skipped_row(chase_run, monkeypatch):
    payload = {"cache": [{"response": {"investmentAccountOverviews": [{
        "investmentAccountDetails": [{"accountId": "1001", "mask": "...1001"},
                                     {"accountId": "99887766"}]}]}}]}
    req = CH._FakeReq({"1001": [CH._VAL_OK, CH._exec_ok("O1")]})
    monkeypatch.setattr(chase, "ensure_session", lambda **k: chase.BrokerOutput(
        broker="Chase", state="success", accounts=[], message=""))
    monkeypatch.setattr(chase, "_require_session", lambda: ({"c": "1"}, None))
    monkeypatch.setattr(chase, "_account_list", lambda c: payload)
    monkeypatch.setattr(chase, "_requests", lambda: req)
    monkeypatch.setattr(chase.time, "sleep", lambda s: None)
    out = chase._execute_trade_one(side="buy", qty="1", symbol="abcd")
    rows = {a.account_id: a for a in out.accounts}
    assert rows["...1001"].ok
    skip = rows["Chase account ...7766"]
    assert not skip.ok and skip.message.startswith("Skipped") and _nothing(skip.message)
    assert out.state == "partial"


# ===================================================== 2 Fidelity confirmation

def _confirmed_by_text(text: str) -> bool:
    """Run _ORDER_CONFIRMED_JS in node over a page showing `text` with Place
    Order gone and no alert (fix5: the JS now uses /i regexes and an error
    veto, so it is executed rather than re-implemented in Python)."""
    from test_fix5_brokers import confirm_js
    [got] = confirm_js([{"text": text}])
    return bool(got)


@pytest.mark.parametrize("text", [
    "Manage Order notifications",
    "Order no longer valid",
    "Order number will appear here once placed",
    "order NOTIFICATIONS",
    "Confirmation number pending",
    "Order #TBD",
])
def test_fidelity_lookalike_text_is_not_a_confirmation(text):
    assert not _confirmed_by_text(text)


@pytest.mark.parametrize("text", [
    "Order Received\nYour order to buy 1 share",
    "Order received",
    "Order number: 24A0BC1D",
    "Order #: 12AB34",
    "Confirmation number 7XK2Q9",
    "Order no. 1A2B3C",
])
def test_fidelity_real_confirmation_forms_still_match(text):
    # NEEDS LIVE VERIFICATION against a real confirmation page.
    assert _confirmed_by_text(text)


def test_fidelity_confirmation_refuses_while_an_alert_or_dialog_shows():
    js = fidelity._ORDER_CONFIRMED_JS
    assert ".pvd-inline-alert" in js and ".pvd-modal__dialog" in js
    loop = js.index("querySelectorAll('.pvd-inline-alert")
    assert loop < js.index("const received"), "the alert check must come first"
    assert "return false" in js[loop:js.index("const received")]


def test_fidelity_profile_lock_is_not_stolen_from_a_live_owner(tmp_path, monkeypatch):
    lock = tmp_path / "fidelity_1.lock"
    lock.write_text(str(os.getpid()))
    old = time.time() - 3600
    os.utime(lock, (old, old))
    monkeypatch.setattr(fidelity, "_lock_file", lambda i: lock)
    monkeypatch.setattr(fidelity, "_sessions_dir", lambda: tmp_path)
    monkeypatch.setattr(fidelity, "_clean_chrome_singletons", lambda p: None)
    with pytest.raises(RuntimeError) as ei:
        fidelity._acquire_profile_lock(1, timeout_s=0.3, poll_s=0.05)
    assert _nothing(str(ei.value))
    assert lock.read_text() == str(os.getpid())       # still the owner's


def test_fidelity_profile_lock_from_a_dead_owner_is_taken(tmp_path, monkeypatch):
    lock = tmp_path / "fidelity_1.lock"
    lock.write_text("999999")
    monkeypatch.setattr(fidelity, "_lock_file", lambda i: lock)
    monkeypatch.setattr(fidelity, "_sessions_dir", lambda: tmp_path)
    monkeypatch.setattr(fidelity, "_clean_chrome_singletons", lambda p: None)
    monkeypatch.setattr(fidelity, "_lock_owner_alive", lambda pid, since=None: False)
    assert fidelity._acquire_profile_lock(1, timeout_s=1, poll_s=0.05) == lock
    assert lock.read_text() == str(os.getpid())


def test_fidelity_not_sent_helper():
    assert _nothing(fidelity._not_sent("Preview failed: x"))
    assert fidelity._not_sent("a — nothing was sent") == "a — nothing was sent"


# ======================================================== 3 Fennel createOrder

class _FennelFake:
    def __init__(self, reply, holdings=None):
        import fennel_invest_api.fennel as F
        self.reply = reply
        self.session = None
        self.endpoints = F.Endpoints()
        self.holdings = holdings
        fennel._harden_client(self)

    def place_order(self, account_id, ticker, quantity, side, dry_run=False):
        if isinstance(self.reply, Exception) and getattr(self.reply, "pre", False):
            raise self.reply
        self.endpoints.stock_order_query(account_id, ticker, quantity, "ISIN", side, "market")
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply

    def get_stock_holdings(self, acct_id):
        return self.holdings


class _Pre(Exception):
    pre = True


def _fennel_broker(client):
    cfg = fennel.FennelConfig(emails=["a@b"], sessions_dir=Path(tempfile.mkdtemp()))
    b = fennel.FennelBroker(cfg)
    b._sessions.append(fennel._LoginSession(label="Fennel", email="a@b", client=client,
                                            accounts=[("Account 1", "id1")], pkl_name="x"))
    return b


@pytest.mark.parametrize("status", ["accepted", "failed", "rejected", "queued"])
def test_fennel_a_status_other_than_pending_is_verify(status):
    out = _fennel_broker(_FennelFake({"data": {"createOrder": status}})).place_order_all(
        "ABCD", 1, "buy")
    (a,) = out.accounts
    assert not a.ok and _may_exist(a.message) and status in a.message


def test_fennel_pending_is_still_a_placed_order():
    out = _fennel_broker(_FennelFake({"data": {"createOrder": "pending"}})).place_order_all(
        "ABCD", 1, "buy")
    assert out.accounts[0].ok


@pytest.mark.parametrize("exc", [_Pre("Market is closed. Cannot place order."),
                                 _Pre("Stock ABCD is not tradable: halted"),
                                 _Pre("Failed to find ISIN for stock with ticker ABCD")])
def test_fennel_library_refusal_before_the_post_says_nothing_was_sent(exc):
    (a,) = _fennel_broker(_FennelFake(exc)).place_order_all("ABCD", 1, "buy").accounts
    assert not a.ok and _nothing(a.message)


def test_fennel_error_after_the_post_stays_verify():
    exc = Exception("Order Request failed with status code 502: bad")
    (a,) = _fennel_broker(_FennelFake(exc)).place_order_all("ABCD", 1, "buy").accounts
    assert _may_exist(a.message) and not _nothing(a.message)


@pytest.mark.parametrize("raw", [None, {"bulbs": []}, "x"])
def test_fennel_holdings_without_a_list_is_an_error(raw):
    out = _fennel_broker(_FennelFake(None, holdings=raw)).get_holdings()
    (a,) = out.accounts
    assert not a.ok and out.state == "failed"


def test_fennel_empty_list_is_still_an_empty_account():
    out = _fennel_broker(_FennelFake(None, holdings=[])).get_holdings()
    assert out.accounts[0].ok and out.accounts[0].holdings == []


# ====================================================== 4 Schwab session cache

def _h(s):
    return hashlib.md5(s.encode()).hexdigest()


def _cache(path, user, cookie):
    path.write_text(json.dumps({"cookies": {"SESSION_OF": cookie},
                                "headers": {"authorization": f"Bearer {cookie}"},
                                "username_hash": _h(user), "password_hash": _h("pw"),
                                "totp_secret_hash": _h("")}), encoding="utf-8")


@pytest.fixture
def schwab_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(schwab, "_sessions_dir", lambda: tmp_path)
    return tmp_path


def test_schwab_login_never_inherits_another_users_session(schwab_dir):
    """brkC/t6: schwab1.json held userA's cookies; login 1 is now userB."""
    _cache(schwab_dir / "schwab1.json", "userA", "A")
    (p,) = schwab._login_cache_paths(["userB"])
    # Left for userA (maybe only absent from .env right now); never reused.
    assert (schwab_dir / "schwab1.json").exists()
    assert not p.exists()
    from schwab_api import Schwab
    c = Schwab(session_cache=str(p))
    c.login(username="userB", password="pwB", totp_secret="", lazy=True)
    assert "SESSION_OF" not in c.session.cookies.get_dict()


def test_schwab_login_1_keeps_its_session_across_the_upgrade(schwab_dir):
    _cache(schwab_dir / "schwab1.json", "userA", "A")
    (schwab_dir / "schwab1_accounts.json").write_text(
        json.dumps({"username": "userA", "account_ids": ["1"]}), encoding="utf-8")
    (p,) = schwab._login_cache_paths(["userA"])
    assert p.exists() and json.loads(p.read_text())["cookies"]["SESSION_OF"] == "A"
    assert p.with_name(f"{p.stem}_accounts.json").exists()
    # The legacy schwab.json (pre-schwab1) migrates the same way.
    p.unlink()
    _cache(schwab_dir / "schwab.json", "userA", "A0")
    (p2,) = schwab._login_cache_paths(["userA"])
    assert p2 == p and json.loads(p2.read_text())["cookies"]["SESSION_OF"] == "A0"


def test_schwab_reordered_logins_each_keep_their_own_session(schwab_dir):
    _cache(schwab_dir / "schwab1.json", "userA", "A")
    _cache(schwab_dir / "schwab2.json", "userB", "B")
    pb, pa = schwab._login_cache_paths(["userB", "userA"])
    assert json.loads(pb.read_text())["cookies"]["SESSION_OF"] == "B"
    assert json.loads(pa.read_text())["cookies"]["SESSION_OF"] == "A"
    # Stable: asking again changes nothing.
    assert schwab._login_cache_paths(["userB", "userA"]) == [pb, pa]


def test_schwab_keyed_file_with_a_foreign_owner_is_discarded(schwab_dir):
    (p,) = schwab._login_cache_paths(["userB"])
    _cache(p, "userA", "A")
    schwab._login_cache_paths(["userB"])
    assert not p.exists()


def test_schwab_build_sessions_uses_the_keyed_path(schwab_dir, monkeypatch):
    monkeypatch.setattr(schwab, "_SESSIONS", [])
    monkeypatch.setattr(schwab, "_parse_accounts_from_env",
                        lambda: [("userA", "pw", None), ("userB", "pw", None)])

    class FakeSchwab:
        def __init__(self, session_cache=None, **kw):
            self.session_cache = session_cache
    monkeypatch.setattr(schwab, "_load_schwab_class", lambda: FakeSchwab)
    monkeypatch.setattr(schwab, "_harden_client", lambda c: None)
    s1, s2 = schwab._build_sessions()
    assert Path(s1["cache_path"]).name == f"schwab_{_h('userA')[:16]}.json"
    assert Path(s2["cache_path"]).name == f"schwab_{_h('userB')[:16]}.json"
    assert s1["label"] == "Schwab" and s2["label"] == "Schwab 2"


def test_schwab_account_scoping_is_per_login(monkeypatch):
    monkeypatch.setenv("SCHWAB_ACCOUNT_NUMBERS", "111:222")
    monkeypatch.setenv("SCHWAB_ACCOUNT_ID", "111")
    monkeypatch.delenv("SCHWAB_ACCOUNT_NUMBERS_2", raising=False)
    monkeypatch.delenv("SCHWAB_ACCOUNT_ID_2", raising=False)
    try:
        schwab._set_env_login(1)
        assert schwab._purchase_accounts_filter() == ["111", "222"]
        assert schwab._selected_account_id() == "111"
        schwab._set_env_login(2)
        assert schwab._purchase_accounts_filter() == []
        assert schwab._selected_account_id() == ""
        monkeypatch.setenv("SCHWAB_ACCOUNT_NUMBERS_2", "333")
        assert schwab._purchase_accounts_filter() == ["333"]
    finally:
        schwab._set_env_login(1)


def test_schwab_failure_outside_the_account_loop_keeps_earlier_rows(monkeypatch):
    import test_schwab_no_double_order as SW
    good = SW._StubClient(check_result=([], True), v2_result=([], True))
    calls = {"n": 0}

    def discover(c):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("discovery blew up")
        return ["12345678"]
    monkeypatch.setattr(schwab, "_build_sessions", lambda: [
        {"idx": 1, "label": "Schwab", "client": good},
        {"idx": 2, "label": "Schwab 2", "client": good}])
    monkeypatch.setattr(schwab, "_refresh_token_soft", lambda c: True)
    monkeypatch.setattr(schwab, "_discover_account_ids_for_trade", discover)
    monkeypatch.setattr(schwab, "_remember_account_ids", lambda *a: None)
    monkeypatch.setattr(schwab, "BLOG", None)
    monkeypatch.setattr(schwab.time, "sleep", lambda s: None)
    out = schwab.execute_trade(side="buy", qty="1", symbol="abcd")
    assert out.accounts[0].ok                        # login 1's order is not lost
    last = out.accounts[-1]
    assert not last.ok and _may_exist(last.message)
    assert out.state == "partial"


def test_schwab_precheck_refusal_and_legacy_unconfirmed_say_nothing_was_sent(monkeypatch):
    import test_schwab_no_double_order as SW

    class Sess:
        def post(self, url, *a, **k):
            return None
    client = SW._StubClient(check_result=(["Insufficient buying power"], False))
    client.session = Sess()
    client.trade = lambda **kw: (["Insufficient buying power"], False)
    monkeypatch.setattr(schwab, "_build_sessions",
                        lambda: [{"idx": 1, "label": "Schwab", "client": client}])
    monkeypatch.setattr(schwab, "_refresh_token_soft", lambda c: True)
    monkeypatch.setattr(schwab, "_discover_account_ids_for_trade", lambda c: ["12345678"])
    monkeypatch.setattr(schwab, "_remember_account_ids", lambda *a: None)
    monkeypatch.setattr(schwab, "BLOG", None)
    out = schwab.execute_trade(side="buy", qty="1", symbol="abcd")
    (a,) = out.accounts
    assert not a.ok and _nothing(a.message)


# ============================================== 5 / 7 / 10 Robinhood sessions

@pytest.fixture
def rh_world(tmp_path, monkeypatch):
    # Module state these runs write: restored afterwards for later tests.
    for name in ("_LOGIN_LOAD_FAILURES", "_ACCOUNTS"):
        monkeypatch.setattr(RH, name, [])
    monkeypatch.setattr(RH, "_RH", None)
    monkeypatch.setattr(RH.time, "sleep", lambda s: None)
    (tmp_path / "p").write_text("x")
    cur = {"p": None}
    orders = []

    def lap(dataType="results"):
        if cur["p"] == "Robinhood 2":
            import requests
            raise requests.exceptions.ReadTimeout("read timed out")
        return [{"account_number": "11111111", "type": "individual"}]

    fake = types.SimpleNamespace(
        account=types.SimpleNamespace(load_account_profile=lap), profiles=None,
        order=lambda **k: orders.append(k) or {"id": "o", "state": "queued"},
        orders=None)
    monkeypatch.setattr(RH, "_pickle_file", lambda n: tmp_path / "p")
    monkeypatch.setattr(RH, "_load_rh", lambda: (fake, None))
    monkeypatch.setattr(RH, "_login_profiles",
                        lambda: [("Robinhood 1", "u1", "p1"), ("Robinhood 2", "u2", "p2")])
    monkeypatch.setattr(RH, "_log_session_issue", lambda **k: None)
    monkeypatch.setattr(RH, "login_with_cache",
                        lambda *, rh, pickle_name: cur.__setitem__("p", pickle_name))
    return types.SimpleNamespace(fake=fake, orders=orders, cur=cur)


def test_robinhood_unreadable_account_list_is_a_failed_login_row(rh_world):
    """brkC/t4: login 2's account list timed out; it used to vanish."""
    out = RH.execute_trade(side="buy", qty="1", symbol="ABC")
    assert out.state == "partial"
    rows = {a.account_id: a for a in out.accounts}
    assert [a.ok for a in out.accounts if a.account_id != "Robinhood 2"] == [True]
    bad = rows["Robinhood 2"]
    assert not bad.ok and "ReadTimeout" in bad.message and _nothing(bad.message)
    assert len(rh_world.orders) == 1


def test_robinhood_holdings_also_report_the_unread_login(rh_world, monkeypatch):
    monkeypatch.setattr(RH, "_safe_open_positions", lambda rh, account_number: [])
    out = RH.get_holdings()
    assert out.state == "partial"
    assert any(a.account_id == "Robinhood 2" and not a.ok for a in out.accounts)


def test_robinhood_safe_load_accounts_raises_instead_of_returning_empty():
    def boom(dataType="results"):
        raise ConnectionError("reset")
    rh = types.SimpleNamespace(account=types.SimpleNamespace(load_account_profile=boom),
                               profiles=None)
    with pytest.raises(RuntimeError):
        RH._safe_load_accounts(rh)
    assert RH._safe_load_accounts(types.SimpleNamespace(account=None, profiles=None)) == []


def test_robinhood_pre_send_exception_says_nothing_was_sent(rh_world, monkeypatch):
    def order(**k):
        raise IndexError("list index out of range")     # no quote, inside order()
    rh_world.fake.order = order
    out = RH.execute_trade(side="buy", qty="1", symbol="ABC")
    row = next(a for a in out.accounts if a.account_id != "Robinhood 2")
    assert not row.ok and _nothing(row.message)


def test_robinhood_no_session_says_nothing_was_sent(monkeypatch):
    monkeypatch.setattr(RH, "_ensure_session", lambda: (False, "robin_stocks not installed"))
    out = RH.execute_trade(side="buy", qty="1", symbol="ABC")
    assert _nothing(out.accounts[0].message)


def test_robinhood_session_lock_wait_is_bounded(monkeypatch):
    monkeypatch.setattr(RH, "_SESSION_LOCK_WAIT_S", 0.2)
    held = threading.Event()
    release = threading.Event()

    def holder():
        with RH._SESSION_LOCK:
            held.set()
            release.wait(5)
    t = threading.Thread(target=holder, daemon=True)
    t.start()
    held.wait(2)
    try:
        out = RH.execute_trade(side="buy", qty="1", symbol="ABC")
    finally:
        release.set()
        t.join(2)
    assert out.state == "failed" and _nothing(out.accounts[0].message)


def test_robinhood_cancelled_code_fails_once_instead_of_posting_empty_codes(monkeypatch):
    """brkC/t3: Cancel returned "", and robin_stocks POSTed it every 5 s."""
    import robin_stocks.robinhood.authentication as RA
    monkeypatch.setattr(RH, "_RH", None)
    monkeypatch.setattr(RH, "_ACCOUNTS", [])
    clock = [0.0]
    monkeypatch.setattr(RA, "time", types.SimpleNamespace(
        time=lambda: clock[0], sleep=lambda s: clock.__setitem__(0, clock[0] + s)))
    calls = {"respond": 0, "asked": 0}

    def rp(url=None, payload=None, json=False, **k):
        if "user_machine" in str(url):
            return {"id": "m1"}
        if "respond" in str(url):
            calls["respond"] += 1
            return {"status": "failed"}
        return None

    def rg(url=None, *a, **k):
        return {"context": {"sheriff_challenge": {"type": "sms", "status": "issued", "id": "c1"}}}
    monkeypatch.setattr(RA, "request_post", rp)
    monkeypatch.setattr(RA, "request_get", rg)

    def fake_login(username=None, password=None, store_session=True, expiresIn=None,
                   pickle_path=None, pickle_name=None):
        try:                          # robin_stocks' own catch-all around this
            RA._validate_sherrif_id("dev", "wf")
        except Exception:
            return None
        return {"access_token": "x"}

    def ask(*a, **k):
        calls["asked"] += 1
        return None                   # the user pressed Cancel
    monkeypatch.setattr(RH._2fa_prompt, "request_text", ask)
    monkeypatch.setattr(RH, "_load_rh", lambda: (types.SimpleNamespace(login=fake_login), None))
    monkeypatch.setattr(RH, "_login_profiles", lambda: [("Robinhood 1", "u", "p")])
    monkeypatch.setattr(RH, "_log_mfa_decision", lambda **k: None)
    monkeypatch.setattr(RH, "_log_login_transcript", lambda *a, **k: None)
    out = RH.bootstrap()
    assert calls == {"respond": 0, "asked": 1}
    assert out.state == "failed"
    assert "code not entered" in out.accounts[0].message
    assert _nothing(out.accounts[0].message)


# ================================================================ 6 watchdog

def test_leg_clock_restarts_when_the_order_phase_begins(worker, monkeypatch):
    """wd.py: a two-login Fidelity sell spent ~2400 s in its pre-sell quote and
    the leg clock (started at the browser slot) wrote a healthy leg off."""
    batch = {"origin": "desk", "pending": {"sofi"}}
    seen = {}

    def slow_quote(*a, **k):
        seen["pre"] = batch["leg_started"]["sofi"]
        time.sleep(0.02)
        return 1.0
    worker._fetch_quote_price = slow_quote

    def execute(**kw):
        seen["send"] = batch["leg_started"]["sofi"]
        return A.BrokerOutput(broker="sofi", state="success", accounts=[
            A.AccountOutput(account_id="IND (1111)", ok=True, message="order placed")])
    monkeypatch.setattr(A, "_load_broker", lambda b: types.SimpleNamespace(execute_trade=execute))
    A.App._trade_worker(worker, "sofi", "sell", "AIFA", "1", False, batch)
    assert seen["send"] > seen["pre"]
    # and again for the post-fill quote, the last phase
    assert batch["leg_started"]["sofi"] >= seen["send"]


def test_each_phase_fits_the_budget_at_two_logins(monkeypatch):
    import broker_logins
    monkeypatch.setattr(broker_logins, "login_count",
                        lambda b: {"fidelity": 2, "wellsfargo": 2}.get(b, 1))
    budget = A._mirror_stall_ms() / 1000 + A.TRADE_LEG_WATCHDOG_SLACK_S
    fid_holdings = 1200 + 600 * 1
    fid_trade = 1800 + 900 * 1
    wf_phase = 1200 * 2
    assert max(fid_holdings, fid_trade, wf_phase) < budget


def test_restart_leg_clock_tolerates_no_batch():
    A._restart_leg_clock(None, "sofi")
    b = {}
    A._restart_leg_clock(b, "sofi")
    assert isinstance(b["leg_started"]["sofi"], datetime)


# ================================================ 8 Wells Fargo requested rows

def _wf_row(lbl, ok=True):
    return wellsfargo.AccountOutput(account_id=lbl, ok=ok, message="Placed" if ok else "x")


def test_wf_requested_accounts_no_login_holds_get_a_row(monkeypatch):
    monkeypatch.setattr(wellsfargo.broker_logins, "fan_out", lambda *a, **k: wellsfargo.BrokerOutput(
        broker="wellsfargo", state="success",
        accounts=[_wf_row("WELLSTRADE (****0012)"), _wf_row("Wells Fargo 2 · IRA (****0034)")],
        message=""))
    out = wellsfargo.execute_trade(side="buy", qty="1", symbol="AAA", only_accounts=[
        "WELLSTRADE (****0012)", "IRA (****0034)", "WELLSTRADE (****0099)", "0077"])
    missing = {a.account_id: a for a in out.accounts if not a.ok}
    assert set(missing) == {"WELLSTRADE (****0099)", "0077"}
    assert all(_nothing(a.message) and a.message.startswith("Skipped") for a in missing.values())
    assert out.state == "partial"


def test_wf_all_requested_found_stays_success(monkeypatch):
    monkeypatch.setattr(wellsfargo.broker_logins, "fan_out", lambda *a, **k: wellsfargo.BrokerOutput(
        broker="wellsfargo", state="success", accounts=[_wf_row("WELLSTRADE (****0012)")],
        message=""))
    out = wellsfargo.execute_trade(side="buy", qty="1", symbol="AAA",
                                   only_accounts=["0012"])
    assert out.state == "success" and len(out.accounts) == 1


# ===================================================== 10 SoFi cancel / holdings

def test_sofi_cancel_mid_run_gives_every_remaining_account_a_row(monkeypatch):
    cancel = threading.Event()

    class Req(SO._FakeReq):
        def post(self, url, json=None, **kw):
            r = super().post(url, json=json, **kw)
            cancel.set()
            return r
    req = Req([SO._ok(), SO._ok(), SO._ok()])
    monkeypatch.setattr(sofi, "_rehydrate_session", lambda **kw: sofi.BrokerOutput(
        broker="SoFi", state="success", accounts=[], message=""))
    monkeypatch.setattr(sofi, "_require_session", lambda **kw: None)
    monkeypatch.setattr(sofi, "_requests", lambda: req)
    monkeypatch.setattr(sofi, "_trading_session", lambda: "CORE_HOURS")
    monkeypatch.setattr(sofi.time, "sleep", lambda s: None)
    out = sofi._execute_trade_one(side="buy", qty="1", symbol="abcd", cancel_event=cancel)
    assert req.posts == ["A1111"]
    assert len(out.accounts) == 3
    a, b, c = out.accounts
    assert a.ok
    assert all(not r.ok and _nothing(r.message) for r in (b, c))


@pytest.fixture
def sofi_run(monkeypatch):
    def _run(req):
        monkeypatch.setattr(sofi, "_rehydrate_session", lambda **kw: sofi.BrokerOutput(
            broker="SoFi", state="success", accounts=[], message=""))
        monkeypatch.setattr(sofi, "_require_session", lambda **kw: None)
        monkeypatch.setattr(sofi, "_requests", lambda: req)
        monkeypatch.setattr(sofi, "_trading_session", lambda: "CORE_HOURS")
        monkeypatch.setattr(sofi.time, "sleep", lambda s: None)
        monkeypatch.setattr(sofi.BLOG, "write_log", lambda *a, **k: None)
        monkeypatch.setattr(sofi.BLOG, "log_exception", lambda *a, **k: None)
        return sofi._execute_trade_one(side="buy", qty="1", symbol="abcd")
    return _run


@pytest.mark.parametrize("which", ["quote429", "nofunded"])
def test_sofi_pre_order_failures_say_nothing_was_sent(sofi_run, which):
    class Req(SO._FakeReq):
        def get(self, url, **kw):
            if "quote" in url:
                if which == "quote429":
                    return SO._Resp(status=429, text="slow down")
                return SO._Resp(body={"last": 2.0, "bid": 1.99, "ask": 2.01})
            return SO._Resp(body=[])
    out = sofi_run(Req([]))
    (a,) = out.accounts
    assert not a.ok and _nothing(a.message)


def test_sofi_unreadable_reply_after_a_post_is_never_nothing_sent(sofi_run):
    class Weird:
        status_code = 418
        text = None                    # makes the reply-reading code raise

        def json(self):
            return {}
    out = sofi_run(SO._FakeReq([Weird()]))
    first = next(a for a in out.accounts if "1111" in a.account_id)
    assert not first.ok and _may_exist(first.message)
    assert not A._result_nothing_sent({"accounts": [vars(a) for a in out.accounts],
                                       "errors": []})


# ================================================================ 10 desk busy

def test_desk_refuses_a_broker_whose_hung_thread_still_holds_the_browser(monkeypatch):
    monkeypatch.setitem(A._slot_holders, "fidelity", {"timed_out": {"fidelity"}})
    d = CO.Desk()
    d._select_only_brokers(["fidelity"])
    d._trade_execute()
    assert d.launched == []
    assert d.notes and "already running" in d.notes[-1][0]


# ============================================================ 11 Public caps

class _PubClient:
    def __init__(self, positions):
        self.positions = positions
        self.orders = []

    def get_portfolio_v2(self, account_id):
        return {"positions": [{"instrument": {"symbol": s}, "quantity": q}
                              for s, q in self.positions.get(account_id, [])]}

    def place_equity_market_order(self, *, account_id, side, symbol, quantity, **_kw):
        self.orders.append((account_id, quantity))
        return f"oid-{account_id}"


def _pub_sell(monkeypatch, ready, caps):
    monkeypatch.setattr(public.time, "sleep", lambda *_a: None)
    monkeypatch.setattr(public, "_ensure_clients", lambda: (True, "", ready))
    return public.execute_trade(side="sell", qty="1", symbol="IPDN",
                                size_from_holdings=True, max_by_account=caps)


def test_public_caps_follow_the_account_after_logins_are_reordered(monkeypatch):
    # Journaled when token X was login 1 and token Y login 2; .env now has
    # them the other way round.
    cx = _PubClient({"X0001": [("IPDN", "1")]})
    cy = _PubClient({"Y0002": [("IPDN", "1")]})
    ready = [(1, cy, [{"accountId": "Y0002", "accountType": "BROKERAGE"}]),
             (2, cx, [{"accountId": "X0001", "accountType": "BROKERAGE"}])]
    caps = {"Public 1 BROKERAGE (0001)": "1", "Public 2 BROKERAGE (0002)": "1"}
    out = _pub_sell(monkeypatch, ready, caps)
    assert cx.orders == [("X0001", "1")] and cy.orders == [("Y0002", "1")]
    assert out.state == "success"


def test_public_ambiguous_fallback_never_guesses(monkeypatch):
    c1 = _PubClient({"A0001": [("IPDN", "5")]})
    c2 = _PubClient({"B0001": [("IPDN", "5")]})
    ready = [(1, c1, [{"accountId": "A0001", "accountType": "BROKERAGE"}]),
             (2, c2, [{"accountId": "B0001", "accountType": "BROKERAGE"}])]
    caps = {"Public 3 BROKERAGE (0001)": "1"}     # matches both by last-4
    out = _pub_sell(monkeypatch, ready, caps)
    assert c1.orders == [] and c2.orders == []
    row = next(a for a in out.accounts if a.account_id == "Public 3 BROKERAGE (0001)")
    assert not row.ok and _nothing(row.message)
    assert out.state == "failed"


def test_public_cap_that_matches_no_account_is_not_a_clean_result(monkeypatch):
    c = _PubClient({"A0001": [("IPDN", "0")]})
    ready = [(1, c, [{"accountId": "A0001", "accountType": "BROKERAGE"}])]
    caps = {"Public 1 BROKERAGE (0001)": "1", "Public 1 IRA (9999)": "1"}
    out = _pub_sell(monkeypatch, ready, caps)
    assert out.state == "failed"
    (row,) = [a for a in out.accounts if not a.ok]
    assert row.account_id == "Public 1 IRA (9999)" and "not find" in row.message


def test_public_exact_labels_still_work(monkeypatch):
    c = _PubClient({"A0001": [("IPDN", "101")]})
    ready = [(1, c, [{"accountId": "A0001", "accountType": "BROKERAGE"}])]
    out = _pub_sell(monkeypatch, ready, {"Public 1 BROKERAGE (0001)": "1"})
    assert c.orders == [("A0001", "1")] and out.state == "success"


def test_public_failed_login_and_token_refresh_say_nothing_was_sent(monkeypatch):
    assert _nothing(public._failed_login_row(2, "Token exchange failed: HTTP 401").message)
    cl = public._PublicClient(secret="s")

    def bad():
        raise RuntimeError("Token exchange failed: HTTP 401 - nope")
    monkeypatch.setattr(cl, "_refresh_access_token_if_needed", bad)
    with pytest.raises(RuntimeError) as ei:
        cl.place_equity_market_order(account_id="A", side="BUY", symbol="X", quantity="1")
    assert _nothing(str(ei.value))


# ======================================================= 9 IBKR / app pre-send

def test_app_worker_failure_before_execute_trade_is_nothing_sent(worker, monkeypatch):
    def bad_load(_b):
        raise ImportError("No module named 'zendriver'")
    monkeypatch.setattr(A, "_load_broker", bad_load)
    A.App._trade_worker(worker, "sofi", "buy", "AIFA", "1", False,
                        {"origin": "desk", "pending": {"sofi"}})
    (s,) = worker.completed
    assert A._result_nothing_sent(s)


def test_ibkr_stall_before_the_account_list_says_nothing_was_sent():
    import ibkr
    gw = types.SimpleNamespace(name="IBKR")
    sess = types.SimpleNamespace(gw=gw, lock=threading.Lock(), outs=[], abandoned=True,
                                 sent=set(), todo=[], fatal="")
    (row,) = ibkr._session_outputs(sess, trading=True)
    assert _nothing(row.message)
    (row,) = ibkr._session_outputs(sess)          # holdings keep the old words
    assert "nothing was sent" not in row.message
    sess2 = types.SimpleNamespace(gw=gw, lock=threading.Lock(), outs=[], abandoned=False,
                                  sent={"U****2"}, todo=["U****1", "U****2"],
                                  fatal="Couldn't connect to IB Gateway")
    rows = {o.account_id: o for o in ibkr._session_outputs(sess2, trading=True)}
    assert _nothing(rows["U****1"].message)
    assert _may_exist(rows["U****2"].message) and not _nothing(rows["U****2"].message)
