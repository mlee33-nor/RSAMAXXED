"""API-broker result handling: a refusal is not a fill, a failed read is not
"holds nothing", a failed login is a row, and an order that MAY exist says
"submitted ... verify" so nothing re-sends it.

Fakes and monkeypatching only: no broker, no network, no browser.
"""

from __future__ import annotations

import builtins
import pickle
import sys
import threading
import time
import types
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import fennel
import public
import robinhood
import schwab
import trade_journal
import etf_journal
from modules import http_timeouts
from modules.outputs import BrokerOutput


def _may_exist(msg: str) -> bool:
    return A._account_order_may_exist({"ok": False, "message": msg})


def _no_order_words(msg: str) -> bool:
    t = msg.lower()
    return not any(w in t for w in A._ORDER_MAY_EXIST)


# ================================================================ Robinhood

class _RhOrders:
    def __init__(self):
        self.calls = []

    def order(self, **kw):
        self.calls.append(kw)
        return {"id": f"o{len(self.calls)}", "state": "queued"}


def _rh_with_positions(result):
    helper = types.SimpleNamespace(request_get=lambda url, dt, payload: result)
    urls = types.SimpleNamespace(positions_url=lambda account_number=None: "u")
    return types.SimpleNamespace(helper=helper, urls=urls, orders=None,
                                 account=types.SimpleNamespace(
                                     load_account_profile=lambda dataType=None: []))


def test_rh_http_error_positions_raise_not_empty():
    with pytest.raises(RuntimeError):
        robinhood._safe_open_positions(_rh_with_positions([None]),
                                       account_number="5QR11234")
    assert robinhood._safe_open_positions(_rh_with_positions([]),
                                          account_number="5QR11234") == []


def test_rh_failed_positions_read_is_a_failed_account(monkeypatch):
    monkeypatch.setattr(robinhood, "_ensure_session", lambda: (True, ""))
    monkeypatch.setattr(robinhood, "_RH", _rh_with_positions([None]))
    monkeypatch.setattr(robinhood, "_ACCOUNTS",
                        [("individual (****1234)", "5QR11234", "Robinhood 1")])
    monkeypatch.setattr(robinhood, "login_with_cache", lambda **kw: None)
    out = robinhood.get_holdings()
    assert out.state == "failed"
    assert not out.accounts[0].ok


def test_rh_login_one_keeps_its_label_when_a_second_login_exists():
    profiles = [("Robinhood 1", "a", "x"), ("Robinhood 2", "b", "y")]
    assert robinhood._account_display(profiles, "Robinhood 1",
                                      "individual (****1234)") == "individual (****1234)"
    assert robinhood._account_display(profiles, "Robinhood 2",
                                      "individual (****9999)") == \
        "Robinhood 2 | individual (****9999)"
    assert robinhood._account_display(profiles[:1], "Robinhood 1", "x") == "x"


def _rh_trade(monkeypatch, accounts, cap):
    rh = _RhOrders()
    monkeypatch.setattr(robinhood, "_ensure_session", lambda: (True, ""))
    monkeypatch.setattr(robinhood, "_RH", rh)
    monkeypatch.setattr(robinhood, "_ACCOUNTS", accounts)
    monkeypatch.setattr(robinhood, "login_with_cache", lambda **kw: None)
    monkeypatch.setattr(robinhood, "_max_trade_accounts", lambda: cap)
    monkeypatch.setattr(robinhood.time, "sleep", lambda s: None)
    return rh, robinhood.execute_trade(side="buy", qty="1", symbol="abcd")


def test_rh_account_cap_is_per_login(monkeypatch):
    accts = [(f"individual (****{i}{n})", f"ACCT{i}{n}", f"Robinhood {i}")
             for i in (1, 2) for n in range(4)]
    rh, out = _rh_trade(monkeypatch, accts, 3)
    assert len(rh.calls) == 6
    assert len(out.accounts) == 6 and all(a.ok for a in out.accounts)
    assert out.message.count("over the 3-account limit") == 2


def test_rh_no_tradable_accounts_is_a_failed_row(monkeypatch):
    rh, out = _rh_trade(monkeypatch,
                        [("joint_tenancy_with_ros (****1)", "J1", "Robinhood 1")], 3)
    assert rh.calls == []
    [acct] = out.accounts
    assert out.state == "failed" and not acct.ok
    assert _no_order_words(acct.message), acct.message


class _FakeSession:
    def __init__(self):
        self.seen = []

    def request(self, method, url, **kw):
        self.seen.append(kw.get("timeout"))
        return "resp"

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


def test_rh_session_gets_a_default_timeout_and_keeps_explicit_ones():
    sess = _FakeSession()
    rh = types.SimpleNamespace(helper=types.SimpleNamespace(SESSION=sess))
    robinhood._harden_session(rh)
    robinhood._harden_session(rh)            # idempotent
    sess.get("u")
    sess.get("u", timeout=5)
    assert sess.seen == [http_timeouts.DEFAULT_TIMEOUT, 5]


def test_rh_login_is_bounded_and_the_abandoned_thread_stops(monkeypatch):
    sess = _FakeSession()
    rh = types.SimpleNamespace(helper=types.SimpleNamespace(SESSION=sess))
    robinhood._harden_session(rh)
    stopped = threading.Event()

    def never_approved():
        try:
            while True:                       # robin_stocks' approval poll
                time.sleep(0.02)
                sess.get("prompt-status")
        finally:
            stopped.set()

    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="did not finish"):
        robinhood._run_login_bounded(never_approved, {}, timeout_s=0.2)
    assert time.monotonic() - t0 < 2
    assert stopped.wait(2), "abandoned login thread kept polling"
    deadline = time.monotonic() + 2
    while robinhood._ABANDONED_LOGIN_THREADS and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not robinhood._ABANDONED_LOGIN_THREADS


def test_rh_bounded_login_passes_results_and_errors_through():
    assert robinhood._run_login_bounded(lambda **kw: kw["x"], {"x": 7}) == 7
    with pytest.raises(ValueError):
        robinhood._run_login_bounded(lambda: (_ for _ in ()).throw(ValueError("bad")), {})


# =================================================================== Public

class _PubClient:
    def __init__(self, idx, fail=False):
        self.idx = idx
        self.fail = fail
        self.orders = []

    def get_accounts(self):
        if self.fail:
            raise RuntimeError("Token exchange failed: HTTP 401 - bad secret")
        return [{"accountId": f"ACC{self.idx}0001", "accountType": "BROKERAGE"}]

    def place_equity_market_order(self, **kw):
        self.orders.append(kw)
        return kw.get("order_id")

    def get_portfolio_v2(self, account_id):
        return {"positions": [], "equity": [], "buyingPower": {}}


@pytest.fixture
def pub(monkeypatch):
    clients = {}

    def setup(*failing, idxs=(1, 2)):
        monkeypatch.setattr(public, "_load_public_secrets",
                            lambda: [(i, f"s{i}") for i in idxs])
        for i in idxs:
            clients[i] = _PubClient(i, fail=i in failing)
        monkeypatch.setattr(public, "_get_client_for_secret", lambda i, s: clients[i])
        monkeypatch.setattr(public.time, "sleep", lambda s: None)
        return clients
    return setup


def test_public_one_failed_login_is_its_own_row(pub):
    clients = pub(2)
    out = public.execute_trade(side="buy", qty="1", symbol="ABCD")
    by_id = {a.account_id: a for a in out.accounts}
    assert by_id["Public 2"].ok is False
    assert "401" in by_id["Public 2"].message
    assert _no_order_words(by_id["Public 2"].message)
    assert by_id["Public 1 BROKERAGE (0001)"].ok
    assert out.state == "partial"
    assert clients[2].orders == []


def test_public_every_login_failed_still_reports_rows(pub):
    pub(1, 2)
    out = public.execute_trade(side="buy", qty="1", symbol="ABCD")
    assert out.state == "failed"
    assert [a.account_id for a in out.accounts] == ["Public 1", "Public 2"]
    assert not any(a.ok for a in out.accounts)


def test_public_failed_login_on_a_sized_sell_reads_as_unread_position(pub):
    pub(2)
    out = public.execute_trade(side="sell", qty="", symbol="ABCD",
                               size_from_holdings=True, max_by_account={})
    [row] = [a for a in out.accounts if a.account_id == "Public 2"]
    assert "Could not read the position" in row.message


def test_public_holdings_and_healthcheck_show_failed_logins(pub):
    pub(2)
    h = public.get_holdings()
    assert any(a.account_id == "Public 2" and not a.ok for a in h.accounts)
    hc = public.healthcheck()
    assert hc.state == "partial"
    assert any(a.account_id == "Public 2" and not a.ok for a in hc.accounts)


class _Resp:
    def __init__(self, code, body=None, text=""):
        self.status_code = code
        self._body = body
        self.text = text

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _pub_client_posting(monkeypatch, outcome):
    c = public._PublicClient(secret="s")
    c._access_token = "t"
    c._access_expiry_epoch = time.time() + 3600

    def post(url, **kw):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    fake_requests = types.SimpleNamespace(post=post, exceptions=requests.exceptions)
    monkeypatch.setattr(c, "_requests", lambda: fake_requests)
    return c


@pytest.mark.parametrize("outcome", [
    requests.ReadTimeout("read timed out"),
    requests.ConnectionError("connection reset by peer"),
    _Resp(502, text="Bad Gateway"),
])
def test_public_unknown_outcome_after_post_says_verify(monkeypatch, outcome):
    c = _pub_client_posting(monkeypatch, outcome)
    with pytest.raises(public._OrderMayExist) as ei:
        c.place_equity_market_order(account_id="A", side="BUY", symbol="X",
                                    quantity="1", order_id="oid-1")
    assert _may_exist(str(ei.value)), str(ei.value)


@pytest.mark.parametrize("outcome", [
    requests.ConnectTimeout("connect timed out"),
    _Resp(400, text="insufficient funds"),
])
def test_public_nothing_sent_stays_plain(monkeypatch, outcome):
    c = _pub_client_posting(monkeypatch, outcome)
    with pytest.raises(RuntimeError) as ei:
        c.place_equity_market_order(account_id="A", side="BUY", symbol="X",
                                    quantity="1", order_id="oid-1")
    assert not isinstance(ei.value, public._OrderMayExist)
    assert not _may_exist(str(ei.value))


def test_public_2xx_with_unreadable_body_is_still_the_order(monkeypatch):
    c = _pub_client_posting(monkeypatch, _Resp(200, ValueError("not json")))
    assert c.place_equity_market_order(account_id="A", side="BUY", symbol="X",
                                       quantity="1", order_id="oid-1") == "oid-1"


# ================================================================ app.py

class _StubApp:
    def __init__(self):
        self.completed = []
        self._quick_picks = []

    def after(self, _ms, func=None, *args):
        if callable(func):
            func(*args)

    def _log(self, *a, **k):
        pass

    def _fetch_quote_price(self, *a, **k):
        return None

    def _trade_result_write(self, *a, **k):
        pass

    def _render_quick_picks(self, *a, **k):
        pass

    def _trade_broker_complete(self, batch, summary):
        self.completed.append(summary)


def test_trade_worker_counts_a_rowless_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf.json")
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    fake = types.SimpleNamespace(execute_trade=lambda **kw: BrokerOutput(
        broker="public", state="failed", accounts=[],
        message="Missing PUBLIC_SECRET_TOKEN_1"))
    monkeypatch.setattr(A, "_load_broker", lambda b: fake)
    monkeypatch.setattr(A, "_browser_slot", lambda b: None)
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)
    stub = _StubApp()
    A.App._trade_worker(stub, "public", "buy", "ABCD", "1", False,
                        {"origin": "desk", "pending": {"public"}})
    [s] = stub.completed
    assert s["fail_accounts"] == 1
    assert "Missing PUBLIC_SECRET_TOKEN_1" in s["errors"]


class _Settle:
    _exit_batch_settle = A.App._exit_batch_settle

    def _autosell_retry(self, task, why):
        pass


def _pub_summary(**kw):
    s = {"broker": "public", "ok_accounts": 0, "fail_accounts": 0, "shares": 0.0,
         "errors": [], "state": "success", "accounts": [], "skipped": {}}
    s.update(kw)
    return s


@pytest.mark.parametrize("summary,marked", [
    (_pub_summary(), False),                                    # no rows at all
    (_pub_summary(state="failed", fail_accounts=1,
                  errors=["Auth failed"]), False),
    (_pub_summary(skipped={"none": 3}), True),                  # read, held none
    (_pub_summary(ok_accounts=1, accounts=[{"account_id": "Public 1 X (1)",
                                            "ok": True, "message": "ok"}]), True),
])
def test_public_late_check_needs_a_clean_read(monkeypatch, summary, marked):
    calls = []
    monkeypatch.setattr(A, "_mark_public_late_checked", lambda syms: calls.append(syms))
    task = types.SimpleNamespace(symbol="IPDN", alert_symbol="IPDN")
    _Settle()._exit_batch_settle({"exit_task": task}, [summary])
    assert bool(calls) is marked


# =================================================================== Fennel

def test_fennel_login_one_keeps_its_label(tmp_path, monkeypatch):
    class C:
        def login(self, **kw):
            return True

        def get_full_accounts(self):
            return [{"name": "Account 1", "id": "x1"}]

    cfg = fennel.FennelConfig(emails=["a@x", "b@x"], sessions_dir=tmp_path)
    b = fennel.FennelBroker(cfg, otp_provider=lambda *a: None)
    monkeypatch.setattr(b, "_make_client", lambda i: (C(), f"fennel{i + 1}.pkl"))
    out = b.ensure_authenticated()
    assert [a.account_id for a in out.accounts] == ["Fennel", "Fennel 2"]
    assert [s.label for s in b._sessions] == ["Fennel", "Fennel 2"]


def test_fennel_truncated_pickle_is_moved_aside_and_retried(tmp_path):
    from fennel_invest_api import Fennel
    (tmp_path / "fennel1.pkl").write_bytes(pickle.dumps({"Bearer": "x"})[:5])
    client = fennel._open_fennel_client(Fennel, "fennel1.pkl", tmp_path)
    assert client.Bearer is None
    assert not (tmp_path / "fennel1.pkl").exists()
    assert len(list(tmp_path.glob("fennel1.pkl.corrupt-*"))) == 1
    assert client.session._rsa_default_timeout == http_timeouts.DEFAULT_TIMEOUT


class _FennelOrderClient:
    """place_order shaped like fennel_invest_api's: lookups, then the query
    build, then the POST."""

    def __init__(self, before=None, after=None, reply=None):
        self.before, self.after, self.reply = before, after, reply
        self.endpoints = types.SimpleNamespace(stock_order_query=lambda *a: "q")
        fennel._harden_client(self)

    def place_order(self, **kw):
        if self.before:
            raise self.before
        if kw.get("dry_run"):
            return {"dry_run_success": True}
        self.endpoints.stock_order_query("acct", "X", 1, "isin", "buy", None)
        if self.after:
            raise self.after
        return self.reply


def _fennel_place(client):
    cfg = fennel.FennelConfig(emails=["a@x"], sessions_dir=Path("."))
    b = fennel.FennelBroker(cfg)
    b._sessions = [fennel._LoginSession(label="Fennel", email="a@x", client=client,
                                        accounts=[("Account 1", "x1")], pkl_name="p")]
    return b.place_order_all("ABCD", 1.0, "buy")


def test_fennel_failure_before_the_order_post_is_plain():
    out = _fennel_place(_FennelOrderClient(before=Exception("Failed to find ISIN")))
    msg = out.accounts[0].message
    assert not out.accounts[0].ok and not _may_exist(msg)


def test_fennel_failure_after_the_order_post_says_verify():
    out = _fennel_place(_FennelOrderClient(after=requests.ReadTimeout("timed out")))
    assert _may_exist(out.accounts[0].message), out.accounts[0].message


def test_fennel_4xx_order_answer_is_plain():
    out = _fennel_place(_FennelOrderClient(after=Exception(
        "Order Request failed with status code 400: bad request")))
    assert not _may_exist(out.accounts[0].message)


@pytest.mark.parametrize("reply,ok,verify", [
    ({"data": {"createOrder": "pending"}}, True, False),
    ({"data": {"createOrder": None}}, False, True),             # unknown
    ({"errors": [{"message": "not allowed"}]}, False, False),   # GraphQL refusal
    ("garbage", False, True),
])
def test_fennel_order_reply_interpretation(reply, ok, verify):
    out = _fennel_place(_FennelOrderClient(reply=reply))
    acct = out.accounts[0]
    assert acct.ok is ok
    assert _may_exist(acct.message) is verify, acct.message


def test_fennel_otp_goes_through_the_prompt_hook_not_input(monkeypatch):
    asked = []
    monkeypatch.setattr(fennel, "request_text",
                        lambda broker, prompt, timeout_s=300: asked.append(broker) or "123456")

    def _boom(*a, **k):
        raise AssertionError("builtins.input must not be used")
    monkeypatch.setattr(builtins, "input", _boom)
    assert fennel._otp_provider_terminal()("Fennel", 300) == "123456"
    assert asked == ["Fennel"]


# =================================================================== Schwab

class _SchwabSession:
    def __init__(self, verify_code=200, confirm=None):
        self.posts = []
        self.verify_code = verify_code
        self.confirm = confirm

    def post(self, url, data=None, **kw):
        self.posts.append(url)
        return url


class _LegacyClient:
    """trade_v2's check refuses; legacy trade() runs on a watched session."""

    def __init__(self, confirm_fails=False, verify_fails=False, raise_after_confirm=False):
        self.session = _SchwabSession()
        self.confirm_fails = confirm_fails
        self.verify_fails = verify_fails
        self.raise_after_confirm = raise_after_confirm
        self.live_v2 = 0

    def trade_v2(self, **kw):
        if not kw.get("dry_run"):
            self.live_v2 += 1
        return (["unnamed v2 problem"], False)

    def trade(self, **kw):
        self.session.post("https://client.schwab.com/api/ts/stamp/verifyOrder", {})
        if self.verify_fails:
            return (["Insufficient buying power"], False)
        self.session.post("https://client.schwab.com/api/ts/stamp/confirmorder", {})
        if self.raise_after_confirm:
            raise KeyError("ReturnCode")
        return (["Gateway Timeout"], not self.confirm_fails)


@pytest.fixture
def schwab_run(monkeypatch):
    def _run(client):
        monkeypatch.setattr(schwab, "_build_sessions",
                            lambda: [{"idx": 1, "label": "Schwab", "client": client}])
        monkeypatch.setattr(schwab, "_refresh_token_soft", lambda c: True)
        monkeypatch.setattr(schwab, "_discover_account_ids_for_trade", lambda c: ["12345678"])
        monkeypatch.setattr(schwab, "BLOG", None)
        monkeypatch.setattr(schwab.time, "sleep", lambda s: None)
        return schwab.execute_trade(side="buy", qty="1", symbol="abcd")
    return _run


def test_schwab_legacy_failure_after_confirmation_says_verify(schwab_run):
    c = _LegacyClient(confirm_fails=True)
    out = schwab_run(c)
    assert c.live_v2 == 0
    assert _may_exist(out.accounts[0].message), out.accounts[0].message
    assert "post" not in vars(c.session)       # the watch is removed again


def test_schwab_legacy_exception_after_confirmation_says_verify(schwab_run):
    out = schwab_run(_LegacyClient(raise_after_confirm=True))
    assert _may_exist(out.accounts[0].message), out.accounts[0].message


def test_schwab_legacy_failure_at_verification_stays_plain(schwab_run):
    out = schwab_run(_LegacyClient(verify_fails=True))
    msg = out.accounts[0].message
    assert "Insufficient buying power" in msg and not _may_exist(msg)


def test_schwab_login_one_keeps_its_label(monkeypatch, tmp_path):
    class FakeSchwab:
        def __init__(self, session_cache=None, debug=False):
            self.session = _FakeSession()

    monkeypatch.setattr(schwab, "_SESSIONS", [])
    monkeypatch.setattr(schwab, "_parse_accounts_from_env",
                        lambda: [("u1", "p1", None), ("u2", "p2", None)])
    monkeypatch.setattr(schwab, "_load_schwab_class", lambda: FakeSchwab)
    monkeypatch.setattr(schwab, "_session_cache_path", lambda i: tmp_path / f"s{i}.json")
    sessions = schwab._build_sessions()
    assert [s["label"] for s in sessions] == ["Schwab", "Schwab 2"]
    assert sessions[0]["client"].session._rsa_default_timeout == http_timeouts.DEFAULT_TIMEOUT


# ============================================================ http_timeouts

def test_module_proxy_adds_a_timeout_only_when_missing():
    seen = []
    real = types.SimpleNamespace(
        post=lambda url, **kw: seen.append(kw.get("timeout")),
        exceptions=requests.exceptions)
    mod = types.SimpleNamespace(requests=real)
    assert http_timeouts.patch_module_requests(mod)
    assert http_timeouts.patch_module_requests(mod)           # idempotent
    mod.requests.post("u")
    mod.requests.post("u", timeout=3)
    assert seen == [http_timeouts.DEFAULT_TIMEOUT, 3]
    assert mod.requests.exceptions is requests.exceptions
    assert http_timeouts.patch_module_requests(None) is False
