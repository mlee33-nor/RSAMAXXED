"""API-broker audit fixes, round two: failed logins are rows at Fennel, a
failed Schwab account read is a row, Robinhood logins never share the
robin_stocks session mid-call, refused Robinhood logins are failures, a ':' in
a password survives, and dependency drift is detected.

Fakes and monkeypatching only: no broker, no network, no browser, and no
dependence on `import schwab_api` working (it does not on a machine with
playwright-stealth 2.x, which is one of the things this file tests for).
"""

from __future__ import annotations

import json
import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import broker_logins
import fennel
import robinhood
import schwab
from modules import depcheck
from modules.outputs import AccountOutput, BrokerOutput


def _may_exist(msg: str) -> bool:
    return A._account_order_may_exist({"ok": False, "message": msg})


# ================================================================ Robinhood

def test_rh_entry_points_hold_one_session_lock(monkeypatch):
    """Two threads never run a login+call against the shared session at once."""
    inside = threading.Event()
    release = threading.Event()
    order = []

    def slow_session():
        order.append("first-in")
        inside.set()
        release.wait(5)
        order.append("first-out")
        return False, "Auth required: test"

    monkeypatch.setattr(robinhood, "_ensure_session", slow_session)
    t1 = threading.Thread(target=robinhood.get_holdings)
    t1.start()
    assert inside.wait(5)

    def second():
        order.append("second-in")
        return False, "Auth required: test"

    monkeypatch.setattr(robinhood, "_ensure_session", second)
    t2 = threading.Thread(target=lambda: robinhood.execute_trade(
        side="buy", qty="1", symbol="ABCD"))
    t2.start()
    time.sleep(0.2)
    assert order == ["first-in"]            # blocked behind the first call
    release.set()
    t1.join(5)
    t2.join(5)
    assert order == ["first-in", "first-out", "second-in"]


def test_rh_lock_is_reentrant_for_get_accounts(monkeypatch):
    monkeypatch.setattr(robinhood, "_ensure_session", lambda: (False, "Auth required"))
    out = robinhood.get_accounts()          # get_accounts -> get_holdings
    assert out.state == "failed"


def _fake_rh(login_result):
    def login(username=None, password=None, expiresIn=None, store_session=True,
              pickle_path="", pickle_name=""):
        return login_result
    auth = types.SimpleNamespace(login=login)
    return types.SimpleNamespace(authentication=auth)


def test_rh_cached_login_returning_none_is_a_failure():
    with pytest.raises(RuntimeError) as ei:
        robinhood.login_with_cache(rh=_fake_rh(None), pickle_name="Robinhood 1")
    assert "Interactive re-login required" in str(ei.value)


def test_rh_cached_login_returning_a_session_passes():
    robinhood.login_with_cache(rh=_fake_rh({"access_token": "t"}),
                               pickle_name="Robinhood 1")


def test_rh_bootstrap_refused_login_reports_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(robinhood, "_load_rh", lambda: (_fake_rh(None), None))
    monkeypatch.setattr(robinhood, "_login_profiles",
                        lambda: [("Robinhood 1", "u", "p")])
    monkeypatch.setattr(robinhood, "_pickle_path", lambda: tmp_path)
    monkeypatch.setattr(robinhood, "_log_login_transcript", lambda *a, **k: None)
    monkeypatch.setattr(robinhood, "_log_mfa_decision", lambda *a, **k: None)
    rehydrated = []
    monkeypatch.setattr(robinhood, "login_with_cache",
                        lambda **kw: rehydrated.append(kw))
    out = robinhood.bootstrap()
    assert out.state == "failed"
    assert "did not accept the sign-in" in out.accounts[0].message
    assert rehydrated == []                 # no misleading rehydrate afterwards


# =================================================================== Fennel

class _FennelClient:
    def __init__(self, fail=False):
        self.fail = fail
        self.orders = []
        self.endpoints = types.SimpleNamespace(stock_order_query=lambda *a: "q")

    def login(self, **kw):
        if self.fail:
            raise RuntimeError("Failed to login: bad code")
        return True

    def get_full_accounts(self):
        return [{"name": "Account 1", "id": "x1"}]

    def place_order(self, **kw):
        self.orders.append(kw)
        return {"data": {"createOrder": "pending"}}

    def get_stock_holdings(self, acct_id):
        return [{"security": {"ticker": "ABCD", "currentStockPrice": 1.0},
                 "investment": {"ownedShares": 1}}]


def _fennel_broker(monkeypatch, tmp_path, failing=(1,), n=2):
    clients = {i: _FennelClient(fail=i in failing) for i in range(n)}
    cfg = fennel.FennelConfig(emails=[f"e{i}@x" for i in range(n)], sessions_dir=tmp_path)
    b = fennel.FennelBroker(cfg, otp_provider=lambda *a: None)
    monkeypatch.setattr(b, "_make_client", lambda i: (clients[i], f"fennel{i + 1}.pkl"))
    return b, clients


def test_fennel_failed_login_is_a_row_when_trading(monkeypatch, tmp_path):
    b, clients = _fennel_broker(monkeypatch, tmp_path)
    assert b.ensure_authenticated().state == "partial"
    out = b.place_order_all("ABCD", 1.0, "buy")
    by_id = {a.account_id: a for a in out.accounts}
    assert by_id["Fennel · Account 1"].ok
    assert not by_id["Fennel 2"].ok
    assert A._nothing_was_sent(by_id["Fennel 2"].message)
    assert not _may_exist(by_id["Fennel 2"].message)
    assert out.state == "partial"
    assert clients[1].orders == []


def test_fennel_failed_login_is_a_row_in_holdings(monkeypatch, tmp_path):
    b, _ = _fennel_broker(monkeypatch, tmp_path)
    b.ensure_authenticated()
    out = b.get_holdings()
    assert out.state == "partial"
    assert [a.account_id for a in out.accounts if not a.ok] == ["Fennel 2"]


def test_fennel_failed_rows_are_fresh_copies(monkeypatch, tmp_path):
    b, _ = _fennel_broker(monkeypatch, tmp_path)
    b.ensure_authenticated()
    first = b.place_order_all("ABCD", 1.0, "buy")
    first.accounts[0].account_id = "mangled"   # app/_prefixed mutate rows
    second = b.place_order_all("ABCD", 1.0, "buy")
    assert any(a.account_id == "Fennel 2" for a in second.accounts)


def test_fennel_every_login_failed_reports_each_login(monkeypatch, tmp_path):
    clients = {i: _FennelClient(fail=True) for i in range(2)}
    cfg = fennel.FennelConfig(emails=["a@x", "b@x"], sessions_dir=tmp_path)
    monkeypatch.setattr(fennel.FennelConfig, "from_env", staticmethod(lambda: cfg))
    monkeypatch.setattr(fennel.FennelBroker, "_make_client",
                        lambda self, i: (clients[i], f"fennel{i + 1}.pkl"))
    for fn in (fennel.get_holdings,
               lambda: fennel.execute_trade(side="buy", qty="1", symbol="ABCD")):
        out = fn()
        assert out.state == "failed"
        assert [a.account_id for a in out.accounts] == ["Fennel", "Fennel 2"]
        assert all(A._nothing_was_sent(a.message) for a in out.accounts)
    assert all(c.orders == [] for c in clients.values())


def test_fennel_bootstrap_lists_the_failed_login(monkeypatch, tmp_path):
    clients = {0: _FennelClient(), 1: _FennelClient(fail=True)}
    cfg = fennel.FennelConfig(emails=["a@x", "b@x"], sessions_dir=tmp_path)
    monkeypatch.setattr(fennel.FennelConfig, "from_env", staticmethod(lambda: cfg))
    monkeypatch.setattr(fennel.FennelBroker, "_make_client",
                        lambda self, i: (clients[i], f"fennel{i + 1}.pkl"))
    out = fennel.bootstrap()
    assert out.state == "success"           # the working login stays green
    assert any(a.account_id == "Fennel 2" and not a.ok for a in out.accounts)
    assert "Fennel 2" in out.message


# =================================================================== Schwab

class _Resp:
    def __init__(self, code, text):
        self.status_code = code
        self.text = text


def _v2_payload(acc_id, sym="ABCD"):
    return json.dumps({"accounts": [{
        "accountId": acc_id,
        "totals": {"marketValue": 5, "accountValue": 5},
        "groupedPositions": [{"groupName": "Equity", "holdingsRows": [
            {"symbol": {"symbol": sym}, "qty": {"qty": 1},
             "marketValue": {"val": 5}}]}],
    }]})


@pytest.fixture
def fake_schwab_api(monkeypatch):
    """`from schwab_api import urls` without importing the real package."""
    urls = types.SimpleNamespace(positions_v2=lambda: "https://x/positions")
    pkg = types.ModuleType("schwab_api")
    pkg.urls = urls
    monkeypatch.setitem(sys.modules, "schwab_api", pkg)
    monkeypatch.setattr(schwab, "_dump_schwab_payload", lambda *a, **k: None)
    return urls


def _v2_client():
    return types.SimpleNamespace(update_token=lambda **kw: None, headers={})


@pytest.mark.parametrize("bad", [_Resp(500, "oops"), _Resp(200, "<html>"),
                                 _Resp(200, "{}"), RuntimeError("timed out")])
def test_schwab_v2_failed_account_read_is_kept_marked(monkeypatch, fake_schwab_api, bad):
    monkeypatch.setenv("SCHWAB_ACCOUNT_NUMBERS", "11112222:33334444")
    monkeypatch.delenv("SCHWAB_ACCOUNT_ID", raising=False)

    def get(url, headers=None, timeout=None):
        if headers["schwab-client-account"] == "33334444":
            if isinstance(bad, Exception):
                raise bad
            return bad
        return _Resp(200, _v2_payload("11112222"))
    monkeypatch.setattr(schwab.requests, "get", get)

    info = schwab._probe_account_info_v2(_v2_client())
    assert info[11112222]["positions"][0]["symbol"] == "ABCD"
    assert info[33334444][schwab._READ_ERROR]
    assert schwab._has_read_errors(info)


def test_schwab_failed_account_read_is_a_failed_holdings_row(monkeypatch):
    monkeypatch.delenv("SCHWAB_ACCOUNT_ID", raising=False)
    monkeypatch.setattr(schwab, "_build_sessions",
                        lambda: [{"idx": 1, "label": "Schwab", "client": object()}])
    monkeypatch.setattr(schwab, "BLOG", None)
    monkeypatch.setattr(schwab, "_ensure_authed", lambda sess: {
        11112222: {"account_id": "11112222", "account_value": 5.0, "positions": [
            {"symbol": "ABCD", "quantity": 1.0, "market_value": 5.0}]},
        33334444: {"account_id": "33334444", "positions": [],
                   schwab._READ_ERROR: "HTTP 500"},
    })
    out = schwab.get_holdings()
    assert out.state == "partial"
    bad = [a for a in out.accounts if not a.ok]
    assert len(bad) == 1 and "****4444" in bad[0].account_id
    assert "holdings unknown" in bad[0].message


def test_schwab_ensure_authed_returns_partial_read_not_empty(monkeypatch):
    partial = {33334444: {"account_id": "33334444", "positions": [],
                          schwab._READ_ERROR: "HTTP 500"}}
    monkeypatch.setattr(schwab, "_refresh_token_soft", lambda c: True)
    monkeypatch.setattr(schwab, "_probe_account_info_v2", lambda c: partial)
    monkeypatch.setattr(schwab, "_probe_account_info_legacy", lambda c: None)
    monkeypatch.setattr(schwab, "_login_one", lambda s: None)
    monkeypatch.setattr(schwab, "BLOG", None)
    assert schwab._ensure_authed({"idx": 1, "client": object()}) is partial


class _TradeClient:
    def __init__(self):
        self.calls = []

    def trade_v2(self, **kw):
        self.calls.append(kw)
        return (["ok"], True)


@pytest.fixture
def schwab_trade(monkeypatch, tmp_path):
    def _run(client, discovered, qty="1", username="u1"):
        sess = {"idx": 1, "label": "Schwab", "client": client, "username": username,
                "cache_path": tmp_path / "schwab1.json"}
        monkeypatch.setattr(schwab, "_build_sessions", lambda: [sess])
        monkeypatch.setattr(schwab, "_refresh_token_soft", lambda c: True)
        monkeypatch.setattr(schwab, "_discover_account_ids_for_trade",
                            lambda c: list(discovered))
        monkeypatch.setattr(schwab, "BLOG", None)
        monkeypatch.setattr(schwab.time, "sleep", lambda s: None)
        return schwab.execute_trade(side="buy", qty=qty, symbol="abcd")
    return _run


def test_schwab_trades_on_remembered_ids_when_discovery_fails(schwab_trade):
    c1 = _TradeClient()
    schwab_trade(c1, ["11112222"])
    c2 = _TradeClient()
    out = schwab_trade(c2, [])              # holdings outage: nothing discovered
    assert out.state == "success"
    assert {c["account_id"] for c in c2.calls} == {"11112222"}


def test_schwab_remembered_ids_belong_to_one_username(schwab_trade):
    schwab_trade(_TradeClient(), ["11112222"], username="u1")
    c = _TradeClient()
    out = schwab_trade(c, [], username="someone-else")
    assert c.calls == []
    assert out.state == "failed"
    assert A._nothing_was_sent(out.accounts[0].message)


def test_schwab_whole_quantity_is_sent_as_an_int(schwab_trade):
    c = _TradeClient()
    schwab_trade(c, ["11112222"], qty="1")
    assert all(str(call["qty"]) == "1" for call in c.calls)
    c2 = _TradeClient()
    schwab_trade(c2, ["11112222"], qty="0.5")
    assert all(call["qty"] == 0.5 for call in c2.calls)


def test_schwab_session_cache_follows_the_credentials(monkeypatch, tmp_path):
    class FakeSchwab:
        def __init__(self, session_cache=None, debug=False):
            self.session = None

    creds = [[("u1", "p1", None)]]
    monkeypatch.setattr(schwab, "_SESSIONS", [])
    monkeypatch.setattr(schwab, "_parse_accounts_from_env", lambda: list(creds[0]))
    monkeypatch.setattr(schwab, "_load_schwab_class", lambda: FakeSchwab)
    monkeypatch.setattr(schwab, "_session_cache_path", lambda i: tmp_path / f"s{i}.json")
    first = schwab._build_sessions()
    assert schwab._build_sessions() is first           # unchanged: reused
    creds[0] = [("u1", "NEW", None)]
    second = schwab._build_sessions()
    assert second is not first and second[0]["password"] == "NEW"


def test_schwab_password_with_colon_survives_env_parse(monkeypatch):
    monkeypatch.setenv("SCHWAB", "u1:pa:ss:JBSWY3DPEHPK3PXP,u2:plain")
    assert schwab._parse_accounts_from_env() == [
        ("u1", "pa:ss", "JBSWY3DPEHPK3PXP"), ("u2", "plain", None)]


# ============================================================ broker_logins

@pytest.mark.parametrize("item,want", [
    ("u:p", ["u", "p"]),
    ("u:p:", ["u", "p", ""]),
    ("u:p:NA", ["u", "p", "NA"]),
    ("u:p:t1", ["u", "p", "t1"]),
    # Exactly as many pieces as fields: read exactly as before.
    ("u:pa:ss", ["u", "pa", "ss"]),
    ("u:pa:ss:", ["u", "pa:ss", ""]),
    ("u:pa:ss:JBSWY3DPEHPK3PXP", ["u", "pa:ss", "JBSWY3DPEHPK3PXP"]),
    ("u:a:b:c:T", ["u", "a:b:c", "T"]),
])
def test_split_fields_keeps_a_colon_in_the_password(item, want):
    assert broker_logins.split_fields(item, broker_logins.SCHEMAS["schwab"]) == want


def test_list_login_with_colon_password_reads_whole(monkeypatch):
    monkeypatch.setenv("ROBINHOOD", "u1:pa:ss,u2:p2")
    rows = broker_logins.logins("robinhood")
    assert [r.get("password") for r in rows] == ["pa:ss", "p2"]
    assert [r.idx for r in rows] == [1, 2]
    monkeypatch.setenv("FIDELITY", "u1:a:b:JBSWY3DPEHPK3PXP")
    [f] = broker_logins.logins("fidelity")
    assert (f.get("password"), f.get("totp")) == ("a:b", "JBSWY3DPEHPK3PXP")


def test_colon_password_round_trips_through_the_editor(monkeypatch):
    monkeypatch.setenv("SCHWAB", "u1:pa:ss:JBSWY3DPEHPK3PXP")
    up = broker_logins.env_updates("schwab", broker_logins.as_rows("schwab"))
    assert up["SCHWAB"] == "u1:pa:ss:JBSWY3DPEHPK3PXP"


def test_colon_password_without_totp_keeps_an_empty_totp_slot(monkeypatch):
    for broker in ("schwab", "fidelity"):
        up = broker_logins.env_updates(broker, [
            {"username": "u1", "password": "pa:ss", "totp": ""},
            {"username": "u2", "password": "plain", "totp": ""}])
        blob = up[broker_logins.SCHEMAS[broker].blob]
        assert blob == "u1:pa:ss:,u2:plain"
        monkeypatch.setenv(broker_logins.SCHEMAS[broker].blob, blob)
        one, two = broker_logins.logins(broker)
        assert (one.get("password"), one.get("totp")) == ("pa:ss", "")
        assert two.get("password") == "plain"
    monkeypatch.setenv("SCHWAB", "u1:pa:ss:")
    assert schwab._parse_accounts_from_env() == [("u1", "pa:ss", None)]


# ================================================================= depcheck

_REQS = """\
# comment
requests>=2.28.0,<3
playwright-stealth==1.0.6
robin-stocks==3.4.0
missing-lib==1.0
weird @ https://example.invalid/x.whl
marker-lib==1.0 ; sys_platform == "linux"
"""


def test_depcheck_flags_drift_and_missing(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(_REQS, encoding="utf-8")
    have = {"requests": "2.32.3", "playwright-stealth": "2.0.2",
            "robin-stocks": "3.4.0"}
    problems = depcheck.check(req, version_of=have.get)
    assert {p.name: p.installed for p in problems} == {
        "playwright-stealth": "2.0.2", "missing-lib": None}
    assert [p.pin for p in problems] == ["playwright-stealth==1.0.6", "missing-lib==1.0"]
    msg = depcheck.startup_warning(req, version_of=have.get)
    assert "playwright-stealth" in msg and "INSTALL.bat" in msg


def test_depcheck_quiet_when_everything_matches(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2.28.0,<3\nfoo==1.0.0\n", encoding="utf-8")
    have = {"requests": "2.32.3", "foo": "1.0"}
    assert depcheck.check(req, version_of=have.get) == []
    assert depcheck.startup_warning(req, version_of=have.get) == ""
    assert depcheck.check(tmp_path / "nope.txt") == []      # unreadable: no crash


def test_depcheck_upper_bound(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests>=2.28.0,<3\n", encoding="utf-8")
    assert depcheck.check(req, version_of=lambda n: "3.0.0")[0].installed == "3.0.0"


def test_depcheck_warn_at_startup_never_raises(monkeypatch):
    monkeypatch.setattr(depcheck, "startup_warning", lambda: "drift")
    seen = []
    assert depcheck.warn_at_startup(seen.append) == "drift"
    assert seen == ["drift"]

    def boom(_m):
        raise RuntimeError("ui gone")
    assert depcheck.warn_at_startup(boom) == "drift"


def test_real_requirements_parse_every_pin():
    names = {n for n, _s, _c in depcheck.parse_requirements(
        depcheck.REQUIREMENTS.read_text(encoding="utf-8"))}
    assert {"playwright-stealth", "schwab-api", "robin-stocks",
            "fennel-invest-api"} <= names
