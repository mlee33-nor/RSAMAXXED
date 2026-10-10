"""SoFi must never POST an account's order twice in one run.

The old loop raised out of the per-account loop on a 401 (or any exception
from the POST / its JSON), discarding the results of accounts already ordered;
the outer handler then re-logged-in and re-ran _do_once over EVERY account — a
confirmed duplicate. Now: a 401 before anything was sent may re-login and
retry; a 401 after an order went out reports the rest as not sent; a POST that
raised, or a 200 whose body can't be read, is "submitted ... verify" and never
retried. Fake HTTP only: no network, no login, no browser.
"""

from __future__ import annotations

import pytest

import sofi


class _Resp:
    def __init__(self, status=200, body=None, text=None, bad_json=False):
        self.status_code = status
        self._body = body
        self.bad_json = bad_json
        self.text = text if text is not None else ("x" if (body is not None or bad_json) else "")

    def json(self):
        if self.bad_json:
            raise ValueError("Expecting value: line 1 column 1")
        return self._body


class _FakeReq:
    def __init__(self, post_plan, accounts=("A1111", "B2222", "C3333")):
        self.post_plan = list(post_plan)  # per POST: _Resp or Exception
        self.posts = []
        self.accounts = accounts

    def get(self, url, **kw):
        if "quote" in url:
            return _Resp(body={"last": 2.0, "bid": 1.99, "ask": 2.01})
        return _Resp(body=[{"accountId": a, "accountType": "INDIVIDUAL"} for a in self.accounts])

    def post(self, url, json=None, **kw):
        self.posts.append(json["accountId"])
        step = self.post_plan.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


@pytest.fixture
def run(monkeypatch):
    calls = {"rehydrate": 0}

    def _rehydrate(**kw):
        calls["rehydrate"] += 1
        return sofi.BrokerOutput(broker="SoFi", state="success", accounts=[], message="")

    def _run(req):
        monkeypatch.setattr(sofi, "_rehydrate_session", _rehydrate)
        monkeypatch.setattr(sofi, "_require_session", lambda **kw: None)
        monkeypatch.setattr(sofi, "_requests", lambda: req)
        monkeypatch.setattr(sofi, "_trading_session", lambda: "CORE_HOURS")
        monkeypatch.setattr(sofi.time, "sleep", lambda s: None)
        monkeypatch.setattr(sofi.BLOG, "write_log", lambda *a, **k: None)
        monkeypatch.setattr(sofi.BLOG, "log_exception", lambda *a, **k: None)
        return sofi._execute_trade_one(side="buy", qty="1", symbol="abcd")

    _run.calls = calls
    return _run


def _ok():
    return _Resp(body={"experiment": "ORDER_SUBMITTED"})


def _may_exist(msg: str) -> bool:
    m = msg.lower()
    return "verify" in m and ("submitted" in m or "placed" in m)


def test_401_after_an_order_never_reorders(run):
    req = _FakeReq([_ok(), _Resp(status=401, text="unauthorized")])
    out = run(req)

    assert req.posts == ["A1111", "B2222"]          # C never sent, A never re-sent
    assert run.calls["rehydrate"] == 1              # only the up-front login
    a, b, c = out.accounts
    assert a.ok and a.message == "order placed"
    assert not b.ok and not _may_exist(b.message)
    assert not c.ok and c.message.startswith("Skipped:") and not _may_exist(c.message)
    assert out.state == "partial"


def test_401_before_any_order_relogs_and_retries(run):
    req = _FakeReq([_Resp(status=401, text="unauthorized"), _ok(), _ok(), _ok()])
    out = run(req)

    assert req.posts == ["A1111", "A1111", "B2222", "C3333"]
    assert run.calls["rehydrate"] == 2
    assert [a.ok for a in out.accounts] == [True, True, True]


def test_post_exception_is_verify_and_not_retried(run):
    req = _FakeReq([_ok(), TimeoutError("read timed out"), _ok()])
    out = run(req)

    assert req.posts == ["A1111", "B2222", "C3333"]
    assert run.calls["rehydrate"] == 1
    a, b, c = out.accounts
    assert a.ok and c.ok
    assert not b.ok and _may_exist(b.message)


def test_unauthorized_text_in_post_exception_does_not_trigger_rerun(run):
    # Even an exception whose text looks like an auth failure must not
    # re-run accounts: the POST itself may have reached SoFi.
    req = _FakeReq([_ok(), RuntimeError("HTTP 401 unauthorized"), _ok()])
    out = run(req)

    assert req.posts == ["A1111", "B2222", "C3333"]
    assert run.calls["rehydrate"] == 1
    assert _may_exist(out.accounts[1].message)


def test_unparseable_200_is_verify(run):
    req = _FakeReq([_Resp(bad_json=True), _ok(), _ok()])
    out = run(req)

    assert req.posts == ["A1111", "B2222", "C3333"]
    a = out.accounts[0]
    assert not a.ok and _may_exist(a.message)
    assert out.accounts[1].ok and out.accounts[2].ok


def test_retry_after_relogin_then_second_401_keeps_results(run):
    # 401 before anything sent -> re-login; the retry orders A, then 401 on B.
    req = _FakeReq([_Resp(status=401), _ok(), _Resp(status=401)])
    out = run(req)

    assert req.posts == ["A1111", "A1111", "B2222"]
    assert out.accounts[0].ok
    assert not out.accounts[1].ok and not out.accounts[2].ok
    assert all(not _may_exist(a.message) for a in out.accounts[1:])
