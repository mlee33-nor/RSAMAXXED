"""Chase's unauthorized retry must only re-run accounts where nothing was sent.

The old code re-ran EVERY account after a re-login whenever the whole trade
came back "failed" with any unauthorized text — including accounts whose
execute POST had already gone out (an "Unknown result"), i.e. a duplicate.
Now only accounts that failed as unauthorized BEFORE their execute POST are
run again; an error or unreadable answer after the execute POST is
"submitted ... verify", and a validate-phase failure never uses those words.
Fake HTTP only: no network, no login, no browser.
"""

from __future__ import annotations

import pytest

import chase


class _Resp:
    def __init__(self, status=200, body=None, text="{}", bad_json=False):
        self.status_code = status
        self._body = body
        self.text = text
        self.bad_json = bad_json

    def json(self):
        if self.bad_json:
            raise ValueError("not json")
        return self._body


def _accounts_payload(ids):
    return {"cache": [{"response": {"investmentAccountOverviews": [{
        "investmentAccountDetails": [{"accountId": i, "mask": f"...{i[-4:]}"} for i in ids]
    }]}}]}


class _FakeReq:
    def __init__(self, plan):
        # plan: acc_id -> list of steps for successive POSTs on that account;
        # a step is a _Resp or an Exception.
        self.plan = {k: list(v) for k, v in plan.items()}
        self.validates = []
        self.executes = []

    def get(self, url, **kw):
        return _Resp(body={"lastTradePriceAmount": 2.0})

    def post(self, url, json=None, **kw):
        acc = str(json["accountIdentifier"])
        (self.executes if "financialInformationExchangeSystemOrderIdentifier" in json
         else self.validates).append(acc)
        step = self.plan[acc].pop(0)
        if isinstance(step, BaseException):
            raise step
        return step


_VAL_OK = _Resp(body={"financialInformationExchangeSystemOrderIdentifier": "X1"})
_VAL_UNAUTH = _Resp(status=401, text="appId:UnauthenticationException")


def _exec_ok(oid="O1"):
    return _Resp(body={"orderIdentifier": oid, "orderStatus": "SUBMITTED"})


@pytest.fixture
def run(monkeypatch):
    calls = {"ensure": 0}

    def _ensure(**kw):
        calls["ensure"] += 1
        return chase.BrokerOutput(broker="Chase", state="success", accounts=[], message="")

    def _run(req, ids=("1001", "1002", "1003")):
        monkeypatch.setattr(chase, "ensure_session", _ensure)
        monkeypatch.setattr(chase, "_require_session", lambda: ({"c": "1"}, None))
        monkeypatch.setattr(chase, "_account_list", lambda cookies: _accounts_payload(ids))
        monkeypatch.setattr(chase, "_requests", lambda: req)
        monkeypatch.setattr(chase.time, "sleep", lambda s: None)
        return chase._execute_trade_one(side="buy", qty="1", symbol="abcd")

    _run.calls = calls
    return _run


def _may_exist(msg: str) -> bool:
    m = msg.lower()
    return "verify" in m and ("submitted" in m or "placed" in m)


def test_retry_reruns_only_unauthorized_pre_execute_accounts(run):
    # 1001: execute POST raised (may exist). 1002: validate 401 (nothing sent).
    req = _FakeReq({
        "1001": [_VAL_OK, TimeoutError("read timed out")],
        "1002": [_VAL_UNAUTH, _VAL_OK, _exec_ok("O2")],
    })
    out = run(req, ids=("1001", "1002"))

    assert req.executes == ["1001", "1002"]   # 1001 executed exactly once
    assert req.validates == ["1001", "1002", "1002"]
    assert run.calls["ensure"] == 2
    a, b = out.accounts
    assert not a.ok and _may_exist(a.message)
    assert b.ok and b.order_id == "O2"
    assert out.state == "partial"


def test_no_retry_when_failures_are_not_pre_execute_unauthorized(run):
    req = _FakeReq({
        "1001": [_VAL_OK, TimeoutError("unauthorized?")],   # after execute
        "1002": [_VAL_OK, _Resp(status=401, text="Unauthorized")],  # execute 401
    })
    out = run(req, ids=("1001", "1002"))

    assert req.executes == ["1001", "1002"]
    assert run.calls["ensure"] == 1
    assert out.state == "failed"
    assert _may_exist(out.accounts[0].message)


def test_no_order_id_after_execute_is_verify(run):
    req = _FakeReq({"1001": [_VAL_OK, _Resp(body={"orderStatus": "SUBMITTED"})]})
    out = run(req, ids=("1001",))
    [a] = out.accounts
    assert not a.ok and _may_exist(a.message)
    assert "unknown result" not in a.message.lower()


def test_unreadable_execute_answer_is_verify(run):
    req = _FakeReq({"1001": [_VAL_OK, _Resp(bad_json=True, text="<html>")]})
    out = run(req, ids=("1001",))
    [a] = out.accounts
    assert not a.ok and _may_exist(a.message)


def test_validate_phase_exception_never_uses_may_exist_words(run):
    req = _FakeReq({"1001": [ConnectionError("reset by peer")]})
    out = run(req, ids=("1001",))
    [a] = out.accounts
    assert not a.ok
    low = a.message.lower()
    for w in ("submitted", "placed", "verify", "confirmation", "unknown result"):
        assert w not in low
    assert req.executes == []


def test_all_pre_execute_unauthorized_reruns_each_once(run):
    req = _FakeReq({
        "1001": [_VAL_UNAUTH, _VAL_OK, _exec_ok("A")],
        "1002": [_VAL_UNAUTH, _VAL_OK, _exec_ok("B")],
    })
    out = run(req, ids=("1001", "1002"))
    assert req.executes == ["1001", "1002"]
    assert [a.ok for a in out.accounts] == [True, True]
    assert out.state == "success"
