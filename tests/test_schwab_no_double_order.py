"""Schwab must never send a second order after trade_v2 says False.

schwab_api's trade_v2 returns False AFTER its placement POST too (a 504 once
Schwab accepted the order, a return code outside the valid set). The old code
answered every unrecognised False with the legacy client.trade(), which could
place the same order a second time. These run on a stub client: no network,
no browser, no login.
"""

from __future__ import annotations

import pytest

import schwab


class _StubClient:
    """`check_*` answers trade_v2(dry_run=True) — the verification-only pass
    (and the whole call on a dry run); `v2_*` answers the live call."""

    def __init__(self, v2_result=None, v2_exc=None, check_result=([], True), check_exc=None):
        self.v2_result = v2_result
        self.v2_exc = v2_exc
        self.check_result = check_result
        self.check_exc = check_exc
        self.v2_calls = []
        self.trade_calls = []

    @property
    def live_calls(self):
        return [c for c in self.v2_calls if not c["dry_run"]]

    def trade_v2(self, **kw):
        self.v2_calls.append(kw)
        if kw.get("dry_run"):
            if self.check_exc is not None:
                raise self.check_exc
            return self.check_result
        if self.v2_exc is not None:
            raise self.v2_exc
        return self.v2_result

    def trade(self, **kw):
        self.trade_calls.append(kw)
        return ["legacy ok"], True


@pytest.fixture
def run(monkeypatch):
    def _run(client, *, dry_run=False):
        monkeypatch.setattr(schwab, "_build_sessions",
                            lambda: [{"idx": 1, "label": "Schwab 1", "client": client}])
        monkeypatch.setattr(schwab, "_refresh_token_soft", lambda c: True)
        monkeypatch.setattr(schwab, "_discover_account_ids_for_trade", lambda c: ["12345678"])
        monkeypatch.setattr(schwab, "BLOG", None)
        monkeypatch.setattr(schwab.time, "sleep", lambda s: None)
        return schwab.execute_trade(side="buy", qty="1", symbol="abcd", dry_run=dry_run)
    return _run


def test_v2_false_after_submit_never_calls_legacy_trade(run):
    client = _StubClient(v2_result=(["Gateway Timeout"], False))
    out = run(client)

    assert len(client.live_calls) == 1
    assert client.v2_calls[0]["dry_run"] is True  # checked before the live call
    assert client.trade_calls == []
    assert out.state == "failed"
    [acct] = out.accounts
    assert not acct.ok
    msg = acct.message.lower()
    assert "verify" in msg and "submitted" in msg
    assert "Gateway Timeout" in acct.message


def test_v2_false_with_empty_messages_still_reports_may_be_submitted(run):
    client = _StubClient(v2_result=(None, False))
    out = run(client)

    assert client.trade_calls == []
    [acct] = out.accounts
    assert not acct.ok and "verify" in acct.message.lower()


def test_known_pre_placement_error_keeps_friendly_message(run):
    err = "This order may result in an oversold/overbought position in your account."
    client = _StubClient(check_result=([err], False))
    out = run(client)

    assert client.live_calls == []
    assert client.trade_calls == []
    [acct] = out.accounts
    assert not acct.ok
    assert acct.message == ("Order failed: This may result in an oversold/overbought position."
                            " — nothing was sent")


def test_v2_exception_on_live_order_reads_as_may_be_submitted(run):
    client = _StubClient(v2_exc=TimeoutError("read timed out"))
    out = run(client)

    assert client.trade_calls == []
    [acct] = out.accounts
    assert not acct.ok
    msg = acct.message.lower()
    assert "verify" in msg and "submitted" in msg and "read timed out" in msg


def test_v2_success_is_ok(run):
    client = _StubClient(v2_result=([], True))
    out = run(client)

    assert client.trade_calls == []
    assert out.state == "success"
    assert out.accounts[0].ok


def test_dry_run_keeps_legacy_verification_retry(run):
    # A dry run never reaches the placement POST, and the legacy call stops at
    # verification with dry_run=True, so the retry is still allowed there.
    client = _StubClient(check_result=(["something odd"], False))
    out = run(client, dry_run=True)

    assert len(client.v2_calls) == 1  # no separate pre-check on a dry run

    assert len(client.trade_calls) == 1
    assert client.trade_calls[0]["dry_run"] is True
    assert out.accounts[0].ok


# Mirrors app._ORDER_MAY_EXIST (app.py is a GUI module; not imported here).
_ORDER_MAY_EXIST = ("submitted", "placed", "accepted", "pending", "queued",
                    "working", "order id", "confirmation", "verify")


def _no_order_words(msg):
    low = msg.lower()
    return not [w for w in _ORDER_MAY_EXIST if w in low]


def test_precheck_false_falls_back_to_one_legacy_order_never_live_v2(run):
    # v2's verification refused for an unnamed reason: nothing was placed, so
    # the legacy endpoint gets the order -- exactly once -- and v2 never goes live.
    client = _StubClient(check_result=(["Something v2 did not like"], False),
                         v2_result=([], True))
    out = run(client)

    assert client.live_calls == []
    assert len(client.trade_calls) == 1
    assert client.trade_calls[0]["dry_run"] is False
    [acct] = out.accounts
    assert acct.ok


def test_precheck_false_then_legacy_failure_is_plain(run):
    # Token expiry / insufficient funds at both endpoints: nothing was sent,
    # so the failure must stay retryable.
    client = _StubClient(check_result=(["Insufficient buying power"], False),
                         v2_result=([], True))
    client.trade = lambda **kw: (client.trade_calls.append(kw)
                                 or (["Insufficient buying power"], False))
    out = run(client)

    assert client.live_calls == []
    assert len(client.trade_calls) == 1
    [acct] = out.accounts
    assert not acct.ok
    assert "Insufficient buying power" in acct.message
    assert _no_order_words(acct.message), acct.message


def test_precheck_exception_is_plain_and_never_goes_live(run):
    client = _StubClient(check_exc=ConnectionError("connection reset"), v2_result=([], True))
    out = run(client)

    assert client.live_calls == []
    [acct] = out.accounts
    assert not acct.ok and "connection reset" in acct.message
    assert _no_order_words(acct.message), acct.message


def test_precheck_known_error_uses_friendly_text(run):
    err = ("Your order is not eligible for electronic entry. Please call a Charles Schwab "
           "representative at (800) 435-9050 for assistance with this trade.")
    client = _StubClient(check_result=([err], False))
    out = run(client)

    assert client.live_calls == []
    # The verification-only pass refused it: friendly text, and positively
    # nothing sent (round-2 audit), so a hand-back may retry it.
    assert out.accounts[0].message == ("Order failed: Stock not eligible for online entry"
                                       " — nothing was sent")


def test_precheck_ok_then_live_false_says_verify(run):
    client = _StubClient(check_result=([], True), v2_result=(["orderReturnCode 99"], False))
    out = run(client)

    assert len(client.live_calls) == 1
    assert client.trade_calls == []
    msg = out.accounts[0].message.lower()
    assert "verify" in msg and "submitted" in msg
