"""A leg whose order may already be at the broker is never retried.

Broker modules report an order they submitted but never saw confirmed as
ok=False with "submitted ... verify" in the message. The receipt's Retry button,
auto-sell's hand-back and mirror's "Trade manually" row must all treat that as
"check the broker", never as "place it again".

Pure logic: the real methods run unbound against stand-ins, no App, no Tk.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


UNCONFIRMED = {"account_id": "Z222", "ok": False,
               "message": "Order submitted but no confirmation seen — verify at the broker"}
REJECTED = {"account_id": "Z333", "ok": False, "message": "Insufficient shares"}
FILLED = {"account_id": "Z111", "ok": True, "message": "filled"}


def _result(broker, *accounts):
    ok = sum(1 for a in accounts if a.get("ok"))
    return {"broker": broker, "ok_accounts": ok,
            "fail_accounts": len(accounts) - ok, "errors": [],
            "accounts": list(accounts)}


def test_the_retry_plan_skips_an_order_that_may_exist():
    plan = A.App._failed_account_plan(
        [_result("fidelity", FILLED, UNCONFIRMED, REJECTED)])
    assert plan == {"fidelity": ["Z333"]}


def test_only_unconfirmed_failures_mean_no_retry_at_all():
    assert A.App._failed_account_plan([_result("wellsfargo", UNCONFIRMED)]) == {}


def test_unconfirmed_accounts_are_listed_to_verify_by_hand():
    out = A._verify_manually_accounts([
        _result("fidelity", FILLED, UNCONFIRMED, REJECTED),
        _result("robinhood", dict(UNCONFIRMED, account_id="R1")),
        _result("schwab", REJECTED)])
    assert out == {"fidelity": ["Z222"], "robinhood": ["R1"]}


def test_a_filled_account_is_never_flagged_whatever_its_message():
    assert not A._account_order_may_exist({"ok": True, "message": "order submitted"})
    assert A._account_order_may_exist({"ok": False, "message": "Submitted; VERIFY"})


# --------------------------------------------------------------- auto-sell

class _Settle:
    _exit_batch_settle = A.App._exit_batch_settle

    def __init__(self):
        self.handed_back = []

    def _autosell_retry(self, task, why):
        self.handed_back.append(why)


def test_autosell_keeps_an_unconfirmed_leg_claimed(monkeypatch):
    monkeypatch.setattr(A, "_mark_public_late_checked", lambda syms: None)
    s = _Settle()
    task = types.SimpleNamespace(symbol="GRNQ", alert_symbol="GRNQ")
    s._exit_batch_settle({"exit_task": task, "autosell": True},
                         [_result("fidelity", UNCONFIRMED)])
    assert s.handed_back == []


def test_autosell_still_hands_back_a_plain_rejection(monkeypatch):
    s = _Settle()
    task = types.SimpleNamespace(symbol="GRNQ", alert_symbol="GRNQ")
    s._exit_batch_settle({"exit_task": task, "autosell": True},
                         [_result("fidelity", REJECTED)])
    assert len(s.handed_back) == 1


# ------------------------------------------------------------------ mirror

class _Mirror:
    _mirror_record_outcome = A.App._mirror_record_outcome
    _mirror_owe_failed_legs = A.App._mirror_owe_failed_legs

    def __init__(self):
        self._mirror_failed = set()
        self._mirror_failed_notes = {}
        self.logs, self.notes = [], []

    def _mirror_log_msg(self, msg):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _save_mirror_state(self):
        pass

    def _render_mirror_failed(self):
        pass


def test_mirror_says_verify_before_offering_a_second_buy():
    m = _Mirror()
    key = ("2026-10-05", "SFWL")
    m._mirror_record_outcome({"symbol": "SFWL", "mirror_key": key,
                              "all_brokers": ["fidelity"], "mirror_skipped": [],
                              "results": [_result("fidelity", UNCONFIRMED)]}, 0, 1)
    assert key in m._mirror_failed
    assert "verify manually" in m._mirror_failed_notes[key]
    assert any("verify" in msg for msg, _k in m.notes)


def test_mirror_plain_failure_wording_is_unchanged():
    m = _Mirror()
    key = ("2026-10-05", "SFWL")
    # A plain rejection sent nothing, so earlier launches are handed back for
    # another try (test_mirror_fixes_2026_10); this is the last one, which is
    # what lands in NEEDS ATTENTION.
    m._mirror_executed = {key}
    m._mirror_attempts = {key: A.MIRROR_MAX_ATTEMPTS - 1}
    m._mirror_record_outcome({"symbol": "SFWL", "mirror_key": key,
                              "all_brokers": ["fidelity"], "mirror_skipped": [],
                              "results": [_result("fidelity", REJECTED)]}, 0, 1)
    assert "verify" not in m._mirror_failed_notes[key]
