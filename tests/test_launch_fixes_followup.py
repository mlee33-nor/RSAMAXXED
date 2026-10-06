"""Follow-ups to the launch fixes.

* Retry / "verify manually" keys on the brokers' actual may-exist wording
  ("verify" + "submitted"/"placed"), not the broad run-level keyword list that
  swallowed plain rejections and never-attempted "Skipped:" rows.
* The journal-dispute safety net compares journal KEYS ("fidelity"), not the
  display names ("Fidelity") a resolved exit carries — exercised through the
  real _leg_open_accounts, which the older tests stubbed out and so hid this.
* A recovered / unreadable journal is surfaced once in the GUI.
* CLI scripts load .env without interpolation; cloud_sync reads a BOM journal.

Pure logic: no App is instantiated, no window opens, no broker is called.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as A
import lifecycle
import trade_journal


# --------------------------------------------------------------- 1. verify


def _acct(msg, ok=False, acct="F1"):
    return {"account_id": acct, "ok": ok, "message": msg}


#: Copied from the broker modules' may-exist messages.
MAY_EXIST = [
    "Order submitted but the confirmation page didn't load — verify in "
    "Fidelity before retrying (TimeoutError)",
    "Order submitted but the confirmation page didn't load — verify in "
    "Wells Fargo before retrying (TimeoutError)",
    "Robinhood gave no response — the order may have been submitted; verify "
    "in Robinhood before retrying",
    "Schwab returned an error after the order may have been submitted — "
    "verify in Schwab before retrying: boom",
    "Schwab raised an error while the order may have been submitted — verify "
    "in Schwab before retrying: boom",
    "Fidelity trade did not finish within 30 min — some orders may have been "
    "submitted; verify in Fidelity before retrying (x)",
]

#: Plain failures: no order exists, so they belong in Retry.
NO_ORDER = [
    "Preview failed: This order cannot be placed because the security is "
    "pending a corporate action",
    "Skipped: Preview failed: ... pending a corporate action",
    "Timeout waiting for #prevdata",
    "SoFi needs you: tick 'Verify you are human' in the SoFi browser window",
    "Order rejected: order not accepted, queued orders limit",
]


@pytest.mark.parametrize("msg", MAY_EXIST)
def test_broker_may_exist_wording_is_held_back(msg):
    assert A._account_order_may_exist(_acct(msg))


@pytest.mark.parametrize("msg", NO_ORDER)
def test_plain_rejections_are_not_may_exist(msg):
    assert not A._account_order_may_exist(_acct(msg))


def test_ok_account_is_never_may_exist():
    assert not A._account_order_may_exist(_acct(MAY_EXIST[0], ok=True))


def test_rejections_go_to_retry_and_verify_rows_do_not():
    res = [{"broker": "fidelity", "accounts": [
        _acct(NO_ORDER[0], acct="F1 · Ind"),
        _acct(NO_ORDER[1], acct="F1 · Roth"),
        _acct(NO_ORDER[2], acct="F1 · Tr"),
        _acct(MAY_EXIST[0], acct="F1 · HSA"),
        _acct("order placed", ok=True, acct="F1 · Joint"),
    ]}]
    assert A.App._failed_account_plan(res) == {
        "fidelity": ["F1 · Ind", "F1 · Roth", "F1 · Tr"]}
    assert A._verify_manually_accounts(res) == {"fidelity": ["F1 · HSA"]}


def test_run_level_check_is_unchanged():
    # Auto-sell's established behaviour keeps the broad list.
    assert A._order_may_exist({"errors": ["order pending"], "accounts": []})


# ------------------------------------------------------------- 2. disputes


def _rows(broker, sym, n):
    return [{"broker": broker, "symbol": sym, "side": "buy", "qty": 1,
             "account_id": f"a{i}"} for i in range(n)]


@pytest.fixture
def journal(monkeypatch):
    rows: list = []
    monkeypatch.setattr(trade_journal, "split_adjusted", lambda *a, **k: rows)
    return rows


def _task(brokers, sym="SMTK", alert="SMTK"):
    return lifecycle.SellTask(symbol=sym, alert_symbol=alert,
                              alert_date="2026-09-02", status="exit_called",
                              brokers=tuple(brokers), accounts=3)


def test_dispute_fires_on_display_names_through_the_real_lookup(journal):
    journal += _rows("fidelity", "SMTK", 3) + _rows("wellsfargo", "SMTK", 2)
    out = A.App._journal_disputes(None, _task(("Fidelity", "Wells Fargo")),
                                  ("Fidelity", "Wells Fargo"))
    assert out == ["Fidelity (3 accounts)", "Wells Fargo (2 accounts)"]


def test_dispute_counts_the_pre_rename_ticker(journal):
    journal += _rows("robinhood", "AGAE", 1)
    out = A.App._journal_disputes(None, _task(("Robinhood",), "AIFA", "AGAE"),
                                  ("Robinhood",))
    assert out == ["Robinhood (1 account)"]


def test_no_dispute_when_the_journal_is_closed_too(journal):
    journal += _rows("fidelity", "SMTK", 1)
    journal.append({"broker": "fidelity", "symbol": "SMTK", "side": "sell",
                    "qty": 1, "account_id": "a0"})
    assert A.App._journal_disputes(None, _task(("Fidelity",)), ("Fidelity",)) == []


def test_shortfall_uses_the_leg_key(journal):
    journal += _rows("wellsfargo", "SMTK", 10)
    leg = lifecycle.BrokerLeg(broker="Wells Fargo", key="wellsfargo",
                              qty="1", accounts=7, low=1, high=1)
    resolved = lifecycle.ResolvedExit(task=_task(("Wells Fargo",)), legs=(leg,))
    out = A.App._journal_shortfalls(None, resolved)
    assert len(out) == 1 and out[0].startswith("Wells Fargo: journal says 10")


# ------------------------------------------------------- 3. journal surfacing


class _Stub:
    def __init__(self):
        self.logs, self.notes = [], []

    def _log(self, msg, tag=None):
        self.logs.append((msg, tag))

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))


def test_journal_error_is_surfaced_once(monkeypatch):
    err = {"v": None}
    monkeypatch.setattr(trade_journal, "last_error", lambda: err["v"])
    s = _Stub()
    A.App._surface_journal_error(s)
    assert s.logs == [] and s.notes == []

    err["v"] = "trades.json is corrupt (x); recovered 4 trades from trades.bak."
    for _ in range(3):
        A.App._surface_journal_error(s)
    assert len(s.logs) == 1 and s.logs[0][1] == "warn"
    assert len(s.notes) == 1 and s.notes[0][1] == "warning"

    err["v"] = "trades.json could not be opened: locked"
    A.App._surface_journal_error(s)
    A.App._surface_journal_error(s)
    assert len(s.logs) == 2 and s.logs[1][1] == "error"
    assert s.notes[1][1] == "error" and "NOT" in s.notes[1][0]


# ------------------------------------------------------------ 4. CLI + BOM


@pytest.mark.parametrize("name", ["runner.py", "reconcile.py", "publish_feed.py",
                                  "feed_archive.py", "diagnose_feed.py"])
def test_cli_loads_env_without_interpolation(name):
    src = (ROOT / name).read_text(encoding="utf-8")
    calls = [ln for ln in src.splitlines() if "load_dotenv(" in ln
             and "import" not in ln]
    assert calls and all("interpolate=False" in ln for ln in calls)


def test_cloud_sync_reads_a_bom_journal(tmp_path, monkeypatch):
    import cloud_sync
    f = tmp_path / "trades.json"
    f.write_bytes(b"\xef\xbb\xbf" + json.dumps([{"symbol": "X"}]).encode())
    monkeypatch.setattr(cloud_sync, "_TRADES_FILE", f)
    assert cloud_sync.CloudSync._load_trades() == [{"symbol": "X"}]
