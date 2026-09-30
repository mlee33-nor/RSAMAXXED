"""Public exits capped at what RSAMAXXED bought, and Public's late round-up.

Three owner-approved rules, 2026-09-25:

1. A holdings-sized Public sell takes min(live balance, what the tool BOUGHT in
   that account). An account holding 101 IPDN where the tool bought 1 sells 1.
2. Eligibility and the cap come from RAW journal rows. Public can credit 0.2 of
   a share after a split and round the account up to 0.98 weeks later; once
   the 0.2 is sold the split-adjusted journal calls the account closed, and an
   exit called AT Public must still be able to take the 0.98.
3. "Nothing to sell" is an outcome, not a failure, and an account Public could
   not read hands an auto-sell back for a retry.
"""
from __future__ import annotations

import sys
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle
import public
import rsa_feed
import trade_journal
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow

L1 = "Public 1 BROKERAGE (0001)"
L2 = "Public 1 BROKERAGE (0002)"


def row(side, qty, acct=L1, sym="IPDN", broker="public"):
    return {"broker": broker, "account_id": acct, "side": side,
            "symbol": sym, "qty": qty}


@pytest.fixture()
def journal(tmp_path, monkeypatch):
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    monkeypatch.setattr(A, "PUBLIC_LATE_CHECKED_FILE", tmp_path / "late.json")

    def add(side, qty, acct=L1, sym="IPDN"):
        trade_journal.record_trade(broker="public", account_id=acct, side=side,
                                   symbol=sym, qty=qty, fill_price=1.0)
    return add


# ------------------------------------------------------------------ the caps

@pytest.mark.parametrize("rows,expected", [
    ([row("buy", 1)], {L1: 1.0}),                                   # untouched
    ([row("buy", 1), row("sell", 0.2)], {L1: 1.0}),                 # late round-up
    ([row("buy", 1), row("sell", 1)], {}),                          # fully sold
    ([row("buy", 1), row("sell", 0.2), row("sell", 0.98)], {}),     # 1 - 1.18 < 0
    ([row("buy", 1), {**row("close", 1), "side": "close"}], {}),    # marked gone
    ([row("buy", 1, broker="robinhood")], {}),                      # not Public
    ([row("buy", 1, sym="AGAE"), row("sell", 0.2, sym="AIFA")], {L1: 1.0}),
])
def test_caps_are_gross_buys_for_accounts_still_open_in_the_raw_journal(rows, expected):
    assert A._public_sell_caps(("AIFA", "AGAE", "IPDN"), rows) == expected


def test_split_adjusted_still_calls_the_late_round_up_account_closed(journal):
    """The reason the caps read RAW rows: this lens is unchanged."""
    journal("buy", 1)
    journal("sell", 0.2)
    assert A._leg_open_accounts("public", "IPDN") == []
    assert A._public_sell_caps(("IPDN",)) == {L1: 1.0}


# ---------------------------------------------------- caps -> real sell sizes

class FakeClient:
    def __init__(self, held):
        self.held = held                    # acct_id -> "qty"
        self.orders = []

    def get_portfolio_v2(self, account_id):
        q = self.held.get(account_id)
        return {"positions": [{"instrument": {"symbol": "IPDN"}, "quantity": q}]
                if q else []}

    def place_equity_market_order(self, *, account_id, symbol, quantity, **_k):
        self.orders.append((account_id, symbol, quantity))
        return "oid"


def sell_with(kwargs, held, monkeypatch):
    c = FakeClient(held)
    accts = [{"accountId": f"A000{i}", "accountType": "BROKERAGE"}
             for i in (1, 2)]
    monkeypatch.setattr(public, "_ensure_clients", lambda: (True, "", [(1, c, accts)]))
    monkeypatch.setattr(public.time, "sleep", lambda *_a: None)
    out = public.execute_trade(side="sell", qty="1", symbol="IPDN", **kwargs)
    return c.orders, out


class FireStub:
    def _push_notification(self, *a, **k):
        pass

    def _log(self, *a, **k):
        pass

    def _live_start(self, batch):
        self.batch = batch

    def _run_in_thread(self, *a):
        pass

    def _trade_worker(self, *a, **k):
        pass


def holdings_out(*accts):
    """get_holdings() shape: labels carry the ' = $value' suffix."""
    return BrokerOutput(broker="public", state="success", accounts=[
        AccountOutput(account_id=f"{lbl} = $4.00", ok=True,
                      holdings=[HoldingRow(symbol="IPDN", shares=q)] if q else [])
        for lbl, q in accts])


def task(status="exit_called", brokers=("Public",)):
    return lifecycle.SellTask(symbol="IPDN", alert_symbol="IPDN",
                              alert_date="2026-09-25", status=status,
                              brokers=brokers)


@pytest.mark.parametrize("bought,sold,held,sent", [
    (1, None, "101", "1"),          # the customer's own 100 are not ours
    (1, 0.2, "0.98", "0.98"),       # late round-up after a fractional sell
    (1, None, "0.0333", "0.0333"),  # un-rounded remnant
    (1, None, "1", "1"),            # rounded up to a whole share
])
def test_the_exit_sends_min_of_held_and_bought(journal, monkeypatch, bought, sold, held, sent):
    journal("buy", bought)
    if sold:
        journal("sell", sold)
    resolved = lifecycle.resolve(task(), {"public": holdings_out((L1, float(held)))})
    s = FireStub()
    A.App._exit_fire(s, resolved)
    orders, _ = sell_with(s.batch["broker_kwargs"]["public"], {"A0001": held},
                          monkeypatch)
    assert orders == [("A0001", "IPDN", sent)]


def test_an_account_absent_from_the_journal_is_never_sold(journal, monkeypatch):
    journal("buy", 1, acct=L1)
    resolved = lifecycle.resolve(task(), {"public": holdings_out((L1, 1.0), (L2, 7.0))})
    s = FireStub()
    A.App._exit_fire(s, resolved)
    orders, out = sell_with(s.batch["broker_kwargs"]["public"],
                            {"A0001": "1", "A0002": "7"}, monkeypatch)
    assert orders == [("A0001", "IPDN", "1")]
    assert "not bought through RSAMAXXED" in out.message


# ----------------------------------------------------------- the dialog line

def test_the_dialog_describes_each_account_capped_not_one_quantity():
    holdings = tuple((f"Public 1 BROKERAGE ({i:04d})", 0.03333) for i in range(21))
    caps = {lbl: 1.0 for lbl, _q in holdings}
    text = A._public_plan_text(A._public_sell_plan(holdings, caps))
    assert text == ("sells what each account holds, up to what RSAMAXXED "
                    "bought there — 21 accounts, 0.0333 each")
    assert "left behind" not in text


def test_the_dialog_shows_a_range_and_the_accounts_that_are_not_ours():
    holdings = ((L1, 101.0), (L2, 0.98), ("Public 2 BROKERAGE (0003)", 5.0))
    text = A._public_plan_text(A._public_sell_plan(holdings, {L1: 1.0, L2: 1.0}))
    assert "2 accounts, 0.98–1 each" in text
    assert "1 account not bought through RSAMAXXED, skipped" in text


def test_the_dialog_strips_the_value_suffix_when_matching_caps():
    plan = A._public_sell_plan(((f"{L1} = $3.20", 0.5),), {L1: 1.0})
    assert plan["sell"] == [(f"{L1} = $3.20", 0.5)]


def test_resolve_carries_each_accounts_balance_without_the_suffix():
    resolved = lifecycle.resolve(task(), {"public": holdings_out((L1, 0.5), (L2, 0.98))})
    assert resolved.legs[0].holdings == ((L1, 0.5), (L2, 0.98))


# ------------------------------------------------- late round-up on the board

def exit_at(broker="Public", day="2026-09-25"):
    return [{"symbol": "IPDN", "sell_date": day, "posted_at": f"{day}T14:00:00",
             "exit_price": 4.0, "legs": [{"broker": broker}]}]


def public_leg(plays):
    (p,) = plays
    return next(l for l in p.legs if l.broker == "public")


def test_a_fraction_sold_then_an_exit_at_public_offers_the_leg_again(journal):
    journal("buy", 1)
    journal("sell", 0.2)
    assert public_leg(A._sell_plays(exit_at())).state == A.SELL_NOW
    (t,) = A._sellnow_tasks(exit_at())
    assert t.brokers == ("Public",) and t.accounts == 1


def test_without_an_exit_at_public_the_leg_stays_done(journal):
    journal("buy", 1)
    journal("sell", 0.2)
    assert public_leg(A._sell_plays(exit_at("Robinhood"))).state == A.SELL_DONE


def test_fully_sold_stays_done_even_with_an_exit_at_public(journal):
    journal("buy", 1)
    journal("sell", 1)
    assert public_leg(A._sell_plays(exit_at())).state == A.SELL_DONE


class ResolveStub:
    def after(self, _ms, fn=None, *a):
        if callable(fn):
            fn(*a)

    def _log(self, *a, **k):
        pass


def test_nothing_held_at_the_read_settles_it_with_no_dispute(journal, monkeypatch):
    journal("buy", 1)
    journal("sell", 0.2)
    (t,) = A._sellnow_tasks(exit_at())
    monkeypatch.setattr(A, "_load_broker", lambda k: types.SimpleNamespace(
        get_holdings=lambda: holdings_out((L1, 0))))
    seen = []
    A.App._exit_resolve_worker(ResolveStub(), t, then=seen.append)
    (resolved,) = seen
    assert not resolved.ok and resolved.missing == ("Public",)
    # The journal agrees it is closed, so this is an answer, not a dispute.
    assert A.App._journal_disputes(None, t, resolved.missing) == []
    # And the board stops offering it.
    assert public_leg(A._sell_plays(exit_at())).state == A.SELL_DONE
    assert A._sellnow_tasks(exit_at()) == []


def test_a_newer_exit_at_public_reopens_a_settled_leg(journal):
    journal("buy", 1)
    journal("sell", 0.2)
    A._mark_public_late_checked(("IPDN",), day="2026-09-25")
    assert public_leg(A._sell_plays(exit_at(day="2026-09-25"))).state == A.SELL_DONE
    assert public_leg(A._sell_plays(exit_at(day="2026-10-02"))).state == A.SELL_NOW


def test_a_late_round_up_exit_sells_the_098(journal, monkeypatch):
    journal("buy", 1)
    journal("sell", 0.2)
    (t,) = A._sellnow_tasks(exit_at())
    resolved = lifecycle.resolve(t, {"public": holdings_out((L1, 0.98))})
    s = FireStub()
    A.App._exit_fire(s, resolved)
    orders, _ = sell_with(s.batch["broker_kwargs"]["public"], {"A0001": "0.98"},
                          monkeypatch)
    assert orders == [("A0001", "IPDN", "0.98")]


# ---------------------------------------- TRACK fractionals are not the flag's

def test_a_track_fractional_play_still_queues_public_with_the_flag_off(journal, monkeypatch):
    monkeypatch.setattr(A, "PUBLIC_REMNANT_CLEAR", False)
    journal("buy", 1)
    stub = types.SimpleNamespace(
        _track_rows=[rsa_feed.LifecycleRow(symbol="IPDN", sell_symbol="IPDN",
                                           alert_date="2026-09-20",
                                           status="fractional")],
        _autosell_worklist=lambda: [],
        _symbol_renames=lambda: {})
    (t,) = A.App._fractional_worklist(stub, exits=[])
    assert "Public" in t.brokers and t.is_fractional
    resolved = lifecycle.resolve(t, {"public": holdings_out((L1, 0.0333))})
    s = FireStub()
    A.App._exit_fire(s, resolved)
    kw = s.batch["broker_kwargs"]["public"]
    assert kw["size_from_holdings"] is True
    assert kw["max_by_account"] == {L1: "1"}


# ------------------------------------------------- nothing to sell is neutral

def test_skip_notes_read_as_english():
    assert A._skip_note({"whole": 21}) == \
        "21 skipped (21 whole shares wait for their own exit)"
    assert A._skip_note({"whole": 1, "none": 2}) == \
        "3 skipped (1 whole share waits for its own exit, 2 hold none)"


class Finish:
    """Just enough App for _trade_broker_complete / _trade_batch_finish."""

    def __init__(self):
        self._brokers_in_flight = set()
        self._live_batches = []
        self._trade_in_flight = True
        self._active_nav = "trade"
        self.logs, self.notes, self.receipt = [], [], None
        self.retried = []

    _release_broker = A.App._release_broker
    _trade_batch_finish = A.App._trade_batch_finish
    _trade_broker_complete = A.App._trade_broker_complete
    _exit_batch_settle = A.App._exit_batch_settle

    def _log(self, msg, tag=None):
        self.logs.append((msg, tag))

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _render_done_receipt(self, **kw):
        self.receipt = kw

    def _autosell_retry(self, task, why):
        self.retried.append(why)

    def after(self, *_a, **_k):
        pass

    def __getattr__(self, name):          # every other UI hook is a no-op
        # Widgets probed with hasattr() must read as absent, not as a no-op.
        if name.startswith("_") and not name.endswith(("_btn", "_card")):
            return lambda *a, **k: None
        raise AttributeError(name)


def batch_of(summary, **extra):
    b = {"pending": {"public"}, "all_brokers": ["public"], "results": [],
         "side": "sell", "symbol": "IPDN", "qty": "1", "dry_run": False,
         "origin": "exit", "finished": False, "started": datetime.now()}
    b.update(extra)
    return b


def summary(**kw):
    s = {"broker": "public", "ok_accounts": 0, "fail_accounts": 0, "shares": 0.0,
         "errors": [], "state": "success", "accounts": [], "fill_price": None,
         "skipped": {}}
    s.update(kw)
    return s


def test_every_account_skipped_reads_as_nothing_to_sell_not_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "PUBLIC_LATE_CHECKED_FILE", tmp_path / "late.json")
    f = Finish()
    b = batch_of(None, exit_task=task(), autosell=True)
    f._trade_broker_complete(b, summary(skipped={"whole": 21}))
    assert ("–  Public: nothing to sell — 21 skipped (21 whole shares wait "
            "for their own exit)", "meta") in f.logs
    assert f.receipt["kind"] == "none"
    assert not any(k == "error" for _m, k in f.notes)
    assert not any("failed" in m for m, _t in f.logs)
    assert f.retried == []


def test_a_real_failure_is_still_a_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "PUBLIC_LATE_CHECKED_FILE", tmp_path / "late.json")
    f = Finish()
    f._trade_broker_complete(batch_of(None), summary(
        fail_accounts=1, errors=["x: rejected"], state="failed"))
    assert f.receipt["kind"] == "fail"


def test_an_unreadable_public_account_hands_the_autosell_back(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "PUBLIC_LATE_CHECKED_FILE", tmp_path / "late.json")
    f = Finish()
    b = batch_of(None, exit_task=task(), autosell=True)
    f._trade_broker_complete(b, summary(
        ok_accounts=1, fail_accounts=1, state="partial",
        errors=[f"{L2}: Could not read the position before selling: 503"],
        accounts=[{"account_id": L1, "ok": True, "message": "order placed"},
                  {"account_id": L2, "ok": False,
                   "message": "Could not read the position before selling: 503"}]))
    assert f.retried == ["Public couldn't read 1 account before selling"]
    # A failed leg does not settle a late round-up: it has not had its look.
    assert not (tmp_path / "late.json").exists()


def test_a_manual_exit_is_not_retried_automatically(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "PUBLIC_LATE_CHECKED_FILE", tmp_path / "late.json")
    f = Finish()
    b = batch_of(None, exit_task=task(), autosell=False)
    f._trade_broker_complete(b, summary(
        fail_accounts=1, state="failed",
        errors=["Could not read the position before selling: 503"],
        accounts=[{"account_id": L1, "ok": False,
                   "message": "Could not read the position before selling: 503"}]))
    assert f.retried == []


def test_the_retry_skips_accounts_that_already_sold(journal, monkeypatch):
    """Account 1 sold its 0.0333 before account 2's read failed. On the retry
    account 1 reads empty and is skipped; only account 2 sells."""
    journal("buy", 1, acct=L1)
    journal("buy", 1, acct=L2)
    journal("sell", 0.0333, acct=L1)
    resolved = lifecycle.resolve(task(), {"public": holdings_out((L1, 0), (L2, 0.0333))})
    s = FireStub()
    A.App._exit_fire(s, resolved)
    orders, out = sell_with(s.batch["broker_kwargs"]["public"],
                            {"A0002": "0.0333"}, monkeypatch)
    assert orders == [("A0002", "IPDN", "0.0333")]
    assert "holds none" in out.message
