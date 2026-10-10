"""Journal / P/L audit fixes (fix2/journal).

  1  reconcile --apply never closes a position in an account it could not
     read (a partial read's ok=False accounts), and finds renamed tickers.
  3  the trade worker journals each fill BEFORE the slow quote lookup, so a
     crash or hang there costs a price, never a fill.
  4  unpriced rows move positions, never the money -- reconcile and
     unaccounted() included; the Command Center counts them.
  5  per-account netting keys on the account NUMBER, not the drifting label.
  6  a cross-process lock around every journal read-modify-write.
  7  renamed tickers fold onto one name before P/L is aggregated.
  8  backfill_basis no longer re-sorts the journal; the Analytics period
     filters compare local time; runner.py journals like the app worker.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import app as A
import backfill_basis
import etf_journal
import reconcile
import runner
import trade_journal
from modules import atomic
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow


def _r(i, side, sym, qty, price, broker="public", acct="Public 1 BROKERAGE (0001)"):
    return {"id": f"r{i}", "timestamp": f"2026-07-{i:02d}T14:00:00+00:00",
            "broker": broker, "account_id": acct, "side": side,
            "symbol": sym, "qty": qty, "fill_price": price}


@pytest.fixture()
def journal(tmp_path, monkeypatch):
    p = tmp_path / "trades.json"
    monkeypatch.setattr(trade_journal, "_FILE", p)
    trade_journal._cache.clear()

    def write(rows):
        p.write_text(json.dumps(rows), encoding="utf-8")
        trade_journal._cache.clear()
    yield write
    trade_journal._cache.clear()


# --------------------------------------------------------------- 6: the lock

def test_file_lock_excludes_another_process(tmp_path):
    target = tmp_path / "trades.json"
    holder = subprocess.Popen(
        [sys.executable, "-c", textwrap.dedent(f"""
            import sys, time
            sys.path.insert(0, {str(ROOT)!r})
            from modules import atomic
            with atomic.file_lock({str(target)!r}):
                print("held", flush=True)
                time.sleep(3)
        """)], stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        with pytest.raises(atomic.LockTimeout):
            with atomic.file_lock(target, timeout=0.3):
                pass
    finally:
        holder.wait(timeout=10)
    # Released when the holder exits, and never left behind by a crash.
    with atomic.file_lock(target, timeout=2):
        pass


def test_two_processes_recording_at_once_lose_no_rows(tmp_path):
    target = tmp_path / "trades.json"
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        from pathlib import Path
        import trade_journal
        trade_journal._FILE = Path({str(target)!r})
        for i in range(25):
            trade_journal.record_trade("public", "a", "buy", "X" + sys.argv[1], 1)
    """)
    procs = [subprocess.Popen([sys.executable, "-c", script, str(n)])
             for n in range(2)]
    for p in procs:
        assert p.wait(timeout=120) == 0
    rows = json.loads(target.read_text(encoding="utf-8"))
    assert len(rows) == 50


# ------------------------------------------------------ 3: price after fills

def test_set_fill_prices_touches_only_the_named_rows(journal):
    journal([])
    a = trade_journal.record_trade("public", "a", "buy", "AAA", 1)
    b = trade_journal.record_trade("public", "b", "buy", "AAA", 1)
    assert trade_journal.set_fill_prices([a["id"]], 1.25) == 1
    got = {t["id"]: t["fill_price"] for t in trade_journal.get_trades()}
    assert got == {a["id"]: 1.25, b["id"]: None}
    assert trade_journal.set_fill_prices([b["id"]], None) == 0


class _Stub:
    def __init__(self, quote):
        self.quote = quote
        self.logs = []
        self.completed = []
        self._quick_picks = []
        self.seen_at_quote = None

    def after(self, _ms, func=None, *args):
        if callable(func):
            func(*args)

    def _log(self, msg, tag=None):
        self.logs.append(msg)

    def _trade_result_write(self, text, tag=None):
        self.logs.append(text)

    def _render_quick_picks(self, picks):
        pass

    def _trade_broker_complete(self, batch, summary):
        self.completed.append(summary)

    def _push_notification(self, *a, **k):
        pass

    def _fetch_quote_price(self, broker, symbol, side="buy"):
        # What is already on disk at the moment the slow lookup starts.
        self.seen_at_quote = list(trade_journal.get_trades())
        if isinstance(self.quote, BaseException):
            raise self.quote
        return self.quote


@pytest.fixture()
def worker(tmp_path, monkeypatch, journal):
    journal([])
    monkeypatch.setattr(etf_journal, "ETF_FILE", tmp_path / "etf_trades.json")
    fake = types.SimpleNamespace(execute_trade=lambda **kw: BrokerOutput(
        broker="public", state="success", accounts=[
            AccountOutput(account_id="p1", ok=True, message="filled", order_id="o1"),
            AccountOutput(account_id="p2", ok=True, message="filled", order_id="o2"),
        ]))
    monkeypatch.setattr(A, "_load_broker", lambda b: fake)
    monkeypatch.setattr(A, "_browser_slot", lambda b: None)
    monkeypatch.setattr(A, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr(A, "log_event", lambda *a, **k: None)


def test_fills_are_on_disk_before_the_quote_lookup_runs(worker):
    stub = _Stub(quote=0.42)
    A.App._trade_worker(stub, "public", "buy", "AAA", "1", False,
                        {"origin": "desk", "pending": {"public"}})
    assert [t["order_id"] for t in stub.seen_at_quote] == ["o1", "o2"]
    assert all(t["fill_price"] is None for t in stub.seen_at_quote)
    # ...and the quote is then backfilled onto exactly those rows.
    assert [t["fill_price"] for t in trade_journal.get_trades()] == [0.42, 0.42]


def test_a_quote_lookup_that_blows_up_costs_the_price_not_the_fills(worker):
    stub = _Stub(quote=RuntimeError("browser session died"))
    A.App._trade_worker(stub, "public", "buy", "AAA", "1", False,
                        {"origin": "desk", "pending": {"public"}})
    rows = trade_journal.get_trades()
    assert [t["order_id"] for t in rows] == ["o1", "o2"]
    assert all(t["fill_price"] is None for t in rows)
    assert stub.completed and stub.completed[0]["ok_accounts"] == 2


def test_etf_rows_are_backfilled_in_their_own_journal(worker):
    stub = _Stub(quote=500.0)
    A.App._trade_worker(stub, "public", "buy", "SPY", "1", False,
                        {"origin": "etf", "pending": {"public"}})
    assert [t["fill_price"] for t in etf_journal.get_trades()] == [500.0, 500.0]
    assert trade_journal.get_trades() == []


# -------------------------------------------- 5: account number, not label

def test_account_key_survives_label_drift_but_not_fake_numbers():
    k = trade_journal.account_key
    assert k("Fidelity 1 · Individual (Z1234)") == k("Fidelity 1 · FinTec (Z1234)")
    assert k("Public 1 ROTH_IRA (0003) = $61.32") == k("Public 1 ROTH_IRA (0003)")
    # Four different SoFi accounts all end '(manual entry)'.
    assert k("SoFi account 1 (manual entry)") != k("SoFi account 2 (manual entry)")


def test_split_remnant_sold_under_a_drifted_label_is_still_restated():
    rows = [_r(1, "buy", "GRNQ", 1, 1.30, "fidelity", "Fidelity 1 · Individual (Z1)"),
            _r(2, "sell", "GRNQ", 0.1, 10.0, "fidelity", "Fidelity 1 · FinTec (Z1)")]
    sell = trade_journal.split_adjusted(rows)[1]
    assert sell["qty"] == 1.0 and sell["fill_price"] == pytest.approx(1.0)
    assert sell["account_id"] == "Fidelity 1 · FinTec (Z1)"     # label untouched


# ------------------------------------------------------------ 4: unpriced

def test_unaccounted_and_portfolio_average_over_priced_buys(journal):
    journal([_r(1, "buy", "AAA", 1, 2.0), _r(2, "buy", "AAA", 1, None),
             {**_r(3, "close", "AAA", 1, None), "close_reason": "reconciled"}])
    assert trade_journal.unaccounted()["total"] == pytest.approx(2.0)
    pos = trade_journal.get_portfolio()[("public", "AAA")]
    assert pos["avg_cost"] == pytest.approx(2.0)
    assert pos["qty"] == pytest.approx(1.0)


def test_command_center_counts_what_it_leaves_out(journal):
    journal([_r(1, "buy", "AAA", 2, 1.0), _r(2, "buy", "AAA", 1, None),
             _r(3, "sell", "AAA", 1, None), _r(4, "sell", "AAA", 1, 2.0)])
    s = A.App._portfolio_summary(None)
    assert s["realized"] == pytest.approx(1.0)
    assert (s["unpriced_buys"], s["unpriced_sells"]) == (1, 1)


# ------------------------------------------------------------ 7: renames

def test_renamed_ticker_folds_into_one_play(journal, monkeypatch):
    journal([_r(1, "buy", "AGAE", 1, 1.0), _r(2, "sell", "AIFA", 1, 3.0)])
    # No board in memory and none saved: nothing knows the two names are one.
    monkeypatch.setattr(A.lifecycle, "saved_renames", lambda path=None: {})
    bare = A.App._portfolio_summary(None)
    assert bare["realized"] == 0.0 and bare["open_count"] == 1      # the bug
    # Before the first pull of the session the saved board supplies the map.
    monkeypatch.setattr(A.lifecycle, "saved_renames",
                        lambda path=None: {"AIFA": "AGAE"})
    saved = A.App._portfolio_summary(None)
    assert saved["realized"] == pytest.approx(2.0) and saved["open_count"] == 0
    board = types.SimpleNamespace(
        _track_rows=[types.SimpleNamespace(symbol="AGAE", sell_symbol="AIFA")])
    s = A.App._portfolio_summary(board)
    assert s["realized"] == pytest.approx(2.0)
    assert s["open_count"] == 0 and s["deployed"] == 0.0


def test_fold_renames_keeps_the_traded_ticker():
    out = trade_journal.fold_renames([_r(1, "sell", "AIFA", 1, 3.0)], {"AIFA": "AGAE"})
    assert out[0]["symbol"] == "AGAE" and out[0]["executed_symbol"] == "AIFA"


# ------------------------------------------------------------ 1: reconcile

def _holdings(accounts, state="partial"):
    return types.SimpleNamespace(get_holdings=lambda: BrokerOutput(
        broker="public", state=state, accounts=accounts))


def test_reconcile_leaves_unread_accounts_alone(journal, monkeypatch, capsys):
    journal([_r(1, "buy", "AAA", 1, 1.0, acct="Public 1 BROKERAGE (0001)"),
             _r(2, "buy", "BBB", 1, 1.0, acct="Public 1 ROTH_IRA (0002)")])
    monkeypatch.setitem(sys.modules, "public", _holdings([
        AccountOutput(account_id="Public 1 BROKERAGE (0001) = $5.00", ok=True,
                      holdings=[HoldingRow(symbol="AAA", shares=1)]),
        # Could not be read this time: no holdings listed, and ok=False.
        AccountOutput(account_id="Public 1 ROTH_IRA (0002)", ok=False,
                      message="timeout"),
    ]))
    monkeypatch.setattr(reconcile, "_renames", lambda: {})
    assert reconcile.main(["--broker", "public", "--apply"]) == 0
    assert not [t for t in trade_journal.get_trades() if t["side"] == "close"]


def test_reconcile_finds_a_position_under_its_new_ticker(journal, monkeypatch):
    journal([_r(1, "buy", "AGAE", 1, 1.0), _r(2, "buy", "GONE", 1, 1.0)])
    monkeypatch.setitem(sys.modules, "public", _holdings([
        AccountOutput(account_id="Public 1 BROKERAGE (0001)", ok=True,
                      holdings=[HoldingRow(symbol="AIFA", shares=1)])], "success"))
    monkeypatch.setattr(reconcile, "_renames", lambda: {"AIFA": "AGAE"})
    reconcile.main(["--broker", "public", "--apply"])
    closes = [t["symbol"] for t in trade_journal.get_trades() if t["side"] == "close"]
    assert closes == ["GONE"]


def test_reconcile_nets_per_account_number(journal, monkeypatch):
    # Bought under one label, sold under the drifted one: nothing is open.
    journal([_r(1, "buy", "AAA", 1, 1.0, "fidelity", "Fidelity 1 · Individual (Z1)"),
             _r(2, "sell", "AAA", 1, 2.0, "fidelity", "Fidelity 1 · FinTec (Z1)")])
    assert reconcile._open_positions() == {}


# ------------------------------------------------------------ 8: the rest

def test_backfill_inserts_buys_without_reordering_the_journal():
    trades = [_r(5, "buy", "X", 1, 1.0), _r(9, "sell", "TOPT", 1, 3.0),
              # an after-the-fact correction, deliberately appended last
              {**_r(2, "sell", "X", 1, 2.0), "id": "late"}]
    made = [{**_r(8, "buy", "TOPT", 1, 1.0), "id": "made"}]
    backfill_basis._insert_buys(trades, made, "TOPT")
    assert [t["id"] for t in trades] == ["r5", "made", "r9", "late"]


def test_period_filters_compare_local_time():
    utc = datetime(2026, 1, 1, 3, 0, tzinfo=timezone.utc)
    local = A.App._local_ts(utc.isoformat())
    assert local == utc.astimezone().replace(tzinfo=None).isoformat()
    assert A.App._local_ts("garbage") == "garbage"


def test_runner_journals_every_filled_account_and_keeps_going(journal, monkeypatch):
    journal([])
    out = BrokerOutput(broker="public", state="failed", accounts=[
        AccountOutput(account_id="a", ok=True, order_id="o1"),
        AccountOutput(account_id="b", ok=False, message="rejected"),
        AccountOutput(account_id="c", ok=True, order_id="o3"),
    ])
    real = trade_journal.record_trade

    def flaky(**kw):
        if kw["account_id"] == "a":
            raise OSError("disk hiccup")
        return real(**kw)
    monkeypatch.setattr(trade_journal, "record_trade", flaky)
    ids, failed = runner.journal_fills("public", "buy", "AAA", 1.0, out)
    rows = trade_journal.get_trades()
    assert [t["account_id"] for t in rows] == ["c"]
    assert rows[0]["order_id"] == "o3"
    assert rows[0]["price_source"] == trade_journal.PRICE_QUOTE
    assert len(ids) == 1 and len(failed) == 1 and "o1" in failed[0]


def test_runner_refuses_a_large_quantity_without_yes(monkeypatch):
    called = []
    monkeypatch.setattr(runner, "_load_broker", lambda b: called.append(b))
    args = types.SimpleNamespace(broker="public", side="buy", symbol="aaa",
                                 qty=10, dry_run=False, yes=False)
    with pytest.raises(SystemExit):
        runner.cmd_trade(args)
    assert called == []
