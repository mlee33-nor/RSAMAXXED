"""Round-2 sell-path and bookkeeping audit fixes (fix4/sell), one block each.

  N1  may-exist holds are keyed by TICKER + brokerage, so a newer exit date
      cannot step around one; a hold at a brokerage that can leave a GTC order
      working never lapses by time -- only the journal, a live read or a human
      ends it; old play-keyed saves are folded onto the ticker
  N2  the stored board's renames survive a pull
  N3  a renamed play's remnant sale restates against the old-name buy, so no
      phantom open leg is offered for sale
  N4  (web side lives in web/tests/test_client_contract.py) the masking port
      agrees with trade_journal
  N6  account_key keeps two logins' same-numbered accounts apart
  N7  runner.py prices a sell BEFORE it goes out; qty <= 0 is refused
  N8  a play auto-sell gives up on is listed under NEEDS ATTENTION; attempt
      counts, the per-pull hold-back and that list survive a restart
  N9  the .bak write-back takes the cross-process journal lock
  +   a hand-fired sell is warned (not blocked) when the market is shut
  B   every leg is held on disk before the first sell goes out (sim: 4b)
  E/F state files read as utf-8-sig; an unreadable one is kept, copied aside,
      reported, and never saved over (atomic.load_state; sim: 9)

Pure logic against stand-ins and the conftest-redirected journal: no window,
no broker, no network, no order.
"""
from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import cloud_sync
import lifecycle
import runner
import trade_journal as tj
from modules import atomic

RH = "individual (****0042)"
WF = "WELLSTRADE (****0044)"


def _task(brokers=("Robinhood",), sym="ABC", alert=None, date="2026-10-08"):
    return lifecycle.SellTask(symbol=sym, alert_symbol=alert or sym,
                              alert_date=date, status="exit_called",
                              brokers=tuple(brokers), accounts=1)


def _board(tmp_path, rows):
    p = tmp_path / "lifecycle_state.json"
    p.write_text(json.dumps({"rows": {r["symbol"]: r for r in rows}}))
    return p


class Var:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v


# ------------------------------------------------------------- N1 holds

def test_a_newer_exit_date_cannot_step_around_a_hold():
    """r2.py: WF's sell came back may-exist on the 8th; on the 9th the same
    ticker's exit was also called at Robinhood. The new play key used to carry
    no hold, so the WF shares were offered for sale a second time."""
    tj.record_trade("wellsfargo", WF, "buy", "ABC", 1, 0.2, price_source="fill")
    tj.record_trade("robinhood", RH, "buy", "ABC", 1, 0.2, price_source="fill")
    a = types.SimpleNamespace()
    s1 = [{"symbol": "ABC", "sell_date": "2026-10-08", "posted_at": "2026-10-08T10:00",
           "exit_price": 1.5, "legs": [{"broker": "Wells Fargo"}]}]
    (t1,) = A._sellnow_tasks(s1, {})
    A._autosell_hold(a, t1, ["wellsfargo"])
    assert A._autosell_strip_held(a, t1) is None

    s2 = s1 + [{"symbol": "ABC", "sell_date": "2026-10-09", "posted_at": "2026-10-09T10:00",
                "exit_price": 1.5, "legs": [{"broker": "Robinhood"}]}]
    (t2,) = A._sellnow_tasks(s2, {})
    assert t2.alert_date != t1.alert_date
    assert A._autosell_held_brokers(a, t2) == {"wellsfargo"}
    assert A._autosell_strip_held(a, t2).brokers == ("Robinhood",)


def test_the_hand_sell_warning_follows_the_ticker_not_the_date():
    a = types.SimpleNamespace()
    A._autosell_hold(a, _task(("Wells Fargo",), date="2026-10-01"), ["wellsfargo"])
    later = _task(("Wells Fargo",), date="2026-10-09")
    leg = lifecycle.BrokerLeg(broker="Wells Fargo", key="wellsfargo", qty="1",
                              accounts=1, low=1.0, high=1.0)
    r = lifecycle.ResolvedExit(task=later, legs=(leg,), missing=(), errors=())
    (w,) = A._exit_may_exist_warnings(a, r)
    assert w.startswith("Wells Fargo:") and "may still be open" in w


def test_a_renamed_play_shares_one_hold(tmp_path, monkeypatch):
    monkeypatch.setattr(lifecycle, "STATE_FILE",
                        _board(tmp_path, [{"symbol": "AGAE", "sell_symbol": "AIFA"}]))
    a = types.SimpleNamespace()
    A._autosell_hold(a, _task(("Wells Fargo",), sym="AIFA", alert="AGAE"), ["wellsfargo"])
    # The same shares asked for under the new name alone.
    assert A._autosell_held_brokers(a, _task(("Wells Fargo",), sym="AIFA")) == {"wellsfargo"}


@pytest.mark.parametrize("broker", sorted({"wellsfargo", "fidelity"}))
def test_a_hold_that_may_be_gtc_never_lapses_by_time(broker):
    a = types.SimpleNamespace()
    old = datetime.now() - timedelta(days=40)
    A._autosell_hold(a, _task((broker,)), [broker], now=old)
    assert A._autosell_held_brokers(a, _task((broker,))) == {broker}


@pytest.mark.parametrize("broker", sorted(A.AUTOSELL_DAY_ORDER_BROKERS))
def test_a_day_order_hold_still_lapses(broker):
    a = types.SimpleNamespace()
    old = datetime.now() - timedelta(days=10)
    A._autosell_hold(a, _task((broker,)), [broker], now=old)
    assert A._autosell_held_brokers(a, _task((broker,))) == set()


def test_the_wf_tif_table_matches_the_module():
    """wellsfargo.py sends a sub-$2 sell as a Good-til-Cancel limit. If that
    ever changes, revisit AUTOSELL_DAY_ORDER_BROKERS rather than this test."""
    src = (Path(A.__file__).parent / "wellsfargo.py").read_text(encoding="utf-8")
    assert '"Good til Cancel" if order_type == "Limit"' in src
    assert "wellsfargo" not in A.AUTOSELL_DAY_ORDER_BROKERS


def test_a_closed_journal_leg_ends_the_hold():
    tj.record_trade("wellsfargo", WF, "buy", "ABC", 1, 0.2, price_source="fill")
    a = types.SimpleNamespace()
    A._autosell_hold(a, _task(("Wells Fargo",)), ["wellsfargo"])
    assert A._autosell_held_brokers(a, _task(("Wells Fargo",))) == {"wellsfargo"}
    # Resolved by hand: the journal now shows the leg sold.
    tj.record_trade("wellsfargo", WF, "sell", "ABC", 1, 1.5, price_source="fill")
    assert A._autosell_held_brokers(a, _task(("Wells Fargo",))) == set()
    assert a._autosell_may_exist == {}


def test_an_empty_journal_is_not_a_closed_leg():
    a = types.SimpleNamespace()
    A._autosell_hold(a, _task(("Wells Fargo",)), ["wellsfargo"])
    assert A._autosell_held_brokers(a, _task(("Wells Fargo",))) == {"wellsfargo"}


def test_a_live_read_that_finds_no_shares_ends_the_hold():
    a = types.SimpleNamespace(saved=0, logs=[])
    a._save_autosell_state = lambda: setattr(a, "saved", a.saved + 1)
    a._log = lambda m, *x, **k: a.logs.append(m)
    t = _task(("Wells Fargo", "Robinhood"))
    A._autosell_hold(a, t, ["wellsfargo", "robinhood"])
    # Wells Fargo read in full and empty; Robinhood could not be read.
    r = lifecycle.ResolvedExit(task=t, legs=(), missing=("Wells Fargo",),
                               errors=("Robinhood",))
    A._holds_after_read(a, t, r)
    assert A._autosell_held_brokers(a, t) == {"robinhood"}
    assert a.saved == 1 and "hold cleared" in a.logs[0]


def test_a_human_can_clear_every_hold():
    a = types.SimpleNamespace()
    A._autosell_hold(a, _task(("Wells Fargo",)), ["wellsfargo"])
    A._autosell_hold(a, _task(("Fidelity",), sym="XYZ"), ["fidelity"])
    assert A._autosell_clear_all_holds(a) == ["ABC @ wellsfargo", "XYZ @ fidelity"]
    assert a._autosell_may_exist == {}


def test_old_play_keyed_holds_fold_onto_the_ticker():
    state = {"may_exist": {"2026-10-01:IPDN": {"fidelity": "2026-10-01T10:00:00"},
                           "remnant:2026-10-03:IPDN": {"fidelity": "2026-10-03T10:00:00",
                                                       "public": "2026-10-03T10:00:00"}}}
    assert A._autosell_restore_holds(state) == {
        "IPDN": {"fidelity": "2026-10-03T10:00:00", "public": "2026-10-03T10:00:00"}}


def test_the_hold_reason_is_kept_and_listed():
    class S:
        _exit_batch_settle = A.App._exit_batch_settle
        _autosell_key = A.App._autosell_key
        _autosell_play_key = A.App._autosell_play_key

        def _autosell_retry(self, *a):
            pass

        def _save_autosell_state(self):
            pass

        def _log(self, *a, **k):
            pass

    s = S()
    msg = "Order submitted but not confirmed — verify at the broker"
    s._exit_batch_settle(
        {"exit_task": _task(("Wells Fargo",)), "autosell": True},
        [{"broker": "wellsfargo", "ok_accounts": 0, "fail_accounts": 1,
          "errors": [msg], "accounts": [{"account_id": "x", "ok": False, "message": msg}]}])
    (line,) = A._autosell_attention_lines(s)
    assert line.startswith("ABC @ wellsfargo") and "GTC" in line and "verify" in line


# ------------------------------------------------------------- N2 renames

def test_stored_renames_survive_a_pull(tmp_path, monkeypatch):
    """r3.py: after any pull, a rename older than the live board vanished."""
    monkeypatch.setattr(lifecycle, "STATE_FILE",
                        _board(tmp_path, [{"symbol": "AGAE", "sell_symbol": "AIFA"}]))
    s = types.SimpleNamespace(_track_rows=[])
    assert A.App._symbol_renames(s) == {"AIFA": "AGAE"}
    s._track_rows = [types.SimpleNamespace(symbol="XYZ", sell_symbol="XYZ")]
    assert A.App._symbol_renames(s) == {"AIFA": "AGAE"}


def test_apply_never_drops_a_row_off_the_board(tmp_path):
    p = tmp_path / "lc.json"
    row = lambda sym, new: types.SimpleNamespace(   # noqa: E731
        key=f"{sym}:1", symbol=sym, sell_symbol=new, alert_date="2026-09-01",
        status="pending", kind="", renamed=sym != new)
    state, _ = lifecycle.apply([row("AGAE", "AIFA")], {"rows": {}, "last_pull": ""})
    lifecycle.save_state(state, p)
    # A later board that no longer lists AGAE at all.
    state, _ = lifecycle.apply([row("ZZZ", "ZZZ")], lifecycle.load_state(p))
    lifecycle.save_state(state, p)
    assert lifecycle.saved_renames(p) == {"AIFA": "AGAE"}


# ------------------------------------------------------------- N3 phantom leg

def test_a_renamed_remnant_leaves_no_phantom_open_leg():
    """r1.py: buy 1 AGAE, the split leaves 0.05 sold as AIFA. Unfolded, the
    remnant met no holding, stayed 0.05, and 0.95 of a share read as open --
    auto-sell queued AIFA at Robinhood."""
    tj.record_trade("robinhood", RH, "buy", "AGAE", 1, 1.00, price_source="fill")
    tj.record_trade("robinhood", RH, "sell", "AIFA", 0.05, 10.0, price_source="fill")
    ren = {"AIFA": "AGAE"}
    assert A._leg_open_accounts("robinhood", ("AIFA", "AGAE")) == []
    sells = [{"symbol": "AIFA", "sell_date": "2026-10-09", "posted_at": "2026-10-09T10:00",
              "exit_price": 10, "legs": [{"broker": "Robinhood"}]}]
    (play,) = A._sell_plays(sells, ren)
    (leg,) = play.legs
    assert (leg.bought, leg.sold, leg.left, leg.state) == (1.0, 1.0, 0.0, A.SELL_DONE)
    assert A._sellnow_tasks(sells, ren) == []
    assert lifecycle.held_accounts(renames=ren) == {}


def test_an_unrenamed_partial_exit_is_unchanged():
    tj.record_trade("robinhood", RH, "buy", "QQQQ", 2, 1.00, price_source="fill")
    tj.record_trade("robinhood", RH, "sell", "QQQQ", 1, 2.00, price_source="fill")
    assert A._leg_open_accounts("robinhood", "QQQQ") == [(RH, 1.0)]


# ------------------------------------------------------------- N6 account_key

def test_two_logins_same_number_are_two_accounts():
    assert (tj.account_key("Public 1 BROKERAGE (0043)")
            != tj.account_key("Public 2 BROKERAGE (0043)"))
    # Login 1, numbered or bare, keys exactly as before.
    assert tj.account_key("Public 1 BROKERAGE (0043)") == "0043"
    assert tj.account_key("individual (****0042)") == "0042"
    assert tj.account_key("Robinhood 1 | individual (****0042)") == "0042"
    # The intended Fidelity relabel merge still merges.
    assert (tj.account_key("Fidelity 1 · FinTec (Z00000071)")
            == tj.account_key("Fidelity 1 · Individual (Z00000071)") == "Z00000071")
    # An account NAME ending in a digit is not a login number.
    assert tj.account_key("Fidelity 1 · Fidelity Etf 2 (Z1)") == "Z1"


@pytest.mark.parametrize("broker,label", [
    ("public", "Public 2 BROKERAGE (0043)"), ("public", "Public 1 ROTH_IRA (0043) = $5"),
    ("robinhood", "Robinhood 1 | individual (****0042)"),
    ("robinhood", "Robinhood 2 · individual (****0042)"),
    ("fidelity", "Fidelity 1 · FinTec (Z00000071)"), ("chase", "0045"),
    ("sofi", "SoFi account 1 (manual entry)"), ("schwab", "Schwab 1 (1234)"),
    ("fennel", "Fennel 1 · Account 1"), ("wellsfargo", "WELLSTRADE (****0044)")])
def test_the_cloud_sync_port_agrees_with_trade_journal(broker, label):
    assert cloud_sync._canonical_account(broker, label) == tj.canonical_account(broker, label)
    canon = tj.canonical_account(broker, label)
    assert cloud_sync._account_key(canon) == tj.account_key(canon)


def test_a_drifted_label_masks_to_one_token():
    salt = "s" * 32
    a = cloud_sync.mask_account_id("Fidelity 1 · Individual (Z00000071)", salt, "fidelity")
    b = cloud_sync.mask_account_id("Fidelity 1 · FinTec (Z00000071)", salt, "fidelity")
    assert a.rsplit("#", 1)[1] == b.rsplit("#", 1)[1]
    c = cloud_sync.mask_account_id("Robinhood 1 | individual (****0042)", salt, "robinhood")
    d = cloud_sync.mask_account_id("individual (****0042)", salt, "robinhood")
    assert c == d


# ------------------------------------------------------------- N7 runner

def _out(ok=True):
    from modules.outputs import AccountOutput, BrokerOutput
    return BrokerOutput(broker="public", state="success" if ok else "failed",
                        accounts=[AccountOutput(account_id="Public 1 BROKERAGE (0001)",
                                                ok=ok, message="ok")])


def test_a_cli_sell_is_priced_before_it_goes_out(monkeypatch):
    calls = []

    class Mod:
        def get_holdings(self):
            calls.append("read")
            from modules.outputs import AccountOutput, BrokerOutput, HoldingRow
            held = [] if "sell" in calls else [HoldingRow(symbol="AAA", shares=1, price=4.75)]
            return BrokerOutput(broker="public", state="success",
                                accounts=[AccountOutput(account_id="x", ok=True,
                                                        holdings=held)])

        def execute_trade(self, **kw):
            calls.append("sell")
            return _out()

    monkeypatch.setattr(runner, "_load_broker", lambda b: Mod())
    monkeypatch.setattr(runner, "log_event", lambda **k: None)
    monkeypatch.setattr(runner, "_print_output", lambda o: None)
    runner.cmd_trade(types.SimpleNamespace(broker="public", side="sell", symbol="aaa",
                                           qty=1, dry_run=False, yes=False))
    assert calls[:2] == ["read", "sell"]
    (row,) = tj.get_trades()
    assert row["side"] == "sell" and row["fill_price"] == 4.75


@pytest.mark.parametrize("qty", [0, -1])
def test_a_cli_trade_of_no_shares_is_refused(monkeypatch, qty):
    called = []
    monkeypatch.setattr(runner, "_load_broker", lambda b: called.append(b))
    with pytest.raises(SystemExit):
        runner.cmd_trade(types.SimpleNamespace(broker="public", side="sell", symbol="aaa",
                                               qty=qty, dry_run=False, yes=False))
    assert called == []


# ------------------------------------------------------------- N8 attention

class Retry:
    _autosell_retry = A.App._autosell_retry
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key
    _autosell_read_done = A.App._autosell_read_done
    _reading_keys = A.App._reading_keys

    def __init__(self):
        self._autosell_fails = {}
        self._autosell_sold = set()
        self.notes = []

    def _save_autosell_state(self):
        pass

    def _log(self, *a, **k):
        pass

    def _push_notification(self, msg, *a):
        self.notes.append(msg)


def test_a_play_auto_sell_gave_up_on_needs_attention():
    r = Retry()
    t = _task(("Fidelity",))
    for _ in range(A.AUTOSELL_MAX_ATTEMPTS):
        r._autosell_retry(t, "None of the requested accounts were found: ['Z1']")
    lines = A._autosell_attention_lines(r)
    assert any(l.startswith("ABC:") and "gave up" in l and "None of the requested" in l
               for l in lines)


def test_no_accounts_matched_is_nothing_sent():
    assert A._nothing_was_sent("None of the requested accounts were found: ['Z1']")


def test_counts_hold_back_and_attention_survive_a_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "AUTOSELL_STATE_FILE", tmp_path / "autosell_state.json")
    s = types.SimpleNamespace(
        _autosell_enabled=Var(True), _autosell_dry_run=Var(False),
        _autosell_fracs=Var(True), _autosell_sold=set(), _autosell_reading=set(),
        _autosell_fails={"2026-10-08:ABC": 2},
        _autosell_capped={"2026-10-08:DEF", "2026-10-08:GHI"},
        _autosell_attn={"2026-10-01:JKL": {"symbol": "JKL", "why": "gave up", "at": "x"}},
        _log=lambda *a, **k: None)
    s._reading_keys = types.MethodType(A.App._reading_keys, s)
    A.App._save_autosell_state(s)
    state = json.loads((tmp_path / "autosell_state.json").read_text())
    assert A._autosell_restore_counts(state) == {"2026-10-08:ABC": 2}
    assert set(state["held_back"]) == {"2026-10-08:DEF", "2026-10-08:GHI"}
    assert A._autosell_restore_attention(state)["2026-10-01:JKL"]["symbol"] == "JKL"
    assert A._autosell_restore_counts({"fails": {"x": "junk", "y": -1}}) == {}


# ------------------------------------------------------------- N9 .bak lock

def test_the_bak_write_back_waits_for_the_cross_process_lock(monkeypatch):
    tj.record_trade("public", "P (0001)", "buy", "AAA", 1, 1.0, price_source="fill")
    good = tj._bak_path().read_text(encoding="utf-8")
    tj._FILE.write_text("{ torn", encoding="utf-8")
    monkeypatch.setattr(tj, "_RECOVER_LOCK_SECONDS", 0.05)
    with atomic.file_lock(tj._FILE):            # another process mid-write
        rows = tj._load()
        assert len(rows) == 1
        assert tj._FILE.read_text(encoding="utf-8") == "{ torn"   # not rewritten
    tj._FILE.write_text("{ torn", encoding="utf-8")
    assert len(tj._load()) == 1
    assert json.loads(tj._FILE.read_text(encoding="utf-8")) == json.loads(good)


# ------------------------------------------------------------- market warning

def test_a_hand_sell_is_warned_when_the_market_is_shut(monkeypatch):
    monkeypatch.setattr(A.market_calendar, "now_et", lambda: datetime(2026, 10, 10, 12))
    monkeypatch.setattr(A, "_market_status", lambda: ("closed", "Markets closed", None))
    w = A._exit_market_warning()
    assert w and "not open" in w
    monkeypatch.setattr(A, "_market_status", lambda: ("open", "Markets open", None))
    assert A._exit_market_warning() is None


# ------------------------------------------------------------- state loaders

def test_a_bom_state_file_reads(tmp_path):
    p = tmp_path / "sells.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps([{"symbol": "OLDX"}]).encode())
    assert atomic.load_state(p, []) == [{"symbol": "OLDX"}]


def test_an_unreadable_state_file_is_kept_and_never_saved_over(tmp_path):
    p = tmp_path / "sells.json"
    p.write_text('[{"symbol": "OLDX"', encoding="utf-8")
    seen = []
    old_hook = atomic.on_unreadable
    atomic.on_unreadable = lambda path, msg: seen.append(msg)
    try:
        assert atomic.load_state(p, [], pause=0) == []
        assert atomic.load_state(p, [], pause=0) == []      # said once
    finally:
        atomic.on_unreadable = old_hook
    assert len(seen) == 1 and "sells.json" in seen[0]
    assert list(tmp_path.glob("sells.unreadable-*.json"))   # a copy kept aside
    with pytest.raises(atomic.StateUnreadable):
        atomic.write_json(p, [])
    assert p.read_text(encoding="utf-8") == '[{"symbol": "OLDX"'
    # Fixed by hand: the next good read lifts the block.
    p.write_text("[]", encoding="utf-8")
    assert atomic.load_state(p, None) == []
    atomic.write_json(p, [1])


def test_load_sells_refuses_to_wipe_an_unreadable_file(monkeypatch, tmp_path):
    p = tmp_path / "sells.json"
    p.write_text('[{"symbol": "OLDX"', encoding="utf-8")
    monkeypatch.setattr(A, "SELLS_FILE", p)
    assert A._load_sells() == []
    A._save_sells(A._merge_sells(A._load_sells(), [{"symbol": "NEW", "sell_date": "2026-10-09"}]))
    assert "OLDX" in p.read_text(encoding="utf-8")


def test_a_hold_is_on_disk_before_the_first_sell_goes_out():
    """BUG-B, unit level: _exit_fire holds every leg before any worker starts;
    a leg that comes back filled or positively nothing-sent releases it."""
    t = _task(("Fidelity", "Wells Fargo", "Schwab"))

    class F:
        _exit_fire = A.App._exit_fire
        _exit_batch_settle = A.App._exit_batch_settle
        _autosell_key = A.App._autosell_key
        _autosell_play_key = A.App._autosell_play_key

        def __init__(self):
            self.saved_holds = []
            self.started = []
            self._autosell_sold = set()

        def _save_autosell_state(self):
            self.saved_holds.append({k: dict(v) for k, v in
                                     A._autosell_holds(self).items()})

        def _log(self, *a, **k):
            pass

        def _push_notification(self, *a, **k):
            pass

        def _live_start(self, batch):
            pass

        def _run_in_thread(self, fn, *args):
            # The hold must already be on disk when the first worker starts.
            assert self.saved_holds and set(self.saved_holds[-1]["ABC"]) == {
                "fidelity", "wellsfargo", "schwab"}
            self.started.append(args[0])

        def _autosell_retry(self, *a):
            pass

        def _trade_worker(self, *a):
            pass

    f = F()
    legs = tuple(lifecycle.BrokerLeg(broker=b, key=lifecycle.app_key(b), qty="1",
                                     accounts=1, low=1.0, high=1.0) for b in t.brokers)
    r = lifecycle.ResolvedExit(task=t, legs=legs, missing=(), errors=())
    import unittest.mock as um
    with um.patch.object(A, "_exit_leg_plan", lambda res, autosell=False: {
            "legs": list(legs), "qty": {l.key: "1" for l in legs}, "only": {},
            "dropped": [], "refused": [], "human": [], "notes": [], "warn": []}):
        batch = f._exit_fire(r, autosell=True)
    assert len(f.started) == 3
    ok = {"broker": "schwab", "ok_accounts": 1, "fail_accounts": 0, "errors": [],
          "accounts": [{"account_id": "s", "ok": True, "message": "ok"}]}
    nothing = {"broker": "wellsfargo", "ok_accounts": 0, "fail_accounts": 1,
               "errors": ["Login failed — nothing was sent"],
               "accounts": [{"account_id": "w", "ok": False,
                             "message": "Login failed — nothing was sent"}]}
    verify = {"broker": "fidelity", "ok_accounts": 0, "fail_accounts": 1,
              "errors": ["Order submitted — verify"],
              "accounts": [{"account_id": "f", "ok": False,
                            "message": "Order submitted — verify"}]}
    f._exit_batch_settle(batch, [ok, nothing, verify])
    assert A._autosell_held_brokers(f, t) == {"fidelity"}
