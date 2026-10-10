"""fix5/sell: the last SELL/bookkeeping findings before launch.

1  plays held back by AUTOSELL_MAX_PER_PULL are listed (and releasable) after
   a restart
2  _autosell_live_holds nets the journal once, not once per hold
3  an exit pulled while sells.json is locked is never lost
4  saved_renames does not cache a failed read; one quarantine copy per content
5  Public's renumbered-login cap fallback only when every login was read
6  DAY-order holds lapse by market session, not wall clock
8  the sim restores held-back / attention state like App.__init__
9  "Clear order holds" leaves a leg in a batch still in flight alone
"""

from __future__ import annotations

import json
import os
import types
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

import app as A
import lifecycle
import public
from modules import atomic

NY = ZoneInfo("America/New_York")


class Var:
    def __init__(self, v):
        self.v = v

    def get(self):
        return self.v

    def set(self, v):
        self.v = v


def _task(brokers, sym="IPDN", date="2026-10-05"):
    return lifecycle.SellTask(symbol=sym, alert_symbol=sym, alert_date=date,
                              status="exit_called", brokers=tuple(brokers),
                              accounts=1)


def _local(et: datetime) -> datetime:
    """A New York wall time as the naive local time a hold is stamped in."""
    return et.replace(tzinfo=NY).astimezone().replace(tzinfo=None)


# ===================================================== 1. held back, restart

class _Seller:
    _autosell_clear_skipped = A.App._autosell_clear_skipped
    _autosell_key = A.App._autosell_key
    _autosell_play_key = A.App._autosell_play_key

    def __init__(self, sold=(), capped=()):
        self._autosell_sold = set(sold)
        self._autosell_capped = set(capped)
        self._autosell_fails = {}
        self.saved = 0
        self.logs = []
        self.said = []

    def _save_autosell_state(self):
        self.saved += 1

    def _log(self, msg, *a):
        self.logs.append(msg)

    def _sweep_say(self, msg, **_k):
        self.said.append(msg)


def test_held_back_plays_are_listed_in_needs_attention():
    s = _Seller(capped={"2026-10-05:AAAA", "remnant:2026-10-05:BBBB"})
    lines = A._autosell_attention_lines(s)
    assert any(l.startswith("AAAA:") and "held back" in l and "Retry skipped" in l
               for l in lines)
    assert any(l.startswith("BBBB:") and "held back" in l for l in lines)


def test_a_held_back_play_also_on_the_attention_list_is_listed_once():
    s = _Seller(capped={"2026-10-05:AAAA"})
    s._autosell_attn = {"2026-10-05:AAAA": {"symbol": "AAAA", "why": "gave up"}}
    lines = A._autosell_attention_lines(s)
    assert [l for l in lines if l.startswith("AAAA")] == ["AAAA: gave up"]


def test_retry_skipped_releases_held_back_even_with_nothing_claimed():
    """After a restart _autosell_sold can be empty while the persisted
    held-back plays still wait for exactly this click."""
    s = _Seller(sold=(), capped={"2026-10-05:AAAA", "2026-10-05:BBBB"})
    s._autosell_clear_skipped()
    assert s._autosell_capped == set()
    assert s.saved == 1
    assert s.said and "Released 2" in s.said[-1]
    assert A._autosell_attention_lines(s) == []


def test_retry_skipped_with_nothing_at_all_says_so():
    s = _Seller()
    s._autosell_clear_skipped()
    assert s.said == ["Nothing has been skipped"] and s.saved == 0


# ===================================================== 2. ledger once

def test_live_holds_nets_the_journal_once_for_every_hold(monkeypatch):
    calls = []
    monkeypatch.setattr(A, "_sell_share_ledger",
                        lambda renames=None: calls.append(1) or {})
    s = types.SimpleNamespace()
    far = (datetime.now() + timedelta(days=30)).isoformat(timespec="seconds")
    s._autosell_may_exist = {f"T{i:02d}": {"fidelity": far, "wellsfargo": far}
                             for i in range(20)}
    held = A._autosell_live_holds(s)
    assert len(held) == 20                  # nothing closed: all still held
    assert len(calls) == 1


def test_live_holds_still_releases_a_closed_leg(monkeypatch):
    monkeypatch.setattr(A, "_sell_share_ledger",
                        lambda renames=None: {("fidelity", "DONE"): [2.0, 2.0],
                                              ("fidelity", "OPEN"): [2.0, 1.0]})
    s = types.SimpleNamespace()
    far = (datetime.now() + timedelta(days=30)).isoformat(timespec="seconds")
    s._autosell_may_exist = {"DONE": {"fidelity": far}, "OPEN": {"fidelity": far}}
    assert set(A._autosell_live_holds(s)) == {"OPEN"}


# ===================================================== 3. exits never lost

class _App:
    def __init__(self):
        self.notes = []
        self.logs = []

    def after(self, _ms, fn=None, *a):
        if fn is not None:
            fn(*a)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _log(self, msg, *a):
        self.logs.append(msg)


OLD = {"source_id": "s:1", "symbol": "OLDX", "sell_date": datetime.now().strftime("%Y-%m-%d")}
NEW = {"source_id": "s:2", "symbol": "NEWX", "sell_date": datetime.now().strftime("%Y-%m-%d")}


@pytest.fixture()
def sells(monkeypatch, tmp_path):
    p = tmp_path / "sells.json"
    p.write_text(json.dumps([OLD]), encoding="utf-8")
    monkeypatch.setattr(A, "SELLS_FILE", p)
    yield p
    atomic.load_state(p, None)            # lift any block this test left


def _symbols(p):
    return {r["symbol"] for r in json.loads(p.read_text(encoding="utf-8-sig"))}


def test_a_transient_lock_at_save_is_retried_once(sells, monkeypatch):
    good = sells.read_bytes()
    real = A._load_sells
    n = [0]

    def flaky():
        n[0] += 1
        if n[0] == 1:                       # the lock: one unreadable read
            sells.write_bytes(good[:-3])
            try:
                return real()
            finally:
                sells.write_bytes(good)     # ...and it lifts
        return real()
    monkeypatch.setattr(A, "_load_sells", flaky)
    app = _App()
    assert A._keep_exits(app, [NEW]) is True
    assert _symbols(sells) == {"OLDX", "NEWX"}
    assert app.notes == [] and not getattr(app, "_pending_exits", None)


def test_a_lasting_lock_keeps_the_exit_in_memory_and_saves_it_next_pull(sells):
    good = sells.read_bytes()
    sells.write_bytes(good[:-3])
    app = _App()
    assert A._keep_exits(app, [NEW]) is False
    assert sells.read_bytes() == good[:-3]          # never written over
    assert [r["symbol"] for r in app._pending_exits] == ["NEWX"]
    assert app.notes and app.notes[-1][1] == "error" and "NEWX" in app.notes[-1][0]
    sells.write_bytes(good)                          # the lock lifted
    assert A._keep_exits(app, []) is True
    assert _symbols(sells) == {"OLDX", "NEWX"}
    assert app._pending_exits == []


class _Batch:
    def __init__(self, rows):
        self.sells = [types.SimpleNamespace(symbol=r["symbol"], proceeds_text="")
                      for r in rows]
        self.roundups = []
        self._rows = rows

    def to_json(self):
        return {"sells": list(self._rows)}


class _Feed(_App):
    _alerts_import_worker = A.App._alerts_import_worker

    def __init__(self):
        super().__init__()
        self._alerts_state = {"enabled": True, "last_id": "1", "last_sell_id": "100"}
        self.arrived = 0

    def _alerts_log_msg(self, msg):
        self.logs.append(msg)

    def _ensure_alerts_channel_id(self, role="buy", required=True):
        return ("123", None) if role == "buy" else ("456", None)

    def _import_picks_from_messages(self, msgs):
        return []

    def _sells_arrived(self, why):
        self.arrived += 1

    def _publish_feed(self, batch):
        pass


def _feed_setup(monkeypatch):
    monkeypatch.setattr(A, "_save_feed_state", lambda st: None)
    monkeypatch.setattr(A, "_env", lambda k: "x")
    monkeypatch.setattr(A, "_feed_fetch", lambda cid, *a, **k:
                        ([], None) if cid == "123" else ([{"id": "105"}], None))
    monkeypatch.setattr(A.rsa_feed, "parse_messages", lambda b, s: _Batch([NEW]))


def test_last_sell_id_waits_for_the_exit_to_be_on_disk(sells, monkeypatch):
    _feed_setup(monkeypatch)
    good = sells.read_bytes()
    sells.write_bytes(good[:-3])                     # locked for the whole pull
    f = _Feed()
    f._alerts_import_worker(True)
    assert f._alerts_state["last_sell_id"] == "100"  # not moved past it
    assert f.arrived == 0 and f.notes
    sells.write_bytes(good)
    f._alerts_import_worker(True)
    assert f._alerts_state["last_sell_id"] == "105"
    assert _symbols(sells) == {"OLDX", "NEWX"} and f.arrived == 1


# ===================================================== 4. renames / quarantine

def _board(p, renames):
    rows = {f"k{i}": {"symbol": old, "sell_symbol": new}
            for i, (new, old) in enumerate(renames.items())}
    p.write_text(json.dumps({"rows": rows, "last_pull": ""}), encoding="utf-8")


def test_saved_renames_does_not_cache_a_failed_read(tmp_path, monkeypatch):
    monkeypatch.setitem(lifecycle._renames_cache, "stamp", None)
    p = tmp_path / "lifecycle_state.json"
    _board(p, {"AIFA": "AGAE"})
    good = p.read_bytes()
    assert lifecycle.saved_renames(p) == {"AIFA": "AGAE"}
    # A transient lock: same size, new mtime, unreadable.
    p.write_bytes(b"{" + b" " * (len(good) - 1))
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    stamp = p.stat().st_mtime_ns
    assert lifecycle.saved_renames(p) == {"AIFA": "AGAE"}   # last good map, not {}
    # The lock lifts; the file's stamp is the SAME as the failed read's.
    p.write_bytes(good)
    os.utime(p, ns=(st.st_atime_ns, stamp))
    assert lifecycle.saved_renames(p) == {"AIFA": "AGAE"}
    assert not atomic.is_unreadable(p)


def test_one_quarantine_copy_per_content_and_no_restart_wording(tmp_path):
    p = tmp_path / "sells.json"
    seen = []
    old_hook = atomic.on_unreadable
    atomic.on_unreadable = lambda path, msg: seen.append(msg)
    try:
        for _ in range(3):                   # blip, lift, blip, lift ...
            p.write_text('[{"symbol": "X"', encoding="utf-8")
            assert atomic.load_state(p, None, pause=0) is None
            p.write_text("[]", encoding="utf-8")
            assert atomic.load_state(p, None) == []
        p.write_text('[{"symbol": "Y"', encoding="utf-8")   # different content
        atomic.load_state(p, None, pause=0)
        atomic.load_state(p.with_name("x"), None)            # unrelated, missing
    finally:
        atomic.on_unreadable = old_hook
        p.write_text("[]", encoding="utf-8")
        atomic.load_state(p, None)
    assert len(list(tmp_path.glob("sells.unreadable-*.json"))) == 2
    assert seen and all("restart" not in m and "this session" not in m for m in seen)
    assert "until it reads cleanly again" in seen[0]


# ===================================================== 5. Public cap fallback

class _PubClient:
    def __init__(self, positions):
        self.positions = positions
        self.orders = []

    def get_portfolio_v2(self, account_id):
        return {"positions": [{"instrument": {"symbol": s}, "quantity": q}
                              for s, q in self.positions.get(account_id, [])]}

    def place_equity_market_order(self, *, account_id, side, symbol, quantity, **_kw):
        self.orders.append((account_id, quantity))
        return f"oid-{account_id}"


def test_match_caps_without_fallback_takes_exact_labels_only():
    caps = {"Public 1 BROKERAGE (0001)": 1, "Public 2 IRA (0002)": 1}
    labels = ["Public 2 BROKERAGE (0001)", "Public 2 IRA (0002)"]
    assert public._match_caps(caps, labels, fallback=False) == {
        "Public 2 IRA (0002)": "Public 2 IRA (0002)"}
    assert public._match_caps(caps, labels)["Public 2 BROKERAGE (0001)"] == \
        "Public 1 BROKERAGE (0001)"


def test_a_down_login_1_cap_is_not_taken_by_a_login_2_lookalike(monkeypatch):
    """Login 1 (whose BROKERAGE ends 0001) is down; login 2 has an unrelated
    BROKERAGE also ending 0001. It must not inherit login 1's cap."""
    c2 = _PubClient({"B0001": [("IPDN", "5")]})
    ready = [(1, None, "token expired"),
             (2, c2, [{"accountId": "B0001", "accountType": "BROKERAGE"}])]
    monkeypatch.setattr(public.time, "sleep", lambda *_a: None)
    monkeypatch.setattr(public, "_ensure_clients", lambda: (True, "", ready))
    out = public.execute_trade(side="sell", qty="1", symbol="IPDN",
                               size_from_holdings=True,
                               max_by_account={"Public 1 BROKERAGE (0001)": "1"})
    assert c2.orders == []
    assert out.state != "success"


# ===================================================== 6. session-based lapse

def test_a_friday_evening_hold_survives_monday_and_lapses_after_its_close():
    a = types.SimpleNamespace()
    A._autosell_hold(a, _task(("Schwab",)), ["schwab"],
                     now=_local(datetime(2026, 10, 9, 17, 5)))      # Fri 17:05 ET
    for et in (datetime(2026, 10, 12, 9, 31), datetime(2026, 10, 12, 20, 0),
               datetime(2026, 10, 13, 3, 59)):
        assert A._autosell_live_holds(a, now=_local(et)) != {}, et
    assert A._autosell_live_holds(a, now=_local(datetime(2026, 10, 13, 4, 1))) == {}


def test_an_intraday_hold_lapses_after_that_days_close_and_skips_a_holiday():
    # Thanksgiving 2026-11-26 is shut; the 27th closes at 13:00.
    exp = A._hold_expires_at(_local(datetime(2026, 11, 25, 16, 30)))
    assert exp == datetime(2026, 11, 28, 1, 0, tzinfo=NY)
    exp = A._hold_expires_at(_local(datetime(2026, 10, 7, 11, 0)))     # Wed
    assert exp == datetime(2026, 10, 8, 4, 0, tzinfo=NY)


def test_an_unreadable_stamp_never_lapses():
    assert A._hold_expired("not a time", datetime.now()) is False


# ===================================================== 9. in-flight holds

def test_clear_all_holds_skips_a_leg_in_a_live_batch():
    a = types.SimpleNamespace(_autosell_reading=set(), _live_batches=[])
    far = (datetime.now() + timedelta(days=30)).isoformat(timespec="seconds")
    a._autosell_may_exist = {"IPDN": {"schwab": far, "fidelity": far},
                             "OTHR": {"fidelity": far}}
    live = _task(("Schwab",))
    a._live_batches = [{"finished": False, "exit_task": live}]
    assert A._autosell_inflight_holds(a) == ["IPDN @ schwab"]
    gone = A._autosell_clear_all_holds(a)
    assert sorted(gone) == ["IPDN @ fidelity", "OTHR @ fidelity"]
    assert a._autosell_may_exist == {"IPDN": {"schwab": far}}
    a._live_batches[0]["finished"] = True
    assert A._autosell_clear_all_holds(a) == ["IPDN @ schwab"]
    assert a._autosell_may_exist == {}


# ===================================================== 8. sim: restart

def test_sim_held_back_plays_survive_a_restart_and_sell_after_release(sim):
    from test_e2e_launch_sim_failures import (assert_no_duplicates, exit_called,
                                              held_everywhere, sells_launch,
                                              split_everywhere)
    from test_e2e_launch_sim import _idle
    brokers = ("public", "schwab")
    syms = [f"HB{c}" for c in "ABCDEF"]
    for s in syms:
        held_everywhere(sim, s, brokers=brokers)
        split_everywhere(sim, s)
        exit_called(sim, s, brokers=brokers)
    sells_launch(sim)
    sold = {sym for (_b, _a, sym, side) in _ledger_keys(sim) if side == "sell"}
    assert len(sold) == A.AUTOSELL_MAX_PER_PULL
    held = set(syms) - sold
    assert len(held) == 2

    sim.kill()
    sim.launch()
    sim.pump(lambda: _idle(sim) and not sim.app._trade_in_flight, max_fake_s=2 * 3600)
    still = {sym for (_b, _a, sym, side) in _ledger_keys(sim) if side == "sell"}
    assert still == sold                              # the cap still holds them
    lines = A._autosell_attention_lines(sim.app)
    for s in held:
        assert any(l.startswith(f"{s}:") and "held back" in l for l in lines), lines

    sim.app._autosell_clear_skipped()
    assert A._autosell_held_back(sim.app) == set()
    sim.app._autosell_consider("test")
    sim.pump(lambda: _idle(sim) and not sim.app._trade_in_flight, max_fake_s=2 * 3600)
    after = {sym for (_b, _a, sym, side) in _ledger_keys(sim) if side == "sell"}
    assert after == set(syms)
    assert_no_duplicates(sim)


def _ledger_keys(sim):
    """(broker, account, symbol, side) for every order that reached a broker."""
    return list(sim.ledger())


@pytest.fixture
def sim(monkeypatch, tmp_path):
    import sim_harness as H
    from test_e2e_launch_sim import MON
    s = H.Sim(monkeypatch, tmp_path, MON)
    yield s
    s.close()
