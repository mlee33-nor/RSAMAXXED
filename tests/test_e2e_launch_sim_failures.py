"""End-to-end launch simulation, part 2: restarts, broker failure modes,
failed holdings reads, renames. See test_e2e_launch_sim for the setup."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

import pytest

import sim_harness as H
from sim_harness import A, ALL_BROKERS
from test_e2e_launch_sim import (FRI, MON_D, _idle, assert_no_wedge, boot,  # noqa: F401
                                 sim, standard_feed)


# ================================================================== helpers

def held_everywhere(sim, sym, day=FRI, price=0.25, brokers=ALL_BROKERS):
    """SYM bought through this tool at every account, on `day`."""
    for b in brokers:
        sim.seed_buy(b, sym, f"{day}T10:00:00", price=price)


def split_everywhere(sim, sym, ratio=20, fractions=(), rename=None, new_price=5.0):
    for b in ALL_BROKERS:
        sim.brokers[b].split(sym, ratio, roundup=True, rename=rename,
                             fraction_accounts=set(fractions))
    sim.market.set(rename or sym, new_price)


def exit_called(sim, sym, price=5.0, brokers=ALL_BROKERS, day=MON_D):
    sim.feed.exit(sym, price, {H.LOGIN_LABEL[b]: len(sim.brokers[b].accounts())
                               for b in brokers}, day)


def sells_launch(sim, start=datetime(2026, 10, 5, 10, 0, 0), max_fake_s=4 * 3600):
    """Launch with auto-sell on (live) and mirror off; run until idle."""
    sim.clock.set_et(start)
    sim.seed_mirror(enabled=False)
    sim.seed_autosell(enabled=True, dry_run=False)
    sim.launch()
    sim.pump(lambda: _idle(sim) and not sim.app._trade_in_flight, max_fake_s=max_fake_s)
    return sim.app


def assert_no_duplicates(sim):
    dup = {k: v for k, v in sim.ledger().items() if v > 1}
    assert dup == {}, f"orders reached a broker more than once: {dup}"


def run_for(sim, seconds):
    sim.settle(max_fake_s=seconds)


# ===================================================== 4. kill / restart

def _mirror_batch(sim):
    return next((b for b in sim.app._mirror_active if not b.get("finished")), None)


BUG_REPAIR_RELEASES = (
    "BUG: app.App._repair_mirror_executed releases an executed pick whose run is "
    "missing from mirror_runs.json whenever the journal does not show it bought at "
    "EVERY broker. mirror_runs.json is written by a background thread that retries "
    "on WinError 5 (Drive/AV lock) and loses the queued write on a kill, so after "
    "the restart the pick is re-launched to the brokers that never reported -- "
    "Fidelity's orders had reached the broker: duplicate buy")


@pytest.mark.parametrize("runs_write", [
    "lands",
    "locked",       # was BUG_REPAIR_RELEASES; fixed by the launch marker (fix4)
])
def test_4a_kill_mid_buy_batch_resends_nothing_that_may_exist(sim, runs_write, monkeypatch):
    """runs_write="locked": mirror_runs.json could not be replaced (the WinError 5
    a sync client causes, see modules/atomic) for as long as the first process
    lived, so the run it opened never reached disk before the kill."""
    sim.feed.alert("KIL", FRI, "standard")
    sim.market.set("KIL", 0.25)
    sim.seed_mirror()
    if runs_write == "locked":
        def _locked(*_a, **_k):
            raise PermissionError(5, "Access is denied (held by sync client)")
        monkeypatch.setattr(A.mirror_journal, "atomic", H.types.SimpleNamespace(replace=_locked))
    sim.brokers["fidelity"].set_mode("hang_after", side="buy")     # at the broker, unreported
    sim.brokers["wellsfargo"].set_mode("hang_before", side="buy")  # never sent
    sim.launch()
    sim.pump(lambda: _mirror_batch(sim) is not None
             and _mirror_batch(sim)["pending"] == {"fidelity", "wellsfargo"},
             max_fake_s=600)
    before = sim.ledger(side="buy")
    assert {k[0] for k in before} == set(ALL_BROKERS) - {"wellsfargo"}

    sim.kill(flush_runs=runs_write == "lands")
    if runs_write == "locked":
        monkeypatch.setattr(A.mirror_journal, "atomic", H.atomic)   # lock gone after restart
    for b in ("fidelity", "wellsfargo"):
        sim.brokers[b].modes.clear()
    sim.clock.advance(60)
    sim.launch()
    run_for(sim, 2 * 3600)

    assert_no_duplicates(sim)
    for k in before:                                   # nothing that reached was re-sent
        assert sim.ledger(side="buy")[k] == 1
    # The leg that never went out: completed, or on NEEDS ATTENTION.
    wf_done = all(sim.ledger(side="buy").get(k) == 1
                  for k in sim.every_account("KIL", brokers=("wellsfargo",)))
    attention = [r for r in sim.app._mirror_needs_attention(A.mirror_journal.runs(), [])
                 if r.get("symbol") == "KIL"]
    assert wf_done or attention, "Wells Fargo never sent and nothing says so"
    assert sim.idle_ok() == []


def test_4b_kill_mid_sell_batch_resends_nothing_that_may_exist(sim):
    held_everywhere(sim, "KSL")
    split_everywhere(sim, "KSL")
    exit_called(sim, "KSL")
    fid = sim.brokers["fidelity"]
    fid.set_mode("hang_after", side="sell")
    fid.working_orders_hold_shares = True       # the order is in, not yet filled
    sim.brokers["wellsfargo"].set_mode("hang_before", side="sell")
    sim.clock.set_et(datetime(2026, 10, 5, 10, 0, 0))
    sim.seed_mirror(enabled=False)
    sim.seed_autosell(enabled=True, dry_run=False)
    sim.launch()
    sim.pump(lambda: getattr(sim.app, "_trade_batch", None) is not None
             and sim.app._trade_batch.get("pending") == {"fidelity", "wellsfargo"},
             max_fake_s=1800)
    reached = sim.ledger(side="sell")
    assert {k[0] for k in reached} == set(ALL_BROKERS) - {"wellsfargo"}

    sim.kill()
    for b in ("fidelity", "wellsfargo"):
        sim.brokers[b].modes.clear()
    sim.clock.advance(60)
    sim.launch()
    run_for(sim, 3 * 3600)

    # FIXED (fix4/sell, was BUG-B): _exit_fire holds every leg on disk before
    # the first order, so the relaunch cannot re-sell Fidelity behind its
    # working order. Wells Fargo hung INSIDE execute_trade too, and from the
    # app's side "hung before sending" and "hung after sending" are the same
    # thing -- so it is not re-sent blind either: once each, or still held and
    # on NEEDS ATTENTION for a human to check at the broker.
    assert_no_duplicates(sim)
    fid = sim.every_account("KSL", side="sell", brokers=("fidelity",))
    assert all(sim.ledger(side="sell").get(k) == 1 for k in fid)
    lines = A._autosell_attention_lines(sim.app)
    wf = sim.every_account("KSL", side="sell", brokers=("wellsfargo",))
    wf_sold = all(sim.ledger(side="sell").get(k) == 1 for k in wf)
    assert wf_sold or any(l.startswith("KSL @ wellsfargo") for l in lines), lines
    assert any(l.startswith("KSL @ fidelity") for l in lines), lines


# ============================================ 5. broker failure modes, BUY

BUG_PARTIAL_NOT_OWED = (
    "BUG: app._mirror_leg_retryable (via App._mirror_owe_failed_legs) only owes a "
    "broker whose leg filled NO account. Accounts that positively sent nothing "
    "('Session expired ... not sent', 'Public login 2 failed') beside one that "
    "filled are never retried, never on the failed list or NEEDS ATTENTION, and the "
    "pick reads as held at that broker: missed buy, surfaced only by a transient "
    "'n ok, m failed' toast")
BUG_VERIFY_TRANSIENT = (
    "BUG: App._mirror_record_outcome returns early when anything filled, so a leg "
    "whose broker said 'submitted ... verify' (or raised after sending) is never "
    "put on the mirror failed list or in a notification -- only the receipt card, "
    "which the next pick's batch hides 20s later. Those fills are not journaled, so "
    "the Exits board never sells them either")

BUY_MODES = [
    # (mode, broker, times, expectation)
    ("ok", "schwab", 0, "all"),
    ("login_fail", "schwab", 1, "all"),
    ("timeout_before", "sofi", 1, "all"),
    ("raise_before", "schwab", 1, "all"),
    ("refuse", "chase", 0, "never_at_broker"),
    ("timeout_after", "schwab", 1, "all_reached"),      # was BUG_VERIFY_TRANSIENT (fixed, fix4)
    ("raise_after", "robinhood", 1, "all_reached"),      # was BUG_VERIFY_TRANSIENT (fixed, fix4)
    ("hang_after", "robinhood", 1, "all_reached"),
    ("hang_before", "robinhood", 1, "first_missing"),
    # Was BUG_PARTIAL_NOT_OWED (fixed, fix4). A broker that can aim at named
    # accounts retries just the unsent ones; Robinhood and Public can't, so a
    # whole-broker re-send would re-buy the accounts that filled -- those
    # land on the failed list as "short at <broker> (...)" instead.
    ("partial", "robinhood", 1, "short"),
    ("login2_fail", "public", 1, "short"),
    ("login2_fail", "fidelity", 1, "all"),
]


@pytest.mark.parametrize("mode, broker, times, expect", BUY_MODES)
def test_5a_buy_failure_modes(sim, mode, broker, times, expect):
    standard_feed(sim, ("AAA", "BBB"))
    sim.seed_mirror()
    sim.brokers[broker].set_mode(mode, side="buy", symbol="AAA", times=times)
    boot(sim, max_fake_s=4 * 3600)
    run_for(sim, 3 * 3600)                     # past the 30-min owed back-off and two slots

    assert_no_duplicates(sim)
    got = sim.ledger(side="buy")
    full = {**sim.every_account("AAA"), **sim.every_account("BBB")}
    at_broker_aaa = {k for k in full if k[0] == broker and k[2] == "AAA"}
    if expect in ("all", "all_reached"):
        assert got == full
    elif expect == "short":
        assert {k: v for k, v in got.items() if k not in at_broker_aaa} ==             {k: v for k, v in full.items() if k not in at_broker_aaa}
        assert got.keys() < full.keys()
        key = (FRI, "AAA")
        assert key in sim.app._mirror_failed
        assert "short at" in sim.app._mirror_failed_notes[key]
    else:
        assert got == {k: v for k, v in full.items() if k not in at_broker_aaa}
    # Journal: one row per FILLED order, none for an order that never confirmed.
    filled = {}
    for o in sim.orders(side="buy"):
        if o.status == "filled":
            k = (o.broker, o.account, o.symbol, "buy")
            filled[k] = filled.get(k, 0) + 1
    assert sim.journal_ledger(side="buy") == filled
    if expect in ("all_reached", "first_missing"):
        # Durably surfaced: a notification-centre entry or the mirror failed list.
        key = (FRI, "AAA")
        assert (any("verify" in m.lower() for m, _k in sim.app.notes)
                or key in sim.app._mirror_failed), sim.app.notes
    assert sim.idle_ok() == [], sim.idle_ok()
    assert sim.callback_errors == []


def test_5a_hung_browser_leg_frees_the_app_and_the_queue_moves(sim):
    """A Fidelity leg that never returns: the watchdog writes it off, every
    other broker buys both picks, nothing is re-sent to Fidelity, and Fidelity's
    missed pick ends on the failed list rather than vanishing."""
    standard_feed(sim, ("AAA", "BBB"))
    sim.seed_mirror()
    sim.brokers["fidelity"].set_mode("hang_after", side="buy", symbol="AAA")
    boot(sim, max_fake_s=6 * 3600)
    run_for(sim, 3 * 3600)
    assert_no_duplicates(sim)
    got = sim.ledger(side="buy")
    others = [b for b in ALL_BROKERS if b != "fidelity"]
    for s in ("AAA", "BBB"):
        for k in sim.every_account(s, brokers=others):
            assert got.get(k) == 1, k
    assert all(got.get(k) == 1 for k in sim.every_account("AAA", brokers=("fidelity",)))
    assert sim.idle_ok() == [], sim.idle_ok()
    bbb_fid = [k for k in sim.every_account("BBB", brokers=("fidelity",)) if got.get(k)]
    assert bbb_fid or any(k[1] == "BBB" for k in sim.app._mirror_failed), \
        "Fidelity's BBB neither bought nor on the failed list"


# ============================================ 5. broker failure modes, SELL

SELL_MODES = [
    ("ok", "robinhood", 0, "all"),
    ("login_fail", "robinhood", 1, "all"),
    ("timeout_before", "sofi", 1, "all"),
    ("raise_before", "robinhood", 1, "all"),
    ("refuse", "robinhood", 0, "never_at_broker"),
    ("timeout_after", "robinhood", 1, "all"),
    ("raise_after", "schwab", 1, "all"),
    ("hang_after", "robinhood", 0, "all"),
    ("hang_before", "robinhood", 0, "never_at_broker"),
    ("partial", "robinhood", 1, "all"),
    ("partial", "fidelity", 1, "all"),
    ("login2_fail", "public", 1, "all"),
    ("login2_fail", "fidelity", 1, "all"),
]


@pytest.mark.parametrize("mode, broker, times, expect", SELL_MODES)
def test_5b_sell_failure_modes(sim, mode, broker, times, expect):
    held_everywhere(sim, "AAA")
    split_everywhere(sim, "AAA", fractions={"Public 1 BROKERAGE (1001)"})
    exit_called(sim, "AAA")
    sim.brokers[broker].set_mode(mode, side="sell", times=times)
    sells_launch(sim, max_fake_s=5 * 3600)
    run_for(sim, 3 * 3600)

    assert_no_duplicates(sim)
    full = sim.every_account("AAA", side="sell")
    at_broker = {k for k in full if k[0] == broker}
    got = sim.ledger(side="sell")
    if expect == "all":
        assert got == full
    else:
        assert got == {k: v for k, v in full.items() if k not in at_broker}
    # Public sold per account, capped at what we bought.
    pub = {o.account: o.qty for o in sim.orders(side="sell") if o.broker == "public"}
    if "Public 1 BROKERAGE (1001)" in pub:
        assert pub["Public 1 BROKERAGE (1001)"] == Decimal("0.05")
    assert all(q <= 1 for q in pub.values())
    assert sim.idle_ok() == [], sim.idle_ok()
    assert sim.callback_errors == []


# =================================== 6. a failed holdings read is not "none"

@pytest.mark.parametrize("hmode, broker", [
    ("raise", "robinhood"), ("failed", "robinhood"), ("unread", "fidelity"),
    ("empty_success", "schwab"), ("hang", "robinhood"), ("failed", "public"),
])
def test_6_failed_holdings_read_is_retried_not_called_empty(sim, hmode, broker):
    held_everywhere(sim, "AAA")
    split_everywhere(sim, "AAA")
    exit_called(sim, "AAA")
    sim.brokers[broker].set_holdings_mode(hmode, times=1)
    sells_launch(sim, max_fake_s=5 * 3600)
    run_for(sim, 3 * 3600)
    assert_no_duplicates(sim)
    assert sim.ledger(side="sell") == sim.every_account("AAA", side="sell")
    assert sim.idle_ok() == [], sim.idle_ok()


# ============================================== 7. rename AGAE -> AIFA

def test_7_renamed_exit_sells_the_old_lots_and_folds_pl(sim):
    sim.feed.alert("AGAE", FRI, "standard")
    sim.market.set("AGAE", 0.25)
    sim.seed_mirror()
    sim.seed_autosell(enabled=True, dry_run=False)
    boot(sim)
    assert sim.ledger(side="buy") == sim.every_account("AGAE")

    split_everywhere(sim, "AGAE", rename="AIFA", new_price=5.0)
    sim.feed.board("AGAE", FRI, "rounded_up", sell_symbol="AIFA")
    exit_called(sim, "AIFA", brokers=("public", "robinhood", "fidelity"))
    sim.clock.advance(3600)
    sim.app._track_pull_now()
    sim.pump(lambda: not sim.app._track_busy, max_fake_s=60)
    sim.app._run_in_thread(sim.app._feed_pull_worker)
    sim.pump(lambda: sim.orders(side="sell") != [] and _idle(sim)
             and not sim.app._trade_in_flight, max_fake_s=3 * 3600)
    run_for(sim, 1800)

    exp = sim.every_account("AIFA", side="sell", brokers=("public", "robinhood", "fidelity"))
    assert sim.ledger(side="sell") == exp
    assert not sim.orders(side="sell", symbol="AGAE")
    n = len(exp)
    summary = A.App._portfolio_summary(sim.app)
    assert summary["realized"] == pytest.approx(n * (5.0 - 0.25))
    assert "AIFA" not in summary["no_basis"]
    # one play: AGAE open only where no exit was called
    assert {p["symbol"] for p in summary["open_positions"]} == {"AGAE"}
    assert_no_wedge(sim)
