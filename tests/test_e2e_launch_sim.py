"""End-to-end launch simulation: mirror check -> buys -> exits -> sells.

Every test builds an install in a temp folder (tests/sim_harness.Sim), seeds
its state files, "launches" the app (the real startup timers on a fake clock)
and drives it until it is idle, then asserts the exact order ledger at the fake
brokers, the journal rows, realized P/L, and that nothing is left wedged.

A scenario that fails because of an APP bug is marked xfail(strict=True) with
the bug in its reason -- app code is not patched here.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

import pytest

import sim_harness as H
from sim_harness import A, ALL_BROKERS

MON = datetime(2026, 10, 5, 9, 44, 59)       # Monday, a second before the 09:45 slot
FRI = "2026-10-02"
MON_D = "2026-10-05"


@pytest.fixture
def sim(monkeypatch, tmp_path):
    s = H.Sim(monkeypatch, tmp_path, MON)
    yield s
    s.close()


def boot(sim, until_idle=True, max_fake_s=3 * 3600):
    app = sim.launch()
    if until_idle:
        sim.pump(lambda: _idle(sim), max_fake_s=max_fake_s)
    return app


def _idle(sim):
    app = sim.app
    return (app._mirror_resumed and not app._mirror_queue
            and not any(not b.get("finished") for b in app._mirror_active)
            and not app._brokers_in_flight and not app._queue_busy
            and not app._autosell_queue and sim.threads.busy() == []
            and not getattr(app, "_mirror_ran", False))


def assert_no_wedge(sim):
    assert sim.idle_ok() == [], sim.idle_ok()
    assert sim.callback_errors == [], sim.callback_errors[0]


# Picks as the alert bot posts them.
def standard_feed(sim, syms=("AAA", "BBB", "CCC"), day=FRI):
    for s in syms:
        sim.feed.alert(s, day, "standard")
        sim.market.set(s, 0.25)


# ============================================================ 1. clean launch

def test_1_clean_launch_buys_each_unbought_standard_pick_once_everywhere(sim):
    standard_feed(sim)
    sim.feed.alert("DDD", FRI, "standard")              # already bought everywhere
    sim.feed.alert("EEE", FRI, "otc")
    sim.feed.alert("FFF", FRI, "conditional")
    sim.feed.alert("GGG", FRI, "standard", type_line="CANCELLED")   # unknown type
    for s in ("DDD", "EEE", "FFF", "GGG"):
        sim.market.set(s, 0.30)
    for b in ALL_BROKERS:
        sim.seed_buy(b, "DDD", f"{FRI}T15:00:00", price=0.30)
    sim.seed_mirror()
    sim.seed_autosell(enabled=True, dry_run=False)

    boot(sim)

    # ---- exactly the three, once per account, nothing else
    expected = {}
    for s in ("AAA", "BBB", "CCC"):
        expected.update(sim.every_account(s))
    got = {k: v for k, v in sim.ledger(side="buy").items() if k[2] != "DDD"}
    assert got == expected
    assert not sim.orders(symbol="DDD")
    for s in ("EEE", "FFF", "GGG"):
        assert not sim.orders(symbol=s), s
    assert sim.journal_ledger(side="buy") == {**expected, **{
        k: 1 for k in sim.every_account("DDD")}}

    # ---- skips carry their reasons
    reasons = {}
    for scan in A.mirror_journal.scans():
        for sk in scan.get("skipped") or []:
            reasons.setdefault(sk["symbol"], set()).add(sk["reason"])
    assert any("already bought" in r for r in reasons["DDD"])
    assert any("OTC" in r for r in reasons["EEE"])
    assert any("conditional" in r for r in reasons["FFF"])
    assert any("not recognised" in r for r in reasons["GGG"])
    assert_no_wedge(sim)

    # ---- the split lands, then exits arrive
    for b in ALL_BROKERS:
        sim.brokers[b].split("AAA", 20, roundup=True,
                             fraction_accounts={"Public 1 BROKERAGE (1001)",
                                                "Public 1 BROKERAGE (1002)"})
    sim.market.set("AAA", 5.00)
    sim.market.set("BBB", 0.40)
    sim.clock.advance(3600)
    sim.feed.exit("AAA", 5.00, {H.LOGIN_LABEL[b]: 1 for b in ALL_BROKERS}, MON_D)
    sim.feed.exit("BBB", 0.40, {"Robinhood": 2}, MON_D)
    sim.app._run_in_thread(sim.app._feed_pull_worker)
    sim.pump(lambda: _idle(sim) and not sim.app._autosell_queue
             and sim.orders(side="sell") != [] and not sim.app._trade_in_flight,
             max_fake_s=3 * 3600)
    sim.settle(max_fake_s=600)

    sells = sim.orders(side="sell")
    by = {(o.broker, o.account, o.symbol): o.qty for o in sells}
    exp_aaa = {(b, a, "AAA") for b in ALL_BROKERS for a in sim.brokers[b].accounts()}
    exp_bbb = {("robinhood", a, "BBB") for a in sim.brokers["robinhood"].accounts()}
    assert set(by) == exp_aaa | exp_bbb
    assert sim.ledger(side="sell") == {(b, a, s, "sell"): 1 for (b, a, s) in exp_aaa | exp_bbb}
    for (b, a, s), q in by.items():
        if s == "AAA" and a in ("Public 1 BROKERAGE (1001)", "Public 1 BROKERAGE (1002)"):
            assert q == Decimal("0.05"), (b, a, q)      # Public sized per account
        else:
            assert q == Decimal("1"), (b, a, q)
    assert not sim.orders(symbol="CCC", side="sell")
    # journal: one sell row per order, at the qty actually sold
    jl = sim.journal_ledger(side="sell")
    assert jl == {(b, a, s, "sell"): 1 for (b, a, s) in exp_aaa | exp_bbb}
    # realized: AAA 23 x (5.00 - 0.25) + 2 Public fractions at break-even
    # (0.05 x $5 = $0.25 restated onto the whole share); BBB 2 x 0.15.
    assert sim.realized() == pytest.approx(23 * 4.75 + 0 + 2 * 0.15, abs=1e-6)
    assert_no_wedge(sim)


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


# ================================================================ 2. re-alert

@pytest.mark.parametrize("sold_since", [False, True])
def test_2_re_alert_of_a_split_already_bought_places_no_order(sim, sold_since):
    """SFWL: bought 09-28 everywhere, re-alerted with a new date 10-02."""
    held_everywhere(sim, "SFWL", day="2026-09-28")
    if sold_since:
        for b in ALL_BROKERS:
            for a in sim.brokers[b].accounts():
                A.trade_journal.record_trade(broker=b, account_id=a, side="sell",
                                             symbol="SFWL", qty=1.0, fill_price=0.3,
                                             when="2026-09-30T15:00:00+00:00")
    sim.feed.alert("SFWL", FRI, "standard")
    sim.market.set("SFWL", 0.25)
    sim.seed_mirror()
    boot(sim)
    run_for(sim, 2 * 3600)                      # two more scheduled checks
    assert sim.orders() == []
    reasons = {sk["reason"] for sc in A.mirror_journal.scans()
               for sk in sc.get("skipped") or [] if sk["symbol"] == "SFWL"}
    assert any("already bought" in r for r in reasons), reasons
    assert_no_wedge(sim)


# ======================================================= 3. calendar edges

def test_3a_friday_evening_alert_bought_at_monday_0945_launch(sim):
    sim.feed.alert("FRI", FRI, "standard", posted_et=f"{FRI}T17:50:00")
    sim.market.set("FRI", 0.25)
    sim.seed_mirror()                           # default max age (2 trading days)
    boot(sim)
    assert sim.ledger(side="buy") == sim.every_account("FRI")
    assert_no_wedge(sim)


def test_3b_left_running_friday_evening_through_the_weekend(sim):
    """Imported at 17:50 Friday with the app open: nothing until Monday's
    09:45 slot, then bought once everywhere -- the heartbeat survives 64h."""
    sim.clock.set_et(datetime(2026, 10, 2, 17, 45, 0))
    sim.seed_mirror()
    sim.market.set("FRI", 0.25)
    sim.launch()
    run_for(sim, 10 * 60)
    sim.feed.alert("FRI", FRI, "standard", posted_et=f"{FRI}T17:50:00")
    sim.app._run_in_thread(sim.app._feed_pull_worker)
    # Saturday, Sunday, Monday pre-market: nothing.
    sim.pump(lambda: sim.clock.et() >= datetime(2026, 10, 5, 9, 44).replace(tzinfo=H.NY),
             max_fake_s=70 * 3600)
    assert sim.orders() == []
    sim.pump(lambda: _idle(sim) and sim.orders() != [], max_fake_s=2 * 3600)
    assert sim.ledger(side="buy") == sim.every_account("FRI")
    assert all(o.t >= "2026-10-05T09:45" for o in sim.orders())
    assert_no_wedge(sim)


def test_3c_holiday_sends_nothing_and_buries_nothing(sim):
    """Thanksgiving: no slot, no order -- and the pick still buys Friday."""
    sim.clock.set_et(datetime(2026, 11, 26, 10, 0, 0))
    sim.feed.alert("TKY", "2026-11-25", "standard")
    sim.market.set("TKY", 0.25)
    sim.seed_mirror()
    sim.launch()
    run_for(sim, 8 * 3600)
    assert sim.orders() == []
    assert sim.app._mirror_executed == set()
    # Friday 11-27 is a 13:00 half day: the 09:45 slot buys it.
    sim.pump(lambda: sim.orders() != [] and _idle(sim), max_fake_s=30 * 3600)
    assert sim.ledger(side="buy") == sim.every_account("TKY")
    assert all("2026-11-27T09:4" <= o.t < "2026-11-27T13:00" for o in sim.orders())
    assert_no_wedge(sim)


def test_3d_half_day_after_1300_sends_nothing(sim):
    sim.clock.set_et(datetime(2026, 11, 27, 13, 30, 0))
    sim.feed.alert("HLF", "2026-11-27", "standard")
    sim.market.set("HLF", 0.25)
    sim.seed_mirror()
    sim.launch()
    # A fresh import after the close must not fire either.
    sim.feed.alert("HLX", "2026-11-27", "standard")
    sim.market.set("HLX", 0.25)
    sim.app._run_in_thread(sim.app._feed_pull_worker)
    sim.pump(lambda: sim.clock.et() >= datetime(2026, 11, 30, 9, 0).replace(tzinfo=H.NY),
             max_fake_s=70 * 3600)
    assert sim.orders() == []
    # ... and both buy at Monday's open slot (one session old).
    sim.pump(lambda: len(sim.orders()) == 2 * 25 and _idle(sim), max_fake_s=3 * 3600)
    assert sim.ledger(side="buy") == {**sim.every_account("HLF"), **sim.every_account("HLX")}
    assert_no_wedge(sim)
