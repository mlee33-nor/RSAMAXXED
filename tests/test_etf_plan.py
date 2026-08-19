"""Tests for the ETF planner.

The planner decides how much money moves, so these lean on the cases that
would cost real money if they were wrong: rounding up, sending a fractional
quantity to a broker that truncates it to zero, and letting one near-empty
account decide the order for every account at that broker.
"""

from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import etf_plan
from etf_plan import Capability, capability_for, plan_exposure, qty_text


SP500 = etf_plan.exposure_by_key("sp500")
# Real prices, so the arithmetic in these tests is the arithmetic that runs.
PRICES = {"SPY": 770.56, "VOO": 708.42, "IVV": 774.23,
          "SPLG": 80.00, "SCHX": 30.43}


def only(plan, broker):
    return next(b for b in plan.brokers if b.broker == broker)


# ---------------------------------------------------------------- capability

def test_capability_table_matches_the_broker_modules():
    assert capability_for("public") is Capability.FULL
    assert capability_for("robinhood") is Capability.FULL
    assert capability_for("sofi") is Capability.SUB_ONE_ONLY
    for b in ("fidelity", "chase", "wellsfargo"):
        assert capability_for(b) is Capability.WHOLE_ONLY
    for b in ("schwab", "fennel", "bbae", "dspac"):
        assert capability_for(b) is Capability.UNVERIFIED


def test_unverified_brokers_are_treated_as_whole_share():
    # An untested fractional order is worse than an under-deployed account.
    assert not etf_plan.buys_fractional(Capability.UNVERIFIED)


def test_an_unknown_broker_is_not_assumed_fractional():
    assert capability_for("some-new-broker") is Capability.UNVERIFIED


def test_sofi_stops_being_fractional_outside_core_hours():
    # sofi.py refuses a fractional order out of hours, so the planner must not
    # build one.
    assert capability_for("sofi", market_open=True) is Capability.SUB_ONE_ONLY
    assert capability_for("sofi", market_open=False) is Capability.WHOLE_ONLY


def test_capability_is_not_the_split_lifecycle_table():
    """rsa_feed.FRACTIONAL_BROKERS answers who CUSTODIES a fraction, not who
    can buy one. SoFi is in that tuple and cannot buy 1.5 shares."""
    import rsa_feed
    assert "SoFi" in rsa_feed.FRACTIONAL_BROKERS
    assert capability_for("sofi") is not Capability.FULL


# ---------------------------------------------------------------- rounding

@pytest.mark.parametrize("cash,price,cap,expected", [
    (100, 80, Capability.WHOLE_ONLY, "1"),      # 1.25 -> 1, never 2
    (79.99, 80, Capability.WHOLE_ONLY, "0"),    # one cent short is short
    (770.56, 770.56, Capability.WHOLE_ONLY, "1"),
    (100, 80, Capability.FULL, "1.25"),
    (100, 30.43, Capability.FULL, "3.28623"),   # truncated, not rounded up
    (100, 80, Capability.UNVERIFIED, "1"),
])
def test_affordable_quantity_always_rounds_down(cash, price, cap, expected):
    got = etf_plan._floor_shares(Decimal(str(cash)), Decimal(str(price)), cap)
    assert qty_text(got) == expected


def test_a_fractional_quantity_never_costs_more_than_the_cash():
    for cash in ("100", "33.33", "7.77", "1000.01"):
        for price in ("30.43", "770.56", "80"):
            c, p = Decimal(cash), Decimal(price)
            q = etf_plan._floor_shares(c, p, Capability.FULL)
            assert q * p <= c


def test_qty_text_never_uses_exponent_notation():
    # Several broker APIs reject '4.5E-2' outright.
    assert qty_text(Decimal("0.00005")) == "0.00005"
    assert "E" not in qty_text(Decimal("0.000012345"))
    assert qty_text(Decimal("1.000")) == "1"
    assert qty_text(Decimal("0")) == "0"


# ---------------------------------------------------------------- whole-share

def test_whole_share_broker_drops_to_the_cheap_equivalent():
    """$300 buys no SPY at $770, but does buy SCHX — same index."""
    plan = plan_exposure(SP500, {"fidelity": {"a": 300, "b": 300}}, PRICES,
                         mode="max")
    fid = only(plan, "fidelity")
    assert fid.ticker in ("SPLG", "SCHX")
    assert fid.qty > 0
    assert len(fid.participating) == 2


def test_the_tier_that_deploys_the_most_wins():
    # $100/account: SPLG buys 1 ($80), SCHX buys 3 ($91.29). SCHX deploys more.
    plan = plan_exposure(SP500, {"chase": {"a": 100, "b": 100}}, PRICES,
                         mode="max")
    chase = only(plan, "chase")
    assert chase.ticker == "SCHX"
    assert qty_text(chase.qty) == "3"


def test_a_rich_whole_share_account_can_still_reach_the_headline():
    plan = plan_exposure(SP500, {"wellsfargo": {"a": 100_000}}, PRICES,
                         mode="target", target_per_account=800)
    wf = only(plan, "wellsfargo")
    assert wf.ticker == "SPY"
    assert qty_text(wf.qty) == "1"


def test_whole_share_broker_never_receives_a_fraction():
    plan = plan_exposure(SP500, {"fidelity": {"a": 250}}, PRICES, mode="max")
    fid = only(plan, "fidelity")
    # fidelity.py does int(float(qty)); a fraction here becomes 0 -> "Invalid qty"
    assert fid.qty == fid.qty.to_integral_value()


# ---------------------------------------------------------------- fractional

def test_fractional_broker_keeps_the_headline_ticker():
    """Price is not a barrier at Public, so there is no reason to leave SPY."""
    plan = plan_exposure(SP500, {"public": {"a": 300, "b": 300}}, PRICES,
                         mode="max")
    pub = only(plan, "public")
    assert pub.ticker == "SPY"
    assert pub.qty > 0


def test_fractional_broker_deploys_nearly_all_the_cash():
    plan = plan_exposure(SP500, {"public": {"a": 300, "b": 300}}, PRICES,
                         mode="max")
    pub = only(plan, "public")
    assert pub.deployed > Decimal("599")     # of $600


def test_sofi_is_never_handed_a_quantity_between_one_and_two():
    """sofi.py routes qty < 1 to the fractional endpoint and everything else
    to a whole-share LIMIT order, so 1.5 has nowhere to go."""
    plan = plan_exposure(SP500, {"sofi": {"a": 200}}, PRICES, mode="max")
    sofi = only(plan, "sofi")
    assert sofi.qty < 1 or sofi.qty == sofi.qty.to_integral_value()


def test_sofi_out_of_hours_is_planned_as_whole_shares():
    plan = plan_exposure(SP500, {"sofi": {"a": 200}}, PRICES, mode="max",
                         market_open=False)
    sofi = only(plan, "sofi")
    assert sofi.qty == sofi.qty.to_integral_value()


# ------------------------------------------------- the uniform-quantity rule

def test_the_poorest_account_sets_the_quantity_in_max_mode():
    """One call sends one quantity to every account, so among the accounts
    that can take part it has to be one the smallest balance can honour —
    the same rule lifecycle.resolve uses for fractional sells."""
    plan = plan_exposure(SP500, {"fidelity": {"rich": 10_000, "poor": 800}},
                         PRICES, mode="max")
    fid = only(plan, "fidelity")
    assert len(fid.participating) == 2
    assert fid.qty * fid.price <= Decimal("800")
    # and the rich account is capped by the poor one, not by its own balance
    assert fid.accounts[0].affordable > fid.qty


def test_an_account_too_poor_for_one_share_does_not_cap_the_others():
    """The min is taken over accounts that can actually take part. Otherwise
    a single near-empty account would reduce every order to nothing."""
    plan = plan_exposure(SP500, {"fidelity": {"rich": 10_000, "poor": 5}},
                         PRICES, mode="max")
    fid = only(plan, "fidelity")
    assert fid.qty > 0
    assert [a.account_id for a in fid.participating] == ["rich"]
    assert [a.account_id for a in fid.short] == ["poor"]


def test_target_mode_sends_the_same_quantity_and_reports_who_is_short():
    plan = plan_exposure(SP500, {"fidelity": {"rich": 10_000, "poor": 50}},
                         PRICES, mode="target", target_per_account=500)
    fid = only(plan, "fidelity")
    assert [a.account_id for a in fid.participating] == ["rich"]
    short = fid.short[0]
    assert short.account_id == "poor"
    assert short.shortfall > 0
    assert short.deployed == 0
    assert short.leftover == Decimal("50")     # untouched


def test_shortfall_is_what_it_would_take_to_join():
    plan = plan_exposure(SP500, {"chase": {"a": 20}}, PRICES,
                         mode="target", target_per_account=30.43,
                         ticker_override={"chase": "SCHX"})
    row = only(plan, "chase").accounts[0]
    assert row.shortfall == Decimal("10.43")
    assert 0.6 < row.progress < 0.7


def test_one_order_per_broker_covers_every_participating_account():
    plan = plan_exposure(SP500, {"public": {f"a{i}": 500 for i in range(20)}},
                         PRICES, mode="target", target_per_account=100)
    assert len(plan.orders()) == 1               # not 20
    assert len(only(plan, "public").participating) == 20


# ---------------------------------------------------------------- edge cases

def test_an_empty_account_sits_the_round_out_rather_than_failing():
    plan = plan_exposure(SP500, {"fidelity": {"a": 0, "b": 5000}}, PRICES,
                         mode="max")
    fid = only(plan, "fidelity")
    assert fid.qty > 0                    # the empty one does not veto the order
    assert [a.account_id for a in fid.short] == ["a"]


def test_a_missing_quote_is_skipped_not_guessed():
    plan = plan_exposure(SP500, {"public": {"a": 1000}}, {}, mode="max")
    pub = only(plan, "public")
    assert pub.qty == 0
    assert "no quote" in pub.skipped_reason
    assert plan.orders() == []


def test_a_broker_with_no_recorded_cash_is_reported_not_traded():
    plan = plan_exposure(SP500, {"wellsfargo": {}}, PRICES, mode="max")
    wf = only(plan, "wellsfargo")
    assert wf.qty == 0
    assert wf.skipped_reason == "no cash on record"
    assert plan.orders() == []


def test_a_sliver_order_is_not_worth_placing():
    plan = plan_exposure(SP500, {"public": {"a": Decimal("0.40")}}, PRICES,
                         mode="max")
    assert only(plan, "public").qty == 0


def test_balances_may_carry_their_source():
    plan = plan_exposure(SP500,
                         {"fidelity": {"a": {"cash": 500, "source": "manual"}}},
                         PRICES, mode="max")
    assert only(plan, "fidelity").accounts[0].source == "manual"


def test_orders_are_shaped_for_execute_trade():
    plan = plan_exposure(SP500, {"public": {"a": 1000}}, PRICES,
                         mode="target", target_per_account=200)
    (broker, ticker, qty) = plan.orders()[0]
    assert broker == "public"
    assert ticker == "SPY"
    assert isinstance(qty, str) and "E" not in qty and float(qty) > 0


def test_a_whole_fleet_plans_without_blowing_up():
    balances = {
        "public":     {f"p{i}": 400 for i in range(20)},
        "wellsfargo": {f"w{i}": 250 for i in range(20)},
        "fidelity":   {f"f{i}": 900 for i in range(11)},
        "sofi":       {f"s{i}": 120 for i in range(4)},
        "chase":      {f"c{i}": 60 for i in range(3)},
        "robinhood":  {f"r{i}": 800 for i in range(3)},
        "fennel":     {"f1": 45},
    }
    plan = plan_exposure(SP500, balances, PRICES, mode="max")
    assert plan.account_count > 50
    assert plan.deployed > 0
    # every actionable broker yields exactly one order
    assert len(plan.orders()) == len(plan.actionable)
    for b in plan.brokers:
        if not etf_plan.buys_fractional(b.capability):
            assert b.qty == b.qty.to_integral_value(), b.broker


def test_a_tier_that_includes_more_accounts_beats_one_that_banks_more_dollars():
    """With {50, 300, 1200, 5000, 80}, SPY is affordable by two accounts and
    banks more dollars than SCHX, which all five can afford. Picking on
    dollars alone would leave three accounts out — the exact problem the cheap
    equivalent exists to solve."""
    balances = {"wellsfargo": dict(zip("abcde", [50, 300, 1200, 5000, 80]))}
    plan = plan_exposure(SP500, balances, PRICES, mode="max")
    wf = only(plan, "wellsfargo")
    assert wf.ticker == "SCHX"
    assert len(wf.participating) == 5
    assert wf.short == []


def test_participation_does_not_override_a_clearly_better_tier_at_equal_reach():
    """When every tier reaches the same accounts, dollars decide again."""
    plan = plan_exposure(SP500, {"fidelity": {f"a{i}": 120 for i in range(11)}},
                         PRICES, mode="max")
    fid = only(plan, "fidelity")
    assert len(fid.participating) == 11      # SPLG and SCHX both reach all 11
    assert fid.ticker == "SCHX"              # ...and SCHX deploys $91 vs $80


def test_a_lopsided_plan_says_so_instead_of_looking_healthy():
    balances = {"wellsfargo": dict(zip("abcde", [50, 300, 1200, 5000, 80]))}
    wf = only(plan_exposure(SP500, balances, PRICES, mode="max"), "wellsfargo")
    assert len(wf.participating) == 5          # everyone is in...
    assert wf.idle > wf.deployed * 4           # ...but almost nothing deployed
    assert "stays in cash" in wf.advisory
    assert "a" in wf.advisory                  # names the account doing the capping


def test_an_even_fleet_gets_no_advisory():
    balances = {"wellsfargo": {f"w{i}": 900 for i in range(20)}}
    wf = only(plan_exposure(SP500, balances, PRICES, mode="max"), "wellsfargo")
    assert wf.advisory == ""
