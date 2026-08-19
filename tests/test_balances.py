"""Tests for the cash store.

The two behaviours worth protecting: a figure you typed must survive every
refresh, and an account whose cash nobody can see must stay visibly unknown
rather than quietly becoming zero.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import balances
from modules.outputs import AccountOutput


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(balances, "BALANCES_FILE", tmp_path / "balances.json")
    yield


def acct(account_id, extra):
    return AccountOutput(account_id=account_id, ok=True, extra=extra)


# ------------------------------------------------------------- extraction

def test_each_broker_is_read_from_its_own_key():
    assert balances.cash_from_extra("public", {"cash_only_buying_power": 120.5}) == 120.5
    assert balances.cash_from_extra("schwab", {"cash_investments": 44.0}) == 44.0
    assert balances.cash_from_extra("sofi", {"cash_dollars_calc": 9.99}) == 9.99
    assert balances.cash_from_extra("robinhood", {"profile_cash": "301.20"}) == 301.20
    assert balances.cash_from_extra("fidelity", {"cash": 88.0}) == 88.0
    assert balances.cash_from_extra("chase", {"cash": 12.0}) == 12.0


def test_public_prefers_settled_cash_over_buying_power():
    # buying_power can include margin and unsettled proceeds, which are not
    # yours to deploy.
    got = balances.cash_from_extra(
        "public", {"buying_power": 900.0, "cash_only_buying_power": 100.0})
    assert got == 100.0


def test_a_broker_with_no_cash_key_reports_none_not_zero():
    assert balances.cash_from_extra("wellsfargo", {"balance": 500.0}) is None
    assert balances.cash_from_extra("fennel", {"positions_parsed": 3}) is None
    assert balances.cash_from_extra("bbae", {}) is None
    assert balances.cash_from_extra("public", None) is None


def test_a_genuine_zero_is_kept_distinct_from_unknown():
    assert balances.cash_from_extra("public", {"cash_only_buying_power": 0}) == 0.0


def test_a_stray_cash_shaped_key_is_not_read_as_buying_power():
    # wellsfargo has no entry in the table, so nothing on its extra counts.
    assert balances.cash_from_extra("wellsfargo", {"cash": 999.0}) is None


# ------------------------------------------------------------- recording

def test_recording_a_broker_output_stores_live_cash():
    balances.record_broker_output("public", [
        acct("Public 1 BROKERAGE (4150)", {"cash_only_buying_power": 120.0}),
        acct("Public 1 BROKERAGE (4153)", {"cash_only_buying_power": 80.0}),
    ])
    t = balances.totals()
    assert t["total"] == 200.0
    assert t["by_broker"]["public"] == 200.0
    assert t["unknown_accounts"] == 0


def test_an_account_with_no_readable_cash_is_recorded_as_unknown():
    balances.record_broker_output("wellsfargo", [
        acct("WELLSTRADE (****1058)", {"balance": 500.0}),
    ])
    t = balances.totals()
    assert t["unknown_by_broker"]["wellsfargo"] == 1
    assert t["total"] == 0.0
    # and it is still listed, because it is what needs typing in
    assert [r["account_id"] for r in balances.rows()] == ["WELLSTRADE (****1058)"]


def test_a_manual_figure_survives_a_live_refresh():
    balances.set_manual("wellsfargo", "WELLSTRADE (****1058)", 750.0)
    balances.record_broker_output("wellsfargo", [
        acct("WELLSTRADE (****1058)", {"balance": 500.0}),
    ])
    row = balances.rows()[0]
    assert row["cash"] == 750.0
    assert row["source"] == balances.SOURCE_MANUAL


def test_a_manual_figure_outranks_a_live_one_until_cleared():
    balances.record_broker_output("public", [
        acct("p1", {"cash_only_buying_power": 100.0})])
    balances.set_manual("public", "p1", 250.0)
    assert balances.rows()[0]["cash"] == 250.0

    balances.clear_manual("public", "p1")
    row = balances.rows()[0]
    assert row["cash"] == 100.0                  # the live figure is still there
    assert row["source"] == balances.SOURCE_LIVE


def test_a_failed_refresh_does_not_erase_the_last_known_figure():
    balances.record_broker_output("public", [
        acct("p1", {"cash_only_buying_power": 100.0})])
    balances.record_broker_output("public", [acct("p1", {})])   # broker hiccup
    assert balances.rows()[0]["cash"] == 100.0


def test_every_figure_carries_its_source_and_a_timestamp():
    balances.record_broker_output("public", [
        acct("p1", {"cash_only_buying_power": 100.0})])
    balances.set_manual("wellsfargo", "w1", 42.0)
    by_id = {r["account_id"]: r for r in balances.rows()}
    assert by_id["p1"]["source"] == balances.SOURCE_LIVE
    assert by_id["p1"]["as_of"]
    assert by_id["w1"]["source"] == balances.SOURCE_MANUAL
    assert by_id["w1"]["as_of"]


# ------------------------------------------------------------- planner shape

def test_for_planner_omits_accounts_with_no_figure():
    """An unknown balance must not be planned against as if it were zero, and
    must not be invented either — it simply is not there."""
    balances.record_broker_output("public", [
        acct("p1", {"cash_only_buying_power": 100.0}),
        acct("p2", {}),
    ])
    shaped = balances.for_planner()
    assert list(shaped["public"]) == ["p1"]
    assert shaped["public"]["p1"] == {"cash": 100.0, "source": "live"}


def test_for_planner_can_be_narrowed_to_chosen_brokers():
    balances.record_broker_output("public", [acct("p1", {"cash_only_buying_power": 100.0})])
    balances.record_broker_output("schwab", [acct("s1", {"cash_investments": 50.0})])
    assert set(balances.for_planner(brokers=["public"])) == {"public"}


def test_the_planner_can_consume_the_store_directly():
    import etf_plan
    balances.record_broker_output("public", [
        acct("p1", {"cash_only_buying_power": 1000.0})])
    plan = etf_plan.plan_exposure(
        etf_plan.exposure_by_key("sp500"), balances.for_planner(),
        {"SPY": 770.56}, mode="max")
    assert plan.orders()[0][0] == "public"
    assert plan.brokers[0].accounts[0].source == "live"


# ------------------------------------------------------------- persistence

def test_the_store_round_trips_through_disk():
    balances.record_broker_output("public", [
        acct("p1", {"cash_only_buying_power": 100.0})])
    balances.set_manual("wellsfargo", "w1", 42.0)
    assert balances.BALANCES_FILE.exists()
    reread = balances.rows(balances.load())
    assert {r["account_id"]: r["cash"] for r in reread} == {"p1": 100.0, "w1": 42.0}


def test_a_corrupt_file_reads_as_empty_rather_than_raising():
    balances.BALANCES_FILE.write_text("{not json", encoding="utf-8")
    assert balances.load() == {"version": 1, "brokers": {}}
    assert balances.rows() == []


def test_no_temp_file_is_left_behind():
    balances.set_manual("public", "p1", 1.0)
    leftovers = list(balances.BALANCES_FILE.parent.glob("*.tmp"))
    assert leftovers == []


def test_version_changes_when_the_store_changes():
    before = balances.version()
    balances.set_manual("public", "p1", 1.0)
    assert balances.version() != before
