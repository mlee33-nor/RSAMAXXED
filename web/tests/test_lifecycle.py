"""Tracking the TRACK board across pulls, and the sell worklist it produces."""
from __future__ import annotations

import pathlib
import sys
from datetime import date

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import lifecycle  # noqa: E402
import rsa_feed  # noqa: E402

TODAY = date(2026, 7, 31)


def rows(board: str):
    return rsa_feed.parse_lifecycle_message({"content": board}, today=TODAY)


PENDING = "\U0001f514 7/17 - TOMZ ⏳"
FRACTIONAL = "\U0001f514 7/17 - TOMZ \U0001f9e9"
ROUNDED = "\U0001f514 7/17 - TOMZ ✅"
CIL = "\U0001f514 7/17 - ALUR \U0001f4b5"
RENAMED = "\U0001f514 6/11 - AGAE ↔️ AIFA \U0001f9e9"


def _trade(symbol, broker, account, side="buy", qty=1.0):
    return {"symbol": symbol, "broker": broker, "account_id": account,
            "side": side, "qty": qty}


# ------------------------------------------------------------------ transitions

def test_first_sighting_of_a_row_is_new_not_a_change():
    state, changes = lifecycle.apply(rows(PENDING), {"rows": {}})
    assert len(changes) == 1
    assert changes[0].is_new and changes[0].old_status == ""
    assert not changes[0].became_sellable        # pending has nothing to sell
    assert state["rows"]["2026-07-17:TOMZ"]["status"] == "pending"


def test_the_very_first_pull_announces_nothing():
    """A cold start sees ~84 rows at once. None of them just happened, and
    alerting on all of them would bury the ones that later do."""
    _, changes = lifecycle.apply(rows(FRACTIONAL), {"rows": {}})
    assert changes[0].seeded
    assert not changes[0].became_sellable
    assert not changes[0].became_fractional


def test_a_row_appearing_on_a_known_board_does_announce():
    """Once we have a board, a genuinely new already-fractional row IS news."""
    state, _ = lifecycle.apply(rows(PENDING), {"rows": {}})
    _, changes = lifecycle.apply(rows(PENDING + "\n" + RENAMED), state)
    assert len(changes) == 1
    assert changes[0].symbol == "AGAE"
    assert not changes[0].seeded
    assert changes[0].became_sellable and changes[0].became_fractional


def test_an_unchanged_board_produces_no_transitions():
    """The board is one message re-read on every poll; a quiet day must be quiet."""
    state, _ = lifecycle.apply(rows(PENDING), {"rows": {}})
    _, changes = lifecycle.apply(rows(PENDING), state)
    assert changes == []


def test_pending_to_fractional_is_the_event_we_care_about():
    state, _ = lifecycle.apply(rows(PENDING), {"rows": {}})
    _, changes = lifecycle.apply(rows(FRACTIONAL), state)
    assert len(changes) == 1
    t = changes[0]
    assert (t.old_status, t.new_status) == ("pending", "fractional")
    assert t.became_sellable and t.became_fractional
    assert not t.is_new


def test_a_row_that_stays_sellable_is_not_re_announced():
    """Otherwise every poll would re-alert 51 open plays and be ignored."""
    state, _ = lifecycle.apply(rows(FRACTIONAL), {"rows": {}})
    state2, changes = lifecycle.apply(rows(ROUNDED), state)
    assert len(changes) == 1
    assert changes[0].became_sellable is False   # fractional -> rounded_up
    assert changes[0].new_status == "rounded_up"


def test_first_seen_survives_later_pulls():
    state, _ = lifecycle.apply(rows(PENDING), {"rows": {}})
    first = state["rows"]["2026-07-17:TOMZ"]["first_seen"]
    state2, _ = lifecycle.apply(rows(FRACTIONAL), state)
    assert state2["rows"]["2026-07-17:TOMZ"]["first_seen"] == first


def test_a_row_leaving_the_board_is_not_a_transition():
    state, _ = lifecycle.apply(rows(FRACTIONAL), {"rows": {}})
    _, changes = lifecycle.apply(rows(CIL), state)   # TOMZ gone, ALUR appears
    assert [c.symbol for c in changes] == ["ALUR"]


def test_state_round_trips_through_disk(tmp_path):
    p = tmp_path / "lifecycle_state.json"
    state, _ = lifecycle.apply(rows(FRACTIONAL), {"rows": {}})
    lifecycle.save_state(state, p)
    assert lifecycle.load_state(p)["rows"] == state["rows"]
    # A missing file reads as an empty board rather than exploding.
    assert lifecycle.load_state(tmp_path / "nope.json")["rows"] == {}


# --------------------------------------------------------------- sell routing

def test_fractional_routes_only_to_the_three_fractional_brokers():
    assert lifecycle.brokers_for("fractional") == ("Public", "Robinhood", "SoFi")


def test_roundup_and_cancel_route_everywhere():
    assert lifecycle.brokers_for("rounded_up") == rsa_feed.SUPPORTED_BROKERS
    assert lifecycle.brokers_for("canceled") == rsa_feed.SUPPORTED_BROKERS


def test_nothing_to_do_for_unresolved_or_cashed_out_plays():
    for status in ("pending", "new", "cash_in_lieu", "low_odds", "unknown"):
        assert lifecycle.brokers_for(status) == (), status


# ------------------------------------------------------------------- worklist

def test_fractional_worklist_skips_the_cash_in_lieu_brokers():
    """The core of it: we hold TOMZ at 4 brokers, only 2 can return a fraction."""
    held = lifecycle.held_accounts([
        _trade("TOMZ", "robinhood", "acct-1"),
        _trade("TOMZ", "public", "acct-2"),
        _trade("TOMZ", "fidelity", "acct-3"),
        _trade("TOMZ", "schwab", "acct-4"),
    ])
    tasks = lifecycle.sell_worklist(rows(FRACTIONAL), held)
    assert len(tasks) == 1
    assert set(tasks[0].brokers) == {"Robinhood", "Public"}
    assert set(tasks[0].skipped_brokers) == {"Fidelity", "Schwab"}
    assert tasks[0].accounts == 2
    assert tasks[0].is_fractional


def test_roundup_worklist_uses_every_broker_we_hold():
    held = lifecycle.held_accounts([
        _trade("TOMZ", "fidelity", "acct-1"),
        _trade("TOMZ", "schwab", "acct-2"),
    ])
    tasks = lifecycle.sell_worklist(rows(ROUNDED), held)
    assert set(tasks[0].brokers) == {"Fidelity", "Schwab"}
    assert tasks[0].skipped_brokers == ()


def test_multiple_accounts_at_one_broker_are_counted():
    held = lifecycle.held_accounts([
        _trade("TOMZ", "public", "acct-1"),
        _trade("TOMZ", "public", "acct-2"),
        _trade("TOMZ", "public", "acct-3"),
    ])
    tasks = lifecycle.sell_worklist(rows(FRACTIONAL), held)
    assert tasks[0].accounts == 3


def test_a_sold_position_drops_off_the_worklist():
    held = lifecycle.held_accounts([
        _trade("TOMZ", "robinhood", "acct-1"),
        _trade("TOMZ", "robinhood", "acct-1", side="sell"),
    ])
    assert lifecycle.sell_worklist(rows(FRACTIONAL), held) == []


def test_holdings_we_do_not_own_are_left_out_unless_asked_for():
    assert lifecycle.sell_worklist(rows(FRACTIONAL), {}) == []
    shown = lifecycle.sell_worklist(rows(FRACTIONAL), {}, include_unheld=True)
    assert len(shown) == 1 and shown[0].brokers == ()


def test_cash_in_lieu_never_reaches_the_worklist():
    """Nothing is left in the account — an order would be rejected everywhere."""
    held = lifecycle.held_accounts([_trade("ALUR", "robinhood", "acct-1")])
    assert lifecycle.sell_worklist(rows(CIL), held) == []


def test_a_renamed_ticker_sells_under_the_new_symbol():
    held = lifecycle.held_accounts([_trade("AGAE", "sofi", "acct-1")])
    tasks = lifecycle.sell_worklist(rows(RENAMED), held)
    assert len(tasks) == 1
    assert tasks[0].alert_symbol == "AGAE"    # what the journal knows
    assert tasks[0].symbol == "AIFA"          # what the broker will accept
    assert tasks[0].renamed
    assert tasks[0].brokers == ("SoFi",)


def test_a_position_opened_under_the_new_name_still_matches():
    held = lifecycle.held_accounts([_trade("AIFA", "public", "acct-9")])
    tasks = lifecycle.sell_worklist(rows(RENAMED), held)
    assert tasks[0].brokers == ("Public",)


# ------------------------------------------------------- quantity resolution

class _Holding:
    def __init__(self, symbol, shares):
        self.symbol, self.shares = symbol, shares


class _Account:
    def __init__(self, account_id, holdings, ok=True):
        self.account_id, self.holdings, self.ok = account_id, holdings, ok


class _Out:
    def __init__(self, accounts, state="success"):
        self.accounts, self.state = accounts, state


def _task(symbol="TOMZ", brokers=("Robinhood", "Public"), status="fractional",
          alert_symbol=None):
    return lifecycle.SellTask(
        symbol=symbol, alert_symbol=alert_symbol or symbol,
        alert_date="2026-07-17", status=status, brokers=tuple(brokers),
        accounts=len(brokers))


def test_quantity_comes_from_holdings_not_the_board():
    """The board never says how much; only the broker knows."""
    out = _Out([_Account("a1", [_Holding("TOMZ", 0.04545)]),
                _Account("a2", [_Holding("TOMZ", 0.04545)])])
    r = lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out})
    assert r.ok
    assert r.legs[0].qty == "0.04545"
    assert r.legs[0].accounts == 2
    assert r.legs[0].uniform


def test_fractional_quantity_never_goes_scientific():
    """Several broker APIs reject '4.545E-2' — that is how a fractional sell
    silently becomes an invalid order."""
    out = _Out([_Account("a1", [_Holding("TOMZ", "0.00001234")])])
    r = lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out})
    assert r.legs[0].qty == "0.00001234"
    assert "E" not in r.legs[0].qty.upper()


def test_uneven_accounts_send_the_minimum_and_report_the_spread():
    """Overselling rejects the whole leg, so we send the smallest — but the
    stranded remainder must be visible, not swallowed."""
    out = _Out([_Account("a1", [_Holding("TOMZ", 0.05)]),
                _Account("a2", [_Holding("TOMZ", 1.0)])])
    r = lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out})
    leg = r.legs[0]
    assert leg.qty == "0.05"
    assert not leg.uniform
    assert leg.stranded == pytest.approx(0.95)
    assert not r.uniform


def test_a_broker_holding_nothing_is_skipped_not_ordered():
    out = _Out([_Account("a1", [_Holding("SOMETHINGELSE", 3)])])
    r = lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out})
    assert r.legs == ()
    assert r.missing == ("Robinhood",)
    assert not r.ok


def test_a_broker_we_could_not_read_is_an_error_not_a_zero():
    """Silently treating an unreadable broker as 'nothing to sell' would leave
    a position open with no sign anything went wrong."""
    r = lifecycle.resolve(_task(brokers=("Robinhood", "Public")),
                          {"robinhood": _Out([], state="failed")})
    assert set(r.errors) == {"Robinhood", "Public"}   # Public absent entirely
    assert r.legs == ()


def test_failed_accounts_do_not_contribute_a_quantity():
    out = _Out([_Account("good", [_Holding("TOMZ", 0.5)]),
                _Account("bad", [_Holding("TOMZ", 0.01)], ok=False)])
    r = lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out})
    assert r.legs[0].qty == "0.5"
    assert r.legs[0].accounts == 1


def test_a_renamed_position_is_found_under_either_ticker():
    """The broker reports AIFA; our journal still says AGAE."""
    task = _task(symbol="AIFA", alert_symbol="AGAE", brokers=("SoFi",))
    out = _Out([_Account("a1", [_Holding("AIFA", 1)])])
    assert lifecycle.resolve(task, {"sofi": out}).legs[0].qty == "1"
    old = _Out([_Account("a1", [_Holding("AGAE", 1)])])
    assert lifecycle.resolve(task, {"sofi": old}).legs[0].qty == "1"


def test_multiple_lots_in_one_account_are_summed():
    out = _Out([_Account("a1", [_Holding("TOMZ", 0.5), _Holding("TOMZ", 0.25)])])
    r = lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out})
    assert r.legs[0].qty == "0.75"


def test_each_broker_gets_its_own_quantity():
    """execute_trade takes one qty per broker, so the split can differ per leg."""
    r = lifecycle.resolve(
        _task(brokers=("Robinhood", "Public")),
        {"robinhood": _Out([_Account("a", [_Holding("TOMZ", 0.05)])]),
         "public": _Out([_Account("b", [_Holding("TOMZ", 0.1)])])})
    got = {l.broker: l.qty for l in r.legs}
    assert got == {"Robinhood": "0.05", "Public": "0.1"}
    assert r.total_accounts == 2


def test_partial_broker_state_still_resolves():
    """'partial' means some accounts reported; the ones that did are real."""
    out = _Out([_Account("a1", [_Holding("TOMZ", 0.2)])], state="partial")
    assert lifecycle.resolve(_task(brokers=("Robinhood",)), {"robinhood": out}).ok


def test_broker_names_normalize_before_the_routing_test():
    """'rh' and 'wells' are both written in the wild; routing must still work."""
    held = lifecycle.held_accounts([
        _trade("TOMZ", "rh", "acct-1"),
        _trade("TOMZ", "wells", "acct-2"),
    ])
    tasks = lifecycle.sell_worklist(rows(FRACTIONAL), held)
    assert tasks[0].brokers == ("Robinhood",)
    assert tasks[0].skipped_brokers == ("Wells Fargo",)
