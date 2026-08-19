"""Two things that used to be impossible on the Trade Desk.

1. A sell alert names the brokerage it was taken at ("Fidelity x10"), and the
   ticket now opens armed at exactly that broker instead of at whatever was
   selected last.
2. Two orders can be in the air at once as long as they touch different brokers
   — sell AIFA at Fidelity while BBBB goes out at Robinhood. The old guard
   refused every second batch, which is safe but wrong; the new one refuses only
   the overlap, which is what actually double-sold AIFA on Robinhood.

The App class cannot be instantiated headlessly (CustomTkinter's DPI tracker
takes the process down), so the methods are called unbound against a stub that
supplies only the attributes they touch — same approach as
test_trade_worker_routing.
"""

from __future__ import annotations

import sys
import types
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


# --------------------------------------------------------------------- stub

class Entry:
    """The three ttk.Entry calls _prefill_trade makes."""

    def __init__(self, text=""):
        self.text = text

    def get(self):
        return self.text

    def delete(self, *_a):
        self.text = ""

    def insert(self, _i, text):
        self.text += text


class Desk:
    """Just enough App for the desk's selection + guard paths."""

    def __init__(self, linked=("fidelity", "robinhood", "public", "chase")):
        self._trade_broker_chips = {b: {"label": object(), "selected": False}
                                    for b in linked}
        self._trade_selected_brokers: set = set()
        self._linked_brokers = list(linked)
        self._select_all_chip = object()
        self._brokers_in_flight: set = set()
        self._live_batches: list = []
        self._trade_in_flight = False
        self._trade_side = types.SimpleNamespace(get=lambda: "sell")
        self._trade_dry = types.SimpleNamespace(get=lambda: True)
        self._trade_symbol = Entry("AIFA")
        self._trade_qty = Entry("1")
        self.launched: list = []        # (broker, side, symbol)
        self.notes: list = []
        self.logs: list = []
        self.shown_frame = None

    # -- widget-level no-ops -------------------------------------------------
    def _style_chip(self, *_a, **_k):
        pass

    def _update_trade_estimate(self, *_a):
        pass

    def _refresh_trade_busy(self):
        pass

    def _trade_result_write(self, *_a, **_k):
        pass

    def _render_done_receipt(self, **_k):
        pass

    def _live_hide(self):
        pass

    def _show_frame(self, name):
        self.shown_frame = name

    def _set_trade_side(self, side):
        self.side = side

    # -- observable -----------------------------------------------------------
    def _log(self, msg, tag=None):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _run_in_thread(self, _target, broker, side, symbol, *_rest):
        self.launched.append((broker, side, symbol))

    # real methods under test, bound in
    _select_only_brokers = A.App._select_only_brokers
    _toggle_broker_chip = A.App._toggle_broker_chip
    _trade_execute = A.App._trade_execute
    _live_start = A.App._live_start
    _trade_broker_complete = A.App._trade_broker_complete
    _trade_batch_finish = A.App._trade_batch_finish


def fills(broker, ok=1):
    return {"broker": broker, "ok_accounts": ok, "fail_accounts": 0,
            "shares": 1.0, "errors": [], "state": "success", "accounts": [],
            "fill_price": None}


def batch_of(brokers, origin="desk", symbol="AIFA"):
    return {"pending": set(brokers), "all_brokers": sorted(brokers),
            "results": [], "side": "sell", "symbol": symbol, "qty": "1",
            "dry_run": True, "origin": origin, "finished": False,
            "started": datetime.now()}


# ------------------------------------------------ a sell alert names a broker

def test_a_named_brokerage_becomes_the_only_armed_chip():
    d = Desk()
    d._select_only_brokers(["fidelity"])
    assert d._trade_selected_brokers == {"fidelity"}


def test_arming_one_broker_disarms_the_brokers_left_over_from_last_time():
    d = Desk()
    d._toggle_broker_chip("public")
    d._toggle_broker_chip("chase")
    d._select_only_brokers(["fidelity"])
    assert d._trade_selected_brokers == {"fidelity"}
    assert not d._trade_broker_chips["public"]["selected"]


def test_an_alert_naming_two_brokers_arms_both():
    """The point of the multi-broker desk: one exit, two brokerages, one click."""
    d = Desk()
    assert d._select_only_brokers(["fidelity", "robinhood"]) == ["fidelity",
                                                                "robinhood"]
    assert d._trade_selected_brokers == {"fidelity", "robinhood"}


def test_a_broker_we_do_not_run_leaves_the_selection_alone():
    """Webull is named in the feed and not automated here. Better to hand back
    the ticket untouched than to empty it and look broken."""
    d = Desk()
    d._toggle_broker_chip("public")
    assert d._select_only_brokers(["webull"]) == []
    assert d._trade_selected_brokers == {"public"}


@pytest.mark.parametrize("legs, expected", [
    ([{"broker": "Fidelity", "accounts_low": 10}], ["fidelity"]),
    ([{"broker": "RH"}, {"broker": "fid"}], ["robinhood", "fidelity"]),
    ([{"broker": "Wells Fargo"}], ["wellsfargo"]),
    ([{"broker": "Webull"}], []),                    # named, not automated
    ([{"broker": "Fidelity"}, {"broker": "Fidelity"}], ["fidelity"]),
    ([{"broker": ""}, "not-a-dict"], []),
    ([], []),
])
def test_leg_brokers_map_to_desk_keys(legs, expected):
    assert A._sell_leg_broker_keys({"legs": legs}) == expected


def test_a_sell_alert_click_primes_the_ticket_at_its_broker():
    d = Desk()
    d._toggle_broker_chip("public")          # stale selection from a past trade
    A.App._sell_alert_trade(d, "AIFA", ["fidelity"])
    assert d.shown_frame == "trade"
    assert d.side == "sell"
    assert d._trade_selected_brokers == {"fidelity"}
    assert any("Fidelity" in m for m in d.logs)


def test_a_sell_alert_with_no_broker_we_run_says_so_and_changes_nothing():
    d = Desk()
    d._toggle_broker_chip("public")
    A.App._sell_alert_trade(d, "AIFA", ["webull"])
    assert d._trade_selected_brokers == {"public"}
    assert any("by hand" in m for m in d.logs)


# -------------------------------------------------------- overlapping orders

def test_two_orders_at_different_brokers_both_go_out():
    d = Desk()
    d._select_only_brokers(["fidelity"])
    d._trade_execute()
    d.symbol = "BBBB"
    d._select_only_brokers(["robinhood"])
    d._trade_execute()
    assert d.launched == [("fidelity", "sell", "AIFA"),
                          ("robinhood", "sell", "BBBB")]
    assert d._brokers_in_flight == {"fidelity", "robinhood"}


def test_one_ticket_can_still_fan_out_across_brokers_at_once():
    d = Desk()
    d._select_only_brokers(["fidelity", "robinhood"])
    d._trade_execute()
    assert [b for b, _s, _y in d.launched] == ["fidelity", "robinhood"]


def test_a_second_click_on_the_same_ticket_is_still_refused():
    """The AIFA double-sell. Same brokers selected, so the overlap is total."""
    d = Desk()
    d._select_only_brokers(["robinhood"])
    d._trade_execute()
    d._trade_execute()
    assert d.launched == [("robinhood", "sell", "AIFA")]
    assert d.notes and "already running" in d.notes[-1][0]


def test_an_order_overlapping_a_busy_broker_is_refused_whole():
    """Fidelity is mid-order and the new ticket includes it. Sending only the
    free half would be a different order than the one on screen, so nothing
    goes out."""
    d = Desk()
    d._select_only_brokers(["fidelity"])
    d._trade_execute()
    d.symbol = "BBBB"
    d._select_only_brokers(["fidelity", "public"])
    d._trade_execute()
    assert [b for b, _s, _y in d.launched] == ["fidelity"]
    assert "Fidelity" in d.notes[-1][0]


def test_a_broker_is_free_again_the_moment_it_lands():
    """Not when the slowest broker in its batch lands."""
    d = Desk()
    b = batch_of(["fidelity", "robinhood"])
    d._live_start(b)
    d._trade_broker_complete(b, fills("robinhood"))
    assert d._brokers_in_flight == {"fidelity"}
    assert not b["finished"]


# ------------------------------------------------- the automation-idle flag

def test_the_first_batch_to_land_does_not_report_an_idle_app():
    """mirror / auto-sell wait on _trade_in_flight. While a second ticket is
    still executing, the app is not idle."""
    d = Desk()
    d._select_only_brokers(["fidelity"])
    d._trade_execute()
    d.symbol = "BBBB"
    d._select_only_brokers(["robinhood"])
    d._trade_execute()

    first = d._live_batches[0]
    d._trade_broker_complete(first, fills("fidelity"))
    assert first["finished"]
    assert d._trade_in_flight is True          # robinhood still working

    second = d._live_batches[0]
    d._trade_broker_complete(second, fills("robinhood"))
    assert d._trade_in_flight is False
    assert d._brokers_in_flight == set()


@pytest.mark.parametrize("origin", ["desk", "exit", "mirror", "retry", "etf"])
def test_every_origin_can_clear_the_flag(origin):
    """A flag only the desk can reset is a flag that sticks True until restart —
    the app would refuse to trade at all."""
    d = Desk()
    d._invest_batch_done = lambda: None
    b = batch_of(["public"], origin=origin)
    d._live_start(b)
    d._trade_in_flight = True
    d._trade_broker_complete(b, fills("public"))
    assert d._trade_in_flight is False
    assert d._brokers_in_flight == set()


def test_a_broker_that_never_reports_is_released_with_its_batch():
    """One lost thread must not wedge its chip forever."""
    d = Desk()
    b = batch_of(["fidelity", "robinhood"])
    d._live_start(b)
    b["pending"].discard("fidelity")            # thread vanished
    d._trade_broker_complete(b, fills("robinhood"))
    assert b["finished"]
    assert d._brokers_in_flight == set()
