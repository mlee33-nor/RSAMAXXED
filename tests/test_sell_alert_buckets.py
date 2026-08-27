"""Sell alerts are per-BROKERAGE, so they must be bucketed that way.

The feed posts an exit per brokerage: HAO at Public at 16:23 and HAO at Wells
Fargo at 17:40 are two separate alerts on the same ticker, an hour apart. All
of the bucketing was done per SYMBOL, so the moment Public's HAO was sold, the
brand-new Wells Fargo exit — ten accounts held, nothing sold — was filed under
Partial and vanished from the tab you work from. On the live board that hid six
actionable exits and mislabelled every fully-closed leg as half-done.

The App class cannot be instantiated headlessly (CustomTkinter's DPI tracker
takes the process down), so the real methods are called unbound against a stub
— same approach as test_mirror_pacing and test_concurrent_orders.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


class Sells:
    """Just enough App for the three bucketing decisions."""

    _sell_alert_scope = A.App._sell_alert_scope
    _sell_alert_is_update = A.App._sell_alert_is_update
    _sell_alert_state = A.App._sell_alert_state


def alert(symbol, *brokers):
    return {"symbol": symbol,
            "legs": [{"broker": b, "accounts_low": 1} for b in brokers]}


def accounts(broker, n):
    return {(broker, f"{broker}-{i}") for i in range(n)}


# HAO: bought at four brokers, sold out at two of them, still fully held at
# Wells Fargo. This is the exact shape that went wrong on 2026-08-27.
BOUGHT = {"HAO": accounts("public", 20) | accounts("robinhood", 3)
                 | accounts("wellsfargo", 10) | accounts("fennel", 2)}
SOLD = {"HAO": accounts("public", 20) | accounts("robinhood", 3)}
OPEN = {("wellsfargo", "HAO"), ("fennel", "HAO")}


def test_a_fresh_leg_of_a_part_sold_play_is_a_sell_alert_not_partial():
    s = Sells()
    wf = alert("HAO", "Wells Fargo")
    assert s._sell_alert_state(wf, OPEN, BOUGHT, SOLD) == "alerts"
    # and it is called out, because the name looks like old news
    assert s._sell_alert_is_update(wf, SOLD) is True


def test_a_leg_we_are_fully_out_of_reads_sold_not_partial():
    s = Sells()
    for broker in ("Public", "Robinhood"):
        a = alert("HAO", broker)
        assert s._sell_alert_state(a, OPEN, BOUGHT, SOLD) == "sold"


def test_partial_is_reserved_for_a_leg_half_sold_at_its_own_brokers():
    s = Sells()
    half = {"HAO": accounts("wellsfargo", 4)}      # 4 of the 10 WF accounts out
    assert s._sell_alert_state(
        alert("HAO", "Wells Fargo"), OPEN, BOUGHT, half) == "partial"


def test_counts_are_scoped_to_the_brokers_the_alert_names():
    s = Sells()
    keys, bought_here, sold_here, still_open = s._sell_alert_scope(
        alert("HAO", "Wells Fargo"), OPEN, BOUGHT, SOLD)
    assert keys == ("wellsfargo",)
    assert len(bought_here) == 10      # not the 35 that ever held HAO
    assert sold_here == set()
    assert still_open is True


def test_an_exit_we_never_bought_is_an_alert():
    s = Sells()
    assert s._sell_alert_state(alert("ZZZZ", "Public"), OPEN, BOUGHT, SOLD) == "alerts"
    assert s._sell_alert_is_update(alert("ZZZZ", "Public"), SOLD) is False


def test_an_unautomated_brokerage_falls_back_to_the_whole_symbol():
    """The feed also calls exits at Webull and Vanguard. There is no narrower
    question to ask about those, so they keep the old symbol-level answer."""
    s = Sells()
    a = alert("HAO", "Webull")
    keys, bought_here, sold_here, still_open = s._sell_alert_scope(
        a, OPEN, BOUGHT, SOLD)
    assert keys == ()
    assert bought_here == BOUGHT["HAO"]
    assert still_open is True
    assert s._sell_alert_state(a, OPEN, BOUGHT, SOLD) == "partial"
    assert s._sell_alert_is_update(a, SOLD) is False


def test_the_first_exit_on_a_wholly_unsold_play_is_not_flagged_updated():
    """UPDATED means 'you are already part-way out of this one'. A play with no
    sales anywhere is just an ordinary new alert."""
    s = Sells()
    assert s._sell_alert_is_update(alert("HAO", "Wells Fargo"), {}) is False
