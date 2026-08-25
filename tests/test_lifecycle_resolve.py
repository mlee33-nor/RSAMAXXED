"""An account that would not read is not an account holding nothing.

The bug this pins: `resolve()` skipped every account with ok=False and then, if
none of the survivors reported the symbol, filed the broker under `missing` --
which the UI renders as "No position found at Fidelity -- skipped" and which
auto-sell treats as a settled answer and never retries. A customer whose session
had died on the one account holding the shares was told he did not own them.
"""
from __future__ import annotations

import lifecycle
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow


def _task(symbol="AIFA", alert="AIFA", brokers=("Public",)):
    return lifecycle.SellTask(symbol=symbol, alert_symbol=alert,
                              alert_date="6/18/26", status="fractional",
                              brokers=tuple(brokers), accounts=len(brokers))


def _acct(label, ok=True, holdings=()):
    return AccountOutput(account_id=label, ok=ok, holdings=list(holdings))


def _hold(symbol, shares):
    return HoldingRow(symbol=symbol, shares=shares)


def _out(state, accounts):
    return BrokerOutput(broker="Public", state=state, accounts=list(accounts))


def test_every_account_read_and_none_holds_it_is_missing():
    """The real answer. A fraction swept to cash IS an empty position."""
    out = _out("success", [_acct("P1"), _acct("P2")])
    r = lifecycle.resolve(_task(), {"public": out})
    assert r.missing == ("Public",)
    assert r.errors == ()


def test_unreadable_account_is_not_reported_as_no_position():
    """The bug. One account failed, the rest are empty -- we did NOT find out."""
    out = _out("partial", [_acct("P1"), _acct("P2", ok=False)])
    r = lifecycle.resolve(_task(), {"public": out})
    assert r.missing == (), "an unread account must never read as 'no position'"
    assert r.errors == ("Public",)


def test_no_readable_account_at_all_is_an_error():
    """'success' with nothing readable behind it tells us nothing either."""
    for accounts in ([], [_acct("P1", ok=False)]):
        r = lifecycle.resolve(_task(), {"public": _out("success", accounts)})
        assert r.errors == ("Public",)
        assert r.missing == ()


def test_position_found_alongside_an_unread_account_still_sells():
    """The order goes -- sized off what we could see -- and says what it missed."""
    out = _out("partial", [
        _acct("P1", holdings=[_hold("AIFA", 0.05)]),
        _acct("P2", holdings=[_hold("AIFA", 0.05)]),
        _acct("P3", ok=False),
    ])
    r = lifecycle.resolve(_task(), {"public": out})
    assert r.ok
    leg = r.legs[0]
    assert leg.qty == "0.05"
    assert leg.accounts == 2
    assert leg.unread == 1
    assert not leg.complete
    assert r.missing == () and r.errors == ()


def test_clean_read_leaves_the_leg_complete():
    out = _out("success", [_acct("P1", holdings=[_hold("AIFA", 0.05)])])
    leg = lifecycle.resolve(_task(), {"public": out}).legs[0]
    assert leg.unread == 0 and leg.complete


def test_renamed_ticker_matches_either_spelling():
    """Bought AGAE, broker reports AIFA, order goes in AIFA."""
    out = _out("success", [_acct("P1", holdings=[_hold("AGAE", 0.05)])])
    r = lifecycle.resolve(_task(symbol="AIFA", alert="AGAE"), {"public": out})
    assert r.ok and r.legs[0].qty == "0.05"


def test_broker_that_failed_or_never_answered_is_an_error():
    assert lifecycle.resolve(_task(), {"public": None}).errors == ("Public",)
    assert lifecycle.resolve(_task(), {}).errors == ("Public",)
    failed = _out("failed", [_acct("P1", ok=False)])
    assert lifecycle.resolve(_task(), {"public": failed}).errors == ("Public",)


def test_zero_and_unparseable_balances_are_not_positions():
    """shares=None (Fidelity's 0-qty row) and 0.0 both mean nothing to sell."""
    out = _out("success", [_acct("P1", holdings=[_hold("AIFA", None),
                                                 _hold("AIFA", 0.0)])])
    r = lifecycle.resolve(_task(), {"public": out})
    assert r.missing == ("Public",) and not r.ok
