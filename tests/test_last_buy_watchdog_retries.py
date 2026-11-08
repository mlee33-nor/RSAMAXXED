"""Past-last-buy rejection, per-broker leg watchdog budgets, and the retry caps.

Regression for 2026-10-02: a hung Chase buy of SUGP held the mirror queue for
2h28m (every broker got the slowest broker's budget), and POAS never bought.
"""
from datetime import date

import app as A


def test_quick_broker_written_off_in_15_minutes():
    for broker in ("chase", "robinhood", "public", "fennel", "schwab", "sofi"):
        assert A._broker_leg_budget_s(broker) == 15 * 60


def test_slow_browser_brokers_keep_their_own_budget(monkeypatch):
    monkeypatch.setattr(A.broker_logins, "login_count", lambda b: 1)
    # Fidelity 30 min + 5 min stall slack + 10 min watchdog slack
    assert A._broker_leg_budget_s("fidelity") == 1800 + 300 + 600
    monkeypatch.setattr(A.broker_logins, "login_count", lambda b: 3)
    assert A._broker_leg_budget_s("wellsfargo") == 1200 * 3 + 300 + 600
    # ...and none of that leaks onto Chase any more.
    assert A._broker_leg_budget_s("chase") == 15 * 60


PICKS = [
    {"symbol": "POAS", "note": "Reg Alert", "date": "2026-10-02", "last_buy": "2026-10-09"},
    {"symbol": "OLD", "note": "Reg Alert", "date": "2026-08-01"},
    {"symbol": "BACK", "note": "Reg Alert", "date": "2026-09-01", "last_buy": "2026-09-03"},
    {"symbol": "BACK", "note": "Reg Alert", "date": "2026-10-08", "last_buy": "2026-10-15"},
]


def test_past_last_buy_rejects_after_the_day():
    assert A._past_last_buy("POAS", PICKS, date(2026, 10, 10)) == "2026-10-09"
    assert A._past_last_buy("poas", PICKS, date(2026, 10, 10)) == "2026-10-09"


def test_last_day_itself_is_still_buyable():
    assert A._past_last_buy("POAS", PICKS, date(2026, 10, 9)) is None
    assert A._past_last_buy("POAS", PICKS, date(2026, 10, 3)) is None


def test_no_last_buy_or_unknown_symbol_is_not_blocked():
    assert A._past_last_buy("OLD", PICKS, date(2026, 11, 1)) is None
    assert A._past_last_buy("NOPE", PICKS, date(2026, 11, 1)) is None
    assert A._past_last_buy("", PICKS, date(2026, 11, 1)) is None


def test_newest_alert_for_a_symbol_wins():
    # The September play closed, but the October re-alert is open.
    assert A._past_last_buy("BACK", PICKS, date(2026, 10, 10)) is None
    assert A._past_last_buy("BACK", PICKS, date(2026, 10, 16)) == "2026-10-15"


def test_past_last_buy_refusal_is_never_retried():
    leg = {"broker": "chase", "ok_accounts": 0, "fail_accounts": 1,
           "errors": [f"POAS not bought — {A.PAST_LAST_BUY_MARK} (2026-10-09); "
                      f"the play is closed — nothing was sent"],
           "accounts": []}
    assert not A._mirror_leg_retryable(leg)


def test_one_retry_only():
    assert A.MIRROR_MAX_ATTEMPTS == 2
    assert A.AUTOSELL_MAX_ATTEMPTS == 2
    assert A.AUTOSELL_RETRY_BACKOFF_MS == 30 * 60 * 1000
