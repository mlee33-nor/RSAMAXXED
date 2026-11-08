"""Activity feed: search, view chips and hidden broker-step chatter (2026-10-26)."""
from __future__ import annotations

import pytest

import app as A


class _Feed:
    """Just the logging half of App, without building a window."""
    pass


for _n, _v in A.App.__dict__.items():
    if _n.startswith(("_log", "_LOG")) or _n == "LOG_MAX_LINES":
        setattr(_Feed, _n, _v)


@pytest.fixture
def feed():
    f = _Feed()
    f._log_lines = []
    return f


def test_broker_step_chatter_is_a_step(feed):
    assert feed._log_is_step("    fidelity: still purchasing… (45s elapsed)")
    assert feed._log_is_step("    fidelity: LOGIN | goto=https://example.test/login")
    assert feed._log_is_step("    fidelity: TRADE | Fidelity 1 | navigating to trade page")
    assert feed._log_is_step("Stats: refreshed")


def test_a_step_that_failed_stays_visible(feed):
    assert not feed._log_is_step("    fidelity: TRADE | Fidelity 1 · X | preview failed: (020255) "
                                 "Opening buy orders are not allowed online for this security.")
    assert not feed._log_is_step("    fidelity: TRADE | Fidelity 1 | 2 consecutive errors, "
                                 "skipping remaining accounts")


def test_top_level_lines_are_never_steps(feed):
    assert not feed._log_is_step("Mirror: NEW PICK: MASK — executing BUY 1 share")
    assert not feed._log_is_step("Trade: wellsfargo -> success (10 accounts)")


def test_default_view_hides_steps_but_search_finds_them(feed):
    step = "    fidelity: LOGIN | begin"
    assert not feed._log_visible(step, None, "mirror")
    feed._log_query = "login"
    assert feed._log_visible(step, None, "mirror")
    assert not feed._log_visible("Mirror: Scheduled check", None, "mirror")


def test_search_is_case_insensitive(feed):
    feed._log_query = "MaSk"
    assert feed._log_visible("Mirror: NEW PICK: MASK", None, "mirror")


def test_issues_view_keeps_failures_only(feed):
    feed._log_view = "issues"
    assert feed._log_visible("  ✘  Fidelity: preview failed", None, "trade")
    assert feed._log_visible("Trade: chase -> failed: Rejected", "error", "trade")
    assert not feed._log_visible("Trade: robinhood -> success (3 accounts)", None, "trade")


def test_trades_view_includes_sells_and_their_details(feed):
    feed._log_view = "trades"
    assert feed._log_visible("Auto-sell: CPOP — nothing to sell", None, "sell")
    assert feed._log_visible("  ✔  Robinhood filled 3 accounts", None, "trade")
    assert not feed._log_visible("Mirror: Scheduled check (15:45)...", None, "mirror")


def test_detail_lines_inherit_their_parents_category(feed, monkeypatch):
    monkeypatch.setattr(A, "_activity_note", lambda line: None)
    feed._log("Mirror: NEW PICK: MASK — executing BUY 1 share")
    feed._log("  ⚠  Fennel: 1 ok, 4 failed")
    feed._log("Trade: chase -> failed")
    feed._log("  ✘  Chase: Rejected")
    cats = [c for _l, _t, c in feed._log_lines]
    assert cats == ["mirror", "mirror", "trade", "trade"]
    assert feed._log_lines[0][0][10:] == "Mirror: NEW PICK: MASK — executing BUY 1 share"


def test_trades_view_keeps_mirror_run_outcomes(feed):
    feed._log_view = "trades"
    assert feed._log_visible("✘  Nothing bought — 10 accounts failed · 91.0s", None, "mirror")
    assert feed._log_visible("⚠  Bought MASK with errors — 35 ok, 19 failed", None, "mirror")
