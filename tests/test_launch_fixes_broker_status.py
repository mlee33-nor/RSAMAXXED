"""The Command Center's Broker Status rows come from a plan that can be rebuilt.

The card was built once from .env at startup, so a broker linked later never
appeared until a restart. The row list is now a pure function that
_render_broker_status (called from _refresh_linked_brokers) draws from. The
drawing itself needs Tk and is not exercised here — no window is ever opened.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


def test_nothing_linked_is_an_empty_plan():
    assert A._broker_status_plan([], lambda: [1], lambda: {}) == []


def test_public_gets_a_row_per_login_and_others_one_each():
    plan = A._broker_status_plan(
        ["fidelity", "public", "robinhood"], lambda: [1, 2],
        lambda: {"fidelity": 10})
    assert plan == [
        ("broker", "fidelity", "Fidelity", "10 accounts"),
        ("public", 1, "Public P1", "credentials set"),
        ("public", 2, "Public P2", "credentials set"),
        ("broker", "robinhood", "Robinhood", "credentials set"),
    ]


def test_public_logins_are_not_read_when_public_is_not_linked():
    def boom():
        raise AssertionError("asked for Public tokens")
    assert A._broker_status_plan(["chase"], boom, lambda: {}) == [
        ("broker", "chase", "Chase", "credentials set")]


def test_refresh_linked_brokers_rebuilds_the_card():
    calls = []

    class S:
        _refresh_linked_brokers = A.App._refresh_linked_brokers

        def _render_trade_broker_chips(self):
            calls.append("chips")

        def _render_mirror_broker_chips(self):
            calls.append("mirror")

        def _render_linked_count(self):
            calls.append("count")

        def _render_broker_status(self):
            calls.append("status")

        def _log(self, *a, **k):
            pass

    S()._refresh_linked_brokers()
    assert "status" in calls
