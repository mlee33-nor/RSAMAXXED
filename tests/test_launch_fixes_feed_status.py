"""An offline feed pull counts as a failed pull.

_cloud_picks() returns None on a network error without recording an auth
error, so `ok = _PICKS_AUTH_ERROR is None` read an offline pull as good: the
status bar said "just now" and the 5-30 minute retry never scheduled.

Pure logic: the cloud client is a stand-in; nothing touches the network.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A

cloud_sync = pytest.importorskip("cloud_sync")


def _client(picks=None, sells=None):
    """A CloudSync stand-in: a value to return, or an exception to raise."""
    class _C:
        def fetch_picks(self):
            if isinstance(picks, Exception):
                raise picks
            return picks

        def fetch_sells(self):
            if isinstance(sells, Exception):
                raise sells
            return sells
    return _C


class _Worker:
    _feed_pull_worker = A.App._feed_pull_worker

    def __init__(self):
        self.results = []

    def after(self, ms, fn=None):
        if fn is not None:
            fn()

    def _render_quick_picks(self, picks):
        pass

    def _feed_result(self, ok):
        self.results.append(ok)

    def _sells_arrived(self, why):
        pass


@pytest.fixture()
def cloud(monkeypatch):
    monkeypatch.setattr(A, "CLOUD_AVAILABLE", True)
    monkeypatch.setattr(A, "_PICKS_AUTH_ERROR", None)
    monkeypatch.setattr(A, "_PICKS_LAST_FETCH_OK", False)
    # The picks half without the on-disk cache: just the cloud read.
    monkeypatch.setattr(A, "_fetch_quick_picks", lambda: A._cloud_picks() or [])
    monkeypatch.setattr(A, "_save_sells", lambda rows: None)
    monkeypatch.setattr(A, "_load_sells", lambda: [])

    def _use(**kw):
        monkeypatch.setattr(A.cloud_sync, "CloudSync", _client(**kw))
    return _use


def test_offline_picks_are_not_ok(cloud):
    cloud(picks=cloud_sync.CloudError("Can't reach"), sells=[])
    assert A._cloud_picks() is None
    assert A._PICKS_LAST_FETCH_OK is False
    assert A._PICKS_AUTH_ERROR is None          # an outage, not a password


def test_a_good_read_is_ok(cloud):
    cloud(picks=[{"symbol": "GRNQ"}], sells=[])
    assert A._cloud_picks() == [{"symbol": "GRNQ"}]
    assert A._PICKS_LAST_FETCH_OK is True


def test_an_offline_pull_reports_failure_so_the_retry_schedules(cloud):
    cloud(picks=cloud_sync.CloudError("Can't reach"),
          sells=cloud_sync.CloudError("Can't reach"))
    w = _Worker()
    w._feed_pull_worker()
    assert w.results == [False]


def test_sells_answering_cannot_vouch_for_failed_picks(cloud):
    cloud(picks=cloud_sync.CloudError("Can't reach"), sells=[])
    w = _Worker()
    w._feed_pull_worker()
    assert w.results == [False]


def test_a_failed_sells_call_fails_the_pull(cloud):
    cloud(picks=[], sells=cloud_sync.CloudError("Can't reach"))
    w = _Worker()
    w._feed_pull_worker()
    assert w.results == [False]


def test_a_healthy_pull_is_ok(cloud):
    cloud(picks=[], sells=[])
    w = _Worker()
    w._feed_pull_worker()
    assert w.results == [True]


def test_feed_result_schedules_a_retry_on_failure(monkeypatch):
    monkeypatch.setattr(A, "_PICKS_AUTH_ERROR", None)
    calls = []
    s = types.SimpleNamespace(
        _feed_retry_id=None, _feed_fail_streak=0, _notified_no_plays_key=False,
        _update_feed_status=lambda: None,
        after=lambda ms, fn=None: calls.append(ms) or "id",
        after_cancel=lambda i: None,
        _run_in_thread=lambda *a: None,
        _feed_pull_worker=lambda: None,
        _push_notification=lambda *a, **k: None)
    A.App._feed_result(s, False)
    assert calls == [300_000] and not hasattr(s, "_feed_last_ok")
