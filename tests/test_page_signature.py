"""A page's render cache records what it rendered only once it has rendered.

_show_frame used to write the page signature BEFORE running the renderer, so a
render that raised was remembered as done and the page stayed broken on every
later visit. And the Watchlist keyed its cache on len(picks), so a pick whose
note or date changed never redrew; Analytics never rolled over at midnight.
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


class Pages:
    _show_frame = A.App._show_frame

    def __init__(self, render):
        self._page_sig = {}
        self._render = render
        self.sig = ("watchlist", 1)
        self.raised = []
        self.queue = []
        self.renders = 0

    def _set_active_nav(self, name):
        self._active_nav = name

    def _page_renderer(self, name):
        def base():
            self.renders += 1
            self._render()
        return base

    def _page_signature(self, name):
        return self.sig

    def _raise_page(self, name):
        self.raised.append(name)

    def update_idletasks(self):
        pass

    def after(self, _ms, fn):
        self.queue.append(fn)

    def drain(self):
        while self.queue:
            fn = self.queue.pop(0)
            try:
                fn()
            except RuntimeError:
                pass                       # Tk would report it and carry on


def boom():
    raise RuntimeError("render failed")


def test_a_failed_render_is_not_remembered_as_done():
    p = Pages(boom)
    p._show_frame("watchlist")
    p.drain()
    assert "watchlist" not in p._page_sig
    assert p.raised == ["watchlist"]           # still raised, as before
    p._render = lambda: None
    p._show_frame("watchlist")                 # next visit tries again
    p.drain()
    assert p.renders == 2
    assert p._page_sig["watchlist"] == p.sig


def test_a_successful_render_is_cached():
    p = Pages(lambda: None)
    p._show_frame("watchlist")
    p.drain()
    p._show_frame("watchlist")
    p.drain()
    assert p.renders == 1


def test_two_quick_clicks_render_once_and_raise_after_it():
    p = Pages(lambda: None)
    p._show_frame("watchlist")
    p._show_frame("watchlist")                 # before the first render ran
    p.drain()
    assert p.renders == 1
    assert p.raised == ["watchlist"]           # the newer click's raise
    assert p._page_sig["watchlist"] == p.sig


class Sig:
    _page_signature = A.App._page_signature

    def __init__(self, picks):
        self._quick_picks = picks
        self._watchlist = ["IPDN"]
        self._quotes_rev = 3
        self._etf_quotes = {}

    def _journal_version(self):
        return (1, 2)


def test_the_watchlist_signature_sees_a_note_change_at_the_same_count():
    a = Sig([{"symbol": "IPDN", "note": "Reg Alert", "date": "2026-09-24"}])
    b = Sig([{"symbol": "IPDN", "note": "conditional", "date": "2026-09-24"}])
    assert a._page_signature("watchlist") != b._page_signature("watchlist")


def test_the_analytics_signature_rolls_over_with_the_date(monkeypatch):
    s = Sig([])
    assert s._page_signature("stats")[-1] == date.today().isoformat()
