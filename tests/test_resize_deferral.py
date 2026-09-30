"""Window resizes must not redraw pages nobody can see, nor redraw per event.

Dragging the window edge froze the app for 1.1-2.0s: every stacked page is
mapped, so every hidden list and all seven Analytics charts redrew on every
<Configure> -- and each chart canvas's event redrew all seven charts.
"""
from __future__ import annotations

import sys
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
from modules.canvas_rows import RowCanvas


@pytest.fixture()
def rc(tk_root, monkeypatch):
    c = RowCanvas(tk_root, bg="#000000")
    c.draws = 0

    def recipe(_rc, _y, _w):
        c.draws += 1
        return 10
    c.set_rows([recipe])
    c._drawn_width = 400
    c.draws = 0
    yield c
    RowCanvas._stale.discard(c)
    c.destroy()


def cfg(w):
    return types.SimpleNamespace(width=w)


def test_a_hidden_list_only_goes_stale(rc, monkeypatch):
    monkeypatch.setattr(RowCanvas, "is_hidden", staticmethod(lambda _rc: True))
    rc._on_configure(cfg(700))
    assert rc.draws == 0 and rc in RowCanvas._stale


def test_flushing_redraws_only_the_lists_of_the_page_being_shown(rc, monkeypatch):
    monkeypatch.setattr(RowCanvas, "is_hidden", staticmethod(lambda _rc: True))
    rc._on_configure(cfg(700))
    assert RowCanvas.flush_stale(lambda _rc: False) == 0
    assert rc.draws == 0 and rc in RowCanvas._stale
    monkeypatch.setattr(rc, "winfo_width", lambda: 700)
    assert RowCanvas.flush_stale(lambda c: c is rc) == 1
    assert rc.draws == 1 and rc not in RowCanvas._stale


def test_a_burst_on_the_visible_page_redraws_once_after_it_stops(rc, tk_root, monkeypatch):
    monkeypatch.setattr(RowCanvas, "is_hidden", staticmethod(lambda _rc: False))
    monkeypatch.setattr(rc, "winfo_width", lambda: 720)
    for w in range(701, 721):
        rc._on_configure(cfg(w))
    assert rc.draws == 0                        # nothing yet: still resizing
    deadline = time.time() + 1.0
    while time.time() < deadline and rc.draws == 0:
        tk_root.update()
        time.sleep(0.01)
    assert rc.draws == 1


def test_the_first_real_layout_is_not_delayed(rc, monkeypatch):
    monkeypatch.setattr(RowCanvas, "is_hidden", staticmethod(lambda _rc: True))
    rc._drawn_width = 0                         # drawn before it had a width
    rc._on_configure(cfg(640))
    assert rc.draws == 1


class Charts:
    """Just enough App for the chart resize scheduling."""

    _RESIZE_REDRAW_MS = 60
    _schedule_chart_redraw = A.App._schedule_chart_redraw
    _chart_redraw_due = A.App._chart_redraw_due
    _flush_resize = A.App._flush_resize

    def __init__(self, active):
        self._active_nav = active
        self._frames = {}
        self.redraws = 0
        self.timers = []

    def _page_hidden(self, name):
        return self._active_nav != name

    def after(self, _ms, fn):
        self.timers.append(fn)
        return f"id{len(self.timers)}"

    def after_cancel(self, _id):
        self.timers.pop(0)

    def _redraw_charts(self):
        self._charts_stale = False
        self.redraws += 1


def test_seven_chart_events_on_a_hidden_page_draw_nothing_until_shown():
    c = Charts(active="dashboard")
    for _ in range(7):
        c._schedule_chart_redraw()
    assert c.redraws == 0 and c.timers == [] and c._charts_stale
    c._active_nav = "stats"
    c._flush_resize("stats")
    assert c.redraws == 1


def test_seven_chart_events_on_screen_coalesce_to_one_redraw():
    c = Charts(active="stats")
    for _ in range(7):
        c._schedule_chart_redraw()
    assert len(c.timers) == 1
    c.timers.pop()()
    assert c.redraws == 1


def test_leaving_the_page_before_the_timer_fires_defers_the_redraw():
    c = Charts(active="stats")
    c._schedule_chart_redraw()
    c._active_nav = "exits"
    c.timers.pop()()
    assert c.redraws == 0 and c._charts_stale
