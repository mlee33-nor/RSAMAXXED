"""Paint suspension and page-swap bookkeeping — no Tk window needed.

_frozen turns a window's painting off for the length of a block. The one
failure that matters is leaving it off: that is a blank, dead-looking app. So
these pin the contract — always back on, only at the outermost level, and never
at the cost of swallowing the body's exception.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as A


class FakeUser32:
    def __init__(self):
        self.calls = []

    def SendMessageW(self, hwnd, msg, wparam, lparam):
        self.calls.append(("redraw", hwnd, wparam))
        return 0

    def RedrawWindow(self, hwnd, rect, rgn, flags):
        self.calls.append(("repaint", hwnd, flags))
        return 1


class Widget:
    def __init__(self, hwnd=42, mapped=True):
        self.hwnd, self.mapped = hwnd, mapped

    def winfo_id(self):
        return self.hwnd

    def winfo_ismapped(self):
        return self.mapped


@pytest.fixture
def user32(monkeypatch):
    fake = FakeUser32()
    monkeypatch.setattr(A, "_USER32", fake)
    monkeypatch.setattr(A, "_freeze_depth", {})
    return fake


def test_painting_is_suspended_then_restored_and_repainted(user32):
    with A._frozen(Widget()):
        assert user32.calls == [("redraw", 42, 0)]
    assert user32.calls[1] == ("redraw", 42, 1)
    assert user32.calls[2][0] == "repaint"
    assert user32.calls[2][2] & A._RDW_ALLCHILDREN
    assert user32.calls[2][2] & A._RDW_UPDATENOW


def test_an_exception_still_turns_painting_back_on(user32):
    with pytest.raises(RuntimeError):
        with A._frozen(Widget()):
            raise RuntimeError("render blew up")
    assert ("redraw", 42, 1) in user32.calls
    assert A._freeze_depth == {}


def test_nested_freezes_only_unfreeze_at_the_outermost(user32):
    w = Widget()
    with A._frozen(w):
        with A._frozen(w):
            pass
        # the inner exit must not have turned painting back on mid-render
        assert ("redraw", 42, 1) not in user32.calls
    assert user32.calls.count(("redraw", 42, 0)) == 1
    assert user32.calls.count(("redraw", 42, 1)) == 1


def test_an_unmapped_window_is_left_alone(user32):
    """WM_SETREDRAW(TRUE) sets WS_VISIBLE — un-freezing a window Tk hid
    would show it."""
    with A._frozen(Widget(mapped=False)):
        pass
    assert user32.calls == []


def test_no_user32_means_no_suspension(monkeypatch):
    monkeypatch.setattr(A, "_USER32", None)
    ran = []
    with A._frozen(Widget()):
        ran.append(1)
    assert ran == [1]


def test_a_failing_win32_call_does_not_break_the_body(monkeypatch):
    class Broken:
        def SendMessageW(self, *a):
            raise OSError("no")

        def RedrawWindow(self, *a):
            raise OSError("no")

    monkeypatch.setattr(A, "_USER32", Broken())
    monkeypatch.setattr(A, "_freeze_depth", {})
    ran = []
    with A._frozen(Widget()):
        ran.append(1)
    assert ran == [1]
    assert A._freeze_depth == {}


def test_the_composited_window_option_is_gone():
    """Removed, not just off: measured ~7x slower page switches on the target
    machine, so there is nothing left to opt in to."""
    assert not hasattr(A, "_set_composited")


# ------------------------------------------------------------ page bookkeeping

class Pages:
    """Enough App for the show/defer bookkeeping."""

    def __init__(self, active):
        self._active_nav = active
        self._page_sig = {}
        self.rendered = []
        self._frames = {"mirror": Widget(mapped=False),
                        "watchlist": Widget(mapped=False)}

    _page_hidden = A.App._page_hidden
    _invalidate_page = A.App._invalidate_page
    _render_or_defer = A.App._render_or_defer

    def _page_renderer(self, name):
        return lambda: self.rendered.append(name)

    def _page_signature(self, name):
        return (name, 1)

    def update_idletasks(self):
        pass


def test_a_hidden_page_is_marked_stale_not_rendered():
    p = Pages("dashboard")
    p._page_sig["mirror"] = ("mirror", 0)
    p._render_or_defer("mirror")
    assert p.rendered == []
    assert "mirror" not in p._page_sig        # the next visit renders it


def test_the_page_on_screen_renders_and_records_its_signature():
    p = Pages("mirror")
    p._render_or_defer("mirror")
    assert p.rendered == ["mirror"]
    assert p._page_sig["mirror"] == ("mirror", 1)   # next visit can skip


def test_the_sidebar_restyles_only_the_two_items_that_change():
    class Nav:
        _active_nav = "dashboard"
        _nav_items = {n: {} for n in ("dashboard", "watchlist", "trade",
                                      "mirror", "exits", "stats")}
        styled = []

        def _style_nav(self, name, state):
            self.styled.append((name, state))

    n = Nav()
    A.App._set_active_nav(n, "mirror")
    assert sorted(n.styled) == [("dashboard", "idle"), ("mirror", "active")]
    assert n._active_nav == "mirror"


def test_positions_page_is_gone():
    names = [name for _s, items in A.App._NAV_SECTIONS for name, _l, _i in items]
    assert "holdings" not in names
    assert "holdings" not in A.App._PAGE_META
    for attr in ("_build_holdings", "_render_allocation", "_draw_allocation_pie",
                 "_holdings_refresh", "_recompute_allocation"):
        assert not hasattr(A.App, attr), attr


# ------------------------------------------------ Partial / Purchased: 14 days

from datetime import date as _date


def _p(sym, d):
    return {"symbol": sym, "date": d, "note": "Reg Alert"}


def test_only_the_last_fourteen_days_show_by_default():
    today = _date(2026, 9, 25)
    picks = [_p("NEW", "2026-09-24"), _p("EDGE", "2026-09-11"),
             _p("OLD", "2026-09-10"), _p("ANCIENT", "2026-06-01")]
    recent, older = A._split_recent_picks(picks, 14, today)
    assert [p["symbol"] for p in recent] == ["NEW", "EDGE"]
    assert [p["symbol"] for p in older] == ["OLD", "ANCIENT"]


def test_a_pick_with_no_readable_date_is_never_hidden():
    """It cannot be aged honestly, and hiding it behind "Show older" would
    lose it from view."""
    recent, older = A._split_recent_picks(
        [_p("X", ""), _p("Y", "someday")], 14, _date(2026, 9, 25))
    assert [p["symbol"] for p in recent] == ["X", "Y"] and older == []


def test_the_default_window_is_fourteen_days():
    assert A.PICK_TAB_RECENT_DAYS == 14


def test_coverage_is_computed_once_per_journal_version(monkeypatch):
    calls = []
    real = A._pick_coverage_uncached
    monkeypatch.setattr(A, "_pick_coverage_uncached",
                        lambda picks: calls.append(1) or real(picks))
    monkeypatch.setattr(A, "_COVERAGE_MEMO", {})
    picks = [_p("AAA", "2026-09-20")]
    A._pick_coverage(picks)
    A._pick_coverage(picks)
    A._pick_coverage(list(picks))       # same content, new list: still a hit
    assert calls == [1]
    A._pick_coverage([_p("BBB", "2026-09-20")])     # different picks: recompute
    assert calls == [1, 1]


# ---- the previous page bleeding through (2026-09-29) ----------------------
#
# WM_SETREDRAW(FALSE) discards what Tk draws inside the freeze, so the repaint
# after it is queued, and the old page's text showed through until the event
# loop got to it. _raise_page now services those repaints before returning.


def test_a_click_during_the_paint_is_run_after_it_not_inside_it():
    app = types.SimpleNamespace(_painting=True, later=[])
    app.after = lambda ms, fn: app.later.append(fn)
    app._set_active_nav = lambda name: pytest.fail("swap nested inside a paint")
    A.App._show_frame(app, "exits")
    assert len(app.later) == 1


def test_painting_now_never_raises_and_always_clears_the_flag():
    class _Tk:
        def dooneevent(self, flags):
            raise A.tk.TclError("application destroyed")
    app = types.SimpleNamespace(tk=_Tk(), update_idletasks=lambda: None)
    A.App._paint_now(app)
    assert app._painting is False


def test_painting_now_stops_when_the_queue_is_empty():
    served = []

    class _Tk:
        def dooneevent(self, flags):
            served.append(flags)
            return len(served) < 3          # three events, then empty
    idle = []
    app = types.SimpleNamespace(tk=_Tk(), update_idletasks=lambda: idle.append(1))
    A.App._paint_now(app)
    assert len(served) == 3 and idle == [1]
