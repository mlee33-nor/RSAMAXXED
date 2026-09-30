"""Hidden pages sit out window resizes; the page being raised catches up.

Every stacked page followed the window (place relwidth=1/relheight=1), so each
step of a window drag re-laid-out all ten pages -- 1.1-2.0s per step, measured
in the QA sandbox, almost all of it native Tk layout and ~100 CTk frame redraws
on pages nobody could see. Hidden pages are now pinned at an absolute size.

Headless: fake frames record their placement; no window is created.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


class Frame:
    def __init__(self, name):
        self.name = name
        self.place = {"relwidth": 1, "relheight": 1, "width": 0, "height": 0}
        self.raised = 0

    def place_configure(self, **kw):
        self.place.update(kw)

    def tkraise(self):
        self.raised += 1

    def winfo_ismapped(self):
        return False                       # keeps _frozen a no-op


class Content:
    def winfo_width(self):
        return 1175

    def winfo_height(self):
        return 700


class Label:
    def configure(self, **_kw):
        pass


class Pages:
    _pin_hidden_pages = A.App._pin_hidden_pages
    _unpin_page = A.App._unpin_page
    _raise_page = A.App._raise_page
    _paint_now = lambda self: None          # no Tk here: nothing to service
    _PAGE_META = A.App._PAGE_META

    def __init__(self):
        self._frames = {n: Frame(n) for n in ("dashboard", "exits", "stats")}
        self._content = Content()
        self._content_wrap = Frame("wrap")
        self._page_header = Frame("header")
        self._page_icon = self._page_title = self._page_subtitle = Label()
        self.calls = []

    def _render_header_actions(self, name):
        pass

    def _flush_resize(self, name):
        self.calls.append(("flush", name, dict(self._frames[name].place)))

    def update_idletasks(self):
        self.calls.append(("idle",))


def following(f):
    return f.place["relwidth"] == 1 and f.place["width"] == 0


def test_raising_a_page_pins_every_other_page_at_the_current_size():
    p = Pages()
    p._raise_page("dashboard")
    assert following(p._frames["dashboard"])
    for n in ("exits", "stats"):
        assert p._frames[n].place == {"relwidth": 0, "relheight": 0,
                                      "width": 1175, "height": 700}


def test_the_raised_page_follows_the_window_again_before_it_catches_up():
    p = Pages()
    p._raise_page("dashboard")
    p.calls.clear()
    p._raise_page("stats")
    flush = next(c for c in p.calls if c[0] == "flush")
    assert flush[2]["relwidth"] == 1 and flush[2]["width"] == 0   # unpinned first
    assert following(p._frames["stats"])
    assert not following(p._frames["dashboard"])               # now pinned


def test_nothing_is_pinned_before_the_window_has_a_size():
    p = Pages()
    p._content.winfo_width = lambda: 1
    p._raise_page("dashboard")
    assert all(following(f) for f in p._frames.values())
