"""A scrolling page whose content shrinks must not strand the view past its end.

Command Center -> Purchased -> Show older -> scroll to the bottom -> Hide older
left the page blank: the scroll region stayed at the tall height and nothing
pulled the view back -- once the content sat wholly above the viewport the
canvas unmapped the frame and no <Configure> fired at all. _bind_scrollregion
listens for the unmap too, sizes from the requested height, and clamps.

Headless: fakes stand in for the canvas and frame, so no window is ever shown.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


class Canvas:
    def __init__(self, view_h, top, width=1175):
        self.view_h, self.top, self.width = view_h, top, width
        self.region = None

    def configure(self, scrollregion):
        self.region = scrollregion

    def winfo_width(self):
        return self.width

    def winfo_height(self):
        return self.view_h

    def canvasy(self, _y):
        return self.top

    def yview_moveto(self, frac):
        self.top = frac * self.region[3]


class Inner:
    def __init__(self, req_h):
        self.req_h = req_h
        self.bound = {}

    def winfo_reqheight(self):
        return self.req_h

    def bind(self, seq, fn, add=None):
        self.bound[seq] = fn


def test_shrinking_content_pulls_the_view_back_to_the_last_screen():
    """The QA repro's numbers: at the bottom of 8,375px, content drops to 2,202."""
    cv, inner = Canvas(view_h=637, top=7738), Inner(2202)
    A._fit_scrollregion(cv, inner)
    assert cv.region == (0, 0, 1175, 2202)
    assert abs(cv.top - (2202 - 637)) < 1e-6           # the last full screen


def test_content_that_now_fits_goes_back_to_the_top():
    cv, inner = Canvas(view_h=637, top=900), Inner(400)
    A._fit_scrollregion(cv, inner)
    assert cv.top == 0


def test_a_view_still_inside_the_content_is_left_alone():
    cv, inner = Canvas(view_h=637, top=300), Inner(2202)
    A._fit_scrollregion(cv, inner)
    assert cv.top == 300


def test_both_the_resize_and_the_unmap_resync_the_region():
    cv, inner = Canvas(view_h=637, top=7738), Inner(2202)
    A._bind_scrollregion(cv, inner)
    assert set(inner.bound) == {"<Configure>", "<Unmap>"}
    inner.bound["<Unmap>"](None)                       # the only event that fires
    assert cv.region[3] == 2202 and cv.top + 637 <= 2202 + 1e-6
