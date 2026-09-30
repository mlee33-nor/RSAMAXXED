"""Lists drawn as canvas items instead of widgets.

Why this exists: on Windows every Tk widget is a real child window (an HWND),
and on the machines this app runs on that is expensive in exactly the ways a
list feels — measured on the target machine:

    400 labels in rows      create 30-40ms   map+layout 370-460ms   destroy 530-900ms
    the same, canvas items  create 10-25ms   map 10-15ms            destroy 2-3ms

A page of widget rows therefore took most of a second to appear, most of a
second to tear down, and a couple of hundred milliseconds just to repaint when
its tab was raised — and you could watch it happen, one box at a time. A list
drawn on ONE canvas is one window no matter how many rows it has.

A RowCanvas holds a list of *recipes*: callables `recipe(rc, y, width) -> h`
that draw one row at `y` and return the height they used. Redrawing is cheap
enough to do wholesale, so there is no diffing: changing a row (expanding it,
a new quote) re-runs the recipes, and a width change reflows everything.

Clicks and hover are canvas tag bindings, which is what lets a row carry both a
whole-row click and buttons of its own: a button's items carry the row's hover
tag (so the row stays lit under the pointer) but not its click tag (so a click
on the button does only the button's thing).
"""
from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
import weakref
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

Recipe = Callable[["RowCanvas", int, int], int]


def _mix(c1: str, c2: str, t: float) -> str:
    """Blend two '#rrggbb' colours; t=0 is c1. Anything else comes back as c1
    (a named colour cannot be blended, and a hover must never raise)."""
    try:
        a, b = c1.lstrip("#"), c2.lstrip("#")
        if len(a) != 6 or len(b) != 6:
            return c1
        ch = [round(int(a[i:i + 2], 16) * (1 - t) + int(b[i:i + 2], 16) * t)
              for i in (0, 2, 4)]
        return "#%02x%02x%02x" % tuple(ch)
    except (ValueError, AttributeError):
        return c1

# Text measurement is the one expensive call in drawing a row: `font measure`
# on a string with an arrow or an icon glyph makes Tk walk font fallback, and
# it measured ~0.3ms a call — more than drawing the item. The same few hundred
# strings ("Top up →", badges, symbols) are measured on every redraw, so the
# answers are kept for the life of the process, shared by every list.
_FONTS: Dict[Any, tkfont.Font] = {}
_WIDTHS: Dict[Tuple[Any, str], int] = {}
_LINES: Dict[Any, int] = {}
_WIDTHS_MAX = 20000


class RowCanvas(tk.Canvas):
    """A vertically stacked list of drawn rows that sizes itself to fit.

    RESIZING. A width change reflows every row, and a window drag delivers
    dozens of <Configure> events a second to every list on every page -- the
    stacked pages are all mapped, so the hidden ones get them too. Redrawing
    each list on each event froze the app for over a second per drag. So:

      * on a page that is not on screen (`is_hidden`, installed by the app),
        a width change only marks the list stale; `flush_stale` redraws it
        when its page is next raised;
      * on the page that is on screen, the redraw waits until the events stop
        (RESIZE_DEBOUNCE_MS after the last one) and then runs once.
    """

    RESIZE_DEBOUNCE_MS = 60

    #: Corner radius of a non-clickable badge, and how far a button's fill
    #: moves toward its text colour under the pointer.
    BADGE_RADIUS = 4
    CAPSULE = 999.0             # any radius past half the height is a capsule
    HOVER_MIX = 0.16

    #: Set by the app: True when this list's page is not the one on screen.
    #: The default (never hidden) keeps a RowCanvas usable on its own.
    is_hidden: Callable[["RowCanvas"], bool] = staticmethod(lambda _rc: False)

    #: Lists that skipped a resize while hidden. Weak, so a list that is
    #: destroyed while stale simply drops out.
    _stale: "weakref.WeakSet[RowCanvas]" = weakref.WeakSet()
    #: Lists with a debounced resize redraw still waiting to run.
    _pending: "weakref.WeakSet[RowCanvas]" = weakref.WeakSet()

    def __init__(self, parent, bg: str, min_width: int = 600, **kw):
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0, height=1,
                         **kw)
        self.bg = bg
        self._min_width = min_width
        self._recipes: List[Recipe] = []
        self._drawn_width = 0
        self._tag_seq = 0
        # (tag, sequence, funcid) for every binding made during a draw, so the
        # next draw can drop them — and their Tcl commands — instead of
        # leaking a callback per button per redraw for the life of the app.
        self._bound: List[Tuple[str, str, str]] = []
        self._resize_id: Optional[str] = None
        self.bind("<Configure>", self._on_configure)

    @staticmethod
    def measure_with(canvas) -> Callable[[str, Any], int]:
        """The shared, cached text measure — for a plain canvas that is not a
        RowCanvas but draws text runs the same way."""
        def measure(text: str, spec) -> int:
            key = (spec, text)
            w = _WIDTHS.get(key)
            if w is None:
                f = _FONTS.get(spec)
                if f is None:
                    f = _FONTS[spec] = tkfont.Font(font=spec)
                w = _WIDTHS[key] = f.measure(text)
            return w
        return measure

    # ------------------------------------------------------------ list API

    def set_rows(self, recipes: Sequence[Recipe]) -> None:
        self._recipes = list(recipes)
        self.redraw()

    def redraw(self) -> None:
        # Tk keeps a tag's bindings after its items are deleted, so they are
        # dropped explicitly, with the Tcl command behind each one.
        for tag, seq, funcid in self._bound:
            try:
                self.tag_unbind(tag, seq, funcid)
            except (tk.TclError, ValueError):
                pass
        self._bound = []
        self.delete("all")
        width = self.width()
        self._drawn_width = width
        y = 0
        for recipe in self._recipes:
            try:
                y += int(recipe(self, y, width) or 0)
            except tk.TclError:
                continue
        self.configure(height=max(1, y))

    def width(self) -> int:
        w = self.winfo_width()
        if w <= 1:
            # Not laid out yet: draw at the parent's width (or a sane minimum);
            # the <Configure> that follows redraws at the real one.
            try:
                w = self.master.winfo_width()
            except tk.TclError:
                w = 0
        return max(w, self._min_width) if w <= 1 else w

    def _on_configure(self, event) -> None:
        if event.width == self._drawn_width or not self._recipes:
            return
        if self._drawn_width <= 1:
            # The first real layout of a list drawn before it had a width.
            # Nothing on screen is right yet, so there is nothing to wait for.
            self.redraw()
            return
        if RowCanvas.is_hidden(self):
            RowCanvas._stale.add(self)
            return
        if self._resize_id is not None:
            try:
                self.after_cancel(self._resize_id)
            except (tk.TclError, ValueError):
                pass
        self._resize_id = self.after(self.RESIZE_DEBOUNCE_MS, self._resize_due)
        RowCanvas._pending.add(self)

    def _resize_due(self) -> None:
        self._resize_id = None
        RowCanvas._pending.discard(self)
        try:
            if RowCanvas.is_hidden(self):
                RowCanvas._stale.add(self)
            elif self.winfo_width() != self._drawn_width:
                self.redraw()
        except tk.TclError:
            pass                                    # destroyed meanwhile

    @classmethod
    def flush_stale(cls, belongs: Callable[["RowCanvas"], bool]) -> int:
        """Redraw every stale list for which `belongs(list)` is true -- the
        lists on the page about to be shown. Returns how many were redrawn.

        A list whose debounced redraw is still waiting is brought forward too:
        the page is about to be seen, and 60ms at the old width would show.
        """
        n = 0
        for rc in list(cls._pending):
            try:
                if belongs(rc) and rc._resize_id is not None:
                    rc.after_cancel(rc._resize_id)
                    rc._resize_id = None
                    cls._pending.discard(rc)
                    cls._stale.add(rc)
            except (tk.TclError, ValueError):
                cls._pending.discard(rc)
        for rc in list(cls._stale):
            try:
                if not belongs(rc):
                    continue
                cls._stale.discard(rc)
                if rc.winfo_width() != rc._drawn_width:
                    rc.redraw()
                    n += 1
            except tk.TclError:
                cls._stale.discard(rc)
        return n

    # ------------------------------------------------------------ helpers

    def new_tag(self) -> str:
        self._tag_seq += 1
        return f"r{self._tag_seq}"

    def _tagbind(self, tag: str, seq: str, fn) -> None:
        funcid = self.tag_bind(tag, seq, fn, add="+")
        self._bound.append((tag, seq, funcid))

    def font(self, spec) -> tkfont.Font:
        f = _FONTS.get(spec)
        if f is None:
            # Rooted at the default root, not this canvas: fonts outlive any
            # one list, and a font owned by a destroyed canvas is deleted.
            f = tkfont.Font(font=spec)
            _FONTS[spec] = f
        return f

    def measure(self, text: str, spec) -> int:
        key = (spec, text)
        w = _WIDTHS.get(key)
        if w is None:
            if len(_WIDTHS) > _WIDTHS_MAX:
                _WIDTHS.clear()
            w = _WIDTHS[key] = self.font(spec).measure(text)
        return w

    def line_height(self, spec) -> int:
        h = _LINES.get(spec)
        if h is None:
            h = _LINES[spec] = self.font(spec).metrics("linespace")
        return h

    def on_click(self, tag: str, fn: Callable[[], Any]) -> None:
        self._tagbind(tag, "<Button-1>", lambda _e: fn())
        self._tagbind(tag, "<Enter>", lambda _e: self.configure(cursor="hand2"))
        self._tagbind(tag, "<Leave>", lambda _e: self.configure(cursor=""))

    def on_hover(self, tag: str, items: Sequence[int], normal: str, hover: str,
                 option: str = "fill") -> None:
        """Repaint `items` while the pointer is over anything tagged `tag`."""
        def paint(color):
            for it in items:
                try:
                    self.itemconfigure(it, **{option: color})
                except tk.TclError:
                    pass
        self._tagbind(tag, "<Enter>", lambda _e: paint(hover))
        self._tagbind(tag, "<Leave>", lambda _e: paint(normal))

    # ------------------------------------------------------------ primitives

    def rect(self, x0, y0, x1, y1, fill, tags=()) -> int:
        return self.create_rectangle(x0, y0, x1, y1, fill=fill, outline="",
                                     tags=tags)

    def round_rect(self, x0, y0, x1, y1, r, fill, tags=()) -> int:
        """A filled rectangle with corners of radius `r` (clamped to half the
        height, which makes a capsule). One smoothed polygon, so hover can
        recolour it with a single itemconfigure like a plain rect."""
        r = max(0.0, min(float(r), (y1 - y0) / 2, (x1 - x0) / 2))
        if r < 1:
            return self.rect(x0, y0, x1, y1, fill, tags=tags)
        pts = (x0 + r, y0, x0 + r, y0, x1 - r, y0, x1 - r, y0, x1, y0,
               x1, y0 + r, x1, y0 + r, x1, y1 - r, x1, y1 - r, x1, y1,
               x1 - r, y1, x1 - r, y1, x0 + r, y1, x0 + r, y1, x0, y1,
               x0, y1 - r, x0, y1 - r, x0, y0 + r, x0, y0 + r, x0, y0)
        return self.create_polygon(pts, smooth=True, fill=fill, outline="",
                                   tags=tags)

    def text(self, x, y, text, spec, fill, anchor="w", tags=(),
             width: Optional[int] = None, justify="left") -> int:
        kw = {"width": width} if width else {}
        return self.create_text(x, y, text=text, font=spec, fill=fill,
                                anchor=anchor, tags=tags, justify=justify, **kw)

    def text_run(self, x, cy, parts, tags=()) -> int:
        """Left-to-right run of (text, font, fill) at vertical centre `cy`.
        Returns the x after the last part — what `pack(side="left")` did."""
        for text, spec, fill in parts:
            if not text:
                continue
            self.text(x, cy, text, spec, fill, anchor="w", tags=tags)
            x += self.measure(text, spec)
        return x

    def pill(self, x, cy, text, spec, bg, fg, *, padx=10, pady=3, anchor="w",
             tags=(), on_click: Optional[Callable[[], Any]] = None,
             hover_bg: Optional[str] = None, hover_fg: Optional[str] = None,
             radius: Optional[float] = None) -> Tuple[int, int]:
        """A filled label (badge or button). anchor 'w' = starts at x,
        'e' = ends at x. Returns (x0, x1).

        Shaped like the app's CTk buttons: a clickable pill is a capsule
        (PillButton's corner_radius is height // 2), a plain badge gets
        BADGE_RADIUS. And EVERY clickable pill answers the pointer -- a fill
        change as well as the hand cursor -- not just the few call sites that
        remembered to pass hover_bg; a button that does not react looks
        disabled.
        """
        tw = self.measure(text, spec)
        h = self.line_height(spec) + 2 * pady
        w = tw + 2 * padx
        x0 = x if anchor == "w" else x - w
        if on_click and not hover_bg:
            hover_bg = _mix(bg, fg, self.HOVER_MIX)
        own = self.new_tag() if (on_click or hover_bg or hover_fg) else None
        all_tags = tuple(tags) + ((own,) if own else ())
        if radius is None:
            radius = h / 2 if on_click else self.BADGE_RADIUS
        r = self.round_rect(x0, cy - h / 2, x0 + w, cy + h / 2, radius, bg,
                            tags=all_tags)
        t = self.text(x0 + w / 2, cy, text, spec, fg, anchor="center",
                      tags=all_tags)
        if own:
            if hover_bg:
                self.on_hover(own, [r], bg, hover_bg)
            if hover_fg:
                self.on_hover(own, [t], fg, hover_fg)
            if on_click:
                self.on_click(own, on_click)
        return int(x0), int(x0 + w)

    def link(self, x, cy, text, spec, fg, hover_fg, on_click, anchor="w",
             tags=()) -> Tuple[int, int]:
        """Unfilled clickable text."""
        own = self.new_tag()
        t = self.text(x, cy, text, spec, fg, anchor=anchor, tags=tuple(tags) + (own,))
        self.on_hover(own, [t], fg, hover_fg)
        self.on_click(own, on_click)
        w = self.measure(text, spec)
        return (int(x), int(x + w)) if anchor == "w" else (int(x - w), int(x))

    def text_height(self, item: int) -> int:
        bb = self.bbox(item)
        return (bb[3] - bb[1]) if bb else 0


def wrap_lines(rc: RowCanvas, text: str, spec, max_width: int) -> List[str]:
    """Greedy word wrap, for text whose height must be known before drawing."""
    out: List[str] = []
    for para in str(text).split("\n"):
        words = para.split(" ")
        line = ""
        for word in words:
            cand = word if not line else f"{line} {word}"
            if rc.measure(cand, spec) <= max_width or not line:
                line = cand
            else:
                out.append(line)
                line = word
        out.append(line)
    return out
