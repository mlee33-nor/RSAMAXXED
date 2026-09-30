"""RowCanvas — the drawn lists behind Watchlist, Mirror, Exits and the
Command Center pick tabs.

What has to hold for those pages to behave like the widget rows they replaced:
a button's click does only the button's thing (not the row's too), redraws do
not leak a Tcl command per binding, and the canvas sizes itself to its rows.
"""
from __future__ import annotations

import sys
from pathlib import Path

import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.canvas_rows import RowCanvas, wrap_lines

FONT = ("Segoe UI", 9)


def make(tk_root):
    rc = RowCanvas(tk_root, bg="#101010")
    rc.pack(fill="x")
    return rc


def click(rc, x, y):
    """Fire <Button-1> on whatever item is topmost at (x, y), the way Tk does:
    every binding on every tag of that item."""
    item = rc.find_overlapping(x, y, x, y)[-1]
    for tag in rc.gettags(item):
        script = rc.tag_bind(tag, "<Button-1>")
        if script:
            for line in script.strip().splitlines():
                cmd = line.split('"[')[1].split(" ")[0] if '"[' in line else None
                if cmd:
                    rc.tk.call(cmd, *(["0"] * 19))


def test_rows_stack_and_size_the_canvas(tk_root):
    rc = make(tk_root)
    rc.set_rows([lambda c, y, w: 30, lambda c, y, w: 12, lambda c, y, w: 0])
    assert int(rc.cget("height")) == 42


def test_a_button_click_does_not_also_click_the_row(tk_root):
    rc = make(tk_root)
    hits = []

    def row(c, y, w):
        row_tag, click_tag = c.new_tag(), c.new_tag()
        c.rect(0, y, 400, y + 30, "#222", tags=(row_tag, click_tag))
        c.on_click(click_tag, lambda: hits.append("row"))
        c.pill(390, y + 15, "Buy", FONT, "#050", "#0f0", anchor="e",
               tags=(row_tag,), on_click=lambda: hits.append("button"))
        return 30

    rc.set_rows([row])
    tk_root.update_idletasks()
    click(rc, 380, 15)          # on the button
    assert hits == ["button"]
    click(rc, 10, 15)           # on the row
    assert hits == ["button", "row"]


def test_redraws_do_not_leak_tcl_commands(tk_root):
    rc = make(tk_root)

    def row(c, y, w):
        t = c.new_tag()
        c.rect(0, y, 100, y + 20, "#333", tags=(t,))
        c.on_click(t, lambda: None)
        c.pill(90, y + 10, "x", FONT, "#000", "#fff", anchor="e",
               on_click=lambda: None, hover_bg="#111")
        return 24

    rc.set_rows([row] * 20)
    before = len(tk_root.tk.call("info", "commands"))
    for _ in range(10):
        rc.redraw()
    assert len(tk_root.tk.call("info", "commands")) == before


def test_wrap_lines_respects_the_width(tk_root):
    rc = make(tk_root)
    text = "exit called at BBAE DSPAC Fidelity Public Robinhood Schwab Wells Fargo"
    lines = wrap_lines(rc, text, FONT, 120)
    assert len(lines) > 1
    assert " ".join(lines) == text
    assert all(rc.measure(l, FONT) <= 120 or " " not in l for l in lines)
