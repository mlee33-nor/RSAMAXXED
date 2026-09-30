"""Wording, money and button polish that the QA pass flagged."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
from modules.canvas_rows import RowCanvas


def test_plurals_read_as_english():
    assert A._plural(1, "exit") == "1 exit"
    assert A._plural(3, "share") == "3 shares"
    assert A._plural("1", "share") == "1 share"             # _qty_text output
    assert A._plural("0.98", "share") == "0.98 shares"
    assert A._plural(0, "account") == "0 accounts"
    assert (f"{A._plural(1, 'exit')} ready ({A._plural(A._qty_text(3.0), 'share')})"
            == "1 exit ready (3 shares)")


def test_no_ui_string_still_says_parenthesised_s():
    src = Path(A.__file__).read_text(encoding="utf-8")
    offenders = [ln.strip() for ln in src.splitlines()
                 if ("(s)" in ln and not ln.strip().startswith("#")
                     and ('f"' in ln or "f'" in ln))
                 and any(w + "(s)" in ln for w in (
                     "account", "acct", "share", "exit", "broker", "pick", "play"))]
    assert offenders == []


def test_signed_money_puts_the_sign_before_the_dollar():
    assert A._money_signed(3728.34) == "+$3,728.34"
    assert A._money_signed(-12.5) == "-$12.50"
    assert A._money_signed(0) == "+$0.00"
    assert A._money_signed(-0.001) == "+$0.00"               # no "-$0.00"
    assert A._money_signed(1234.4, 0) == "+$1,234"


def test_plain_money_only_signs_negatives():
    assert A._money(12) == "$12.00"
    assert A._money(-5, 0) == "-$5"


def test_every_clickable_pill_is_a_capsule_with_a_hover(tk_root):
    rc = RowCanvas(tk_root, bg="#101010")
    try:
        rc.pill(10, 20, "Sell", ("Segoe UI", 9), "#402020", "#ff5050",
                on_click=lambda: None)
        shape = rc.find_all()[0]
        assert rc.type(shape) == "polygon"                  # rounded, not a rect
        own = [t for t in rc.gettags(shape) if t.startswith("r")]
        assert own and rc.tag_bind(own[0], "<Enter>")       # it answers the pointer
        assert rc.tag_bind(own[0], "<Button-1>")
        # The default hover moves the fill toward the text colour.
        from modules import canvas_rows
        assert canvas_rows._mix("#402020", "#ff5050", RowCanvas.HOVER_MIX) == \
            A._blend("#402020", "#ff5050", RowCanvas.HOVER_MIX)
    finally:
        rc.destroy()


def test_a_plain_badge_is_gently_rounded_and_inert(tk_root):
    rc = RowCanvas(tk_root, bg="#101010")
    try:
        rc.pill(10, 20, " OTC ", ("Segoe UI", 8), "#202020", "#aaaaaa",
                padx=0, pady=1)
        shape = rc.find_all()[0]
        assert rc.type(shape) == "polygon"
        assert not [t for t in rc.gettags(shape) if t.startswith("r")]
    finally:
        rc.destroy()
