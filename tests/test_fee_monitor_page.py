"""The MONITOR page builds and paints both states, headless (withdrawn root)."""
from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as A  # noqa: E402
import public_evidence  # noqa: E402
import public_fees  # noqa: E402

_METHODS = ("_build_fee_monitor", "_paint_fee_monitor", "_fee_guard_resume",
            "_fee_guard_event", "_fee_monitor_copy_head", "_fee_monitor_export", "_fee_monitor_open_folder")


@pytest.fixture()
def page(tk_root):
    attrs = {n: getattr(A.App, n) for n in _METHODS}
    attrs.update({
        "_log": lambda self, *a, **k: self.logs.append(a),
        "_push_notification": lambda self, m, k="info": self.notes.append((k, m)),
        "_attach_wheel": lambda self, *a: None,
        "_render_fee_monitor": lambda self: None,
        "_fee_guard_render": lambda self: None,
    })
    Page = type("Page", (tk.Frame,), attrs)
    p = Page(tk_root, bg=A.BG_PRIMARY)
    p.logs, p.notes, p._frames, p._fee_notices_seen = [], [], {}, set()
    p._content = p
    p._build_fee_monitor()
    yield p
    p.destroy()


def _snap():
    st = public_fees._load()
    return {"halt": public_fees.halt_status(), "last_scan": st.get("last_scan") or {},
            "events": st.get("events") or [], "threshold": "0.25",
            "ev": public_evidence.summary()}


def test_watching_state(page):
    public_evidence.record("note", i=1)
    page._paint_fee_monitor(_snap())
    assert "WATCHING" in page._fm["status"].cget("text")
    assert not page._fm["resume"].winfo_manager()
    assert "Chain intact" in page._fm["chain"].cget("text")


def test_paused_state_and_resume(page):
    public_fees.trip("Public charged $0.99 IPDN at Public 1 BROKERAGE (1234)")
    page._paint_fee_monitor(_snap())
    assert "PAUSED" in page._fm["status"].cget("text")
    assert page._fm["resume"].winfo_manager() == "pack"
    assert page._fm["tiles"]["fees"].cget("text") == "1"
    page._fee_guard_resume()
    assert public_fees.halt_status() is None
    assert any(k == "success" for k, _m in page.notes)


def test_first_halt_event_shouts(page):
    page._fee_guard_event({"kind": "halt", "first": True, "reason": "fee $0.99"})
    assert page.notes and page.notes[0][0] == "error"
    assert "PUBLIC FEE DETECTED" in page.notes[0][1]


def test_buy_notice_is_shown_once_per_symbol(page):
    ev = {"kind": "notice", "symbol": "IPDN", "note": "commission $0.99",
          "side": "BUY", "account": "Public 1 BROKERAGE (1234)"}
    page._fee_guard_event(ev)
    page._fee_guard_event(dict(ev, account="Public 1 BROKERAGE (5678)"))
    assert len(page.notes) == 1 and page.notes[0][0] == "warning"
