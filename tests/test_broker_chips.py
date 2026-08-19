"""Broker selectors have to survive linking a broker after the app opened.

Both selectors — the Trade Desk's BROKERS row and the Automation page's BROKERS
TO MIRROR ON — are built from `.env` inside `_build_*`, which runs once at
startup. Credentials are entered on a different page, later, so on a fresh copy
both were built from nothing and stayed empty for the rest of the session.

That is worse on the mirror card than it looks. With no chip to click there is
no way to select a broker, and Enable Mirror Trading refuses with "Select at
least one broker for mirror trading first" — an instruction the page gives no
means of following. A second machine was stuck exactly there.

The App class cannot be instantiated headlessly, so these build the methods onto
a plain Tk frame with the attributes they read, the same way test_invest_page
does.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A

_METHODS = [
    "_render_trade_broker_chips", "_broker_empty_hint", "_toggle_broker_chip",
    "_render_mirror_broker_chips", "_toggle_mirror_broker",
    "_refresh_linked_brokers", "_render_linked_count",
    "_save_account_creds",
    "_make_chip", "_style_chip",
]


@pytest.fixture
def page(monkeypatch, tk_root):
    """A frame carrying both selectors, over a settable set of linked brokers."""
    linked: set = set()

    monkeypatch.setattr(A, "_broker_has_creds", lambda b: b in linked)

    attrs = {n: getattr(A.App, n) for n in _METHODS}
    attrs.update({
        "_log": lambda self, *a, **k: None,
        "_show_frame": lambda self, name: setattr(self, "shown", name),
        "_update_trade_estimate": lambda self, *a: None,
        "_save_mirror_state": lambda self: setattr(
            self, "saves", getattr(self, "saves", 0) + 1),
    })
    Page = type("Page", (tk.Frame,), attrs)

    p = Page(tk_root, bg=A.BG_PRIMARY)
    p.pack(fill="both", expand=True)

    p.linked = linked                      # tests mutate this to link brokers

    p._trade_broker_chips = {}
    p._trade_selected_brokers = set()
    p._linked_brokers = []
    p._trade_chips_wrap = tk.Frame(p, bg=A.BG_CARD)
    p._trade_chips_wrap.pack(anchor="w")
    p._select_all_chip = p._make_chip(p, "Select All", None)

    p._mirror_broker_chips = {}
    p._mirror_selected_brokers = set()
    p._mirror_chips_frame = tk.Frame(p, bg=A.BG_CARD)
    p._mirror_chips_frame.pack(anchor="w")

    p._sidebar_conn_lbl = tk.Label(p)
    p._sidebar_conn_dot = type("D", (), {"set_color": lambda self, c: None})()
    p._statusbar_conn_lbl = tk.Label(p)

    yield p
    p.destroy()


def texts(widget):
    """Every text= string in the subtree, so an empty state can be asserted on."""
    out = []
    for child in widget.winfo_children():
        try:
            t = child.cget("text")
        except Exception:
            t = None
        if t:
            out.append(str(t))
        out.extend(texts(child))
    return out


# ------------------------------------------------------- the empty state

def test_an_unlinked_copy_says_so_instead_of_showing_an_empty_row(page):
    page._render_trade_broker_chips()
    page._render_mirror_broker_chips()

    assert page._trade_broker_chips == {}
    assert page._linked_brokers == []
    assert any("No brokers linked" in t for t in texts(page._trade_chips_wrap))
    assert any("nothing to buy on" in t for t in texts(page._mirror_chips_frame))


def test_the_empty_state_offers_the_page_that_fixes_it(page):
    """A bare "no brokers" line leaves the reader hunting. Credentials live on
    the Brokers page, so the hint carries the way there."""
    page._render_trade_broker_chips()
    link = [w for w in page._trade_chips_wrap.winfo_children()[0].winfo_children()
            if getattr(w, "cget", None) and w.cget("text") == "Link a broker"]
    assert link, "no route to the Brokers page"
    link[0].invoke()
    assert page.shown == "accounts"


def test_select_all_does_not_read_as_armed_when_nothing_is_linked(page):
    """0 selected == 0 linked is True by arithmetic and false in meaning."""
    page._render_trade_broker_chips()
    assert page._select_all_chip.cget("fg_color") == A.BG_INPUT


# --------------------------------------------- linking without a restart

def test_a_broker_linked_after_startup_appears_without_a_restart(page):
    """The bug. Both selectors were built once, so this used to need a restart."""
    page._render_trade_broker_chips()
    page._render_mirror_broker_chips()
    assert page._trade_broker_chips == {}

    page.linked.update({"fidelity", "public"})
    page._refresh_linked_brokers()

    assert set(page._trade_broker_chips) == {"fidelity", "public"}
    assert set(page._mirror_broker_chips) == {"fidelity", "public"}
    assert page._linked_brokers == ["fidelity", "public"]


def test_saving_credentials_is_what_triggers_the_refresh(page, monkeypatch):
    """The refresh has to hang off the save, not off opening the page — the
    mirror card is not re-rendered on navigation."""
    written = {}
    monkeypatch.setattr(A, "_save_env_file", written.update)

    entry = tk.Entry(page)
    entry.insert(0, "someone@example.com")
    page._account_widgets = {"fidelity": {
        "dot": type("D", (), {"set_color": lambda self, c: None})(),
        "status": tk.Label(page),
        "entries": {"FIDELITY_USERNAME": entry},
    }}
    page._broker_status_labels = {}
    page.linked.add("fidelity")

    page._save_account_creds("fidelity")

    assert written == {"FIDELITY_USERNAME": "someone@example.com"}
    assert set(page._mirror_broker_chips) == {"fidelity"}
    assert set(page._trade_broker_chips) == {"fidelity"}


def test_a_selection_survives_the_rebuild(page):
    """Re-rendering must not silently disarm a broker the user chose."""
    page.linked.update({"fidelity", "public"})
    page._render_trade_broker_chips()
    page._render_mirror_broker_chips()

    page._toggle_broker_chip("fidelity")
    page._toggle_mirror_broker("public")

    page.linked.add("chase")
    page._refresh_linked_brokers()

    assert page._trade_selected_brokers == {"fidelity"}
    assert page._mirror_selected_brokers == {"public"}
    assert page._trade_broker_chips["fidelity"]["selected"] is True
    assert page._mirror_broker_chips["public"]["selected"] is True
    assert page._mirror_broker_chips["chase"]["selected"] is False


# ------------------------------------------- losing credentials disarms

def test_a_broker_that_loses_its_credentials_is_disarmed(page):
    """Mirror places orders unattended, so a broker that can no longer log in
    must not stay in the set that gets bought on."""
    page.linked.update({"fidelity", "public"})
    page._render_trade_broker_chips()
    page._render_mirror_broker_chips()
    page._toggle_broker_chip("fidelity")
    page._toggle_mirror_broker("fidelity")

    page.linked.discard("fidelity")
    page._refresh_linked_brokers()

    assert page._trade_selected_brokers == set()
    assert page._mirror_selected_brokers == set()


def test_disarming_is_not_written_to_disk(page):
    """If .env fails to load, every broker looks unlinked for a moment.
    Persisting that would erase the saved selection for good, so the disarm
    stays in memory and the file keeps what the user chose."""
    page.linked.update({"fidelity"})
    page._render_mirror_broker_chips()
    page._toggle_mirror_broker("fidelity")
    saves_after_toggle = page.saves          # the toggle itself does persist

    page.linked.clear()                      # .env unreadable
    page._refresh_linked_brokers()

    assert page._mirror_selected_brokers == set()
    assert page.saves == saves_after_toggle


def test_one_broken_selector_does_not_swallow_the_save(page, monkeypatch):
    """The refresh runs inside the credential save. A widget error in one
    selector must not take the other one, or the save, down with it."""
    def boom(self):
        raise RuntimeError("widget gone")
    monkeypatch.setattr(type(page), "_render_trade_broker_chips", boom)

    page.linked.add("public")
    page._refresh_linked_brokers()

    assert set(page._mirror_broker_chips) == {"public"}


# --------------------------------------------------- the linked counters

def test_the_linked_counters_follow_the_credentials(page):
    """Both readouts were rendered once at startup and never again, so a fresh
    copy said "0 brokers linked" for the whole session however many were added."""
    page._render_linked_count()
    assert page._sidebar_conn_lbl.cget("text") == "0 brokers linked"
    assert "0 BROKERS LINKED" in page._statusbar_conn_lbl.cget("text")

    page.linked.update({"fidelity", "public"})
    page._refresh_linked_brokers()
    assert page._sidebar_conn_lbl.cget("text") == "2 brokers linked"
    assert "2 BROKERS LINKED" in page._statusbar_conn_lbl.cget("text")


def test_one_linked_broker_is_not_pluralised(page):
    page.linked.add("fidelity")
    page._render_linked_count()
    assert page._sidebar_conn_lbl.cget("text") == "1 broker linked"
    assert "1 BROKER LINKED" in page._statusbar_conn_lbl.cget("text")
