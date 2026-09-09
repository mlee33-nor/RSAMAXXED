"""Adding, naming and removing broker logins on the Brokers page.

The Brokers page used to show one fixed set of credential boxes per broker,
because a broker could only have one login. It now shows a block per login with
a tag on it, plus Add and Remove.

Two things here are worth more than the rest:

  * saving must keep login 1 on the keys it has always used, or an existing
    install silently loses its broker
  * removing a login must not renumber the ones after it, because their number
    is in their account labels and the journal nets buys against sells on those

App cannot be instantiated headlessly, so the real methods are built onto a
plain Tk frame — the same approach as test_broker_chips.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import broker_logins as BL

_METHODS = ["_login_model", "_collect_login_rows", "_render_login_editor",
            "_add_login", "_remove_login", "_save_account_creds",
            "_refresh_linked_brokers", "_render_linked_count"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for schema in BL.SCHEMAS.values():
        if schema.blob:
            monkeypatch.delenv(schema.blob, raising=False)
        for idx in range(1, 6):
            for f in schema.fields:
                monkeypatch.delenv(BL.env_key(schema.broker, f.name, idx),
                                   raising=False)
            monkeypatch.delenv(BL.tag_key(schema.broker, idx), raising=False)


@pytest.fixture
def page(monkeypatch, tk_root):
    written: dict = {}
    monkeypatch.setattr(A, "_save_env_file", written.update)

    attrs = {n: getattr(A.App, n) for n in _METHODS}
    attrs.update({
        "_log": lambda self, *a, **k: None,
        "_render_trade_broker_chips": lambda self: None,
        "_render_mirror_broker_chips": lambda self: None,
        "_render_linked_count": lambda self: None,
    })
    Page = type("EditorPage", (tk.Frame,), attrs)

    p = Page(tk_root, bg=A.BG_PRIMARY)
    p.pack()
    p.written = written
    p._broker_status_labels = {}
    p._account_widgets = {}

    def open_broker(broker: str):
        p._account_widgets[broker] = {
            "dot": type("D", (), {"set_color": lambda self, c: None})(),
            "status": tk.Label(p),
            "box": tk.Frame(p),
        }
        p._render_login_editor(broker)
        return p._account_widgets[broker]

    p.open = open_broker
    yield p
    p.destroy()


def texts(widget):
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


# ---------------------------------------------------------------- rendering

@pytest.mark.parametrize("broker", sorted(BL.SCHEMAS))
def test_every_broker_renders_an_editor(page, broker):
    """All ten, including the ones with no credentials set — the empty card is
    where a new user types their first login."""
    ed = page.open(broker)
    labels = texts(ed["box"])
    assert any("Add login" in t for t in labels)
    for f in BL.SCHEMAS[broker].fields:
        assert f.label in labels


def test_an_unconfigured_broker_starts_with_one_empty_block(page):
    ed = page.open("chase")
    assert len(ed["rows"]) == 1
    assert not any("Remove" in t for t in texts(ed["box"]))    # nothing to remove


def test_the_existing_login_is_shown_with_its_tag(page, monkeypatch):
    monkeypatch.setenv("CHASE_USERNAME", "first-login")
    monkeypatch.setenv("CHASE_PASSWORD", "pw")
    monkeypatch.setenv("CHASE_TAG_1", "myles")

    ed = page.open("chase")

    assert ed["rows"][0]["username"].get() == "first-login"
    assert ed["rows"][0]["tag"].get() == "myles"


def test_a_password_is_masked_and_a_username_is_not(page):
    ed = page.open("chase")
    row = ed["rows"][0]
    assert row["password"].cget("show") != ""
    assert row["username"].cget("show") == ""


# ------------------------------------------------------------ add / remove

def test_add_login_appends_a_block_without_losing_what_was_typed(page):
    ed = page.open("chase")
    ed["rows"][0]["username"].insert(0, "half-typed")

    page._add_login("chase")

    assert len(ed["rows"]) == 2
    assert ed["rows"][0]["username"].get() == "half-typed"
    assert ed["rows"][1]["username"].get() == ""


def test_there_is_no_ceiling(page):
    page.open("public")
    for _ in range(9):
        page._add_login("public")
    assert len(page._account_widgets["public"]["rows"]) == 10


def test_remove_takes_out_the_one_that_was_clicked(page):
    ed = page.open("chase")
    page._add_login("chase")
    ed["rows"][0]["username"].insert(0, "first")
    ed["rows"][1]["username"].insert(0, "second")

    page._remove_login("chase", 0)

    assert [r["username"].get() for r in ed["rows"]] == ["second"]


# ----------------------------------------------------------------- saving

def test_saving_keeps_login_one_on_the_key_it_always_used(page):
    ed = page.open("chase")
    ed["rows"][0]["username"].insert(0, "first-login")
    ed["rows"][0]["password"].insert(0, "pw")
    ed["rows"][0]["tag"].insert(0, "myles")

    page._save_account_creds("chase")

    assert page.written["CHASE_USERNAME"] == "first-login"
    assert page.written["CHASE_TAG_1"] == "myles"
    assert "CHASE_USERNAME_2" not in page.written


def test_saving_a_second_login_is_purely_additive(page, monkeypatch):
    monkeypatch.setenv("CHASE_USERNAME", "first-login")
    monkeypatch.setenv("CHASE_PASSWORD", "pw1")
    ed = page.open("chase")
    page._add_login("chase")
    ed["rows"][1]["username"].insert(0, "someone-else")
    ed["rows"][1]["password"].insert(0, "pw2")
    ed["rows"][1]["tag"].insert(0, "the other one")

    page._save_account_creds("chase")

    assert page.written["CHASE_USERNAME"] == "first-login"        # untouched
    assert page.written["CHASE_USERNAME_2"] == "someone-else"
    assert page.written["CHASE_TAG_2"] == "the other one"


def test_removing_a_login_blanks_its_keys(page, monkeypatch):
    """Not merely omitted: a key left on disk is a password the broker still
    logs in with."""
    monkeypatch.setenv("CHASE_USERNAME", "first-login")
    monkeypatch.setenv("CHASE_PASSWORD", "pw1")
    monkeypatch.setenv("CHASE_USERNAME_2", "someone-else")
    monkeypatch.setenv("CHASE_PASSWORD_2", "pw2")
    page.open("chase")

    page._remove_login("chase", 1)
    page._save_account_creds("chase")

    assert page.written["CHASE_USERNAME_2"] == ""
    assert page.written["CHASE_PASSWORD_2"] == ""


def test_removing_the_middle_login_does_not_renumber_the_last(page, monkeypatch):
    """THE ONE THAT PROTECTS THE JOURNAL. Public 3's accounts are labelled
    "Public 3 ...", and trades.json nets buys against sells on that string. If
    deleting Public 2 turned Public 3 into Public 2, every open position at
    that login would stop matching its own buys."""
    for i, tok in enumerate(("a", "b", "c"), 1):
        monkeypatch.setenv(f"PUBLIC_SECRET_TOKEN_{i}", tok)
    page.open("public")

    page._remove_login("public", 1)
    page._save_account_creds("public")

    assert page.written["PUBLIC_SECRET_TOKEN_1"] == "a"
    assert page.written["PUBLIC_SECRET_TOKEN_2"] == ""
    assert page.written["PUBLIC_SECRET_TOKEN_3"] == "c"       # still 3


def test_saving_refreshes_the_rest_of_the_app(page, monkeypatch):
    """Linking a broker has to reach the desk and the mirror card, which are
    built from .env at startup — see the env-derived-UI-goes-stale note."""
    seen = []
    page._render_trade_broker_chips = lambda: seen.append("desk")
    page._render_mirror_broker_chips = lambda: seen.append("mirror")
    page.open("chase")
    page._account_widgets["chase"]["model"] = [{"username": "u", "password": "p"}]

    page._save_account_creds("chase")

    assert sorted(seen) == ["desk", "mirror"]
