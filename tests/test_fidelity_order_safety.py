"""Fidelity order-entry safety: one click, the right account, the right qty.

Covers the pre-launch QA findings on fidelity.py:
- Place Order: an error FROM mouse_click is "submitted ... verify" with no
  second click; only select/mouse_move errors (nothing dispatched) retry.
- The selected destination account is read back before anything else.
- The Quantity field must hold exactly the ordered quantity before preview.
- No confirmation within ~25s is ok=False "submitted ... verify", not a fill.
- A run-level timeout keeps finished accounts' results, gives the in-flight
  click a verify row and every untouched account a nothing-sent Skipped row.
- An auth/login failure skips the rest of that login with rows, but later
  logins still run; a browser failure stops them, still with rows.
- Account numbers with any one-letter prefix are scraped.

No browser, no network: every zendriver touchpoint is a fake.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import fidelity

_ORDER_MAY_EXIST = ("submitted", "placed", "accepted", "pending", "queued",
                    "working", "order id", "confirmation", "verify")


def _no_order_words(acct):
    low = acct.message.lower()
    return acct.ok is False and not [w for w in _ORDER_MAY_EXIST if w in low]


def _verify(acct):
    low = acct.message.lower()
    return acct.ok is False and "verify" in low and "submitted" in low


class _El:
    def __init__(self, page, name):
        self.page, self.name = page, name

    async def scroll_into_view(self):
        pass

    async def mouse_move(self):
        if self.name == "place" and self.page.move_fails:
            self.page.move_fails -= 1
            raise RuntimeError("Node with given id not found")

    async def mouse_click(self):
        if self.name == "place":
            self.page.clicks.append(("place", self.page.selected))
            n = len([c for c in self.page.clicks if c[0] == "place"])
            if self.page.click_raises is not None:
                raise self.page.click_raises
            if n in self.page.hang_on_click:
                await asyncio.sleep(self.page.hang_on_click[n])
        else:
            self.page.clicks.append((self.name, None))
            if self.name.startswith("acct:") and self.page.select_sticks:
                self.page.selected = self.name[len("acct:"):].strip("()")


class _Page:
    def __init__(self, *, confirm=True, click_raises=None, move_fails=0,
                 shown_override=None, qty_value="1", hang_on_click=None):
        self.clicks = []
        self.selected = ""
        self.select_sticks = True
        self.confirm = confirm
        self.click_raises = click_raises
        self.move_fails = move_fails
        self.shown_override = shown_override
        self.qty_value = qty_value
        self.hang_on_click = hang_on_click or {}
        self.js_clicks = 0

    def places(self):
        return [c for c in self.clicks if c[0] == "place"]

    async def sleep(self, *_a):
        pass

    async def wait_for_ready_state(self, *_a, **_k):
        pass

    async def wait(self, *_a, **_k):
        pass

    async def find(self, text, best_match=True):
        return _El(self, f"acct:{text}")

    async def select(self, sel, timeout=None):
        if sel == "#placeOrderBtn":
            return _El(self, "place")
        raise asyncio.TimeoutError(sel)

    async def evaluate(self, js, *_a, **_k):
        if "Order Received" in js:
            return self.confirm
        if "placeOrderBtn" in js:
            self.js_clicks += 1
            self.clicks.append(("place-js", self.selected))
            return True
        if "dest-acct-dropdown" in js:
            if self.shown_override is not None:
                return self.shown_override
            return f"Individual ({self.selected})"
        if "eqt-shared-quantity" in js:
            return self.qty_value
        return ""


def _run(monkeypatch, page, *, accounts=("X11111111",), logins=1, preview=None,
         budget_s=None, js_option_click=None):
    async def _noop(*_a, **_k):
        return None

    async def _true(*_a, **_k):
        return True

    async def _false(*_a, **_k):
        return False

    started = []

    async def _start(idx, **_k):
        started.append(idx)
        return SimpleNamespace(), page

    async def _accts(*_a, **_k):
        return [{"acctNum": n, "name": "Individual"} for n in accounts]

    async def _prices(*_a, **_k):
        return {"last": 5.0, "bid": 4.99, "ask": 5.01}

    async def _action(*_a, **_k):
        return True, "Buy"

    async def _preview(_page):
        err = (preview or {}).get(_page.selected)
        if err is not None:
            raise err
        return True, ""

    async def _js_opt(*_a, **_k):
        return True

    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)
    monkeypatch.setattr(fidelity, "_load_creds", lambda: [
        fidelity._LoginCred(idx_1based=i, label=f"Fidelity {i}", username="u",
                            password="p", totp_secret="")
        for i in range(1, logins + 1)])
    monkeypatch.setattr(fidelity, "_start_browser_for_login", _start)
    monkeypatch.setattr(fidelity, "_close_browser", _noop)
    monkeypatch.setattr(fidelity, "_ensure_logged_in", _true)
    if budget_s is not None:
        real_run_coro = fidelity._run_coro
        monkeypatch.setattr(fidelity, "_run_coro",
                            lambda factory, *, timeout_s: real_run_coro(factory, timeout_s=budget_s))
    monkeypatch.setattr(fidelity, "_nav", _noop)
    monkeypatch.setattr(fidelity, "_wait_for_trade_ticket", _noop)
    monkeypatch.setattr(fidelity, "_ensure_expanded_ticket_mode", _noop)
    monkeypatch.setattr(fidelity, "_open_account_dropdown_and_scrape", _accts)
    monkeypatch.setattr(fidelity, "_element_visible", _true)
    monkeypatch.setattr(fidelity, "_settle", _noop)
    monkeypatch.setattr(fidelity, "_js_pointer_click_selector", _true)
    monkeypatch.setattr(fidelity, "_js_click_option_by_text", js_option_click or _js_opt)
    monkeypatch.setattr(fidelity, "_maybe_force_extended_hours", _false)
    monkeypatch.setattr(fidelity, "_enter_symbol_and_get_prices", _prices)
    monkeypatch.setattr(fidelity, "_select_action", _action)
    monkeypatch.setattr(fidelity, "_stale_safe_type", _true)
    monkeypatch.setattr(fidelity, "_safe_select", _noop)
    monkeypatch.setattr(fidelity, "_set_order_type", _noop)
    monkeypatch.setattr(fidelity, "_preview_and_check_error", _preview)
    monkeypatch.setattr(fidelity.random, "uniform", lambda a, b: 0.0)
    out = fidelity.execute_trade(side="buy", qty="1", symbol="ABC")
    out.started = started
    return out


# ------------------------------------------------------------ Place Order

def test_error_from_mouse_click_is_verify_and_never_clicks_again(monkeypatch):
    page = _Page(click_raises=RuntimeError("Node with given id not found"))
    out = _run(monkeypatch, page)
    assert len(page.places()) == 1
    assert page.js_clicks == 0          # no JS fallback after an attempted click
    [a] = out.accounts
    assert _verify(a)


def test_error_from_mouse_move_retries_safely(monkeypatch):
    page = _Page(move_fails=1)
    out = _run(monkeypatch, page)
    assert len(page.places()) == 1
    assert out.accounts[0].ok and out.accounts[0].message == "order placed"


# ------------------------------------------------------------ confirmation

def test_no_confirmation_is_not_a_fill(monkeypatch):
    page = _Page(confirm=False)
    out = _run(monkeypatch, page)
    assert len(page.places()) == 1
    [a] = out.accounts
    assert _verify(a)
    assert out.state == "failed"


# ------------------------------------------------------------ account readback

def test_wrong_account_on_ticket_fails_before_preview(monkeypatch):
    page = _Page(shown_override="Individual (X99999999)")
    out = _run(monkeypatch, page)
    assert page.places() == []
    [a] = out.accounts
    assert _no_order_words(a)
    assert "X11111111" in a.message and "nothing was sent" in a.message


def test_account_readback_recovers_via_js_repick(monkeypatch):
    page = _Page()
    page.selected = "X00000001"         # the ticket is still on the previous account
    page.select_sticks = False          # the handle click "misses"...

    async def _repick(pg, container, item, text):
        pg.selected = text               # ...the JS re-pick lands
        return True

    out = _run(monkeypatch, page, js_option_click=_repick)
    assert out.accounts[0].ok
    assert page.places() == [("place", "X11111111")]


def test_label_without_an_account_number_is_not_a_false_failure(monkeypatch):
    # The closed dropdown's live markup is unverified. A label we cannot
    # compare must not fail every Fidelity account.
    page = _Page(shown_override="Individual")
    out = _run(monkeypatch, page)
    assert out.accounts[0].ok
    assert page.places() == [("place", "X11111111")]


def test_account_label_conflicts_rules():
    assert not fidelity._account_label_conflicts("Individual (X11111111)", "X11111111")
    assert not fidelity._account_label_conflicts("", "X11111111")
    assert not fidelity._account_label_conflicts("Individual - TOD", "X11111111")
    assert fidelity._account_label_conflicts("Global (Z22222222)", "X11111111")


# ------------------------------------------------------------ quantity

def test_quantity_mismatch_fails_before_preview(monkeypatch):
    page = _Page(qty_value="11")
    out = _run(monkeypatch, page)
    assert page.places() == []
    [a] = out.accounts
    assert _no_order_words(a)
    assert "nothing was sent" in a.message


def test_quantity_normalization():
    assert fidelity._qty_value_matches("1,000", "1000")
    assert fidelity._qty_value_matches("2.0", "2")
    assert not fidelity._qty_value_matches("", "1")
    assert not fidelity._qty_value_matches("11", "1")


# ------------------------------------------------------------ run timeout

def test_timeout_keeps_finished_results_and_rows_for_the_rest(monkeypatch):
    # Account 1 places; account 2's click hangs past the budget; 3 never starts.
    page = _Page(hang_on_click={2: 1.5})
    out = _run(monkeypatch, page, accounts=("X11111111", "X22222222", "X33333333"),
               budget_s=0.5)
    time.sleep(1.6)  # let the orphan finish
    assert len(page.places()) == 2
    by = {a.account_id: a for a in out.accounts}
    assert by["Fidelity 1 · Individual (X11111111)"].ok
    assert _verify(by["Fidelity 1 · Individual (X22222222)"])
    a3 = by["Fidelity 1 · Individual (X33333333)"]
    assert _no_order_words(a3) and a3.message.startswith("Skipped:")
    assert out.state == "partial"


def test_timeout_before_any_login_finished_gives_each_login_a_row(monkeypatch):
    page = _Page(hang_on_click={1: 1.5})
    out = _run(monkeypatch, page, logins=2, budget_s=0.5)
    time.sleep(1.6)
    ids = [a.account_id for a in out.accounts]
    assert "Fidelity 2" in ids
    assert _no_order_words(out.accounts[ids.index("Fidelity 2")])
    assert _verify(out.accounts[ids.index("Fidelity 1 · Individual (X11111111)")])


# ------------------------------------------------------------ hard stop

def test_login_failure_skips_rest_of_login_but_runs_next_login(monkeypatch):
    page = _Page()
    out = _run(monkeypatch, page, accounts=("X11111111", "X22222222"), logins=2,
               preview={"X11111111": RuntimeError("session bounced back to login")})
    assert out.started == [1, 2]
    rows = {a.account_id: a for a in out.accounts}
    assert _no_order_words(rows["Fidelity 1 · Individual (X22222222)"])
    assert rows["Fidelity 1 · Individual (X22222222)"].message.startswith("Skipped:")
    # Login 2 ran: its X11111111 hit the same scripted error, X22222222 skipped
    assert "Fidelity 2 · Individual (X11111111)" in rows


def test_browser_failure_stops_later_logins_with_rows(monkeypatch):
    page = _Page()
    out = _run(monkeypatch, page, accounts=("X11111111", "X22222222"), logins=2,
               preview={"X11111111": RuntimeError("browser connection lost")})
    assert out.started == [1]
    rows = {a.account_id: a for a in out.accounts}
    assert rows["Fidelity 1 · Individual (X22222222)"].message.startswith("Skipped:")
    assert rows["Fidelity 2"].message.startswith("Skipped:")
    assert _no_order_words(rows["Fidelity 2"])


# ------------------------------------------------------------ scrape regex

def test_scrape_accepts_any_one_letter_prefix():
    class _P:
        async def evaluate(self, js, *a, **k):
            if "ett-acct-sel-list" in js:
                return ["Individual (Z12345678)", "Roth IRA (X98765432)",
                        "HSA (245678901)", "Junk (zz1)"]
            return True

        async def sleep(self, *_a):
            pass

    got = asyncio.run(fidelity._open_account_dropdown_and_scrape(_P()))
    assert [g["acctNum"] for g in got] == ["Z12345678", "X98765432", "245678901"]
