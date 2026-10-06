"""An error AFTER the submit click must never read as a plain, retryable failure.

Wells Fargo and Fidelity both used to record ok=False with a bare (often empty)
message when the confirmation page was slow — the order was already live, and a
Retry would have placed it twice. The app keys on "submitted" / "verify" in the
account message (app._ORDER_MAY_EXIST) to treat such a result as "order may
exist". Errors BEFORE the click keep their plain message.

No browser, no network: every zendriver touchpoint is a fake.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import pytest

import fidelity
import wellsfargo

# Mirrors app._ORDER_MAY_EXIST (app.py is a GUI module; not imported here).
_ORDER_MAY_EXIST = ("submitted", "placed", "accepted", "pending", "queued",
                    "working", "order id", "confirmation", "verify")


def _assert_no_order_words(acct):
    assert acct.ok is False
    low = acct.message.lower()
    assert not [w for w in _ORDER_MAY_EXIST if w in low], acct.message


def _assert_verify(acct):
    assert acct.ok is False
    low = acct.message.lower()
    assert "submitted" in low and "verify" in low, acct.message


def _assert_plain(acct, text):
    assert acct.ok is False
    assert text in acct.message
    low = acct.message.lower()
    assert "verify" not in low and "submitted" not in low, acct.message


# =============================================================================
# Wells Fargo
# =============================================================================

class _WFEl:
    def __init__(self, page, name, value=None):
        self.page, self.name, self.value = page, name, value
        self.text_all = ""

    def get(self, key):
        return self.value

    async def scroll_into_view(self):
        pass

    async def clear_input(self):
        pass

    async def send_keys(self, *_a):
        pass

    async def mouse_click(self):
        self.page.clicks.append(self.name)
        if self.name == "confirm" and self.page.confirm_hang:
            await asyncio.sleep(self.page.confirm_hang)


class _WFPage:
    def __init__(self, *, fail_after_confirm=None, fail_on_qty=None, confirm_hang=0.0):
        self.clicks = []
        self.fail_after_confirm = fail_after_confirm
        self.fail_on_qty = fail_on_qty
        self.confirm_hang = confirm_hang

    async def get(self, url):
        pass

    async def wait_for_ready_state(self, *_a, **_k):
        if "confirm" in self.clicks and self.fail_after_confirm is not None:
            raise self.fail_after_confirm

    async def wait(self, *_a, **_k):
        pass

    async def sleep(self, *_a):
        pass

    async def evaluate(self, *_a, **_k):
        return ""

    async def select(self, sel, timeout=None):
        if sel == "#last":
            return _WFEl(self, "last", "5.00")
        if sel == "#OrderQuantity":
            if self.fail_on_qty is not None:
                raise self.fail_on_qty
            return _WFEl(self, "qty")
        if sel == "#actionbtnContinue":
            return _WFEl(self, "preview")
        if sel == ".btn-wfa-primary.btn-wfa-submit":
            return _WFEl(self, "confirm")
        raise asyncio.TimeoutError(f"no {sel}")  # e.g. no warning banner


def _wf_run(monkeypatch, page, **kw):
    return asyncio.run(wellsfargo._cmd_trade(_wf_ctx(monkeypatch, page, **kw)))


def _wf_ctx(monkeypatch, page, *, login_hang=0.0, quote_hook=None):
    """The ctx _cmd_trade runs on, every browser step stubbed. `login_hang`
    stalls the login; `quote_hook(ctx)` runs where the quote would load."""
    ctx: dict = {}

    async def _noop(*_a, **_k):
        return None

    async def _quote(*_a, **_k):
        if quote_hook is not None:
            quote_hook(ctx)

    async def _sel(*_a, **_k):
        return object()

    async def _state(*_a, **_k):
        return "state"

    async def _mask(*_a, **_k):
        return ""

    monkeypatch.setattr(wellsfargo, "_trace", lambda *a, **k: None)
    monkeypatch.setattr(wellsfargo, "_safe_select", _sel)
    monkeypatch.setattr(wellsfargo, "_get_account_mask", _mask)
    monkeypatch.setattr(wellsfargo, "_select_dropdown_option", _noop)
    monkeypatch.setattr(wellsfargo, "_wait_for_quote", _quote)
    monkeypatch.setattr(wellsfargo, "_capture_page_state", _state)

    async def _start(**_k):
        return object(), page

    async def _login(*_a, **_k):
        if login_hang:
            await asyncio.sleep(login_hang)
        return True

    async def _accts(*_a, **_k):
        return [{"index": 0, "account_id": "WF 1"}]

    ctx.update({
        "username": "u", "password": "p",
        "notify": None, "otp_provider": None, "dry_run": False,
        "side": "buy", "qty": "1", "symbol": "ABC", "headless": True,
        "only_accounts": [], "cancel_event": None,
        "_start_browser": _start, "_close_browser": _noop,
        "_login_on_page": _login, "_write_login_handoff": lambda ok: None,
        "_fetch_initial_account_data": _accts, "_current_url": _mask,
    })
    return ctx


def test_wf_slow_confirmation_after_click_says_verify(monkeypatch):
    # The confirmed bug: wait_for_ready_state times out AFTER the confirm click.
    page = _WFPage(fail_after_confirm=asyncio.TimeoutError())
    out = _wf_run(monkeypatch, page)
    assert "confirm" in page.clicks
    assert len(out.accounts) == 1
    _assert_verify(out.accounts[0])
    assert "TimeoutError" in out.accounts[0].message  # detail kept for logs


def test_wf_error_before_click_is_unchanged(monkeypatch):
    page = _WFPage(fail_on_qty=RuntimeError("qty box missing"))
    out = _wf_run(monkeypatch, page)
    assert "confirm" not in page.clicks
    assert len(out.accounts) == 1
    _assert_plain(out.accounts[0], "qty box missing")


def test_wf_clean_submit_still_ok(monkeypatch):
    page = _WFPage()
    out = _wf_run(monkeypatch, page)
    assert out.accounts[0].ok is True
    assert out.accounts[0].message.startswith("Placed Buy 1 ABC")


def _wf_dispatch_short(monkeypatch, ctx):
    """Run the real _dispatch on `ctx` with a 0.3s budget instead of 20 min."""
    real_run_coro = wellsfargo._run_coro
    monkeypatch.setattr(wellsfargo, "_run_coro",
                        lambda factory, *, timeout_s: real_run_coro(factory, timeout_s=0.3))
    monkeypatch.setattr(wellsfargo, "_build_ctx", lambda kw: ctx)
    return wellsfargo._dispatch("trade", timeout_s=1200, side="buy", qty="1", symbol="ABC")


def test_wf_timeout_hung_at_login_is_plain(monkeypatch):
    page = _WFPage()
    ctx = _wf_ctx(monkeypatch, page, login_hang=1.0)
    out = _wf_dispatch_short(monkeypatch, ctx)
    time.sleep(1.2)  # let the orphan finish
    assert "confirm" not in page.clicks  # abandoned: stopped at the account boundary
    _assert_no_order_words(out.accounts[0])


def test_wf_timeout_hung_after_click_says_verify(monkeypatch):
    page = _WFPage(confirm_hang=1.0)
    ctx = _wf_ctx(monkeypatch, page)
    out = _wf_dispatch_short(monkeypatch, ctx)
    time.sleep(1.2)
    assert page.clicks.count("confirm") == 1
    _assert_verify(out.accounts[0])


def test_wf_abandoned_run_never_clicks_confirm(monkeypatch):
    # _dispatch gave up while this account was mid-ticket: the click must not go.
    page = _WFPage()
    ctx = _wf_ctx(monkeypatch, page, quote_hook=lambda c: c["_abandoned"].set())
    ctx["_abandoned"] = threading.Event()
    out = asyncio.run(wellsfargo._cmd_trade(ctx))
    assert "confirm" not in page.clicks
    assert ctx["_clicked"] is True  # flag raised first, so _dispatch would say verify
    _assert_no_order_words(out.accounts[0])


def test_wf_commit_symbol_fallback_has_no_name_error():
    # SpecialKeys only existed inside _cmd_trade; this path raised NameError.
    sent = []

    class _In:
        async def scroll_into_view(self):
            pass

        async def clear_input(self):
            pass

        async def send_keys(self, k):
            sent.append(k)

    class _P:
        async def select(self, sel, timeout=None):
            return _In()

        async def evaluate(self, *_a, **_k):
            return "ABC"

    assert asyncio.run(wellsfargo._commit_symbol(_P(), "ABC")) is True
    assert sent[0] == "ABC" and len(sent) == 2


# =============================================================================
# Fidelity
# =============================================================================

class _FidEl:
    def __init__(self, page, name):
        self.page, self.name = page, name

    async def scroll_into_view(self):
        pass

    async def mouse_move(self):
        pass

    async def mouse_click(self):
        self.page.clicks.append(self.name)
        if self.name == "place" and self.page.place_hang:
            await asyncio.sleep(self.page.place_hang)


class _FidPage:
    """Order-entry fake. `confirm_evals` scripts the confirmation poll: each
    item is a value to return or an exception to raise (last one repeats)."""

    def __init__(self, *, confirm_evals=(True,), sleep_raises_after_place=None,
                 place_select_fails=False, js_place_raises=None, place_hang=0.0):
        self.clicks = []
        self.place_hang = place_hang
        self.confirm_evals = list(confirm_evals)
        self.sleep_raises_after_place = sleep_raises_after_place
        self.place_select_fails = place_select_fails
        self.js_place_raises = js_place_raises

    def _placed(self):
        return "place" in self.clicks

    async def sleep(self, *_a):
        if self._placed() and self.sleep_raises_after_place is not None:
            raise self.sleep_raises_after_place

    async def wait_for_ready_state(self, *_a, **_k):
        pass

    async def wait(self, *_a, **_k):
        pass

    async def find(self, text, best_match=True):
        return _FidEl(self, f"acct:{text}")

    async def select(self, sel, timeout=None):
        if sel == "#placeOrderBtn":
            if self.place_select_fails:
                raise RuntimeError("Node with given id not found")
            return _FidEl(self, "place")
        raise asyncio.TimeoutError(sel)

    async def evaluate(self, js, *_a, **_k):
        if "placeOrderBtn" in js:
            self.clicks.append("place")  # b.click() ran...
            if self.js_place_raises is not None:
                raise self.js_place_raises  # ...then the context went away
            return True
        if "Order Received" in js:
            item = self.confirm_evals.pop(0) if len(self.confirm_evals) > 1 else self.confirm_evals[0]
            if isinstance(item, BaseException):
                raise item
            return item
        if "location.href" in js:
            return "https://digital.fidelity.com/ftgw/digital/trade-equity/index/orderEntry"
        return ""


def _fid_run(monkeypatch, pages, *, preview=None, accounts=("X11111111",),
             preview_hang=0.0, budget_s=None, login_hang=0.0):
    """Run the real execute_trade with every browser step stubbed. `pages` is
    one page shared by all accounts; `preview` maps acctNum -> exception.
    `budget_s` swaps the 30 min trade timeout for a short one."""
    page = pages
    current = {"acct": None}

    async def _noop(*_a, **_k):
        return None

    async def _true(*_a, **_k):
        return True

    async def _false(*_a, **_k):
        return False

    async def _start(*_a, **_k):
        return SimpleNamespace(), page

    async def _accts(*_a, **_k):
        return [{"acctNum": n, "name": "Individual"} for n in accounts]

    async def _prices(*_a, **_k):
        return {"last": 5.0, "bid": 4.99, "ask": 5.01}

    async def _action(*_a, **_k):
        return True, "Buy"

    async def _login(*_a, **_k):
        if login_hang:
            await asyncio.sleep(login_hang)
        return True

    async def _preview(_page):
        if preview_hang:
            await asyncio.sleep(preview_hang)
        err = (preview or {}).get(current["acct"])
        if err is not None:
            raise err
        return True, ""

    orig_find = _FidPage.find

    async def _tracking_find(self, text, best_match=True):
        current["acct"] = text.strip("()")
        return await orig_find(self, text, best_match)

    monkeypatch.setattr(_FidPage, "find", _tracking_find)
    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)
    monkeypatch.setattr(fidelity, "_load_creds", lambda: [fidelity._LoginCred(
        idx_1based=1, label="Fidelity 1", username="u", password="p", totp_secret="")])
    monkeypatch.setattr(fidelity, "_start_browser_for_login", _start)
    monkeypatch.setattr(fidelity, "_close_browser", _noop)
    monkeypatch.setattr(fidelity, "_ensure_logged_in", _login)
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
    monkeypatch.setattr(fidelity, "_maybe_force_extended_hours", _false)
    monkeypatch.setattr(fidelity, "_enter_symbol_and_get_prices", _prices)
    monkeypatch.setattr(fidelity, "_select_action", _action)
    monkeypatch.setattr(fidelity, "_stale_safe_type", _true)
    monkeypatch.setattr(fidelity, "_safe_select", _noop)
    monkeypatch.setattr(fidelity, "_set_order_type", _noop)
    monkeypatch.setattr(fidelity, "_preview_and_check_error", _preview)
    monkeypatch.setattr(fidelity.random, "uniform", lambda a, b: 0.0)
    return fidelity.execute_trade(side="buy", qty="1", symbol="ABC")


class _ContextGone(Exception):
    """Stand-in for zendriver's ProtocolException on a navigating page."""

    def __str__(self):
        return "Cannot find context with specified id"


def test_fid_confirmation_page_never_readable_says_verify(monkeypatch):
    # The confirmed bug: evaluate() keeps raising while the page navigates.
    page = _FidPage(confirm_evals=[_ContextGone()])
    out = _fid_run(monkeypatch, page)
    assert page.clicks.count("place") == 1
    assert len(out.accounts) == 1
    _assert_verify(out.accounts[0])
    assert "Cannot find context" in out.accounts[0].message


def test_fid_context_lost_briefly_then_confirmed_is_ok(monkeypatch):
    page = _FidPage(confirm_evals=[_ContextGone(), _ContextGone(), True])
    out = _fid_run(monkeypatch, page)
    assert out.accounts[0].ok is True
    assert out.accounts[0].message == "order placed"


def test_fid_error_after_click_from_sleep_says_verify(monkeypatch):
    page = _FidPage(sleep_raises_after_place=ConnectionError("websocket closed"))
    out = _fid_run(monkeypatch, page)
    _assert_verify(out.accounts[0])
    assert "websocket closed" in out.accounts[0].message


def test_fid_js_fallback_click_that_raises_says_verify(monkeypatch):
    # Every handle attempt fails, the JS b.click() runs, then evaluate raises:
    # the order may be out, so this is NOT "Could not click Place Order".
    page = _FidPage(place_select_fails=True, js_place_raises=_ContextGone())
    out = _fid_run(monkeypatch, page)
    _assert_verify(out.accounts[0])


def test_fid_error_before_click_is_unchanged(monkeypatch):
    page = _FidPage()
    out = _fid_run(monkeypatch, page,
                   preview={"X11111111": RuntimeError("preview exploded")})
    assert "place" not in page.clicks
    _assert_plain(out.accounts[0], "preview exploded")


def test_fid_placed_flag_does_not_leak_into_next_account(monkeypatch):
    # Account 1 places cleanly; account 2 fails BEFORE its click. Account 2's
    # failure must stay plain, not inherit account 1's "submitted" state.
    page = _FidPage()
    out = _fid_run(monkeypatch, page, accounts=("X11111111", "X22222222"),
                   preview={"X22222222": RuntimeError("preview exploded")})
    assert len(out.accounts) == 2
    assert out.accounts[0].ok is True
    _assert_plain(out.accounts[1], "preview exploded")


def test_fid_timeout_hung_at_login_is_plain(monkeypatch):
    page = _FidPage()
    out = _fid_run(monkeypatch, page, login_hang=1.0, budget_s=0.3)
    time.sleep(1.3)  # let the orphan finish
    assert "place" not in page.clicks
    _assert_no_order_words(out.accounts[0])
    assert "timed out" in out.accounts[0].message


def test_fid_timeout_hung_after_click_says_verify(monkeypatch):
    page = _FidPage(place_hang=1.0)
    out = _fid_run(monkeypatch, page, budget_s=0.3)
    time.sleep(1.3)
    assert page.clicks.count("place") == 1
    _assert_verify(out.accounts[0])


def test_fid_abandoned_run_never_clicks_place(monkeypatch):
    # The run times out while this account sits in preview; once it resumes
    # it must stop short of Place Order instead of placing an orphan order.
    page = _FidPage()
    out = _fid_run(monkeypatch, page, preview_hang=0.8, budget_s=0.3)
    time.sleep(1.3)
    assert "place" not in page.clicks
    # Timed out before the flag went up, so the answer is the plain one.
    _assert_no_order_words(out.accounts[0])
