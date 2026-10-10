"""Wells Fargo order-entry and holdings safety (pre-launch QA findings).

- After the submit click the result page is read: Placed only with a success
  indicator; a shown rejection or no indicator is ok=False "submitted ... verify".
- Never-sent failures carry none of the may-exist words.
- The per-account trade page load is bounded (asyncio.wait_for).
- A run-level timeout keeps finished accounts' results, gives the in-flight
  click a verify row, and every untouched account a nothing-sent Skipped row.
- Buy/Sell must be confirmed on the ticket or the account fails, nothing sent.
- only_accounts refuses to match on an unparsed "****" mask.
- _run_coro reports a CancelledError as a cancellation, not a timeout.
- An empty holdings result needs the holdings table to have rendered.

No browser, no network: every zendriver touchpoint is a fake.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

import wellsfargo

_ORDER_MAY_EXIST = ("submitted", "placed", "accepted", "pending", "queued",
                    "working", "order id", "confirmation", "verify")


def _no_order_words(acct):
    low = acct.message.lower()
    return acct.ok is False and not [w for w in _ORDER_MAY_EXIST if w in low]


def _verify(acct):
    low = acct.message.lower()
    return acct.ok is False and "verify" in low and "submitted" in low


class _El:
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
        if self.name == "confirm":
            n = self.page.clicks.count("confirm")
            hang = self.page.hang_on_confirm.get(n)
            if hang:
                await asyncio.sleep(hang)


class _Page:
    def __init__(self, *, results=None, hang_on_confirm=None, review_missing=False,
                 get_hang=None):
        self.clicks = []
        # per confirm click number -> result dict the page shows afterwards
        self.results = results or {}
        self.hang_on_confirm = hang_on_confirm or {}
        self.review_missing = review_missing
        self.get_hang = get_hang or {}
        self.gets = 0

    async def get(self, url):
        self.gets += 1
        hang = self.get_hang.get(self.gets)
        if hang:
            await asyncio.sleep(hang)

    async def wait_for_ready_state(self, *_a, **_k):
        pass

    async def wait(self, *_a, **_k):
        pass

    async def sleep(self, *_a):
        pass

    async def evaluate(self, js="", *_a, **_k):
        if "btn-wfa-submit" in js:
            n = self.clicks.count("confirm")
            res = self.results.get(n, {"submit": False, "ok": True, "alert": ""})
            return json.dumps(res)
        return ""

    async def select(self, sel, timeout=None):
        if sel == "#last":
            return _El(self, "last", "5.00")
        if sel == "#OrderQuantity":
            return _El(self, "qty")
        if sel == "#actionbtnContinue":
            return _El(self, "preview")
        if sel == ".btn-wfa-primary.btn-wfa-submit":
            if self.review_missing:
                raise asyncio.TimeoutError(sel)
            return _El(self, "confirm")
        raise asyncio.TimeoutError(f"no {sel}")


def _ctx(monkeypatch, page, *, accounts=("WF 1",), masks=None, only=None):
    async def _noop(*_a, **_k):
        return None

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
    monkeypatch.setattr(wellsfargo, "_wait_for_quote", _noop)
    monkeypatch.setattr(wellsfargo, "_capture_page_state", _state)
    monkeypatch.setattr(wellsfargo.random, "uniform", lambda a, b: 0.0)

    async def _start(**_k):
        return object(), page

    async def _login(*_a, **_k):
        return True

    async def _accts(*_a, **_k):
        out = []
        for i, a in enumerate(accounts):
            m = (masks[i] if masks else f"****{1000 + i}")
            out.append({"index": i, "account_id": a, "mask": m})
        return out

    return {
        "username": "u", "password": "p",
        "notify": None, "otp_provider": None, "dry_run": False,
        "side": "buy", "qty": "1", "symbol": "ABC", "headless": True,
        "only_accounts": list(only or []), "cancel_event": None,
        "_start_browser": _start, "_close_browser": _noop,
        "_login_on_page": _login, "_write_login_handoff": lambda ok: None,
        "_fetch_initial_account_data": _accts, "_current_url": _mask,
    }


def _run(monkeypatch, page, **kw):
    return asyncio.run(wellsfargo._cmd_trade(_ctx(monkeypatch, page, **kw)))


# ------------------------------------------------------------ result page

def test_success_indicator_reports_placed(monkeypatch):
    out = _run(monkeypatch, _Page())
    assert out.accounts[0].ok and out.accounts[0].message.startswith("Placed Buy 1 ABC")


def test_rejection_on_result_page_is_reported_with_verify(monkeypatch):
    page = _Page(results={1: {"submit": True, "ok": False,
                              "alert": "This security is not eligible for trading online"}})
    out = _run(monkeypatch, page)
    assert page.clicks.count("confirm") == 1
    [a] = out.accounts
    assert _verify(a)
    assert "not eligible" in a.message


def test_no_success_indicator_is_verify_not_placed(monkeypatch):
    page = _Page(results={1: {"submit": False, "ok": False, "alert": ""}})
    out = _run(monkeypatch, page)
    [a] = out.accounts
    assert _verify(a)
    assert out.state == "failed"


def test_indicator_with_submit_still_visible_is_not_placed(monkeypatch):
    page = _Page(results={1: {"submit": True, "ok": True, "alert": ""}})
    out = _run(monkeypatch, page)
    assert _verify(out.accounts[0])


# ------------------------------------------------------------ never-sent wording

def test_review_page_missing_has_no_may_exist_words(monkeypatch):
    out = _run(monkeypatch, _Page(review_missing=True))
    [a] = out.accounts
    assert _no_order_words(a)
    assert "nothing was sent" in a.message


# ------------------------------------------------------------ bounded nav

def test_trade_page_get_is_bounded_and_next_account_runs(monkeypatch):
    monkeypatch.setattr(wellsfargo, "_TRADE_NAV_TIMEOUT_S", 0.05)
    page = _Page(get_hang={1: 5.0})
    t0 = time.monotonic()
    out = _run(monkeypatch, page, accounts=("WF 1", "WF 2"))
    assert time.monotonic() - t0 < 3.0
    a1, a2 = out.accounts
    assert _no_order_words(a1) and "did not load" in a1.message
    assert a2.ok
    assert page.clicks.count("confirm") == 1


# ------------------------------------------------------------ run timeout

def test_dispatch_timeout_keeps_results_and_rows(monkeypatch):
    page = _Page(hang_on_confirm={2: 1.5})
    ctx = _ctx(monkeypatch, page, accounts=("WF 1", "WF 2", "WF 3"))
    real_run_coro = wellsfargo._run_coro
    monkeypatch.setattr(wellsfargo, "_run_coro",
                        lambda factory, *, timeout_s: real_run_coro(factory, timeout_s=0.5))
    monkeypatch.setattr(wellsfargo, "_build_ctx", lambda kw: ctx)
    out = wellsfargo._dispatch("trade", timeout_s=1200, side="buy", qty="1", symbol="ABC")
    time.sleep(1.6)  # let the orphan finish
    by = {a.account_id: a for a in out.accounts}
    assert by["WF 1"].ok
    assert _verify(by["WF 2"])
    assert _no_order_words(by["WF 3"]) and by["WF 3"].message.startswith("Skipped:")
    assert page.clicks.count("confirm") == 2
    assert out.state == "partial"


# ------------------------------------------------------------ Buy/Sell required

def test_buy_sell_dropdown_must_confirm(monkeypatch):
    async def _never(*_a, **_k):
        return False

    class _P:
        async def select(self, sel, timeout=None):
            raise asyncio.TimeoutError(sel)

        async def sleep(self, *_a):
            pass

    monkeypatch.setattr(wellsfargo, "_dropdown_shows", _never)
    with pytest.raises(RuntimeError) as ei:
        asyncio.run(wellsfargo._select_dropdown_option(_P(), "#BuySellBtn", "Buy",
                                                       timeout_s=0.01, require=True))
    assert "nothing was sent" in str(ei.value)
    low = str(ei.value).lower()
    assert not [w for w in _ORDER_MAY_EXIST if w in low]


def test_buy_sell_call_site_requires_confirmation(monkeypatch):
    seen = []

    async def _rec(page, sel, value, **kw):
        seen.append((sel, value, kw.get("require", False)))

    page = _Page()
    ctx = _ctx(monkeypatch, page)
    monkeypatch.setattr(wellsfargo, "_select_dropdown_option", _rec)
    asyncio.run(wellsfargo._cmd_trade(ctx))
    assert ("#BuySellBtn", "Buy", True) in seen


# ------------------------------------------------------------ only_accounts

def test_only_accounts_refuses_unparsed_masks(monkeypatch):
    page = _Page()
    out = _run(monkeypatch, page, accounts=("WF (****)", "WF2 (****)"),
               masks=["****", "****"], only=["WELLSTRADE (****0012)"])
    assert page.clicks == []
    [a] = out.accounts
    assert _no_order_words(a)


def test_account_matches_ignores_bare_star_mask():
    assert not wellsfargo._account_matches({"mask": "****", "account_id": "X (****)"},
                                           {"WELLSTRADE (****0012)"})
    assert wellsfargo._account_matches({"mask": "****0012", "account_id": "W (****0012)"},
                                       {"WELLSTRADE (****0012)"})


# ------------------------------------------------------------ _run_coro

def test_run_coro_cancelled_is_not_reported_as_timeout():
    async def _cancelled():
        raise asyncio.CancelledError()

    with pytest.raises(wellsfargo._WorkerCancelled) as ei:
        wellsfargo._run_coro(lambda: _cancelled(), timeout_s=5)
    assert "cancelled" in str(ei.value).lower()
    assert not isinstance(ei.value, TimeoutError)


# ------------------------------------------------------------ holdings

class _HPage:
    def __init__(self, html):
        self.html = html

    async def get_content(self):
        return self.html


def _holdings(monkeypatch, html):
    async def _noop(*_a, **_k):
        return None

    monkeypatch.setattr(wellsfargo, "_goto", _noop)
    monkeypatch.setattr(wellsfargo, "_settle", _noop)
    return asyncio.run(wellsfargo._fetch_holdings_for_account(
        _HPage(html), {"index": 0, "mask": "****0012"}))


def test_holdings_page_not_rendered_is_an_error(monkeypatch):
    with pytest.raises(wellsfargo._HoldingsNotLoaded):
        _holdings(monkeypatch, "<html><body>Please sign on</body></html>")


def test_holdings_empty_table_is_really_empty(monkeypatch):
    html = ("<table><thead><tr><th>Symbol</th><th>Quantity</th><th>Price</th></tr>"
            "</thead><tbody></tbody></table>")
    assert _holdings(monkeypatch, html) == []


def test_positions_marks_unloaded_account_failed(monkeypatch):
    page = _Page()
    ctx = _ctx(monkeypatch, page, accounts=("WF 1", "WF 2"))

    async def _fetch(page, acct, notify=None):
        if acct["index"] == 0:
            raise wellsfargo._HoldingsNotLoaded("holdings page did not load")
        return []

    ctx["_fetch_holdings_for_account"] = _fetch
    out = asyncio.run(wellsfargo._cmd_positions(ctx))
    a1, a2 = out.accounts
    assert not a1.ok and "holdings page did not load" in a1.message
    assert a2.ok
    assert out.state == "partial"
