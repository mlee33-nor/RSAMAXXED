"""Second audit pass on the browser/API brokers (SoFi, Chase, Wells Fargo, Fidelity).

- SoFi: an HTTP 200 without ORDER_SUBMITTED or an order id is "submitted ...
  verify", not a fill; a non-whole quantity is refused before any POST; an
  account with no id fails its holdings instead of reading as empty.
- Chase: switching logins unpacks the parked session; a 200 without a
  positions list is an error; cash is told apart by type/symbol, not by name.
- Wells Fargo: the order side must match exactly ("Sell Short" is not Sell);
  a ticket showing a different account stops before Continue; a $0.00 quote
  is refused and a sub-penny sell never prices at $0.00; some-failed is
  "partial"; an unreadable position row is unknown, not empty.
- Fidelity: only specific auth/browser failures stop a login's accounts.

Fakes only: no browser, no network, no orders.
"""

from __future__ import annotations

import asyncio

import pytest

import chase
import fidelity
import sofi
import wellsfargo

import test_fidelity_order_safety as FT
import test_sofi_no_double_order as SO
import test_wellsfargo_order_safety as WT


def _may_exist(msg: str) -> bool:
    m = (msg or "").lower()
    return "verify" in m and ("submitted" in m or "placed" in m)


# =============================================================== SoFi

def _sofi_run(monkeypatch, req, qty="1"):
    def _rehydrate(**kw):
        return sofi.BrokerOutput(broker="SoFi", state="success", accounts=[], message="")

    monkeypatch.setattr(sofi, "_rehydrate_session", _rehydrate)
    monkeypatch.setattr(sofi, "_require_session", lambda **kw: None)
    monkeypatch.setattr(sofi, "_requests", lambda: req)
    monkeypatch.setattr(sofi, "_trading_session", lambda: "CORE_HOURS")
    monkeypatch.setattr(sofi.time, "sleep", lambda s: None)
    monkeypatch.setattr(sofi.BLOG, "write_log", lambda *a, **k: None)
    monkeypatch.setattr(sofi.BLOG, "log_exception", lambda *a, **k: None)
    return sofi._execute_trade_one(side="buy", qty=qty, symbol="abcd")


def test_sofi_bare_200_is_verify_not_a_fill(monkeypatch):
    req = SO._FakeReq([SO._Resp(body={}), SO._ok(), SO._Resp(body={"orderId": "778"})])
    out = _sofi_run(monkeypatch, req)
    a, b, c = out.accounts
    assert not a.ok and _may_exist(a.message)
    assert b.ok and c.ok and "778" in c.message
    assert req.posts == ["A1111", "B2222", "C3333"]
    assert out.state == "partial"


def test_sofi_mixed_quantity_is_refused_before_any_post(monkeypatch):
    req = SO._FakeReq([])
    out = _sofi_run(monkeypatch, req, qty="1.5")
    assert req.posts == []
    assert out.state == "failed"
    assert "invalid qty" in out.message.lower() and not _may_exist(out.message)


def test_sofi_whole_and_fractional_quantities_still_pass(monkeypatch):
    req = SO._FakeReq([SO._ok()], accounts=("A1111",))
    assert _sofi_run(monkeypatch, req, qty="2.0").accounts[0].ok
    req = SO._FakeReq([SO._ok()], accounts=("A1111",))
    assert _sofi_run(monkeypatch, req, qty="0.5").accounts[0].ok


class _SofiHoldReq:
    def get(self, url, **kw):
        if url.endswith("/accounts"):
            return SO._Resp(body=[
                {"id": "", "apexAccountId": "AP0001", "type": {"description": "IRA"}},
                {"id": "77", "apexAccountId": "AP0002", "type": {"description": "INDIVIDUAL"}},
            ])
        return SO._Resp(body={"holdings": [{"symbol": "ABCD", "shares": 1, "price": 2.0}]})


def test_sofi_holdings_account_without_id_is_not_empty_ok(monkeypatch):
    monkeypatch.setattr(sofi, "_rehydrate_session",
                        lambda *a, **k: sofi.BrokerOutput(broker="SoFi", state="success",
                                                          accounts=[], message=""))
    monkeypatch.setattr(sofi, "_require_session", lambda **kw: None)
    monkeypatch.setattr(sofi, "_requests", lambda: _SofiHoldReq())
    out = sofi._get_holdings_one()
    a, b = out.accounts
    assert not a.ok and "without an id" in a.message
    assert b.ok and [h.symbol for h in b.holdings] == ["ABCD"]
    assert out.state == "partial"


# =============================================================== Chase

def test_chase_login_switch_unpacks_the_parked_session(monkeypatch):
    monkeypatch.setattr(chase, "_SESSION_BY_LOGIN", {})
    monkeypatch.setattr(chase, "_CUR_LOGIN", 1)
    monkeypatch.setattr(chase, "_COOKIES", {"a": "1"})
    chase._on_login_switch(2)
    assert chase._COOKIES is None
    chase._COOKIES = {"b": "2"}
    chase._on_login_switch(1)
    assert chase._COOKIES == {"a": "1"}
    chase._on_login_switch(2)
    assert chase._COOKIES == {"b": "2"}


def _pos(name, sym=None, qty=3.0, **extra):
    p = {"instrumentLongName": name, "tradedUnitQuantity": qty,
         "marketPrice": {"baseValueAmount": 1.0}}
    if sym is not None:
        p["positionComponents"] = [{"securityIdDetail": [{"symbolSecurityIdentifier": sym}]}]
    p.update(extra)
    return p


def test_chase_cash_is_decided_by_type_or_symbol():
    assert chase._is_cash_position(_pos("Cash"))
    assert chase._is_cash_position(_pos("Cash Sweep", sym="QACDS", assetClassCode="CASH"))
    assert not chase._is_cash_position(_pos("Cash America Intl", sym="CSH"))


class _ChaseHoldReq:
    def __init__(self, bodies):
        self.bodies = list(bodies)

    def post(self, url, **kw):
        return SO._Resp(body=self.bodies.pop(0))


def _chase_holdings(monkeypatch, bodies):
    ok = chase.BrokerOutput(broker="Chase", state="success", accounts=[], message="")
    monkeypatch.setattr(chase, "ensure_session", lambda **kw: ok)
    monkeypatch.setattr(chase, "_require_session", lambda: ({"c": "1"}, None))
    monkeypatch.setattr(chase, "_account_list", lambda c: {})
    monkeypatch.setattr(chase, "_extract_accounts_map",
                        lambda r: [("...1111", "1111", 10.0), ("...2222", "2222", 10.0)])
    monkeypatch.setattr(chase, "_requests", lambda: _ChaseHoldReq(bodies))
    monkeypatch.setattr(chase, "chase_normalize", lambda o: o)
    return chase._get_holdings_one()


def test_chase_200_without_positions_is_an_error(monkeypatch):
    out = _chase_holdings(monkeypatch, [
        {"errorMessage": "try later"},
        {"positions": [_pos("Cash America Intl", sym="CSH"), _pos("Cash", qty=50.0)]},
    ])
    a, b = out.accounts
    assert not a.ok and "positions list" in a.message
    assert b.ok and [h.symbol for h in b.holdings] == ["CSH"]
    assert b.extra["cash"] == 50.0
    assert out.state == "partial"


def test_chase_empty_positions_list_is_really_empty(monkeypatch):
    out = _chase_holdings(monkeypatch, [{"positions": []}, {"positions": None}])
    assert all(a.ok and a.holdings == [] for a in out.accounts)


# =============================================================== Wells Fargo

def test_wf_side_label_must_be_exact():
    assert wellsfargo._label_is_exactly("Sell", "Sell")
    assert wellsfargo._label_is_exactly(" Action: Sell ", "Sell")
    assert not wellsfargo._label_is_exactly("Sell Short", "Sell")
    assert not wellsfargo._label_is_exactly("Buy to Cover", "Buy")
    assert not wellsfargo._label_is_exactly("", "Buy")


def test_wf_dropdown_shows_exact_rejects_sell_short():
    class _Opener:
        text_all = "Sell Short"

    class _P:
        async def select(self, sel, timeout=None):
            return _Opener()

    assert asyncio.run(wellsfargo._dropdown_shows(_P(), "#TIFBtn", "Sell"))  # loose
    assert not asyncio.run(wellsfargo._dropdown_shows(_P(), "#BuySellBtn", "Sell", exact=True))


def test_wf_ticket_on_another_account_stops_before_continue(monkeypatch):
    page = WT._Page()
    ctx = WT._ctx(monkeypatch, page, accounts=("WF 1", "WF 2"))

    async def _mask(_page):
        return "9999"

    monkeypatch.setattr(wellsfargo, "_get_account_mask", _mask)
    out = asyncio.run(wellsfargo._cmd_trade(ctx))
    assert "preview" not in page.clicks and "confirm" not in page.clicks
    assert out.accounts and all(WT._no_order_words(a) for a in out.accounts)
    assert "nothing was sent" in out.accounts[0].message
    assert out.state == "failed"


def test_wf_matching_ticket_mask_still_trades(monkeypatch):
    page = WT._Page()
    ctx = WT._ctx(monkeypatch, page)

    async def _mask(_page):
        return "1000"

    monkeypatch.setattr(wellsfargo, "_get_account_mask", _mask)
    out = asyncio.run(wellsfargo._cmd_trade(ctx))
    assert out.accounts[0].ok and page.clicks.count("confirm") == 1


class _PricedPage(WT._Page):
    def __init__(self, last, **kw):
        super().__init__(**kw)
        self.last = last
        self.price_typed = []

    async def select(self, sel, timeout=None):
        if sel == "#last":
            return WT._El(self, "last", self.last)
        if sel == "#Price":
            page = self

            class _PriceEl(WT._El):
                async def send_keys(self, *a):
                    page.price_typed.extend(a)

            return _PriceEl(self, "price")
        return await super().select(sel, timeout)


def test_wf_zero_quote_is_refused(monkeypatch):
    page = _PricedPage("0.00")
    out = WT._run(monkeypatch, page)
    assert "confirm" not in page.clicks and "preview" not in page.clicks
    [a] = out.accounts
    assert WT._no_order_words(a) and "nothing was sent" in a.message


def test_wf_sub_penny_sell_never_prices_at_zero(monkeypatch):
    page = _PricedPage("0.004")
    ctx = WT._ctx(monkeypatch, page)
    ctx["side"] = "sell"
    out = asyncio.run(wellsfargo._cmd_trade(ctx))
    assert page.price_typed == ["0.01"]
    assert out.accounts[0].ok


def test_wf_some_failed_is_partial(monkeypatch):
    page = WT._Page(results={1: {"submit": False, "ok": False, "alert": ""}})
    out = WT._run(monkeypatch, page, accounts=("WF 1", "WF 2"))
    a, b = out.accounts
    assert not a.ok and b.ok
    assert out.state == "partial"


def test_wf_unreadable_position_row_is_not_empty(monkeypatch):
    html = ("<table><tbody><tr class='level1'><td><a class='navlink quickquote'>ABCD</a></td>"
            "<td class='datanumeric'><div>x</div></td><td class='datanumeric'><div>--</div></td>"
            "<td class='datanumeric'><div>$1.00</div></td></tr></tbody></table>")
    with pytest.raises(wellsfargo._HoldingsNotLoaded):
        WT._holdings(monkeypatch, html)


def test_wf_readable_position_row_still_parses(monkeypatch):
    html = ("<table><tbody><tr class='level1'><td><a class='navlink quickquote'>ABCD</a></td>"
            "<td class='datanumeric'><div>x</div></td><td class='datanumeric'><div>3</div></td>"
            "<td class='datanumeric'><div>$1.00</div></td></tr></tbody></table>")
    [row] = WT._holdings(monkeypatch, html)
    assert (row.symbol, row.shares, row.price) == ("ABCD", 3.0, 1.0)


# =============================================================== Fidelity

def test_fidelity_stop_kind_is_specific():
    k = fidelity._login_stop_kind
    assert k(RuntimeError("session bounced back to login")) == "auth"
    assert k(RuntimeError("Fidelity order ticket did not load after two attempts "
                          "(url: https://x/login?AuthRedUrl=y) — the session was "
                          "bounced back to login")) == "auth"
    assert k(RuntimeError("browser connection lost")) == "browser"
    assert k(ConnectionRefusedError("refused")) == "browser"
    assert k(RuntimeError("Account not authorized to trade this security")) == ""
    assert k(RuntimeError("Could not enter quantity (1); see login help")) == ""


def test_fidelity_unauthorized_security_does_not_skip_the_login(monkeypatch):
    page = FT._Page()
    out = FT._run(monkeypatch, page, accounts=("X11111111", "X22222222"),
                  preview={"X11111111": RuntimeError("Account not authorized to trade this security")})
    rows = {a.account_id: a for a in out.accounts}
    assert not rows["Fidelity 1 · Individual (X11111111)"].ok
    assert rows["Fidelity 1 · Individual (X22222222)"].ok
