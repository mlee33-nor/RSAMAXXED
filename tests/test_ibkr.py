"""IBKR through IB Gateway, against a fake IB -- no Gateway, no network.

What is pinned here is what costs money when it is wrong: which results the
app may retry (nothing was sent), which it must never retry (the order may be
live), that a dry run sends nothing, that each account is traded exactly once,
and that importing ib_async does not patch the event loop every other broker's
thread runs on.

The fake stands in for ib_async.IB at the one seam ibkr.py creates it
(`_new_ib`). Stock and MarketOrder are the real ib_async classes -- they are
plain dataclasses and touch nothing.
"""
from __future__ import annotations

import asyncio
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import broker_logins as BL
import ibkr
from modules.outputs import AccountOutput
import lifecycle
import rsa_feed
from etf_plan import Capability, capability_for


# ---------------------------------------------------------------- the fake

class FakeEvent:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self

    def emit(self, *args):
        for h in list(self.handlers):
            h(*args)


class FakeIB:
    """Just the slice of ib_async.IB that ibkr.py uses."""

    def __init__(self, world):
        self.w = world
        self.errorEvent = FakeEvent()
        self.connected = False
        self.RequestTimeout = 0
        self._next_id = 100
        world.instances.append(self)

    # -- connection
    def connect(self, host, port, clientId, timeout, readonly, raiseSyncErrors=False):
        self.w.connects.append((host, port, clientId, readonly))
        self.w.raise_sync.append(raiseSyncErrors)
        script = self.w.connect_script.pop(0) if self.w.connect_script else None
        if script:
            for err in script.get("errors", ()):
                self.errorEvent.emit(*err)
            if script.get("raise"):
                raise script["raise"]
        self.connected = True

    def isConnected(self):
        return self.connected

    def disconnect(self):
        self.connected = False
        self.w.disconnects += 1

    def managedAccounts(self):
        return list(self.w.accounts)

    # -- data
    def qualifyContracts(self, contract):
        if self.w.unknown_symbol:
            self.errorEvent.emit(5, 200, "No security definition has been found "
                                         "for the request", contract)
            return []
        contract.conId = 4242
        return [contract]

    def positions(self, account=""):
        return list(self.w.positions.get(account, []))

    def accountSummary(self, account=""):
        return [SimpleNamespace(account=account, tag="TotalCashValue",
                                value="1234.5", currency="USD", modelCode="")]

    # -- orders
    def whatIfOrder(self, contract, order):
        self.w.what_ifs.append((contract, order))
        return SimpleNamespace(status="PreSubmitted", commission=1.0,
                               initMarginChange="12.5", warningText="")

    def placeOrder(self, contract, order):
        self._next_id += 1
        order.orderId = self._next_id
        order.permId = 900000 + self._next_id
        # ib_async's placeOrder logs the new order with errorCode 0.
        trade = SimpleNamespace(
            contract=contract, order=order,
            log=[SimpleNamespace(status="PendingSubmit", message="", errorCode=0)],
            orderStatus=SimpleNamespace(status="PendingSubmit", filled=0.0,
                                        avgFillPrice=0.0))
        self.w.placed.append((contract, order))
        if self.w.on_place:
            self.w.on_place(self, trade)
        self.w.trades.append(trade)
        return trade

    def sleep(self, secs=0.02):
        if self.w.on_sleep:
            for trade in self.w.trades:
                self.w.on_sleep(self, trade)
        time.sleep(0.001)
        return True


# What ib_async's wrapper does with what Gateway sends about an order
# (site-packages/ib_async/wrapper.py: error() and orderStatus()).

_IB_WARNINGS = frozenset({105, 110, 165, 321, 329, 399, 404, 434, 492, 10167})
_IB_DONE = ("Filled", "Cancelled", "ApiCancelled", "Inactive")


def ib_error(ib, trade, code, text):
    """wrapper.error() for an order id: a non-warning code marks the trade
    Cancelled LOCALLY (whatever IBKR thinks), logged with that code; then
    errorEvent fires."""
    if code in _IB_WARNINGS or 2100 <= code < 2200:
        trade.orderStatus.status = "ValidationError"
        trade.log.append(SimpleNamespace(status="ValidationError",
                                         message=f"Warning {code}: {text}",
                                         errorCode=code))
    elif trade.orderStatus.status not in _IB_DONE:
        trade.orderStatus.status = "Cancelled"
        trade.log.append(SimpleNamespace(
            status="Cancelled",
            message=f"Error {code}, reqId {trade.order.orderId}: {text}",
            errorCode=code))
    ib.errorEvent.emit(trade.order.orderId, code, text, trade.contract)


def ib_status(trade, status, filled=None, avg=None):
    """wrapper.orderStatus(): IBKR's own status, logged with errorCode 0."""
    trade.orderStatus.status = status
    if filled is not None:
        trade.orderStatus.filled = filled
    if avg is not None:
        trade.orderStatus.avgFillPrice = avg
    trade.log.append(SimpleNamespace(status=status, message="", errorCode=0))


def _forbidden(text: str) -> list:
    t = text.lower()
    return [w for w in A._ORDER_MAY_EXIST if w in t]


@pytest.fixture
def world(monkeypatch, tmp_path):
    for key in list(__import__("os").environ):
        if key.startswith("IBKR_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("IBKR_PORT", "4002")

    w = SimpleNamespace(
        accounts=["DU1234567"], positions={}, connect_script=[], connects=[],
        disconnects=0, placed=[], what_ifs=[], trades=[], instances=[],
        unknown_symbol=False, on_place=None, on_sleep=None, raise_sync=[])
    monkeypatch.setattr(ibkr, "_new_ib", lambda: FakeIB(w))
    monkeypatch.setattr(ibkr, "_root_dir", lambda: tmp_path)
    monkeypatch.setattr(ibkr, "ORDER_WAIT", 0.3)
    monkeypatch.setattr(ibkr, "CANCEL_SETTLE", 0.3)
    monkeypatch.setattr(ibkr, "_IDS_IN_USE", set())
    return w


def buy(qty="1", **kw):
    return ibkr.execute_trade(side="buy", qty=qty, symbol="ABCD", **kw)


def fill_at(price):
    def on_place(ib, trade):
        trade.orderStatus.status = "Filled"
        trade.orderStatus.filled = trade.order.totalQuantity
        trade.orderStatus.avgFillPrice = price
    return on_place


# ---------------------------------------------------------------- connecting

def test_gateway_not_running_says_exactly_what_to_do(world):
    world.connect_script = [{"raise": ConnectionRefusedError(1225, "refused")}]
    out = buy()
    assert out.state == "failed"
    msg = out.accounts[0].message
    assert msg == ("IB Gateway isn't running or the API is off — open IB Gateway, "
                   "log in, and enable the API (port 4002) — nothing was sent")
    assert not _forbidden(msg)
    assert world.placed == []


def test_not_set_up_is_a_plain_failure(world, monkeypatch):
    monkeypatch.delenv("IBKR_PORT")
    out = buy()
    assert out.state == "failed" and "Brokers page" in out.message
    assert world.connects == []


def test_read_only_api_is_explained_and_nothing_is_sent(world):
    world.connect_script = [{"errors": [(-1, 321, "Error validating request.-'bN' : "
                                                  "cause - The API interface is "
                                                  "currently in Read-Only mode.")]}]
    out = buy()
    msg = out.accounts[0].message
    assert out.state == "failed" and "Read-Only" in msg
    assert world.placed == [] and not _forbidden(msg)


def test_lost_link_to_ibkr_servers_reads_as_a_competing_session(world):
    world.connect_script = [{"errors": [(-1, 1100, "Connectivity between IB and "
                                                   "Trader Workstation has been lost.")]}]
    out = buy()
    assert "competing session" in out.accounts[0].message
    assert world.placed == []


def test_a_taken_client_id_retries_with_the_next_one(world):
    world.connect_script = [
        {"errors": [(-1, 326, "Unable to connect as the client id is already in use. "
                              "Retry with a unique client id.")],
         "raise": ConnectionError("Socket disconnect")},
        None,
    ]
    world.on_place = fill_at(2.0)
    out = buy()
    assert out.state == "success"
    ids = [c[2] for c in world.connects]
    assert ids == [ibkr.DEFAULT_CLIENT_ID, ibkr.DEFAULT_CLIENT_ID + 1]
    assert all(c[3] is False for c in world.connects)        # never readonly


def test_overlapping_sessions_never_share_a_client_id(world):
    gw = ibkr._gateways()[0]
    a = ibkr._claim_client_id(gw, set())
    b = ibkr._claim_client_id(gw, set())
    assert a != b
    ibkr._release_client_ids(gw, [a, b])
    assert ibkr._claim_client_id(gw, set()) == a


def test_every_session_disconnects(world):
    world.on_place = fill_at(1.0)
    buy()
    ibkr.get_holdings()
    ibkr.bootstrap()
    assert world.disconnects == 3


# ---------------------------------------------------------------- trading

def test_dry_run_uses_what_if_and_never_places(world):
    world.accounts = ["U1111111", "U2222222"]
    out = buy(dry_run=True)
    assert out.state == "success"
    assert len(world.what_ifs) == 2 and world.placed == []
    assert out.message.startswith("DRY RUN")
    assert all("IBKR what-if: OK" in a.message for a in out.accounts)


def test_filled_is_ok_with_the_fill_price(world):
    world.on_place = fill_at(1.2345)
    out = buy()
    acct = out.accounts[0]
    assert out.state == "success" and acct.ok
    assert acct.account_id == "DU****4567"
    assert "@ $1.2345" in acct.message
    assert acct.extra["fill_price"] == pytest.approx(1.2345)
    assert acct.order_id
    order = world.placed[0][1]
    assert (order.action, order.totalQuantity, order.orderType, order.tif,
            order.account) == ("BUY", 1, "MKT", "DAY", "DU1234567")
    contract = world.placed[0][0]
    assert (contract.symbol, contract.exchange, contract.currency) == ("ABCD", "SMART", "USD")


def test_submitted_but_not_filled_is_ok(world):
    def on_place(ib, trade):
        trade.orderStatus.status = "PreSubmitted"
    world.on_place = on_place
    out = buy()
    acct = out.accounts[0]
    assert acct.ok and "placed" in acct.message and "PreSubmitted" in acct.message


def test_rejected_before_acceptance_is_plain_and_retryable(world):
    reason = ("Order rejected - reason:YOUR ORDER IS NOT ACCEPTED. IN ORDER TO "
              "OBTAIN THE DESIRED POSITION YOUR EQUITY WITH LOAN VALUE MUST "
              "EXCEED; order id 7 pending, working, queued, submitted, placed - "
              "verify the confirmation")

    def on_place(ib, trade):
        ib.errorEvent.emit(trade.order.orderId, 201, reason, trade.contract)
        trade.orderStatus.status = "Cancelled"
    world.on_place = on_place
    out = buy()
    acct = out.accounts[0]
    assert out.state == "failed" and not acct.ok
    assert acct.message.startswith("IBKR rejected it:")
    assert "EQUITY WITH LOAN VALUE" in acct.message
    assert not _forbidden(acct.message), _forbidden(acct.message)
    as_dict = {"ok": False, "message": acct.message, "account_id": acct.account_id}
    assert not A._account_order_may_exist(as_dict)
    assert not A._order_may_exist({"accounts": [as_dict],
                                   "errors": [f"{acct.account_id}: {acct.message}"]})


def test_disconnect_after_sending_says_verify(world):
    def on_place(ib, trade):
        ib.connected = False                  # status never arrives
    world.on_place = on_place
    out = buy()
    acct = out.accounts[0]
    assert not acct.ok
    assert "submitted" in acct.message and "verify" in acct.message
    assert A._account_order_may_exist({"ok": False, "message": acct.message})
    assert len(world.placed) == 1             # never re-sent


def test_no_status_within_the_wait_says_verify(world):
    out = buy()                               # stays PendingSubmit
    acct = out.accounts[0]
    assert not acct.ok
    assert A._account_order_may_exist({"ok": False, "message": acct.message})
    assert len(world.placed) == 1


def test_partial_fill_then_cancel_journals_what_filled(world):
    def on_place(ib, trade):
        trade.orderStatus.status = "Cancelled"
        trade.orderStatus.filled = 1.0
        trade.orderStatus.avgFillPrice = 3.0
    world.on_place = on_place
    out = buy(qty="2")
    acct = out.accounts[0]
    assert acct.ok and acct.extra["qty"] == 1.0


def test_fractional_quantity_is_refused_before_connecting(world):
    out = buy(qty="1.5")
    assert out.state == "failed"
    assert out.accounts[0].message == ("IBKR: fractional quantities aren't "
                                       "supported via the API here — nothing was sent")
    assert world.connects == []


def test_unknown_symbol_is_a_plain_failure(world):
    world.unknown_symbol = True
    out = buy()
    msg = out.accounts[0].message
    assert out.state == "failed" and "doesn't recognize ABCD" in msg
    assert world.placed == [] and not _forbidden(msg)


def test_each_account_is_traded_exactly_once(world):
    world.accounts = ["U1111111", "U2222222", "DU3333333"]
    world.on_place = fill_at(1.0)
    out = buy()
    assert out.state == "success"
    assert sorted(o.account for _c, o in world.placed) == sorted(world.accounts)
    assert [a.account_id for a in out.accounts] == ["U****1111", "U****2222",
                                                    "DU****3333"]
    assert len(world.instances) == 1          # one connection for all of them


def test_only_accounts_trades_just_those(world):
    world.accounts = ["U1111111", "U2222222"]
    world.on_place = fill_at(1.0)
    out = buy(only_accounts=["U****2222"])
    assert [o.account for _c, o in world.placed] == ["U2222222"]
    assert [a.account_id for a in out.accounts] == ["U****2222"]
    assert "ibkr" in A.RETRYABLE_ACCOUNT_BROKERS


def test_only_accounts_that_match_nothing_says_so(world):
    out = buy(only_accounts=["U****9999"])
    assert out.state == "failed" and "None of the requested accounts" in \
        out.accounts[0].message
    assert world.placed == []


def test_a_sell_never_opens_a_short(world):
    world.positions = {"DU1234567": [SimpleNamespace(
        account="DU1234567", position=1.0, avgCost=2.0,
        contract=SimpleNamespace(conId=4242, symbol="ABCD", localSymbol="ABCD"))]}
    out = ibkr.execute_trade(side="sell", qty="2", symbol="ABCD")
    msg = out.accounts[0].message
    assert out.state == "failed" and "short" in msg
    assert world.placed == [] and not _forbidden(msg)

    world.on_place = fill_at(5.0)
    out = ibkr.execute_trade(side="sell", qty="1", symbol="ABCD")
    assert out.state == "success" and world.placed[0][1].action == "SELL"


def test_a_stalled_gateway_is_bounded_and_never_sends_again(world, monkeypatch):
    monkeypatch.setattr(ibkr, "REQUEST_TIMEOUT", 0.1)
    monkeypatch.setattr(ibkr, "ORDER_WAIT", 0.1)
    monkeypatch.setattr(ibkr, "_SLACK", 0.4)
    world.accounts = ["U1111111", "U2222222"]
    release = threading.Event()
    world.on_place = lambda ib, trade: release.wait(10)

    t0 = time.monotonic()
    out = buy()
    took = time.monotonic() - t0
    release.set()

    assert took < 5
    first, second = out.accounts
    assert A._account_order_may_exist({"ok": False, "message": first.message})
    assert not second.ok and not _forbidden(second.message)
    time.sleep(0.5)                           # let the abandoned worker finish
    assert len(world.placed) == 1


def test_second_login_is_its_own_gateway_with_prefixed_labels(world, monkeypatch):
    monkeypatch.setenv("IBKR_PORT_2", "4001")
    world.on_place = fill_at(1.0)
    out = buy()
    assert [c[1] for c in world.connects] == [4002, 4001]
    assert [a.account_id for a in out.accounts] == ["DU****4567",
                                                    "IBKR 2 · DU****4567"]


# ---------------------------------------------------------------- holdings

def test_holdings_parse_positions_and_cash(world):
    world.accounts = ["U1111111"]
    world.positions = {"U1111111": [
        SimpleNamespace(account="U1111111", position=3.0, avgCost=1.5,
                        contract=SimpleNamespace(conId=1, symbol="ABCD",
                                                 localSymbol="ABCD", secType="STK",
                                                 primaryExchange="PINK", currency="USD")),
        SimpleNamespace(account="U1111111", position=2.0, avgCost=400.0,
                        contract=SimpleNamespace(conId=2, symbol="BRK B",
                                                 localSymbol="BRK B", secType="STK",
                                                 primaryExchange="NYSE", currency="USD")),
        SimpleNamespace(account="U1111111", position=0.0, avgCost=0.0,
                        contract=SimpleNamespace(conId=3, symbol="GONE",
                                                 localSymbol="GONE")),
    ]}
    out = ibkr.get_holdings()
    assert out.state == "success"
    acct = out.accounts[0]
    assert acct.account_id == "U****1111"
    rows = {h.symbol: h for h in acct.holdings}
    assert set(rows) == {"ABCD", "BRK.B"}
    assert rows["ABCD"].shares == 3.0 and rows["ABCD"].price is None
    assert rows["ABCD"].extra["avg_cost"] == 1.5
    assert acct.extra["cash"] == 1234.5
    import balances
    assert balances.cash_from_extra("ibkr", acct.extra) == 1234.5


def test_bootstrap_lists_one_row_per_account(world):
    world.accounts = ["U1111111", "DU2222222"]
    out = ibkr.bootstrap()
    assert out.state == "success" and len(out.accounts) == 2
    assert "paper" in out.accounts[1].message


def test_reads_connect_read_only_and_orders_do_not(world):
    # A Gateway with "Read-Only API" ticked refuses a trading-mode connect, so
    # bootstrap/holdings must connect read-only or they fail on that setting
    # (found against a live Gateway). Orders still need trading mode.
    ibkr.bootstrap()
    ibkr.get_holdings()
    assert world.connects and all(c[3] is True for c in world.connects)
    world.connects.clear()
    world.on_place = fill_at(2.0)
    buy()
    assert world.connects and all(c[3] is False for c in world.connects)


# ---------------------------------------------------------------- the event loop

def test_ib_async_does_not_patch_asyncio(world):
    import ib_async  # noqa: F401  -- the real import, as ibkr._new_ib does
    ibkr._contract_api()
    assert not hasattr(asyncio, "_nest_patched")
    assert asyncio.run.__module__ == "asyncio.runners"
    assert asyncio.BaseEventLoop.run_until_complete.__module__ == "asyncio.base_events"


def test_a_session_runs_on_its_own_loop_and_closes_it(world):
    seen = {}

    def on_place(ib, trade):
        loop = asyncio.get_event_loop_policy().get_event_loop()
        seen["loop"] = loop
        seen["thread"] = threading.current_thread()
        fill_at(1.0)(ib, trade)
    world.on_place = on_place
    buy()
    assert seen["thread"] is not threading.current_thread()
    assert seen["loop"].is_closed()


# ---------------------------------------------------------------- registration

def test_ibkr_is_registered_everywhere_a_broker_must_be():
    import runner
    import reconcile
    assert A.BROKER_MODULES["ibkr"] == "ibkr"
    assert runner.BROKER_MODULES["ibkr"] == "ibkr"
    assert "ibkr" in reconcile.BROKERS
    assert "IBKR_PORT" in A.BROKER_ENV_KEYS["ibkr"]
    assert lifecycle.app_key("IBKR") == "ibkr"
    assert lifecycle.app_key("Interactive Brokers") == "ibkr"
    assert "IBKR" in rsa_feed.SUPPORTED_BROKERS
    assert "IBKR" in rsa_feed.CASH_IN_LIEU_BROKERS
    assert capability_for("ibkr") is Capability.WHOLE_ONLY


def test_a_port_is_what_links_ibkr(monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("IBKR_"):
            monkeypatch.delenv(key, raising=False)
    assert BL.logins("ibkr") == []
    monkeypatch.setenv("IBKR_PORT", "4001")
    (login,) = BL.logins("ibkr")
    assert login.complete and login.label_prefix == ""
    schema = BL.SCHEMAS["ibkr"]
    assert not any(f.secret for f in schema.fields)       # no password field
    assert BL.env_key("ibkr", "port", 2) == "IBKR_PORT_2"
    assert BL.tag_key("ibkr", 1) == "IBKR_TAG_1"


def test_ibkr_runs_no_subprocess():
    src = Path(ibkr.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in src


# ---------------------------------------------------------------- a Cancelled is not always a no

def _may_exist(acct) -> bool:
    return A._account_order_may_exist({"ok": acct.ok, "message": acct.message,
                                       "account_id": acct.account_id})


def _retry_plan(out) -> dict:
    rows = [dict(account_id=a.account_id, ok=a.ok, message=a.message)
            for a in out.accounts]
    return A.App._failed_account_plan([{"broker": "ibkr", "accounts": rows}])


def test_a_local_cancel_with_no_rejection_says_verify(world):
    # ib_async marks the order Cancelled itself on any non-warning error for
    # its id; this one is a notice about a live order, not a refusal.
    world.on_place = lambda ib, trade: ib_error(
        ib, trade, 10349, "Order TIF was set to DAY based on order preset.")
    out = buy()
    acct = out.accounts[0]
    assert not acct.ok and _may_exist(acct)
    assert "submitted" in acct.message and "verify" in acct.message
    assert _retry_plan(out) == {}                 # never retried into a 2nd order
    assert len(world.placed) == 1


def test_a_local_cancel_then_submitted_is_placed(world):
    world.on_place = lambda ib, trade: ib_error(ib, trade, 10349, "TIF set to DAY")
    ticks = {"n": 0}

    def on_sleep(ib, trade):
        ticks["n"] += 1
        if ticks["n"] == 3:
            ib_status(trade, "Submitted")
    world.on_sleep = on_sleep
    out = buy()
    acct = out.accounts[0]
    assert acct.ok and "Submitted" in acct.message
    assert len(world.placed) == 1


def test_a_local_cancel_then_filled_is_filled(world):
    world.on_place = lambda ib, trade: ib_error(ib, trade, 10349, "TIF set to DAY")
    world.on_sleep = lambda ib, trade: ib_status(
        trade, "Filled", filled=trade.order.totalQuantity, avg=2.5)
    out = buy()
    acct = out.accounts[0]
    assert acct.ok and "filled" in acct.message
    assert acct.extra["fill_price"] == pytest.approx(2.5)


def test_cancelled_by_ibkr_status_callback_is_plain_and_retryable(world):
    world.on_place = lambda ib, trade: ib_status(trade, "Cancelled")
    out = buy()
    acct = out.accounts[0]
    assert not acct.ok and acct.message.startswith("IBKR rejected it:")
    assert not _forbidden(acct.message) and not _may_exist(acct)
    assert _retry_plan(out) == {"ibkr": [acct.account_id]}


@pytest.mark.parametrize("code,text", [
    (201, "Order rejected - reason:Insufficient funds"),
    (202, "Order cancelled - Reason: outside trading hours"),
    (203, "The security is not available or allowed for this account."),
])
def test_hard_reject_codes_are_plain(world, code, text):
    world.on_place = lambda ib, trade: ib_error(ib, trade, code, text)
    out = buy()
    acct = out.accounts[0]
    assert acct.message.startswith("IBKR rejected it:")
    assert not _forbidden(acct.message) and not _may_exist(acct)


def test_hard_reject_in_the_trade_log_alone_is_enough(world):
    # The errorEvent can go unheard; ib_async's trade log still has the code.
    def on_place(ib, trade):
        trade.orderStatus.status = "Cancelled"
        trade.log.append(SimpleNamespace(
            status="Cancelled", errorCode=201,
            message="Error 201, reqId 1: Order rejected - reason:no permissions"))
    world.on_place = on_place
    acct = buy().accounts[0]
    assert acct.message.startswith("IBKR rejected it:") and not _may_exist(acct)


def test_inactive_without_a_rejection_says_verify(world):
    world.on_place = lambda ib, trade: ib_status(trade, "Inactive")
    acct = buy().accounts[0]
    assert not acct.ok and _may_exist(acct)


def test_inactive_with_a_rejection_is_plain(world):
    def on_place(ib, trade):
        ib_error(ib, trade, 201, "Order rejected - reason:account restricted")
        ib_status(trade, "Inactive")
    world.on_place = on_place
    acct = buy().accounts[0]
    assert acct.message.startswith("IBKR rejected it:") and not _may_exist(acct)


# ---------------------------------------------------------------- Retry after a whole-Gateway failure

def test_retry_after_gateway_down_trades_every_account(world):
    world.accounts = ["U1111111", "U2222222"]
    world.connect_script = [{"raise": ConnectionRefusedError(1225, "refused")}]
    out = buy()
    assert [a.account_id for a in out.accounts] == ["IBKR"]
    plan = _retry_plan(out)
    assert plan == {"ibkr": ["IBKR"]}

    world.on_place = fill_at(1.0)
    out2 = buy(only_accounts=plan["ibkr"])
    assert out2.state == "success"
    assert sorted(o.account for _c, o in world.placed) == ["U1111111", "U2222222"]
    assert not any("None of the requested" in a.message for a in out2.accounts)


def test_retry_of_a_gateway_still_down_reports_it_once(world):
    world.connect_script = [{"raise": ConnectionRefusedError(1225, "refused")}] * 2
    buy()
    out = buy(only_accounts=["IBKR"])
    assert [a.account_id for a in out.accounts] == ["IBKR"]
    assert "isn't running" in out.accounts[0].message
    assert world.placed == []


def test_retry_of_one_gateway_leaves_the_other_alone(world, monkeypatch):
    monkeypatch.setenv("IBKR_PORT_2", "4001")
    world.on_place = fill_at(1.0)
    out = buy(only_accounts=["IBKR 2"])
    assert [a.account_id for a in out.accounts] == ["IBKR 2 · DU****4567"]
    assert len(world.placed) == 1


# ---------------------------------------------------------------- a stall never drops an account

def test_abandoned_session_reports_every_account_even_once_done(world):
    sess = ibkr._Session(ibkr._gateways()[0])
    sess.todo = ["U****1111", "U****2222", "U****3333"]
    sess.outs = [AccountOutput(account_id="U****1111", ok=True, message="order filled")]
    sess.sent = {"U****2222"}
    sess.abandoned = True
    sess.done.set()                           # the worker finished after the give-up
    outs = {o.account_id: o for o in ibkr._session_outputs(sess)}
    assert set(outs) == {"U****1111", "U****2222", "U****3333"}
    assert _may_exist(outs["U****2222"])
    assert not outs["U****3333"].ok and not _forbidden(outs["U****3333"].message)


def test_a_late_error_after_every_account_never_makes_a_gateway_row(world):
    sess = ibkr._Session(ibkr._gateways()[0])
    sess.todo = ["U****1111"]
    sess.outs = [AccountOutput(account_id="U****1111", ok=True, message="order filled")]
    sess.fatal = "IBKR: boom"
    sess.done.set()
    assert [o.account_id for o in ibkr._session_outputs(sess)] == ["U****1111"]


# ---------------------------------------------------------------- labels never collide

def test_accounts_that_mask_alike_get_distinct_stable_labels(world):
    world.accounts = ["U1111234", "U2221234", "U3335678", "DU1111234"]
    world.on_place = fill_at(1.0)
    held = [a.account_id for a in ibkr.get_holdings().accounts]
    traded = [a.account_id for a in buy().accounts]
    booted = [a.account_id for a in ibkr.bootstrap().accounts]
    assert held == traded == booted
    assert len(set(held)) == 4
    assert held[2] == "U****5678" and held[3] == "DU****1234"   # no clash, unchanged
    assert held[0] != held[1] and held[0].startswith("U****")

    world.placed.clear()
    out = buy(only_accounts=[held[1]])
    assert [o.account for _c, o in world.placed] == ["U2221234"]
    assert [a.account_id for a in out.accounts] == [held[1]]


def test_labels_unmask_only_as_far_as_needed():
    gw = ibkr._Gateway(idx=1, host="h", port=1, client_id=1, prefix="")
    labels = ibkr._labels(gw, ["U1111234", "U1121234", "U9995678"])
    assert labels == {"U1111234": "U****11234", "U1121234": "U****21234",
                      "U9995678": "U****5678"}


# ------------------------------------------------- warnings and startup sync

def test_a_warning_after_presubmitted_is_still_placed(world):
    # 399 "won't be placed at the exchange until 09:30": ib_async turns the
    # status into ValidationError, but IBKR already had it PreSubmitted. It
    # used to wait out ORDER_WAIT and come back "verify".
    def on_place(ib, trade):
        ib_status(trade, "PreSubmitted")
        ib_error(ib, trade, 399, "Order Message: BUY 1 ABCD ... will not be "
                                 "placed at the exchange until 09:30")
    world.on_place = on_place
    out = buy()
    acct = out.accounts[0]
    assert acct.ok and "PreSubmitted" in acct.message, acct.message
    assert len(world.placed) == 1


def test_a_warning_before_any_status_from_ibkr_still_says_verify(world):
    world.on_place = lambda ib, trade: ib_error(ib, trade, 399, "Order Message")
    out = buy()
    acct = out.accounts[0]
    assert not acct.ok
    assert A._account_order_may_exist({"ok": False, "message": acct.message})


def test_a_non_warning_validation_error_is_not_promoted(world):
    def on_place(ib, trade):
        ib_status(trade, "PreSubmitted")
        trade.orderStatus.status = "ValidationError"
        trade.log.append(SimpleNamespace(status="ValidationError",
                                         message="Error 999: odd", errorCode=999))
    world.on_place = on_place
    assert not buy().accounts[0].ok


def test_every_connect_raises_startup_sync_errors(world):
    ibkr.get_holdings()
    world.on_place = fill_at(2.0)
    buy()
    assert world.raise_sync and all(world.raise_sync)


def test_a_startup_sync_timeout_is_a_failed_read_not_empty_holdings(world):
    world.connect_script = [{"raise": ConnectionError(["positions request timed out"])}]
    out = ibkr.get_holdings()
    assert out.state == "failed"
    assert not any(a.ok for a in out.accounts)
    assert all(not a.holdings for a in out.accounts)
