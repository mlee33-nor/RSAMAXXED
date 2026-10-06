"""Interactive Brokers, through IB Gateway's official API (ib_async).

HOW IT CONNECTS

IBKR has no password login an app is allowed to automate. The supported route
is IB Gateway: the user installs it, logs in to it themselves (with IBKR's own
2FA), and turns its API on. This module then talks to that local Gateway over a
socket. It never sees, stores or sends an IBKR password. All it is configured
with is where Gateway listens:

    IBKR_HOST       default 127.0.0.1
    IBKR_PORT       4001 = live Gateway, 4002 = paper Gateway. Required: a port
                    is what makes IBKR "linked".
    IBKR_CLIENT_ID  optional; default DEFAULT_CLIENT_ID

A second login is a second Gateway (IBKR_PORT_2, ...), because one Gateway is
one IBKR username. See broker_logins for the key scheme.

THREADS AND EVENT LOOPS

ib_async is asyncio underneath. The app calls brokers from worker threads, and
the zendriver brokers run event loops of their own in theirs, so this module
must not touch anyone else's loop. Every Gateway session therefore runs in a
thread of its own, on a brand-new event loop that is closed when it ends, and
disconnects in a `finally`. The caller waits on it with a watchdog that each
phase re-arms (connect, then each account), so a Gateway that stops answering
costs a bounded wait, not a hung trade.

Importing ib_async does NOT apply nest_asyncio (only `util.startLoop()` /
`util.patchAsyncio()` do, and nothing here calls them), so no other broker's
loop is patched. tests/test_ibkr.py pins that.

Every concurrent connection takes its own clientId (see _claim_client_id): a
holdings refresh that overlaps a trade would otherwise be refused by Gateway
with error 326, "client id is already in use".

WHAT A RESULT MEANS

A failed account whose order MAY exist at IBKR says "submitted ... verify" --
the app never retries those (app._account_order_may_exist). A failure where
nothing went out says none of the words in app._ORDER_MAY_EXIST, which is why
IBKR's own error text goes through _plain() before it reaches a message:
"YOUR ORDER IS NOT ACCEPTED" would otherwise read as "an order may exist".
Nothing here ever re-sends an order.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo

import broker_logins
from modules.broker_logging import log_exception
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow

BROKER = "ibkr"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 4001                 # live Gateway; paper is 4002
#: Arbitrary, but deliberately not 0 (which binds the user's manual TWS
#: orders to this connection) and not 1 (every sample script's default).
DEFAULT_CLIENT_ID = 7311

CONNECT_TIMEOUT = 15.0      # seconds for the socket + API handshake
REQUEST_TIMEOUT = 20.0      # each blocking request once connected
ORDER_WAIT = 20.0           # how long to watch a new order for a status
#: How long a Cancelled/Inactive with no proof IBKR refused the order is
#: watched for a Submitted/Filled that overrides it (see _outcome).
CANCEL_SETTLE = 2.5
#: Fresh clientIds to try when Gateway says one is taken (error 326). A
#: crashed earlier run can hold one until Gateway notices it is gone.
CLIENT_ID_TRIES = 5
#: Watchdog headroom on top of the timeouts a phase is already bounded by.
_SLACK = 10.0


def _connect_budget() -> float:
    """Watchdog for one connect: the handshake, then ib_async's startup sync
    (positions/orders/account updates, then executions), each bounded by
    CONNECT_TIMEOUT."""
    return 3 * CONNECT_TIMEOUT + _SLACK


_ET = ZoneInfo("America/New_York")

for _lname in ("ib_async", "ib_async.client", "ib_async.wrapper", "ib_async.ib"):
    try:
        logging.getLogger(_lname).setLevel(logging.CRITICAL)
    except Exception:
        pass


# =============================================================================
# Paths + logging
# =============================================================================

def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _log_ctx() -> dict:
    return {"log_dir": _root_dir() / "logs"}


def _trace(msg: str) -> None:
    """One line to sessions/ibkr/ibkr_nav.log -- the app tails it for live
    progress while a trade runs. Never a secret: there are none to log."""
    try:
        d = _root_dir() / "sessions" / BROKER
        d.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with (d / f"{BROKER}_nav.log").open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def _write_dry_run_log(*, content: str) -> str:
    d = _root_dir() / "logs" / BROKER / datetime.now(_ET).strftime("%m.%d.%y")
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"test_order_{BROKER}_{uuid.uuid4().hex[:10]}.log"
    path.write_text(content, encoding="utf-8")
    return str(path)


# =============================================================================
# Wording
# =============================================================================

#: Words app._ORDER_MAY_EXIST reads as "an order may be live". A plain failure
#: must contain none of them, and IBKR's own messages are full of them ("YOUR
#: ORDER IS NOT ACCEPTED", "Order held while securities are located" ...).
_MAY_EXIST_SWAPS = (
    (re.compile(r"order\s*id", re.I), "order number"),
    (re.compile(r"submitted", re.I), "sent"),
    (re.compile(r"placed", re.I), "entered"),
    (re.compile(r"accepted", re.I), "allowed"),
    (re.compile(r"pending", re.I), "awaiting"),
    (re.compile(r"queued", re.I), "lined up"),
    (re.compile(r"working", re.I), "active"),
    (re.compile(r"confirmation", re.I), "confirm notice"),
    (re.compile(r"verify", re.I), "check"),
)
_ERR_PREFIX = re.compile(r"^\s*(?:Error|Warning)\s+\d+,\s*reqId\s+-?\d+:\s*", re.I)
_CONTRACT_SUFFIX = re.compile(r",\s*contract:\s.*$", re.I | re.S)


def _plain(text: str) -> str:
    """Text for a failure where NOTHING was sent: no may-exist words left."""
    out = _CONTRACT_SUFFIX.sub("", _ERR_PREFIX.sub("", str(text or ""))).strip()
    for pat, repl in _MAY_EXIST_SWAPS:
        out = pat.sub(repl, out)
    return out


def _gateway_down(port: int) -> str:
    return (f"IB Gateway isn't running or the API is off — open IB Gateway, "
            f"log in, and enable the API (port {port})")


_READ_ONLY_MSG = ("IB Gateway's API is set to Read-Only, so it refuses every "
                  "trade — in Gateway open Configure → Settings → API → "
                  "Settings, untick \"Read-Only API\", and try again")

_LINK_LOST_MSG = ("IB Gateway is open but has lost its link to IBKR's servers "
                  "— usually because the same IBKR username logged in "
                  "somewhere else (a competing session). Log out of the other "
                  "session, let Gateway reconnect, and try again")


def _verify(why: str) -> str:
    """The may-exist wording: the app lists these as 'verify manually' and
    never retries them."""
    return (f"{why} — the order may have been submitted; verify in IBKR "
            f"(TWS / Client Portal → Orders) before retrying")


#: Codes that are news, not problems: market-data farm chatter (2100-2199,
#: except 2110 "connectivity broken") and "connectivity restored".
def _informational(code: int) -> bool:
    return (2100 <= code < 2200 and code != 2110) or code in (1101, 1102)


def _is_read_only(text: str) -> bool:
    t = (text or "").lower()
    return "read-only" in t or "read only" in t


# =============================================================================
# Configuration: one IB Gateway per login
# =============================================================================

@dataclass
class _Gateway:
    idx: int
    host: str
    port: int
    client_id: int
    prefix: str          # account-label prefix; '' for login 1
    problem: str = ""    # a config error, reported instead of connecting

    @property
    def name(self) -> str:
        """The row a whole-login failure is reported under."""
        return "IBKR" if self.idx == 1 else f"IBKR {self.idx}"


def _gateways() -> List[_Gateway]:
    out: List[_Gateway] = []
    for login in broker_logins.logins(BROKER):
        host = login.get("host") or DEFAULT_HOST
        problem = ""
        port = DEFAULT_PORT
        raw_port = login.get("port")
        if not raw_port:
            problem = ("no IB Gateway port set — enter 4001 (live) or 4002 "
                       "(paper) on the Brokers page")
        else:
            try:
                port = int(raw_port)
                if not 0 < port < 65536:
                    raise ValueError
            except ValueError:
                problem = (f"IB Gateway port {raw_port!r} isn't a port number "
                           f"— use 4001 (live) or 4002 (paper)")
        client_id = DEFAULT_CLIENT_ID
        raw_cid = login.get("client_id")
        if raw_cid:
            try:
                client_id = int(raw_cid)
            except ValueError:
                problem = problem or (f"IBKR client ID {raw_cid!r} isn't a whole "
                                      f"number — clear it to use the default")
        out.append(_Gateway(idx=login.idx, host=host, port=port,
                            client_id=client_id, prefix=login.label_prefix,
                            problem=problem))
    return out


_NOT_SET_UP = ("IBKR isn't set up — on the Brokers page enter IB Gateway's port "
               "(4001 live, 4002 paper) and Save")


def _mask(account: str, keep: int = 4) -> str:
    """'U1234567' -> 'U****4567', 'DU1234567' -> 'DU****4567'.

    The leading letters stay because they are what tells a PAPER account (DU)
    from a live one (U): the journal nets buys against sells on this label, and
    a paper fill must never close a live position. `keep` is how many trailing
    characters show; _labels raises it only to tell two accounts apart.
    """
    a = (account or "").strip()
    if len(a) < 5:
        return a or "----"
    lead = re.match(r"[A-Za-z]*", a).group(0)
    rest = a[len(lead):]
    return f"{lead}****{rest[-keep:] if keep < len(rest) else rest}"


def _labels(gw: _Gateway, accounts: List[str]) -> Dict[str, str]:
    """Every account's label, one Gateway's whole account list at a time.

    Two accounts that mask alike ('U1111234' and 'U2221234') would share a
    label, and then the journal nets one's buys against the other's sells and
    a Retry of one trades both. So the colliding ones show more digits until
    they differ. Deterministic: holdings and trades both label from the same
    full managedAccounts list through this one function, so a label means the
    same account everywhere.
    """
    accts = list(dict.fromkeys(str(a).strip() for a in accounts))
    keep = {a: 4 for a in accts}
    while True:
        masked = {a: _mask(a, keep[a]) for a in accts}
        seen: Dict[str, int] = {}
        for m in masked.values():
            seen[m] = seen.get(m, 0) + 1
        clash = [a for a in accts if seen[masked[a]] > 1 and keep[a] < len(a)]
        if not clash:
            return {a: f"{gw.prefix}{m}" for a, m in masked.items()}
        for a in clash:
            keep[a] += 1


# =============================================================================
# clientId allocation
# =============================================================================

_ID_LOCK = threading.Lock()
_IDS_IN_USE: Set[Tuple[str, int, int]] = set()


def _claim_client_id(gw: _Gateway, skip: Set[int]) -> int:
    """The lowest free clientId at or above the configured one, for this
    Gateway. Released when the session ends, so ids do not creep upward."""
    with _ID_LOCK:
        cid = gw.client_id
        while (gw.host, gw.port, cid) in _IDS_IN_USE or cid in skip:
            cid += 1
        _IDS_IN_USE.add((gw.host, gw.port, cid))
        return cid


def _release_client_ids(gw: _Gateway, ids: List[int]) -> None:
    with _ID_LOCK:
        for cid in ids:
            _IDS_IN_USE.discard((gw.host, gw.port, cid))


# =============================================================================
# One Gateway session, in its own thread and event loop
# =============================================================================

def _new_ib() -> Any:
    """A fresh ib_async.IB. Imported here, not at module load, so the app starts
    without paying for ib_async until IBKR is actually used. Tests replace this
    with a fake."""
    from ib_async import IB
    return IB()


def _contract_api():
    from ib_async import MarketOrder, Stock
    return Stock, MarketOrder


class _Fatal(Exception):
    """Ends a session with a message that is already plain and final."""


class _Session:
    """State shared between a Gateway worker thread and the caller waiting on
    it. Everything is read and written under `lock`."""

    def __init__(self, gw: _Gateway):
        self.gw = gw
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.abandoned = False
        self.deadline = time.monotonic() + _connect_budget()
        self.errors: List[Tuple[int, int, str]] = []     # (reqId, code, text)
        self.todo: List[str] = []                        # labels this run will trade
        self.outs: List[AccountOutput] = []
        self.sent: Set[str] = set()   # placeOrder called, outcome not yet recorded
        self.fatal = ""
        self.read_only = False

    def budget(self, secs: float) -> None:
        with self.lock:
            self.deadline = time.monotonic() + secs

    def alive(self) -> bool:
        with self.lock:
            return not self.abandoned

    def claim_send(self, label: str) -> bool:
        """Mark an order as about to go out -- or refuse, if the caller has
        already given up on this session and reported its accounts."""
        with self.lock:
            if self.abandoned:
                return False
            self.sent.add(label)
            return True

    def finish(self, label: str, out: AccountOutput) -> None:
        with self.lock:
            self.sent.discard(label)
            self.outs.append(out)

    def on_error(self, req_id, code, text="", *_rest) -> None:
        try:
            code = int(code)
        except (TypeError, ValueError):
            code = 0
        try:
            req_id = int(req_id)
        except (TypeError, ValueError):
            req_id = -1
        with self.lock:
            self.errors.append((req_id, code, str(text or "")))

    def errors_since(self, mark: int) -> List[Tuple[int, int, str]]:
        with self.lock:
            return list(self.errors[mark:])

    def mark(self) -> int:
        with self.lock:
            return len(self.errors)


def _close_loop(loop: asyncio.AbstractEventLoop) -> None:
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:
        pass
    finally:
        try:
            asyncio.set_event_loop(None)
        except Exception:
            pass
        try:
            loop.close()
        except Exception:
            pass


def _link_lost(errors: List[Tuple[int, int, str]]) -> bool:
    """Did Gateway report losing IBKR's servers, without a later restore?"""
    lost = False
    for _rid, code, _text in errors:
        if code in (1100, 2110):
            lost = True
        elif code in (1101, 1102):
            lost = False
    return lost


def _connect(ib: Any, sess: _Session, claimed: List[int],
             readonly: bool = False) -> List[str]:
    """Connect, trying a fresh clientId if Gateway says one is taken. Returns
    the managed accounts. Raises _Fatal with a message the user can act on.

    `readonly` for sessions that only read (accounts, holdings): a Gateway with
    "Read-Only API" ticked refuses a trading-mode connect outright, and reading
    must not depend on that setting. Only order sessions connect to trade."""
    gw = sess.gw
    skip: Set[int] = set()
    for _attempt in range(CLIENT_ID_TRIES):
        cid = _claim_client_id(gw, skip)
        claimed.append(cid)
        sess.budget(_connect_budget())
        mark = sess.mark()
        _trace(f"connecting to IB Gateway {gw.host}:{gw.port} (client id {cid})")
        exc: Optional[BaseException] = None
        try:
            ib.connect(gw.host, gw.port, clientId=cid,
                       timeout=CONNECT_TIMEOUT, readonly=readonly)
        except BaseException as e:      # noqa: BLE001 -- includes CancelledError
            exc = e
        errs = sess.errors_since(mark)
        connected = False
        try:
            connected = bool(ib.isConnected())
        except Exception:
            pass
        if exc is None and connected:
            if not readonly and any(_is_read_only(t) for _r, _c, t in errs):
                raise _Fatal(_READ_ONLY_MSG)
            if _link_lost(errs):
                raise _Fatal(_LINK_LOST_MSG)
            accounts = [str(a).strip() for a in (ib.managedAccounts() or [])
                        if str(a).strip()]
            if not accounts:
                raise _Fatal("IB Gateway answered but reported no accounts — it "
                             "may still be logging in; wait for it to finish "
                             "and try again")
            _trace(f"connected: {len(accounts)} account(s)")
            return accounts
        if any(code == 326 for _r, code, _t in errs):
            skip.add(cid)
            _trace(f"client id {cid} is in use at Gateway; trying another")
            continue
        raise _Fatal(_explain_connect(exc, gw, errs))
    raise _Fatal(f"IB Gateway refused {CLIENT_ID_TRIES} client IDs in a row as "
                 f"already in use — restart IB Gateway, or set a different "
                 f"IBKR_CLIENT_ID")


def _explain_connect(exc: Optional[BaseException], gw: _Gateway,
                     errs: List[Tuple[int, int, str]]) -> str:
    if any(_is_read_only(t) for _r, _c, t in errs):
        return _READ_ONLY_MSG
    if _link_lost(errs):
        return _LINK_LOST_MSG
    text = str(exc or "").lower()
    if isinstance(exc, ConnectionRefusedError) or "refused" in text \
            or getattr(exc, "winerror", None) in (1225, 10061) \
            or getattr(exc, "errno", None) in (111, 10061):
        return _gateway_down(gw.port)
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return (f"IB Gateway at {gw.host}:{gw.port} didn't finish connecting "
                f"within {int(CONNECT_TIMEOUT)}s — check it is logged in, its "
                f"API is enabled, and accept the incoming-connection prompt if "
                f"Gateway shows one")
    if exc is None:
        return _gateway_down(gw.port)
    detail = _plain(str(exc)) or type(exc).__name__
    return f"Couldn't connect to IB Gateway at {gw.host}:{gw.port}: {detail}"


def _run(gw: _Gateway, job, readonly: bool = False) -> _Session:
    """Run `job(ib, sess, accounts)` against one Gateway, in its own thread on
    its own event loop, and wait for it under the session's watchdog.

    Returns the session either way. If the watchdog fired, `sess.abandoned` is
    set and the worker is left to finish (and disconnect) on its own; it can
    no longer send an order, because claim_send refuses once abandoned.
    """
    sess = _Session(gw)

    def target() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ib = None
        claimed: List[int] = []
        try:
            ib = _new_ib()
            try:
                ib.errorEvent += sess.on_error
            except Exception:
                pass
            accounts = _connect(ib, sess, claimed, readonly=readonly)
            # Only after connecting: connect's own startup sync is bounded by
            # its `timeout`, and a RequestTimeout under it would cut it short.
            try:
                ib.RequestTimeout = REQUEST_TIMEOUT
            except Exception:
                pass
            if sess.alive():
                job(ib, sess, accounts)
        except _Fatal as e:
            sess.fatal = str(e)
        except Exception as e:          # noqa: BLE001
            log_exception(_log_ctx(), broker=BROKER, action="session",
                          label=str(gw.idx), exc=e)
            sess.fatal = _plain(f"IBKR: {e}") or "IBKR: unexpected error"
        finally:
            if ib is not None:
                try:
                    ib.disconnect()
                except Exception:
                    pass
            _release_client_ids(gw, claimed)
            _close_loop(loop)
            sess.done.set()

    t = threading.Thread(target=target, name=f"ibkr-gateway-{gw.idx}", daemon=True)
    t.start()
    while not sess.done.wait(0.2):
        with sess.lock:
            if time.monotonic() > sess.deadline:
                sess.abandoned = True
                break
    if sess.abandoned and not sess.done.is_set():
        _trace("IB Gateway stopped responding; gave up waiting")
    return sess


_STALLED_MSG = ("IB Gateway stopped responding — check it is logged in and not "
                "showing a dialog, then try again")


def _session_outputs(sess: _Session) -> List[AccountOutput]:
    """Every account's outcome, including the ones a stall left unfinished."""
    gw = sess.gw
    # Abandoned alone decides, not "abandoned and still running": a worker that
    # finishes after the caller gave up may have left accounts it never
    # reached, and every account this run meant to trade must get a row.
    with sess.lock:
        outs = list(sess.outs)
        stalled = sess.abandoned
        sent = sorted(sess.sent)
        todo = list(sess.todo)
        fatal = sess.fatal
    if stalled:
        for label in sent:
            outs.append(AccountOutput(
                account_id=label, ok=False,
                message=_verify("IB Gateway stopped responding right after the "
                                "order went out")))
        reached = {o.account_id for o in outs}
        for label in todo:
            if label not in reached:
                outs.append(AccountOutput(
                    account_id=label, ok=False,
                    message=f"{_STALLED_MSG} (nothing was sent for this account)"))
        if not todo and not outs:
            outs.append(AccountOutput(account_id=gw.name, ok=False, message=_STALLED_MSG))
    elif fatal:
        reached = {o.account_id for o in outs}
        left = [l for l in todo if l not in reached]
        for label in left:
            outs.append(AccountOutput(
                account_id=label, ok=False,
                message=(_verify("IBKR raised an error right after the order "
                                 "went out") if label in sent else fatal)))
        # The Gateway-named row means "nothing reached any account" (a Retry
        # of it trades them all), so only a run that never listed its
        # accounts may produce one. Past that, every account has a row.
        if not todo:
            outs.append(AccountOutput(account_id=gw.name, ok=False, message=fatal))
        elif not left:
            _trace(f"session ended with an error after every account had a "
                   f"result: {fatal}")
    return outs


def _state_from_counts(ok_ct: int, fail_ct: int) -> str:
    if ok_ct > 0 and fail_ct == 0:
        return "success"
    if ok_ct > 0:
        return "partial"
    return "failed"


def _config_failure(gw: _Gateway) -> AccountOutput:
    return AccountOutput(account_id=gw.name, ok=False, message=gw.problem)


# =============================================================================
# bootstrap / holdings
# =============================================================================

def bootstrap(*args, **kwargs) -> BrokerOutput:
    """Connect to each configured Gateway and list its accounts (one row each,
    which is what the Brokers page counts)."""
    gws = _gateways()
    if not gws:
        return BrokerOutput(broker=BROKER, state="failed", message=_NOT_SET_UP,
                            accounts=[AccountOutput(account_id="IBKR", ok=False,
                                                    message=_NOT_SET_UP)])
    outs: List[AccountOutput] = []
    for gw in gws:
        if gw.problem:
            outs.append(_config_failure(gw))
            continue

        def job(ib, sess, accounts, gw=gw):
            kind = lambda a: "paper" if a.upper().startswith("D") else "live"
            labels = _labels(gw, accounts)
            for acct in accounts:
                sess.finish(labels[acct], AccountOutput(
                    account_id=labels[acct], ok=True,
                    message=f"connected via IB Gateway {gw.host}:{gw.port} "
                            f"({kind(acct)})"))

        outs.extend(_session_outputs(_run(gw, job, readonly=True)))

    ok_ct = sum(1 for a in outs if a.ok)
    state = _state_from_counts(ok_ct, len(outs) - ok_ct)
    msg = (f"ok ({ok_ct} account{'s' if ok_ct != 1 else ''})" if state == "success"
           else "; ".join(a.message for a in outs if not a.ok))
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)


def healthcheck(*args, **kwargs) -> BrokerOutput:
    return bootstrap(*args, **kwargs)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return bootstrap(*args, **kwargs)


def _symbol_out(contract: Any) -> str:
    """IBKR writes share classes with a space ('BRK B'); the journal, the feed
    and Yahoo use a dot."""
    sym = str(getattr(contract, "localSymbol", "") or getattr(contract, "symbol", "")
              or "?").strip().upper()
    return sym.replace(" ", ".") or "?"


def _float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _cash(ib: Any, account: str) -> Optional[float]:
    """TotalCashValue from the account summary, or None if IBKR won't say."""
    try:
        for v in ib.accountSummary(account) or []:
            if getattr(v, "tag", "") == "TotalCashValue" and \
                    getattr(v, "account", account) == account:
                return _float(getattr(v, "value", None))
    except Exception:
        pass
    return None


def _holdings_for(ib: Any, account: str) -> List[HoldingRow]:
    """Positions from Gateway. `price` stays None on purpose: avgCost is a cost
    basis, not a quote, and the app reads HoldingRow.price as the market price
    it journals a trade at."""
    rows: List[HoldingRow] = []
    for p in ib.positions(account) or []:
        qty = _float(getattr(p, "position", None))
        if not qty:
            continue
        c = getattr(p, "contract", None)
        rows.append(HoldingRow(
            symbol=_symbol_out(c), shares=qty, price=None,
            extra={
                "avg_cost": _float(getattr(p, "avgCost", None)),
                "sec_type": str(getattr(c, "secType", "") or ""),
                "con_id": getattr(c, "conId", None),
                "exchange": str(getattr(c, "primaryExchange", "")
                                or getattr(c, "exchange", "") or ""),
                "currency": str(getattr(c, "currency", "") or ""),
            }))
    return rows


def get_holdings(*args, **kwargs) -> BrokerOutput:
    gws = _gateways()
    if not gws:
        return BrokerOutput(broker=BROKER, state="failed", message=_NOT_SET_UP,
                            accounts=[AccountOutput(account_id="IBKR", ok=False,
                                                    message=_NOT_SET_UP)])
    outs: List[AccountOutput] = []
    for gw in gws:
        if gw.problem:
            outs.append(_config_failure(gw))
            continue

        def job(ib, sess, accounts, gw=gw):
            labels = _labels(gw, accounts)
            with sess.lock:
                sess.todo = [labels[a] for a in accounts]
            for acct in accounts:
                if not sess.alive():
                    return
                sess.budget(2 * REQUEST_TIMEOUT + _SLACK)
                label = labels[acct]
                try:
                    holdings = _holdings_for(ib, acct)
                    cash = _cash(ib, acct)
                    sess.finish(label, AccountOutput(
                        account_id=label, ok=True,
                        message=f"{len(holdings)} position"
                                f"{'s' if len(holdings) != 1 else ''}",
                        holdings=holdings,
                        extra={"cash": cash, "positions_count": len(holdings)}))
                except Exception as e:      # noqa: BLE001
                    sess.finish(label, AccountOutput(
                        account_id=label, ok=False,
                        message=_plain(f"Could not read positions: {e}")))

        outs.extend(_session_outputs(_run(gw, job, readonly=True)))

    ok_ct = sum(1 for a in outs if a.ok)
    return BrokerOutput(broker=BROKER, state=_state_from_counts(ok_ct, len(outs) - ok_ct),
                        accounts=outs, message="")


# =============================================================================
# Trading
# =============================================================================

_DONE = ("Cancelled", "ApiCancelled", "Inactive")
_LIVE = ("PreSubmitted", "Submitted")

#: IBKR error codes that are IBKR's own verdict that this order is dead and
#: nothing of it is working: 200 no security definition (it cannot route),
#: 201 "Order rejected - reason: ...", 202 "Order cancelled - reason: ...",
#: 203 "The security is not available or allowed for this account".
#: Deliberately NOT every error: ib_async's wrapper.error() marks an order
#: Cancelled LOCALLY on any non-warning code for its id, and plenty of those
#: are notices about an order that is still live (a later Submitted/Filled
#: can follow). 10147/10148 are about cancel requests, which this module
#: never sends.
_HARD_REJECT = frozenset({200, 201, 202, 203})
_CANCELLED = ("Cancelled", "ApiCancelled")


@dataclass
class _Request:
    action: str          # 'BUY' | 'SELL'
    qty: int
    symbol: str          # as the app writes it: 'BRK.B'
    dry_run: bool
    only: Optional[Set[str]]


def _ib_symbol(sym: str) -> str:
    return sym.replace(".", " ")


def _reason(sess: _Session, mark: int, req_id: Optional[int] = None,
            trade: Any = None) -> str:
    """IBKR's own explanation for a refusal, plainly worded, or ''."""
    texts: List[str] = []
    for rid, code, text in sess.errors_since(mark):
        if _informational(code):
            continue
        if req_id is not None and rid not in (req_id, -1):
            continue
        if text and text not in texts:
            texts.append(text)
    if not texts and trade is not None:
        for entry in getattr(trade, "log", None) or []:
            m = str(getattr(entry, "message", "") or "")
            code = int(getattr(entry, "errorCode", 0) or 0)
            if m and code and not _informational(code) and m not in texts:
                texts.append(m)
    return "; ".join(_plain(t) for t in texts if _plain(t))


def _hard_rejected(sess: _Session, mark: int, req_id: Optional[int],
                   trade: Any, status: str) -> bool:
    """Is there proof IBKR itself killed this order, not just ib_async?

    Either a _HARD_REJECT code for this order (in the session's errors or the
    trade's log), or a Cancelled that arrived through an orderStatus callback:
    ib_async logs those with errorCode 0, while the Cancelled it sets itself
    on an error() carries that error's code. Inactive is never proof on its
    own -- IBKR also reports held orders as Inactive.
    """
    for rid, code, _text in sess.errors_since(mark):
        if code in _HARD_REJECT and req_id is not None and rid == req_id:
            return True
    for entry in getattr(trade, "log", None) or []:
        try:
            code = int(getattr(entry, "errorCode", 0) or 0)
        except (TypeError, ValueError):
            code = 0
        if code in _HARD_REJECT:
            return True
        if code == 0 and status in _CANCELLED and \
                str(getattr(entry, "status", "") or "") in _CANCELLED:
            return True
    return False


def _held(ib: Any, account: str, contract: Any, symbol: str) -> float:
    total = 0.0
    con_id = getattr(contract, "conId", 0)
    for p in ib.positions(account) or []:
        c = getattr(p, "contract", None)
        same = (con_id and getattr(c, "conId", None) == con_id) or \
            _symbol_out(c) == symbol
        if same:
            total += _float(getattr(p, "position", 0)) or 0.0
    return total


def _ticket(req: _Request, label: str) -> str:
    return ("DRY RUN — NO ORDER SUBMITTED\n"
            f"side: {req.action}\n"
            f"symbol: {req.symbol}\n"
            f"quantity: {req.qty}\n"
            f"order_type: MARKET\n"
            f"tif: DAY\n"
            f"route: SMART (USD)\n"
            f"account: {label}")


def _what_if_line(state: Any) -> str:
    parts = []
    comm = _float(getattr(state, "commission", None))
    if comm is not None and 0 <= comm < 1e9:
        parts.append(f"commission ~${comm:.2f}")
    margin = _float(getattr(state, "initMarginChange", None))
    if margin is not None and abs(margin) < 1e12:
        parts.append(f"init margin change ${margin:,.2f}")
    warn = str(getattr(state, "warningText", "") or "").strip()
    if warn:
        parts.append(f"note: {warn}")
    return "IBKR what-if: OK" + (f" ({'; '.join(parts)})" if parts else "")


def _trade_one(ib: Any, sess: _Session, contract: Any, account: str,
               label: str, req: _Request) -> AccountOutput:
    _Stock, MarketOrder = _contract_api()

    if sess.read_only:
        return AccountOutput(account_id=label, ok=False, message=_READ_ONLY_MSG)

    # A market SELL for more than the account holds opens a SHORT at IBKR
    # rather than being refused the way every other broker here refuses it.
    if req.action == "SELL":
        held = _held(ib, account, contract, req.symbol)
        if held < req.qty:
            return AccountOutput(
                account_id=label, ok=False,
                message=(f"IBKR: this account holds {held:g} {req.symbol}; selling "
                         f"{req.qty} would open a short, so nothing was sent"))

    order = MarketOrder(req.action, req.qty, account=account, tif="DAY")

    if req.dry_run:
        mark = sess.mark()
        try:
            state = ib.whatIfOrder(contract, order)
        except Exception as e:          # noqa: BLE001 -- e.g. RequestTimeout
            state = None
            err = str(e) or type(e).__name__
        else:
            err = ""
        reason = _reason(sess, mark) or _plain(err)
        if not state:
            if _is_read_only(reason):
                sess.read_only = True
                return AccountOutput(account_id=label, ok=False, message=_READ_ONLY_MSG)
            return AccountOutput(
                account_id=label, ok=False,
                message=f"IBKR refused the test: {reason or 'no answer to the what-if check'}")
        return AccountOutput(account_id=label, ok=True,
                             message=_ticket(req, label) + "\n" + _what_if_line(state))

    if not sess.claim_send(label):
        return AccountOutput(account_id=label, ok=False,
                             message=f"{_STALLED_MSG} (nothing was sent for this account)")
    mark = sess.mark()
    _trace(f"{label}: sending {req.action} {req.qty} {req.symbol}")
    try:
        trade = ib.placeOrder(contract, order)
    except Exception as e:              # noqa: BLE001
        return AccountOutput(account_id=label, ok=False,
                             message=_verify(f"IBKR raised an error while the order "
                                             f"was going out ({_plain(str(e))})"))
    try:
        return _outcome(ib, sess, trade, label, req, mark)
    except Exception as e:              # noqa: BLE001
        return AccountOutput(account_id=label, ok=False,
                             message=_verify(f"lost track of the order at IBKR "
                                             f"({_plain(str(e))})"))


def _outcome(ib: Any, sess: _Session, trade: Any, label: str, req: _Request,
             mark: int) -> AccountOutput:
    """Watch a sent order for up to ORDER_WAIT and say what it is.

    A Cancelled/Inactive status is not taken at its word: ib_async sets
    Cancelled itself, locally, on any non-warning error for the order's id,
    and IBKR can still answer Submitted or Filled after that. Unless IBKR
    plainly refused it (_hard_rejected), the order is watched CANCEL_SETTLE
    longer, and if it stays down it is reported as may-exist, never as a
    rejection the app would retry into a second order.
    """
    order = getattr(trade, "order", None)
    req_id = getattr(order, "orderId", None)
    end = time.monotonic() + ORDER_WAIT
    settle_end: Optional[float] = None
    connected = True
    while True:
        status = str(getattr(trade.orderStatus, "status", "") or "")
        if status == "Filled":
            break
        now = time.monotonic()
        if status in _DONE:
            if _hard_rejected(sess, mark, req_id, trade, status):
                break
            if settle_end is None:
                settle_end = now + CANCEL_SETTLE
            elif now >= settle_end:
                break
        else:
            settle_end = None
        try:
            connected = bool(ib.isConnected())
        except Exception:
            connected = False
        if not connected or (settle_end is None and now >= end):
            break
        ib.sleep(0.25)

    st = trade.orderStatus
    status = str(getattr(st, "status", "") or "")
    filled = _float(getattr(st, "filled", 0)) or 0.0
    avg = _float(getattr(st, "avgFillPrice", 0)) or 0.0
    order_id = getattr(order, "permId", 0) or getattr(order, "orderId", 0)
    oid = str(order_id) if order_id else None
    price = f" @ ${avg:,.4f}".rstrip("0").rstrip(".") if avg else ""

    if status == "Filled":
        _trace(f"{label}: filled {filled:g}{price}")
        return AccountOutput(account_id=label, ok=True,
                             message=f"order filled{price}", order_id=oid,
                             extra={"fill_price": avg or None})

    if status in _DONE:
        reason = _reason(sess, mark, req_id, trade)
        if filled > 0:
            # Shares changed hands; the rest is gone. Journal what filled.
            _trace(f"{label}: partly filled {filled:g}, rest cancelled")
            return AccountOutput(
                account_id=label, ok=True, order_id=oid,
                message=(f"partly filled {filled:g} of {req.qty}{price}; IBKR "
                         f"cancelled the rest" + (f": {reason}" if reason else "")),
                extra={"qty": filled, "fill_price": avg or None})
        if _is_read_only(reason):
            sess.read_only = True
            return AccountOutput(account_id=label, ok=False, message=_READ_ONLY_MSG)
        if _hard_rejected(sess, mark, req_id, trade, status):
            _trace(f"{label}: refused ({status})")
            return AccountOutput(account_id=label, ok=False,
                                 message=f"IBKR rejected it: {reason or status}")
        _trace(f"{label}: {status} with no rejection from IBKR")
        return AccountOutput(
            account_id=label, ok=False, order_id=oid,
            message=_verify(f"IBKR showed the order as {status} without saying "
                            f"it was rejected" + (f" ({reason})" if reason else "")))

    if status in _LIVE:
        # IBKR has it and it is live: a market order outside regular hours
        # sits PreSubmitted until the open. Same answer the other brokers give
        # for an order that went in and has not filled yet.
        part = f", {filled:g} filled so far{price}" if filled else ""
        _trace(f"{label}: {status}{part}")
        return AccountOutput(account_id=label, ok=True, order_id=oid,
                             message=f"order placed (IBKR: {status}, not filled yet{part})")

    reason = _reason(sess, mark, req_id, trade)
    if status == "ValidationError" and _is_read_only(reason):
        sess.read_only = True
        return AccountOutput(account_id=label, ok=False, message=_READ_ONLY_MSG)
    why = ("the connection to IB Gateway dropped before IBKR confirmed it"
           if not connected else
           f"IBKR hadn't confirmed it after {int(ORDER_WAIT)}s"
           f" (status: {status or 'none'})")
    _trace(f"{label}: unconfirmed — {why}")
    return AccountOutput(account_id=label, ok=False, order_id=oid,
                         message=_verify(why))


def _trade_job(ib: Any, sess: _Session, accounts: List[str], req: _Request) -> None:
    gw = sess.gw
    labels = _labels(gw, accounts)
    pairs = [(a, labels[a]) for a in accounts]
    # A row named after the Gateway itself only ever reports a failure where
    # nothing was sent (it never reached the account list), so retrying it
    # means every account behind that Gateway.
    if req.only is not None and gw.name not in req.only:
        pairs = [(a, l) for a, l in pairs if l in req.only]
    with sess.lock:
        sess.todo = [l for _a, l in pairs]
    if not pairs:
        return

    Stock, _MarketOrder = _contract_api()
    contract = Stock(_ib_symbol(req.symbol), "SMART", "USD")
    sess.budget(REQUEST_TIMEOUT + _SLACK)
    mark = sess.mark()
    try:
        found = ib.qualifyContracts(contract) or []
    except Exception:                   # noqa: BLE001 -- e.g. RequestTimeout
        found = []
    found = [c for c in found
             if c is not None and not isinstance(c, list) and getattr(c, "conId", 0)]
    if len(found) != 1:
        reason = _reason(sess, mark)
        msg = (f"IBKR doesn't recognize {req.symbol} as a single US stock"
               + (f": {reason}" if reason else "") + " — nothing was sent")
        for _a, label in pairs:
            sess.finish(label, AccountOutput(account_id=label, ok=False, message=msg))
        return
    contract = found[0]

    for acct, label in pairs:
        if not sess.alive():
            return
        sess.budget(2 * REQUEST_TIMEOUT + ORDER_WAIT + _SLACK)
        try:
            out = _trade_one(ib, sess, contract, acct, label, req)
        except Exception as e:          # noqa: BLE001 -- only before any send
            out = AccountOutput(account_id=label, ok=False,
                                message=_plain(f"IBKR: {e}") + " — nothing was sent")
        sess.finish(label, out)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False,
                  only_accounts: Optional[List[str]] = None,
                  **kwargs) -> BrokerOutput:
    """One DAY market order per IBKR account, whole shares only.

    `only_accounts` narrows to those account labels (exactly as this module
    returns them), which is what lets the app retry just the accounts that
    failed. A Gateway's own name ("IBKR", "IBKR 2") stands for all of that
    Gateway's accounts: that row is only ever a whole-login failure where
    nothing was sent. A dry run asks IBKR's what-if check and sends nothing.
    """
    side_norm = (side or "").strip().lower()
    if side_norm not in ("buy", "sell"):
        return BrokerOutput(broker=BROKER, state="failed", accounts=[],
                            message=f"Invalid side: {side!r}")
    sym = (symbol or "").strip().upper()
    if not sym:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[],
                            message="Invalid symbol")
    try:
        q = Decimal(str(qty).strip())
        if q <= 0:
            raise InvalidOperation
    except (InvalidOperation, ValueError, AttributeError):
        return BrokerOutput(broker=BROKER, state="failed", accounts=[],
                            message=f"Invalid qty: {qty!r}")
    if q != q.to_integral_value():
        msg = "IBKR: fractional quantities aren't supported via the API here"
        return BrokerOutput(broker=BROKER, state="failed", message=msg,
                            accounts=[AccountOutput(account_id="IBKR", ok=False,
                                                    message=msg)])

    gws = _gateways()
    if not gws:
        return BrokerOutput(broker=BROKER, state="failed", message=_NOT_SET_UP,
                            accounts=[AccountOutput(account_id="IBKR", ok=False,
                                                    message=_NOT_SET_UP)])

    only = ({str(a).strip() for a in only_accounts if str(a).strip()}
            if only_accounts else None)
    req = _Request(action=side_norm.upper(), qty=int(q), symbol=sym,
                   dry_run=bool(dry_run), only=only)
    _trace(f"{'DRY RUN ' if dry_run else ''}{req.action} {req.qty} {sym}")

    outs: List[AccountOutput] = []
    matched = False
    for gw in gws:
        whole = only is not None and gw.name in only
        if gw.problem:
            if only is None or whole:
                outs.append(_config_failure(gw))
                matched = matched or whole
            continue
        sess = _run(gw, lambda ib, s, accounts: _trade_job(ib, s, accounts, req))
        got = _session_outputs(sess)
        matched = matched or (whole and bool(got))
        outs.extend(got)

    # Nothing matched and nothing failed to explain why: say so, rather than
    # report an empty success for a retry that traded nothing.
    if only is not None and not matched and not any(o.account_id in only for o in outs) \
            and all(o.ok for o in outs):
        outs.append(AccountOutput(
            account_id="IBKR", ok=False,
            message=f"None of the requested accounts were found: {sorted(only)}"))

    ok_ct = sum(1 for a in outs if a.ok)
    state = _state_from_counts(ok_ct, len(outs) - ok_ct)

    message = ""
    if dry_run:
        lines = ["DRY RUN — NO ORDER SUBMITTED", f"broker: {BROKER}",
                 f"time_et: {datetime.now(_ET).isoformat()}",
                 f"requested: side={req.action} symbol={sym} qty={req.qty}", ""]
        for o in outs:
            lines += [f"[{o.account_id}] {'OK' if o.ok else 'FAILED'}", o.message, ""]
        try:
            message = (f"DRY RUN — NO ORDER SUBMITTED | log: "
                       f"{_write_dry_run_log(content=chr(10).join(lines).rstrip() + chr(10))}")
        except Exception:
            message = "DRY RUN — NO ORDER SUBMITTED"
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=message)
