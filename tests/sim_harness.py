"""End-to-end launch simulator: the real App logic, fake brokers, fake feed,
fake clock, no window, no network, no real state file.

What runs for real
------------------
Every App method on the buy and sell paths -- _mirror_resume, _mirror_poll,
_mirror_check_now (and its worker thread), _mirror_execute, _mirror_drain,
_mirror_launch_pick, _live_start, _trade_worker (real threads), the leg
watchdog, _trade_broker_complete, _trade_batch_finish/_report/_release,
_mirror_record_outcome, _autosell_consider/_pump/_resolve/_fire,
_exit_resolve_worker (real threads), _exit_fire, _exit_batch_settle -- plus the
module-level helpers they call (_fetch_quick_picks, _pick_broker_map,
_sellnow_tasks, lifecycle.resolve/pull, trade_journal, mirror_journal).

What is faked
-------------
* The Tk root. SimApp is a plain object; App's functions are bound onto it by
  __getattr__. Only drawing methods are overridden (they would build widgets),
  and `after` is a thread-safe timer heap on the fake clock instead of Tk's.
* Time. app/trade_journal/mirror_journal/lifecycle see a FakeClock through
  their module-level `datetime`/`date`, and market_calendar.now_et reads it.
  The driver advances the clock to the next timer whenever every live worker
  thread has gone quiet, so a 70-minute watchdog costs milliseconds.
* Brokers: FakeBroker, one per BROKER_MODULES key, injected via _load_broker.
  Multiple accounts each, multi-login at Public and Fidelity, real positions,
  every order recorded, failure modes with each module's real wording.
* The cloud feed: FakeCloud replaces cloud_sync (and sys.modules['cloud_sync']
  for lifecycle.fetch_cloud). Picks and exits are produced by running fake
  Alert Bot embeds / exit messages through the real rsa_feed parsers.

App.__init__ itself cannot run (it builds the whole window). SimApp.__init__
replicates its runtime-state block and the mirror-state restore from
_build_settings; keep those in step with app.py.
"""

from __future__ import annotations

import heapq
import itertools
import json
import random
import sys
import threading
import time
import types
from dataclasses import dataclass
from datetime import date as _real_date, datetime as _real_datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A  # noqa: E402
import lifecycle  # noqa: E402
import mirror_journal  # noqa: E402
import rsa_feed  # noqa: E402
import trade_journal  # noqa: E402
from modules import atomic, market_calendar  # noqa: E402,F401  (atomic: tests restore it)
from modules.outputs import AccountOutput, BrokerOutput, HoldingRow  # noqa: E402

NY = ZoneInfo("America/New_York")


# =========================================================================
# Clock
# =========================================================================

class FakeClock:
    """One instant shared by every patched module. "Local" time is New York:
    the simulated machine sits in ET, so naive datetime.now() == ET wall time."""

    def __init__(self, et_wall: _real_datetime):
        self._lock = threading.Lock()
        self._t = et_wall.replace(tzinfo=NY).astimezone(timezone.utc)

    def utc(self) -> _real_datetime:
        with self._lock:
            return self._t

    def set_et(self, et_wall: _real_datetime) -> None:
        with self._lock:
            self._t = et_wall.replace(tzinfo=NY).astimezone(timezone.utc)

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t = self._t + timedelta(seconds=seconds)

    def advance_to(self, utc: _real_datetime) -> None:
        with self._lock:
            if utc > self._t:
                self._t = utc

    def now(self, tz=None) -> _real_datetime:
        t = self.utc()
        if tz is None:
            return t.astimezone(NY).replace(tzinfo=None)
        return t.astimezone(tz)

    def et(self) -> _real_datetime:
        return self.utc().astimezone(NY)


def make_fake_datetime(clock: FakeClock):
    class FakeDateTime(_real_datetime):
        @classmethod
        def now(cls, tz=None):                         # noqa: D401
            return clock.now(tz)

        @classmethod
        def today(cls):
            return clock.now()

        @classmethod
        def utcnow(cls):
            return clock.utc().replace(tzinfo=None)

    class FakeDate(_real_date):
        @classmethod
        def today(cls):
            return clock.now().date()

    return FakeDateTime, FakeDate


# =========================================================================
# Timers + threads
# =========================================================================

class Scheduler:
    """Tk's `after`, on the fake clock, callable from any thread."""

    def __init__(self, clock: FakeClock):
        self.clock = clock
        self._lock = threading.RLock()
        self._heap: List[tuple] = []
        self._seq = itertools.count()
        self._cancelled: set = set()

    def after(self, ms, func=None, *args):
        if func is None:
            return None
        due = self.clock.utc() + timedelta(milliseconds=float(ms or 0))
        with self._lock:
            n = next(self._seq)
            tid = f"after#{n}"
            heapq.heappush(self._heap, (due, n, tid, func, args))
        return tid

    def cancel(self, tid) -> None:
        if tid is None:
            return
        with self._lock:
            self._cancelled.add(tid)

    def pop_due(self):
        now = self.clock.utc()
        with self._lock:
            while self._heap:
                due, n, tid, func, args = self._heap[0]
                if tid in self._cancelled:
                    heapq.heappop(self._heap)
                    self._cancelled.discard(tid)
                    continue
                if due <= now:
                    heapq.heappop(self._heap)
                    return func, args
                return None
        return None

    def next_due(self) -> Optional[_real_datetime]:
        with self._lock:
            while self._heap and self._heap[0][2] in self._cancelled:
                tid = heapq.heappop(self._heap)[2]
                self._cancelled.discard(tid)
            return self._heap[0][0] if self._heap else None

    def pending(self) -> int:
        with self._lock:
            return sum(1 for e in self._heap if e[2] not in self._cancelled)


class ThreadTracker:
    """Every thread the app starts, so the driver knows when work is quiet.

    A thread that a fake broker deliberately hangs is PARKED: it is alive
    forever and must not stop the clock. The trade worker's progress ticker
    loops on real 3-second waits for as long as its leg runs; it is never
    counted either."""

    IGNORE_TARGETS = {"progress_ticker"}

    def __init__(self):
        self._lock = threading.Lock()
        self.threads: List[threading.Thread] = []
        self.parked: set = set()

    def make_module(self):
        tracker = self
        real = threading

        class TrackedThread(real.Thread):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                tgt = k.get("target") if "target" in k else (a[1] if len(a) > 1 else None)
                self._sim_name = getattr(tgt, "__name__", "")
                with tracker._lock:
                    tracker.threads.append(self)

        mod = types.ModuleType("threading_tracked")
        for name in dir(real):
            if not name.startswith("__"):
                setattr(mod, name, getattr(real, name))
        mod.Thread = TrackedThread
        return mod

    def park_current(self) -> None:
        with self._lock:
            self.parked.add(threading.get_ident())

    def busy(self) -> List[threading.Thread]:
        with self._lock:
            live = [t for t in self.threads if t.is_alive()]
            self.threads = [t for t in self.threads if t.is_alive()]
            return [t for t in live if t.ident not in self.parked
                    and t._sim_name not in self.IGNORE_TARGETS]


# =========================================================================
# Market
# =========================================================================

class Market:
    """Quote per symbol. Fills are journaled at these prices (the worker's
    _fetch_quote_price), so P/L expectations are exact."""

    def __init__(self):
        self.prices: Dict[str, float] = {}
        self._lock = threading.Lock()

    def set(self, symbol: str, price: float) -> None:
        with self._lock:
            self.prices[symbol.upper()] = float(price)

    def price(self, symbol: str) -> Optional[float]:
        with self._lock:
            return self.prices.get(str(symbol).upper())


# =========================================================================
# Fake brokers
# =========================================================================

#: How each broker labels itself on a whole-login failure row.
LOGIN_LABEL = {"chase": "Chase", "fennel": "Fennel", "fidelity": "Fidelity",
               "ibkr": "IBKR", "public": "Public", "robinhood": "Robinhood",
               "schwab": "Schwab", "sofi": "SoFi", "wellsfargo": "Wells Fargo"}

#: Accounts per login, by broker. Public and Fidelity have two logins.
FLEET: Dict[str, List[List[str]]] = {
    "chase": [["CHASE (...1001)", "CHASE (...1002)", "CHASE (...1003)"]],
    "fennel": [["Fennel · Individual (F0001)", "Fennel · Individual (F0002)"]],
    "fidelity": [["Fidelity 1 - Individual (Z10001)", "Fidelity 1 - Roth IRA (Z10002)"],
                 ["Fidelity 2 - Individual (Z20001)", "Fidelity 2 - Joint (Z20002)"]],
    "ibkr": [["IBKR U1000001", "IBKR U1000002"]],
    "public": [["Public 1 BROKERAGE (1001)", "Public 1 BROKERAGE (1002)",
                "Public 1 BROKERAGE (1003)"],
               ["Public 2 BROKERAGE (2001)", "Public 2 BROKERAGE (2002)"]],
    "robinhood": [["individual (****0041)", "ira_roth (****0042)"]],
    "schwab": [["Schwab (...101)", "Schwab (...102)"]],
    "sofi": [["SoFi Invest (...501)", "SoFi Invest (...502)"]],
    "wellsfargo": [["WELLSTRADE (****1001)", "WELLSTRADE (****1002)",
                    "WELLSTRADE (****1003)"]],
}

ACCOUNT_BROKERS = ("fidelity", "wellsfargo", "ibkr")   # take only_accounts

#: Order-time failure modes.
#:   ok              every account fills
#:   refuse          every account rejected by the broker (nothing sent)
#:   login_fail      no login got in (nothing sent)
#:   login2_fail     multi-login brokers: login 2 refused, login 1 fills
#:   timeout_before  gave up before any order page (nothing sent)
#:   timeout_after   orders sent, confirmation lost ("submitted ... verify")
#:   raise_before    exception before anything is sent
#:   raise_after     orders sent, then the module raises
#:   partial         first account fills, the rest session-expired (not sent)
#:   hang_before     never returns, nothing sent
#:   hang_after      orders reach the broker, then never returns
MODES = ("ok", "refuse", "login_fail", "login2_fail", "timeout_before",
         "timeout_after", "raise_before", "raise_after", "partial",
         "hang_before", "hang_after")

#: Holdings-read failure modes: ok, raise, failed (login refused), unread
#: (one account could not be read), empty_success (dead session, 0 accounts),
#: hang.


@dataclass
class Order:
    broker: str
    account: str
    side: str
    symbol: str
    qty: Decimal
    status: str          # filled | unconfirmed | rejected
    t: str = ""

    @property
    def reached(self) -> bool:
        """An order the broker has (or may have)."""
        return self.status in ("filled", "unconfirmed")


class FakeBroker:
    def __init__(self, name: str, sim: "Sim"):
        self.name = name
        self.sim = sim
        self.logins = [list(l) for l in FLEET[name]]
        self.lock = threading.RLock()
        # account -> SYMBOL -> Decimal shares
        self.positions: Dict[str, Dict[str, Decimal]] = {a: {} for a in self.accounts()}
        self.orders: List[Order] = []
        self.calls: List[dict] = []
        self.holdings_calls = 0
        self.modes: Dict[tuple, List[str]] = {}       # (side, SYM|*) -> queue
        self.holdings_modes: List[str] = []
        self.release = threading.Event()              # frees hung calls
        self.latency: Tuple[float, float] = (0.0, 0.0)
        self.rng = random.Random(sum(map(ord, name)))
        # A sell the broker took but has not filled ("working") still shows
        # the shares on a live read. False = it filled.
        self.working_orders_hold_shares = False
        self._busy = 0
        self.max_concurrent = 0

    # ----- configuration
    def accounts(self) -> List[str]:
        return [a for login in self.logins for a in login]

    def set_mode(self, mode: str, side: str = "*", symbol: str = "*", times: int = 0):
        """`times` = 0: sticky. Otherwise the mode applies to that many calls,
        then the broker behaves normally again."""
        assert mode in MODES, mode
        key = (side, symbol.upper() if symbol != "*" else "*")
        self.modes[key] = [mode] * times if times else [mode, "__sticky__"]

    def set_holdings_mode(self, mode: str, times: int = 0):
        self.holdings_modes = [mode] * times if times else [mode, "__sticky__"]

    def _take_mode(self, side: str, symbol: str) -> str:
        for key in ((side, symbol), (side, "*"), ("*", symbol), ("*", "*")):
            q = self.modes.get(key)
            if not q:
                continue
            if len(q) == 2 and q[1] == "__sticky__":
                return q[0]
            mode = q.pop(0)
            if not q:
                del self.modes[key]
            return mode
        return "ok"

    def _take_holdings_mode(self) -> str:
        q = self.holdings_modes
        if not q:
            return "ok"
        if len(q) == 2 and q[1] == "__sticky__":
            return q[0]
        mode = q.pop(0)
        return mode

    def hold(self, account: str, symbol: str, qty) -> None:
        with self.lock:
            self.positions.setdefault(account, {})[symbol.upper()] = Decimal(str(qty))

    def held(self, account: str, symbol: str) -> Decimal:
        with self.lock:
            return self.positions.get(account, {}).get(symbol.upper(), Decimal("0"))

    def split(self, symbol: str, ratio: int, roundup: bool = True,
              rename: Optional[str] = None, fraction_accounts=()) -> None:
        """Reverse split: n shares -> n/ratio. With `roundup` every fraction
        becomes one whole share, except accounts in `fraction_accounts`."""
        sym = symbol.upper()
        with self.lock:
            for acct, pos in self.positions.items():
                q = pos.pop(sym, None)
                if q is None or q <= 0:
                    continue
                post = (q / Decimal(ratio)).quantize(Decimal("0.0001"))
                if roundup and acct not in fraction_accounts and post < 1:
                    post = Decimal("1")
                pos[(rename or sym).upper()] = post

    # ----- ledger helpers
    def reached(self, side=None, symbol=None) -> List[Order]:
        with self.lock:
            return [o for o in self.orders if o.reached
                    and (side is None or o.side == side)
                    and (symbol is None or o.symbol == symbol.upper())]

    # ----- module surface
    def _sleep(self):
        lo, hi = self.latency
        if hi > 0:
            time.sleep(self.rng.uniform(lo, hi))

    def _hang(self):
        self.sim.threads.park_current()
        self.release.wait()

    def _login_names(self, i: int) -> set:
        """The only_accounts entries that mean "all of login i", exactly as
        the real module reads them -- no more lenient, or the sim hides a
        retry the real broker answers with "none found":
          fidelity    c.label in only            -> "Fidelity i" (login 1 too)
          ibkr        gw.name in only            -> "IBKR" / "IBKR i"
          wellsfargo  wellsfargo._login_names(i) -> "Wells Fargo" (login 1),
                      "Wells Fargo i", "Wells Fargo i · Wells Fargo[ i]"
        Every other broker takes no only_accounts at all."""
        if self.name == "fidelity":
            return {f"Fidelity {i}"}
        if self.name == "ibkr":
            return {"IBKR" if i == 1 else f"IBKR {i}"}
        if self.name == "wellsfargo":
            if i == 1:
                return {"Wells Fargo", "Wells Fargo 1"}
            pre = f"Wells Fargo {i} · "
            return {f"Wells Fargo {i}", pre + "Wells Fargo", pre + f"Wells Fargo {i}"}
        return set()

    def _accounts_for(self, only) -> List[Tuple[int, str]]:
        out = []
        for i, login in enumerate(self.logins, start=1):
            whole = only is not None and bool(self._login_names(i) & set(only))
            for a in login:
                if only is None or whole or a in only:
                    out.append((i, a))
        return out

    def _login_row_label(self, i: int) -> str:
        """What the real module labels login i's whole-login failure row."""
        if self.name == "fidelity":
            return f"Fidelity {i}"                       # c.label
        if self.name == "wellsfargo":
            # The module's "Wells Fargo" row, fan_out-prefixed past login 1.
            return "Wells Fargo" if i == 1 else f"Wells Fargo {i} · Wells Fargo"
        label = LOGIN_LABEL[self.name]
        return f"{label} {i}" if i > 1 else label

    def _place(self, acct: str, side: str, sym: str, qty: Decimal, status: str) -> None:
        with self.lock:
            self.orders.append(Order(self.name, acct, side, sym, qty, status,
                                     self.sim.clock.now().isoformat()))
            if status == "unconfirmed" and side == "sell" and self.working_orders_hold_shares:
                return
            if status in ("filled", "unconfirmed"):
                pos = self.positions.setdefault(acct, {})
                cur = pos.get(sym, Decimal("0"))
                if side == "buy":
                    pos[sym] = cur + qty
                else:
                    pos[sym] = max(Decimal("0"), cur - qty)

    def _login_rows(self, which=None, sized: bool = False) -> List[AccountOutput]:
        label = LOGIN_LABEL[self.name]
        if self.name == "public":
            idx = which or range(1, len(self.logins) + 1)
            # public._login_failed: a holdings-sized sell words a refused
            # login like a failed per-account read.
            pre = "Could not read the position before selling: " if sized else ""
            return [AccountOutput(account_id=f"Public {i}", ok=False,
                                  message=f"{pre}Public login {i} failed: 401 Unauthorized")
                    for i in idx]
        if which:
            return [AccountOutput(account_id=self._login_row_label(i), ok=False,
                                  message=f"Login failed: login {i} rejected the password")
                    for i in which]
        return [AccountOutput(account_id=label, ok=False,
                              message="Login failed: bad credentials")]

    def execute_trade(self, **kw):
        with self.lock:
            self._busy += 1
            self.max_concurrent = max(self.max_concurrent, self._busy)
        try:
            return self._execute_trade(**kw)
        finally:
            with self.lock:
                self._busy -= 1

    def _execute_trade(self, *, side: str, qty: str, symbol: str, dry_run: bool = False,
                       only_accounts=None, size_from_holdings: bool = False,
                       remnant_only: bool = False, also_symbols=(), max_by_account=None,
                       **extra_kw):
        if extra_kw:
            raise TypeError(f"execute_trade() got unexpected keyword arguments {sorted(extra_kw)}")
        if only_accounts is not None and self.name not in ACCOUNT_BROKERS:
            raise TypeError("execute_trade() got an unexpected keyword argument 'only_accounts'")
        if self.name != "public" and (size_from_holdings or max_by_account is not None):
            raise TypeError("execute_trade() got an unexpected keyword argument 'size_from_holdings'")
        side = side.lower()
        sym = symbol.upper()
        with self.lock:
            self.calls.append({"side": side, "qty": qty, "symbol": sym, "dry_run": dry_run,
                               "only_accounts": only_accounts,
                               "size_from_holdings": size_from_holdings,
                               "max_by_account": dict(max_by_account or {}),
                               "also_symbols": tuple(also_symbols or ()),
                               "t": self.sim.clock.now().isoformat()})
        mode = self._take_mode(side, sym)
        self._sleep()
        if mode == "hang_before":
            self._hang()
            return BrokerOutput(broker=self.name, state="failed",
                                message="released after hang (nothing sent)")
        if mode == "raise_before":
            raise RuntimeError("could not reach the order page: nothing was sent")
        sized = self.name == "public" and side == "sell" and size_from_holdings
        if mode == "login_fail":
            return BrokerOutput(broker=self.name, state="failed",
                                accounts=self._login_rows(sized=sized), message="Login failed")
        if mode == "timeout_before":
            return BrokerOutput(broker=self.name, state="failed", accounts=[
                AccountOutput(account_id=LOGIN_LABEL[self.name], ok=False,
                              message="Login timed out before the order page loaded — nothing was sent")],
                message="timeout")

        accts = self._accounts_for(set(only_accounts) if only_accounts else None)
        outs: List[AccountOutput] = []
        skipped: Dict[str, int] = {}
        if mode == "login2_fail" and len(self.logins) > 1:
            outs.extend(self._login_rows(which=[2], sized=sized))
            accts = [(i, a) for i, a in accts if i != 2]
        for n, (i, acct) in enumerate(accts):
            q = Decimal(str(qty or "0"))
            row_extra = None
            order_sym = sym
            if self.name == "public" and side == "sell" and size_from_holdings:
                if max_by_account is None:
                    return BrokerOutput(broker=self.name, state="failed",
                                        message="Holdings-sized sell refused: no per-account cap")
                cap = max_by_account.get(acct)
                if cap is None:
                    skipped["not_ours"] = skipped.get("not_ours", 0) + 1
                    continue
                syms = [sym] + [str(s).upper() for s in also_symbols if s]
                held = self.held(acct, sym)
                if held <= 0:
                    for alt in syms[1:]:
                        if self.held(acct, alt) > 0:
                            held, order_sym = self.held(acct, alt), alt
                            break
                if held <= 0:
                    skipped["none"] = skipped.get("none", 0) + 1
                    continue
                if remnant_only and held >= 1:
                    skipped["whole"] = skipped.get("whole", 0) + 1
                    continue
                q = min(held, Decimal(str(cap)))
                row_extra = {"qty": format(q.normalize(), "f"), "symbol": order_sym}
            if dry_run:
                outs.append(AccountOutput(account_id=acct, ok=True, message="DRY RUN ticket",
                                          extra=row_extra))
                continue
            if mode == "refuse":
                self._place(acct, side, order_sym, q, "rejected")
                outs.append(AccountOutput(account_id=acct, ok=False,
                                          message="Order rejected: symbol not tradable here"))
                continue
            if mode == "partial" and n > 0:
                outs.append(AccountOutput(account_id=acct, ok=False,
                                          message="Session expired (HTTP 401) — this account's order was not sent"))
                continue
            if side == "sell" and self.held(acct, order_sym) < q:
                self._place(acct, side, order_sym, q, "rejected")
                outs.append(AccountOutput(account_id=acct, ok=False,
                                          message="Order rejected: not enough shares to sell"))
                continue
            if mode in ("timeout_after", "raise_after", "hang_after"):
                self._place(acct, side, order_sym, q, "unconfirmed")
                if mode == "timeout_after":
                    outs.append(AccountOutput(
                        account_id=acct, ok=False,
                        message=f"Order submitted but the confirmation page didn't load — "
                                f"verify in {LOGIN_LABEL[self.name]} before retrying"))
                continue
            self._place(acct, side, order_sym, q, "filled")
            outs.append(AccountOutput(account_id=acct, ok=True, message="order placed",
                                      order_id=f"{self.name}-{len(self.orders)}",
                                      extra=row_extra))
        if mode == "raise_after":
            raise RuntimeError("HTTP 502 from order endpoint")
        if mode == "hang_after":
            self._hang()
            raise RuntimeError("released after hang")
        ok = sum(1 for a in outs if a.ok)
        bad = sum(1 for a in outs if not a.ok)
        state = "success" if ok and not bad else ("partial" if ok else "failed")
        if self.name == "public" and not outs and skipped:
            state = "success"
        return BrokerOutput(broker=self.name, state=state, accounts=outs,
                            extra={"skipped": skipped} if skipped else None)

    def get_holdings(self, *a, **k) -> BrokerOutput:
        with self.lock:
            self.holdings_calls += 1
        mode = self._take_holdings_mode()
        self._sleep()
        if mode == "hang":
            self._hang()
            raise RuntimeError("released after hang")
        if mode == "raise":
            raise RuntimeError("session dropped while reading positions")
        if mode == "failed":
            return BrokerOutput(broker=self.name, state="failed", accounts=self._login_rows(),
                                message="Login failed")
        if mode == "empty_success":
            return BrokerOutput(broker=self.name, state="success", accounts=[])
        outs = []
        with self.lock:
            for i, acct in enumerate(self.accounts()):
                if mode == "unread" and i == 0:
                    outs.append(AccountOutput(account_id=acct, ok=False,
                                              message="could not load positions", holdings=[]))
                    continue
                rows = [HoldingRow(symbol=s, shares=float(q),
                                   price=self.sim.market.price(s))
                        for s, q in self.positions.get(acct, {}).items() if q > 0]
                label = f"{acct} = $1000.00" if self.name == "public" else acct
                outs.append(AccountOutput(account_id=label, ok=True, holdings=rows))
        state = "partial" if mode == "unread" else "success"
        return BrokerOutput(broker=self.name, state=state, accounts=outs)


# =========================================================================
# Fake feed + cloud
# =========================================================================

_KIND_LINE = {"standard": "STANDARD", "otc": "OTC", "conditional": "CONDITIONAL"}


def us_date(iso: str) -> str:
    d = _real_date.fromisoformat(iso)
    return f"{d.month}/{d.day}/{d.year % 100:02d} ({d.strftime('%a')})"


class FakeFeed:
    """The alert channel and the cloud board, in the shapes the real parsers
    read. Picks go through rsa_feed.parse_buy_message + to_pick exactly as the
    feed import does; exits through rsa_feed.parse_messages(...).to_json()."""

    def __init__(self):
        self._ids = itertools.count(1_300_000_000_000_000_000)
        self.buy_msgs: List[dict] = []
        self.sell_msgs: List[dict] = []
        self.lifecycle: List[dict] = []
        self.picks_override: Optional[List[dict]] = None
        self.picks_fail = False
        self.sells_fail = False
        self._lock = threading.Lock()

    def alert(self, symbol: str, alert_date: str, kind: str = "standard",
              last_buy: Optional[str] = None, posted_et: Optional[str] = None,
              type_line: Optional[str] = None) -> dict:
        """One Alert Bot rich embed. `kind` standard/otc/conditional, or any
        other word for an unknown type line."""
        title = {"standard": "🔔 RSA Alert", "otc": "💊 RSA Alert",
                 "conditional": "📝 RSA Alert"}.get(kind, "🔔 RSA Alert")
        desc = type_line if type_line is not None else _KIND_LINE.get(kind, kind.upper())
        fields = [{"name": "🎟️ Ticker", "value": symbol},
                  {"name": "📅 Alert Date", "value": us_date(alert_date)},
                  {"name": "Ratio", "value": "1:20"},
                  {"name": "Current Share Price", "value": "$0.25"},
                  {"name": "Strategy", "value": "1 Share/Account"}]
        if last_buy:
            fields.append({"name": "Last Day to Buy", "value": us_date(last_buy)})
        posted = posted_et or f"{alert_date}T08:30:00"
        msg = {"id": str(next(self._ids)),
               "timestamp": _real_datetime.fromisoformat(posted).replace(tzinfo=NY)
               .astimezone(timezone.utc).isoformat(),
               "content": "", "embeds": [{"title": title, "description": desc,
                                          "fields": fields}]}
        with self._lock:
            self.buy_msgs.append(msg)
        return msg

    def exit(self, symbol: str, price: float, brokers: Dict[str, int],
             sell_date: str) -> dict:
        lines = [f"{symbol} ${price:.2f}"]
        for b, n in brokers.items():
            lines.append(f"- {b} x{n}")
        total = price * sum(brokers.values())
        lines.append(f"**+${total:.2f}**")
        msg = {"id": str(next(self._ids)),
               "timestamp": _real_datetime.fromisoformat(f"{sell_date}T11:00:00")
               .replace(tzinfo=NY).astimezone(timezone.utc).isoformat(),
               "content": "\n".join(lines), "embeds": []}
        with self._lock:
            self.sell_msgs.append(msg)
        return msg

    def board(self, symbol: str, alert_date: str, status: str,
              sell_symbol: Optional[str] = None, kind: str = "standard") -> None:
        with self._lock:
            self.lifecycle = [r for r in self.lifecycle
                              if not (r["symbol"] == symbol and r["alert_date"] == alert_date)]
            self.lifecycle.append({"source_id": f"{alert_date}:{symbol}", "symbol": symbol,
                                   "sell_symbol": sell_symbol or symbol,
                                   "alert_date": alert_date, "status": status, "kind": kind})

    # ---- what the cloud serves
    def picks(self) -> List[dict]:
        if self.picks_override is not None:
            return [dict(p) for p in self.picks_override]
        with self._lock:
            msgs = list(self.buy_msgs)
        out = []
        for m in msgs:
            for b in rsa_feed.parse_buy_message(m):
                out.append(rsa_feed.to_pick(b))
        return out

    def sells(self) -> List[dict]:
        with self._lock:
            msgs = list(self.sell_msgs)
        if not msgs:
            return []
        return rsa_feed.parse_messages([], msgs).to_json().get("sells") or []


def make_fake_cloud(feed: FakeFeed):
    mod = types.ModuleType("cloud_sync")

    class CloudError(Exception):
        pass

    class CloudAuthError(CloudError):
        pass

    class CloudSync:
        can_publish_feed = False
        feed_key = ""

        def fetch_picks(self):
            if feed.picks_fail:
                raise CloudError("offline")
            return feed.picks()

        def fetch_sells(self):
            if feed.sells_fail:
                raise CloudError("offline")
            return feed.sells()

        def fetch_lifecycle(self):
            return [dict(r) for r in feed.lifecycle]

        def publish_feed(self, *_a, **_k):
            raise AssertionError("a customer copy must never publish the feed")

        def __getattr__(self, name):
            raise CloudError(f"FakeCloud: {name} is not simulated (no network)")

    mod.CloudError = CloudError
    mod.CloudAuthError = CloudAuthError
    mod.CloudSync = CloudSync
    return mod


# =========================================================================
# The app stand-in
# =========================================================================

class Var:
    def __init__(self, value=None):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


class Null:
    """A widget that accepts anything."""

    def __getattr__(self, name):
        return self

    def __call__(self, *a, **k):
        return self

    def __bool__(self):
        return True

    def __iter__(self):
        return iter(())


#: Widget attributes the logic configures in passing.
WIDGETS = ("_mirror_exec_count", "_mirror_log", "_mirror_status_dot",
           "_mirror_status_lbl", "_mirror_toggle_btn", "_status_journal")


class SimApp:
    """App's logic without App's window. See the module docstring."""

    LOG_MAX_LINES = A.App.LOG_MAX_LINES

    def __init__(self, sim: "Sim"):
        self._sim = sim
        self.notes: List[Tuple[str, str]] = []
        self.mirror_lines: List[str] = []
        self.renders: Dict[str, int] = {}
        for w in WIDGETS:
            setattr(self, w, Null())

        # ---- App.__init__ runtime state (keep in step with app.py) ----
        self._ui_queue = None
        self._feed_last_ok = None
        self._feed_fail_streak = 0
        self._feed_retry_id = None
        self._log_lines: List[tuple] = []
        self._trade_in_flight = False
        self._brokers_in_flight: set = set()
        self._startup_sessions_done = False
        self._mirror_resumed = False
        self._startup_began_at = A.datetime.now()
        self._trade_progress_at = None
        self._live_batches: List[dict] = []
        self._live_anim_id = None
        self._live_frame = 0
        self._active_nav = None
        self._quick_picks: List[Dict[str, str]] = []
        self._user_watchlist: List[str] = []
        self._pick_symbols: List[str] = []
        self._watchlist: List[str] = []
        self._quotes: Dict[str, Any] = {}
        self._quotes_rev = 0
        self._page_sig: Dict[str, Any] = {}
        self._notifications: List[Dict[str, Any]] = []
        self._notif_unread = 0
        self._notif_popup = None
        self._toasts: list = []
        self._roundup_flagged: set = set()
        self._track_rows: List[Any] = []
        self._track_error = ""
        self._track_pulled_at = ""
        self._track_busy = False
        self._track_loop_id = None
        self._exit_busy = False

        _as = self._load_autosell_state()
        if self._autosell_state_blocked:
            self.after(1500, self._announce_autosell_state_blocked)
        self._autosell_enabled = Var(bool(_as.get("enabled")))
        self._autosell_dry_run = Var(bool(_as.get("dry_run", True)))
        self._autosell_fracs = Var(bool(_as.get("fractionals", True)))
        self._confirmed_sells: set = A._load_confirmed_sells()
        self._show_confirmed = False
        self._autosell_reading: set = set()
        self._autosell_sold, self._autosell_released = A._autosell_restore(_as)
        self._autosell_dry_keys: set = {
            k for k in (_as.get("dry_sold") or [])
            if isinstance(k, str) and k in self._autosell_sold}
        self._autosell_may_exist = A._autosell_restore_holds(_as)
        self._autosell_may_exist_why = A._autosell_restore_hold_reasons(_as)
        self._autosell_retry_after: Dict[str, Any] = {}
        self._autosell_recheck = False
        self._autosell_recheck_id = None
        self._autosell_queue: List[Any] = []
        self._queue_busy = False
        self._queue_busy_at = None
        self._queue_held_said = False
        self._queue_stalled_said = False
        self._pump_after_id = None
        # Persisted like App.__init__ restores them: attempts, the per-pull
        # cap's hold-back and the NEEDS ATTENTION list survive a restart.
        self._autosell_fails: Dict[str, int] = A._autosell_restore_counts(_as)
        self._autosell_capped: set = {
            k for k in (_as.get("held_back") or []) if isinstance(k, str)}
        self._autosell_attn: Dict[str, Dict[str, str]] = A._autosell_restore_attention(_as)

        # ---- _build_settings: mirror state restore (keep in step) ----
        saved = self._load_mirror_state()
        self._mirror_enabled = Var(bool(saved.get("enabled")))
        self._mirror_selected_brokers: set = set(saved.get("brokers", []))
        self._mirror_executed: set = set(
            tuple(x) if isinstance(x, list) else x for x in saved.get("executed", []))
        self._mirror_poll_id = None
        self._mirror_last_slot = str(saved.get("last_slot", "") or "")
        self._mirror_failed: set = set(
            tuple(x) if isinstance(x, list) else x for x in saved.get("failed", []))
        self._mirror_failed_notes: Dict[tuple, str] = {}
        for entry in saved.get("failed_notes") or []:
            try:
                d, sym, txt = entry
            except (TypeError, ValueError):
                continue
            self._mirror_failed_notes[(d, sym)] = str(txt)
        self._mirror_attention_dismissed = {
            str(x) for x in (saved.get("attention_dismissed") or [])}
        self._mirror_attempts: Dict[tuple, int] = {}
        for entry in saved.get("attempts") or []:
            try:
                d, sym, n = entry
                self._mirror_attempts[(str(d), str(sym))] = int(n)
            except (TypeError, ValueError):
                continue
        self._mirror_wedged: Dict[str, dict] = {}
        self._mirror_owed: List[dict] = A._mirror_owed_from(saved)
        self._mirror_launched = A._mirror_launched_from(saved)
        self._mirror_repaired = False
        try:
            _age = int(saved.get("max_age_days", A.MIRROR_MAX_AGE_DEFAULT))
        except (TypeError, ValueError):
            _age = A.MIRROR_MAX_AGE_DEFAULT
        self._mirror_max_age = Var(min(max(_age, A.MIRROR_AGE_CHOICES[0]),
                                       A.MIRROR_AGE_CHOICES[-1]))
        self._mirror_age_chips: Dict[int, Any] = {}
        self._mirror_queue: List[Dict[str, str]] = []
        self._mirror_active: List[dict] = []
        self._mirror_drain_id = None
        self._mirror_settled_at = None
        self._mirror_busy_logged = None
        self._mirror_queue_lbl = None

        # Trade Desk ticket (for desk-trade interleaving).
        self._trade_selected_brokers: set = set()
        self._trade_side = Var("buy")
        self._trade_symbol = Var("")
        self._trade_qty = Var("1")
        self._trade_dry = Var(False)

    # ------------------------------------------------------------ binding
    def __getattr__(self, name):
        attr = A.App.__dict__.get(name)
        if attr is None:
            raise AttributeError(name)
        if isinstance(attr, staticmethod):
            return attr.__func__
        if isinstance(attr, classmethod):
            return types.MethodType(attr.__func__, type(self))
        if callable(attr):
            return types.MethodType(attr, self)
        return attr

    # ------------------------------------------------------------ Tk
    def after(self, ms, func=None, *args):
        return self._sim.sched.after(ms, func, *args)

    def after_cancel(self, tid):
        self._sim.sched.cancel(tid)

    def after_idle(self, func, *args):
        return self.after(0, func, *args)

    def update_idletasks(self):
        pass

    def update(self):
        pass

    def bell(self):
        pass

    def _run_in_thread(self, target, *args):
        A.threading.Thread(target=target, args=args, daemon=True).start()

    # ------------------------------------------------------------ drawing
    def _push_notification(self, message, kind="info"):
        self.notes.append((str(message), kind))

    def _show_toast(self, *a, **k):
        pass

    def _show_notification(self, *a, **k):
        pass

    def _hide_notification(self, *a, **k):
        pass

    def _mirror_log_msg(self, msg):
        self.mirror_lines.append(str(msg))
        self._log(f"Mirror: {msg}")

    def _alerts_log_msg(self, msg):
        self._log(f"Feed: {msg}")

    def _render_quick_picks(self, picks):
        # The logic half of _render_quick_picks_body: store, then repair.
        self._quick_picks = picks
        if picks:
            self._repair_mirror_executed()

    def _render_noop(self, *_a, **_k):
        pass

    for _n in ("_render_exits", "_render_sell_alerts", "_render_sell_queue",
               "_render_mirror_failed", "_render_mirror_age_note",
               "_render_mirror_queue_lbl", "_mirror_sync_toggle_ui",
               "_invalidate_page", "_render_or_defer", "_live_hide", "_done_hide",
               "_live_show", "_done_show", "_trade_result_write",
               "_update_exits_summary", "_apply_dashboard_summary",
               "_render_linked_count", "_show_frame", "_render_mirror",
               "_render_done_receipt", "_render_retry_row", "_update_feed_status",
               "_render_trade_broker_chips", "_refresh_stats", "_render_watchlist",
               "_update_notif_badge", "_render_notifications", "_render_invest"):
        locals()[_n] = _render_noop
    del _n

    def _cloud_push_async(self, *a, **k):
        pass

    def _publish_feed(self, *a, **k):
        pass

    def _startup_refresh_worker(self):
        # The real one reads holdings at every API broker to paint the
        # Brokers page; nothing on the order path depends on it except the
        # "settled" signal, which _startup_refresh_guarded still sends.
        pass

    def _fetch_quote_price(self, broker, symbol, side="buy"):
        return self._sim.market.price(symbol)


# =========================================================================
# The simulation
# =========================================================================

ALL_BROKERS = tuple(A.BROKER_MODULES)

#: State files the harness may seed/read: name -> (module, attribute).
STATE = {
    "trades": (trade_journal, "_FILE"),
    "mirror_state": (A, "MIRROR_STATE_FILE"),
    "autosell_state": (A, "AUTOSELL_STATE_FILE"),
    "sells": (A, "SELLS_FILE"),
    "picks": (A, "PICKS_FILE"),
    "picks_done": (A, "PICKS_DONE_FILE"),
    "mirror_runs": (mirror_journal, "_FILE"),
    "lifecycle": (lifecycle, "STATE_FILE"),
}


class Sim:
    """One install: a state folder, a broker fleet, a feed, a clock. Apps come
    and go (restart = a fresh SimApp over the same state)."""

    def __init__(self, monkeypatch, tmp_path: Path, start_et: _real_datetime,
                 brokers=ALL_BROKERS):
        self.mp = monkeypatch
        self.dir = tmp_path
        self.clock = FakeClock(start_et)
        self.threads = ThreadTracker()
        self.market = Market()
        self.feed = FakeFeed()
        self.brokers: Dict[str, FakeBroker] = {b: FakeBroker(b, self) for b in ALL_BROKERS}
        self.callback_errors: List[str] = []
        self.app: Optional[SimApp] = None
        self.sched: Optional[Scheduler] = None
        self._patch(brokers)

    # ------------------------------------------------------------ setup
    def _patch(self, brokers) -> None:
        mp = self.mp
        state = self.dir / "state"
        state.mkdir(parents=True, exist_ok=True)
        for name, (mod, attr) in STATE.items():
            mp.setattr(mod, attr, state / f"{name}.json")
        mp.setattr(A, "COVERAGE_READ_FILE", state / "coverage_read.json", raising=False)
        mp.setattr(A, "FEED_STATE_FILE", state / "feed_state.json", raising=False)
        mp.setattr(A, "SELLS_CONFIRMED_FILE", state / "sells_confirmed.json", raising=False)
        mp.setattr(A, "WATCHLIST_FILE", state / "watchlist.json", raising=False)
        mp.setattr(A, "CUSTOM_ACCOUNTS_FILE", state / "custom_accounts.json", raising=False)
        mp.setattr(A, "PUBLIC_LATE_CHECKED_FILE", state / "public_late_checked.json")
        mp.setattr(A, "ROUNDUP_RADAR_FILE", state / "roundup_radar.json")
        mp.setattr(A, "LOG_DIR", self.dir / "logs")
        mp.setattr(A, "TRADE_RESULTS_LOG", self.dir / "logs" / "trade_results.log",
                   raising=False)

        FakeDT, FakeD = make_fake_datetime(self.clock)
        for mod in (A, trade_journal, mirror_journal, lifecycle):
            mp.setattr(mod, "datetime", FakeDT)
        mp.setattr(A, "date", FakeD)
        mp.setattr(market_calendar, "now_et", lambda: self.clock.et())
        # Some helpers import the class at call time (`from datetime import
        # date as _date` in _prune_stale_picks / _pick_is_fresh), so the
        # module itself is swapped for the duration of the test.
        import datetime as _dt_mod
        fake_mod = types.ModuleType("datetime")
        for name in dir(_dt_mod):
            if not name.startswith("__"):
                setattr(fake_mod, name, getattr(_dt_mod, name))
        fake_mod.datetime = FakeDT
        fake_mod.date = FakeD
        mp.setitem(sys.modules, "datetime", fake_mod)

        mp.setattr(A, "threading", self.threads.make_module())
        mp.setattr(A, "_load_broker", self._load_broker)
        # Fresh per-broker Chrome locks: a thread a previous test hung must
        # never hold this test's slot.
        mp.setattr(A, "_browser_locks", {b: threading.Lock() for b in A._browser_locks})
        mp.setattr(A, "load_dotenv", lambda *a, **k: None)
        mp.setattr(A, "log_event", lambda *a, **k: None)
        mp.setattr(A, "winsound", types.SimpleNamespace(
            MessageBeep=lambda *_a: None, MB_ICONEXCLAMATION=0))
        mp.setattr(A.messagebox, "showerror", lambda *a, **k: None)
        mp.setattr(A.messagebox, "showwarning", lambda *a, **k: None)
        mp.setattr(A.messagebox, "showinfo", lambda *a, **k: None)
        mp.setattr(A.messagebox, "askyesno", lambda *a, **k: True)

        cloud = make_fake_cloud(self.feed)
        mp.setattr(A, "cloud_sync", cloud, raising=False)
        mp.setattr(A, "CLOUD_AVAILABLE", True)
        mp.setitem(sys.modules, "cloud_sync", cloud)

        # Bounded real waits the harness cannot fake.
        mp.setattr(A, "EXIT_READ_TIMEOUT_S", 1.5)
        mp.setattr(A, "_BROWSER_LOCK_TIMEOUT", 1.5)
        mp.setattr(A, "AUTOSELL_STATE_READ_PAUSE_S", 0.0)
        mp.setattr(A, "_activity_note", lambda *_a, **_k: None)
        mp.setattr(trade_journal, "_READ_DELAY", 0.0, raising=False)
        mp.setattr(mirror_journal, "_READ_DELAY", 0.0, raising=False)

        # Fresh module caches: the journal and its memo outlive a test.
        A._COVERAGE_MEMO.clear()
        self.reset_mirror_journal()

    def reset_mirror_journal(self, flush: bool = True) -> None:
        """Drop mirror_journal's in-memory copy, as a new process would.

        Assigned directly, NOT monkeypatched: its background writer reads these
        globals, and restoring a `_dirty=True` at teardown let it write a test's
        runs into the real mirror_runs.json once _FILE had been put back."""
        if flush:
            mirror_journal.flush()
        with mirror_journal._lock:
            mirror_journal._cache = None
            mirror_journal._cache_stat = None
            mirror_journal._dirty = False
            mirror_journal._read_error = None

    def close(self) -> None:
        """Fixture teardown, BEFORE monkeypatch is undone: free hung calls,
        wait for every thread, and leave nothing queued to write anywhere."""
        self.release_hangs()
        try:
            mirror_journal.flush()
        except Exception:
            pass
        self.reset_mirror_journal(flush=False)

    def _load_broker(self, name: str):
        return self.brokers[name]

    def path(self, name: str) -> Path:
        mod, attr = STATE[name]
        return getattr(mod, attr)

    # ------------------------------------------------------------ seeding
    def seed_mirror(self, enabled=True, brokers=ALL_BROKERS, **extra) -> None:
        state = {"enabled": enabled, "brokers": sorted(brokers), "executed": [],
                 "last_slot": "", "failed": [], "max_age_days": 2}
        state.update(extra)
        self.path("mirror_state").write_text(json.dumps(state), encoding="utf-8")

    def seed_autosell(self, enabled=True, dry_run=False, fractionals=False, **extra) -> None:
        state = {"enabled": enabled, "dry_run": dry_run, "fractionals": fractionals,
                 "sold": []}
        state.update(extra)
        self.path("autosell_state").write_text(json.dumps(state), encoding="utf-8")

    def seed_buy(self, broker: str, symbol: str, when_et: str, price: float = 0.25,
                 accounts=None, qty: float = 1.0) -> None:
        """A buy already in the journal AND at the broker (bought earlier)."""
        b = self.brokers[broker]
        for acct in (accounts or b.accounts()):
            trade_journal.record_trade(broker=broker, account_id=acct, side="buy",
                                       symbol=symbol, qty=qty, fill_price=price,
                                       when=_real_datetime.fromisoformat(when_et)
                                       .replace(tzinfo=NY).astimezone(timezone.utc).isoformat())
            b.hold(acct, symbol, Decimal(str(b.held(acct, symbol))) + Decimal(str(qty)))

    # ------------------------------------------------------------ app lifecycle
    def launch(self) -> SimApp:
        """A fresh process over the same state: what App() + mainloop would
        schedule at startup, in the same order and at the same offsets."""
        self.sched = Scheduler(self.clock)
        A._COVERAGE_MEMO.clear()
        app = SimApp(self)
        self.app = app
        app.after(300, app._reload_quick_picks)
        app.after(700, app._startup_refresh)
        app.after(2500, app._track_loop)
        app.after(3000, app._mirror_resume)
        return app

    def kill(self, flush_runs: bool = True) -> None:
        """Hard stop. Threads of the dead app keep running against a scheduler
        nobody drains (exactly what a dead process's callbacks amount to).
        With flush_runs=False, mirror_runs.json writes still queued are lost."""
        if self.app is not None:
            self.app._sim_dead = True
        # The OS frees a dead process's locks; the hung threads of the old app
        # keep theirs, so the new process gets its own.
        self.mp.setattr(A, "_browser_locks", {b: threading.Lock() for b in A._browser_locks})
        self.reset_mirror_journal(flush=flush_runs)
        self.app = None
        self.sched = None

    # ------------------------------------------------------------ driving
    def pump(self, until: Optional[Callable[[], bool]] = None,
             max_fake_s: float = 3600.0, real_timeout_s: float = 60.0,
             max_step_s: Optional[float] = None,
             free_run_s: Optional[float] = None) -> bool:
        """Run timers and let worker threads finish, advancing the fake clock
        only when everything is quiet. Returns True if `until` came true (or,
        with no `until`, when nothing is left to do before the limit)."""
        sched = self.sched
        limit = self.clock.utc() + timedelta(seconds=max_fake_s)
        t_end = time.monotonic() + real_timeout_s
        while True:
            if time.monotonic() > t_end:
                raise TimeoutError("simulation did not settle in real time "
                                   f"(busy: {[t._sim_name for t in self.threads.busy()]})")
            ran = False
            while True:
                item = sched.pop_due()
                if item is None:
                    break
                func, args = item
                ran = True
                try:
                    func(*args)
                except Exception as exc:            # what report_callback_exception sees
                    import traceback
                    self.callback_errors.append(
                        f"{getattr(func, '__name__', func)}: {exc!r}\n{traceback.format_exc()}")
            if self.threads.busy():
                time.sleep(0.001)
                if free_run_s:
                    # Real time passes while brokers work: let timers due in
                    # the meantime fire against the running threads.
                    if self.clock.utc() + timedelta(seconds=free_run_s) <= limit:
                        self.clock.advance(free_run_s)
                continue
            if ran:
                continue
            # Quiet: nothing due now and no worker running.
            if until is not None and until():
                return True
            nxt = sched.next_due()
            if nxt is None or nxt > limit:
                if nxt is not None or until is None:
                    self.clock.advance_to(min(limit, nxt or limit))
                return until is None
            if max_step_s is not None:
                nxt = min(nxt, self.clock.utc() + timedelta(seconds=max_step_s))
            self.clock.advance_to(nxt)

    def settle(self, max_fake_s: float = 3600.0, **kw) -> None:  # noqa: D401
        self.pump(None, max_fake_s=max_fake_s, **kw)

    # ------------------------------------------------------------ ledgers
    def orders(self, side=None, symbol=None, reached_only=True) -> List[Order]:
        out = []
        for b in self.brokers.values():
            with b.lock:
                for o in b.orders:
                    if reached_only and not o.reached:
                        continue
                    if side and o.side != side:
                        continue
                    if symbol and o.symbol != symbol.upper():
                        continue
                    out.append(o)
        return out

    def ledger(self, side=None, symbol=None) -> Dict[tuple, int]:
        """(broker, account, symbol, side) -> orders that reached the broker."""
        out: Dict[tuple, int] = {}
        for o in self.orders(side, symbol):
            k = (o.broker, o.account, o.symbol, o.side)
            out[k] = out.get(k, 0) + 1
        return out

    def every_account(self, symbol: str, side: str = "buy", brokers=ALL_BROKERS,
                      skip: Dict[str, set] = None) -> Dict[tuple, int]:
        exp = {}
        for b in brokers:
            for acct in self.brokers[b].accounts():
                if skip and acct in skip.get(b, set()):
                    continue
                exp[(b, acct, symbol.upper(), side)] = 1
        return exp

    def journal(self, side=None, symbol=None) -> List[dict]:
        return [t for t in trade_journal.get_trades()
                if (side is None or t["side"] == side)
                and (symbol is None or t["symbol"] == symbol.upper())]

    def journal_ledger(self, side=None, symbol=None) -> Dict[tuple, int]:
        out: Dict[tuple, int] = {}
        for t in self.journal(side, symbol):
            k = (t["broker"], t["account_id"], t["symbol"], t["side"])
            out[k] = out.get(k, 0) + 1
        return out

    def realized(self) -> float:
        return A.App._portfolio_summary(self.app)["realized"]

    def release_hangs(self, join_s: float = 10.0) -> None:
        """Free every hung call and wait for the threads to finish, so none
        writes into the NEXT test's files after monkeypatch is undone."""
        for b in self.brokers.values():
            b.release.set()
        deadline = time.monotonic() + join_s
        for t in list(self.threads.threads):
            t.join(max(0.0, deadline - time.monotonic()))

    def idle_ok(self) -> List[str]:
        """Everything that says the app is wedged, or [] when it is not."""
        app = self.app
        problems = []
        if app._brokers_in_flight:
            problems.append(f"brokers still in flight: {sorted(app._brokers_in_flight)}")
        if app._trade_in_flight:
            problems.append("_trade_in_flight stuck")
        if app._queue_busy:
            problems.append("_queue_busy stuck")
        if any(not b.get("finished") for b in app._mirror_active):
            problems.append("unfinished mirror batch")
        if app._mirror_queue:
            problems.append(f"mirror queue not drained: {[p.get('symbol') for p in app._mirror_queue]}")
        if app._exit_busy:
            problems.append("_exit_busy stuck")
        return problems
