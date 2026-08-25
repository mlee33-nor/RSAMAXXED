"""Tracking the TRACK board over time, and turning it into a sell worklist.

`rsa_feed.parse_lifecycle_message` reads one snapshot of the board. This module
is what makes it useful: it remembers the last snapshot, works out what changed,
and answers the only question that matters day to day —

    which tickers are ready to sell right now, and at which brokers?

WHY A DIFF AND NOT A POLL FOR NEW MESSAGES

The board is a SINGLE message that the alert bot edits in place — same id since
it was posted. Polling with `after=<last_id>` therefore returns nothing, ever,
no matter how many plays resolve. The only way to see a play move from ⏳ to 🧩
is to re-read the same message and compare it to what we saw last time. That is
what `apply()` does, and why there is a state file at all.

WHERE A SELL CAN ACTUALLY HAPPEN

A 🧩 row does not mean "sell everywhere". Only Public, Robinhood and SoFi hand
back a fractional share; the other seven settle it as cash-in-lieu, so there is
nothing in those accounts to sell and an order would be rejected on every one.
A ✅ round-up is the opposite — it leaves a whole share, and any broker can sell
it. `brokers_for()` is the one place that rule lives.

A renamed ticker is handled throughout: we bought AGAE, the board says
``AGAE ↔️ AIFA``, and the order has to be placed in AIFA. Holdings are looked up
under the alert symbol, orders are addressed to the sell symbol.

Nothing here places an order or touches the network except `fetch()`.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

import discord_feed
import rsa_feed
import trade_journal
from rsa_feed import LifecycleRow

__all__ = [
    "STATE_FILE", "Transition", "SellTask",
    "load_state", "save_state", "apply", "diff",
    "brokers_for", "held_accounts", "sell_worklist", "fetch", "pull", "app_key",
    "BrokerLeg", "ResolvedExit", "resolve", "qty_text",
]

ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / "lifecycle_state.json"

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ------------------------------------------------------------------ state file

def load_state(path: Optional[Path] = None) -> dict[str, Any]:
    """The last board we saw. An unreadable or missing file is an empty board.

    Losing this file is harmless: the next pull re-seeds it and every row is
    reported as first-seen rather than as a change.
    """
    p = path or STATE_FILE
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"rows": {}, "last_pull": ""}
    if not isinstance(data, dict):
        return {"rows": {}, "last_pull": ""}
    data.setdefault("rows", {})
    data.setdefault("last_pull", "")
    return data


def save_state(state: dict[str, Any], path: Optional[Path] = None) -> None:
    """Write atomically — a crash mid-write must not cost us the board history."""
    p = path or STATE_FILE
    try:
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(p)
    except OSError:
        pass


# ----------------------------------------------------------------- transitions

@dataclass(frozen=True)
class Transition:
    """One row of the board changing — or appearing for the first time."""

    key: str
    symbol: str
    sell_symbol: str
    alert_date: str
    old_status: str          # "" when the row is new to us
    new_status: str
    at: str = ""
    seeded: bool = False     # came from the very first pull, not a real change

    @property
    def is_new(self) -> bool:
        return not self.old_status

    @property
    def became_sellable(self) -> bool:
        """Crossed INTO a status with something to sell.

        This is the notify-worthy event. A row that was already sellable and
        stayed sellable is not news, and re-announcing it every poll would train
        everyone to ignore the alerts.

        False for a seeded row. The first pull on a fresh install has no prior
        board to compare against, so all 80-odd rows look like they just changed
        — announcing those would bury the handful that actually did.
        """
        return (not self.seeded
                and self.new_status in rsa_feed.SELLABLE_STATUSES
                and self.old_status not in rsa_feed.SELLABLE_STATUSES)

    @property
    def became_fractional(self) -> bool:
        return (not self.seeded
                and self.new_status in rsa_feed.FRACTIONAL_STATUSES
                and self.old_status not in rsa_feed.FRACTIONAL_STATUSES)

    def describe(self) -> str:
        arrow = f"{self.old_status} -> {self.new_status}" if self.old_status else self.new_status
        name = (f"{self.symbol} ({self.sell_symbol})"
                if self.sell_symbol != self.symbol else self.symbol)
        return f"{name} {arrow}"


def diff(rows: Sequence[LifecycleRow], state: dict[str, Any]) -> list[Transition]:
    """What changed between `state` and `rows`. Does not modify `state`.

    A row vanishing from the board is deliberately not a transition: the bot
    trims old plays, and "it disappeared" is not something to act on.
    """
    known = state.get("rows") or {}
    # No stored board at all means this is the first pull ever. Every row will
    # look new; none of them are news.
    seeded = not known
    now = _now()
    out: list[Transition] = []
    for row in rows:
        if not row.key:
            continue
        before = known.get(row.key) or {}
        old = str(before.get("status") or "")
        if old == row.status:
            continue
        out.append(Transition(
            key=row.key, symbol=row.symbol, sell_symbol=row.sell_symbol,
            alert_date=row.alert_date, old_status=old, new_status=row.status,
            at=now, seeded=seeded,
        ))
    return out


def apply(rows: Sequence[LifecycleRow],
          state: Optional[dict[str, Any]] = None) -> tuple[dict[str, Any], list[Transition]]:
    """Fold a fresh board into the stored one. Returns (new_state, transitions).

    Rows we have seen before keep their `first_seen`, so "this went fractional
    today" stays answerable after the fact.
    """
    state = state if state is not None else load_state()
    changes = diff(rows, state)
    known = dict(state.get("rows") or {})
    now = _now()

    for row in rows:
        if not row.key:
            continue
        before = known.get(row.key) or {}
        entry = {
            "key": row.key,
            "symbol": row.symbol,
            "sell_symbol": row.sell_symbol,
            "alert_date": row.alert_date,
            "status": row.status,
            "kind": row.kind,
            "first_seen": before.get("first_seen") or now,
            "last_seen": now,
        }
        if str(before.get("status") or "") != row.status:
            entry["status_changed_at"] = now
        else:
            entry["status_changed_at"] = before.get("status_changed_at") or now
        known[row.key] = entry

    return {"rows": known, "last_pull": now}, changes


# ----------------------------------------------------------------- sell routing

def brokers_for(status: str) -> tuple[str, ...]:
    """Where a play in this status can actually be sold.

    The whole point of the module in one function:

      fractional   only the three brokers that return a fraction at all
      rounded_up   a whole share exists everywhere, so everywhere
      canceled     the split never happened; it is an ordinary share everywhere
      anything else  nothing to do
    """
    if status in rsa_feed.FRACTIONAL_STATUSES:
        return rsa_feed.FRACTIONAL_BROKERS
    if status in ("rounded_up", "canceled"):
        return rsa_feed.SUPPORTED_BROKERS
    return ()


def app_key(broker: str) -> str:
    """'Wells Fargo' -> 'wellsfargo'. The key BROKER_MODULES and the trade desk use.

    rsa_feed speaks display names because that is how the feed writes them; the
    desktop app speaks lowercase keys. This is the one place the two meet.
    """
    return rsa_feed.normalize_broker(broker).lower().replace(" ", "").replace("*", "")


@dataclass(frozen=True)
class SellTask:
    """One ticker ready to sell, and where."""

    symbol: str                       # place the order in THIS ticker
    alert_symbol: str                 # what we bought it as; may differ
    alert_date: str
    status: str
    brokers: tuple[str, ...] = ()     # brokers we hold it at AND can sell at
    accounts: int = 0                 # how many accounts across those brokers
    skipped_brokers: tuple[str, ...] = ()   # held, but can't sell there

    @property
    def renamed(self) -> bool:
        return self.symbol != self.alert_symbol

    @property
    def is_fractional(self) -> bool:
        return self.status in rsa_feed.FRACTIONAL_STATUSES

    def describe(self) -> str:
        where = ", ".join(self.brokers) or "no eligible broker"
        name = f"{self.alert_symbol} -> {self.symbol}" if self.renamed else self.symbol
        return f"{name} [{self.status}] {self.accounts} acct(s) at {where}"


def held_accounts(trades: Optional[Iterable[dict]] = None) -> dict[str, dict[str, int]]:
    """SYMBOL -> {broker: open account count}, from the trade journal.

    An account counts as open when its net (buys - sells) for that symbol is
    still positive, so a position sold on the last pass drops out on its own and
    the worklist never suggests selling the same thing twice.

    Brokers come back normalized ('robinhood' -> 'Robinhood') so they compare
    against FRACTIONAL_BROKERS without every caller remembering to do it.

    Split-adjusted, and it matters most here. A reverse split leaves a fraction
    of a share behind, so an account that sold its whole GRNQ remnant still nets
    1.0 - 0.1 = 0.9 against the raw journal and reads as OPEN — which is exactly
    how the worklist ends up offering to sell the same position a second time,
    the one thing this function promises not to do.
    """
    # Adjusted whichever way the rows arrived, so a caller that hands us a raw
    # journal slice cannot reintroduce the bug by the back door.
    rows = trade_journal.split_adjusted(trades)
    net: dict[tuple[str, str, str], float] = {}
    for t in rows:
        sym = str(t.get("symbol") or "").upper()
        if not sym:
            continue
        broker = rsa_feed.normalize_broker(str(t.get("broker") or ""))
        acct = str(t.get("account_id") or "")
        try:
            qty = float(t.get("qty") or 0)
        except (TypeError, ValueError):
            continue
        side = str(t.get("side") or "").lower()
        if side == "buy":
            net[(sym, broker, acct)] = net.get((sym, broker, acct), 0.0) + qty
        elif side in ("sell", trade_journal.SIDE_CLOSE):
            # A dissolved position is just as gone as a sold one, and the
            # worklist must stop offering it either way.
            net[(sym, broker, acct)] = net.get((sym, broker, acct), 0.0) - qty

    out: dict[str, dict[str, int]] = {}
    for (sym, broker, _acct), qty in net.items():
        if qty > 0 and broker:
            out.setdefault(sym, {})
            out[sym][broker] = out[sym].get(broker, 0) + 1
    return out


def sell_worklist(rows: Sequence[LifecycleRow],
                  held: Optional[dict[str, dict[str, int]]] = None,
                  *, include_unheld: bool = False) -> list[SellTask]:
    """Everything sellable right now, newest play first.

    `held` is what `held_accounts()` returns. Holdings are looked up under the
    ALERT symbol — the journal recorded AGAE, not AIFA — while the resulting
    task is addressed to the sell symbol, which is what the broker will accept.

    Rows we hold nowhere are dropped unless `include_unheld`, which the UI uses
    to show the board in full rather than only our own positions.
    """
    held = held if held is not None else held_accounts()
    out: list[SellTask] = []

    for row in rows:
        eligible = brokers_for(row.status)
        if not eligible:
            continue

        # Look under both tickers. We normally bought the pre-split name (the
        # journal says AGAE), but a position opened after the rename is filed
        # under the new one, and either is the same position.
        mine: dict[str, int] = dict(held.get(row.symbol.upper(), {}))
        if row.renamed:
            for broker, n in (held.get(row.sell_symbol.upper(), {})).items():
                mine[broker] = mine.get(broker, 0) + n

        sellable = tuple(b for b in eligible if mine.get(b, 0) > 0)
        skipped = tuple(b for b in mine if b not in eligible)

        if not sellable and not include_unheld:
            continue

        out.append(SellTask(
            symbol=row.sell_symbol,
            alert_symbol=row.symbol,
            alert_date=row.alert_date,
            status=row.status,
            brokers=sellable,
            accounts=sum(mine.get(b, 0) for b in sellable),
            skipped_brokers=skipped,
        ))

    out.sort(key=lambda t: (t.alert_date, t.symbol), reverse=True)
    return out


# ------------------------------------------------------- resolving a quantity
#
# The board says a play resolved. It never says how much came back, and the
# amount is not derivable: a 1-for-20 split on a $0.25 name leaves 0.05 of a
# share, but only the broker knows the exact figure it credited. So the quantity
# has to be read out of live holdings before any sell can be placed.
#
# WHY PER BROKER AND NOT PER ACCOUNT
#
# `execute_trade(side, qty, symbol)` has no account parameter — every broker
# module fans one quantity out to all of its own accounts. Per-account sizing
# would mean changing all ten modules.
#
# That is acceptable here, and not by luck: RSA buys exactly one share in every
# account, so a 1-for-N split leaves every account at that broker holding the
# same 1/N fraction. Uniform is the expected case, and `uniform` says so
# explicitly rather than assuming it.
#
# When balances DO differ — a partial fill, an account that already held the
# name — we send the smallest, because an order for more shares than an account
# holds is rejected and takes the whole leg with it. Unlike selling the minimum
# blindly, the spread is reported (`low`/`high`, `uniform`) so a leg that would
# strand shares is visible before it is placed rather than after.

def _dec(value: Any) -> Optional[Decimal]:
    if value is None:
        return None
    text = str(value).strip().replace(",", "")
    if not text:
        return None
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError):
        return None


def qty_text(value: Decimal) -> str:
    """0.04545 -> '0.04545', never '4.545E-2'.

    Broker APIs take the quantity as a string and several reject exponent
    notation outright, which is exactly how a fractional sell silently becomes
    an invalid order.
    """
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in ("", "-0") else text


@dataclass(frozen=True)
class BrokerLeg:
    """One broker's share of an exit: what to send, and what we saw."""

    broker: str                  # display name, e.g. 'Robinhood'
    key: str                     # app key, e.g. 'robinhood'
    qty: str                     # what to hand execute_trade
    accounts: int = 0            # accounts holding a positive balance
    low: float = 0.0             # smallest balance seen
    high: float = 0.0            # largest
    unread: int = 0              # accounts at this broker we could not read

    @property
    def uniform(self) -> bool:
        """Every account holds the same amount — the normal RSA case."""
        return self.high <= self.low

    @property
    def stranded(self) -> float:
        """Shares left behind by sending the minimum. 0 when uniform."""
        return max(0.0, self.high - self.low)

    @property
    def complete(self) -> bool:
        """Every account at this broker was read. False means `accounts` is a
        floor, not a count — there may be more of this position than we saw."""
        return not self.unread


@dataclass(frozen=True)
class ResolvedExit:
    """A SellTask priced against live holdings and ready to place."""

    task: "SellTask"
    legs: tuple[BrokerLeg, ...] = ()
    missing: tuple[str, ...] = ()      # eligible, but no position found
    errors: tuple[str, ...] = ()       # brokers we could not read at all

    @property
    def ok(self) -> bool:
        return bool(self.legs)

    @property
    def total_accounts(self) -> int:
        return sum(l.accounts for l in self.legs)

    @property
    def uniform(self) -> bool:
        return all(l.uniform for l in self.legs)

    @property
    def symbol(self) -> str:
        return self.task.symbol

    def describe(self) -> str:
        return "  ".join(f"{l.broker} {l.qty}×{l.accounts}" for l in self.legs)


def _account_qty(account: Any, symbols: Sequence[str]) -> Optional[Decimal]:
    """This account's balance in any of `symbols`, or None if it holds none."""
    total = Decimal("0")
    found = False
    for holding in (getattr(account, "holdings", None) or []):
        sym = str(getattr(holding, "symbol", "") or "").strip().upper()
        if sym not in symbols:
            continue
        qty = _dec(getattr(holding, "shares", None))
        if qty is None:
            continue
        total += qty
        found = True
    return total if found else None


def resolve(task: "SellTask", outputs: dict[str, Any]) -> ResolvedExit:
    """Price a task against `{app_key: BrokerOutput}` from get_holdings().

    Holdings are matched on the CURRENT ticker first and the pre-split one
    second: after a rename the broker reports AIFA while our journal still says
    AGAE, and either is the same position.

    A broker that reports no position is dropped into `missing` rather than
    sent an order for shares it does not have. That is not an error — a fraction
    can be swept to cash between the board updating and us looking.

    SILENCE IS NOT ABSENCE, AND IT IS NOT ONLY A WHOLE-BROKER QUESTION

    `state` is "partial" whenever SOME of a broker's accounts read and some did
    not, and the ones that did not are the ones we know nothing about. Skipping
    them and then reporting "no position at Fidelity" states as fact the one
    thing the read could not establish — and it is the account with the dead
    session that is most likely to be holding the shares, because nothing about
    it was refreshed. A customer who owns the stock is told he does not.

    So a broker only lands in `missing` when every one of its accounts was read
    and none of them had it. If any account could not be read it goes to
    `errors` instead, which is the bucket that says "we did not find out" — and
    which auto-sell hands back for a retry rather than marking sold. A broker
    that hands back no readable account at all has told us nothing either,
    whatever its state field says.

    Unreadable accounts at a broker that DOES report the position are recorded
    on the leg as `unread`: the order still goes, sized off what we could see,
    but shares may be left behind and the dialog says so rather than quietly
    dropping them.
    """
    symbols = tuple({task.symbol.upper(), task.alert_symbol.upper()})
    legs: list[BrokerLeg] = []
    missing: list[str] = []
    errors: list[str] = []

    for broker in task.brokers:
        key = app_key(broker)
        out = outputs.get(key)
        if out is None:
            errors.append(broker)
            continue
        if str(getattr(out, "state", "") or "").lower() not in ("success", "partial"):
            errors.append(broker)
            continue

        accounts = list(getattr(out, "accounts", None) or [])
        readable = [a for a in accounts if bool(getattr(a, "ok", False))]
        unread = len(accounts) - len(readable)

        # No readable account — including the "success with zero accounts" a
        # broker returns when a session is dead but nothing raised.
        if not readable:
            errors.append(broker)
            continue

        found: list[Decimal] = []
        for account in readable:
            qty = _account_qty(account, symbols)
            if qty is not None and qty > 0:
                found.append(qty)

        if not found:
            # Read every account and none had it: a real answer. Read only
            # some of them: not an answer at all.
            (errors if unread else missing).append(broker)
            continue

        legs.append(BrokerLeg(
            broker=broker, key=key,
            qty=qty_text(min(found)), accounts=len(found),
            low=float(min(found)), high=float(max(found)),
            unread=unread,
        ))

    return ResolvedExit(task=task, legs=tuple(legs),
                        missing=tuple(missing), errors=tuple(errors))


# ----------------------------------------------------------------------- fetch

def fetch(channel_id: str, token: str, *, limit: int = 5) -> tuple[list[LifecycleRow], str]:
    """Read the board. Returns (rows, error) — error is "" on success.

    `limit` is small on purpose: the board is one message, so anything past the
    first few is unrelated chatter.
    """
    msgs, err = discord_feed.fetch(channel_id, token, limit=limit)
    if err:
        return [], err
    if not msgs:
        return [], "TRACK channel is empty"
    rows = rsa_feed.parse_lifecycle_messages(msgs)
    if not rows:
        return [], "No lifecycle rows found — is that the TRACK channel?"
    return rows, ""


def fetch_cloud() -> tuple[list[LifecycleRow], str]:
    """The board from the cloud feed. (rows, error).

    The route that works for an actual customer, and it needs no account.
    Reading TRACK off Discord needs a personal user token with access to a
    private channel, which is something only the operator has — everyone else
    gets the board from the cloud, linked or not.
    """
    try:
        import cloud_sync
    except Exception:
        return [], "cloud sync unavailable"
    try:
        raw = cloud_sync.CloudSync().fetch_lifecycle()
    except Exception as exc:
        return [], str(exc)[:160]

    # Parse defensively, INSIDE the guard. The shape of this response is the one
    # thing a client cannot control at runtime: a bad deploy, a schema change or
    # a proxy error page can put anything on the wire, and the parse used to sit
    # outside the try — so a list of the wrong element type raised straight out
    # of here and took the whole TRACK poll down with it.
    if not isinstance(raw, list):
        return [], "the feed returned an unexpected board"
    rows = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            row = rsa_feed.LifecycleRow.from_json(item)
        except Exception:
            continue        # one malformed row must not cost the other fifty
        if row:
            rows.append(row)
    return rows, "" if rows else "the feed has no board yet"


def pull(channel_id: str = "", token: str = "",
         *, path: Optional[Path] = None,
         prefer_cloud: bool = True) -> tuple[list[LifecycleRow], list[Transition], str]:
    """One full cycle: fetch, diff against stored state, persist, report.

    Source order depends on which machine this is, and it has to:

      OPERATOR (a TRACK channel is configured) reads Discord first. Discord is
        the source of truth for the board, and this machine is the one that
        publishes it. Reading the cloud first here was a feedback loop — we'd
        read back what we last published, find rows, never fall through to
        Discord, and the board would freeze at whatever it said the first time.
      EVERYONE ELSE reads the cloud, which is the only source they have. There
        is no account needed for it; see fetch_cloud.

    Serialised on a lock so a manual refresh racing the background poll can't
    interleave two read-modify-writes and lose a transition.
    """
    rows: list[LifecycleRow] = []
    err = ""
    if channel_id:
        rows, err = fetch(channel_id, token)
    if not rows and prefer_cloud:
        rows, cloud_err = fetch_cloud()
        if not rows:
            return [], [], err or cloud_err
    if not rows:
        return [], [], err or "no board source configured"

    with _lock:
        state = load_state(path)
        new_state, changes = apply(rows, state)
        save_state(new_state, path)
    return rows, changes, ""


# --------------------------------------------------------------------- CLI

def _main(argv: Optional[list[str]] = None) -> int:
    """Pull TRACK and print what is ready to sell.

        python lifecycle.py              # only plays we actually hold
        python lifecycle.py --all        # the whole board
    """
    import argparse
    import os

    ap = argparse.ArgumentParser(description="Pull the TRACK board and show the sell worklist.")
    ap.add_argument("--all", action="store_true",
                    help="include plays we hold nowhere")
    ap.add_argument("--channel", default="",
                    help="TRACK channel id (default: DISCORD_LIFECYCLE_CHANNEL)")
    args = ap.parse_args(argv)

    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except Exception:
        pass

    token = (os.environ.get("DISCORD_TOKEN") or "").strip()
    channel = (args.channel or os.environ.get("DISCORD_LIFECYCLE_CHANNEL")
               or os.environ.get("DISCORD_TRACK_CHANNEL") or "").strip()
    if not token:
        print("DISCORD_TOKEN is not set")
        return 1
    if not channel:
        print("Set DISCORD_LIFECYCLE_CHANNEL to the TRACK channel id")
        return 1

    rows, changes, err = pull(channel, token)
    if err:
        print(f"pull failed: {err}")
        return 2

    print(f"{len(rows)} rows on the board")
    if changes:
        print(f"\n{len(changes)} change(s) since the last pull:")
        for c in changes:
            flag = "  <-- SELLABLE" if c.became_sellable else ""
            print(f"   {c.describe()}{flag}")

    tasks = sell_worklist(rows, include_unheld=args.all)
    frac = [t for t in tasks if t.is_fractional]
    whole = [t for t in tasks if not t.is_fractional]

    print(f"\nFRACTIONAL — sell on {', '.join(rsa_feed.FRACTIONAL_BROKERS)} ({len(frac)}):")
    for t in frac:
        print(f"   {t.describe()}")
    print(f"\nROUND-UP / CANCELLED — whole share, any broker ({len(whole)}):")
    for t in whole:
        print(f"   {t.describe()}")
    if not tasks:
        print("\nnothing to sell" + ("" if args.all else " (nothing held; try --all)"))
    return 0


if __name__ == "__main__":  # pragma: no cover - manual smoke test
    raise SystemExit(_main())
