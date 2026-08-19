"""
Cash per account, per broker.

Every broker module already works out what an account holds in cash — Public
reads two buying-power figures, Schwab a cash-investments total, SoFi derives
one from its |CASH| pseudo-holding, Robinhood carries the whole account profile
— and puts it on `AccountOutput.extra`. Nothing in the app has ever read that
attribute, so all of it was computed and thrown away. This module is the other
half: pull it off the outputs, remember it, and let you type in the figures for
the brokers that genuinely do not report one.

A manual figure is never overwritten by a refresh. It is the user's statement
about an account the app cannot see, and silently replacing it with a stale or
absent live value would be worse than having no number at all. Both the source
and the timestamp travel with every figure so the page can say which is which.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent
BALANCES_FILE = ROOT_DIR / "balances.json"

_lock = threading.RLock()

SOURCE_LIVE = "live"
SOURCE_MANUAL = "manual"

__all__ = [
    "BALANCES_FILE", "SOURCE_LIVE", "SOURCE_MANUAL",
    "cash_from_extra", "load", "save", "record_broker_output",
    "set_manual", "clear_manual", "for_planner", "totals", "version",
]


# ------------------------------------------------------------------ extraction

#: Where each broker keeps its cash figure on AccountOutput.extra, best first.
#: Named per broker rather than guessed generically, so a key that happens to
#: contain "cash" somewhere in the fleet can never be read as buying power.
_CASH_KEYS: Dict[str, Tuple[str, ...]] = {
    # cashOnlyBuyingPower is the settled figure; buyingPower can include margin
    # and unsettled proceeds, which are not yours to deploy yet.
    "public":     ("cash_only_buying_power", "buying_power"),
    "schwab":     ("cash_investments",),
    "sofi":       ("cash_dollars_calc",),
    # robin-stocks' account profile is flattened in wholesale by robinhood.py.
    "robinhood":  ("profile_cash", "profile_portfolio_cash",
                   "profile_buying_power"),
    "fidelity":   ("cash",),          # FCASH, recovered in fidelity.py
    "chase":      ("cash",),          # cash positions, recovered in chase.py
}


def cash_from_extra(broker: str, extra: Optional[Dict[str, Any]]) -> Optional[float]:
    """The cash figure for one account, or None if this broker reports none.

    None and 0.0 are different answers and must stay that way: "we cannot see
    this account's cash" is a prompt to type one in, while "this account holds
    nothing" is a fact. Collapsing them would bury every unreported account
    behind a plausible-looking zero.
    """
    if not extra:
        return None
    for key in _CASH_KEYS.get(str(broker or "").strip().lower(), ()):
        if key not in extra:
            continue
        raw = extra.get(key)
        if raw is None:
            continue
        try:
            val = float(str(raw).replace(",", "").replace("$", "").strip())
        except (TypeError, ValueError):
            continue
        if val < 0:
            continue
        return val
    return None


# ------------------------------------------------------------------ storage

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empty() -> Dict[str, Any]:
    return {"version": 1, "brokers": {}}


def load() -> Dict[str, Any]:
    try:
        data = json.loads(BALANCES_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty()
    if not isinstance(data, dict) or not isinstance(data.get("brokers"), dict):
        return _empty()
    return data


def save(state: Dict[str, Any]) -> None:
    """Write atomically. Copied from lifecycle.save_state rather than
    trade_journal._save, which truncates the file first and loses everything if
    the process dies mid-write."""
    try:
        tmp = BALANCES_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(BALANCES_FILE)
    except OSError:
        pass


def version() -> tuple:
    """(mtime_ns, size) — a cheap change-detector for the page signature,
    same shape as trade_journal.version()."""
    try:
        st = BALANCES_FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


# ------------------------------------------------------------------ updates

def record_broker_output(broker: str, accounts: Iterable[Any],
                         state: Optional[Dict[str, Any]] = None,
                         *, persist: bool = True) -> Dict[str, Any]:
    """Fold one broker's get_holdings() accounts into the store.

    Accepts AccountOutput objects or plain dicts. Accounts whose cash cannot be
    read keep whatever was already on record — a refresh that fails to see a
    figure must not erase the one you typed, nor the one that worked yesterday.
    """
    broker = str(broker or "").strip().lower()
    with _lock:
        st = state if state is not None else load()
        book = st.setdefault("brokers", {}).setdefault(broker, {})
        for acct in accounts or ():
            acct_id = getattr(acct, "account_id", None)
            extra = getattr(acct, "extra", None)
            if acct_id is None and isinstance(acct, dict):
                acct_id = acct.get("account_id")
                extra = acct.get("extra")
            if not acct_id:
                continue
            acct_id = str(acct_id)
            row = book.setdefault(acct_id, {})
            row["seen_at"] = _now()
            cash = cash_from_extra(broker, extra)
            if cash is None:
                continue
            row["live_cash"] = cash
            row["live_at"] = _now()
        if persist and state is None:
            save(st)
        return st


def set_manual(broker: str, account_id: str, cash: float,
               state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Record a figure the user typed. Survives every refresh until cleared."""
    broker = str(broker or "").strip().lower()
    with _lock:
        st = state if state is not None else load()
        row = st.setdefault("brokers", {}).setdefault(broker, {}).setdefault(
            str(account_id), {})
        row["manual_cash"] = float(cash)
        row["manual_at"] = _now()
        if state is None:
            save(st)
        return st


def clear_manual(broker: str, account_id: str,
                 state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    broker = str(broker or "").strip().lower()
    with _lock:
        st = state if state is not None else load()
        row = (st.get("brokers", {}).get(broker, {}) or {}).get(str(account_id))
        if row:
            row.pop("manual_cash", None)
            row.pop("manual_at", None)
        if state is None:
            save(st)
        return st


def forget_account(broker: str, account_id: str,
                   state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    broker = str(broker or "").strip().lower()
    with _lock:
        st = state if state is not None else load()
        (st.get("brokers", {}).get(broker, {}) or {}).pop(str(account_id), None)
        if state is None:
            save(st)
        return st


# ------------------------------------------------------------------ reading

def _resolve(row: Dict[str, Any]) -> Tuple[Optional[float], str, str]:
    """(cash, source, stamp) for one stored row. Manual wins."""
    if row.get("manual_cash") is not None:
        return float(row["manual_cash"]), SOURCE_MANUAL, str(row.get("manual_at") or "")
    if row.get("live_cash") is not None:
        return float(row["live_cash"]), SOURCE_LIVE, str(row.get("live_at") or "")
    return None, "", str(row.get("seen_at") or "")


def rows(state: Optional[Dict[str, Any]] = None
         ) -> List[Dict[str, Any]]:
    """Every account on record, flattened for display. Includes the ones with
    no cash figure — those are the whole reason the manual path exists, so
    hiding them would hide the work."""
    st = state if state is not None else load()
    out: List[Dict[str, Any]] = []
    for broker in sorted(st.get("brokers", {})):
        for acct_id in sorted(st["brokers"][broker]):
            row = st["brokers"][broker][acct_id] or {}
            cash, source, stamp = _resolve(row)
            out.append({
                "broker": broker, "account_id": acct_id, "cash": cash,
                "source": source, "as_of": stamp,
                "live_cash": row.get("live_cash"),
                "manual_cash": row.get("manual_cash"),
            })
    return out


def for_planner(state: Optional[Dict[str, Any]] = None,
                brokers: Optional[Iterable[str]] = None
                ) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """`{broker: {account_id: {"cash": float, "source": str}}}` — the shape
    etf_plan.plan_exposure takes. Accounts with no figure are left out
    entirely, so an unknown balance is never planned against as if it were
    zero or as if it were rich."""
    want = ({str(b).strip().lower() for b in brokers}
            if brokers is not None else None)
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for row in rows(state):
        if want is not None and row["broker"] not in want:
            continue
        if row["cash"] is None:
            continue
        out.setdefault(row["broker"], {})[row["account_id"]] = {
            "cash": row["cash"], "source": row["source"],
        }
    return out


def totals(state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fleet and per-broker totals, plus how many accounts still have no
    figure — the number that tells you how much of the fleet the plan is
    actually seeing."""
    per: Dict[str, float] = {}
    unknown: Dict[str, int] = {}
    known = 0
    total = 0.0
    for row in rows(state):
        b = row["broker"]
        if row["cash"] is None:
            unknown[b] = unknown.get(b, 0) + 1
            continue
        per[b] = per.get(b, 0.0) + row["cash"]
        total += row["cash"]
        known += 1
    return {"total": total, "by_broker": per, "known_accounts": known,
            "unknown_by_broker": unknown,
            "unknown_accounts": sum(unknown.values())}
