"""Public fee guard: notice a per-sale fee, and stop selling at Public when it shows up.

WHY THIS EXISTS
---------------
Public charges an administrative fee on a SELL of stock bought ahead of a
reverse split, when the sale lands within 90 days after the split (its
"Reverse Split Trading Fee" disclosure; waived for Premium). Every play this
tool trades is a reverse split, so every Public exit is in that window. One
fee is the price of one round-up, and Public sells across many accounts, so an
unnoticed fee repeats once per account per play.

So a fee of any real size on a Public sale is treated as a stop signal:

  * BEFORE each sell order, Public's own preflight is asked what the order
    will cost. Any commission, or fees summing to FEE_HALT_USD or more, trips
    the halt and that order is never sent.
  * AFTER each sell order, and before every sell batch, the account history is
    read for a fee transaction (or a trade carrying fees) of FEE_HALT_USD or
    more. One found trips the halt: the remaining accounts are skipped.
  * Once tripped, the halt is saved to disk and every Public SELL is refused
    ("nothing was sent") until a person clears it. Buys are untouched.

Regulatory fees (SEC, FINRA TAF, ...) on these orders are fractions of a cent
to a few cents, so the threshold sits well above them and well below the
$0.49-$0.99 Public has published for this fee.

Buys are preflighted too. Public says it tells you "at the point of purchase"
when a stock may carry the fee; its API documents no field for that notice, so
every preflight response is written to logs/public_fees.log whole, and any
commission or any warning/notice-like field in it is reported on the buy row.

Never raises into the trading path: a guard that crashes a sell is worse than
no guard. Anything that fails here is logged and the caller carries on.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent
STATE_FILE = ROOT_DIR / "public_fee_halt.json"
LOG_FILE = ROOT_DIR / "logs" / "public_fees.log"

#: How far back a history scan looks. Public's window is 90 days after the
#: split, and a buy precedes its split, so 120 covers any fee still relevant.
SCAN_LOOKBACK_DAYS = 120
_MAX_HISTORY_PAGES = 10

#: Known regulatory fee fields in a preflight's regulatoryFees object. Anything
#: else that looks like a fee is counted as a broker fee (see preflight_check).
_REGULATORY = {"secfee", "taffee", "orffee", "exchangefee", "occfee", "catfee"}
_REGULATORY_HINTS = ("sec", "taf", "orf", "cat", "finra", "occ", "exchange",
                     "regulatory")
#: A non-commission, non-regulatory preflight fee at or above this stops a
#: sell. Low on purpose: Public's own fee has been $0.49-$0.99.
_OTHER_FEE_MIN = Decimal("0.10")
#: History fees that are real but not the sale fee: logged, never a halt.
_NOT_SALE_FEE = ("TRANSFER", "ACAT", "WIRE", "PREMIUM", "SUBSCRIPTION",
                 "MARGIN", "INTEREST", "PAPER", "STATEMENT")
#: Keys whose values are account numbers: cut to the last 4 before any write.
_ACCOUNT_KEYS = ("accountnumber", "accountid", "account_number", "account_id")


def _is_regulatory(key: str) -> bool:
    k = key.lower()
    return k in _REGULATORY or (k.endswith("fee") and any(
        k.startswith(h) or h in k for h in _REGULATORY_HINTS))


def redact(obj: Any) -> Any:
    """`obj` with every account-number field cut to its last 4 digits."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _ACCOUNT_KEYS and v not in (None, ""):
                out[k] = "…" + str(v)[-4:]
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj

#: Keys in a preflight response that may carry a notice meant for a person.
_NOTICE_HINTS = ("warn", "alert", "notice", "disclos", "message", "reverse",
                 "split", "corporate", "restrict", "advisory")

_lock = threading.RLock()
_listeners: List[Callable[[Dict[str, Any]], None]] = []


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def threshold() -> Decimal:
    """FEE_HALT_USD: PUBLIC_FEE_HALT_USD from .env, else $0.25."""
    raw = (os.getenv("PUBLIC_FEE_HALT_USD") or "").strip()
    try:
        d = Decimal(raw) if raw else Decimal("0.25")
        return d if d > 0 else Decimal("0.25")
    except (InvalidOperation, ValueError):
        return Decimal("0.25")


def _dec(v: Any) -> Optional[Decimal]:
    if v is None or isinstance(v, bool):
        return None
    try:
        s = str(v).strip().replace("$", "").replace(",", "")
        return Decimal(s) if s else None
    except (InvalidOperation, ValueError):
        return None


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def log(line: str, payload: Any = None) -> None:
    """Append one line (plus an optional JSON payload) to logs/public_fees.log."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        text = f"{_now_iso()} {line}"
        if payload is not None:
            try:
                text += " | " + json.dumps(payload, default=str, sort_keys=True)
            except Exception:
                text += f" | {payload!r}"
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Halt state (public_fee_halt.json)
# ---------------------------------------------------------------------------

# A trip is also held in memory for the life of the process, so nothing that
# happens to the file afterwards (a Drive/antivirus lock, a bad write) can let
# a sell through: only clear() lifts it.
_mem_halt: Optional[Dict[str, Any]] = None

_UNREADABLE_REASON = ("the fee guard's state file could not be read, so Public "
                      "sells are held until it can")


def _load_ex() -> Tuple[Dict[str, Any], bool]:
    """(state, readable). A file that exists but cannot be read is NOT an
    empty state: reading it as {} once erased a halt (QA 2026-11-09)."""
    try:
        from modules import atomic
        data = atomic.load_state(STATE_FILE, {})
        if atomic.is_unreadable(STATE_FILE):
            return {}, False
    except Exception:
        return {}, not STATE_FILE.exists()
    return (data if isinstance(data, dict) else {}), isinstance(data, dict)


def _load() -> Dict[str, Any]:
    return _load_ex()[0]


def _save(data: Dict[str, Any]) -> bool:
    """Atomic write only. No raw fallback: that would overwrite a file the
    loader could not read, halt and all."""
    try:
        from modules import atomic
        atomic.write_json(STATE_FILE, data)
        return True
    except Exception as e:
        log(f"could not save {STATE_FILE.name}: {e}")
        return False


def halt_status() -> Optional[Dict[str, Any]]:
    """The halt, or None when Public selling is allowed. Fails CLOSED: an
    unreadable state file reads as halted."""
    with _lock:
        if _mem_halt is not None:
            return dict(_mem_halt)
        data, ok = _load_ex()
    if not ok:
        return {"halted": True, "reason": _UNREADABLE_REASON, "at": _now_iso(),
                "unreadable": True}
    return data if data.get("halted") else None


def halt_reason() -> str:
    """One line for a refused sell. Kept free of "verify"/"may have": the app
    reads those words as "an order may be out" (see _MAY_HAVE_GONE_OUT)."""
    h = halt_status() or {}
    return str(h.get("reason") or "a Public sale fee was detected")


def add_listener(cb: Callable[[Dict[str, Any]], None]) -> None:
    """`cb(event)` runs (on whatever thread detected it) when the halt trips
    or a buy shows a notice. event["kind"] is "halt" or "notice"."""
    with _lock:
        if cb not in _listeners:
            _listeners.append(cb)


def _emit(event: Dict[str, Any]) -> None:
    for cb in list(_listeners):
        try:
            cb(dict(event))
        except Exception:
            pass


def trip(reason: str, **detail: Any) -> Dict[str, Any]:
    """Stop Public selling. Idempotent: a second trip keeps the first reason
    and appends the new detection to `events` (once per fee transaction)."""
    global _mem_halt
    with _lock:
        data, _ok = _load_ex()
        first = _mem_halt is None and not data.get("halted")
        event = {"at": _now_iso(), "reason": reason, **detail}
        seen = set(data.get("seen_tx") or [])
        tx = str(detail.get("tx_id") or "")
        if not (tx and tx in seen):
            events = list(data.get("events") or [])[-49:]
            events.append(event)
            data["events"] = events
        if tx:
            seen.add(tx)
        data["seen_tx"] = sorted(seen)
        if first:
            data.update({"halted": True, "reason": reason, "at": event["at"],
                         "detail": detail})
        data["halted"] = True
        if _mem_halt is None:
            _mem_halt = {"halted": True, "reason": data.get("reason") or reason,
                         "at": data.get("at") or event["at"]}
        _save(data)
    log(f"HALT{' (first)' if first else ''}: {reason}", detail)
    _emit({"kind": "halt", "first": first, "reason": reason, **detail})
    return data


def clear(by: str = "user") -> bool:
    """Allow Public sells again. Every fee transaction already seen stays
    acknowledged, so the same old fee does not trip it a second time.
    False when the state file could not be read or written (still halted)."""
    global _mem_halt
    with _lock:
        data, ok = _load_ex()
        if not ok:
            log(f"clear by {by} refused: state file unreadable")
            return False
        data["halted"] = False
        data["cleared_at"] = _now_iso()
        data["cleared_by"] = by
        if not _save(data):
            return False
        _mem_halt = None
    log(f"halt cleared by {by}")
    return True


def _seen_tx() -> set:
    return set(_load().get("seen_tx") or [])


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def _walk(obj: Any, path: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def preflight_check(resp: Any) -> Dict[str, Any]:
    """Read a preflight response for fees and notices.

    Returns {"commission", "regulatory", "other_fees", "total" (Decimals),
    "notices" [str], "trip" (str reason or "")}. A sell should not be sent
    when "trip" is non-empty.
    """
    out: Dict[str, Any] = {"commission": Decimal("0"), "regulatory": Decimal("0"),
                           "other_fees": Decimal("0"), "total": Decimal("0"),
                           "notices": [], "parts": {}, "trip": ""}
    if not isinstance(resp, dict):
        return out
    for path, val in _walk(resp):
        key = path.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        low = path.lower()
        if any(h in low for h in _NOTICE_HINTS):
            if val not in (None, "", False, [], {}):
                out["notices"].append(f"{path}: {val}")
        amt = _dec(val)
        if amt is None or amt == 0:
            continue
        if key == "estimatedcommission" or "commission" in key:
            out["commission"] += abs(amt)
            out["parts"][path] = str(amt)
        elif _is_regulatory(key):
            # SEC/TAF/ORF/CAT/...: pass-through charges that scale with the
            # order. Recorded, never a reason to stop (a 2,000-share sale
            # carries ~$0.33 of TAF alone).
            out["regulatory"] += abs(amt)
            out["parts"][path] = str(amt)
        elif "fee" in key:
            out["other_fees"] += abs(amt)
            out["parts"][path] = str(amt)
    out["total"] = out["commission"] + out["regulatory"] + out["other_fees"]
    if out["commission"] > 0:
        out["trip"] = f"Public preflight shows a ${out['commission']:.2f} commission"
    elif out["other_fees"] >= _OTHER_FEE_MIN:
        out["trip"] = f"Public preflight shows a ${out['other_fees']:.2f} fee"
    return out


def describe_preflight(chk: Dict[str, Any]) -> str:
    bits = []
    if chk.get("commission"):
        bits.append(f"commission ${chk['commission']:.2f}")
    if chk.get("other_fees"):
        bits.append(f"fee ${chk['other_fees']:.2f}")
    if chk.get("notices"):
        bits.append("notice: " + "; ".join(chk["notices"])[:300])
    return ", ".join(bits)


# ---------------------------------------------------------------------------
# History scan
# ---------------------------------------------------------------------------

def transaction_fee(tx: Any) -> Tuple[Optional[Decimal], str]:
    """(fee amount, why) when a history transaction is a fee at or above the
    threshold; (None, "") otherwise."""
    if not isinstance(tx, dict):
        return None, ""
    lim = threshold()
    kind = " ".join(str(tx.get(k) or "") for k in ("type", "subType")).upper()
    desc = str(tx.get("description") or "")
    label = kind.strip() or "a transaction"
    if any(w in kind or w in desc.upper() for w in _NOT_SALE_FEE):
        return None, ""
    fees = _dec(tx.get("fees"))
    if fees is not None and abs(fees) > 0:
        # A trade's `fees` includes SEC/TAF, which scale with size. Allow
        # twice the most they could be, then look at what is left.
        qty = abs(_dec(tx.get("quantity")) or Decimal("0"))
        principal = abs(_dec(tx.get("principalAmount")) or _dec(tx.get("netAmount"))
                        or Decimal("0"))
        reg = (min(qty * Decimal("0.000166"), Decimal("8.30"))
               + principal * Decimal("0.0000278"))
        excess = abs(fees) - (reg * 2 + Decimal("0.02"))
        if excess >= lim:
            return abs(fees), f"fees ${abs(fees):.2f} on {label}"
    feeish = ("FEE" in kind or "COMMISSION" in kind
              or "reverse split" in desc.lower())
    if feeish:
        amt = _dec(tx.get("netAmount"))
        if amt is None:
            amt = _dec(tx.get("principalAmount"))
        # Money IN (a refund, a fee reversal) is not a charge. A positive
        # amount with no sign of being a credit still counts: Public may
        # report a debit unsigned, and a missed fee costs more than a pause.
        credit = (str(tx.get("direction") or "").upper() in ("INCOMING", "CREDIT", "IN")
                  or any(w in kind or w in desc.upper()
                         for w in ("REFUND", "REVERSAL", "CREDIT", "REBATE")))
        if amt is not None and not (amt > 0 and credit) and abs(amt) >= lim:
            return abs(amt), f"{label} ${abs(amt):.2f}"
    return None, ""


def _tx_id(acct_id: str, tx: Dict[str, Any]) -> str:
    tid = str(tx.get("id") or "").strip()
    if tid:
        return tid
    return "|".join(str(tx.get(k) or "") for k in
                    ("timestamp", "type", "subType", "symbol", "netAmount", "fees")) + f"|{acct_id[-4:]}"


def fetch_history(client: Any, account_id: str, *, days: int = SCAN_LOOKBACK_DAYS,
                  max_pages: int = _MAX_HISTORY_PAGES) -> List[Dict[str, Any]]:
    """Every history transaction for one account over `days`. Raises on a
    failed read (a scan that could not look is not a clean scan)."""
    getter = getattr(client, "get_history", None)
    if not callable(getter):
        return []
    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    txs: List[Dict[str, Any]] = []
    token: Optional[str] = None
    for _ in range(max(1, max_pages)):
        page = getter(account_id, start=start, next_token=token) or {}
        batch = page.get("transactions") if isinstance(page, dict) else None
        txs.extend(t for t in (batch or []) if isinstance(t, dict))
        token = page.get("nextToken") if isinstance(page, dict) else None
        if not token or not batch:
            break
    return txs


def scan_accounts(targets: Iterable[Tuple[Any, str, str]], *,
                  days: int = SCAN_LOOKBACK_DAYS, trip_on_find: bool = True,
                  max_pages: int = _MAX_HISTORY_PAGES) -> Dict[str, Any]:
    """Look for fees in each (client, account_id, label).

    Returns {"found": [..new fee rows..], "errors": [..], "scanned": n}.
    A new fee (one not already acknowledged) trips the halt.
    """
    seen = _seen_tx()
    found: List[Dict[str, Any]] = []
    errors: List[str] = []
    scanned = 0
    for client, acct_id, label in targets:
        try:
            txs = fetch_history(client, acct_id, days=days, max_pages=max_pages)
        except Exception as e:
            errors.append(f"{label}: {e}")
            log(f"history read failed for {label}: {e}")
            continue
        scanned += 1
        try:
            import public_evidence
            public_evidence.record_history(label, txs)
        except Exception:
            pass
        for tx in txs:
            amt, why = transaction_fee(tx)
            if amt is None:
                continue
            tid = _tx_id(acct_id, tx)
            if tid in seen:
                continue
            row = {"account": label, "amount": str(amt), "why": why,
                   "symbol": str(tx.get("symbol") or ""),
                   "timestamp": str(tx.get("timestamp") or ""),
                   "description": str(tx.get("description") or "")[:200],
                   "tx_id": tid, "tx": redact(tx)}
            found.append(row)
            seen.add(tid)
    for row in found:
        log(f"fee found at {row['account']}: {row['why']}", row)
    with _lock:
        data, ok = _load_ex()
        if ok:          # never write over a file that could not be read
            data["last_scan"] = {"at": _now_iso(), "scanned": scanned,
                                 "errors": errors[:5], "found": len(found),
                                 "days": days}
            _save(data)
    if found and trip_on_find:
        first = found[0]
        sym = f" {first['symbol']}" if first["symbol"] else ""
        reason = (f"Public charged ${Decimal(first['amount']):.2f}{sym} at "
                  f"{first['account']} ({first['why']})")
        if len(found) > 1:
            extra_n = len(found) - 1
            reason += f", plus {extra_n} more fee{'' if extra_n == 1 else 's'}"
        for row in found:
            trip(reason, source="history", account=row["account"],
                 amount=row["amount"], symbol=row["symbol"], tx_id=row["tx_id"],
                 description=row["description"], timestamp=row["timestamp"])
    return {"found": found, "errors": errors, "scanned": scanned}
