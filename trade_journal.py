"""Persistent trade journal backed by trades.json.

Records every trade executed through this tool so we can distinguish
"shares I bought" from pre-existing holdings and compute P/L.

EXE packaging: pip install pyinstaller && pyinstaller --onefile --windowed app.py
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import os
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from modules import atomic

_FILE = Path(__file__).resolve().parent / "trades.json"
_lock = threading.Lock()


@contextmanager
def _writing() -> Iterator[None]:
    """Hold the journal for one read-modify-write: this process's threads AND
    every other process (reconcile.py, backfill_basis.py, runner.py, a second
    GUI). Without the cross-process half, two writers that both read N rows
    each save N+1 and one fill is gone. See atomic.file_lock.
    """
    with _lock:
        with atomic.file_lock(_FILE):
            yield


_log = logging.getLogger(__name__)


class JournalUnreadable(RuntimeError):
    """trades.json exists but could not be read, and neither could its .bak.

    Raised instead of returning [] so a read-modify-write caller can never save
    `[] + new row` over the whole history. The trade worker in app.py already
    turns a raised error here into a loud "NOT saved to the journal" line.
    """


# A read can lose a brief race with Google Drive / antivirus holding the file,
# or with a non-atomic external writer (a torn read). A few short retries ride
# that out; a genuinely corrupt file costs well under a second before we give up.
_READ_ATTEMPTS = 4
_READ_DELAY = 0.05
#: How long a READ that recovered from the .bak waits for the cross-process
#: journal lock before giving up on writing the recovery back. Short: it is a
#: reader, and a writer holding the lock will leave a good file behind it.
_RECOVER_LOCK_SECONDS = 1.0

#: Why the last read failed, or None. For a UI that wants to say so.
_last_error: Optional[str] = None


def last_error() -> Optional[str]:
    """The reason the journal could not be read on the last attempt, or None."""
    return _last_error


#: Set when a corrupt trades.json was rebuilt from its .bak and the good copy
#: written back. Informational: the journal is readable again, so this is NOT
#: an error (last_error() is None) and must not hold mirror.
_last_recovery: Optional[str] = None


def last_recovery() -> Optional[str]:
    """What the last .bak recovery did, or None if there has not been one."""
    return _last_recovery


def _read_file(path: Path) -> List[Dict[str, Any]]:
    """Parse one journal file, retrying briefly. Raises OSError / ValueError.

    utf-8-sig, not utf-8: a file re-saved by an editor with a BOM is still the
    same journal. FileNotFoundError is raised at once — it is not transient.
    """
    err: Exception = OSError(f"could not read {path.name}")
    for attempt in range(_READ_ATTEMPTS):
        if attempt:
            time.sleep(_READ_DELAY * (2 ** (attempt - 1)))
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except FileNotFoundError:
            raise
        except (OSError, ValueError) as e:     # ValueError covers JSON + Unicode
            err = e
            continue
        if not isinstance(data, list):
            raise ValueError(f"{path.name} is not a list of trades")
        return data
    raise err


def _quarantine(path: Path) -> Optional[Path]:
    """Keep a copy of an unreadable journal before anything can overwrite it."""
    return atomic.quarantine(path)


def _bak_path() -> Path:
    return _FILE.with_suffix(".bak")


def _stat_key(path: Path) -> Optional[tuple]:
    try:
        st = path.stat()
    except OSError:
        return None
    return (str(path), st.st_mtime_ns, st.st_size)


#: How many rows the .bak holds, keyed on its (path, mtime_ns, size).
#:
#: Every save used to parse BOTH trades.json and trades.bak just to compare
#: their lengths for the shrink guard -- two extra 2MB parses per row recorded,
#: all inside the writer lock. The .bak only changes when we write it, and we
#: know the count when we do, so it is parsed only when something else touched
#: it.
_bak_meta: Dict[str, Any] = {"key": None, "rows": None}


def _bak_count() -> Optional[int]:
    """Rows in the .bak, or None when there is no usable one."""
    bak = _bak_path()
    key = _stat_key(bak)
    if key is None:
        return None
    if _bak_meta.get("key") == key:
        return _bak_meta.get("rows")
    try:
        n: Optional[int] = len(_read_file(bak))
    except (OSError, ValueError):
        n = None
    _bak_meta["key"], _bak_meta["rows"] = key, n
    return n


def _check_not_shrunk(rows: List[Dict[str, Any]]) -> None:
    """Refuse a journal that is FAR smaller than its own backup.

    A valid `[]` (or a file cut down to a handful of rows) parses perfectly
    well, so nothing else here would notice -- and every save after it would
    build on the truncated history. The .bak is refreshed after each good save
    so it normally matches trades.json exactly, and an in-app delete leaves it
    one row ahead. A journal at half its backup or less, two or more rows
    short, was not made by this app: raise (setting last_error) rather than
    journal on top of it. The byte-size test keeps this to a stat() unless the
    .bak is markedly bigger than the journal.
    """
    global _last_error
    bkey = _stat_key(_bak_path())
    if bkey is None:
        return
    main = _stat_key(_FILE)
    main_size = main[2] if main else 0
    if main_size >= bkey[2] * 0.75:
        return
    n = _bak_count()
    if not n or len(rows) >= n - 1 or len(rows) > n // 2:
        return
    bak = _bak_path().name
    _last_error = (f"trades.json holds {len(rows)} trades but its backup {bak} "
                   f"holds {n}, so it looks truncated. Nothing will be written "
                   f"until it is repaired: copy {bak} over trades.json, or "
                   f"delete {bak} if those trades were removed on purpose.")
    _log.error("JOURNAL SHRUNK: %s", _last_error)
    raise JournalUnreadable(_last_error)


def _load() -> List[Dict[str, Any]]:
    """Parse trades.json. Raw read — no cache, for read-modify-write callers.

    Returns [] ONLY when the journal does not exist. Every other failure either
    recovers from the .bak (loudly) or raises JournalUnreadable — it never
    pretends the history is empty, because the caller is about to save.

    The .bak is used only when trades.json was read but did not PARSE. A file
    that cannot even be opened (a lock that outlasted the retries) is most
    likely fine underneath, and the .bak can be behind it (a failed backup
    refresh, a delete), so writing `.bak + new row` back could drop a real
    trade; that case raises.

    A journal that parses but is FAR smaller than its .bak raises too -- see
    _check_not_shrunk.
    """
    global _last_error
    try:
        rows = _read_file(_FILE)
    except FileNotFoundError:
        _check_not_shrunk([])
        _last_error = None
        return []
    except ValueError as e:
        primary: Exception = e
    except OSError as e:
        _last_error = f"trades.json could not be opened: {e}"
        _log.error("JOURNAL UNREADABLE: %s", _last_error)
        raise JournalUnreadable(_last_error) from e
    else:
        _check_not_shrunk(rows)
        _last_error = None
        return rows

    bak = _bak_path()
    try:
        rows = _read_file(bak)
    except (OSError, ValueError) as e:
        _last_error = (f"trades.json is corrupt ({primary}) and its backup "
                       f"{bak.name} could not be used ({e}). Nothing will be "
                       f"written until it is repaired.")
        _log.error("JOURNAL UNREADABLE: %s", _last_error)
        raise JournalUnreadable(_last_error) from primary

    kept = _quarantine(_FILE)
    msg = (f"trades.json is corrupt ({primary}); recovered {len(rows)} "
           f"trades from {bak.name}. The damaged file was kept as "
           f"{kept.name if kept else '(copy failed)'}.")
    # A successful recovery is not an error: the .bak is refreshed after every
    # save, so it IS the last saved journal, and holding mirror over it only
    # paused buying until a restart. Say what happened via last_recovery().
    global _last_recovery
    _last_error = None
    _last_recovery = msg
    # Write the recovered rows back so the file on disk is good again. Only
    # once the damaged file is safely kept (it is the one record of anything
    # it held beyond the .bak), and only under the writer lock with the file
    # re-checked: a reader racing a record_trade must never put the .bak back
    # over a row that was just saved. A writer already holding the lock (this
    # read IS its read-modify-write) saves rows+new itself a moment later.
    #
    # The in-process lock alone was not enough: another PROCESS (reconcile.py,
    # runner.py, a second GUI) can be mid record_trade under the file lock,
    # having just replaced the damaged file with a good one that holds a row
    # the .bak does not. So the cross-process lock is taken too, briefly --
    # a reader must not stall behind a writer, and if the lock is busy the
    # writer holding it is about to leave a good file anyway.
    if kept is not None and _lock.acquire(blocking=False):
        try:
            with atomic.file_lock(_FILE, timeout=_RECOVER_LOCK_SECONDS):
                try:
                    _read_file(_FILE)
                    still_bad = False
                except FileNotFoundError:
                    still_bad = False
                except (OSError, ValueError):
                    still_bad = True
                if still_bad:
                    atomic.write_text(_FILE, json.dumps(rows, indent=2))
                    _last_recovery = f"{msg} trades.json was rewritten from the backup."
        except Exception as e:                  # noqa: BLE001 — incl. LockTimeout
            _log.warning("recovered journal could not be written back: %s", e)
        finally:
            _lock.release()
    _log.warning("JOURNAL RECOVERED FROM BACKUP: %s", _last_recovery)
    return rows


#: Parsed journal, keyed by the file fingerprint it was parsed from.
#:
#: The journal is 4,500+ rows and ~1.4MB, so a parse costs ~10ms. Nothing
#: cached it, and the read paths call in far more often than that suggests:
#: one Quick Picks render alone went through five full parses, because
#: _purchased_pick_keys and _partial_pick_keys each recompute the same
#: coverage from scratch. That is ~50ms of blocked UI thread per render, on
#: a file that only changes when we place a trade.
#:
#: Keyed on version() — the same (mtime_ns, size) fingerprint the GUI already
#: trusts for its page cache — so an external writer (reconcile.py, a restore
#: from backup) is picked up on the next call rather than being served stale.
_cache: Dict[str, Any] = {"key": None, "rows": []}
#: Guards _cache only, and only for a dict lookup or store. It is NOT the
#: writer lock: a reader used to queue behind `_lock` while record_trade
#: re-parsed the 2MB journal several times, which froze the Tk thread for
#: seconds during a fan-out. Readers now never wait on a writer.
_cache_lock = threading.Lock()
#: Bumped by every save, so a reader that parsed the file BEFORE a save cannot
#: overwrite the newer rows that save put in the cache.
_cache_gen = 0


def _load_shared() -> List[Dict[str, Any]]:
    """The parsed journal, reused while the file underneath is unchanged.

    Returns the SHARED list — callers must not mutate it. `get_trades` hands
    out a copy; the read-modify-write paths deliberately use `_load` instead.

    Lock-free with respect to writers: a save swaps the file in with an atomic
    rename, so a parse that races it reads either the old journal or the new
    one, never a fragment, and a stale result is keyed to the old fingerprint
    and re-read on the next call.
    """
    global _last_error
    key = version()
    with _cache_lock:
        if _cache.get("key") == key and "rows" in _cache:
            return _cache["rows"]
        gen = _cache_gen
    try:
        rows = _load()
    except JournalUnreadable:
        # Read-only callers (every page of the GUI) must not crash on this.
        # Serve the last rows we did read, or nothing, and leave the key
        # alone so the next call tries the file again. _load logged it and set
        # last_error, which is what tells a caller this is not the real
        # history.
        if not _last_error:
            _last_error = "trades.json could not be read"
        with _cache_lock:
            return _cache.get("rows") or []
    with _cache_lock:
        if _cache_gen == gen:
            _cache["rows"] = rows
            _cache["key"] = key
    return rows


def _refresh_backup(shrink_ok: bool = False) -> None:
    """Copy the ON-DISK journal to .bak. Used before an intentional delete.

    It must PARSE: when trades.json is corrupt and _load recovered from the
    .bak, copying the corrupt file over it would destroy the one good copy.
    And it must not have FEWER rows than the .bak already holds unless the
    shrink is intentional (`shrink_ok`).
    """
    if not _FILE.exists():
        return
    current = _read_file(_FILE)          # raises -> no backup this time
    if not shrink_ok:
        backed_up = _bak_count()
        if backed_up is not None and len(current) < backed_up:
            _log.warning("trades.json has %d rows but %s has %d; keeping the "
                         "backup rather than shrinking it", len(current),
                         _bak_path().name, backed_up)
            return
    bak = _bak_path()
    shutil.copy2(_FILE, bak)
    _bak_meta["key"], _bak_meta["rows"] = _stat_key(bak), len(current)


def _backup_saved(payload: str, n_rows: int) -> None:
    """Make the .bak a copy of what was JUST saved -- after the replace.

    It used to be refreshed BEFORE the replace, i.e. to the previous version,
    so the backup always lagged one save: a torn trades.json recovered from it
    silently lost the newest fill. Written from the payload already in memory
    (no re-read, no re-parse), atomically, and never to fewer rows than the
    .bak already holds -- a truncated journal must not take its backup with it.
    """
    backed_up = _bak_count()
    if backed_up is not None and n_rows < backed_up:
        _log.warning("trades.json has %d rows but %s has %d; keeping the "
                     "backup rather than shrinking it", n_rows,
                     _bak_path().name, backed_up)
        return
    bak = _bak_path()
    atomic.write_text(bak, payload)
    _bak_meta["key"], _bak_meta["rows"] = _stat_key(bak), n_rows


def _save(trades: List[Dict[str, Any]], shrink_ok: bool = False) -> None:
    """Write the journal so that a crash cannot cost it.

    THIS FILE IS THE PRODUCT. Every share this tool ever bought or sold, the
    cost basis under every open position, and the whole realized-P/L figure are
    5,000-odd rows in one JSON file that nothing else can reconstruct — the
    brokers do not know which of your shares came from here, and the cloud feed
    carries plays, not your fills.

    It used to be written with a plain `write_text`, which truncates the file
    and then writes; a crash in between cost the whole history. Now: temp file
    in the same directory (so `replace` is a rename inside one filesystem,
    which is atomic), fsync before the rename, and then the .bak refreshed to
    the SAME contents. An intentional delete (`shrink_ok`) instead keeps the
    pre-delete journal as the backup, so a mistaken delete can be undone.

    Raises if the journal itself could not be written; a failed backup never
    fails the save.
    """
    global _cache_gen, _last_error
    payload = json.dumps(trades, indent=2)
    if shrink_ok:
        try:
            _refresh_backup(shrink_ok=True)
        except Exception:
            pass
    # atomic.write_text: unique temp + fsync + atomic.replace, which retries
    # the WinError 5 Google Drive causes by holding the journal mid-upload.
    atomic.write_text(_FILE, payload)
    # A good journal is on disk now: whatever made the last read fail is over.
    _last_error = None
    # Refresh rather than merely invalidate: we already hold the rows, and the
    # very next thing a writer does is re-render off them.
    with _cache_lock:
        _cache_gen += 1
        _cache["rows"] = list(trades)
        _cache["key"] = version()
    if not shrink_ok:
        try:
            _backup_saved(payload, len(trades))
        except Exception:
            _log.warning("trades.json saved but its backup could not be "
                         "refreshed", exc_info=True)


#: What `fill_price` on a row actually is.
#:
#: "fill"  the broker told us what the order executed at. Trustworthy.
#: "quote" the market price at the moment we placed it, which is NOT the same
#:         thing and can be far from it on a thin post-split name.
#: ""      recorded before this field existed, so unknown — treat as "quote".
PRICE_FILL = "fill"
PRICE_QUOTE = "quote"
#: "manual" the user typed the price in, reporting a sale this tool did not
#:          place. Not a fill we read, so it stays "estimated" — but it is the
#:          only price anyone has for an order placed at the broker by hand.
PRICE_MANUAL = "manual"

#: A position that LEFT an account without a sale this tool placed.
#:
#: The journal only learns about trades it executes, so a position can vanish
#: for reasons it never sees — most often a reverse split settling to CASH IN
#: LIEU at a broker that does not hold fractions. Seven of the ten do exactly
#: that, and the shares stop existing the moment the split runs.
#:
#: It is its own side because neither existing one can say this honestly:
#:
#:   a sell at no price     books the entire cost basis as a loss. $198 of
#:                          dissolved positions would become $198 of invented
#:                          losses.
#:   a sell at some price   invents proceeds nobody received.
#:   leaving it open        is what produces a $428 "deployed" figure of which
#:                          $198 is shares that have not existed for weeks.
#:
#: So a close records the ONE thing actually known — the position is gone — and
#: stays out of the profit arithmetic entirely, where `unaccounted()` reports it
#: rather than letting it quietly become a number.
SIDE_CLOSE = "close"

#: Why a position was closed. Free text, but these are the ones that recur.
CLOSE_CASH_IN_LIEU = "cash_in_lieu"
CLOSE_RECONCILED = "reconciled"     # the broker simply does not have it
CLOSE_MANUAL = "manual"             # the user says the shares are not there



def is_estimated(trade: Dict[str, Any]) -> bool:
    """True when this row's price is a quote rather than an executed fill.

    Every row written before 2026-08-06 is estimated: the app called what it
    named `_fetch_fill_price`, which asks get_holdings() for the CURRENT market
    price and falls back to Yahoo — it never read an execution. One lookup per
    batch was then stamped onto every account in it, which is why the journal
    contains nine Wells Fargo orders placed across 7.4 minutes all priced at
    exactly $0.08.
    """
    return trade.get("price_source") != PRICE_FILL


def record_trade(
    broker: str,
    account_id: str,
    side: str,
    symbol: str,
    qty: float,
    fill_price: Optional[float] = None,
    order_id: Optional[str] = None,
    price_source: str = "",
    when: Optional[str] = None,
) -> Dict[str, Any]:
    """Append a trade entry and return it.

    `order_id` is the broker's own identifier for the order. It was previously
    returned by the API, carried as far as AccountOutput.order_id, and then
    dropped here — which is why no trade in the journal can be checked against
    the broker that placed it. Keeping it costs one field and is the only thing
    that makes a fill recoverable after the fact.

    `when` is an ISO timestamp for a trade that did not happen just now — a
    sale placed at the broker by hand last Tuesday and reported here after the
    fact. Defaults to now, which is right for everything this tool executes.
    """
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": when or datetime.now(timezone.utc).isoformat(),
        "broker": broker.lower(),
        "account_id": account_id,
        "side": side.lower(),
        "symbol": symbol.upper(),
        "qty": float(qty),
        "fill_price": fill_price,
        "order_id": order_id or None,
        "price_source": price_source or PRICE_QUOTE,
    }
    with _writing():
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def record_close(
    broker: str,
    account_id: str,
    symbol: str,
    qty: float,
    reason: str = CLOSE_RECONCILED,
    note: str = "",
    when: Optional[str] = None,
) -> Dict[str, Any]:
    """Record that a position is gone, without claiming it was sold.

    See SIDE_CLOSE. This is the only honest entry for a holding that a
    corporate action dissolved: it removes the position so the sell worklist
    and the deployed figure stop counting shares that do not exist, and it
    carries NO price, so nothing downstream can turn it into profit or loss.
    """
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": when or datetime.now(timezone.utc).isoformat(),
        "broker": broker.lower(),
        "account_id": account_id,
        "side": SIDE_CLOSE,
        "symbol": symbol.upper(),
        "qty": float(qty),
        "fill_price": None,
        "order_id": None,
        "price_source": "",
        "close_reason": reason,
        "note": note,
    }
    with _writing():
        trades = _load()
        trades.append(entry)
        _save(trades)
    return entry


def set_fill_prices(ids: List[str], fill_price: Optional[float],
                    price_source: str = PRICE_QUOTE) -> int:
    """Price rows that were journaled before their price was known.

    The trade worker writes each fill the moment the broker confirms it, with
    whatever price it already has (none, for a buy), and only THEN goes looking
    for a quote -- a get_holdings() round trip that can take minutes. A crash
    in that window used to cost the fills themselves; now it costs only their
    price, and an unpriced row is reported as such everywhere, never booked
    at $0.

    Touches only the rows named, and only to set the price: a None price is a
    no-op (the row already says "unknown"). Returns how many rows changed.
    """
    if fill_price is None or not ids:
        return 0
    want = {str(i) for i in ids if i}
    with _writing():
        trades = _load()
        n = 0
        for i, t in enumerate(trades):
            if t.get("id") in want:
                trades[i] = dict(t, fill_price=fill_price,
                                 price_source=price_source or PRICE_QUOTE)
                n += 1
        if n:
            _save(trades)
    return n


def unaccounted(trades: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Cost basis removed by closes rather than by sales.

    Reported, never folded in. Cash in lieu DID pay something, so this money is
    not lost -- it is unknown, and a figure the app calls realized must not
    pretend either way.

    Basis is the average over PRICED buys only: an unpriced buy counted at $0
    would understate every close's basis.
    """
    rows = get_trades() if trades is None else list(trades)
    cost: Dict[str, Dict[str, float]] = {}
    for t in rows:
        if t.get("side") == "buy" and t.get("fill_price") is not None:
            b = cost.setdefault(t["symbol"], {"qty": 0.0, "cost": 0.0})
            b["qty"] += float(t.get("qty") or 0)
            b["cost"] += float(t["fill_price"]) * float(t.get("qty") or 0)

    total = 0.0
    by_reason: Dict[str, float] = {}
    n = 0
    for t in rows:
        if t.get("side") != SIDE_CLOSE:
            continue
        b = cost.get(t["symbol"])
        if not b or not b["qty"]:
            continue
        v = (b["cost"] / b["qty"]) * float(t.get("qty") or 0)
        total += v
        n += 1
        r = t.get("close_reason") or CLOSE_RECONCILED
        by_reason[r] = by_reason.get(r, 0.0) + v
    return {"total": total, "positions": n, "by_reason": by_reason}


def version() -> tuple:
    """A cheap fingerprint of the journal: (mtime_ns, size). No parse, no lock.

    Exists so the GUI can ask "has anything changed?" without reading and
    parsing ~2000 rows on every tab switch, which is what it used to do.
    Returns (0, 0) when the file is missing, so an empty journal has a stable
    identity rather than a changing one.
    """
    try:
        st = _FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


#: Login 1's account labels at these brokers once carried a login prefix that
#: was dropped (login 1 must match its single-login form). An install that had
#: several logins then has rows under BOTH spellings of the same account, and
#: positions net on the exact string -- so the old buy never met the new sell.
#: (broker, old prefix, current prefix). Login 1 only, these three only.
_LOGIN1_ALIASES = (
    ("robinhood", "Robinhood 1 | ", ""),
    ("schwab", "Schwab 1 (", "Schwab ("),
    ("fennel", "Fennel 1 · ", "Fennel · "),
)


def canonical_account(broker: Any, account_id: Any) -> str:
    """account_id with an old login-1 prefix mapped to today's bare form."""
    acct = str(account_id or "")
    b = str(broker or "").lower()
    for ab, old, new in _LOGIN1_ALIASES:
        if b == ab and acct.startswith(old):
            return new + acct[len(old):]
    return acct


def _canonical_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The rows with login-1 aliases normalised. Copies only the rows it
    changes; the shared cached dicts are never mutated. The file on disk keeps
    whatever was journaled."""
    out: Optional[List[Dict[str, Any]]] = None
    for i, t in enumerate(rows):
        acct = t.get("account_id")
        if not isinstance(acct, str):
            continue
        canon = canonical_account(t.get("broker"), acct)
        if canon != acct:
            if out is None:
                out = list(rows)
            out[i] = dict(t, account_id=canon)
    return out if out is not None else rows


#: The account number in a label: the LAST parenthesised group, when it holds
#: a digit. "(manual entry)" is not a number -- SoFi gives four different
#: accounts exactly that suffix -- so it does not count.
_ACCT_NUM_RE = re.compile(r"\(([^)]*\d[^)]*)\)\s*$")


def account_key(label: Any) -> str:
    """A stable identity for one account, for NETTING per account.

    The human label drifts while the account stays the same: Fidelity renames
    ('Fidelity 1 · Individual (Z…)' became 'Fidelity 1 · FinTec (Z…)'),
    encoding damage, Public gluing ' = $61.32' onto it. The trailing
    "(number)" does not drift, so that is the key; a label with no number is
    keyed on itself. Same rule as app._account_key, minus its one flaw: a
    parenthesis with no digit in it ('(manual entry)') is not a number and
    must not merge different accounts. Compare keys only within one broker.

    The LOGIN is part of it. Two logins at one broker can hold accounts with
    the same trailing number -- 'Public 1 BROKERAGE (0043)' and 'Public 2
    BROKERAGE (0043)' are two accounts -- so a numbered login above 1 ('Public
    2 ', 'Robinhood 2 · ') prefixes the key. Login 1, numbered or bare, keys as
    the number alone, so every key an existing single-login install produced
    is unchanged.
    """
    text = str(label or "").split(" = ")[0].strip()
    m = _ACCT_NUM_RE.search(text)
    if m:
        key = "".join(c for c in m.group(1) if c.isalnum()).upper()
        if key:
            idx = login_index(text[:m.start()])
            return f"L{idx}:{key}" if idx > 1 else key
    return text.casefold()


#: A label's login prefix: a broker-ish name, then the login number, then
#: anything that is not a digit ('Public 2 BROKERAGE', 'Fidelity 1 · ...',
#: 'Robinhood 1 | ...'). Anchored at the start, so an account NAME that ends in
#: a digit ('... Etf 2 (Z1)') never reads as a login.
_LOGIN_RE = re.compile(r"^\s*[A-Za-z][A-Za-z .&'-]*?\s+(\d{1,2})(?=\D|$)")


def login_index(label: Any) -> int:
    """The login number a label starts with, 1 when it carries none."""
    m = _LOGIN_RE.match(str(label or ""))
    try:
        n = int(m.group(1)) if m else 1
    except ValueError:
        n = 1
    return n if n > 0 else 1


def fold_renames(rows: List[Dict[str, Any]],
                 renames: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Rows with every renamed ticker filed under ONE name.

    `renames` is CURRENT ticker -> the one we bought under (the app's
    `_symbol_renames`). We bought AGAE and sold AIFA: without this, AGAE reads
    as an open position forever (inflating DEPLOYED) and AIFA as a sale with
    no buy (dropped from realized). Rows are copied only where they change,
    and keep the ticker that actually traded as `executed_symbol`.
    """
    m = {str(k).upper(): str(v).upper()
         for k, v in (renames or {}).items() if k and v}
    if not m:
        return rows
    out: List[Dict[str, Any]] = []
    for t in rows:
        sym = str(t.get("symbol") or "").upper()
        old = m.get(sym)
        out.append(dict(t, symbol=old, executed_symbol=t.get("symbol"))
                   if old and old != sym else t)
    return out


def get_trades(broker: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all recorded trades, optionally filtered by broker.

    The returned list is a copy, so callers can filter and sort it freely; the
    row dicts inside are shared with the cache and must be treated as read-only
    (nothing mutates them today — split_adjusted copies every row it restates).
    """
    # No `_lock`: readers use the version-keyed cache and never queue behind
    # a writer (see _cache_lock).
    trades = _canonical_rows(_load_shared())
    if broker:
        return [t for t in trades if t["broker"] == broker.lower()]
    return list(trades)


def split_adjusted(trades: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """The journal restated in PRE-SPLIT shares. For P/L and position maths.

    A reverse split changes your share count with no trade to record, so the
    journal never sees it happen. That quietly breaks any profit computed from
    per-share prices. Buy 1 share of GRNQ at $1.30, let a 1-for-10 split turn it
    into 0.1 of a share, sell that for $10.00, and

        (sell price - buy price) x shares sold  =  (10.00 - 1.30) x 0.1  =  +$0.87

    reports a profit on a trade that took $1.30 and gave back $1.00. It charges a
    tenth of what was paid against the whole of the proceeds. Across 19 Public
    accounts that was +$16.53 where the truth is -$5.70 — and it is wrong in the
    flattering direction on exactly the plays that did NOT round up, which are
    the ones worth reporting honestly.

    THE RULE, and it is deliberately narrow:

        a sell whose quantity is a FRACTION of a share is what a reverse split
        left of whole shares already held. That fraction was never bought, so it
        does not get a fraction's cost basis — it gets the basis of the shares
        it came from.

    So the sell is restated into the units the buy was recorded in: the same
    cash, spread across the shares that actually produced it.

        sold 0.1 @ $10.00   ->   sold 1.0 @ $1.00      ($1.00 of proceeds either way)

    Both sides of the subtraction are finally in the same units, so every figure
    downstream corrects itself — including the open position, which now closes
    to zero instead of leaving 0.9 phantom shares that no longer exist.

    Only FRACTIONAL sells are touched. A sell of whole shares smaller than the
    position is an ordinary partial exit (13 of 26 accounts sold), the existing
    arithmetic is right about it, and widening this rule to cover that case
    would charge a whole position's basis to the first account that sold.

    The executed quantity and price stay on the row as `executed_qty` and
    `executed_price`: a trade history has to show the fill that really happened.
    Rows are copies and trades.json is never rewritten — this is a lens, not a
    migration, so it stays correct for trades recorded before it existed.
    """
    # Processed in file order. record_trade only ever appends, so that is
    # chronological except for a row reported after the fact with `when` — and
    # such a row lands at the END, where it sees the whole history before it,
    # which is exactly where a correction has to be applied. Sorting here would
    # reorder the caller's list out from under a display that expects
    # newest-last, and would move those corrections in front of trades that
    # were recorded knowing about them.
    rows = get_trades() if trades is None else list(trades)
    held: Dict[tuple, float] = {}
    out: List[Dict[str, Any]] = []
    for t in rows:
        row = dict(t)
        # Keyed on the stable account number, not the label: a buy journaled
        # under 'Fidelity 1 · Individual (Z1)' and its remnant sold under
        # 'Fidelity 1 · FinTec (Z1)' are one account, and keyed on the label
        # the remnant would meet no holding and never be restated.
        key = (row.get("broker"),
               account_key(canonical_account(row.get("broker"),
                                             row.get("account_id"))),
               row.get("symbol"))
        try:
            qty = float(row.get("qty") or 0.0)
        except (TypeError, ValueError):
            out.append(row)
            continue
        side = str(row.get("side") or "").lower()

        if side == "buy":
            held[key] = held.get(key, 0.0) + qty
        elif side == SIDE_CLOSE:
            # Reduces the position and nothing else. Never restated: a close
            # carries no price, so there is no proceeds figure to put back into
            # pre-split units, and a fractional close is simply the fraction
            # that dissolved.
            held[key] = max(0.0, held.get(key, 0.0) - qty)
        elif side == "sell":
            have = held.get(key, 0.0)
            # A whole-share sell is an ordinary exit; only a fraction of a share
            # can be a split remnant, and only if there was something to split.
            if abs(qty - round(qty)) > 1e-9 and 0 < qty < have:
                price = row.get("fill_price")
                proceeds = (price or 0.0) * qty
                row["executed_qty"] = qty
                row["executed_price"] = price
                row["split_ratio"] = have / qty
                row["qty"] = have
                # None stays None: an unpriced fill has no basis, and inventing
                # $0.00 here would book the whole position as a total loss.
                row["fill_price"] = (proceeds / have) if price is not None else None
                qty = have
            held[key] = max(0.0, have - qty)
        out.append(row)
    return out


def get_portfolio() -> Dict[tuple, Dict[str, Any]]:
    """Aggregate trades into net positions.

    Returns {(broker, symbol): {qty, avg_cost, total_cost}}.
    Buys add to position; sells reduce it (FIFO-style average).

    Split-adjusted, because a position is exactly what the raw journal gets
    wrong: a sold-off split remnant nets 1.0 - 0.1 and leaves 0.9 of a share
    that no longer exists sitting in the portfolio forever.
    """
    positions: Dict[tuple, Dict[str, Any]] = {}
    for t in split_adjusted():
        key = (t["broker"], t["symbol"])
        pos = positions.setdefault(key, {"qty": 0.0, "avg_cost": 0.0, "total_cost": 0.0,
                                         "_pq": 0.0, "_pc": 0.0})
        if t["side"] == "buy":
            pos["qty"] += t["qty"]
            # Average over PRICED buys only. An unpriced buy counted at $0
            # dragged avg_cost down and showed market value as fake profit.
            if t["fill_price"] is not None:
                pos["_pq"] += t["qty"]
                pos["_pc"] += t["fill_price"] * t["qty"]
            pos["avg_cost"] = pos["_pc"] / pos["_pq"] if pos["_pq"] else 0.0
            pos["total_cost"] = pos["avg_cost"] * pos["qty"]
        elif t["side"] in ("sell", SIDE_CLOSE):
            if pos["qty"] > 0:
                # reduce position, keep avg_cost the same
                sold_qty = min(t["qty"], pos["qty"])
                keep = (pos["qty"] - sold_qty) / pos["qty"]
                pos["_pq"] *= keep
                pos["_pc"] *= keep
                pos["total_cost"] -= pos["avg_cost"] * sold_qty
                pos["qty"] -= sold_qty
                if pos["qty"] <= 0:
                    pos.update(qty=0.0, total_cost=0.0, avg_cost=0.0, _pq=0.0, _pc=0.0)
    # filter out zero-quantity positions
    return {k: {f: v[f] for f in ("qty", "avg_cost", "total_cost")}
            for k, v in positions.items() if v["qty"] > 0}


def delete_trade(trade_id: str) -> bool:
    """Remove a trade entry by ID. Returns True if found and deleted."""
    with _writing():
        trades = _load()
        before = len(trades)
        trades = [t for t in trades if t["id"] != trade_id]
        if len(trades) < before:
            _save(trades, shrink_ok=True)
            return True
    return False
