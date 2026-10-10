"""What automation actually did, kept on disk.

Mirror trading used to leave almost no evidence behind. The live commentary went
into a `tk.Text` box that is wiped on restart, per-account outcomes went into
`logs/trade_results.log` as prose with no marker saying which run they belonged
to, and `trades.json` recorded only the fills — so a rejected account, a pick
that was skipped, or a whole run that fired while you were asleep left nothing
you could look at afterwards. "Did it buy AGAE this morning, and if not why not"
was unanswerable an hour later.

This module is the missing record. It stores two streams:

    SCANS  every time the schedule woke up and looked at the feed, including
           the picks it deliberately did NOT buy and the reason for each. A run
           that bought nothing is still something automation *did*, and it is
           the case people most want explained.
    RUNS   one per pick executed, holding the whole fan-out: broker legs, and
           inside each leg every account with its ok/fail and the broker's own
           message.

Both are written by the desktop app on the machine that runs the automation, so
nothing here needs the alert feed, a subscription, or the network.

Shape (mirror_runs.json):

    {"version": 1,
     "runs":  [{"id", "started_at", "finished_at", "symbol", "side", "qty",
                "note", "pick_date", "trigger", "slot", "dry_run", "brokers":[],
                "legs": [{"broker", "state", "ok_accounts", "fail_accounts",
                          "shares", "fill_price", "errors": [],
                          "accounts": [{"account_id", "ok", "message"}]}],
                "ok_accounts", "fail_accounts", "shares", "elapsed"}],
     "scans": [{"at", "trigger", "slot", "considered", "queued",
                "skipped": [{"symbol", "reason"}]}]}

A run is written the moment it starts and updated in place as legs report, so a
crash mid-fan-out still leaves the finished legs on disk with `finished_at`
empty — which reads correctly as "this run never completed" instead of
vanishing.
"""
from __future__ import annotations

import atexit
import copy
import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules import atomic

_FILE = Path(__file__).resolve().parent / "mirror_runs.json"
_lock = threading.RLock()
_gen = 0          # bumped on every recorded change; see version()


def _bump() -> None:
    global _gen
    _gen += 1

# Enough history to answer "what happened last month" without letting a file the
# UI reads on every page visit grow without bound.
MAX_RUNS = 400
MAX_SCANS = 400


# --------------------------------------------------------------------- storage
#
# The file is ~1.3MB and is written once per broker leg as a mirror run fans
# out — from the Tk main thread, because that is where legs land. Parsing it,
# re-serialising it and writing it back was an 80-100ms freeze per leg, felt on
# whatever page happened to be open. And the Mirror page parsed it three times
# per render (runs, summary, scans).
#
# So the journal lives in memory. Reads come from the cache (reloaded only if
# something else changed the file); a write updates the cache synchronously —
# so a read straight after it sees it — and hands the disk write to one
# background writer. The writer always writes the CURRENT state, so several
# quick legs coalesce into one write and the last write on disk is always the
# newest. flush() drains it; the app calls it on close and atexit backs that
# up, so a queued write is not lost when the window goes away.

_cache: Optional[Dict[str, Any]] = None
_cache_stat: Optional[tuple] = None     # file (mtime, size) the cache matches
_dirty = False                          # cache is ahead of the file
_inflight = False                       # a snapshot is being written now
_wake = threading.Condition(threading.Lock())
_writer: Optional[threading.Thread] = None
# Held for a whole write — snapshot AND disk. Two threads writing the same .tmp
# at once (the writer and a flush on close) could interleave into a file that
# is neither snapshot; serialising them also keeps writes in order.
_io_lock = threading.Lock()


def _empty() -> Dict[str, Any]:
    return {"version": 1, "runs": [], "scans": []}


def _stat() -> Optional[tuple]:
    try:
        st = _FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


#: Why the file could not be READ (opened), or None. While set, nothing is
#: written: the file is most likely fine underneath a lock, and saving this
#: session's view over it would erase the history mirror's repair relies on.
_read_error: Optional[str] = None

_READ_ATTEMPTS = 3
_READ_DELAY = 0.05


def read_error() -> Optional[str]:
    """Why the journal file could not be read on the last attempt, or None."""
    return _read_error


def _read_file() -> Dict[str, Any]:
    """The parsed journal. A CORRUPT file reads as empty (it costs history, not
    the automation). A file that exists but cannot be OPENED raises OSError
    after a few short retries — it is not the same thing as an empty journal.
    """
    if not _FILE.exists():
        return _empty()
    text: Optional[str] = None
    err: Optional[OSError] = None
    for attempt in range(_READ_ATTEMPTS):
        if attempt:
            time.sleep(_READ_DELAY * attempt)
        try:
            text = _FILE.read_text(encoding="utf-8")
            break
        except FileNotFoundError:
            return _empty()
        except OSError as e:
            err = e
    if text is None:
        raise err or OSError(f"could not read {_FILE.name}")
    try:
        data = json.loads(text)
    except ValueError:                  # JSON + Unicode errors
        return _empty()
    if not isinstance(data, dict):
        return _empty()
    data.setdefault("version", 1)
    for key in ("runs", "scans"):
        if not isinstance(data.get(key), list):
            data[key] = []
    return data


def _load() -> Dict[str, Any]:
    """The live journal. Call with _lock held.

    Served from memory unless the file changed underneath us (another copy of
    the app, a restore by hand) — and never reloaded while our own write is
    still queued, because then the memory copy is the newer one.
    """
    global _cache, _cache_stat, _read_error
    if _cache is not None and (_dirty or _inflight or _stat() == _cache_stat):
        return _cache
    st = _stat()
    try:
        data = _read_file()
    except OSError as e:
        # Not cached, so the next call reads again; writes are refused until
        # one succeeds (see _save). Callers get a private copy of what we last
        # read, so a recorder appending to it cannot leak into the cache.
        _read_error = f"{_FILE.name} could not be read ({e})"
        return copy.deepcopy(_cache) if _cache is not None else _empty()
    _read_error = None
    _cache = data
    _cache_stat = st
    return _cache


def _save(data: Dict[str, Any]) -> None:
    """Commit `data` as the journal: in memory now, on disk shortly.

    Refused while the file is unreadable: `data` was built on an empty (or
    stale) view, and writing it would replace the real history.
    """
    global _cache, _dirty
    if _read_error is not None:
        try:
            print(f"mirror_journal: not saving -- {_read_error}", file=sys.stderr)
        except Exception:
            pass                        # pyw: no stderr at all
        return
    data["runs"] = data["runs"][-MAX_RUNS:]
    data["scans"] = data["scans"][-MAX_SCANS:]
    _cache = data
    _dirty = True
    _kick_writer()


def _write_now(timeout: float = -1) -> None:
    """Serialise the current cache and write it. Holds _lock only while it
    serialises, so the snapshot is consistent and recorders are not blocked
    by the disk."""
    if not _io_lock.acquire(timeout=timeout):
        return
    try:
        _write_locked()
    finally:
        _io_lock.release()


def _write_locked() -> None:
    global _dirty, _inflight, _cache_stat
    with _lock:
        if not _dirty or _cache is None:
            return
        # Compact, not indent=2: nobody reads this by eye, and indenting a
        # 1.3MB file roughly doubled both its size and the time to write it.
        text = json.dumps(_cache, separators=(",", ":"))
        _dirty = False
        # Until the replace lands the file is OLDER than memory; _load must not
        # mistake that for someone else's change and reload over our data.
        _inflight = True
    try:
        # Atomic, for the same reason trade_journal is: a half-written file
        # reads as a mirror that has never run and re-buys everything.
        tmp = _FILE.with_suffix(".tmp")
        tmp.write_text(text, encoding="utf-8")
        atomic.replace(tmp, _FILE)
    except OSError:
        # A read-only disk must not take the trade down with it -- but the
        # write is still owed. Mark it pending again so the writer retries
        # (with a backoff, see _writer_loop) instead of dropping this run's
        # history on the floor until something else happens to save.
        with _lock:
            _dirty = True
        raise
    finally:
        with _lock:
            # Whatever is on disk now is ours: adopt its stat so the next read
            # does not reload over the memory copy (on a failed write that
            # keeps this session's history in memory, as before).
            _cache_stat = _stat()
            _inflight = False


#: Backoff between failed writes, seconds: first retry, and the ceiling.
_RETRY_FIRST_S = 1.0
_RETRY_MAX_S = 5.0
_last_error: Optional[str] = None


def _writer_loop() -> None:
    """Write whenever the journal is dirty; back off while writes fail.

    A write that raises leaves the journal dirty, and this loop only sleeps
    while it is CLEAN -- so a failure used to send it straight back round:
    one core pinned at 100% for as long as the disk stayed unwritable (or a
    record stayed unserialisable), in the background of a trading app. Now a
    failure waits 1s, then 2s, 4s, capped at 5s, and is reported once rather
    than once per spin.
    """
    global _last_error
    delay = _RETRY_FIRST_S
    while True:
        with _wake:
            while not _dirty:
                _wake.wait()
        try:
            _write_now()
            delay = _RETRY_FIRST_S
            _last_error = None
        except Exception as exc:                # noqa: BLE001
            msg = f"{type(exc).__name__}: {exc}"
            if msg != _last_error:
                _last_error = msg
                try:
                    print(f"mirror_journal: write failed, retrying -- {msg}",
                          file=sys.stderr)
                except Exception:
                    pass                        # pyw: no stderr at all
            time.sleep(delay)
            delay = min(delay * 2, _RETRY_MAX_S)


def _kick_writer() -> None:
    global _writer
    with _wake:
        if _writer is None or not _writer.is_alive():
            _writer = threading.Thread(target=_writer_loop, name="mirror-journal",
                                       daemon=True)
            _writer.start()
        _wake.notify_all()


def flush(timeout: float = 10.0) -> bool:
    """Block until everything recorded is on disk. True if it is.

    Waits out a write the background thread already has in progress (a daemon
    thread is killed mid-write at exit), then writes anything still pending on
    the calling thread — which works even when the writer thread is gone.
    """
    try:
        _write_now(timeout)
    except Exception:
        return False
    return not _dirty


atexit.register(flush)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def load() -> Dict[str, Any]:
    """The whole journal, newest last. Callers must not mutate the result —
    it is the shared in-memory copy, not a private parse."""
    with _lock:
        return _load()


def version() -> tuple:
    """Cheap fingerprint for the page-render cache — no parse.

    Moves when a write lands in memory (the generation), not when the file
    catches up a moment later, so one change costs the page one render. A
    journal changed by something else is still noticed, as one more change.
    """
    if not (_dirty or _inflight) and _cache is not None and _stat() != _cache_stat:
        # Changed by something other than us: pick it up now and count it as
        # one change, rather than reporting the file stat (which would move
        # again after every write of our own and cost a second render).
        with _lock:
            if not (_dirty or _inflight) and _stat() != _cache_stat:
                _load()
                _bump()
    return (_gen,)


def clear() -> None:
    with _lock:
        _save(_empty())
        _bump()


# ------------------------------------------------------------------- recording

def record_scan(*, trigger: str, slot: str = "", considered: int = 0,
                queued: int = 0, skipped: Optional[List[Dict[str, str]]] = None) -> None:
    """One pass over the feed. Logged even when it queued nothing.

    The empty scan is the entry that earns this table: without it, an
    automation that has been quiet for a week is indistinguishable from one that
    silently stopped waking up.
    """
    entry = {
        "at": _now(),
        "trigger": trigger,
        "slot": slot,
        "considered": int(considered),
        "queued": int(queued),
        "skipped": list(skipped or []),
    }
    with _lock:
        data = _load()
        data["scans"].append(entry)
        _save(data)
        _bump()


def start_run(*, symbol: str, side: str, qty: str, brokers: List[str],
              trigger: str = "schedule", slot: str = "", note: str = "",
              pick_date: str = "", dry_run: bool = False) -> str:
    """Open a run and return its id. The id is what legs report against."""
    run_id = f"{datetime.now().strftime('%Y%m%dT%H%M%S%f')}-{symbol.upper()}"
    entry = {
        "id": run_id,
        "started_at": _now(),
        "finished_at": "",
        "symbol": symbol.upper(),
        "side": side.lower(),
        "qty": str(qty),
        "note": note,
        "pick_date": pick_date,
        "trigger": trigger,
        "slot": slot,
        "dry_run": bool(dry_run),
        "brokers": list(brokers),
        "legs": [],
        "ok_accounts": 0,
        "fail_accounts": 0,
        "shares": 0.0,
        "elapsed": 0.0,
    }
    with _lock:
        data = _load()
        data["runs"].append(entry)
        _save(data)
        _bump()
    return run_id


def _find(data: Dict[str, Any], run_id: str) -> Optional[Dict[str, Any]]:
    for run in reversed(data["runs"]):
        if run.get("id") == run_id:
            return run
    return None


def record_leg(run_id: str, leg: Dict[str, Any]) -> None:
    """One broker's outcome, with its accounts. Re-reporting a broker replaces
    the earlier leg rather than appending a duplicate."""
    if not run_id:
        return
    with _lock:
        data = _load()
        run = _find(data, run_id)
        if run is None:
            return
        broker = str(leg.get("broker") or "")
        run["legs"] = [l for l in run["legs"] if l.get("broker") != broker]
        run["legs"].append({
            "broker": broker,
            "state": leg.get("state", ""),
            "ok_accounts": int(leg.get("ok_accounts") or 0),
            "fail_accounts": int(leg.get("fail_accounts") or 0),
            "shares": float(leg.get("shares") or 0.0),
            "fill_price": leg.get("fill_price"),
            "errors": list(leg.get("errors") or []),
            "accounts": [
                {"account_id": str(a.get("account_id") or ""),
                 "ok": bool(a.get("ok")),
                 "message": str(a.get("message") or "")}
                for a in (leg.get("accounts") or [])
            ],
        })
        _save(data)
        _bump()


def finish_run(run_id: str, *, ok_accounts: int, fail_accounts: int,
               shares: float, elapsed: float) -> None:
    if not run_id:
        return
    with _lock:
        data = _load()
        run = _find(data, run_id)
        if run is None:
            return
        run["finished_at"] = _now()
        run["ok_accounts"] = int(ok_accounts)
        run["fail_accounts"] = int(fail_accounts)
        run["shares"] = float(shares)
        run["elapsed"] = float(elapsed)
        _save(data)
        _bump()


# --------------------------------------------------------------------- reading

def runs(limit: int = 0) -> List[Dict[str, Any]]:
    """Runs newest first."""
    with _lock:
        rows = list(reversed(_load()["runs"]))
    return rows[:limit] if limit else rows


def scans(limit: int = 0) -> List[Dict[str, Any]]:
    with _lock:
        rows = list(reversed(_load()["scans"]))
    return rows[:limit] if limit else rows


def run_outcome(run: Dict[str, Any]) -> str:
    """'filled' | 'partial' | 'failed' | 'running'. What the badge shows."""
    if not run.get("finished_at"):
        return "running"
    ok = int(run.get("ok_accounts") or 0)
    fail = int(run.get("fail_accounts") or 0)
    if ok and not fail:
        return "filled"
    if ok:
        return "partial"
    return "failed"


def summary(days: int = 7) -> Dict[str, Any]:
    """Headline numbers over a trailing window, for the KPI tiles.

    `fill_rate` is accounts filled over accounts attempted — not runs over runs.
    A run that reaches six accounts and fills five is 83% here and would be a
    flat 0 under a per-run measure, and the account number is the one that maps
    to money.
    """
    with _lock:
        data = _load()
        data = {"runs": list(data["runs"]), "scans": list(data["scans"])}
    floor = ""
    if days:
        try:
            from datetime import timedelta
            floor = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
        except Exception:
            floor = ""

    picked = [r for r in data["runs"] if not floor or (r.get("started_at") or "") >= floor]
    ok = sum(int(r.get("ok_accounts") or 0) for r in picked)
    fail = sum(int(r.get("fail_accounts") or 0) for r in picked)
    attempted = ok + fail
    scanned = [s for s in data["scans"] if not floor or (s.get("at") or "") >= floor]

    return {
        "days": days,
        "runs": len(picked),
        "symbols": len({r.get("symbol") for r in picked}),
        "ok_accounts": ok,
        "fail_accounts": fail,
        "attempted": attempted,
        "fill_rate": (ok / attempted) if attempted else 0.0,
        "shares": sum(float(r.get("shares") or 0.0) for r in picked),
        "scans": len(scanned),
        "skipped": sum(len(s.get("skipped") or []) for s in scanned),
        "nowhere": [r for r in picked if run_outcome(r) == "failed"],
        "last_run": picked[-1] if picked else None,
        "last_scan": scanned[-1] if scanned else None,
    }


def csv_rows() -> List[List[str]]:
    """Flat account-level export: one row per account per broker per run."""
    out: List[List[str]] = [[
        "run_started", "symbol", "side", "qty", "trigger", "slot", "dry_run",
        "broker", "account_id", "result", "message", "fill_price",
    ]]
    for run in runs():
        for leg in run.get("legs") or []:
            for acct in leg.get("accounts") or []:
                out.append([
                    run.get("started_at", ""), run.get("symbol", ""),
                    run.get("side", ""), str(run.get("qty", "")),
                    run.get("trigger", ""), run.get("slot", ""),
                    "yes" if run.get("dry_run") else "no",
                    leg.get("broker", ""), acct.get("account_id", ""),
                    "filled" if acct.get("ok") else "rejected",
                    (acct.get("message") or "").replace("\n", " "),
                    "" if leg.get("fill_price") is None else str(leg.get("fill_price")),
                ])
            if not (leg.get("accounts") or []):
                # A broker that blew up before reporting any account still
                # belongs in the export — that failure is the interesting one.
                out.append([
                    run.get("started_at", ""), run.get("symbol", ""),
                    run.get("side", ""), str(run.get("qty", "")),
                    run.get("trigger", ""), run.get("slot", ""),
                    "yes" if run.get("dry_run") else "no",
                    leg.get("broker", ""), "", leg.get("state", "error"),
                    ((leg.get("errors") or [""])[0]).replace("\n", " "), "",
                ])
    return out
