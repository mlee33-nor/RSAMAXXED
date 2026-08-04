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
nothing here needs Discord, a subscription, or the network.

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

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_FILE = Path(__file__).resolve().parent / "mirror_runs.json"
_lock = threading.RLock()

# Enough history to answer "what happened last month" without letting a file the
# UI reads on every page visit grow without bound.
MAX_RUNS = 400
MAX_SCANS = 400


# --------------------------------------------------------------------- storage

def _empty() -> Dict[str, Any]:
    return {"version": 1, "runs": [], "scans": []}


def _load() -> Dict[str, Any]:
    """Never raises. A corrupt journal costs history, not the automation."""
    if not _FILE.exists():
        return _empty()
    try:
        data = json.loads(_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return _empty()
    if not isinstance(data, dict):
        return _empty()
    data.setdefault("version", 1)
    for key in ("runs", "scans"):
        if not isinstance(data.get(key), list):
            data[key] = []
    return data


def _save(data: Dict[str, Any]) -> None:
    data["runs"] = data["runs"][-MAX_RUNS:]
    data["scans"] = data["scans"][-MAX_SCANS:]
    try:
        _FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass          # a read-only disk must not take the trade down with it


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def load() -> Dict[str, Any]:
    """The whole journal, newest last. Callers must not mutate the result."""
    with _lock:
        return _load()


def version() -> tuple:
    """Cheap fingerprint for the page-render cache — mtime and size, no parse."""
    try:
        st = _FILE.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


def clear() -> None:
    with _lock:
        _save(_empty())


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


# --------------------------------------------------------------------- reading

def runs(limit: int = 0) -> List[Dict[str, Any]]:
    """Runs newest first."""
    rows = list(reversed(load()["runs"]))
    return rows[:limit] if limit else rows


def scans(limit: int = 0) -> List[Dict[str, Any]]:
    rows = list(reversed(load()["scans"]))
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
    data = load()
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
