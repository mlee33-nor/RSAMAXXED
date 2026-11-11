"""Evidence log: what Public's API actually told this tool, kept so it can be shown later.

WHY THIS EXISTS
---------------
Public's reverse-split fee disclosure says that "at the point of purchase, we
will let you know if your stock may be subject to the fee and the amount of
the fee." Some users see that notice in Public's mobile app. This tool buys
through Public's API, and if Public ever claws a fee back the question becomes
"what were you told when you bought?" This file is the answer: for every
Public order the tool sends it records, verbatim,

  * the preflight request and Public's full response (estimatedCommission,
    regulatoryFees, and any other field Public returned -- a notice included,
    if there ever is one),
  * the order request and Public's response,
  * Public's own server timestamp (the HTTP Date header) for each,
  * every trade/fee transaction Public's account history later shows.

TAMPER-EVIDENT, NOT TAMPER-PROOF
--------------------------------
Records go to evidence/public_evidence.jsonl, one JSON object per line, and
each one carries the SHA-256 of the record before it ("prev") and of itself
("hash"). Editing, deleting or reordering any line breaks every hash after it,
which verify() finds. What the chain cannot stop is someone rewriting the
WHOLE file from scratch, so the head hash is worth copying somewhere outside
this machine now and then (an email to yourself is enough): a head hash dated
in someone else's system fixes everything up to it.

Never raises into the trading path. Account numbers are kept to the last 4
digits; Public's orderId (a UUID) is what ties a record to Public's own books.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = ROOT_DIR / "evidence"
EVIDENCE_FILE = EVIDENCE_DIR / "public_evidence.jsonl"
GENESIS = "0" * 64

_lock = threading.RLock()
# Hash of the last record, and history transaction ids already recorded.
_head: Optional[str] = None
_seq: Optional[int] = None
_tx_seen: Optional[set] = None


def _canon(rec: Dict[str, Any]) -> bytes:
    # ASCII-only: a lone surrogate in a response body cannot fail the encode,
    # and the bytes hashed are exactly the bytes written.
    return json.dumps(rec, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _hash_of(rec: Dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(_canon(body)).hexdigest()


def _load_tail() -> None:
    """Head hash, next seq and recorded tx ids, read once from the file."""
    global _head, _seq, _tx_seen
    if _head is not None:
        return
    head, seq, seen = GENESIS, 0, set()
    try:
        with open(EVIDENCE_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                head = str(rec.get("hash") or head)
                seq = int(rec.get("seq") or seq) + 1
                if rec.get("kind") == "history_tx" and rec.get("tx_id"):
                    seen.add(str(rec["tx_id"]))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    _head, _seq, _tx_seen = head, seq, seen


def record(kind: str, **data: Any) -> Optional[str]:
    """Append one record; returns its hash (None if it could not be written)."""
    global _head, _seq
    try:
        with _lock:
            _load_tail()
            now = datetime.now(timezone.utc)
            rec: Dict[str, Any] = {
                "seq": _seq,
                "kind": kind,
                "recorded_utc": now.isoformat(timespec="milliseconds"),
                "recorded_local": datetime.now().isoformat(timespec="seconds"),
                **data,
                "prev": _head,
            }
            rec["hash"] = _hash_of(rec)
            line = _canon(rec) + b"\n"
            EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
            with open(EVIDENCE_FILE, "ab") as fh:
                size = fh.tell()
                try:
                    fh.write(line)
                    fh.flush()
                except Exception:
                    # Never leave half a line behind: it would break the
                    # chain for every record after it.
                    try:
                        fh.truncate(size)
                    except Exception:
                        pass
                    raise
            _head, _seq = rec["hash"], _seq + 1
            return rec["hash"]
    except Exception:
        return None


def record_http(kind: str, *, account: str, request: Any, response: Any = None,
                error: Optional[str] = None, **extra: Any) -> Optional[str]:
    """Record one Public API exchange. `response` is a requests.Response."""
    resp: Dict[str, Any] = {}
    if response is not None:
        try:
            resp["status"] = response.status_code
            h = response.headers or {}
            # Public's own clock, and whatever request id it hands back.
            resp["server_date"] = h.get("Date")
            resp["headers"] = {k: v for k, v in h.items()
                               if k.lower() in ("date", "x-request-id", "x-amzn-requestid",
                                                "x-amz-cf-id", "cf-ray", "x-correlation-id",
                                                "content-type")}
            try:
                resp["body"] = response.json()
            except Exception:
                resp["body_text"] = (response.text or "")[:4000]
        except Exception as e:
            resp["read_error"] = str(e)
    try:
        import public_fees
        resp = public_fees.redact(resp)
        request = public_fees.redact(request)
    except Exception:
        pass
    return record(kind, account=account, request=request, response=resp,
                  error=error, **extra)


def record_history(account: str, txs: Iterable[Dict[str, Any]]) -> int:
    """Record each trade/fee transaction from Public's history once, with
    account numbers cut to the last 4."""
    n = 0
    try:
        import public_fees
        redact = public_fees.redact
    except Exception:
        return 0            # never write an unredacted transaction
    try:
        with _lock:         # check-and-record as one step: two scans, one record
            _load_tail()
            seen = _tx_seen
            for tx in txs:
                if not isinstance(tx, dict):
                    continue
                kind = " ".join(str(tx.get(k) or "") for k in ("type", "subType")).upper()
                if not any(w in kind for w in ("TRADE", "FEE", "COMMISSION", "ADJUST",
                                               "CORPORATE")) and not tx.get("fees"):
                    continue
                tid = str(tx.get("id") or "") or "|".join(
                    str(tx.get(k) or "") for k in ("timestamp", "type", "symbol", "netAmount"))
                key = f"{account}|{tid}"
                if key in seen:
                    continue
                if record("history_tx", account=account, tx_id=key, tx=redact(tx)):
                    seen.add(key)
                    n += 1
    except Exception:
        pass
    return n


# ---------------------------------------------------------------------------
# Reading it back
# ---------------------------------------------------------------------------

def read_all() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(EVIDENCE_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        out.append({"_unparseable": line[:200]})
    except FileNotFoundError:
        pass
    return out


def verify(records: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Walk the chain. {"ok", "count", "head", "bad_seq", "why"}."""
    recs = read_all() if records is None else records
    prev = GENESIS
    for i, rec in enumerate(recs):
        if "_unparseable" in rec:
            return {"ok": False, "count": len(recs), "head": prev, "bad_seq": i,
                    "why": "a line is not valid JSON"}
        if rec.get("prev") != prev:
            return {"ok": False, "count": len(recs), "head": prev,
                    "bad_seq": rec.get("seq", i),
                    "why": "link to the previous record is broken (a line was "
                           "removed, inserted or reordered)"}
        if _hash_of(rec) != rec.get("hash"):
            return {"ok": False, "count": len(recs), "head": prev,
                    "bad_seq": rec.get("seq", i), "why": "record was edited"}
        prev = rec["hash"]
    return {"ok": True, "count": len(recs), "head": prev, "bad_seq": None, "why": ""}


def _body(r: Dict[str, Any]) -> Dict[str, Any]:
    body = ((r.get("response") or {}).get("body")) or {}
    return body if isinstance(body, dict) else {}


def _notices_of(r: Dict[str, Any]) -> List[str]:
    """Notice-like fields in a recorded preflight response (see public_fees)."""
    try:
        import public_fees
        return public_fees.preflight_check(_body(r)).get("notices") or []
    except Exception:
        return []


def summary(limit: int = 25) -> Dict[str, Any]:
    """What the MONITOR page shows."""
    recs = read_all()
    chk = verify(recs)
    pre = [r for r in recs if r.get("kind") == "preflight"]
    orders = [r for r in recs if r.get("kind") == "order"]

    def _fees(r):
        body = _body(r)
        reg = body.get("regulatoryFees") or {}
        return body.get("estimatedCommission"), reg if isinstance(reg, dict) else {}

    for r in pre:
        r["notices"] = _notices_of(r)

    rows = []
    for r in pre[-limit:][::-1]:
        comm, reg = _fees(r)
        rq = r.get("request") or {}
        rows.append({
            "time": r.get("recorded_local"), "server_date": (r.get("response") or {}).get("server_date"),
            "side": rq.get("orderSide"), "symbol": (rq.get("instrument") or {}).get("symbol"),
            "qty": rq.get("quantity"), "account": r.get("account"),
            "commission": comm, "reg": {k: v for k, v in reg.items() if v not in (None, "0", "0.00")},
            "notices": r.get("notices") or [], "status": (r.get("response") or {}).get("status"),
            "error": r.get("error"),
        })
    buys_pre = [r for r in pre if (r.get("request") or {}).get("orderSide") == "BUY"]
    buys_with_fee = [r for r in buys_pre
                     if str(_fees(r)[0] or "0").strip() not in ("0", "0.00", "0.0", "", "None")
                     or r.get("notices")]
    return {
        "chain": chk, "records": len(recs), "preflights": len(pre),
        "buy_preflights": len(buys_pre), "buy_preflights_flagged": len(buys_with_fee),
        "orders": len(orders),
        "history_txs": sum(1 for r in recs if r.get("kind") == "history_tx"),
        "recent": rows, "first": recs[0].get("recorded_local") if recs else None,
        "last": recs[-1].get("recorded_local") if recs else None,
    }


_VERIFY_SCRIPT = '''"""Check public_evidence.jsonl: python verify_evidence.py public_evidence.jsonl
Each line's "hash" is SHA-256 over the record without "hash" (keys sorted,
separators "," and ":", UTF-8); "prev" is the previous line's hash (64 zeros
for the first). Any edit, deletion, insertion or reordering breaks the chain."""
import hashlib, json, sys
prev = "0" * 64
for n, line in enumerate(open(sys.argv[1], encoding="utf-8"), 1):
    rec = json.loads(line)
    body = {k: v for k, v in rec.items() if k != "hash"}
    h = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True, default=str).encode("utf-8")).hexdigest()
    if rec.get("prev") != prev or h != rec.get("hash"):
        sys.exit(f"BROKEN at line {n}")
    prev = h
print(f"OK: {n} records, head {prev}")
'''


def export(dest_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    """Write an evidence pack folder: the raw log, a verifier, a CSV of every
    preflight and order, and a README with the head hash. Returns (folder, verify)."""
    dest_dir = Path(dest_dir)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = dest_dir / f"public_evidence_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    recs = read_all()
    chk = verify(recs)
    if EVIDENCE_FILE.exists():
        shutil.copy2(EVIDENCE_FILE, out / "public_evidence.jsonl")
    (out / "verify_evidence.py").write_text(_VERIFY_SCRIPT, encoding="utf-8")
    import csv
    with open(out / "orders_and_preflights.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["seq", "recorded_local", "public_server_date", "kind", "account",
                    "side", "symbol", "qty", "order_id", "http_status",
                    "estimatedCommission", "regulatoryFees", "notices", "error", "hash"])
        for r in recs:
            if r.get("kind") not in ("preflight", "order"):
                continue
            rq = r.get("request") or {}
            rs = r.get("response") or {}
            body = rs.get("body") if isinstance(rs.get("body"), dict) else {}
            w.writerow([r.get("seq"), r.get("recorded_local"), rs.get("server_date"),
                        r.get("kind"), r.get("account"), rq.get("orderSide"),
                        (rq.get("instrument") or {}).get("symbol"), rq.get("quantity"),
                        rq.get("orderId") or body.get("orderId"), rs.get("status"),
                        body.get("estimatedCommission"),
                        json.dumps(body.get("regulatoryFees"), default=str),
                        "; ".join(_notices_of(r)), r.get("error"), r.get("hash")])
    (out / "README.txt").write_text(
        "Public API evidence pack, exported by RSAMAXXED\n"
        f"Exported: {datetime.now().isoformat(timespec='seconds')}\n"
        f"Records: {chk['count']}   Chain intact: {'YES' if chk['ok'] else 'NO - ' + chk['why']}\n"
        f"Head hash: {chk['head']}\n\n"
        "public_evidence.jsonl  every Public API preflight, order and history\n"
        "                       transaction this tool saw, verbatim, with Public's\n"
        "                       own server Date header for each API call.\n"
        "orders_and_preflights.csv  the same preflights and orders as a table.\n"
        "verify_evidence.py     run it on the .jsonl to confirm no line was\n"
        "                       edited, removed or reordered.\n\n"
        "A preflight is Public's own cost estimate for an order, requested\n"
        "immediately before that order was sent. estimatedCommission and any\n"
        "notice field are what Public's API disclosed at the point of purchase.\n",
        encoding="utf-8")
    record("export", folder=str(out.name), head=chk["head"], count=chk["count"])
    return out, chk
