# modules/brokers/schwab/schwab.py
from __future__ import annotations

import json
import os
import random
import sys
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow
from modules.brokers.schwab.schwab_normalizer import normalize as schwab_normalize

try:
    from modules import broker_logging as BLOG
except Exception:  # pragma: no cover
    BLOG = None  # type: ignore

BROKER = "schwab"

# one session per credential entry
# {
#   "idx": int,
#   "label": str,
#   "client": Schwab,
#   "cache_path": Path,
#   "username": str,
#   "password": str,
#   "totp": Optional[str],
# }
_SESSIONS: List[Dict[str, Any]] = []


# =============================================================================
# Safe discovery helpers (positions extras)
# =============================================================================

_DENY_KEY_SUBSTRS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "authorization",
    "bearer",
    "session",
    "ssn",
    "socialsecurity",
    "taxid",
    "ein",
    "routing",
    "iban",
    "swift",
    # account identifiers
    "accountid",
    "account_id",
    "accountnumber",
    "account_number",
    "acctid",
    "acct_id",
    "acctnumber",
    "acct_number",
    "schwab-client-account",
    "schwab-client-ids",
)

def _is_safe_scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))

def _key_allowed(k: str) -> bool:
    kl = (k or "").strip().lower().replace(" ", "").replace("-", "")
    if not kl:
        return False
    return not any(bad.replace("-", "") in kl for bad in _DENY_KEY_SUBSTRS)

def _flatten_safe(obj: Any, *, prefix: str = "", max_items: int = 120) -> Dict[str, Any]:
    """
    Flatten one level of dict -> safe scalars only.
    - Includes scalar values
    - Includes one-level nested dict scalars as key_subkey
    - Skips lists and deep nesting
    - Applies denylist to keys
    """
    out: Dict[str, Any] = {}
    if not isinstance(obj, dict):
        return out

    n = 0
    for k, v in obj.items():
        if n >= max_items:
            break
        if not isinstance(k, str):
            continue
        if not _key_allowed(k):
            continue

        key = f"{prefix}{k}" if prefix else k

        if _is_safe_scalar(v):
            if isinstance(v, str) and len(v) > 200:
                out[key] = v[:200] + "…"
            else:
                out[key] = v
            n += 1
            continue

        if isinstance(v, dict):
            for kk, vv in v.items():
                if n >= max_items:
                    break
                if not isinstance(kk, str):
                    continue
                if not _key_allowed(kk):
                    continue
                if _is_safe_scalar(vv):
                    if isinstance(vv, str) and len(vv) > 200:
                        out[f"{key}_{kk}"] = vv[:200] + "…"
                    else:
                        out[f"{key}_{kk}"] = vv
                    n += 1

    return out


# =============================================================================
# Helpers
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _debug() -> bool:
    return (_env("SCHWAB_DEBUG") or "false").lower().strip() in ("1", "true", "yes", "on")


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _vendor_schwab_api_root() -> Path:
    return _root_dir() / "SETUP" / "vendors" / "schwab-api"


def _sessions_dir() -> Path:
    d = _root_dir() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _logs_root() -> Path:
    d = _root_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _log_ctx() -> dict:
    return {"log_dir": _logs_root(), "debug": _debug()}


def _dump_schwab_payload(tag: str, text: str, *, label: str = "") -> None:
    """
    Write raw Schwab payloads using broker_logging contract:
      logs/<broker>/<mm.dd.yy>/<tag>_<label>_<HHMMSS>.log
    """
    if not _debug():
        return
    if BLOG is None:
        return
    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="positions_dump",
            label=label,
            filename_prefix=tag,
            text=text[:200000],
            secrets=None,
        )
    except Exception:
        pass


def _mask_last4(s: str) -> str:
    s = (s or "").strip()
    return f"****{s[-4:]}" if len(s) >= 4 else "****"


def _selected_account_id() -> str:
    return _env("SCHWAB_ACCOUNT_ID")


def _purchase_accounts_filter() -> List[str]:
    raw = _env("SCHWAB_ACCOUNT_NUMBERS")
    return [p.strip() for p in raw.split(":") if p.strip()]


def _parse_accounts_from_env() -> List[Tuple[str, str, Optional[str]]]:
    """
    Legacy-compatible parsing:
      - SCHWAB="user:pass:totp,user2:pass2:totp2"
      - totp may be "NA"
    Fallback:
      - SCHWAB_USERNAME / SCHWAB_PASSWORD / SCHWAB_TOTP_SECRET
    """
    blob = _env("SCHWAB")
    out: List[Tuple[str, str, Optional[str]]] = []

    if blob:
        parts = [p.strip() for p in blob.split(",") if p.strip()]
        for p in parts:
            seg = p.split(":")
            if len(seg) < 2:
                continue
            u = seg[0].strip()
            pw = seg[1].strip()
            totp = seg[2].strip() if len(seg) > 2 else ""
            totp_norm = None if (not totp or totp.upper() == "NA") else totp
            if u and pw:
                out.append((u, pw, totp_norm))
        return out

    u = _env("SCHWAB_USERNAME")
    pw = _env("SCHWAB_PASSWORD")
    totp = _env("SCHWAB_TOTP_SECRET")
    totp_norm = None if (not totp or totp.upper() == "NA") else totp
    if u and pw:
        out.append((u, pw, totp_norm))
    return out


def _session_cache_path(idx_1based: int) -> Path:
    """
    Back-compat + stable convention:
      - Prefer schwab1.json / schwab2.json / ...
      - If sessions/schwab.json exists and schwab1.json doesn't, use schwab.json for idx=1
    """
    d = _sessions_dir()
    if idx_1based == 1:
        p_new = d / "schwab1.json"
        p_old = d / "schwab.json"
        if p_new.exists():
            return p_new
        if p_old.exists():
            return p_old
        return p_new
    return d / f"schwab{idx_1based}.json"


def _to_float(x: Any) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _looks_stale_account_info(info: Any) -> bool:
    if not isinstance(info, dict) or not info:
        return True

    any_positions = False
    any_positive = False
    any_value_field = False

    for _acc_id, payload in info.items():
        if not isinstance(payload, dict):
            continue

        for k in ("account_value", "market_value", "cash_investments", "cost"):
            v = _to_float(payload.get(k))
            if v is not None:
                any_value_field = True
                if v > 0:
                    any_positive = True

        pos = payload.get("positions") or []
        if isinstance(pos, list) and len(pos) > 0:
            any_positions = True

    if any_positions or any_positive:
        return False

    return True if any_value_field else True


def _load_schwab_class():
    try:
        from schwab_api import Schwab  # type: ignore
        return Schwab
    except Exception as e:
        first_err = e

    vendor_root = _vendor_schwab_api_root()
    if vendor_root.exists():
        p = str(vendor_root)
        if p not in sys.path:
            sys.path.insert(0, p)
        try:
            from schwab_api import Schwab  # type: ignore
            return Schwab
        except Exception as e2:
            raise RuntimeError(
                f"Missing dependency schwab_api: {first_err}; vendor import failed from {vendor_root}: {e2}"
            ) from e2

    raise RuntimeError(f"Missing dependency schwab_api: {first_err}; vendor path not found: {vendor_root}")


def _build_sessions() -> List[Dict[str, Any]]:
    global _SESSIONS

    accts = _parse_accounts_from_env()
    if not accts:
        _SESSIONS = []
        return _SESSIONS

    if _SESSIONS and len(_SESSIONS) == len(accts):
        return _SESSIONS

    Schwab = _load_schwab_class()
    debug = _debug()

    out: List[Dict[str, Any]] = []
    for i, (u, pw, totp) in enumerate(accts, start=1):
        label = f"Schwab {i}" if len(accts) > 1 else "Schwab"
        cache_path = _session_cache_path(i)
        client = Schwab(session_cache=str(cache_path), debug=debug)
        out.append(
            {
                "idx": i,
                "label": label,
                "client": client,
                "cache_path": cache_path,
                "username": u,
                "password": pw,
                "totp": totp,
            }
        )

    _SESSIONS = out
    return _SESSIONS


def _reset_account_scoping_headers(client: Any) -> None:
    """
    Some vendor flows can leave account-scoping headers behind after trades.
    If present, holdings endpoints may return only one account (or nothing).
    """
    try:
        h = getattr(client, "headers", None)
        if not isinstance(h, dict):
            return
        for key in (
            "schwab-client-account",
            "Schwab-Client-Ids",
            "schwab-client-ids",
            "Schwab-Client-IDs",
            "schwab-client-id",
        ):
            h.pop(key, None)
    except Exception:
        return


def _warm_client_center_cookies(client: Any) -> None:
    """
    Best-effort for legacy PositionsDataV2 (Client Center cookies).
    """
    try:
        sess = getattr(client, "session", None)
        if sess is None:
            return
        sess.get("https://client.schwab.com/clientapps/accounts/summary/", timeout=30)
    except Exception:
        return


def _refresh_token_soft(client: Any) -> bool:
    """
    Cheap "stay alive" call. This is what your old router effectively did.
    """
    try:
        client.update_token(token_type="api", login=False)
        return True
    except Exception:
        return False


def _login_one(sess: Dict[str, Any]) -> None:
    c = sess["client"]
    totp = sess.get("totp")

    if not totp:
        ok = c.login(
            username=sess["username"],
            password=sess["password"],
            totp_secret="",
            lazy=True,
        )
        if not ok:
            raise RuntimeError("Schwab login requires SCHWAB_TOTP_SECRET (or a valid cached session).")
        _refresh_token_soft(c)
        return

    c.login(
        username=sess["username"],
        password=sess["password"],
        totp_secret=totp,
    )
    _refresh_token_soft(c)


def _probe_account_info_v2(client: Any) -> Optional[dict]:
    """
    Robust holdings parser (Schwab now requires an account scope).

    We do NOT attempt "all accounts" because the holdings endpoint returns:
      400 "Account number is required."

    Instead:
      - discover account ids WITHOUT calling holdings (no recursion)
      - fetch holdings per account using schwab-client-account / schwab-client-ids
      - merge results into the legacy-friendly dict keyed by int(account_id)
    """
    try:
        from schwab_api import urls as schwab_urls  # type: ignore
    except Exception:
        return None

    # Ensure bearer token is fresh, but don't force browser login here
    try:
        client.update_token(token_type="api", login=False)
    except Exception:
        return None

    # Build a clean header set for holdings (avoid contamination from other calls)
    base_headers = dict(getattr(client, "headers", {}) or {})
    base_headers.setdefault("accept", "application/json")

    # Holdings generally expects resource-version 1.0; other endpoints (orders) set 2.0 and can poison this.
    base_headers["schwab-resource-version"] = "1.0"

    def _num(v: Any, default: float = 0.0) -> float:
        if v is None:
            return default
        if isinstance(v, dict):
            for kk in ("val", "value", "qty", "cstBasis", "amt"):
                if kk in v:
                    return _num(v.get(kk), default=default)
            for vv in v.values():
                if isinstance(vv, (int, float, str)):
                    return _num(vv, default=default)
            return default
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            s = v.strip().replace(",", "").replace("$", "")
            if s in ("", "-", "—"):
                return default
            try:
                return float(s)
            except Exception:
                return default
        return default

    def _text(v: Any) -> str:
        if v is None:
            return ""
        if isinstance(v, str):
            return v.strip()
        if isinstance(v, (int, float, bool)):
            return str(v).strip()
        if isinstance(v, dict):
            for kk in ("description", "desc", "name", "text", "value", "val", "label", "symbol", "ticker"):
                vv = v.get(kk)
                if isinstance(vv, (str, int, float, bool)):
                    return str(vv).strip()
            for vv in v.values():
                if isinstance(vv, (str, int, float, bool)):
                    return str(vv).strip()
            return ""
        return str(v).strip()

    def _sym(row: dict) -> Tuple[Optional[str], Optional[Any]]:
        s = row.get("symbol") or row.get("Symbol") or row.get("DefaultSymbol")
        if isinstance(s, dict):
            sym = _text(s.get("symbol") or s.get("Symbol") or s.get("ticker") or s.get("name"))
            sid = s.get("ssId") or s.get("securityId") or s.get("itemIssueId")
            return (sym.upper() if sym else None, sid)
        if isinstance(s, str):
            sym = _text(s)
            sid = row.get("ssId") or row.get("securityId") or row.get("ItemIssueId") or row.get("itemIssueId")
            return (sym.upper() if sym else None, sid)
        return (None, None)

    def _parse(payload: Any) -> Dict[int, dict]:
        if not isinstance(payload, dict):
            return {}

        accounts = payload.get("accounts") or payload.get("Accounts") or payload.get("account") or payload.get("Account") or []
        if isinstance(accounts, dict):
            accounts = [accounts]
        if not isinstance(accounts, list):
            return {}

        out: Dict[int, dict] = {}

        for acc in accounts:
            if not isinstance(acc, dict):
                continue

            acc_id = acc.get("accountId") or acc.get("AccountId") or acc.get("accountID") or acc.get("accountNumber")
            if not acc_id:
                continue

            try:
                acc_id_int = int(str(acc_id).replace("-", ""))
            except Exception:
                try:
                    acc_id_int = int(acc_id)
                except Exception:
                    continue

            totals = acc.get("totals") or acc.get("Totals") or {}
            mv = _num(totals.get("marketValue") or totals.get("MarketValue"), 0.0)
            cash = _num(totals.get("cashInvestments") or totals.get("CashInvestments"), 0.0)
            av = _num(totals.get("accountValue") or totals.get("AccountValue"), 0.0)
            cost = _num(totals.get("costBasis") or totals.get("Cost") or totals.get("cost"), 0.0)

            positions: List[dict] = []

            grouped = acc.get("groupedPositions") or acc.get("SecurityGroupings") or []
            if isinstance(grouped, dict):
                grouped = [grouped]

            for grp in grouped if isinstance(grouped, list) else []:
                if not isinstance(grp, dict):
                    continue
                gname = _text(grp.get("groupName") or grp.get("GroupName")).lower()
                if gname == "cash":
                    continue

                rows = grp.get("holdingsRows") or grp.get("Positions") or []
                if isinstance(rows, dict):
                    rows = [rows]

                for row in rows if isinstance(rows, list) else []:
                    if not isinstance(row, dict):
                        continue

                    sym, sid = _sym(row)
                    if not sym:
                        continue

                    desc = _text(row.get("description") or row.get("Description"))
                    qty = _num(
                        (row.get("qty") or {}).get("qty") if isinstance(row.get("qty"), dict) else row.get("qty") or row.get("Quantity"),
                        0.0,
                    )
                    if qty == 0:
                        continue

                    cb = _num(
                        (row.get("costBasis") or {}).get("cstBasis") if isinstance(row.get("costBasis"), dict) else row.get("costBasis") or row.get("Cost"),
                        0.0,
                    )
                    mv_row = _num(
                        (row.get("marketValue") or {}).get("val") if isinstance(row.get("marketValue"), dict) else row.get("marketValue") or row.get("MarketValue"),
                        0.0,
                    )

                    positions.append(
                        {
                            "symbol": sym,
                            "description": desc,
                            "quantity": float(qty),
                            "cost": float(cb),
                            "market_value": float(mv_row),
                            "security_id": sid,
                            # keep one raw-ish row for discovery only (safe flatten later)
                            "_raw_row": row,
                        }
                    )

            out[acc_id_int] = {
                "account_id": str(acc_id),
                "positions": positions,
                "market_value": mv,
                "cash_investments": cash,
                "account_value": av,
                "cost": cost,
                # for discovery (safe flatten later)
                "_raw_account": acc,
                "_raw_totals": totals,
            }

        return out

    def _discover_ids_no_holdings() -> List[str]:
        selected = _selected_account_id().strip()
        if selected:
            return [selected]

        purchase_accounts = _purchase_accounts_filter()
        if purchase_accounts:
            return purchase_accounts

        fn = getattr(client, "get_account_numbers", None)
        if callable(fn):
            try:
                data = fn()
                ids: List[str] = []

                if isinstance(data, dict):
                    if "accounts" in data and isinstance(data["accounts"], list):
                        for item in data["accounts"]:
                            if isinstance(item, dict):
                                v = item.get("accountId") or item.get("account_id") or item.get("accountNumber") or item.get("account_number")
                                if v:
                                    ids.append(str(v))
                    else:
                        for k in data.keys():
                            if k:
                                ids.append(str(k))

                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            v = item.get("accountId") or item.get("account_id") or item.get("accountNumber") or item.get("account_number")
                            if v:
                                ids.append(str(v))
                        elif item:
                            ids.append(str(item))

                seen = set()
                out: List[str] = []
                for x in ids:
                    if x not in seen:
                        seen.add(x)
                        out.append(x)
                return out
            except Exception:
                return []

        return []

    ids = _discover_ids_no_holdings()
    if not ids:
        _dump_schwab_payload("holdings_v2_no_accounts", "No account ids discovered for holdings.", label="all")
        return None

    merged: Dict[int, dict] = {}

    for acc_id in ids:
        scoped = dict(base_headers)
        scoped["schwab-client-account"] = str(acc_id)
        scoped["schwab-client-ids"] = str(acc_id)

        rr = requests.get(schwab_urls.positions_v2(), headers=scoped, timeout=30)
        if rr.status_code != 200:
            _dump_schwab_payload(
                f"holdings_v2_http_{rr.status_code}",
                rr.text,
                label=str(acc_id),
            )
            continue

        try:
            pp = json.loads(rr.text)
        except json.JSONDecodeError:
            _dump_schwab_payload(
                "holdings_v2_nonjson",
                rr.text,
                label=str(acc_id),
            )
            continue
        except Exception:
            continue

        parsed = _parse(pp)
        if _debug() and not parsed:
            _dump_schwab_payload(
                "holdings_v2_empty_scoped",
                json.dumps(pp, ensure_ascii=False, indent=2),
                label=str(acc_id),
            )
            continue

        merged.update(parsed)

    return merged or None


def _probe_account_info_legacy(client: Any) -> Optional[dict]:
    fn = getattr(client, "get_account_info", None)
    if not callable(fn):
        return None

    _reset_account_scoping_headers(client)
    _warm_client_center_cookies(client)

    try:
        info = fn()
        return info if isinstance(info, dict) else None
    except json.JSONDecodeError:
        return None
    except Exception:
        return None


def _ensure_authed(sess: Dict[str, Any]) -> Dict[str, Any]:
    """
    Auth + positions fetch:
      - soft refresh token first
      - v2 holdings first (preferred)
      - legacy second (fallback)
      - force login once, then retry
    """
    ctx = _log_ctx()
    idx = int(sess.get("idx") or 0) or 0
    label = f"schwab_{idx}" if idx else "schwab"
    c = sess["client"]

    def _log_exc(action: str, e: BaseException) -> None:
        if BLOG is None:
            return
        try:
            BLOG.log_exception(ctx, broker=BROKER, action=action, label=label, exc=e, secrets=None)
        except Exception:
            pass

    # 0) soft refresh (do not fail the flow if this errors)
    try:
        _refresh_token_soft(c)
    except Exception:
        pass

    # 1) v2 probe
    try:
        info_v2 = _probe_account_info_v2(c)
        if info_v2 is not None and not _looks_stale_account_info(info_v2):
            return info_v2
    except Exception as e:
        _log_exc("positions_v2", e)

    # 2) legacy probe
    try:
        info_leg = _probe_account_info_legacy(c)
        if info_leg is not None and not _looks_stale_account_info(info_leg):
            return info_leg
    except Exception as e:
        _log_exc("positions_legacy", e)

    # 3) force login once
    try:
        _login_one(sess)
    except Exception as e:
        if BLOG is not None:
            try:
                BLOG.log_exception(
                    ctx,
                    broker=BROKER,
                    action="login",
                    label=label,
                    exc=e,
                    secrets=[sess.get("username"), sess.get("password"), sess.get("totp")],
                )
            except Exception:
                pass
        raise

    # 4) retry v2
    try:
        info_v2b = _probe_account_info_v2(c)
        if info_v2b is not None and not _looks_stale_account_info(info_v2b):
            return info_v2b
    except Exception as e:
        _log_exc("positions_v2", e)

    # 5) retry legacy
    try:
        info_legb = _probe_account_info_legacy(c)
        if info_legb is not None and not _looks_stale_account_info(info_legb):
            return info_legb
    except Exception as e:
        _log_exc("positions_legacy", e)

    return {}


def _discover_account_ids_for_trade(client: Any) -> List[str]:
    """
    Trade must not depend on positions.
    Priority:
      1) SCHWAB_ACCOUNT_ID (single)
      2) SCHWAB_ACCOUNT_NUMBERS (list)
      3) client.get_account_numbers()
      4) account_info keys (best-effort)
    """
    selected = _selected_account_id().strip()
    if selected:
        return [selected]

    purchase_accounts = _purchase_accounts_filter()
    if purchase_accounts:
        return purchase_accounts

    fn = getattr(client, "get_account_numbers", None)
    if callable(fn):
        try:
            data = fn()
            ids: List[str] = []

            # handle common shapes
            if isinstance(data, dict):
                # maybe {"accounts":[{"accountId":"..."}]} or {"1234":"hash"}
                if "accounts" in data and isinstance(data["accounts"], list):
                    for item in data["accounts"]:
                        if isinstance(item, dict):
                            v = item.get("accountId") or item.get("account_id") or item.get("accountNumber") or item.get("account_number")
                            if v:
                                ids.append(str(v))
                else:
                    for k in data.keys():
                        if k:
                            ids.append(str(k))

            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        v = item.get("accountId") or item.get("account_id") or item.get("accountNumber") or item.get("account_number")
                        if v:
                            ids.append(str(v))
                    elif item:
                        ids.append(str(item))

            # de-dupe
            seen = set()
            out = []
            for x in ids:
                if x not in seen:
                    seen.add(x)
                    out.append(x)
            if out:
                return out
        except Exception:
            pass

    # last resort: try holdings keys (may be empty)
    try:
        info = _probe_account_info_v2(client) or _probe_account_info_legacy(client) or {}
        if isinstance(info, dict) and info:
            return [str(k) for k in info.keys()]
    except Exception:
        pass

    return []


# =============================================================================
# Public broker interface expected by Idle Markets
# =============================================================================

def bootstrap(*args, **kwargs) -> BrokerOutput:
    ctx = _log_ctx()
    try:
        sessions = _build_sessions()
        if not sessions:
            return schwab_normalize(
                BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Schwab", ok=False, message="Missing SCHWAB credentials")],
                    message="Missing credentials",
                )
            )

        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False

        for sess in sessions:
            idx = int(sess.get("idx") or 0) or 0
            label = f"schwab_{idx}" if idx else "schwab"
            try:
                _login_one(sess)
                outs.append(AccountOutput(account_id=sess["label"], ok=True, message="Login ok"))
                any_ok = True
            except Exception as e:
                if BLOG is not None:
                    try:
                        BLOG.log_exception(
                            ctx,
                            broker=BROKER,
                            action="login",
                            label=label,
                            exc=e,
                            secrets=[sess.get("username"), sess.get("password"), sess.get("totp")],
                        )
                    except Exception:
                        pass
                outs.append(AccountOutput(account_id=sess["label"], ok=False, message=str(e)))
                any_fail = True

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        return schwab_normalize(BrokerOutput(broker=BROKER, state=state, accounts=outs, message=""))

    except Exception as e:
        if BLOG is not None:
            try:
                BLOG.log_exception(ctx, broker=BROKER, action="login", label="schwab", exc=e, secrets=None)
            except Exception:
                pass
        return schwab_normalize(
            BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Schwab", ok=False, message=str(e))],
                message=str(e),
            )
        )


def get_holdings(*args, **kwargs) -> BrokerOutput:
    ctx = _log_ctx()
    try:
        sessions = _build_sessions()
        if not sessions:
            return schwab_normalize(
                BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Schwab", ok=False, message="Missing SCHWAB credentials")],
                    message="Missing credentials",
                )
            )

        selected = _selected_account_id().strip()
        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False

        broker_extra: Dict[str, Any] = {
            "sessions_count": int(len(sessions)),
            "debug": bool(_debug()),
            "accounts_ok": 0,
            "accounts_failed": 0,
            "positions_total": 0,
        }

        for sess in sessions:
            idx = int(sess.get("idx") or 0) or 0
            lbl = f"schwab_{idx}" if idx else "schwab"

            try:
                info = _ensure_authed(sess)
                if not isinstance(info, dict) or not info:
                    outs.append(
                        AccountOutput(
                            account_id=sess["label"],
                            ok=False,
                            message=f"Holdings returned empty (auth/trade OK). debug={_debug()}",
                            holdings=[],
                            extra={
                                "session_idx": idx,
                                "debug": bool(_debug()),
                            },
                        )
                    )
                    any_fail = True
                    continue

                keys = list(info.keys())
                if selected:
                    keys = [k for k in keys if str(k) == str(selected)]
                    if not keys:
                        outs.append(
                            AccountOutput(
                                account_id=sess["label"],
                                ok=False,
                                message="SCHWAB_ACCOUNT_ID not found",
                                holdings=[],
                                extra={
                                    "session_idx": idx,
                                    "selected": selected,
                                },
                            )
                        )
                        any_fail = True
                        continue

                for k in keys:
                    acc = info.get(k, {}) or {}

                    acc_value = _to_float(acc.get("account_value"))
                    acct_line = f"{_mask_last4(str(k))} = ${acc_value:.2f}" if acc_value is not None else f"{_mask_last4(str(k))} = ?"

                    rows: List[HoldingRow] = []
                    parsed = 0
                    raw_positions = (acc.get("positions") or [])
                    if not isinstance(raw_positions, list):
                        raw_positions = []

                    for pos in raw_positions:
                        if not isinstance(pos, dict):
                            continue

                        sym = (pos.get("symbol") or "Unknown")
                        sym = str(sym).strip().upper() or "UNKNOWN"

                        mv = _to_float(pos.get("market_value")) or 0.0
                        qty = _to_float(pos.get("quantity")) or 0.0
                        if qty == 0:
                            continue

                        px = round(mv / qty, 2) if qty else None

                        hextra: Dict[str, Any] = {}
                        try:
                            hextra["keys"] = sorted([str(x) for x in pos.keys()])[:200]
                            # safe scalars from normalized pos dict
                            hextra.update(_flatten_safe(pos, max_items=120))
                            # include a couple normalized-friendly fields explicitly
                            hextra["market_value"] = float(mv)
                            hextra["quantity"] = float(qty)
                            cb = _to_float(pos.get("cost"))
                            if cb is not None:
                                hextra["cost_basis"] = float(cb)
                            sid = pos.get("security_id")
                            if sid is not None:
                                # keep as string (safe)
                                hextra["security_id"] = str(sid)[:200]
                            desc = pos.get("description")
                            if desc:
                                hextra["description"] = str(desc)[:200]
                        except Exception:
                            pass

                        if px is not None:
                            try:
                                hextra["market_value_calc"] = float(qty) * float(px)
                            except Exception:
                                pass

                        rows.append(HoldingRow(symbol=sym, shares=qty, price=px, extra=hextra))
                        parsed += 1

                    acct_extra: Dict[str, Any] = {
                        "session_idx": idx,
                        "account_last4": str(k)[-4:] if str(k) else "----",
                        "account_value": acc_value,
                        "market_value": _to_float(acc.get("market_value")),
                        "cash_investments": _to_float(acc.get("cash_investments")),
                        "cost_total": _to_float(acc.get("cost")),
                        "raw_positions_count": int(len(raw_positions)),
                        "positions_parsed": int(parsed),
                    }

                    # discovery from raw-ish v2 parse (safe flatten only; denylist blocks ids)
                    try:
                        raw_acc = acc.get("_raw_account")
                        if isinstance(raw_acc, dict):
                            acct_extra["raw_account_keys"] = sorted([str(x) for x in raw_acc.keys()])[:200]
                            acct_extra.update(_flatten_safe(raw_acc, prefix="rawAccount_", max_items=120))

                        raw_totals = acc.get("_raw_totals")
                        if isinstance(raw_totals, dict):
                            acct_extra["raw_totals_keys"] = sorted([str(x) for x in raw_totals.keys()])[:200]
                            acct_extra.update(_flatten_safe(raw_totals, prefix="rawTotals_", max_items=80))
                    except Exception:
                        pass

                    outs.append(
                        AccountOutput(
                            account_id=f"{sess['label']} ({acct_line})",
                            ok=True,
                            message="",
                            holdings=rows,
                            extra=acct_extra,
                        )
                    )
                    any_ok = True
                    broker_extra["positions_total"] = int(broker_extra["positions_total"]) + int(len(rows))

            except Exception as e:
                if BLOG is not None:
                    try:
                        BLOG.log_exception(ctx, broker=BROKER, action="positions", label=lbl, exc=e, secrets=None)
                    except Exception:
                        pass
                outs.append(
                    AccountOutput(
                        account_id=sess["label"],
                        ok=False,
                        message=str(e),
                        holdings=[],
                        extra={"session_idx": idx},
                    )
                )
                any_fail = True

        broker_extra["accounts_ok"] = int(sum(1 for a in outs if a.ok))
        broker_extra["accounts_failed"] = int(sum(1 for a in outs if not a.ok))

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        msg = "" if any_ok else "failed"
        return schwab_normalize(BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg, extra=broker_extra))

    except Exception as e:
        if BLOG is not None:
            try:
                BLOG.log_exception(ctx, broker=BROKER, action="positions", label="schwab", exc=e, secrets=None)
            except Exception:
                pass
        return schwab_normalize(
            BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Schwab", ok=False, message=str(e))],
                message=str(e),
            )
        )


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return get_holdings(*args, **kwargs)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    """
    Critical: trades MUST NOT be blocked by holdings being empty.
    We discover account ids independently and then run trade_v2/trade.
    """
    ctx = _log_ctx()
    try:
        sessions = _build_sessions()
        if not sessions:
            return schwab_normalize(
                BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Schwab", ok=False, message="Missing SCHWAB credentials")],
                    message="Missing credentials",
                )
            )

        side_cap = (side or "").strip().capitalize()
        if side_cap not in ("Buy", "Sell"):
            return schwab_normalize(BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid side: {side!r}"))

        sym = (symbol or "").strip().upper()
        if not sym:
            return schwab_normalize(BrokerOutput(broker=BROKER, state="failed", accounts=[], message="Invalid symbol"))

        try:
            q = float(qty)
            if q <= 0:
                raise ValueError()
        except Exception:
            return schwab_normalize(BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid qty: {qty!r}"))

        error_messages = {
            "One share buy orders for this security must be phoned into a representative.": "Order failed: One share buy orders must be phoned in.",
            "This order may result in an oversold/overbought position in your account.": "Order failed: This may result in an oversold/overbought position.",
            "Your order is not eligible for electronic entry. Please call a Charles Schwab representative at (800) 435-9050 for assistance with this trade.": "Order failed: Stock not eligible for online entry",
        }

        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False
        _acct_i = 0

        for sess in sessions:
            idx = int(sess.get("idx") or 0) or 0
            lbl = f"schwab_{idx}" if idx else "schwab"
            client = sess["client"]

            # keep token alive; if that fails, try one login (then continue)
            if not _refresh_token_soft(client):
                try:
                    _login_one(sess)
                except Exception:
                    pass

            account_ids = _discover_account_ids_for_trade(client)
            if not account_ids:
                outs.append(AccountOutput(account_id=sess["label"], ok=False, message="Unauthorized / no Schwab accounts discovered"))
                any_fail = True
                continue

            # If SCHWAB_ACCOUNT_NUMBERS exists, it's already respected by discovery.
            # If SCHWAB_ACCOUNT_ID exists, discovery returns only that one.

            for acc_id in account_ids:
                if _acct_i > 0:
                    time.sleep(random.uniform(1.0, 3.0))
                _acct_i += 1

                acct_label = f"{sess['label']} ({_mask_last4(acc_id)})"

                try:
                    messages, success = client.trade_v2(
                        ticker=sym,
                        side=side_cap,
                        qty=q,
                        account_id=acc_id,
                        dry_run=bool(dry_run),
                    )

                    if not success:
                        handled = False
                        for err, friendly in error_messages.items():
                            if any(err in str(m) for m in (messages or [])):
                                outs.append(AccountOutput(account_id=acct_label, ok=False, message=friendly))
                                any_fail = True
                                handled = True
                                break
                        if handled:
                            continue

                        messages2, success2 = client.trade(
                            ticker=sym,
                            side=side_cap,
                            qty=q,
                            account_id=acc_id,
                            dry_run=bool(dry_run),
                        )
                        if success2:
                            outs.append(AccountOutput(account_id=acct_label, ok=True, message="ok (retry)"))
                            any_ok = True
                        else:
                            text = "\n".join(str(m) for m in (messages2 or [])) if messages2 else "Order failed"
                            outs.append(AccountOutput(account_id=acct_label, ok=False, message=text))
                            any_fail = True
                    else:
                        outs.append(AccountOutput(account_id=acct_label, ok=True, message="ok"))
                        any_ok = True

                except Exception as e:
                    if BLOG is not None:
                        try:
                            BLOG.log_exception(ctx, broker=BROKER, action="trade", label=lbl, exc=e, secrets=None)
                        except Exception:
                            pass
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=str(e)))
                    any_fail = True

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        return schwab_normalize(BrokerOutput(broker=BROKER, state=state, accounts=outs, message=""))

    except Exception as e:
        if BLOG is not None:
            try:
                BLOG.log_exception(ctx, broker=BROKER, action="trade", label="schwab", exc=e, secrets=None)
            except Exception:
                pass
        return schwab_normalize(
            BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Schwab", ok=False, message=str(e))],
                message=str(e),
            )
        )


def healthcheck(*args, **kwargs) -> BrokerOutput:
    # Simple: positions probe is the real healthcheck.
    return get_holdings(*args, **kwargs)
