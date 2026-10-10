# modules/brokers/schwab/schwab.py
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
import threading
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow
from modules.brokers.schwab.schwab_normalizer import normalize as schwab_normalize
from modules import http_timeouts
import broker_logins

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


#: Which login the account-scoping settings are being read for, per thread
#: (get_holdings and execute_trade can run at the same time).
_ENV_LOGIN = threading.local()


def _set_env_login(idx: int) -> None:
    _ENV_LOGIN.idx = int(idx or 1)


def _login_env(name: str) -> str:
    """A per-login account-scoping setting.

    SCHWAB_ACCOUNT_ID / SCHWAB_ACCOUNT_NUMBERS belong to login 1 only (they
    were written when there was one login). They used to apply to EVERY
    login, so login 2 traded login 1's account numbers -- or found none of
    them and reported "SCHWAB_ACCOUNT_ID not found". Login N (N >= 2) reads
    its own SCHWAB_ACCOUNT_ID_N / SCHWAB_ACCOUNT_NUMBERS_N.
    """
    idx = int(getattr(_ENV_LOGIN, "idx", 1) or 1)
    return _env(name) if idx <= 1 else _env(f"{name}_{idx}")


def _selected_account_id() -> str:
    return _login_env("SCHWAB_ACCOUNT_ID")


def _purchase_accounts_filter() -> List[str]:
    raw = _login_env("SCHWAB_ACCOUNT_NUMBERS")
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
            # A ':' inside the password stays in the password (a plain
            # split(":") truncated it and sent the tail as the TOTP secret).
            seg = broker_logins.split_fields(p, broker_logins.SCHEMAS["schwab"])
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


def _harden_client(client: Any) -> None:
    """Default timeouts for schwab_api's HTTP: the client's own Session and the
    module-level requests.post its v2 order calls use. Neither passes one, so a
    stalled socket hung the Schwab slot for good. Never raises."""
    try:
        http_timeouts.patch_session(getattr(client, "session", None))
        http_timeouts.patch_module_requests(sys.modules.get("schwab_api.schwab"))
    except Exception:
        pass


def _legacy_trade_tracked(client: Any, **kw: Any
                          ) -> Tuple[Any, bool, bool, Optional[BaseException]]:
    """client.trade(), plus whether its confirmation POST went out.

    The legacy call POSTs verifyOrder, then confirmorder -- and only the
    second places anything. Its failures look alike either side of that line
    (a False, or an exception), so the session's post() is watched for the
    confirmation URL. Returns (messages, success, confirm_sent, exception).
    confirm_sent is None when there was no session post() to watch: then
    nobody knows, and the caller must not claim nothing was sent.
    """
    sent = [False]
    sess = getattr(client, "session", None)
    orig = getattr(sess, "post", None) if sess is not None else None
    had_own = sess is not None and "post" in getattr(sess, "__dict__", {})
    watched = False
    if callable(orig):
        def _post(url: Any, *a: Any, **k: Any) -> Any:
            if "confirmorder" in str(url).lower():
                sent[0] = True
            return orig(url, *a, **k)
        try:
            sess.post = _post
            watched = True
        except Exception:
            orig = None
    try:
        messages, success = client.trade(**kw)
        return messages, bool(success), (sent[0] if watched else None), None
    except Exception as e:      # noqa: BLE001 -- the caller words it
        return None, False, (sent[0] if watched else None), e
    finally:
        if callable(orig):
            try:
                if had_own:
                    sess.post = orig
                else:
                    del sess.post
            except Exception:
                pass


def _cache_user_hash(username: str) -> str:
    """schwab_api's own fingerprint of a username (what it stores as
    username_hash in the session cache)."""
    return hashlib.md5((username or "").encode("utf-8")).hexdigest()


def _cache_owner_hash(path: Path) -> Optional[str]:
    """The username_hash stored in a session cache, or None if unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None
    h = data.get("username_hash") if isinstance(data, dict) else None
    return str(h) if h else None


def _discard_cache(path: Path) -> None:
    """Delete a session cache and the account-id list kept beside it."""
    for f in (Path(path), Path(path).with_name(f"{Path(path).stem}_accounts.json")):
        try:
            f.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _keyed_cache_path(legacy: Path, username: str) -> Path:
    """The session cache for one USERNAME, next to the positional files."""
    return Path(legacy).parent / f"schwab_{_cache_user_hash(username)[:16]}.json"


def _login_cache_paths(usernames: List[str]) -> List[Path]:
    """One session cache per login, keyed by its username, not its position.

    The cache used to be schwab<position>.json, and schwab_api restores the
    cookies and Bearer token from it BEFORE it compares credential hashes --
    and keeps them when the hashes differ (it only re-hashes and logs in
    lazily). So re-pointing login 1 at another person, or reordering SCHWAB=
    in .env, traded login B through login A's session.

    Migration: a positional file (schwab.json, schwab<N>.json) whose stored
    username_hash belongs to a configured login is moved to that login's
    keyed path, so login 1 keeps its session across the upgrade. Positional
    files are never read again, so one that belongs to no configured login
    is LEFT where it is: that login may only be missing from .env right now,
    and it migrates when it comes back. A move that fails (PermissionError,
    Google Drive's WinError 5) leaves the file in place too -- the next start
    retries -- instead of deleting a valid session.

    The only file deleted is a keyed one whose readable stored owner is not
    the login that would use that path: that is the one case where a session
    could trade one person through another's cookies.
    """
    legacy = [Path(_session_cache_path(i)) for i in range(1, len(usernames) + 1)]
    if not legacy:
        return []
    keyed = [_keyed_cache_path(legacy[i], u) for i, u in enumerate(usernames)]
    by_hash = {_cache_user_hash(u): k for u, k in zip(usernames, keyed)}

    candidates: List[Path] = []
    seen = set()
    dirs = {p.parent for p in legacy}
    for d in dirs:
        try:
            found = sorted(d.glob("schwab*.json"))
        except OSError:
            found = []
        for f in found:
            if f.name.startswith("schwab_") or f.stem.endswith("_accounts"):
                continue
            candidates.append(f)
    candidates += legacy + [legacy[0].parent / "schwab.json"]
    for f in candidates:
        key = str(f).lower()
        if key in seen or not f.exists() or f in keyed:
            continue
        seen.add(key)
        dest = by_hash.get(_cache_owner_hash(f) or "")
        if dest is None or dest.exists():
            continue                   # not ours to move (or already moved): left as is
        try:
            f.replace(dest)
        except OSError:
            continue                   # locked (Drive, AV): leave it, retry next start
        acc = f.with_name(f"{f.stem}_accounts.json")
        try:
            if acc.exists():
                acc.replace(dest.with_name(f"{dest.stem}_accounts.json"))
        except OSError:
            pass

    for u, k in zip(usernames, keyed):
        if not k.exists():
            continue
        try:
            text = k.read_text(encoding="utf-8")
        except OSError:
            continue                   # can't read it now; never delete on a guess
        try:
            data = json.loads(text)
        except Exception:
            data = None
        owner = data.get("username_hash") if isinstance(data, dict) else None
        if str(owner or "") != _cache_user_hash(u):
            _discard_cache(k)
    return keyed


def _build_sessions() -> List[Dict[str, Any]]:
    global _SESSIONS

    accts = _parse_accounts_from_env()
    if not accts:
        _SESSIONS = []
        return _SESSIONS

    # Keyed by the logins themselves, not by how many there are: editing one
    # login's username or password used to keep trading through the old client.
    if _SESSIONS and [(s.get("username"), s.get("password"), s.get("totp"))
                      for s in _SESSIONS] == list(accts):
        return _SESSIONS

    Schwab = _load_schwab_class()
    debug = _debug()

    out: List[Dict[str, Any]] = []
    cache_paths = _login_cache_paths([u for (u, _pw, _t) in accts])
    for i, (u, pw, totp) in enumerate(accts, start=1):
        # Login 1 stays "Schwab" whatever else is configured: its accounts
        # trade (and are journaled) as "Schwab (****1234)", and trades.json
        # nets buys against sells on that exact string. Renaming it to
        # "Schwab 1" when a second login appeared orphaned every open position.
        label = f"Schwab {i}" if i > 1 else "Schwab"
        cache_path = cache_paths[i - 1]
        client = Schwab(session_cache=str(cache_path), debug=debug)
        _harden_client(client)
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

    merged: Dict[Any, dict] = {}

    def _failed(acc_id: Any, why: str) -> None:
        # An account whose read failed is KEPT, marked, instead of skipped.
        # Skipping it made the account vanish from an otherwise good result:
        # no row, no failure, and the exits board read "holds nothing" for
        # stock it really holds. get_holdings turns this into an ok=False row.
        merged[_read_error_key(acc_id)] = {"account_id": str(acc_id), "positions": [],
                                           _READ_ERROR: why}

    for acc_id in ids:
        scoped = dict(base_headers)
        scoped["schwab-client-account"] = str(acc_id)
        scoped["schwab-client-ids"] = str(acc_id)

        try:
            rr = requests.get(schwab_urls.positions_v2(), headers=scoped, timeout=30)
        except Exception as e:
            _failed(acc_id, f"{type(e).__name__}: {e}")
            continue
        if rr.status_code != 200:
            _dump_schwab_payload(
                f"holdings_v2_http_{rr.status_code}",
                rr.text,
                label=str(acc_id),
            )
            _failed(acc_id, f"HTTP {rr.status_code}")
            continue

        try:
            pp = json.loads(rr.text)
        except json.JSONDecodeError:
            _dump_schwab_payload(
                "holdings_v2_nonjson",
                rr.text,
                label=str(acc_id),
            )
            _failed(acc_id, "the reply was not JSON")
            continue
        except Exception as e:
            _failed(acc_id, f"{type(e).__name__}: {e}")
            continue

        parsed = _parse(pp)
        if not parsed:
            if _debug():
                _dump_schwab_payload(
                    "holdings_v2_empty_scoped",
                    json.dumps(pp, ensure_ascii=False, indent=2),
                    label=str(acc_id),
                )
            _failed(acc_id, "the reply held no account")
            continue

        merged.update(parsed)

    return merged or None


#: Marks an account in a holdings dict whose positions could not be read.
_READ_ERROR = "_read_error"


def _read_error_key(acc_id: Any) -> Any:
    """The int key _parse gives a good read of the same account."""
    try:
        return int(str(acc_id).replace("-", ""))
    except Exception:
        return str(acc_id)


def _has_read_errors(info: Any) -> bool:
    return isinstance(info, dict) and any(
        isinstance(v, dict) and v.get(_READ_ERROR) for v in info.values())


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

    # A v2 read where some account failed. If nothing better turns up it is
    # returned at the end instead of {}, so those accounts report their own
    # failure rather than one generic "Holdings returned empty".
    partial: Optional[dict] = None

    # 1) v2 probe
    try:
        info_v2 = _probe_account_info_v2(c)
        if info_v2 is not None and not _looks_stale_account_info(info_v2):
            return info_v2
        if _has_read_errors(info_v2):
            partial = info_v2
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
        if _has_read_errors(info_v2b):
            partial = info_v2b
    except Exception as e:
        _log_exc("positions_v2", e)

    # 5) retry legacy
    try:
        info_legb = _probe_account_info_legacy(c)
        if info_legb is not None and not _looks_stale_account_info(info_legb):
            return info_legb
    except Exception as e:
        _log_exc("positions_legacy", e)

    return partial or {}


def _account_ids_file(sess: Dict[str, Any]) -> Optional[Path]:
    """Where this login's last good account-id list is kept, next to its
    session cache. None for a session without one (nothing is remembered)."""
    cache = sess.get("cache_path")
    if not cache:
        return None
    p = Path(cache)
    return p.with_name(f"{p.stem}_accounts.json")


def _remember_account_ids(sess: Dict[str, Any], ids: List[str]) -> None:
    path = _account_ids_file(sess)
    if path is None or not ids:
        return
    try:
        from modules import atomic
        atomic.write_json(path, {"username": str(sess.get("username") or ""),
                                 "account_ids": [str(i) for i in ids]})
    except Exception:
        pass


def _remembered_account_ids(sess: Dict[str, Any]) -> List[str]:
    """The account ids this login last discovered, for when discovery comes
    back empty.

    schwab_api 0.4.3 has no get_account_numbers, so without
    SCHWAB_ACCOUNT_NUMBERS discovery IS the holdings read, and a holdings
    outage stopped every trade with "no Schwab accounts discovered". Only for
    the same username: a login re-pointed at someone else must never trade
    the previous person's accounts.
    """
    path = _account_ids_file(sess)
    if path is None:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if (not isinstance(data, dict)
            or str(data.get("username") or "") != str(sess.get("username") or "")):
        return []
    ids = data.get("account_ids")
    return [str(i) for i in ids if str(i).strip()] if isinstance(ids, list) else []


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
# Public broker interface expected by RSAMAXXED
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
            _set_env_login(idx)
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
            _set_env_login(idx)
            lbl = f"schwab_{idx}" if idx else "schwab"
            selected = _selected_account_id().strip()

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

                    if acc.get(_READ_ERROR):
                        outs.append(AccountOutput(
                            account_id=f"{sess['label']} ({_mask_last4(str(k))} = ?)",
                            ok=False,
                            message=(f"Schwab holdings read failed: {acc.get(_READ_ERROR)} "
                                     f"— holdings unknown"),
                            holdings=[],
                            extra={"session_idx": idx,
                                   "account_last4": str(k)[-4:] if str(k) else "----"},
                        ))
                        any_fail = True
                        continue

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


def _schwab_friendly_error(messages: Any, error_messages: Dict[str, str]) -> str:
    """A pre-placement rejection, in words the user can act on.

    Known Schwab refusals map to their short form; anything else is Schwab's
    own text. This is only used where no order can exist, so it must never
    borrow the "may have been submitted / verify" wording.
    """
    msgs = [str(m) for m in (messages or [])]
    for err, friendly in error_messages.items():
        if any(err in m for m in msgs):
            return friendly
    text = "; ".join(m for m in msgs if m.strip()) or "no detail"
    return f"Schwab rejected the order before it was sent: {text}"


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
        # schwab_api sends str(qty), and str(1.0) is "1.0". A whole number goes
        # out as an int, "1".
        if q.is_integer():
            q = int(q)

        error_messages = {
            "One share buy orders for this security must be phoned into a representative.": "Order failed: One share buy orders must be phoned in.",
            "This order may result in an oversold/overbought position in your account.": "Order failed: This may result in an oversold/overbought position.",
            "Your order is not eligible for electronic entry. Please call a Charles Schwab representative at (800) 435-9050 for assistance with this trade.": "Order failed: Stock not eligible for online entry",
        }

        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False
        _acct_i = 0
        # Set before any call that can place an order (the legacy fallback,
        # the live trade_v2). The except at the bottom reads it.
        live_called = [False]

        for sess in sessions:
            idx = int(sess.get("idx") or 0) or 0
            _set_env_login(idx)
            lbl = f"schwab_{idx}" if idx else "schwab"
            client = sess["client"]

            # keep token alive; if that fails, try one login (then continue)
            if not _refresh_token_soft(client):
                try:
                    _login_one(sess)
                except Exception:
                    pass

            account_ids = _discover_account_ids_for_trade(client)
            if account_ids:
                _remember_account_ids(sess, account_ids)
            else:
                account_ids = _remembered_account_ids(sess)
            if not account_ids:
                outs.append(AccountOutput(
                    account_id=sess["label"], ok=False,
                    message="Unauthorized / no Schwab accounts discovered — nothing was sent"))
                any_fail = True
                continue

            # If SCHWAB_ACCOUNT_NUMBERS exists, it's already respected by discovery.
            # If SCHWAB_ACCOUNT_ID exists, discovery returns only that one.

            for acc_id in account_ids:
                if _acct_i > 0:
                    time.sleep(random.uniform(1.0, 3.0))
                _acct_i += 1

                acct_label = f"{sess['label']} ({_mask_last4(acc_id)})"

                if not dry_run:
                    # Verification-only pass first (trade_v2 dry_run=True stops
                    # after the verification POST and places nothing). Most
                    # failures — expired token, insufficient funds, restricted
                    # security, a dropped connection — happen right there, and
                    # they hold no order, so they must read as plain, retryable
                    # failures. Only the live call below can leave an order
                    # behind, and only it gets the "verify" wording.
                    try:
                        pre_msgs, pre_ok = client.trade_v2(
                            ticker=sym,
                            side=side_cap,
                            qty=q,
                            account_id=acc_id,
                            dry_run=True,
                        )
                    except Exception as e:
                        if BLOG is not None:
                            try:
                                BLOG.log_exception(ctx, broker=BROKER, action="trade", label=lbl, exc=e, secrets=None)
                            except Exception:
                                pass
                        outs.append(AccountOutput(
                            account_id=acct_label, ok=False,
                            message=f"Schwab order check failed, nothing was sent: {e}"))
                        any_fail = True
                        continue
                    if not pre_ok:
                        known = any(err in str(m) for m in (pre_msgs or [])
                                    for err in error_messages)
                        if known:
                            # The verification-only pass: no order exists.
                            outs.append(AccountOutput(
                                account_id=acct_label, ok=False,
                                message=(_schwab_friendly_error(pre_msgs, error_messages)
                                         + " — nothing was sent")))
                            any_fail = True
                            continue
                        # v2's verification refused for a reason Schwab didn't
                        # name (it is the flakier endpoint, with stricter auth).
                        # Nothing was placed, so the legacy cookie-based call is
                        # safe here and places at most one order — the fallback
                        # this module always had, just moved ahead of the live
                        # v2 call where it can no longer double up.
                        # Its confirmation POST is the one that places the
                        # order; a failure after it went out may be a live
                        # order and says so (see _legacy_trade_tracked).
                        live_called[0] = True
                        messages2, success2, confirm_sent, e = _legacy_trade_tracked(
                            client,
                            ticker=sym,
                            side=side_cap,
                            qty=q,
                            account_id=acc_id,
                            dry_run=False,
                        )
                        if e is not None:
                            if BLOG is not None:
                                try:
                                    BLOG.log_exception(ctx, broker=BROKER, action="trade", label=lbl, exc=e, secrets=None)
                                except Exception:
                                    pass
                            if confirm_sent:
                                text = ("Schwab raised an error after the order may have been "
                                        f"submitted — verify in Schwab before retrying: {e}")
                            elif confirm_sent is False:
                                # Watched: the confirmation POST never went out.
                                text = f"Schwab order failed before it was confirmed: {e} — nothing was sent"
                            else:
                                text = f"Schwab order failed: {e}"
                            outs.append(AccountOutput(account_id=acct_label, ok=False, message=text))
                            any_fail = True
                            continue
                        if success2:
                            outs.append(AccountOutput(account_id=acct_label, ok=True, message="ok (retry)"))
                            any_ok = True
                        else:
                            text = "\n".join(str(m) for m in (messages2 or [])) if messages2 else "Order failed"
                            if confirm_sent:
                                text = ("Schwab returned an error after the order may have been "
                                        f"submitted — verify in Schwab before retrying: {text}")
                            elif confirm_sent is False:
                                # verifyOrder refused (or answered non-200):
                                # confirmorder, the only POST that places, never ran.
                                text = f"{text} — nothing was sent"
                            outs.append(AccountOutput(account_id=acct_label, ok=False, message=text))
                            any_fail = True
                        continue

                try:
                    if not dry_run:
                        live_called[0] = True
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

                        if not dry_run:
                            # No legacy retry on a live order. trade_v2 also
                            # returns False AFTER its placement POST (a 504 once
                            # Schwab has accepted it, an orderReturnCode outside
                            # the valid set), so client.trade() here could place
                            # a second order. Report it as possibly submitted —
                            # the app never auto-retries that wording.
                            text = "; ".join(str(m) for m in (messages or [])) or "no detail"
                            outs.append(AccountOutput(
                                account_id=acct_label, ok=False,
                                message=("Schwab returned an error after the order may have been "
                                         f"submitted — verify in Schwab before retrying: {text}"),
                            ))
                            any_fail = True
                            continue

                        # Dry run only: the legacy call stops at verification
                        # when dry_run=True, so the retry can't place anything.
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
                    # trade_v2 raises from either POST alike (timeouts, a
                    # non-JSON body, a missing key in the placement response),
                    # so a live order can't be told apart from one never sent.
                    # Dry runs never reach the placement POST.
                    if dry_run:
                        text = str(e)
                    else:
                        text = ("Schwab raised an error while the order may have been "
                                f"submitted — verify in Schwab before retrying: {e}")
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=text))
                    any_fail = True

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        return schwab_normalize(BrokerOutput(broker=BROKER, state=state, accounts=outs, message=""))

    except Exception as e:
        if BLOG is not None:
            try:
                BLOG.log_exception(ctx, broker=BROKER, action="trade", label="schwab", exc=e, secrets=None)
            except Exception:
                pass
        # Outside every account's own try (a session refresh, discovery for a
        # later login): keep the rows already written -- an order may stand
        # behind them -- and say nothing-sent only if no live call was made.
        done = list(locals().get("outs") or [])
        if (locals().get("live_called") or [False])[0]:
            row = (f"Schwab failed partway through ({e}) — earlier orders may have been "
                   f"submitted; verify in Schwab before retrying")
        else:
            row = f"{e} — nothing was sent"
        done.append(AccountOutput(account_id="Schwab", ok=False, message=row))
        return schwab_normalize(
            BrokerOutput(
                broker=BROKER,
                state="partial" if any(a.ok for a in done) else "failed",
                accounts=done,
                message=str(e),
            )
        )


def healthcheck(*args, **kwargs) -> BrokerOutput:
    # Simple: positions probe is the real healthcheck.
    return get_holdings(*args, **kwargs)
