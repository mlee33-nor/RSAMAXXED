# modules/brokers/robinhood/robinhood.py
from __future__ import annotations

import builtins
import contextlib
import getpass
import io
import inspect
import logging
import os
import random
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow
from modules._2fa_prompt import universal_2fa_prompt
from modules import broker_logging as BLOG

BROKER = "robinhood"

_RH: Any = None
_QUOTE_UNSUPPORTED: set[str] = set()

# [(display_label, account_number, login_pickle_name)]
_ACCOUNTS: List[Tuple[str, str, str]] = []

_ET = ZoneInfo("America/New_York")

for _lname in ("robin_stocks", "urllib3", "requests"):
    try:
        logging.getLogger(_lname).setLevel(logging.CRITICAL)
    except Exception:
        pass


@contextlib.contextmanager
def _suppress_console_noise():
    """
    Silence noisy third-party prints/log spam from robin_stocks internals.
    """
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield
    except Exception:
        yield


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
    "account_number",
    "accountnumber",
    "acct_number",
    "acctnumber",
)

def _is_safe_scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))

def _key_allowed(k: str) -> bool:
    kl = (k or "").strip().lower().replace(" ", "")
    if not kl:
        return False
    return not any(bad in kl for bad in _DENY_KEY_SUBSTRS)

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
            # cap big strings
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

def _safe_last4(s: Any) -> str:
    x = str(s or "").strip()
    if not x:
        return "----"
    digits = "".join(c for c in x if c.isdigit())
    if len(digits) >= 4:
        return digits[-4:]
    return (x[-4:] if len(x) >= 4 else x) or "----"


# =============================================================================
# Paths / env
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _log_ctx() -> Dict[str, Any]:
    return {"log_dir": _root_dir() / "logs"}


def _log_mfa_decision(*, text: str, secrets: Optional[List[Any]] = None) -> None:
    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="bootstrap",
            label="mfa",
            filename_prefix="bootstrap_mfa",
            text=text,
            secrets=secrets,
        )
    except Exception:
        pass


def _log_session_issue(*, label: str, text: str, secrets: Optional[List[Any]] = None) -> Optional[str]:
    try:
        p = BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="session",
            label=label,
            filename_prefix="session_auth",
            text=text,
            secrets=secrets,
        )
        return str(p)
    except Exception:
        return None


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _pickle_path() -> Path:
    """
    Match legacy idea of a dedicated creds folder.
    Tokens/pickles live here (relative to project root):
      ROOT_DIR/sessions/robinhood/creds/
    """
    p = _root_dir() / "sessions" / "robinhood" / "creds"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _pickle_file(pickle_name: str) -> Path:
    """
    robin_stocks builds: f"{pickle_path}/robinhood{pickle_name}.pickle"
    (This is what legacy relied on with names like "Robinhood 1".)
    """
    return _pickle_path() / f"robinhood{pickle_name}.pickle"


def _pickle_debug_lines(pickle_name: str) -> List[str]:
    p = _pickle_file(pickle_name)
    lines = [
        f"pickle_name={pickle_name}",
        f"pickle_file={p}",
        f"pickle_exists={p.exists()}",
    ]
    if p.exists():
        try:
            st = p.stat()
            lines.append(f"pickle_size={int(st.st_size)}")
            lines.append(f"pickle_mtime_et={datetime.fromtimestamp(st.st_mtime, _ET).isoformat()}")
        except Exception:
            lines.append("pickle_stat_error=true")
    return lines


def _dry_run_log_dir() -> Path:
    d = datetime.now(_ET).strftime("%m.%d.%y")
    p = _root_dir() / "logs" / BROKER / d
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_dry_run_log(*, content: str) -> str:
    rand = uuid.uuid4().hex[:10]
    path = _dry_run_log_dir() / f"test_order_{BROKER}_{rand}.log"
    path.write_text(content, encoding="utf-8")
    return str(path)


# =============================================================================
# robin_stocks load + compatibility
# =============================================================================

def _load_rh():
    try:
        import robin_stocks.robinhood as rh  # type: ignore
        return rh, None
    except Exception as e:
        return None, f"Missing dependency: robin-stocks ({e})"


def _get_login_callable(rh):
    auth = getattr(rh, "authentication", None)
    login_fn = getattr(auth, "login", None) if auth else None
    if callable(login_fn):
        return login_fn
    login_fn = getattr(rh, "login", None)
    if callable(login_fn):
        return login_fn
    return None


def _safe_load_accounts(rh) -> List[Dict[str, Any]]:
    """
    Legacy used: rh.account.load_account_profile(dataType="results")
    Use that first; fallback if needed.
    """
    try:
        fn = getattr(getattr(rh, "account", None), "load_account_profile", None)
        if callable(fn):
            with _suppress_console_noise():
                rows = fn(dataType="results") or []
            return rows if isinstance(rows, list) else []
    except Exception:
        pass

    try:
        fn = getattr(getattr(rh, "profiles", None), "load_account_profile", None)
        if callable(fn):
            with _suppress_console_noise():
                rows = fn(dataType="results") or []
            return rows if isinstance(rows, list) else []
    except Exception:
        pass

    return []


def _safe_open_positions(rh, *, account_number: str) -> List[Dict[str, Any]]:
    """
    Legacy used: obj.get_open_stock_positions(account_number=account)
    Try common call sites.
    """
    try:
        fn = getattr(getattr(rh, "account", None), "get_open_stock_positions", None)
        if callable(fn):
            with _suppress_console_noise():
                rows = fn(account_number=account_number) or []
            return rows if isinstance(rows, list) else []
    except Exception:
        pass

    try:
        fn = getattr(rh, "get_open_stock_positions", None)
        if callable(fn):
            with _suppress_console_noise():
                rows = fn(account_number=account_number) or []
            return rows if isinstance(rows, list) else []
    except Exception:
        pass

    return []


def _symbol_from_instrument(rh, instrument_url: str) -> str:
    """
    Legacy: obj.get_symbol_by_url(item["instrument"])
    """
    instrument_url = (instrument_url or "").strip()
    if not instrument_url:
        return "UNKNOWN"

    fn = getattr(rh, "get_symbol_by_url", None)
    if callable(fn):
        try:
            with _suppress_console_noise():
                sym = (fn(instrument_url) or "").strip().upper()
            return sym or "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    stocks = getattr(rh, "stocks", None)
    fn2 = getattr(stocks, "get_symbol_by_url", None) if stocks else None
    if callable(fn2):
        try:
            with _suppress_console_noise():
                sym = (fn2(instrument_url) or "").strip().upper()
            return sym or "UNKNOWN"
        except Exception:
            return "UNKNOWN"

    return "UNKNOWN"


def _latest_price(rh, sym: str) -> Optional[float]:
    """
    Legacy: float(obj.stocks.get_latest_price(sym)[0])
    """
    sym = (sym or "").strip().upper()
    if not sym or sym == "UNKNOWN":
        return None
    # Robinhood quotes endpoint frequently 400s for OTC symbols (e.g., *F suffix).
    # Skip these up front to avoid noisy console/API errors.
    if sym.endswith("F"):
        return None
    if sym in _QUOTE_UNSUPPORTED:
        return None

    stocks = getattr(rh, "stocks", None)
    fn = getattr(stocks, "get_latest_price", None) if stocks else None
    if not callable(fn):
        fn = getattr(rh, "get_latest_price", None)

    if not callable(fn):
        return None

    try:
        with _suppress_console_noise():
            px_list = fn(sym)
        if isinstance(px_list, list) and px_list:
            px = px_list[0]
        else:
            px = px_list
        if px is None:
            return None
        return float(px)
    except Exception:
        _QUOTE_UNSUPPORTED.add(sym)
        return None


# =============================================================================
# Legacy-mimic session functions
# =============================================================================

@contextlib.contextmanager
def _block_interactive_prompts(*, context: str):
    """
    Prevent silent hangs when robin_stocks falls back to interactive input().
    """
    orig_input = builtins.input
    orig_getpass = getpass.getpass

    def _blocked(prompt: str = "") -> str:
        prompt_txt = str(prompt or "").strip()
        hint = f" Prompt={prompt_txt!r}" if prompt_txt else ""
        raise RuntimeError(
            f"Robinhood requested interactive input during {context}.{hint} "
            "Cached session appears expired/corrupt."
        )

    builtins.input = _blocked
    getpass.getpass = _blocked  # type: ignore[assignment]
    try:
        yield
    finally:
        builtins.input = orig_input
        getpass.getpass = orig_getpass  # type: ignore[assignment]


def login_with_cache(*, rh, pickle_name: str) -> None:
    """
    THIS is the legacy trick.

    Always call rh.login with only:
      - expiresIn (30d)
      - pickle_path
      - pickle_name

    No username/password.
    That forces robin_stocks to load cached tokens (and refresh if it can),
    without OTP prompts in normal cases.
    """
    login_fn = _get_login_callable(rh)
    if not callable(login_fn):
        raise RuntimeError("Could not find robin_stocks login()")

    try:
        params = inspect.signature(login_fn).parameters
    except Exception:
        params = {}

    call_kwargs: Dict[str, Any] = {}

    # keep long-lived like legacy
    if "expiresIn" in params:
        call_kwargs["expiresIn"] = 86400 * 30
    elif "expires_in" in params:
        call_kwargs["expires_in"] = 86400 * 30

    if "pickle_path" in params:
        call_kwargs["pickle_path"] = str(_pickle_path())
    if "pickle_name" in params:
        call_kwargs["pickle_name"] = pickle_name

    # harmless if supported
    if "store_session" in params:
        call_kwargs["store_session"] = True

    try:
        with _block_interactive_prompts(context=f"cache rehydrate ({pickle_name})"):
            with _suppress_console_noise():
                login_fn(**call_kwargs)
    except Exception as e:
        detail = f"{type(e).__name__}: {e}"
        log_text = "\n".join(
            [
                "Robinhood cache rehydrate failed.",
                *(_pickle_debug_lines(pickle_name)),
                f"error={detail}",
                "next_action=run interactive Robinhood login to refresh session pickle",
            ]
        )
        log_path = _log_session_issue(label="rehydrate_failed", text=log_text)
        extra = f" See log: {log_path}" if log_path else ""
        raise RuntimeError(
            f"Cached Robinhood session for {pickle_name} is invalid/expired. "
            f"Interactive re-login required.{extra}"
        ) from e


def _login_profiles() -> List[Tuple[str, str, str]]:
    """
    Scalable:
      - If env ROBINHOOD exists (legacy style): "user:pass,user2:pass2"
      - Else: ROBINHOOD_USERNAME / ROBINHOOD_PASSWORD (single)
    Returns: [(pickle_name, username, password)]
    """
    legacy = _env("ROBINHOOD")
    if legacy:
        out: List[Tuple[str, str, str]] = []
        parts = [p.strip() for p in legacy.split(",") if p.strip()]
        for i, entry in enumerate(parts, start=1):
            if ":" not in entry:
                continue
            u, pw = entry.split(":", 1)
            u = (u or "").strip()
            pw = (pw or "").strip()
            if not u or not pw:
                continue
            out.append((f"Robinhood {i}", u, pw))
        if out:
            return out

    u = _env("ROBINHOOD_USERNAME")
    pw = _env("ROBINHOOD_PASSWORD")
    if u and pw:
        return [("Robinhood 1", u, pw)]

    return []


def bootstrap() -> BrokerOutput:
    """
    Interactive login (OTP) that writes the pickle into sessions/robinhood/creds/
    EXACTLY like legacy: rh.login(username, password, store_session=True, expiresIn=30d, pickle_path, pickle_name)
    """
    global _RH, _ACCOUNTS

    rh, err = _load_rh()
    if err:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=err)],
            message=err,
        )

    profiles = _login_profiles()
    if not profiles:
        msg = "Missing Robinhood creds. Set ROBINHOOD (legacy) or ROBINHOOD_USERNAME/ROBINHOOD_PASSWORD."
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=msg)],
            message=msg,
        )

    # Force-mode is intentionally disabled. Robinhood chooses SMS/email/app.
    requested_mfa = "auto"
    method_label = "auto (Robinhood decides SMS/email/app)"

    otp_provider = None  # _input_stub naturally falls back to terminal input()

    login_fn = _get_login_callable(rh)
    if not callable(login_fn):
        msg = "Could not find robin_stocks login()"
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=msg)],
            message=msg,
        )

    try:
        params = inspect.signature(login_fn).parameters
    except Exception:
        params = {}

    orig_input = builtins.input

    def _input_stub(prompt: str = "") -> str:
        if otp_provider is None:
            return orig_input(prompt)
        code = otp_provider("Robinhood", 300)
        return code or ""

    try:
        builtins.input = _input_stub

        # Build accounts by logging each profile (legacy-style, one pickle per profile)
        merged_accounts: List[Tuple[str, str, str]] = []
        seen_numbers = set()

        for pickle_name, username, password in profiles:
            call_kwargs: Dict[str, Any] = {}

            if "username" in params:
                call_kwargs["username"] = username
            if "password" in params:
                call_kwargs["password"] = password

            if "store_session" in params:
                call_kwargs["store_session"] = True

            if "expiresIn" in params:
                call_kwargs["expiresIn"] = 86400 * 30
            elif "expires_in" in params:
                call_kwargs["expires_in"] = 86400 * 30

            if "pickle_path" in params:
                call_kwargs["pickle_path"] = str(_pickle_path())
            if "pickle_name" in params:
                call_kwargs["pickle_name"] = pickle_name

            by_sms_supported = ("by_sms" in params)
            _log_mfa_decision(
                text=(
                    "Robinhood MFA selection\n"
                    f"requested={requested_mfa}\n"
                    f"by_sms_supported={by_sms_supported}\n"
                    "by_sms_arg=not_used (force method disabled)\n"
                    f"effective_prompt={method_label}"
                ),
                secrets=[username],
            )

            # login (OTP happens here if needed)
            # Keep prompts visible in terminal mode; suppress only for OTP-provider mode.
            if otp_provider is None:
                login_fn(**call_kwargs)
            else:
                with _suppress_console_noise():
                    login_fn(**call_kwargs)

            # immediately rehydrate from the cache (exact legacy habit)
            login_with_cache(rh=rh, pickle_name=pickle_name)

            rows = _safe_load_accounts(rh)
            for a in rows:
                acct = (a.get("account_number") or "").strip()
                if not acct or acct in seen_numbers:
                    continue
                seen_numbers.add(acct)

                acct_type = (a.get("brokerage_account_type") or a.get("type") or "ACCOUNT").strip()
                base_label = f"{acct_type} (****{acct[-4:]})"

                # If multiple logins, prefix with which one
                if len(profiles) > 1:
                    display = f"{pickle_name} | {base_label}"
                else:
                    display = base_label

                merged_accounts.append((display, acct, pickle_name))

        _RH = rh
        _ACCOUNTS = merged_accounts

        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[AccountOutput(account_id="Robinhood", ok=True, message=f"Login ok ({len(_ACCOUNTS)} accounts)")],
            message="Login ok",
        )

    except Exception as e:
        _RH = None
        _ACCOUNTS = []
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=f"Login failed: {e}")],
            message=f"Login failed: {e}",
        )

    finally:
        builtins.input = orig_input


def _ensure_session() -> Tuple[bool, str]:
    """
    Legacy mimic:
      - If pickle exists -> call login_with_cache() -> proceed
      - If not -> require interactive bootstrap to create it
    """
    global _RH, _ACCOUNTS

    rh, err = _load_rh()
    if err:
        return False, err

    profiles = _login_profiles()
    if not profiles:
        return False, "Missing Robinhood creds. Set ROBINHOOD or ROBINHOOD_USERNAME/ROBINHOOD_PASSWORD."

    # If we already have accounts cached in memory, still force rehydrate like legacy does.
    # But also rebuild accounts if empty.
    try:
        merged_accounts: List[Tuple[str, str, str]] = []
        seen_numbers = set()

        for pickle_name, _u, _pw in profiles:
            if not _pickle_file(pickle_name).exists():
                raise FileNotFoundError(f"Missing session pickle for {pickle_name}")

            # THIS IS THE KEY: rehydrate on every command (legacy)
            login_with_cache(rh=rh, pickle_name=pickle_name)

            rows = _safe_load_accounts(rh)
            for a in rows:
                acct = (a.get("account_number") or "").strip()
                if not acct or acct in seen_numbers:
                    continue
                seen_numbers.add(acct)

                acct_type = (a.get("brokerage_account_type") or a.get("type") or "ACCOUNT").strip()
                base_label = f"{acct_type} (****{acct[-4:]})"

                if len(profiles) > 1:
                    display = f"{pickle_name} | {base_label}"
                else:
                    display = base_label

                merged_accounts.append((display, acct, pickle_name))

        _RH = rh
        _ACCOUNTS = merged_accounts

        if not _ACCOUNTS:
            # If we rehydrated but still got no accounts, treat as auth failure.
            raise RuntimeError("Rehydrated session but loaded zero accounts (token invalid / expired).")

        return True, "rehydrated"

    except Exception as e:
        _RH = None
        _ACCOUNTS = []
        detail = f"{type(e).__name__}: {e}"
        summary: List[str] = ["Robinhood session rehydrate failed.", f"error={detail}"]
        for pickle_name, _u, _pw in profiles:
            summary.extend(_pickle_debug_lines(pickle_name))
        log_path = _log_session_issue(label="rehydrate_error", text="\n".join(summary))

        msg = (
            "Auth required: cached Robinhood session is invalid/expired. "
            "Run bootstrap first."
        )
        if log_path:
            msg = f"{msg} See log: {log_path}"
        return False, msg


# =============================================================================
# Public API
# =============================================================================

def get_holdings() -> BrokerOutput:
    ok, why = _ensure_session()
    if not ok:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=why)],
            message=why,
        )

    rh = _RH
    outs: List[AccountOutput] = []

    broker_extra: Dict[str, Any] = {
        "profiles_count": int(len(_login_profiles())),
        "accounts_total": int(len(_ACCOUNTS or [])),
        "accounts_ok": 0,
        "accounts_failed": 0,
        "positions_total": 0,
    }

    # If you ever see "(no accounts)" now, it means:
    # - pickle missing OR
    # - cached login failed and returned 0 accounts (we treat that as failure)
    for display_label, acct_num, pickle_name in (_ACCOUNTS or []):
        acct_last4 = _safe_last4(acct_num)
        try:
            # Legacy behavior: call login_with_cache before any authed call
            login_with_cache(rh=rh, pickle_name=pickle_name)

            # Pull account profile row for discovery (safe subset)
            prof_row: Optional[Dict[str, Any]] = None
            try:
                profs = _safe_load_accounts(rh)
                for pr in profs:
                    if not isinstance(pr, dict):
                        continue
                    if str(pr.get("account_number") or "").strip() == str(acct_num or "").strip():
                        prof_row = pr
                        break
            except Exception:
                prof_row = None

            positions = _safe_open_positions(rh, account_number=acct_num) or []
            if not isinstance(positions, list):
                positions = []

            rows: List[HoldingRow] = []
            parsed = 0

            for item in positions:
                if not isinstance(item, dict):
                    continue

                try:
                    qty = float(item.get("quantity") or 0.0)
                except Exception:
                    qty = 0.0

                if qty == 0:
                    continue

                sym = (item.get("symbol") or "").strip().upper()
                sym_source = "explicit"
                if not sym:
                    sym = _symbol_from_instrument(rh, item.get("instrument") or "")
                    sym_source = "instrument_url"

                px = _latest_price(rh, sym)
                px_source = "latest_price" if px is not None else "none"

                hextra: Dict[str, Any] = {}
                try:
                    hextra["keys"] = sorted([str(k) for k in item.keys()])[:200]
                    hextra.update(_flatten_safe(item, max_items=120))
                except Exception:
                    pass

                # include symbol/price sources
                hextra["symbol_source"] = sym_source
                hextra["price_source"] = px_source

                # keep instrument URL as a hint (not secret, but can be long)
                inst_url = (item.get("instrument") or "").strip()
                if inst_url:
                    hextra["instrument_url"] = inst_url[:200] + ("…" if len(inst_url) > 200 else "")

                if px is not None:
                    try:
                        hextra["market_value_calc"] = float(qty) * float(px)
                    except Exception:
                        pass

                rows.append(HoldingRow(symbol=sym, shares=qty, price=px, extra=hextra))
                parsed += 1

            acct_extra: Dict[str, Any] = {
                "account_last4": acct_last4,
                "pickle_name": pickle_name,
                "raw_positions_count": int(len(positions)),
                "positions_parsed": int(parsed),
            }

            # profile discovery (safe scalars only, no account number)
            if isinstance(prof_row, dict):
                try:
                    acct_extra["profile_keys"] = sorted([str(k) for k in prof_row.keys()])[:200]
                    pe = _flatten_safe(prof_row, prefix="profile_", max_items=140)
                    # ensure we never persist full account number even if key slips through
                    pe.pop("profile_account_number", None)
                    pe.pop("profile_accountnumber", None)
                    acct_extra.update(pe)
                except Exception:
                    pass

            outs.append(AccountOutput(account_id=display_label, ok=True, message="", holdings=rows, extra=acct_extra))
            broker_extra["accounts_ok"] = int(broker_extra["accounts_ok"]) + 1
            broker_extra["positions_total"] = int(broker_extra["positions_total"]) + int(len(rows))

        except Exception as e:
            outs.append(
                AccountOutput(
                    account_id=display_label,
                    ok=False,
                    message=str(e),
                    holdings=[],
                    extra={"account_last4": acct_last4, "pickle_name": pickle_name},
                )
            )
            broker_extra["accounts_failed"] = int(broker_extra["accounts_failed"]) + 1

    ok_ct = sum(1 for a in outs if a.ok)
    fail_ct = sum(1 for a in outs if not a.ok)
    state = "success" if ok_ct > 0 and fail_ct == 0 else ("partial" if ok_ct > 0 else "failed")
    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="", extra=broker_extra)


def get_accounts() -> BrokerOutput:
    return get_holdings()


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False) -> BrokerOutput:
    ok, why = _ensure_session()
    if not ok:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=why)],
            message=why,
        )

    rh = _RH

    side_norm = (side or "").lower().strip()
    if side_norm not in ("buy", "sell"):
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid side: {side!r}")

    sym = (symbol or "").upper().strip()
    if not sym:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message="Invalid symbol")

    try:
        q = int(float(qty))
        if q <= 0:
            raise ValueError
    except Exception:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid qty: {qty!r}")

    outs: List[AccountOutput] = []

    log_lines: List[str] = []
    if dry_run:
        log_lines.append("DRY RUN — NO ORDER SUBMITTED")
        log_lines.append(f"broker: {BROKER}")
        log_lines.append(f"time_et: {datetime.now(_ET).isoformat()}")
        log_lines.append(f"requested: side={side_norm.upper()} symbol={sym} qty={q}")
        log_lines.append("")

    # Prefer legacy-style obj.order() if present; fallback to order_buy_market/order_sell_market
    orders_obj = getattr(rh, "orders", None)
    order_fn = getattr(rh, "order", None)
    if not callable(order_fn) and orders_obj is not None:
        order_fn = getattr(orders_obj, "order", None)

    for _acct_i, (display_label, acct_num, pickle_name) in enumerate(_ACCOUNTS or []):
        if _acct_i > 0:
            time.sleep(random.uniform(1.0, 3.0))
        try:
            # Legacy behavior: call login_with_cache before any authed call
            login_with_cache(rh=rh, pickle_name=pickle_name)

            ticket = (
                "DRY RUN — NO ORDER SUBMITTED\n"
                f"side: {side_norm.upper()}\n"
                f"symbol: {sym}\n"
                f"quantity: {q}\n"
                f"order_type: MARKET\n"
                f"tif: DAY\n"
                f"account: {display_label}\n"
                f"account_number: ****{acct_num[-4:] if acct_num else '----'}"
            )

            if dry_run:
                outs.append(AccountOutput(account_id=display_label, ok=True, message=ticket, order_id=None))
                log_lines.append(f"[{display_label}]")
                log_lines.append(ticket)
                log_lines.append("")
                continue

            resp = None

            if callable(order_fn):
                # Legacy order call shape
                try:
                    resp = order_fn(
                        symbol=sym,
                        quantity=q,
                        side=side_norm,
                        account_number=acct_num,
                        timeInForce="gfd",
                    )
                except TypeError:
                    # Some versions differ; fall through to market helpers
                    resp = None

            if resp is None:
                # Fallback: market helpers
                if orders_obj is None:
                    raise RuntimeError("Robinhood orders API not available")

                if side_norm == "buy":
                    fn = getattr(orders_obj, "order_buy_market", None)
                else:
                    fn = getattr(orders_obj, "order_sell_market", None)

                if not callable(fn):
                    raise RuntimeError("Robinhood market order function not available")

                resp = fn(sym, q, account_number=acct_num)

            oid = resp.get("id") if isinstance(resp, dict) else None
            outs.append(AccountOutput(account_id=display_label, ok=True, message="order placed", order_id=oid))

        except Exception as e:
            outs.append(AccountOutput(account_id=display_label, ok=False, message=str(e)))

            if dry_run:
                log_lines.append(f"[{display_label}] ERROR: {e}")
                log_lines.append("")

    ok_ct = sum(1 for a in outs if a.ok)
    fail_ct = sum(1 for a in outs if not a.ok)
    state = "success" if ok_ct > 0 and fail_ct == 0 else ("partial" if ok_ct > 0 else "failed")

    msg = ""
    if dry_run:
        log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
        msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"

    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)


def healthcheck() -> BrokerOutput:
    """
    Non-interactive probe:
      - If pickle exists, cached login + account load
      - Never OTP here; if it can't rehydrate, it fails.
    """
    global _RH, _ACCOUNTS

    try:
        rh, err = _load_rh()
        if err:
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Robinhood", ok=False, message=err)],
                message=err,
            )

        profiles = _login_profiles()
        if not profiles:
            msg = "Missing Robinhood creds. Set ROBINHOOD or ROBINHOOD_USERNAME/ROBINHOOD_PASSWORD."
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Robinhood", ok=False, message=msg)],
                message=msg,
            )

        merged_accounts: List[Tuple[str, str, str]] = []
        seen_numbers = set()

        for pickle_name, _u, _pw in profiles:
            if not _pickle_file(pickle_name).exists():
                continue

            login_with_cache(rh=rh, pickle_name=pickle_name)
            rows = _safe_load_accounts(rh)

            for a in rows:
                acct = (a.get("account_number") or "").strip()
                if not acct or acct in seen_numbers:
                    continue
                seen_numbers.add(acct)

                acct_type = (a.get("brokerage_account_type") or a.get("type") or "ACCOUNT").strip()
                base_label = f"{acct_type} (****{acct[-4:]})"

                if len(profiles) > 1:
                    display = f"{pickle_name} | {base_label}"
                else:
                    display = base_label

                merged_accounts.append((display, acct, pickle_name))

        if not merged_accounts:
            raise RuntimeError("No cached Robinhood session available (missing/expired pickle).")

        _RH = rh
        _ACCOUNTS = merged_accounts
        return BrokerOutput(broker=BROKER, state="success", accounts=[], message="ok")

    except Exception as e:
        _RH = None
        _ACCOUNTS = []
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=str(e))],
            message=str(e),
        )
