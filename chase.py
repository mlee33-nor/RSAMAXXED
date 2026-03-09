from __future__ import annotations

import asyncio
import json
import os
import random
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow, find_browser_executable, cleanup_orphaned_chrome
from modules._2fa_prompt import universal_2fa_prompt
from modules.brokers.chase.chase_normalizer import normalize as chase_normalize

BROKER = "chase"

# --- URL Constants ---
LOGIN_URL = "https://secure05c.chase.com/web/auth/#/logon/logon/chaseOnline"
LANDING_PAGE = "https://secure.chase.com/web/auth/dashboard#/dashboard/overview"
TRADE_ENTRY_URL = "https://secure.chase.com/web/auth/dashboard#/dashboard/oi-trade/equity/entry"

# --- API Endpoints ---
API_ACCOUNT_LIST = "https://secure.chase.com/svc/rl/accounts/secure/v1/dashboard/module/list"
API_POSITIONS = (
    "https://secure.chase.com/svc/wr/dwm/secure/gateway/investments/servicing/"
    "inquiry-maintenance/digital-investment-positions/v2/positions"
)

# Trading
API_QUOTE = (
    "https://secure.chase.com/svc/wr/dwm/secure/gateway/investments/servicing/"
    "inquiry-maintenance/digital-equity-quote/v1/quotes"
)
API_VALIDATE_BUY = (
    "https://secure.chase.com/svc/wr/dwm/secure/gateway/investments/servicing/"
    "investor-servicing/digital-equity-trades/v1/buy-order-validations"
)
API_EXECUTE_BUY = (
    "https://secure.chase.com/svc/wr/dwm/secure/gateway/investments/servicing/"
    "investor-servicing/digital-equity-trades/v1/buy-orders"
)
API_VALIDATE_SELL = (
    "https://secure.chase.com/svc/wr/dwm/secure/gateway/investments/servicing/"
    "investor-servicing/digital-equity-trades/v1/sell-order-validations"
)
API_EXECUTE_SELL = (
    "https://secure.chase.com/svc/wr/dwm/secure/gateway/investments/servicing/"
    "investor-servicing/digital-equity-trades/v1/sell-orders"
)

# In-memory cookie cache (disk persists via cookies.json)
_COOKIES: Optional[Dict[str, str]] = None

OtpProvider = Callable[[str, int], Optional[str]]
_ET = ZoneInfo("America/New_York")


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
    "accountnumber",
    "account_number",
    "acctnumber",
    "acct_number",
    "accountidentifier",
    "selectoridentifier",
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
                    out[f"{key}_{kk}"] = vv
                    n += 1

    return out


def _first_dict_in_list(x: Any) -> Optional[dict]:
    if not isinstance(x, list) or not x:
        return None
    for it in x:
        if isinstance(it, dict):
            return it
    return None


def _as_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except Exception:
        try:
            return float(str(v))
        except Exception:
            return None


def _safe_last4(v: Any) -> str:
    s = str(v or "").strip()
    if not s:
        return "----"
    digits = "".join(c for c in s if c.isdigit())
    if len(digits) >= 4:
        return digits[-4:]
    return (s[-4:] if len(s) >= 4 else s) or "----"


def _is_cancelled(kwargs: Dict[str, Any]) -> bool:
    token = kwargs.get("cancel_event")
    if token is None:
        token = kwargs.get("cancel_token")
    if token is None:
        return False
    try:
        if callable(token):
            return bool(token())
    except Exception:
        pass
    try:
        return bool(token.is_set())
    except Exception:
        return False


# =============================================================================
# Paths / env / deps
# =============================================================================
def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    d = _root_dir() / "sessions" / "chase"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _profile_dir() -> Path:
    d = _sessions_dir() / "profile"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cookie_path() -> Path:
    return _sessions_dir() / "cookies.json"


def _requests():
    try:
        from curl_cffi import requests  # type: ignore
        return requests
    except Exception as e:
        raise RuntimeError(f"Missing dependency curl-cffi: {e}")


def _save_cookies(cookies: Dict[str, str]) -> None:
    payload = {"ts": time.time(), "cookies": cookies}
    _cookie_path().write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _load_cookies() -> Optional[Dict[str, str]]:
    """
    Legacy behavior: profile is the truth.
    We intentionally do NOT load cookies from disk snapshots.
    """
    return None


def _set_cookies(cookies: Dict[str, str]) -> None:
    """
    Legacy behavior: profile is the truth.
    We keep cookies in-memory for the current action.
    Disk write is optional debug only (off by default).
    """
    global _COOKIES
    _COOKIES = {str(k): str(v) for k, v in (cookies or {}).items()}

    # Optional debug artifact ONLY (never truth)
    if (_env("CHASE_WRITE_COOKIE_CACHE") or "false").lower() == "true":
        _save_cookies(_COOKIES)


def _clear_cookies() -> None:
    global _COOKIES
    _COOKIES = None


def _require_session() -> Tuple[Optional[Dict[str, str]], Optional[BrokerOutput]]:
    """
    Probe-only getter. Does NOT login.
    Profile is truth; disk snapshots are never used.
    """
    global _COOKIES

    if not _COOKIES:
        return None, BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message="not authenticated")],
            message="not authenticated",
        )
    return _COOKIES, None


# =============================================================================
# Chase API helpers (authoritative auth check)
# =============================================================================
def _base_headers() -> Dict[str, str]:
    return {
        "accept": "application/json, text/plain, */*",
        "content-type": "application/json",
        "referer": "https://secure.chase.com/web/auth/dashboard",
        "x-jpmc-csrf-token": "NONE",
        "x-jpmc-channel": "id=C30",
        "origin": "https://secure.chase.com",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/143.0.0.0 Safari/537.36"
        ),
    }


def _account_list(cookies: Dict[str, str]) -> Dict[str, Any]:
    req = _requests()
    headers = _base_headers()
    headers["content-type"] = "application/x-www-form-urlencoded; charset=UTF-8"
    data = "context=WEB_CPO_OVERVIEW_DASHBOARD&selectorIdType=ACCOUNT_GROUP"

    r = req.post(
        API_ACCOUNT_LIST,
        headers=headers,
        cookies=cookies,
        data=data,
        impersonate="chrome",
        timeout=60,
    )
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    return r.json() or {}


def _login_verified(cookies: Dict[str, str]) -> None:
    _ = _account_list(cookies)


def _extract_accounts_map(resp_json: Dict[str, Any]) -> List[Tuple[str, str, Optional[float]]]:
    out: List[Tuple[str, str, Optional[float]]] = []
    cache = resp_json.get("cache", []) if isinstance(resp_json, dict) else []
    if not isinstance(cache, list):
        return out

    for item in cache:
        if not isinstance(item, dict):
            continue
        response = (item.get("response") or {})
        if not isinstance(response, dict):
            continue
        inv = response.get("investmentAccountOverviews")
        if not isinstance(inv, list) or not inv:
            continue
        details = inv[0].get("investmentAccountDetails", [])
        if not isinstance(details, list):
            continue

        for acct in details:
            if not isinstance(acct, dict):
                continue
            acc_id = str(acct.get("accountId") or "").strip()
            mask = str(acct.get("mask") or "").strip()
            val = acct.get("accountValue", None)
            try:
                fval = float(val) if val is not None else None
            except Exception:
                fval = None
            if acc_id and mask:
                out.append((mask, acc_id, fval))
    return out


# =============================================================================
# Unauthorized detection
# =============================================================================
def _looks_unauthorized_http(code: Any) -> bool:
    try:
        return int(code) in (401, 403)
    except Exception:
        return False


def _looks_unauthorized_text(msg: str) -> bool:
    t = (msg or "").lower()
    return (
        ("appid:unauthenticationexception" in t)
        or ("unauth" in t)
        or ("unauthorized" in t)
        or ("not authenticated" in t)
        or ("forbidden" in t)
        or ("login required" in t)
    )


# =============================================================================
# Terminal OTP provider
# =============================================================================
def _otp_provider_terminal() -> OtpProvider:
    """OTP provider that prompts in the terminal."""
    def provider(label: str, timeout_s: int) -> Optional[str]:
        try:
            raw = input(universal_2fa_prompt(label) + " ").strip()
            digits = "".join(c for c in raw if c.isdigit())
            return digits if 4 <= len(digits) <= 10 else None
        except (EOFError, KeyboardInterrupt):
            return None
    return provider


# =============================================================================
# Zendriver helpers (login + prime)
# =============================================================================
async def _safe_find(page, selector: str, timeout_s: float = 3.0):
    try:
        return await page.find(selector, timeout=timeout_s)
    except Exception:
        return None


async def _safe_select(page, selector: str, timeout_s: float = 3.0):
    try:
        return await page.select(selector, timeout=timeout_s)
    except Exception:
        return None


async def _js_click(el) -> bool:
    try:
        await el.apply("e => e.click()")
        return True
    except Exception:
        return False


async def _handle_list_verification(page):
    await page.evaluate("""(()=>{const el=document.querySelector('#sms'); if(el) el.click();})();""")
    await page.sleep(1)
    await page.evaluate("""(()=>{const btn=document.querySelector('#next-content'); if(btn) btn.click();})();""")


async def _handle_radio_verification(page):
    await page.evaluate(
        """(()=>{
            const labels=document.querySelectorAll('label');
            for(const lab of labels){
              if((lab.textContent||'').includes('xxx-')){ lab.click(); break; }
            }
        })();"""
    )
    await page.sleep(1)
    await page.evaluate("""(()=>{const btn=document.querySelector('#next-content'); if(btn) btn.click();})();""")


async def _handle_dropdown_verification(page):
    await page.evaluate(
        """(()=>{
            const trigger=document.querySelector('#header-simplerAuth-dropdownoptions-styledselect');
            if(trigger) trigger.click();
        })();"""
    )
    await page.sleep(1)
    await page.evaluate(
        """(()=>{
            const options=document.querySelectorAll('#ul-list-container-simplerAuth-dropdownoptions-styledselect a.option');
            for(const opt of options){
              if(!(opt.className||'').includes('groupLabelContainer')){ opt.click(); break; }
            }
        })();"""
    )
    await page.sleep(1)
    await page.evaluate("""(()=>{const btn=document.querySelector('#requestIdentificationCode'); if(btn) btn.click();})();""")


async def _handle_push_verification(page, *, notify_push_fn=None):
    await page.evaluate("""(()=>{const el=document.querySelector('#inAppSend'); if(el) el.click();})();""")
    await page.sleep(1)
    await page.evaluate("""(()=>{const btn=document.querySelector('#next-content'); if(btn) btn.click();})();""")
    if callable(notify_push_fn):
        try:
            notify_push_fn()
        except Exception:
            pass


async def _cookies_from_browser(browser) -> Dict[str, str]:
    cookies = await browser.cookies.get_all()
    return {c.name: c.value for c in cookies}


async def _wait_for_auth(browser, page, *, timeout_s: int = 180) -> Dict[str, str]:
    deadline = time.time() + max(30, int(timeout_s))
    last_err: Optional[str] = None

    while time.time() < deadline:
        try:
            await page.get(LANDING_PAGE)
        except Exception:
            pass

        await page.sleep(4)

        try:
            cdict = await _cookies_from_browser(browser)
        except Exception as e:
            last_err = f"cookie read failed: {e}"
            continue

        try:
            _login_verified(cdict)
            return cdict
        except Exception as e:
            last_err = str(e)
            continue

    raise RuntimeError(
        f"Did not reach authenticated state via API within timeout. "
        f"Last error: {last_err or 'unknown'}"
    )


async def _prime_trade_context(page) -> None:
    """
    Legacy behavior: warm the trade entry page so Chase mints trade-context cookies/tokens.
    """
    try:
        await page.get(TRADE_ENTRY_URL)
        await page.sleep(6)
    except Exception:
        # Best-effort only.
        pass


async def _async_login(
    username: str,
    password: str,
    otp_provider: Optional[OtpProvider],
    *,
    prime_trade: bool = False,
    headless_override: Optional[bool] = None,
    notify_push: bool = True,
    notify_push_fn=None,
) -> Dict[str, str]:
    try:
        import zendriver as uc  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Missing dependency zendriver: {e}")

    headless = (_env("CHASE_HEADLESS") or _env("HEADLESS") or "true").lower() == "true"
    if headless_override is not None:
        headless = bool(headless_override)
    browser_args = [
        "--no-sandbox",
        "--force-device-scale-factor=0.8",
        "--window-size=1920,1080",
        "--disable-session-crashed-bubble",
        "--disable-infobars",
        "--disable-features=TranslateUI,VizDisplayCompositor",
        "--no-first-run",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
    ]
    if headless:
        browser_args.insert(0, "--headless=new")

    cleanup_orphaned_chrome(_profile_dir())
    browser = await uc.start(browser_args=browser_args, user_data_dir=str(_profile_dir()), browser_executable_path=find_browser_executable())
    try:
        page = browser.tabs[0] if browser.tabs else await browser()

        # Quick path: already logged in
        try:
            c0 = await _cookies_from_browser(browser)
            _login_verified(c0)

            if prime_trade:
                await _prime_trade_context(page)
                c1 = await _cookies_from_browser(browser)
                _login_verified(c1)
                return c1

            return c0
        except Exception:
            pass

        await page.get(LOGIN_URL)
        await page.sleep(2)

        user_box = await _safe_find(page, "#userId-input-field-input", timeout_s=8)
        pass_box = await _safe_find(page, "#password-input-field-input", timeout_s=8)
        if not user_box or not pass_box:
            raise RuntimeError("Chase login fields not found")

        await user_box.clear_input_by_deleting()
        await user_box.send_keys(username)
        await pass_box.send_keys(password)

        btn = await _safe_find(page, "#signin-button", timeout_s=8)
        if not btn:
            raise RuntimeError("Sign-in button not found")
        await btn.mouse_click()
        await page.sleep(4)

        start = time.time()
        push_notified = False

        while (time.time() - start) < 180:
            # If API already works, we're done
            try:
                c_try = await _cookies_from_browser(browser)
                _login_verified(c_try)

                if prime_trade:
                    await _prime_trade_context(page)
                    c_prime = await _cookies_from_browser(browser)
                    _login_verified(c_prime)
                    return c_prime

                return c_try
            except Exception:
                pass

            list_sms = await _safe_find(page, "#sms", timeout_s=2)
            if list_sms:
                await _handle_list_verification(page)
                await page.sleep(3)
                continue

            radio_group = await _safe_select(page, "#eligibleTextContacts", timeout_s=2)
            if radio_group:
                await _handle_radio_verification(page)
                await page.sleep(3)
                continue

            dropdown = await _safe_find(page, "#header-simplerAuth-dropdownoptions-styledselect", timeout_s=2)
            if dropdown:
                await _handle_dropdown_verification(page)
                await page.sleep(3)
                continue

            push = await _safe_find(page, "#inAppSend", timeout_s=2)
            if push:
                def _notify_once():
                    nonlocal push_notified
                    if (not notify_push) or push_notified:
                        return
                    push_notified = True
                    if callable(notify_push_fn):
                        notify_push_fn()

                await _handle_push_verification(page, notify_push_fn=_notify_once)
                await page.sleep(5)
                continue

            otp_input = await _safe_find(page, "#otpInput", timeout_s=2)
            if otp_input:
                if otp_provider is None:
                    raise RuntimeError("Chase OTP required but no OTP provider available")

                code = otp_provider("Chase", 300)
                if not code:
                    raise RuntimeError("OTP not received")

                await otp_input.send_keys(str(code))

                next_btn = await _safe_find(page, "#next-content", timeout_s=6)
                if next_btn:
                    try:
                        await next_btn.click()
                    except Exception:
                        await _js_click(next_btn)

                await page.sleep(5)
                continue

            await page.sleep(1)

        cookies = await _wait_for_auth(browser, page, timeout_s=180)
        if prime_trade:
            await _prime_trade_context(page)
            cookies = await _cookies_from_browser(browser)
            _login_verified(cookies)
        return cookies

    finally:
        try:
            for tab in getattr(browser, "tabs", []) or []:
                try:
                    await tab.close()
                except Exception:
                    pass
            await browser.stop()
        except Exception:
            pass


# =============================================================================
# Legacy-style session ensure (profile is truth)
# =============================================================================
def ensure_session(*, prime_trade: bool = False, **kwargs: Any) -> BrokerOutput:
    user = _env("CHASE_USERNAME")
    pw = _env("CHASE_PASSWORD")
    if not user or not pw:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message="Missing CHASE_USERNAME or CHASE_PASSWORD")],
            message="Missing credentials",
        )

    force_headed = bool(kwargs.get("debug") or False)

    otp_provider = _otp_provider_terminal()

    local_loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(local_loop)
        cookies = local_loop.run_until_complete(
            _async_login(
                user,
                pw,
                otp_provider,
                prime_trade=prime_trade,
                headless_override=(False if force_headed else None),
                notify_push=True,
                notify_push_fn=lambda: print("Chase sent a push notification. Approve it in your Chase app."),
            )
        )
        _set_cookies(cookies)
        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[AccountOutput(account_id="Chase", ok=True, message="ok")],
            message="ok",
        )
    except Exception as e:
        _clear_cookies()
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message=str(e))],
            message=str(e),
        )
    finally:
        try:
            local_loop.close()
        except Exception:
            pass


# =============================================================================
# DRY RUN log helpers (trade)
# =============================================================================
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
# Public interface expected by Idle Markets
# =============================================================================
def bootstrap(*args, **kwargs) -> BrokerOutput:
    """
    Kept for compatibility only. Not intended as a required bot-level flow.
    """
    prime_trade = bool(kwargs.pop("prime_trade", False))
    return ensure_session(prime_trade=prime_trade, **kwargs)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return get_holdings(*args, **kwargs)


def get_holdings(*args, **kwargs) -> BrokerOutput:
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message="Cancelled before start")],
            message="Cancelled",
        )

    # Legacy-style: rehydrate every command
    boot = ensure_session(prime_trade=False, **kwargs)
    if boot.state not in ("success", "partial"):
        return boot

    def _attempt() -> BrokerOutput:
        cookies, err = _require_session()
        if err:
            return err

        # map accounts
        try:
            resp = _account_list(cookies)
            accts = _extract_accounts_map(resp)
            if not accts:
                return BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Chase", ok=False, message="No accounts returned")],
                    message="No accounts returned",
                )
        except Exception as e:
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Chase", ok=False, message=str(e))],
                message=str(e),
            )

        req = _requests()
        outs: List[AccountOutput] = []
        total_value = 0.0
        total_seen = False

        broker_extra: Dict[str, Any] = {
            "accounts_count": int(len(accts)),
        }

        for mask, acc_id, acc_val in accts:
            if _is_cancelled(kwargs):
                break
            if acc_val is not None:
                total_value += float(acc_val)
                total_seen = True

            acct_line = f"{mask} = ${acc_val:.2f}" if acc_val is not None else f"{mask} = ?"

            payload = {
                "selectorIdentifier": acc_id,
                "selectorCode": "ACCOUNT",
                "taxLotIndicator": False,
                "currencyCode": "",
                "voluntaryCorporateActionIndicator": False,
                "intradayUpdateIndicator": True,
                "pinnedPositionIndicator": True,
            }

            try:
                r = req.post(
                    API_POSITIONS,
                    headers=_base_headers(),
                    cookies=cookies,
                    json=payload,
                    impersonate="chrome",
                    timeout=60,
                )

                if _looks_unauthorized_http(getattr(r, "status_code", 0)):
                    return BrokerOutput(
                        broker=BROKER,
                        state="failed",
                        accounts=[AccountOutput(account_id="Chase", ok=False, message=f"HTTP {r.status_code}: unauthorized")],
                        message=f"HTTP {r.status_code}: unauthorized",
                    )

                if r.status_code != 200:
                    outs.append(
                        AccountOutput(
                            account_id=acct_line,
                            ok=False,
                            message=f"HTTP {r.status_code}: {r.text[:120]}",
                            holdings=[],
                            extra={
                                "account_mask": str(mask),
                                "account_value_reported": float(acc_val) if acc_val is not None else None,
                                "positions_http_status": int(r.status_code),
                            },
                        )
                    )
                    continue

                data = r.json() or {}
                rows: List[HoldingRow] = []

                raw_positions = data.get("positions") or []
                if not isinstance(raw_positions, list):
                    raw_positions = []

                cash_skipped = 0
                parsed = 0

                for pos in raw_positions:
                    if not isinstance(pos, dict):
                        continue

                    # skip “Cash” positions (legacy behavior)
                    long_name = str(pos.get("instrumentLongName") or "")
                    if "Cash" in long_name:
                        cash_skipped += 1
                        continue

                    # --- build symbol ---
                    sym = "UNKNOWN"
                    comps = pos.get("positionComponents", []) or []
                    if isinstance(comps, list) and comps:
                        comp0 = comps[0] if isinstance(comps[0], dict) else None
                        if isinstance(comp0, dict):
                            sid = comp0.get("securityIdDetail", [{}]) or [{}]
                            if isinstance(sid, list) and sid:
                                d0 = sid[0] if isinstance(sid[0], dict) else None
                                if isinstance(d0, dict):
                                    sym = d0.get("symbolSecurityIdentifier", "UNKNOWN") or "UNKNOWN"
                                    # if available, stash additional identifiers safely
                                    # (note: denylist blocks account-ish keys)
                                    # we do NOT persist the full selectorIdentifier/accountIdentifier anywhere
                    sym = str(sym).strip().upper() or "UNKNOWN"

                    # --- quantity ---
                    qty = _as_float(pos.get("tradedUnitQuantity")) or 0.0
                    if qty == 0.0:
                        continue

                    # --- price ---
                    price = pos.get("marketPrice", {}) or {}
                    px = _as_float(price.get("baseValueAmount"))

                    # --- holding extras (safe discovery) ---
                    hextra: Dict[str, Any] = {}
                    try:
                        hextra["keys"] = sorted([str(k) for k in pos.keys()])[:200]
                        hextra.update(_flatten_safe(pos, max_items=120))
                        if isinstance(price, dict):
                            hextra.update(_flatten_safe(price, prefix="marketPrice_", max_items=40))
                    except Exception:
                        pass

                    # one-level peek into first positionComponent / securityIdDetail (safe)
                    try:
                        comp0 = _first_dict_in_list(comps)
                        if isinstance(comp0, dict):
                            hextra["positionComponents_count"] = int(len(comps)) if isinstance(comps, list) else 0
                            hextra.update(_flatten_safe(comp0, prefix="comp0_", max_items=60))

                            sid_list = comp0.get("securityIdDetail")
                            sid0 = _first_dict_in_list(sid_list)
                            if isinstance(sid0, dict):
                                hextra["securityIdDetail_count"] = int(len(sid_list)) if isinstance(sid_list, list) else 0
                                hextra.update(_flatten_safe(sid0, prefix="sid0_", max_items=60))
                    except Exception:
                        pass

                    # computed helpers (safe)
                    if px is not None:
                        hextra["market_value_calc"] = float(qty) * float(px)

                    rows.append(HoldingRow(symbol=sym, shares=float(qty), price=px, extra=hextra))
                    parsed += 1

                acct_extra: Dict[str, Any] = {
                    "account_mask": str(mask),
                    "account_id_last4": _safe_last4(acc_id),
                    "account_value_reported": float(acc_val) if acc_val is not None else None,
                    "raw_positions_count": int(len(raw_positions)),
                    "cash_positions_skipped": int(cash_skipped),
                    "positions_parsed": int(parsed),
                }

                # safe payload discovery at account level (top-level keys only)
                try:
                    acct_extra["payload_keys"] = sorted([str(k) for k in data.keys()])[:200]
                    acct_extra.update(_flatten_safe(data, prefix="payload_", max_items=120))
                except Exception:
                    pass

                outs.append(AccountOutput(account_id=acct_line, ok=True, message="", holdings=rows, extra=acct_extra))

            except Exception as e:
                outs.append(
                    AccountOutput(
                        account_id=acct_line,
                        ok=False,
                        message=str(e),
                        holdings=[],
                        extra={
                            "account_mask": str(mask),
                            "account_id_last4": _safe_last4(acc_id),
                            "account_value_reported": float(acc_val) if acc_val is not None else None,
                        },
                    )
                )

        if _is_cancelled(kwargs):
            state = "partial" if any(a.ok for a in outs) else "failed"
            return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="Cancelled", extra=broker_extra)

        ok_ct = sum(1 for a in outs if a.ok)
        fail_ct = sum(1 for a in outs if not a.ok)
        state = "success" if ok_ct > 0 and fail_ct == 0 else ("partial" if ok_ct > 0 else "failed")
        msg = f"Total Value = ${total_value:.2f}" if total_seen else "Total Value = ?"

        broker_extra["total_value_reported"] = float(total_value) if total_seen else None
        broker_extra["accounts_ok"] = int(ok_ct)
        broker_extra["accounts_failed"] = int(fail_ct)

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg, extra=broker_extra)

    out1 = _attempt()
    if out1.state != "failed":
        return chase_normalize(out1)

    if _looks_unauthorized_text(out1.message) or any(_looks_unauthorized_text(a.message) for a in (out1.accounts or [])):
        boot2 = ensure_session(prime_trade=False, **kwargs)
        if boot2.state not in ("success", "partial"):
            return boot2
        return chase_normalize(_attempt())

    return chase_normalize(out1)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message="Cancelled before start")],
            message="Cancelled",
        )

    # NOTE: trade path unchanged (kept verbatim from your version)
    # Legacy-style: rehydrate + prime trade context before trading
    boot = ensure_session(prime_trade=True, **kwargs)
    if boot.state not in ("success", "partial"):
        return boot

    def _parse_qty_int(qty_raw: Any) -> Optional[int]:
        try:
            f = float(qty_raw)
            if f <= 0:
                return None
            if int(f) != f:
                return None
            return int(f)
        except Exception:
            return None

    def _dedupe_keep_order(xs: List[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for x in xs:
            s = (x or "").strip()
            if not s:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    def _as_str_list(v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v] if v.strip() else []
        if isinstance(v, (list, tuple)):
            out: List[str] = []
            for item in v:
                if item is None:
                    continue
                s = str(item).strip()
                if s:
                    out.append(s)
            return out
        s = str(v).strip()
        return [s] if s else []

    def _extract_error_messages(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        msgs: List[str] = []
        for k in ("tradeErrorMessages", "errorMessages", "errors", "error", "messages"):
            v = payload.get(k)
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        msgs.append(item)
                    elif isinstance(item, dict):
                        for kk in ("message", "title", "detail", "code", "reason", "description"):
                            if item.get(kk):
                                msgs.append(str(item.get(kk)))
                        src = item.get("source")
                        if isinstance(src, dict):
                            for sv in src.values():
                                if sv:
                                    msgs.append(str(sv))
                    else:
                        msgs.extend(_as_str_list(item))
            elif isinstance(v, dict):
                for kk in ("message", "title", "detail", "code", "reason", "description"):
                    if v.get(kk):
                        msgs.append(str(v.get(kk)))
            else:
                msgs.extend(_as_str_list(v))

        code = payload.get("code")
        if code is not None and str(code).strip() and str(code).strip() != "0":
            msgs.append(f"code={code}")

        status = payload.get("status")
        if status is not None and str(status).strip() and str(status).strip() not in ("200", "OK", "ok"):
            msgs.append(f"status={status}")

        return _dedupe_keep_order(msgs)

    def _extract_warnings(payload: Any) -> List[str]:
        if not isinstance(payload, dict):
            return []
        msgs: List[str] = []
        for k in ("tradeWarningMessages", "tradeDisclosureMessages", "warningMessages", "disclosureMessages"):
            msgs.extend(_as_str_list(payload.get(k)))
        return _dedupe_keep_order(msgs)

    def _parse_order_id(payload: Any) -> Optional[str]:
        if not isinstance(payload, dict):
            return None
        for k in ("orderIdentifier", "orderId", "orderID", "order_id"):
            v = payload.get(k)
            if v is None:
                continue
            s = str(v).strip()
            if s:
                return s
        return None

    def _dig(d: Any, *path: str) -> Any:
        cur = d
        for k in path:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(k)
        return cur

    def _parse_order_status(payload: Any) -> str:
        if not isinstance(payload, dict):
            return ""
        for k in (
            "orderStatusCode",
            "orderStatus",
            "tradeStatusCode",
            "tradeStatus",
            "status",
            "orderState",
            "executionStatus",
            "executionState",
        ):
            v = payload.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, dict):
                for kk in ("code", "name", "value", "status"):
                    vv = v.get(kk)
                    if isinstance(vv, str) and vv.strip():
                        return vv.strip()

        for path in (
            ("order", "status"),
            ("order", "orderStatus"),
            ("order", "orderStatusCode"),
            ("orderStatus", "code"),
            ("orderStatus", "name"),
            ("trade", "status"),
            ("trade", "tradeStatus"),
            ("trade", "tradeStatusCode"),
        ):
            v = _dig(payload, *path)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, dict):
                for kk in ("code", "name", "value", "status"):
                    vv = v.get(kk)
                    if isinstance(vv, str) and vv.strip():
                        return vv.strip()
        return ""

    def _join(msgs: List[str], fallback: str) -> str:
        msgs = _dedupe_keep_order(msgs)
        return "; ".join(msgs) if msgs else fallback

    side_norm = (side or "").strip().lower()
    sym = (symbol or "").strip().upper()
    qty_int = _parse_qty_int(qty)

    if side_norm not in ("buy", "sell"):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message=f"Invalid side: {side!r}")],
            message="Invalid side",
        )
    if not sym:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message="Invalid symbol")],
            message="Invalid symbol",
        )
    if qty_int is None:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message=f"Invalid qty (whole shares only): {qty!r}")],
            message="Invalid qty",
        )

    def _attempt_trade() -> BrokerOutput:
        cookies, err = _require_session()
        if err:
            return err

        log_lines: List[str] = []
        if bool(dry_run):
            log_lines.append("DRY RUN — NO ORDER SUBMITTED")
            log_lines.append(f"broker: {BROKER}")
            log_lines.append(f"time_et: {datetime.now(_ET).isoformat()}")
            log_lines.append(f"requested: side={side_norm.upper()} symbol={sym} qty={qty_int}")
            log_lines.append("")

        # accounts map
        try:
            resp = _account_list(cookies)
            accounts = _extract_accounts_map(resp)
            if not accounts:
                raise RuntimeError("No accounts returned")
        except Exception as e:
            if dry_run:
                log_lines.append(f"account_map_error: {e}")
                log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
                return BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Chase", ok=False, message=str(e))],
                    message=f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}",
                )
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Chase", ok=False, message=str(e))],
                message=str(e),
            )

        req = _requests()

        # quote once
        try:
            qresp = req.get(
                f"{API_QUOTE}?security-symbol-code={sym}&security-validate-indicator=true&dollar-based-trading-include-indicator=true",
                headers=_base_headers(),
                cookies=cookies,
                impersonate="chrome",
                timeout=60,
            )
            if qresp.status_code != 200:
                raise RuntimeError(f"Quote HTTP {qresp.status_code}: {qresp.text[:200]}")
            qd = qresp.json() or {}
            px = float(qd.get("lastTradePriceAmount") or 0.0) or 0.0
            if px == 0.0:
                px = float(qd.get("askPriceAmount") or 0.0) if side_norm == "buy" else float(qd.get("bidPriceAmount") or 0.0)
            if px == 0.0:
                raise RuntimeError("Price unavailable")
        except Exception as e:
            if dry_run:
                log_lines.append(f"quote_error: {e}")
                log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
                return BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Chase", ok=False, message=str(e))],
                    message=f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}",
                )
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Chase", ok=False, message=str(e))],
                message=str(e),
            )

        order_type = "MARKET"
        tif = "DAY"
        session = "CORE"

        OK_STATUSES = {"SUBMITTED", "ACCEPTED", "WORKING", "OPEN", "PENDING", "RECEIVED", "QUEUED", "NEW"}
        FILLED_STATUSES = {"FILLED", "EXECUTED", "COMPLETED"}
        BAD_STATUSES = {"REJECTED", "CANCELLED", "CANCELED", "FAILED", "ERROR", "EXPIRED", "VOID"}

        outs: List[AccountOutput] = []

        for _acct_i, (mask, acc_id, _acc_val) in enumerate(accounts):
            if _is_cancelled(kwargs):
                break
            if _acct_i > 0:
                time.sleep(random.uniform(1.0, 3.0))
            acct_label = str(mask)

            try:
                if side_norm == "buy":
                    url_validate = API_VALIDATE_BUY
                    url_execute = API_EXECUTE_BUY
                    payload_validate: Dict[str, Any] = {
                        "accountIdentifier": int(acc_id),
                        "marketPriceAmount": px,
                        "orderQuantity": int(qty_int),
                        "accountTypeCode": "CASH",
                        "timeInForceCode": tif,
                        "securitySymbolCode": sym,
                        "tradeChannelName": "DESKTOP",
                        "dollarBasedTradingEligibleIndicator": False,
                        "orderTypeCode": order_type,
                    }
                else:
                    url_validate = API_VALIDATE_SELL
                    url_execute = API_EXECUTE_SELL
                    payload_validate = {
                        "accountIdentifier": int(acc_id),
                        "marketPriceAmount": px,
                        "orderQuantity": int(qty_int),
                        "accountTypeCode": "CASH",
                        "timeInForceCode": tif,
                        "securitySymbolCode": sym,
                        "tradeChannelName": "DESKTOP",
                        "dollarBasedTradingEligibleIndicator": False,
                        "orderTypeCode": order_type,
                        "tradeActionName": "SELL",
                    }

                rv = req.post(
                    url_validate,
                    headers=_base_headers(),
                    cookies=cookies,
                    json=payload_validate,
                    impersonate="chrome",
                    timeout=60,
                )
                if rv.status_code != 200:
                    msg = f"Rejected — Validation HTTP {rv.status_code}: {rv.text[:200]}"
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=msg))
                    if dry_run:
                        log_lines.append(f"[{acct_label}] {msg}")
                        log_lines.append("")
                    continue

                try:
                    val_data = rv.json() or {}
                except Exception:
                    msg = f"Rejected — Validation returned non-JSON: {rv.text[:200]}"
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=msg))
                    if dry_run:
                        log_lines.append(f"[{acct_label}] {msg}")
                        log_lines.append("")
                    continue

                val_errors = _extract_error_messages(val_data)
                if val_errors:
                    msg = f"Rejected — {_join(val_errors, 'Validation failed')}"
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=msg))
                    if dry_run:
                        log_lines.append(f"[{acct_label}] {msg}")
                        log_lines.append("")
                    continue

                exchange_id = val_data.get("financialInformationExchangeSystemOrderIdentifier")
                if not exchange_id:
                    warns = _extract_warnings(val_data)
                    msg = f"Rejected — {_join(warns, 'Validation returned no exchange identifier')}"
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=msg))
                    if dry_run:
                        log_lines.append(f"[{acct_label}] {msg}")
                        log_lines.append("")
                    continue

                if dry_run:
                    ticket = "\n".join([
                        "DRY RUN — NO ORDER SUBMITTED",
                        f"side: {side_norm.upper()}",
                        f"symbol: {sym}",
                        f"quantity: {qty_int}",
                        f"order_type: {order_type}",
                        f"tif: {tif}",
                        f"session: {session}",
                        f"market_price_amount: {px}",
                        f"account_mask: {acct_label}",
                        f"account_id: {acc_id}",
                        f"validate_endpoint: {url_validate}",
                        f"execute_endpoint: {url_execute}",
                        f"exchange_id: {exchange_id}",
                    ])
                    outs.append(AccountOutput(account_id=acct_label, ok=True, message=ticket, order_id=str(exchange_id)))
                    log_lines.append(f"[{acct_label}]")
                    log_lines.append(ticket)
                    log_lines.append("")
                    continue

                payload_execute = dict(payload_validate)
                payload_execute["financialInformationExchangeSystemOrderIdentifier"] = exchange_id

                rx = req.post(
                    url_execute,
                    headers=_base_headers(),
                    cookies=cookies,
                    json=payload_execute,
                    impersonate="chrome",
                    timeout=60,
                )
                if rx.status_code != 200:
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Rejected — Execution HTTP {rx.status_code}: {rx.text[:200]}"))
                    continue

                try:
                    exec_data = rx.json() or {}
                except Exception:
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Rejected — Execution returned non-JSON: {rx.text[:200]}"))
                    continue

                exec_errors = _extract_error_messages(exec_data)
                if exec_errors:
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Rejected — {_join(exec_errors, 'Execution failed')}"))
                    continue

                oid = _parse_order_id(exec_data)
                status = _parse_order_status(exec_data).strip().upper()

                if not oid:
                    warns = _extract_warnings(exec_data)
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Unknown result — {_join(warns, 'No orderIdentifier returned')}; check Chase UI"))
                    continue

                if status in BAD_STATUSES:
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Rejected — {status.lower()} (order_id={oid})", order_id=str(oid)))
                    continue

                if status in FILLED_STATUSES:
                    outs.append(AccountOutput(account_id=acct_label, ok=True, message=f"Filled (order_id={oid})", order_id=str(oid)))
                    continue

                if status in OK_STATUSES:
                    outs.append(AccountOutput(account_id=acct_label, ok=True, message=f"Submitted (order_id={oid})", order_id=str(oid)))
                    continue

                warns = _extract_warnings(exec_data)
                extra = _join(warns, "")
                msg = f"Submitted (status unavailable) (order_id={oid})"
                if extra:
                    msg += f" — Warnings: {extra}"
                outs.append(AccountOutput(account_id=acct_label, ok=True, message=msg, order_id=str(oid)))

            except Exception as e:
                outs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Unknown result — {e}"))
                if dry_run:
                    log_lines.append(f"[{acct_label}] ERROR: {e}")
                    log_lines.append("")

        if _is_cancelled(kwargs):
            state = "partial" if any(a.ok for a in outs) else "failed"
            msg = "Cancelled"
            if dry_run:
                log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
                msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path} | Cancelled"
            return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)

        ok_ct = sum(1 for a in outs if a.ok)
        state = "success" if ok_ct == len(outs) and outs else ("partial" if ok_ct > 0 else "failed")

        msg = ""
        if dry_run:
            log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
            msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)

    out1 = _attempt_trade()
    if out1.state != "failed":
        return chase_normalize(out1)

    if _looks_unauthorized_text(out1.message) or any(_looks_unauthorized_text(a.message) for a in (out1.accounts or [])):
        boot2 = ensure_session(prime_trade=True, **kwargs)
        if boot2.state not in ("success", "partial"):
            return boot2
        return chase_normalize(_attempt_trade())

    return chase_normalize(out1)
