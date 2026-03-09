# modules/brokers/sofi/sofi.py
from __future__ import annotations

import asyncio
import json
import os
import random
import time
import uuid
from datetime import datetime, time as dtime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

import pytz

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow, display_path, find_browser_executable, cleanup_orphaned_chrome
from modules._2fa_prompt import universal_2fa_prompt
from modules import broker_logging as BLOG

BROKER = "sofi"

_COOKIES: Optional[Dict[str, str]] = None
_CSRF: Optional[str] = None

OtpProvider = Callable[[str, int], Optional[str]]


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
    # account identifiers / internal ids
    "accountid",
    "account_id",
    "apexaccountid",
    "apex_account_id",
    "internalaccountid",
    "internal_account_id",
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


def _safe_last4(s: Any) -> str:
    x = str(s or "").strip()
    if not x:
        return "----"
    digits = "".join(c for c in x if c.isdigit())
    if len(digits) >= 4:
        return digits[-4:]
    return (x[-4:] if len(x) >= 4 else x) or "----"


# =============================================================================
# Paths + env
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _headless_default() -> bool:
    return ((_env("SOFI_HEADLESS") or _env("HEADLESS") or "true").lower() == "true")


def _root_dir() -> Path:
    # .../modules/brokers/sofi/sofi.py -> root is 3 parents up
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    d = _root_dir() / "sessions" / "sofi"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _logs_dir() -> Path:
    d = _root_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _log_ctx() -> Dict[str, Any]:
    return {"log_dir": _logs_dir()}


def _profile_dir() -> Path:
    d = _sessions_dir() / "profile"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cookie_path() -> Path:
    return _sessions_dir() / "cookies.json"


# =============================================================================
# HTTP helpers
# =============================================================================

def _csrf_from_cookies(cookies: Dict[str, str]) -> Optional[str]:
    return cookies.get("SOFI_CSRF_COOKIE") or cookies.get("SOFI_R_CSRF_TOKEN")


def _headers(csrf_token: Optional[str] = None) -> Dict[str, str]:
    h = {
        "accept": "application/json, application/problem+json",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "dnt": "1",
        "priority": "u=1, i",
        "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Brave";v="140"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "sec-gpc": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "x-requested-with": "XMLHttpRequest",
    }
    if csrf_token:
        h["csrf-token"] = csrf_token
        h["origin"] = "https://www.sofi.com"
        h["referer"] = "https://www.sofi.com/"
    return h


def _requests():
    try:
        from curl_cffi import requests  # type: ignore
        return requests
    except Exception as e:
        raise RuntimeError(f"Missing dependency curl-cffi: {e}")


def _save_cookies_to_disk(cookies: Dict[str, str]) -> None:
    # Optional cache only (NOT the source of truth)
    payload = {"ts": datetime.utcnow().isoformat(), "cookies": cookies}
    _cookie_path().write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_cookies_from_disk() -> None:
    """
    Probe-only utility.
    IMPORTANT: action paths must NOT rely on this snapshot to proceed.
    """
    global _COOKIES, _CSRF
    p = _cookie_path()
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        cookies = data.get("cookies") or {}
        if isinstance(cookies, dict) and cookies:
            _COOKIES = {str(k): str(v) for k, v in cookies.items()}
            _CSRF = _csrf_from_cookies(_COOKIES)
    except Exception:
        return


def _require_session(*, allow_disk: bool = False) -> Optional[str]:
    """
    Chase-style rule:
      - For action paths: cookies MUST come from live browser rehydrate (profile truth).
      - Disk cookies.json is never authoritative for actions.
      - Probe-only healthcheck may allow disk snapshot validation.
    """
    global _COOKIES, _CSRF

    if (_COOKIES is None or _CSRF is None) and allow_disk:
        _load_cookies_from_disk()

    if _COOKIES is None or _CSRF is None:
        return "Unauthorized: Session not initialized"
    return None


def _auth_sanity_check(cookies: Dict[str, str]) -> None:
    """
    Source of truth:
      GET https://www.sofi.com/wealth/backend/v1/json/accounts
    """
    req = _requests()
    csrf = _csrf_from_cookies(cookies)
    r = req.get(
        "https://www.sofi.com/wealth/backend/v1/json/accounts",
        impersonate="chrome",
        headers=_headers(csrf),
        cookies=cookies,
        timeout=120,
    )
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code} - {r.text[:200]}")


def _is_unauthorized_text(s: str) -> bool:
    t = (s or "").lower()
    return ("http 401" in t) or ("unauthorized" in t) or ("unauthentication" in t)


def _trading_session() -> str:
    et = pytz.timezone("America/New_York")
    now = datetime.now(et)
    if now.weekday() >= 5:
        return "CORE_HOURS"
    core_start = dtime(9, 30)
    core_end = dtime(16, 0)
    return "CORE_HOURS" if core_start <= now.time() <= core_end else "ALL_HOURS"


def _to_float(x) -> Optional[float]:
    try:
        if x is None:
            return None
        return float(x)
    except Exception:
        return None


def _mask_last4(s: str) -> str:
    s = (s or "").strip()
    return f"****{s[-4:]}" if len(s) >= 4 else "****"


def _totp_now(secret: str) -> Optional[str]:
    secret = (secret or "").strip().replace(" ", "")
    if not secret or secret.lower() in ("na", "none", "false", "0"):
        return None
    try:
        import pyotp  # type: ignore
        return pyotp.TOTP(secret).now()
    except Exception:
        return None


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
# Zendriver login (UI) -> cookies -> backend auth check
# =============================================================================

async def _safe_select(page, selector: str, timeout_s: float = 3.0):
    try:
        return await page.select(selector, timeout=timeout_s)
    except Exception:
        return None


async def _first_select(page, selectors: List[str], timeout_s: float = 5.0):
    for sel in selectors:
        el = await _safe_select(page, sel, timeout_s=timeout_s)
        if el:
            return el
    return None


async def _click_first_text(page, texts: List[str]) -> bool:
    for t in texts:
        try:
            btn = await page.find(t, best_match=True)
            if btn:
                await btn.mouse_click()
                return True
        except Exception:
            continue
    return False


async def _cookies_from_browser(browser) -> Dict[str, str]:
    cookies = await browser.cookies.get_all()
    return {c.name: c.value for c in cookies}


async def _force_login_flow(
    browser,
    page,
    *,
    username: str,
    password: str,
    totp_secret: str,
    otp_provider: Optional[OtpProvider],
) -> None:
    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="session",
            label="login_flow_start",
            filename_prefix="session_stage",
            text="SoFi login flow start",
            secrets=[username, password, totp_secret],
        )
    except Exception:
        pass

    await page.get("https://www.sofi.com/login/")
    await page.sleep(2)

    user_selectors = [
        "input#username",
        "input[id=username]",
        "input[name=username]",
        "input[name=email]",
        "input[type=email]",
        "input[autocomplete=username]",
        "input[autocomplete='username']",
    ]
    pass_selectors = [
        "input#password",
        "input[name=password]",
        "input[type=password]",
        "input[autocomplete='current-password']",
        "input[autocomplete=current-password]",
    ]

    user_el = await _first_select(page, user_selectors, timeout_s=8)
    if not user_el:
        await _click_first_text(page, ["Log In", "Log in", "Sign In", "Sign in"])
        await page.sleep(2)
        user_el = await _first_select(page, user_selectors, timeout_s=8)

    if not user_el:
        raise RuntimeError("Could not locate SoFi login form (username/email input not found).")

    try:
        await user_el.clear_input()
    except Exception:
        pass
    await user_el.send_keys(username)

    pass_el = await _first_select(page, pass_selectors, timeout_s=2)
    if not pass_el:
        await _click_first_text(page, ["Continue", "Next", "Log In", "Log in", "Sign In", "Sign in"])
        await page.sleep(2)
        pass_el = await _first_select(page, pass_selectors, timeout_s=10)

    if not pass_el:
        raise RuntimeError("SoFi login flow did not reveal a password input.")

    await pass_el.send_keys(password)

    clicked = await _click_first_text(page, ["Log In", "Log in", "Sign In", "Sign in", "Continue", "Submit"])
    if not clicked:
        raise RuntimeError("Could not find a SoFi login submit button.")
    await page.sleep(3)

    code_selectors = [
        "#code",
        "input#code",
        "input[name=code]",
        "input[name=otp]",
        "input[name=passcode]",
        "input[inputmode=numeric]",
        "input[inputmode='numeric']",
        "input[type=tel]",
    ]

    code_el = None
    start = time.time()
    while (time.time() - start) < 90:
        try:
            cookies_now = await _cookies_from_browser(browser)
            _auth_sanity_check(cookies_now)
            return
        except Exception:
            pass

        code_el = await _first_select(page, code_selectors, timeout_s=2)
        if code_el:
            break
        await page.sleep(1)

    if not code_el:
        try:
            BLOG.write_log(
                _log_ctx(),
                broker=BROKER,
                action="session",
                label="otp_not_required",
                filename_prefix="session_stage",
                text="SoFi OTP challenge was not detected; continuing.",
                secrets=[username, password, totp_secret],
            )
        except Exception:
            pass
        return

    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="session",
            label="otp_required",
            filename_prefix="session_stage",
            text="SoFi OTP challenge detected.",
            secrets=[username, password, totp_secret],
        )
    except Exception:
        pass

    remember = await _first_select(
        page,
        ["#rememberBrowser", "input#rememberBrowser", "input[name=rememberBrowser]"],
        timeout_s=2,
    )
    if remember:
        try:
            await remember.mouse_click()
        except Exception:
            pass

    code = _totp_now(totp_secret)
    if not code:
        if otp_provider is None:
            raise RuntimeError("SoFi requires a security code, but no OTP provider is available.")
        code = otp_provider("SoFi", 300)
    if not code:
        raise RuntimeError("OTP not received")

    try:
        await code_el.clear_input()
    except Exception:
        pass
    await code_el.send_keys(str(code))

    clicked2 = await _click_first_text(page, ["Verify Code", "Verify", "Continue", "Submit"])
    if not clicked2:
        return
    await page.sleep(2)


async def _wait_until_backend_auth(browser, page, *, timeout_s: int = 180) -> Dict[str, str]:
    deadline = time.time() + max(10, int(timeout_s))
    last_err: Optional[str] = None

    while time.time() < deadline:
        try:
            await page.get("https://www.sofi.com/wealth/app/overview")
        except Exception:
            pass

        await page.sleep(5)

        try:
            cookies = await _cookies_from_browser(browser)
        except Exception as e:
            last_err = f"cookie read failed: {e}"
            continue

        try:
            _auth_sanity_check(cookies)
            return cookies
        except Exception as e:
            last_err = str(e)
            continue

    try:
        cookies = await _cookies_from_browser(browser)
        names = sorted(list(cookies.keys()))
    except Exception:
        names = []

    raise RuntimeError(
        f"Auth never stabilized within {timeout_s}s. "
        f"Last error: {last_err or 'unknown'}. "
        f"Cookie names seen: {names}"
    )


async def _async_login(
    username: str,
    password: str,
    totp_secret: str,
    otp_provider: Optional[OtpProvider],
    headless_override: Optional[bool] = None,
) -> Dict[str, str]:
    try:
        import zendriver as uc  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Missing dependency zendriver: {e}")

    headless = _headless_default() if headless_override is None else bool(headless_override)
    started = time.time()

    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="session",
            label="async_login_start",
            filename_prefix="session_stage",
            text=(
                "SoFi async login start\n"
                f"headless={headless}\n"
                f"profile_dir={_profile_dir()}\n"
            ),
            secrets=[username, password, totp_secret],
        )
    except Exception:
        pass

    browser_args = [
        "--no-sandbox",
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
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
    ]
    if headless:
        browser_args.insert(0, "--headless=new")

    cleanup_orphaned_chrome(_profile_dir())
    browser = await uc.start(browser_args=browser_args, user_data_dir=str(_profile_dir()), browser_executable_path=find_browser_executable())
    try:
        page = browser.tabs[0] if browser.tabs else await browser()

        # Already authenticated? use it.
        try:
            cookies_now = await _cookies_from_browser(browser)
            _auth_sanity_check(cookies_now)
            try:
                BLOG.write_log(
                    _log_ctx(),
                    broker=BROKER,
                    action="session",
                    label="already_authenticated",
                    filename_prefix="session_stage",
                    text=(
                        "SoFi profile already authenticated.\n"
                        f"cookie_count={len(cookies_now)}\n"
                        f"elapsed_s={time.time() - started:.2f}\n"
                    ),
                    secrets=[username, password, totp_secret],
                )
            except Exception:
                pass
            return cookies_now
        except Exception:
            pass

        try:
            BLOG.write_log(
                _log_ctx(),
                broker=BROKER,
                action="session",
                label="login_required",
                filename_prefix="session_stage",
                text="SoFi profile not authenticated; starting login flow.",
                secrets=[username, password, totp_secret],
            )
        except Exception:
            pass

        await _force_login_flow(
            browser,
            page,
            username=username,
            password=password,
            totp_secret=totp_secret,
            otp_provider=otp_provider,
        )

        cookies = await _wait_until_backend_auth(browser, page, timeout_s=120)
        try:
            BLOG.write_log(
                _log_ctx(),
                broker=BROKER,
                action="session",
                label="backend_authenticated",
                filename_prefix="session_stage",
                text=(
                    "SoFi backend authentication succeeded.\n"
                    f"cookie_count={len(cookies)}\n"
                    f"elapsed_s={time.time() - started:.2f}\n"
                ),
                secrets=[username, password, totp_secret],
            )
        except Exception:
            pass
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
# Session wrapper (Chase-style: profile truth, fresh cookies per action)
# =============================================================================

def _rehydrate_session(*args, **kwargs) -> BrokerOutput:
    """
    Action-path session rehydrate:
      - starts Zendriver with persistent profile dir
      - if already authed -> proceed
      - else UI login + OTP
      - extracts fresh cookies from live browser and sets _COOKIES/_CSRF
    """
    global _COOKIES, _CSRF

    user = _env("SOFI_USERNAME")
    pw = _env("SOFI_PASSWORD")
    if not user or not pw:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message="Missing SOFI_USERNAME or SOFI_PASSWORD")],
            message="Missing credentials",
        )

    totp = _env("SOFI_TOTP_SECRET")
    debug_mode = bool(kwargs.get("debug") or False)

    otp_provider = _otp_provider_terminal()

    try:
        try:
            BLOG.write_log(
                _log_ctx(),
                broker=BROKER,
                action="session",
                label="rehydrate_begin",
                filename_prefix="session_stage",
                text=(
                    "SoFi session rehydrate begin.\n"
                    f"default_headless={_headless_default()}\n"
                    f"debug={debug_mode}\n"
                ),
                secrets=[user, pw, totp],
            )
        except Exception:
            pass

        local_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(local_loop)

        default_headless = _headless_default()
        initial_headless = (False if debug_mode else default_headless)
        try:
            cookies = local_loop.run_until_complete(
                _async_login(
                    user,
                    pw,
                    totp,
                    otp_provider,
                    headless_override=initial_headless,
                )
            )
        except Exception:
            if initial_headless:
                try:
                    BLOG.write_log(
                        _log_ctx(),
                        broker=BROKER,
                        action="session",
                        label="headless_retry_headed",
                        filename_prefix="session_stage",
                        text="SoFi headless login failed; retrying in headed mode.",
                        secrets=[user, pw, totp],
                    )
                except Exception:
                    pass
                cookies = local_loop.run_until_complete(
                    _async_login(user, pw, totp, otp_provider, headless_override=False)
                )
            else:
                raise

        local_loop.close()

        csrf = _csrf_from_cookies(cookies)
        if not csrf:
            raise RuntimeError("Missing CSRF token in cookies")

        _COOKIES = cookies
        _CSRF = csrf

        # Optional cache only (NOT used for action auth)
        try:
            _save_cookies_to_disk(cookies)
        except Exception:
            pass

        try:
            BLOG.write_log(
                _log_ctx(),
                broker=BROKER,
                action="session",
                label="rehydrate_success",
                filename_prefix="session_stage",
                text=(
                    "SoFi session rehydrate success.\n"
                    f"cookie_count={len(cookies)}\n"
                    f"csrf_present={bool(csrf)}\n"
                ),
                secrets=[user, pw, totp],
            )
        except Exception:
            pass

        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[AccountOutput(account_id="SoFi", ok=True, message="Session refreshed")],
            message="Session refreshed",
        )

    except Exception as e:
        _COOKIES = None
        _CSRF = None
        try:
            BLOG.log_exception(
                _log_ctx(),
                broker=BROKER,
                action="session",
                label="rehydrate_failed",
                exc=e,
                secrets=[user, pw, totp],
            )
        except Exception:
            pass
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message=f"Login failed: {e}")],
            message=f"Login failed: {e}",
        )


def bootstrap(*args, **kwargs) -> BrokerOutput:
    # Compatibility shim for retry wrappers: just rehydrate like an action path would.
    return _rehydrate_session(*args, **kwargs)


# =============================================================================
# Positions / holdings
# =============================================================================

def get_holdings(*args, **kwargs) -> BrokerOutput:
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message="Cancelled before start")],
            message="Cancelled",
        )

    # Chase-style: rehydrate every action (profile truth, fresh cookies).
    boot = _rehydrate_session(*args, **kwargs)
    if getattr(boot, "state", "") not in ("success", "partial"):
        return boot

    def _do_once() -> BrokerOutput:
        err = _require_session(allow_disk=False)
        if err:
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="SoFi", ok=False, message=err)],
                message=err,
            )

        req = _requests()
        outs: List[AccountOutput] = []
        total_value = 0.0
        total_seen = False

        broker_extra: Dict[str, Any] = {
            "accounts_ok": 0,
            "accounts_failed": 0,
            "positions_total": 0,
            "total_value_reported": None,
        }

        r = req.get(
            "https://www.sofi.com/wealth/backend/v1/json/accounts",
            headers=_headers(_CSRF),
            cookies=_COOKIES,
            impersonate="chrome",
            timeout=60,
        )
        if r.status_code == 401:
            raise RuntimeError(f"HTTP 401: {r.text[:200]}")
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        accounts = r.json() or []
        if not isinstance(accounts, list):
            accounts = []

        broker_extra["accounts_total"] = int(len(accounts))
        if accounts and isinstance(accounts[0], dict):
            broker_extra["account0_keys"] = sorted([str(k) for k in accounts[0].keys()])[:200]

        for acct in accounts:
            if _is_cancelled(kwargs):
                break
            if not isinstance(acct, dict):
                continue

            internal_id = str(acct.get("id") or "")
            apex = str(acct.get("apexAccountId") or "")
            acct_type = ((acct.get("type") or {}).get("description") or "ACCOUNT").strip()

            bal = _to_float(acct.get("totalEquityValue"))
            if bal is not None:
                total_value += bal
                total_seen = True

            rows: List[HoldingRow] = []
            cash_dollars: Optional[float] = None

            acct_extra: Dict[str, Any] = {
                "internal_id_last4": _safe_last4(internal_id),
                "apex_last4": _safe_last4(apex),
                "account_type": acct_type,
                "totalEquityValue": bal,
            }
            try:
                acct_extra["acct_keys"] = sorted([str(k) for k in acct.keys()])[:200]
                acct_extra.update(_flatten_safe(acct, prefix="acct_", max_items=120))
                # ensure no ids sneak through
                acct_extra.pop("acct_id", None)
                acct_extra.pop("acct_apexAccountId", None)
            except Exception:
                pass

            raw_holdings_count = 0
            parsed_positions = 0

            if internal_id:
                url = f"https://www.sofi.com/wealth/backend/api/v3/account/{internal_id}/holdings?accountDataType=INTERNAL"
                rr = req.get(
                    url,
                    headers=_headers(_CSRF),
                    cookies=_COOKIES,
                    impersonate="chrome",
                    timeout=60,
                )
                if rr.status_code == 401:
                    raise RuntimeError(f"HTTP 401: {rr.text[:200]}")
                if rr.status_code >= 400:
                    raise RuntimeError(f"Holdings HTTP {rr.status_code}: {rr.text[:200]}")

                data = rr.json() or {}
                if isinstance(data, dict):
                    try:
                        acct_extra["holdings_payload_keys"] = sorted([str(k) for k in data.keys()])[:200]
                        acct_extra.update(_flatten_safe(data, prefix="holdings_", max_items=120))
                    except Exception:
                        pass

                holdings_list = (data.get("holdings") or []) if isinstance(data, dict) else []
                if not isinstance(holdings_list, list):
                    holdings_list = []

                raw_holdings_count = int(len(holdings_list))

                for h in holdings_list:
                    if not isinstance(h, dict):
                        continue

                    sym = (h.get("symbol") or "UNKNOWN").strip()
                    sh = _to_float(h.get("shares"))
                    px = _to_float(h.get("price"))

                    # Cash row handling (legacy behavior)
                    if sym.upper() in ("|CASH|", "CASH"):
                        if sh is not None and px is not None:
                            cash_dollars = float(sh) * float(px)
                        elif sh is not None:
                            cash_dollars = float(sh)
                        continue

                    hextra: Dict[str, Any] = {}
                    try:
                        hextra["keys"] = sorted([str(k) for k in h.keys()])[:200]
                        hextra.update(_flatten_safe(h, max_items=140))
                    except Exception:
                        pass

                    if sh is not None and px is not None:
                        try:
                            hextra["market_value_calc"] = float(sh) * float(px)
                        except Exception:
                            pass

                    rows.append(HoldingRow(symbol=sym.upper(), shares=sh, price=px, extra=hextra))
                    parsed_positions += 1

            acct_extra["raw_holdings_count"] = int(raw_holdings_count)
            acct_extra["positions_count"] = int(len(rows))
            acct_extra["positions_parsed"] = int(parsed_positions)
            if cash_dollars is not None:
                acct_extra["cash_dollars_calc"] = float(cash_dollars)

            base = f"{acct_type} ({_mask_last4(apex)})"
            header = f"{base} = ${bal:.2f}" if bal is not None else f"{base} = ?"
            if cash_dollars is not None:
                header = f"{header} (${cash_dollars:.2f} cash)"

            outs.append(AccountOutput(account_id=header, ok=True, message="", holdings=rows, extra=acct_extra))
            broker_extra["accounts_ok"] = int(broker_extra["accounts_ok"]) + 1
            broker_extra["positions_total"] = int(broker_extra["positions_total"]) + int(len(rows))

        if _is_cancelled(kwargs):
            msg = "Cancelled"
            state = "partial" if outs else "failed"
            return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg, extra=broker_extra)

        msg = f"Total Value = ${total_value:.2f}" if total_seen else "Total Value = ?"
        broker_extra["total_value_reported"] = float(total_value) if total_seen else None

        ok_ct = sum(1 for a in outs if a.ok)
        fail_ct = sum(1 for a in outs if not a.ok)
        state = "success" if ok_ct > 0 and fail_ct == 0 else ("partial" if ok_ct > 0 else "failed")
        broker_extra["accounts_failed"] = int(fail_ct)

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg, extra=broker_extra)

    try:
        return _do_once()
    except Exception as e:
        if _is_unauthorized_text(str(e)):
            try:
                BLOG.write_log(
                    _log_ctx(),
                    broker=BROKER,
                    action="positions",
                    label="unauthorized_retry",
                    filename_prefix="positions_stage",
                    text="SoFi positions received unauthorized; rehydrating and retrying once.",
                )
            except Exception:
                pass
            boot2 = _rehydrate_session(*args, **kwargs)
            if getattr(boot2, "state", "") in ("success", "partial"):
                try:
                    return _do_once()
                except Exception as e2:
                    try:
                        BLOG.log_exception(
                            _log_ctx(),
                            broker=BROKER,
                            action="positions",
                            label="retry_failed",
                            exc=e2,
                        )
                    except Exception:
                        pass
                    return BrokerOutput(
                        broker=BROKER,
                        state="failed",
                        accounts=[AccountOutput(account_id="SoFi", ok=False, message=str(e2))],
                        message=str(e2),
                    )
        try:
            BLOG.log_exception(
                _log_ctx(),
                broker=BROKER,
                action="positions",
                label="failed",
                exc=e,
            )
        except Exception:
            pass
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message=str(e))],
            message=str(e),
        )


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return get_holdings(*args, **kwargs)


# =============================================================================
# DRY RUN logging (SoFi)
# =============================================================================

def _dry_run_log_dir() -> Path:
    et = pytz.timezone("America/New_York")
    d = datetime.now(et).strftime("%m.%d.%y")
    p = _root_dir() / "logs" / BROKER / d
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_dry_run_log(*, content: str) -> str:
    rand = uuid.uuid4().hex[:10]
    path = _dry_run_log_dir() / f"test_order_{BROKER}_{rand}.log"
    path.write_text(content, encoding="utf-8")
    return display_path(path)


def _fmt_kv(lines: List[str], k: str, v: Any) -> None:
    if v is None or v == "":
        return
    lines.append(f"{k}: {v}")


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message="Cancelled before start")],
            message="Cancelled",
        )

    # Chase-style: rehydrate every action (profile truth, fresh cookies).
    boot = _rehydrate_session(**kwargs)
    if getattr(boot, "state", "") not in ("success", "partial"):
        return boot

    def _do_once() -> BrokerOutput:
        err = _require_session(allow_disk=False)
        if err:
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="SoFi", ok=False, message=err)],
                message=err,
            )

        side_norm = (side or "").strip().lower()
        if side_norm not in ("buy", "sell"):
            return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid side: {side!r}")

        sym = (symbol or "").strip().upper()
        if not sym:
            return BrokerOutput(broker=BROKER, state="failed", accounts=[], message="Invalid symbol")

        try:
            q = float(qty)
            if q <= 0:
                raise ValueError()
        except Exception:
            return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid qty: {qty!r}")

        req = _requests()

        def _pick_num(d: dict, keys: List[str]) -> Optional[float]:
            for k in keys:
                if k in d and d.get(k) is not None:
                    try:
                        return float(d.get(k))
                    except Exception:
                        pass
            return None

        log_sections: List[str] = []
        log_sections.append("DRY RUN — NO ORDER SUBMITTED" if dry_run else "LIVE ORDER MODE")
        log_sections.append(f"broker: {BROKER}")
        log_sections.append(f"time_utc: {datetime.utcnow().isoformat()}")
        log_sections.append(f"requested: side={side_norm} symbol={sym} qty={q}")
        log_sections.append("")

        quote = req.get(
            f"https://www.sofi.com/wealth/backend/api/v1/tearsheet/quote?symbol={sym}&productSubtype=BROKERAGE",
            headers=_headers(),
            cookies=_COOKIES,
            impersonate="chrome",
            timeout=120,
        )
        if quote.status_code == 401:
            raise RuntimeError(f"HTTP 401: {quote.text[:200]}")
        if quote.status_code != 200:
            raise RuntimeError(f"Quote HTTP {quote.status_code}: {quote.text[:200]}")
        qj = quote.json() or {}

        last = _pick_num(qj, ["last", "price", "lastPrice", "lastTradePrice", "lastTradePriceAmount"])
        bid = _pick_num(qj, ["bid", "bidPrice", "bidPriceAmount"])
        ask = _pick_num(qj, ["ask", "askPrice", "askPriceAmount"])

        if isinstance(qj.get("quote"), dict):
            q2 = qj["quote"]
            last = last if last not in (None, 0.0) else _pick_num(q2, ["last", "price", "lastPrice"])
            bid = bid if bid not in (None, 0.0) else _pick_num(q2, ["bid", "bidPrice"])
            ask = ask if ask not in (None, 0.0) else _pick_num(q2, ["ask", "askPrice"])

        if _trading_session() == "ALL_HOURS":
            ah = _pick_num(qj, ["appendedHoursPrice", "extendedHoursPrice"])
            if ah and ah > 0 and (last is None or last == 0.0):
                last = ah

        if last is not None and last <= 0:
            last = None
        if bid is not None and bid <= 0:
            bid = None
        if ask is not None and ask <= 0:
            ask = None

        chosen: Optional[float] = (ask if side_norm == "buy" else bid)
        if chosen is None:
            chosen = last
        if chosen is None or chosen <= 0:
            raise RuntimeError("Price unavailable (bid/ask/last missing).")

        if last is not None and last > 0:
            lo = last * 0.95
            hi = last * 1.05
            if chosen < lo:
                chosen = lo
            elif chosen > hi:
                chosen = hi

        session_type = _trading_session()

        _fmt_kv(log_sections, "quote_last", last)
        _fmt_kv(log_sections, "quote_bid", bid)
        _fmt_kv(log_sections, "quote_ask", ask)
        _fmt_kv(log_sections, "chosen_price", chosen)
        _fmt_kv(log_sections, "tradingSession", session_type)
        log_sections.append("")

        fa = req.get(
            "https://www.sofi.com/wealth/backend/api/v1/user/funded-brokerage-accounts",
            headers=_headers(_CSRF),
            cookies=_COOKIES,
            impersonate="chrome",
            timeout=120,
        )
        if fa.status_code == 401:
            raise RuntimeError(f"HTTP 401: {fa.text[:200]}")
        if fa.status_code != 200:
            raise RuntimeError(f"Funded accounts HTTP {fa.status_code}: {fa.text[:200]}")
        funded = fa.json() or []
        if not funded:
            raise RuntimeError("No funded accounts returned")

        outs: List[AccountOutput] = []

        for _acct_i, acct in enumerate(funded):
            if _acct_i > 0:
                time.sleep(random.uniform(1.0, 3.0))
            if _is_cancelled(kwargs):
                break
            acct_id = str(acct.get("accountId") or "")
            acct_type = str(acct.get("accountType") or "ACCOUNT")
            label = f"{acct_type} ({_mask_last4(acct_id)})"

            if not acct_id:
                outs.append(AccountOutput(account_id=label, ok=False, message="Missing accountId"))
                continue

            is_fractional = (q < 1)

            if is_fractional:
                if session_type != "CORE_HOURS":
                    outs.append(AccountOutput(account_id=label, ok=False, message="Fractionals only supported in CORE_HOURS"))
                    continue

                cash_amount = round(float(chosen) * float(q), 2)
                endpoint = "https://www.sofi.com/wealth/backend/api/v1/trade/order-fractional"
                payload = {
                    "operation": side_norm.upper(),
                    "cashAmount": cash_amount,
                    "quantity": q,
                    "symbol": sym,
                    "accountId": acct_id,
                    "time": "DAY",
                    "type": "MARKET",
                    "tradingSession": session_type,
                    "sellAll": False,
                }
            else:
                endpoint = "https://www.sofi.com/wealth/backend/api/v1/trade/order"
                payload = {
                    "operation": side_norm.upper(),
                    "quantity": str(int(q)),
                    "time": "DAY",
                    "type": "LIMIT",
                    "limitPrice": round(float(chosen), 4),
                    "symbol": sym,
                    "accountId": acct_id,
                    "tradingSession": session_type,
                }

            if dry_run:
                ticket_lines: List[str] = []
                ticket_lines.append("DRY RUN — NO ORDER SUBMITTED")
                _fmt_kv(ticket_lines, "side", side_norm.upper())
                _fmt_kv(ticket_lines, "symbol", sym)
                _fmt_kv(ticket_lines, "qty", q)
                _fmt_kv(ticket_lines, "account", label)
                _fmt_kv(ticket_lines, "endpoint", endpoint)
                _fmt_kv(ticket_lines, "type", payload.get("type"))
                _fmt_kv(ticket_lines, "timeInForce", payload.get("time"))
                _fmt_kv(ticket_lines, "tradingSession", payload.get("tradingSession"))
                if "limitPrice" in payload:
                    _fmt_kv(ticket_lines, "limitPrice", payload.get("limitPrice"))
                if "cashAmount" in payload:
                    _fmt_kv(ticket_lines, "cashAmount", payload.get("cashAmount"))

                outs.append(AccountOutput(account_id=label, ok=True, message="\n".join(ticket_lines)))
                continue

            rr = req.post(
                endpoint,
                json=payload,
                headers=_headers(_CSRF),
                cookies=_COOKIES,
                impersonate="chrome",
                timeout=120,
            )
            if rr.status_code == 401:
                raise RuntimeError(f"HTTP 401: {rr.text[:200]}")
            if rr.status_code == 200:
                resp = rr.json() if rr.text else {}
                if isinstance(resp, dict) and resp.get("experiment") == "ORDER_SUBMITTED":
                    outs.append(AccountOutput(account_id=label, ok=True, message="order placed"))
                else:
                    outs.append(AccountOutput(account_id=label, ok=True, message="order submitted"))
            else:
                outs.append(AccountOutput(account_id=label, ok=False, message=f"HTTP {rr.status_code}: {rr.text[:200]}"))

        if _is_cancelled(kwargs):
            state = "partial" if any(a.ok for a in outs) else "failed"
            return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="Cancelled")

        ok_ct = sum(1 for a in outs if a.ok)
        fail_ct = sum(1 for a in outs if not a.ok)
        state = "success" if ok_ct > 0 and fail_ct == 0 else ("partial" if ok_ct > 0 else "failed")

        broker_msg = ""
        if dry_run:
            log_path = _write_dry_run_log(content="\n".join(log_sections).rstrip() + "\n")
            broker_msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=broker_msg)

    try:
        return _do_once()
    except Exception as e:
        if _is_unauthorized_text(str(e)):
            try:
                BLOG.write_log(
                    _log_ctx(),
                    broker=BROKER,
                    action=f"trade_{(side or '').lower()}",
                    label="unauthorized_retry",
                    filename_prefix="trade_stage",
                    text="SoFi trade received unauthorized; rehydrating and retrying once.",
                )
            except Exception:
                pass
            boot2 = _rehydrate_session(**kwargs)
            if getattr(boot2, "state", "") in ("success", "partial"):
                try:
                    return _do_once()
                except Exception as e2:
                    try:
                        BLOG.log_exception(
                            _log_ctx(),
                            broker=BROKER,
                            action=f"trade_{(side or '').lower()}",
                            label="retry_failed",
                            exc=e2,
                        )
                    except Exception:
                        pass
                    return BrokerOutput(
                        broker=BROKER,
                        state="failed",
                        accounts=[AccountOutput(account_id="SoFi", ok=False, message=str(e2))],
                        message=str(e2),
                    )
        try:
            BLOG.log_exception(
                _log_ctx(),
                broker=BROKER,
                action=f"trade_{(side or '').lower()}",
                label="failed",
                exc=e,
            )
        except Exception:
            pass
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message=str(e))],
            message=str(e),
        )


def healthcheck(*args, **kwargs) -> BrokerOutput:
    """
    Probe-only: do NOT open browser / do NOT login.
    We only validate cached cookies.json if present.
    """
    err = _require_session(allow_disk=True)
    if err:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message=err)],
            message=err,
        )

    try:
        _auth_sanity_check(_COOKIES or {})
        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=[AccountOutput(account_id="SoFi", ok=True, message="ok")],
            message="ok",
        )
    except Exception as e:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="SoFi", ok=False, message=str(e))],
            message=str(e),
        )
