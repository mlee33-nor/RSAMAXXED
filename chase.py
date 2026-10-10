from __future__ import annotations

import asyncio
import json
import os
import random
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from modules import broker_logging as BLOG
import broker_logins
from modules.outputs import BrokerOutput, AccountOutput, HoldingRow, find_browser_executable, cleanup_orphaned_chrome
from modules import quiet
from modules._2fa_prompt import universal_2fa_prompt, notify_user, clear_notice
from modules.brokers.chase.chase_normalizer import normalize as chase_normalize

BROKER = "chase"

# --- URL Constants ---
LOGIN_URL = "https://secure05c.chase.com/web/auth/#/logon/logon/chaseOnline"
LOGIN_NAV_TIMEOUT_S = 60
# Hard ceiling on one login attempt (cold login incl. push approval is ~140s;
# the challenge loop is 180s + 45s). Backstop for hangs wait_for can't cancel.
LOGIN_ATTEMPT_TIMEOUT_S = 480
# ...and on the whole ensure_session (headless attempt + headed retry share it),
# so the slot is released inside the app's 15-min mirror stall window.
LOGIN_TOTAL_TIMEOUT_S = 540
# A headed retry needs time for a push approval (~140s cold login) to matter.
LOGIN_RETRY_MIN_S = 180


class _LoginAttemptTimeout(TimeoutError):
    """A login attempt hit the join() backstop — it hung, it didn't fail."""
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

#: In-memory session per login, parked here while another login is served.
_SESSION_BY_LOGIN: Dict[int, Any] = {}
_CUR_LOGIN: int = 1


def _on_login_switch(idx: int) -> None:
    """Park this login's cached session and pick up the incoming one.

    broker_logins.fan_out calls this when it moves between logins. Without it
    login 2 would be handed the cookies already held for login 1 and would
    quietly read the first person's accounts twice.
    """
    global _COOKIES, _CUR_LOGIN
    if idx == _CUR_LOGIN:
        return
    _SESSION_BY_LOGIN[_CUR_LOGIN] = (_COOKIES,)
    # Unpack: a bare assignment would leave _COOKIES as the 1-tuple itself.
    (_COOKIES,) = _SESSION_BY_LOGIN.get(idx, (None,))
    _CUR_LOGIN = idx


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


def _position_symbol(pos: Any) -> str:
    """symbolSecurityIdentifier of a Chase position line, or ""."""
    comp0 = _first_dict_in_list(pos.get("positionComponents")) if isinstance(pos, dict) else None
    sid0 = _first_dict_in_list(comp0.get("securityIdDetail")) if isinstance(comp0, dict) else None
    if not isinstance(sid0, dict):
        return ""
    return str(sid0.get("symbolSecurityIdentifier") or "").strip().upper()


#: Type-like fields on a position line that can label it as cash.
#: NEEDS LIVE VERIFICATION: Chase's exact field names for the asset type.
_CASH_TYPE_KEYS = ("assetClassCode", "assetClassName", "instrumentTypeCode",
                   "securityTypeCode", "assetTypeCode", "productTypeCode",
                   "positionTypeCode", "instrumentTypeName")


def _is_cash_position(pos: Any) -> bool:
    """True when a position line is the account's cash, not a security.

    The legacy test was the name alone ("Cash" in instrumentLongName), which
    drops a real stock whose name contains "Cash" from the holdings -- and
    auto-sell then never sees the shares. Decide by an explicit cash type when
    Chase sends one, else by the line carrying no tradable symbol.
    """
    if not isinstance(pos, dict):
        return False
    for k in _CASH_TYPE_KEYS:
        v = str(pos.get(k) or "").strip().upper()
        if v and ("CASH" in v or "SWEEP" in v):
            return True
    return _position_symbol(pos) in ("", "UNKNOWN", "CASH", "USD")


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


def _default_headless() -> bool:
    # Warm-session actions (holdings/quotes) run headless so no window pops up.
    # A fresh login that hits interactive 2FA can't finish headless, so
    # ensure_session retries headed on failure (see below).
    return (_env("CHASE_HEADLESS") or _env("HEADLESS") or "true").lower() == "true"


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    """This login's session directory — the browser profile and cookie jar.

    Login 1 keeps the original path, so upgrading an install reuses the Chrome
    profile that is already signed in rather than putting everyone through 2FA
    again. Login 2 and up get their own directory: two logins sharing one
    profile would fight over the same cookies and neither would stay signed in.
    """
    d = _root_dir() / "sessions" / "chase"
    suffix = broker_logins.active_suffix(BROKER)
    if suffix:
        d = d / f"login{suffix}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _profile_dir() -> Path:
    d = _sessions_dir() / "profile"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cookie_path() -> Path:
    return _sessions_dir() / "cookies.json"


def _logs_dir() -> Path:
    d = _root_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _log_ctx() -> Dict[str, Any]:
    return {"log_dir": _logs_dir()}


def _stage(label: str, text: str = "") -> None:
    """Record one login stage. Chase used to log nothing at all, so a failed
    bootstrap left no trace anywhere — the window is headless, the GUI runs
    under pythonw (no console), and ensure_session clears the cookie file on
    the way out. Every branch of the login loop drops a breadcrumb here."""
    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="session",
            label=label,
            filename_prefix="session_stage",
            text=text,
            secrets=[_env("CHASE_USERNAME"), _env("CHASE_PASSWORD")],
        )
    except Exception:
        pass


# The GUI installs a callback here so a Chase in-app push surfaces in the
# notification centre. Default is a plain print, which is invisible under
# pythonw — that is why the push prompt never reached the user.
_PUSH_NOTIFIER = None


def set_push_notifier(fn) -> None:
    """Register a callable(str) used to tell the user to approve a Chase push."""
    global _PUSH_NOTIFIER
    _PUSH_NOTIFIER = fn if callable(fn) else None


def _notify_push(msg: str) -> None:
    _stage("push_sent", msg)
    if _PUSH_NOTIFIER is not None:
        try:
            _PUSH_NOTIFIER(msg)
            return
        except Exception:
            pass
    print(msg)


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


def _unmasked_account_ids(resp_json: Dict[str, Any]) -> List[str]:
    """Account ids Chase listed without a mask. _extract_accounts_map leaves
    them out (the mask is the account's label everywhere), so a trade reports
    each one as skipped instead of dropping it without a word."""
    out: List[str] = []
    for item in (resp_json.get("cache", []) if isinstance(resp_json, dict) else []) or []:
        response = item.get("response") if isinstance(item, dict) else None
        inv = response.get("investmentAccountOverviews") if isinstance(response, dict) else None
        if not isinstance(inv, list) or not inv or not isinstance(inv[0], dict):
            continue
        for acct in inv[0].get("investmentAccountDetails", []) or []:
            if not isinstance(acct, dict):
                continue
            acc_id = str(acct.get("accountId") or "").strip()
            if acc_id and not str(acct.get("mask") or "").strip():
                out.append(acc_id)
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
async def _page_url(page) -> str:
    """Current URL, best-effort — used only to make failure logs readable."""
    try:
        return str(await page.evaluate("location.href")) or "?"
    except Exception:
        return "?"


_LOGIN_ERROR_JS = """
(() => {
  const seen = [];
  const push = t => {
    t = (t || '').trim();
    if (t && t.length < 300 && !seen.includes(t)) seen.push(t);
  };
  // Only report while the logon form itself is still on screen. A 2FA or
  // device-verification step legitimately renders role=alert banners, and
  // treating those as a rejection would abort a login that is going fine.
  if (!document.getElementById('signin-button')) return '';
  for (const id of ['userId-input-label-error-text',
                    'password-input-label-error-text']) {
    const el = document.getElementById(id);
    if (el) push(el.innerText);
  }
  document.querySelectorAll('[role=alert]').forEach(el => {
    if (el.offsetParent !== null) push(el.innerText);
  });
  return seen.join(' | ');
})()
"""


async def _login_form_error(page) -> str:
    """Inline validation/rejection text Chase renders on the logon form.

    Chase never navigates away when it refuses a sign-in — it just paints a
    field error and stays on the same URL. Without reading that text a bad
    credential is indistinguishable from a hung browser, which is why a broken
    login used to burn the full 180s poll plus a 45s wait and then report the
    useless "Did not reach authenticated state within timeout".
    """
    try:
        return str(await page.evaluate(_LOGIN_ERROR_JS) or "").strip()
    except Exception:
        return ""


def _credential_hint(err: str) -> str:
    """Turn Chase's terse field error into something actionable."""
    user = _env("CHASE_USERNAME")
    if "username" in err.lower() and "@" in user:
        return (" — CHASE_USERNAME is set to an email address; Chase requires "
                "your chase.com username (letters/numbers), not an email")
    return ""


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
    profile_dir: Optional[Path] = None,
) -> Dict[str, str]:
    # Resolve the profile ONCE. broker_logins' active login is process-global
    # and moves on after a timeout, so this attempt must never re-resolve it
    # later and touch (or kill the Chrome of) a different login's profile.
    profile = Path(profile_dir) if profile_dir is not None else _profile_dir()
    try:
        import zendriver as uc  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Missing dependency zendriver: {e}")

    headless = _default_headless()
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

    # A headed retry (headless login hit 2FA) must still stay off the user's
    # desktop -- parked off-screen here, taskbar button dropped below.
    browser_args = quiet.browser_args(browser_args, headless=headless)

    cleanup_orphaned_chrome(profile)
    browser = await uc.start(browser_args=browser_args, user_data_dir=str(profile), browser_executable_path=find_browser_executable())
    if not headless:
        quiet.tame_windows(browser)
    code_handed_over = False
    try:
        page = browser.tabs[0] if browser.tabs else await browser()
        _stage("browser_ready", f"headless={headless} profile={profile}")

        # Quick path: already logged in
        try:
            _stage("warm_check_begin", "reading cookies + probing account-list API")
            c0 = await _cookies_from_browser(browser)
            _stage("warm_check_cookies", f"cookie_count={len(c0)}")
            _login_verified(c0)
            _stage("warm_check_ok", "already authenticated — reusing session")

            if prime_trade:
                await _prime_trade_context(page)
                c1 = await _cookies_from_browser(browser)
                _login_verified(c1)
                return c1

            return c0
        except Exception:
            pass

        _stage("login_required", "Chase profile not authenticated; starting login flow.")
        # zendriver's page.get() can simply never return (headless Chrome
        # stalling on the logon page). Unbounded, that held the Chase slot for
        # 100+ minutes on 2026-10-02 with the trade "still purchasing" forever.
        try:
            await asyncio.wait_for(page.get(LOGIN_URL), timeout=LOGIN_NAV_TIMEOUT_S)
        except asyncio.TimeoutError:
            _stage("login_nav_timeout", f"headless={headless} after {LOGIN_NAV_TIMEOUT_S}s")
            raise RuntimeError(
                f"Chase login page did not load within {LOGIN_NAV_TIMEOUT_S}s")
        await page.sleep(2)

        user_box = await _safe_find(page, "#userId-input-field-input", timeout_s=8)
        pass_box = await _safe_find(page, "#password-input-field-input", timeout_s=8)
        if not user_box or not pass_box:
            _stage("login_fields_missing",
                   f"userId={bool(user_box)} password={bool(pass_box)} "
                   f"headless={headless}\nurl={await _page_url(page)}")
            raise RuntimeError("Chase login fields not found")

        await user_box.clear_input_by_deleting()
        await user_box.send_keys(username)
        await pass_box.send_keys(password)

        btn = await _safe_find(page, "#signin-button", timeout_s=8)
        if not btn:
            _stage("signin_button_missing", f"url={await _page_url(page)}")
            raise RuntimeError("Sign-in button not found")
        await btn.mouse_click()
        _stage("credentials_submitted", f"headless={headless}")
        await page.sleep(4)

        start = time.time()
        push_notified = False
        last_branch = ""

        async def _branch(name: str) -> None:
            # Log each challenge type once, not once per 1s poll.
            nonlocal last_branch
            if name != last_branch:
                last_branch = name
                _stage(f"challenge_{name}",
                       f"headless={headless}\nurl={await _page_url(page)}")

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
                await _branch("sms_list")
                await _handle_list_verification(page)
                await page.sleep(3)
                continue

            radio_group = await _safe_select(page, "#eligibleTextContacts", timeout_s=2)
            if radio_group:
                await _branch("sms_radio")
                await _handle_radio_verification(page)
                await page.sleep(3)
                continue

            dropdown = await _safe_find(page, "#header-simplerAuth-dropdownoptions-styledselect", timeout_s=2)
            if dropdown:
                await _branch("dropdown")
                await _handle_dropdown_verification(page)
                await page.sleep(3)
                continue

            push = await _safe_find(page, "#inAppSend", timeout_s=2)
            if push:
                await _branch("push")

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
                await _branch("otp_input")
                if otp_provider is None:
                    if headless:
                        # Can't type a code into a headless window — bail now so
                        # ensure_session retries headed instead of burning the
                        # 180s loop (the "frozen bootstrap").
                        raise RuntimeError(
                            "Chase 2FA code required — retrying with a visible browser")
                    # Headed GUI flow: let the user type the code straight into the
                    # visible browser; keep polling for auth (bounded, never frozen).
                    # In background mode that browser is parked off-screen with no
                    # taskbar button, so it is only "visible" once revealed -- and
                    # the app has to say so, since nothing else asks for the code.
                    if not code_handed_over:
                        code_handed_over = True
                        quiet.reveal_browser(browser)
                        notify_user(
                            "Chase", "Enter your Chase code in the browser",
                            "Chase sent you a security code. Type it into the "
                            "Chase browser window that just opened and press Next.")
                    await page.sleep(3)
                    continue

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

            # No challenge we recognise. Before burning another poll, ask the
            # page whether Chase has already refused the credentials — it says
            # so inline and never changes URL.
            form_err = await _login_form_error(page)
            if form_err:
                _stage("login_rejected", f"{form_err}\nurl={await _page_url(page)}")
                raise RuntimeError(
                    f"Chase rejected the sign-in: {form_err}{_credential_hint(form_err)}")

            await _branch("unrecognised_page")
            await page.sleep(1)

        # Loop exhausted: no challenge we know about ever appeared and the API
        # never authenticated. The old code then waited ANOTHER 180s here, so a
        # dead login looked frozen for six minutes; 45s is enough to catch a
        # challenge the user has just finished in a visible window.
        _stage("login_loop_timeout",
               f"180s elapsed with no authenticated session\n"
               f"last_branch={last_branch or 'none'}\nheadless={headless}\n"
               f"url={await _page_url(page)}")
        cookies = await _wait_for_auth(browser, page, timeout_s=45)
        if prime_trade:
            await _prime_trade_context(page)
            cookies = await _cookies_from_browser(browser)
            _login_verified(cookies)
        return cookies

    finally:
        # However the login ended, whatever it asked of the user is over.
        clear_notice("Chase")
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

    # Only read OTP from the terminal when there's a real interactive console
    # (CLI runs). In the GUI the worker thread has no usable stdin, so a blocking
    # input() would freeze bootstrap forever — there we run headed and let the
    # user type the code straight into the visible browser instead.
    try:
        interactive = bool(sys.stdin and sys.stdin.isatty())
    except Exception:
        interactive = False
    otp_provider = _otp_provider_terminal() if interactive else None

    # Both attempts share ONE deadline. Two independent 8-min attempts could
    # hold the Chase slot ~16 min — longer than the app's 15-min mirror stall
    # window. Pinned now, in the caller's thread, while the active login is
    # still the one this call is for.
    deadline = time.monotonic() + LOGIN_TOTAL_TIMEOUT_S
    profile = _profile_dir()

    def _run(headless: bool, budget_s: float) -> Dict[str, str]:
        # Each attempt gets its own thread + event loop, bounded by join(): a
        # hang that cancellation can't unwind still hands control back (and
        # frees the Chase slot) instead of wedging until the app restarts. The
        # next attempt's cleanup_orphaned_chrome() reaps anything left behind.
        box: Dict[str, Any] = {}

        def _worker() -> None:
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                box["ok"] = _attempt(loop, headless)
            except BaseException as e:
                box["err"] = e
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

        t = threading.Thread(target=_worker, name=f"chase-login-{'hl' if headless else 'hd'}",
                             daemon=True)
        t.start()
        t.join(budget_s)
        if t.is_alive():
            _stage("login_attempt_timeout", f"headless={headless} after {budget_s:.0f}s")
            raise _LoginAttemptTimeout(
                f"Chase login did not finish within {max(1, round(budget_s / 60))} min")
        if "err" in box:
            raise box["err"]
        return box["ok"]

    def _attempt(loop, headless: bool) -> Dict[str, str]:
        return loop.run_until_complete(
            _async_login(
                user,
                pw,
                otp_provider,
                prime_trade=prime_trade,
                headless_override=headless,
                profile_dir=profile,
                notify_push=True,
                # notify_user, not print(): print() goes nowhere under pythonw.
                notify_push_fn=lambda: notify_user(
                    "Chase", "Approve the Chase sign-in",
                    "Chase sent a push notification. Approve it in your Chase app."),
            )
        )

    try:
        # Warm sessions verify headless (no window). If that attempt fails —
        # typically because a fresh login hit interactive 2FA that can't be
        # completed headless — retry with a visible browser so the user can
        # finish the challenge. force_headed (debug) skips straight to headed.
        initial_headless = False if force_headed else _default_headless()
        try:
            cookies = _run(initial_headless,
                           min(LOGIN_ATTEMPT_TIMEOUT_S, deadline - time.monotonic()))
        except Exception as first:
            if not initial_headless:
                raise  # already headed — nothing more to try
            # A backstop timeout means the attempt HUNG, not that it hit 2FA —
            # a headed retry would usually hang the same way, and the shared
            # deadline has (almost) nothing left for it anyway. Likewise skip a
            # retry with too little time to complete a push approval.
            remaining = deadline - time.monotonic()
            if isinstance(first, _LoginAttemptTimeout) or remaining < LOGIN_RETRY_MIN_S:
                _stage("headed_retry_skipped",
                       f"{type(first).__name__}: {first} | remaining={remaining:.0f}s")
                raise
            _stage("headed_retry", f"after {type(first).__name__}: {first} | budget={remaining:.0f}s")
            cookies = _run(False, remaining)

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
# Public interface expected by RSAMAXXED
# =============================================================================
def _bootstrap_one(*args, **kwargs) -> BrokerOutput:
    """
    Kept for compatibility only. Not intended as a required bot-level flow.
    """
    prime_trade = bool(kwargs.pop("prime_trade", False))
    return ensure_session(prime_trade=prime_trade, **kwargs)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    # Deliberately calls the WRAPPED get_holdings: one fan-out, not two.
    return get_holdings(*args, **kwargs)


def _get_holdings_one(*args, **kwargs) -> BrokerOutput:
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

                # A 200 without a positions list is not "holds nothing": an
                # empty ok=True row lets auto-sell skip shares that are there.
                # NEEDS LIVE VERIFICATION: that an empty account still sends
                # "positions": [] rather than omitting the key.
                raw_positions = data.get("positions") if isinstance(data, dict) else None
                if raw_positions is None and isinstance(data, dict) and "positions" in data:
                    raw_positions = []
                if not isinstance(raw_positions, list):
                    keys = sorted(str(k) for k in data.keys())[:20] if isinstance(data, dict) else []
                    outs.append(
                        AccountOutput(
                            account_id=acct_line,
                            ok=False,
                            message=("Chase answered without a positions list — holdings "
                                     f"could not be read (keys: {keys})"),
                            holdings=[],
                            extra={
                                "account_mask": str(mask),
                                "account_value_reported": float(acc_val) if acc_val is not None else None,
                                "positions_http_status": int(r.status_code),
                            },
                        )
                    )
                    continue

                cash_skipped = 0
                cash_value = 0.0
                parsed = 0

                for pos in raw_positions:
                    if not isinstance(pos, dict):
                        continue

                    # skip “Cash” positions (legacy behavior) -- but a line is
                    # cash only by its type or by having no tradable symbol. A
                    # real security whose NAME says "Cash" keeps its row.
                    long_name = str(pos.get("instrumentLongName") or "")
                    if "Cash" in long_name and not _is_cash_position(pos):
                        pass  # a security named "...Cash..." -- a holding
                    elif "Cash" in long_name:
                        cash_skipped += 1
                        # Counted but discarded, which is right for a holdings
                        # list and wrong for anything that wants to know what
                        # the account can buy. Keep the dollars on the side.
                        # A cash line prices at 1.00, so quantity alone is the
                        # value whenever no price comes back.
                        _q = _as_float(pos.get("tradedUnitQuantity")) or 0.0
                        _p = _as_float((pos.get("marketPrice") or {}).get("baseValueAmount"))
                        cash_value += _q * _p if _p else _q
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
                    "cash": float(cash_value),
                    "cash_source": "cash_positions",
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


def _not_sent(msg: str) -> str:
    """`msg` worded for the app's positive nothing-sent rule. Only for a
    failure that provably came before any execute POST."""
    msg = (msg or "").strip() or "Chase failed"
    return msg if "nothing was sent" in msg.lower() else f"{msg} — nothing was sent"


def _boot_not_sent(boot: BrokerOutput) -> BrokerOutput:
    """A failed sign-in, as a trade result: every row says nothing was sent."""
    accts = [AccountOutput(account_id=a.account_id, ok=a.ok,
                           message=a.message if a.ok else _not_sent(a.message),
                           order_id=a.order_id)
             for a in (boot.accounts or [])]
    if not accts:
        accts = [AccountOutput(account_id="Chase", ok=False,
                               message=_not_sent(boot.message or "Chase login failed"))]
    return BrokerOutput(broker=boot.broker, state=boot.state, accounts=accts,
                        message=boot.message)


def _execute_trade_one(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Chase", ok=False, message=_not_sent("Cancelled before start"))],
            message="Cancelled",
        )

    # NOTE: trade path unchanged (kept verbatim from your version)
    # Legacy-style: rehydrate + prime trade context before trading
    boot = ensure_session(prime_trade=True, **kwargs)
    if boot.state not in ("success", "partial"):
        # Never got in: no order request was made for any account.
        return _boot_not_sent(boot)

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

    # Filled by _attempt_trade so the unauthorized retry below knows exactly
    # which accounts it may run again:
    #   loop:       True once the per-account loop has started
    #   unauth_pre: acc_id -> label, for accounts that failed as unauthorized
    #               BEFORE their execute POST (nothing was sent for them)
    #   rows:       acc_id -> that account's result in the latest attempt
    track: Dict[str, Any] = {}

    def _attempt_trade(only_ids: Optional[set] = None) -> BrokerOutput:
        track["loop"] = False
        track["unauth_pre"] = {}
        track["rows"] = {}
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
                accounts=[AccountOutput(account_id="Chase", ok=False,
                                        message=_not_sent(str(e)))],
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
                accounts=[AccountOutput(account_id="Chase", ok=False,
                                        message=_not_sent(str(e)))],
                message=str(e),
            )

        order_type = "MARKET"
        tif = "DAY"
        session = "CORE"

        OK_STATUSES = {"SUBMITTED", "ACCEPTED", "WORKING", "OPEN", "PENDING", "RECEIVED", "QUEUED", "NEW"}
        FILLED_STATUSES = {"FILLED", "EXECUTED", "COMPLETED"}
        BAD_STATUSES = {"REJECTED", "CANCELLED", "CANCELED", "FAILED", "ERROR", "EXPIRED", "VOID"}

        outs: List[AccountOutput] = []
        if only_ids is None:
            for _uid in _unmasked_account_ids(resp):
                outs.append(AccountOutput(
                    account_id=f"Chase account ...{_uid[-4:]}", ok=False,
                    message=("Skipped: Chase listed this account without its number "
                             "mask — nothing was sent")))
        track["loop"] = True
        _first = True

        for _acct_i, (mask, acc_id, _acc_val) in enumerate(accounts):
            if only_ids is not None and str(acc_id) not in only_ids:
                continue
            if _is_cancelled(kwargs):
                break
            if not _first:
                time.sleep(random.uniform(1.0, 3.0))
            _first = False
            acct_label = str(mask)
            n_before = len(outs)
            # Set immediately before the execute POST: from then on an error
            # or an unreadable answer may mean the order is live at Chase.
            exec_sent = False

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

                exec_sent = True
                rx = req.post(
                    url_execute,
                    headers=_base_headers(),
                    cookies=cookies,
                    json=payload_execute,
                    impersonate="chrome",
                    timeout=60,
                )
                if rx.status_code >= 500 or rx.status_code == 408:
                    # A server error / gateway timeout on the execute POST is
                    # not a refusal: Chase may have taken the order.
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=(
                        f"Order submitted but Chase answered HTTP {rx.status_code} — verify in "
                        f"Chase before retrying ({rx.text[:200]})")))
                    continue
                # From here on the execute POST has gone out. Nothing in its
                # answer is a "Rejected": a refusal Chase never acted on looks
                # exactly like a status field we don't know, and calling it
                # rejected told mirror it was safe to buy again. Only the
                # validate phase above may say Rejected.
                if rx.status_code != 200:
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=(
                        f"Order submitted but Chase answered HTTP {rx.status_code} — verify in "
                        f"Chase before retrying ({rx.text[:200]})")))
                    continue

                try:
                    exec_data = rx.json() or {}
                except Exception:
                    # HTTP 200 to the execute POST but an unreadable body: the
                    # order may be live.
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=(
                        "Order submitted but Chase's response could not be read — verify in "
                        f"Chase before retrying ({rx.text[:200]})")))
                    continue

                oid = _parse_order_id(exec_data)
                status = _parse_order_status(exec_data).strip().upper()
                # A status field holding an accepted/filled state is not an
                # error, nor is a "code" that says so (ORDER_ACCEPTED).
                exec_errors = [m for m in _extract_error_messages(exec_data)
                               if m.upper() not in (f"STATUS={status}", f"CODE={status}")
                               or status not in (OK_STATUSES | FILLED_STATUSES)]
                # The error keys proper, without the free-text "messages" list
                # ("Your order has been placed" rides along with an accepted
                # order).
                hard_errors = (_extract_error_messages(
                    {k: v for k, v in exec_data.items() if k not in ("messages", "status", "code")})
                    if isinstance(exec_data, dict) else [])
                if oid and status in (OK_STATUSES | FILLED_STATUSES) and not hard_errors:
                    # An order id with an accepted state is a placed order;
                    # any messages alongside it are Chase's notes, not errors.
                    word = "Filled" if status in FILLED_STATUSES else "Submitted"
                    outs.append(AccountOutput(account_id=acct_label, ok=True,
                                              message=f"{word} (order_id={oid})", order_id=str(oid)))
                    continue

                if oid and not status and not exec_errors:
                    warns = _extract_warnings(exec_data)
                    extra = _join(warns, "")
                    msg = f"Submitted (status unavailable) (order_id={oid})"
                    if extra:
                        msg += f" — Warnings: {extra}"
                    outs.append(AccountOutput(account_id=acct_label, ok=True, message=msg, order_id=str(oid)))
                    continue

                if oid:
                    detail = _join(exec_errors, status.lower() or "no status")
                    outs.append(AccountOutput(account_id=acct_label, ok=False, message=(
                        f"Order submitted (order_id={oid}) but Chase answered '{detail}' — "
                        f"verify in Chase before retrying"), order_id=str(oid)))
                    continue

                warns = _extract_warnings(exec_data)
                detail = _join(exec_errors + warns, "No orderIdentifier returned")
                outs.append(AccountOutput(account_id=acct_label, ok=False, message=(
                    "Order submitted but Chase returned no order id — verify in Chase "
                    f"before retrying ({detail})")))

            except Exception as e:
                if exec_sent:
                    # The execute POST went out; its answer was lost.
                    detail = f"{type(e).__name__}: {e}".strip().rstrip(":")
                    msg = ("Order submitted but Chase's response was lost — verify in "
                           f"Chase before retrying ({detail})")
                else:
                    msg = f"Not sent — {e}"
                outs.append(AccountOutput(account_id=acct_label, ok=False, message=msg))
                if dry_run:
                    log_lines.append(f"[{acct_label}] ERROR: {e}")
                    log_lines.append("")

            finally:
                # In a finally because every branch above ends in `continue`.
                if len(outs) > n_before:
                    row = outs[-1]
                    track["rows"][str(acc_id)] = row
                    if not exec_sent and not row.ok and _looks_unauthorized_text(row.message):
                        track["unauth_pre"][str(acc_id)] = acct_label

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

    if not track.get("loop"):
        # Failed before any account was tried (session / account list /
        # quote): nothing was sent, so the whole trade may run again.
        if _looks_unauthorized_text(out1.message) or any(_looks_unauthorized_text(a.message) for a in (out1.accounts or [])):
            boot2 = ensure_session(prime_trade=True, **kwargs)
            if boot2.state not in ("success", "partial"):
                return _boot_not_sent(boot2)
            return chase_normalize(_attempt_trade())
        return chase_normalize(out1)

    # The loop ran. Only accounts that failed as unauthorized before their
    # execute POST may run again; every other account keeps its result (an
    # order may exist for it).
    retry = dict(track.get("unauth_pre") or {})
    if not retry or _is_cancelled(kwargs):
        return chase_normalize(out1)
    first_rows = dict(track.get("rows") or {})

    boot2 = ensure_session(prime_trade=True, **kwargs)
    if boot2.state not in ("success", "partial"):
        return chase_normalize(out1)
    out2 = _attempt_trade(only_ids=set(retry))
    second_rows = dict(track.get("rows") or {}) if track.get("loop") else {}

    merged: List[AccountOutput] = []
    for a in (out1.accounts or []):
        acc_id = next((k for k, r in first_rows.items() if r is a), None)
        if acc_id is not None and acc_id in retry and acc_id in second_rows:
            merged.append(second_rows[acc_id])
        else:
            merged.append(a)
    ok_ct = sum(1 for a in merged if a.ok)
    state = "success" if ok_ct == len(merged) and merged else ("partial" if ok_ct > 0 else "failed")
    return chase_normalize(BrokerOutput(broker=BROKER, state=state, accounts=merged,
                                        message=out2.message or out1.message))


# ---------------------------------------------------------------------------
# Multi-login entry points
#
# Everything above still handles exactly one login, which is how it has always
# worked and how it is still tested. These wrappers run it once per configured
# login — see broker_logins.fan_out. With one login configured they are a
# straight pass-through, and each login gets its own browser profile and cookie
# jar because _sessions_dir() below is per-login.
# ---------------------------------------------------------------------------


def bootstrap(*args, **kwargs) -> BrokerOutput:
    return broker_logins.fan_out(BROKER, _MODULE, _bootstrap_one, *args, **kwargs)

def get_holdings(*args, **kwargs) -> BrokerOutput:
    return broker_logins.fan_out(BROKER, _MODULE, _get_holdings_one, *args, **kwargs)

def execute_trade(**kwargs) -> BrokerOutput:
    return broker_logins.fan_out(BROKER, _MODULE, _execute_trade_one, **kwargs)

#: Handed to fan_out so it can reach BrokerOutput/AccountOutput and the
#: _on_login_switch hook without importing this module back.
_MODULE = sys.modules[__name__]
