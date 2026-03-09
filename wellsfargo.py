from __future__ import annotations

import asyncio
import json
import os
import random
import re
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo
import uuid
from pathlib import Path
from queue import Queue
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow, find_browser_executable, cleanup_orphaned_chrome
from modules._2fa_prompt import universal_2fa_prompt
from modules import broker_logging as BLOG

BROKER = "wellsfargo"

OtpProvider = Callable[[str, int], Optional[str]]
NotifyFn = Callable[[str], None]


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
    "_x=",
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
# URLs (legacy-aligned)
# =============================================================================

SIGNON_URL = "https://www.wellsfargoadvisors.com/online-access/signon.htm"
BROKOVERVIEW_HINT = "brokoverview"
HOLDINGS_URL_TMPL = "https://wfawellstrade.wellsfargo.com/BW/holdings.do?account={account_index}"


# =============================================================================
# Paths / env
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    d = _root_dir() / "sessions" / "wellsfargo"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _logs_dir() -> Path:
    d = _root_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


_ET = ZoneInfo("America/New_York")


def _dry_run_log_dir() -> Path:
    d = datetime.now(_ET).strftime("%m.%d.%y")
    p = _logs_dir() / BROKER / d
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write_dry_run_log(*, content: str) -> str:
    rand = uuid.uuid4().hex[:10]
    path = _dry_run_log_dir() / f"test_order_{BROKER}_{rand}.log"
    path.write_text(content, encoding="utf-8")
    return str(path)


def _profile_dir() -> Path:
    d = _sessions_dir() / "profile"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _handoff_path() -> Path:
    return _sessions_dir() / "login_handoff.json"


def _write_login_handoff(ok: bool) -> None:
    try:
        _handoff_path().write_text(json.dumps({"ok": bool(ok), "ts": time.time()}), encoding="utf-8")
    except Exception:
        pass


def _headless() -> bool:
    # Default NON-headless (your stabilization preference)
    v = (_env("WELLSFARGO_HEADLESS") or _env("HEADLESS") or "false").lower().strip()
    return v not in ("0", "false", "no", "off")


# =============================================================================
# Tracing
# =============================================================================

def _trace_enabled() -> bool:
    v = (_env("WELLSFARGO_TRACE") or "true").lower().strip()
    return v not in ("0", "false", "no", "off")


def _trace_terminal() -> bool:
    v = (_env("WELLSFARGO_TRACE_TERMINAL") or "false").lower().strip()
    return v in ("1", "true", "yes", "on")


def _trace_path() -> Path:
    return _sessions_dir() / "wf_nav.log"


def _trace(msg: str, notify: Optional[NotifyFn] = None) -> None:
    if not _trace_enabled():
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[{ts}] {msg}\n"
    try:
        with _trace_path().open("a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    if notify is not None and _trace_terminal():
        try:
            notify(f"Wells Fargo trace: {msg}")
        except Exception:
            pass


def _is_cancelled_ctx(ctx: Dict[str, Any]) -> bool:
    token = ctx.get("cancel_event")
    if token is None:
        token = ctx.get("cancel_token")
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
# Terminal helpers (OTP + notify)
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


def _notify_terminal() -> NotifyFn:
    """Notification function that prints to terminal."""
    def notify(msg: str) -> None:
        try:
            print(f"[Wells Fargo] {msg}")
        except UnicodeEncodeError:
            print(f"[Wells Fargo] {msg.encode('ascii', 'replace').decode('ascii')}")
    return notify


# =============================================================================
# Async runner
# =============================================================================

def _run_coro(coro_factory: Callable[[], Coroutine[Any, Any, Any]], *, timeout_s: int = 900):
    try:
        asyncio.get_running_loop()
        in_running_loop = True
    except RuntimeError:
        in_running_loop = False

    if not in_running_loop:
        return asyncio.run(coro_factory())

    q: "Queue[Tuple[bool, Any]]" = Queue()

    def runner() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res = loop.run_until_complete(coro_factory())
            q.put((True, res))
        except Exception as e:
            q.put((False, e))
        finally:
            try:
                loop.close()
            except Exception:
                pass

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout_s)

    if q.empty():
        raise TimeoutError("Wells Fargo operation timed out")

    ok, payload = q.get()
    if ok:
        return payload
    raise payload


# =============================================================================
# Profile lock (prevents concurrent browser profile corruption)
# =============================================================================

def _lock_file() -> Path:
    return _sessions_dir() / ".profile.lock"


def _clean_chrome_singletons(profile_dir: Path) -> None:
    """Remove Chrome SingletonLock/Socket/Cookie files that prevent reuse."""
    for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
        try:
            (profile_dir / name).unlink(missing_ok=True)
        except Exception:
            pass

def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running."""
    try:
        import signal
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False

def _acquire_profile_lock(timeout_s: int = 60, poll_s: float = 0.25, stale_s: int = 120) -> Path:
    lock = _lock_file()
    # Clean Chrome singleton files that can block profile reuse
    _clean_chrome_singletons(_sessions_dir() / "profile")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if lock.exists():
                # Check if owning PID is still alive
                try:
                    pid_text = lock.read_text().strip()
                    if pid_text.isdigit() and not _is_pid_alive(int(pid_text)):
                        lock.unlink()
                except Exception:
                    pass
                # Fall back to age-based staleness
                try:
                    age = time.time() - lock.stat().st_mtime
                    if age > stale_s:
                        lock.unlink()
                except Exception:
                    pass
        except Exception:
            pass

        try:
            fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, str(os.getpid()).encode("utf-8"))
            finally:
                os.close(fd)
            return lock
        except FileExistsError:
            time.sleep(poll_s)

    raise RuntimeError("Wells Fargo profile is busy (another browser is running). Try again.")


def _release_profile_lock(lock: Path) -> None:
    try:
        lock.unlink()
    except Exception:
        pass


# =============================================================================
# Zendriver helpers + browser lifecycle
# =============================================================================

async def _settle(page, sleep_s: float = 0.4) -> None:
    try:
        await page.wait_for_ready_state("complete")
    except Exception:
        pass
    try:
        await page.wait()
    except Exception:
        pass
    try:
        await page.sleep(sleep_s)
    except Exception:
        pass


async def _current_url(page) -> str:
    try:
        return await page.evaluate("window.location.href")
    except Exception:
        return ""


async def _goto(page, url: str, label: str, *, notify: Optional[NotifyFn] = None, settle_s: float = 0.8) -> None:
    _trace(f"{label} | goto={url}", notify=notify)
    try:
        await page.get(url)
    except Exception as e:
        _trace(f"{label} | goto ERROR: {type(e).__name__}: {e}", notify=notify)
    await _settle(page, sleep_s=settle_s)
    u = await _current_url(page)
    _trace(f"{label} | after goto url={u}", notify=notify)


async def _safe_select(page, selector: str, timeout_s: float = 5.0):
    try:
        return await page.select(selector, timeout=timeout_s)
    except Exception:
        return None


async def _element_text(el) -> str:
    if el is None:
        return ""
    try:
        t = getattr(el, "text_all", "")
        if t:
            return str(t)
    except Exception:
        pass
    try:
        tc = await el.text_content()
        return (tc or "").strip()
    except Exception:
        return ""


async def _start_browser(*, headless: Optional[bool] = None):
    try:
        import zendriver as uc  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Missing dependency zendriver: {e}")

    use_headless = _headless() if headless is None else bool(headless)

    profile = _profile_dir()
    # Kill any orphaned Chrome still using this profile
    cleanup_orphaned_chrome(profile)
    lock = _acquire_profile_lock(timeout_s=60)

    browser_args: List[str] = ["--no-sandbox"]
    if use_headless:
        browser_args.extend(["--headless=new", "--window-size=1920,1080"])
    else:
        browser_args.extend([
            "--start-maximized",
            "--disable-session-crashed-bubble",
            "--disable-infobars",
            "--disable-features=TranslateUI,VizDisplayCompositor",
            "--no-first-run",
            "--disable-default-apps",
            "--disable-extensions",
        ])

    browser_args.extend([
        "--force-device-scale-factor=0.8",
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ])

    try:
        browser = await uc.start(browser_args=browser_args, user_data_dir=str(profile), browser_executable_path=find_browser_executable())
        setattr(browser, "_wf_lock_path", str(lock))
        page = browser.tabs[0] if getattr(browser, "tabs", None) else await browser()
        return browser, page
    except Exception:
        _release_profile_lock(lock)
        raise


async def _close_browser(browser) -> None:
    try:
        await asyncio.sleep(2)
        for tab in getattr(browser, "tabs", []) or []:
            try:
                await tab.close()
            except Exception:
                pass
        await asyncio.sleep(1)
        try:
            await browser.stop()
        except Exception:
            pass
        # Force-kill any lingering Chrome processes for this profile
        await asyncio.sleep(1)
        try:
            cleanup_orphaned_chrome(_profile_dir())
        except Exception:
            pass
    finally:
        lock_path = getattr(browser, "_wf_lock_path", None)
        if lock_path:
            _release_profile_lock(Path(lock_path))


# =============================================================================
# Login + 2FA (legacy-aligned)
# =============================================================================

async def _handle_2fa(page, *, otp_provider: Optional[OtpProvider], notify: Optional[NotifyFn]) -> None:
    await _settle(page, sleep_s=1.0)

    try:
        content = await page.get_content()
    except Exception:
        content = ""

    if "We sent a notification to your phone" in (content or ""):
        _trace("2FA | push detected", notify=notify)
        if notify:
            notify("📲 Wells Fargo sent a push notification. Approve it on your phone (waiting up to 2 minutes).")

        for _ in range(60):  # 120s
            await _settle(page, sleep_s=0.8)
            u = (await _current_url(page)).lower()
            if BROKOVERVIEW_HINT in u:
                _trace("2FA | push approved -> brokoverview", notify=notify)
                return
            await page.sleep(2)

        _trace("2FA | push timed out -> try another method", notify=notify)
        btn = await _safe_select(page, "#buttonTryAnotherMethod", timeout_s=10.0)
        if not btn:
            raise RuntimeError("2FA push timed out; could not find #buttonTryAnotherMethod")
        try:
            await btn.mouse_click()
        except Exception:
            pass
        await _settle(page, sleep_s=1.0)

    try:
        options = await page.select_all('[role="listitem"] button', timeout=5)
    except Exception:
        options = None

    if options:
        for opt in options:
            txt = (await _element_text(opt)).strip()
            if "Mobile" in txt:
                _trace("2FA | selecting Mobile option", notify=notify)
                try:
                    await opt.mouse_click()
                except Exception:
                    pass
                await _settle(page, sleep_s=1.0)
                break

    sms_btn = await _safe_select(page, "#optionSMS button", timeout_s=10.0)
    if sms_btn:
        _trace("2FA | clicking #optionSMS button", notify=notify)
        try:
            await sms_btn.mouse_click()
        except Exception:
            pass
        await _settle(page, sleep_s=1.0)

    otp_input = await _safe_select(page, "#otp", timeout_s=10.0)
    if not otp_input:
        u = (await _current_url(page)).lower()
        if BROKOVERVIEW_HINT in u:
            return
        raise RuntimeError("2FA flow: OTP input #otp not found")

    if otp_provider:
        code = otp_provider("Wells Fargo", 300)
    else:
        code = input("Enter Wells Fargo OTP: ").strip()

    if not code:
        raise RuntimeError("2FA flow: no OTP code provided")

    try:
        await otp_input.send_keys(code)
    except Exception:
        pass

    submit = await _safe_select(page, 'button[type="submit"]', timeout_s=10.0)
    if not submit:
        raise RuntimeError("2FA flow: submit button not found (button[type='submit'])")

    _trace("2FA | submitting OTP", notify=notify)
    try:
        await submit.mouse_click()
    except Exception:
        pass

    for _ in range(60):
        await _settle(page, sleep_s=0.8)
        u = (await _current_url(page)).lower()
        if BROKOVERVIEW_HINT in u:
            _trace("2FA | OTP accepted -> brokoverview", notify=notify)
            return
        await page.sleep(1)

    raise RuntimeError("2FA flow: OTP submitted but brokoverview never loaded")


async def _login_on_page(
    page,
    *,
    username: str,
    password: str,
    otp_provider: Optional[OtpProvider],
    notify: Optional[NotifyFn],
) -> bool:
    _trace("LOGIN | begin", notify=notify)
    await _goto(page, SIGNON_URL, "LOGIN", notify=notify, settle_s=1.0)

    user_el = await _safe_select(page, "input[id=j_username]", timeout_s=10.0)
    pass_el = await _safe_select(page, "input[id=j_password]", timeout_s=10.0)
    btn = await _safe_select(page, ".button.button--login.button--signOn", timeout_s=10.0)

    if not user_el or not pass_el or not btn:
        _trace("LOGIN | missing username/password/button", notify=notify)
        return False

    try:
        await user_el.mouse_click()
        await user_el.clear_input()
    except Exception:
        pass
    try:
        await user_el.send_keys(username)
    except Exception:
        pass

    try:
        await pass_el.send_keys(password)
    except Exception:
        pass

    _trace("LOGIN | click login button", notify=notify)
    try:
        await btn.mouse_click()
    except Exception:
        pass

    await _settle(page, sleep_s=1.0)

    u = await _current_url(page)
    if u and "dest=INTERDICTION" in u:
        _trace(f"LOGIN | 2FA interdict detected url={u}", notify=notify)
        await _handle_2fa(page, otp_provider=otp_provider, notify=notify)
        u = await _current_url(page)

    u_low = (u or "").lower()
    if BROKOVERVIEW_HINT in u_low:
        _trace(f"LOGIN | success url={u}", notify=notify)
        return True

    for _ in range(15):
        await _settle(page, sleep_s=0.5)
        u2 = (await _current_url(page)).lower()
        if BROKOVERVIEW_HINT in u2:
            _trace("LOGIN | success after short wait", notify=notify)
            return True
        await page.sleep(0.5)

    _trace(f"LOGIN | failed end_url={u}", notify=notify)
    return False


# =============================================================================
# Account discovery + holdings scrape (legacy-aligned)
# =============================================================================

def _extract_x_param(url: str) -> str:
    m = re.search(r"_x=([^&]+)", url or "")
    if not m:
        return ""
    return f"_x={m.group(1)}"


def _to_float(s: str) -> Optional[float]:
    try:
        x = str(s or "").replace("$", "").replace(",", "").strip()
        return float(x) if x else None
    except Exception:
        return None


def _mask_last4(raw: str) -> str:
    raw = (raw or "").strip()
    return f"****{raw[-4:]}" if len(raw) >= 4 else "****"


async def _fetch_initial_account_data(page, *, notify: Optional[NotifyFn] = None) -> List[Dict[str, Any]]:
    await _settle(page, sleep_s=2.0)

    try:
        await page.select("#account-summary", timeout=10)
    except Exception:
        try:
            await page.reload()
        except Exception:
            pass
        await _settle(page, sleep_s=2.0)
        try:
            await page.select("#account-summary", timeout=10)
        except Exception:
            pass

    url = await _current_url(page)
    x_param = _extract_x_param(url)
    _trace(f"POSITIONS | x_param={x_param}", notify=notify)

    html = await page.get_content()
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Missing bs4 dependency: {e}")

    soup = BeautifulSoup(html, "html.parser")
    rows = soup.select("tr[data-p_account]")
    _trace(f"POSITIONS | rows={len(rows)}", notify=notify)

    out: List[Dict[str, Any]] = []
    for row in rows:
        idx = (row.get("data-p_account") or "").strip()
        if not idx or idx == "-1":
            continue

        account_name_el = row.select_one('[role="rowheader"]')
        if not account_name_el:
            continue

        nickname_el = account_name_el.select_one(".ellipsis")
        nickname = nickname_el.get_text(strip=True) if nickname_el else "WellsFargo"

        acct_number_div = account_name_el.select_one("div:not(.ellipsis-container)")
        acct_number = acct_number_div.get_text(strip=True).replace("*", "") if acct_number_div else ""
        mask = _mask_last4(acct_number)

        balance_cells = row.select("td[data-sort-value]")
        balance_text = balance_cells[-1].get_text(strip=True) if balance_cells else ""
        bal = _to_float(balance_text)

        out.append({
            "account_id": f"{nickname} ({mask})",
            "mask": mask,
            "balance": bal,
            "index": idx,
            # include x param but do NOT persist it into extras (denylist) to avoid leakage
            "x_param": x_param,
        })

    return out


async def _fetch_holdings_for_account(page, acct: Dict[str, Any], *, notify: Optional[NotifyFn] = None) -> List[HoldingRow]:
    idx = acct["index"]
    x_param = acct.get("x_param") or ""

    url = HOLDINGS_URL_TMPL.format(account_index=idx)
    if x_param:
        url = f"{url}&{x_param}"

    await _goto(page, url, f"HOLDINGS[{acct.get('mask','')}]",
               notify=notify, settle_s=1.2)

    await _settle(page, sleep_s=1.0)

    html = await page.get_content()
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception as e:
        raise RuntimeError(f"Missing bs4 dependency: {e}")

    soup = BeautifulSoup(html, "html.parser")
    holding_rows = soup.select("tbody > tr.level1")

    rows: List[HoldingRow] = []
    for r in holding_rows:
        sym_el = r.select_one("a.navlink.quickquote")
        if not sym_el:
            continue
        symbol = sym_el.get_text(strip=True).replace(",popup", "").strip().upper()

        numeric_cells = r.select("td.datanumeric")
        qty: Optional[float] = None
        px: Optional[float] = None

        if len(numeric_cells) > 2:
            qty_div = numeric_cells[1].select_one("div:first-child")
            px_div = numeric_cells[2].select_one("div:first-child")
            if qty_div:
                try:
                    qty = float(qty_div.get_text(strip=True).replace(",", ""))
                except Exception:
                    qty = None
            if px_div:
                try:
                    px = float(px_div.get_text(strip=True).replace("$", "").replace(",", ""))
                except Exception:
                    px = None

        if symbol and qty and qty > 0:
            # minimal extras for discovery (no raw HTML, no x-param, no account ids)
            hextra: Dict[str, Any] = {
                "source": "wf_holdings_table",
            }
            if px is not None:
                try:
                    hextra["market_value_calc"] = float(qty) * float(px)
                except Exception:
                    pass

            rows.append(HoldingRow(symbol=symbol, shares=qty, price=px, extra=hextra))

    return rows


# =============================================================================
# Inline commands (consolidated from commands/*.py)
# =============================================================================

def _build_ctx(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    user = _env("WELLSFARGO_USERNAME")
    pw = _env("WELLSFARGO_PASSWORD")

    side = kwargs.get("side")
    qty = kwargs.get("qty")
    symbol = kwargs.get("symbol")
    dry_run = bool(kwargs.get("dry_run") or False)
    force_headed = bool(kwargs.get("debug") or False)

    otp_provider = _otp_provider_terminal()
    notify = _notify_terminal()

    return {
        "username": user,
        "password": pw,
        "otp_provider": otp_provider,
        "notify": notify,

        # logging (shared broker_logging contract)
        "log_dir": _logs_dir(),

        # IMPORTANT:
        # - headed only when debug/dry_run is explicitly requested
        # - otherwise always headless for normal runs
        "headless": (False if (dry_run or force_headed) else True),

        # trade params
        "side": side,
        "qty": qty,
        "symbol": symbol,
        "dry_run": dry_run,

        "_write_dry_run_log": _write_dry_run_log,

        "_start_browser": _start_browser,
        "_close_browser": _close_browser,
        "_login_on_page": _login_on_page,
        "_fetch_initial_account_data": _fetch_initial_account_data,
        "_fetch_holdings_for_account": _fetch_holdings_for_account,
        "_current_url": _current_url,
        "_write_login_handoff": _write_login_handoff,
        "cancel_event": kwargs.get("cancel_event"),
    }


async def _cmd_login(ctx) -> BrokerOutput:
    notify = ctx.get("notify")
    otp_provider = ctx.get("otp_provider")

    browser = None
    page = None

    try:
        browser, page = await ctx["_start_browser"](headless=bool(ctx.get("headless")))

        ok = await ctx["_login_on_page"](
            page,
            username=ctx["username"],
            password=ctx["password"],
            otp_provider=otp_provider,
            notify=notify,
        )
        ctx["_write_login_handoff"](ok)

        if not ok:
            try:
                current_url = ""
                try:
                    current_url = await ctx["_current_url"](page)
                except Exception:
                    current_url = ""

                BLOG.write_log(
                    ctx,
                    broker=BROKER,
                    action="login",
                    label="Wells Fargo",
                    filename_prefix="login_failed",
                    text=(
                        "Wells Fargo login returned ok=False (no exception).\n"
                        f"headless={bool(ctx.get('headless'))}\n"
                        f"url={current_url}\n"
                        "See sessions/wellsfargo/wf_nav.log for step trace.\n"
                    ),
                    secrets=[ctx.get("username"), ctx.get("password")],
                )
            except Exception:
                pass

        return BrokerOutput(
            broker=BROKER,
            state="success" if ok else "failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=ok, message="Login ok" if ok else "Login failed")],
            message="Login ok" if ok else "Login failed",
        )

    except Exception as e:
        ctx["_write_login_handoff"](False)

        try:
            BLOG.log_exception(
                ctx,
                broker=BROKER,
                action="login",
                label="Wells Fargo",
                exc=e,
                secrets=[ctx.get("username"), ctx.get("password")],
            )
        except Exception:
            pass

        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"Login failed: {type(e).__name__}: {e}")],
            message=f"Login failed: {type(e).__name__}: {e}",
        )

    finally:
        try:
            if browser is not None:
                await ctx["_close_browser"](browser)
        except Exception:
            pass


async def _cmd_positions(ctx) -> BrokerOutput:
    notify = ctx.get("notify")
    otp_provider = ctx.get("otp_provider")

    browser = None
    page = None

    try:
        if _is_cancelled_ctx(ctx):
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Cancelled before start")],
                message="Cancelled",
            )

        browser, page = await ctx["_start_browser"](headless=bool(ctx.get("headless")))

        ok = await ctx["_login_on_page"](
            page,
            username=ctx["username"],
            password=ctx["password"],
            otp_provider=otp_provider,
            notify=notify,
        )
        ctx["_write_login_handoff"](ok)

        if not ok:
            u = ""
            try:
                u = await ctx["_current_url"](page)
            except Exception:
                pass

            try:
                BLOG.write_log(
                    ctx,
                    broker=BROKER,
                    action="positions",
                    label="login_failed",
                    filename_prefix="positions_login_failed",
                    text=(
                        "Wells Fargo positions: login returned ok=False (no exception).\n"
                        f"headless={bool(ctx.get('headless'))}\n"
                        f"url={u}\n"
                        "See sessions/wellsfargo/wf_nav.log for trace.\n"
                    ),
                    secrets=[ctx.get("username"), ctx.get("password")],
                )
            except Exception:
                pass

            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"Login failed (landed on: {u})")],
                message="Login failed",
            )

        accts = await ctx["_fetch_initial_account_data"](page, notify=notify)
        if not accts:
            u = ""
            try:
                u = await ctx["_current_url"](page)
            except Exception:
                pass

            try:
                BLOG.write_log(
                    ctx,
                    broker=BROKER,
                    action="positions",
                    label="no_accounts",
                    filename_prefix="positions_no_accounts",
                    text=(
                        "Wells Fargo positions: _fetch_initial_account_data returned 0 accounts.\n"
                        f"headless={bool(ctx.get('headless'))}\n"
                        f"url={u}\n"
                        "See sessions/wellsfargo/wf_nav.log for trace.\n"
                    ),
                    secrets=[ctx.get("username"), ctx.get("password")],
                )
            except Exception:
                pass

            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"No accounts found (url: {u})")],
                message="No accounts found",
            )

        outputs: List[AccountOutput] = []

        broker_extra: Dict[str, Any] = {
            "accounts_total": int(len(accts)),
            "accounts_ok": 0,
            "accounts_failed": 0,
            "positions_total": 0,
            "headless": bool(ctx.get("headless")),
        }

        for acct in accts:
            if _is_cancelled_ctx(ctx):
                break
            rows = await ctx["_fetch_holdings_for_account"](page, acct, notify=notify)
            total = acct.get("balance")
            label = f"{acct['account_id']} = ${total:.2f}" if total is not None else f"{acct['account_id']} = ?"

            acct_extra: Dict[str, Any] = {
                "mask": acct.get("mask"),
                "balance": total,
                "index": acct.get("index"),
                "positions_count": int(len(rows)),
            }
            # do NOT persist x_param
            # also include safe keys for discovery
            try:
                acct_extra["acct_keys"] = sorted([str(k) for k in acct.keys()])[:50]
                acct_extra.update(_flatten_safe(acct, prefix="acct_", max_items=40))
                acct_extra.pop("acct_x_param", None)
            except Exception:
                pass

            outputs.append(AccountOutput(account_id=label, ok=True, message="", holdings=rows, extra=acct_extra))
            broker_extra["accounts_ok"] = int(broker_extra["accounts_ok"]) + 1
            broker_extra["positions_total"] = int(broker_extra["positions_total"]) + int(len(rows))

        if _is_cancelled_ctx(ctx):
            state = "partial" if any(a.ok for a in outputs) else "failed"
            return BrokerOutput(broker=BROKER, state=state, accounts=outputs, message="Cancelled", extra=broker_extra)

        return BrokerOutput(broker=BROKER, state="success", accounts=outputs, message="", extra=broker_extra)

    except Exception as e:
        try:
            BLOG.log_exception(
                ctx,
                broker=BROKER,
                action="positions",
                label="Wells Fargo",
                exc=e,
                secrets=[ctx.get("username"), ctx.get("password")],
            )
        except Exception:
            pass

        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"{type(e).__name__}: {e}")],
            message=f"{type(e).__name__}: {e}",
        )

    finally:
        try:
            if browser is not None:
                await ctx["_close_browser"](browser)
        except Exception:
            pass


def _parse_qty_int(qty: Any) -> Optional[int]:
    try:
        f = float(qty)
        if f <= 0:
            return None
        if int(f) != f:
            return None
        return int(f)
    except Exception:
        return None


def _to_float_any(s: Any) -> Optional[float]:
    try:
        if s is None:
            return None
        txt = str(s).replace("$", "").replace(",", "").strip()
        return float(txt) if txt else None
    except Exception:
        return None


async def _select_dropdown_option(page, dropdown_opener_selector: str, option_value: str, *, timeout_s: float = 10.0) -> None:
    opener = await page.select(dropdown_opener_selector, timeout=timeout_s)
    await opener.scroll_into_view()
    await opener.mouse_click()

    option_selector = f"a[data-val='{option_value}']"
    opt = await page.select(option_selector, timeout=timeout_s)
    await opt.scroll_into_view()
    await opt.mouse_click()


async def _get_account_mask(page) -> str:
    try:
        el = await page.select(".acctmask", timeout=5)
    except Exception:
        return ""

    if isinstance(el, list):
        el = el[0] if el else None
    if not el:
        return ""

    try:
        full_text = getattr(el, "text_all", "") or ""
    except Exception:
        full_text = ""

    full_text = str(full_text)
    full_text = re.sub(r"Account ending with", "", full_text, flags=re.I).strip()
    full_text = full_text.replace("*", "").strip()
    return full_text


async def _cmd_trade(ctx: Dict[str, Any]) -> BrokerOutput:
    notify = ctx.get("notify")
    otp_provider = ctx.get("otp_provider")
    dry_run = bool(ctx.get("dry_run") or False)

    log_lines: List[str] = []
    if dry_run:
        log_lines.append("DRY RUN — NO ORDER SUBMITTED")

    side = (ctx.get("side") or "").strip().lower()
    qty_raw = ctx.get("qty")
    symbol = (ctx.get("symbol") or "").strip().upper()

    if side not in ("buy", "sell"):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"Invalid side: {side!r}")],
            message=f"Invalid side: {side!r}",
        )

    qty_int = _parse_qty_int(qty_raw)
    if qty_int is None:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"Invalid qty (whole shares only): {qty_raw!r}")],
            message="Invalid qty",
        )

    if not symbol:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Missing symbol")],
            message="Missing symbol",
        )

    action = "Buy" if side == "buy" else "Sell"

    try:
        from zendriver.core.keys import KeyEvents, KeyPressEvent  # type: ignore
        from zendriver import SpecialKeys  # type: ignore
    except Exception:  # pragma: no cover
        KeyEvents = None  # type: ignore
        KeyPressEvent = None  # type: ignore
        SpecialKeys = None  # type: ignore

    browser = None
    page = None

    try:
        if _is_cancelled_ctx(ctx):
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Cancelled before start")],
                message="Cancelled",
            )

        browser, page = await ctx["_start_browser"](headless=bool(ctx.get("headless")))

        ok = await ctx["_login_on_page"](
            page,
            username=ctx["username"],
            password=ctx["password"],
            otp_provider=otp_provider,
            notify=notify,
        )
        ctx["_write_login_handoff"](ok)

        if not ok:
            u = await ctx["_current_url"](page)
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"Login failed (landed on: {u})")],
                message="Login failed",
            )

        accts = await ctx["_fetch_initial_account_data"](page, notify=notify)
        if not accts:
            u = await ctx["_current_url"](page)
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=f"No accounts found (url: {u})")],
                message="No accounts found",
            )

        outputs: List[AccountOutput] = []

        for _acct_i, acct in enumerate(accts):
            if _acct_i > 0:
                await asyncio.sleep(random.uniform(1.0, 3.0))
            if _is_cancelled_ctx(ctx):
                break
            idx = acct.get("index")
            x_param = acct.get("x_param") or ""
            acct_label = acct.get("account_id") or "Wells Fargo"

            try:
                trade_url = f"https://wfawellstrade.wellsfargo.com/BW/equity.do?account={idx}&symbol=&selectedAction="
                if x_param:
                    trade_url = f"{trade_url}&{x_param}"

                await page.get(trade_url)
                await page.wait_for_ready_state("complete")
                await page.wait()

                try:
                    await page.select("#eqentryfrm", timeout=10)
                except Exception:
                    pass

                mask = await _get_account_mask(page)
                if mask and mask not in acct_label:
                    acct_label = f"{acct_label} [*{mask}]"

                await _select_dropdown_option(page, "#BuySellBtn", action)

                sym_in = await page.select("#Symbol", timeout=10)
                await sym_in.scroll_into_view()
                try:
                    await sym_in.clear_input()
                except Exception:
                    pass
                await sym_in.send_keys(symbol)
                if SpecialKeys is not None:
                    await sym_in.send_keys(SpecialKeys.TAB)
                else:
                    await sym_in.send_keys("\t")

                await page.select("#prevdata", timeout=10)

                if action == "Sell":
                    try:
                        owned_el = await page.select("#currentSharesOwned .numshares", timeout=10)
                        owned_txt = (getattr(owned_el, "text_all", "") or "").strip()
                        owned = int(re.sub(r"[^0-9]", "", owned_txt) or "0")
                        if owned <= 0:
                            outputs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Skipped sell: own 0 shares of {symbol}"))
                            continue
                        if qty_int > owned:
                            outputs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Skipped sell: qty {qty_int} exceeds owned {owned} for {symbol}"))
                            continue
                    except Exception:
                        pass

                last_el = await page.select("#last", timeout=10)
                last_val = None
                try:
                    last_val = last_el.get("value")
                except Exception:
                    last_val = None
                last_price = _to_float_any(last_val)
                if last_price is None:
                    raise RuntimeError("Quote loaded but last price (#last) was empty")

                order_type = "Market" if last_price >= 2.00 else "Limit"

                qty_in = await page.select("#OrderQuantity", timeout=10)
                await qty_in.scroll_into_view()
                try:
                    await qty_in.clear_input()
                except Exception:
                    pass
                if KeyEvents is not None and KeyPressEvent is not None:
                    payloads = KeyEvents.from_text(str(int(qty_int)), KeyPressEvent.DOWN_AND_UP)
                    await qty_in.send_keys(payloads)
                else:
                    await qty_in.send_keys(str(int(qty_int)))
                if SpecialKeys is not None:
                    await qty_in.send_keys(SpecialKeys.TAB)

                await _select_dropdown_option(page, "#OrderTypeBtn", order_type)

                limit_price: Optional[float] = None
                if order_type == "Limit":
                    limit_price = round(last_price + 0.01, 2) if action == "Buy" else round(last_price - 0.01, 2)
                    price_in = await page.select("#Price", timeout=10)
                    await price_in.scroll_into_view()
                    try:
                        await price_in.clear_input()
                    except Exception:
                        pass
                    await price_in.send_keys(f"{limit_price:.2f}")

                await _select_dropdown_option(page, "#TIFBtn", "Day")

                prev_btn = await page.select("#actionbtnContinue", timeout=10)
                await prev_btn.scroll_into_view()
                await prev_btn.mouse_click()
                await page.wait_for_ready_state("complete", timeout=20)
                await page.wait()
                await page.sleep(0.25)

                try:
                    confirm_btn = await page.select(".btn-wfa-primary.btn-wfa-submit", timeout=10)
                    await confirm_btn.scroll_into_view()
                except Exception:
                    err_txt = "Confirmation page did not load"
                    try:
                        err_el = await page.select(".alert-msg-summary p", timeout=10)
                        err_txt = (getattr(err_el, "text_all", "") or "").strip().replace("\n", " ")
                    except Exception:
                        pass
                    outputs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Wells Fargo HARD Error for {symbol}: {err_txt}"))
                    continue

                warn_txt = ""
                try:
                    warn_el = await page.select(".alert-msg-summary p", timeout=2)
                    if warn_el:
                        warn_txt = (getattr(warn_el, "text_all", "") or "").strip().replace("\n", " ")
                except Exception:
                    warn_txt = ""

                if dry_run:
                    ticket = (
                        "DRY RUN — NO ORDER SUBMITTED\n"
                        f"side: {action.upper()}\n"
                        f"symbol: {symbol}\n"
                        f"quantity: {qty_int}\n"
                        f"order_type: {order_type}\n"
                        f"tif: DAY\n"
                        f"limit_price: {f'{limit_price:.2f}' if limit_price is not None else ''}\n"
                        f"account: {acct_label}\n"
                        f"warning: {warn_txt or ''}"
                    ).strip()

                    outputs.append(AccountOutput(account_id=acct_label, ok=True, message=ticket))

                    log_lines.append(f"[{acct_label}]")
                    log_lines.append(ticket)
                    log_lines.append("")
                    continue

                await confirm_btn.mouse_click()
                await page.wait_for_ready_state("complete", timeout=20)
                await page.wait()
                await page.sleep(0.25)

                msg = f"Placed {action} {qty_int} {symbol} ({order_type}" + (f" @{limit_price:.2f}" if limit_price is not None else "") + ")"
                if warn_txt:
                    msg += f" | Warning: {warn_txt}"
                outputs.append(AccountOutput(account_id=acct_label, ok=True, message=msg))

            except Exception as e:
                outputs.append(AccountOutput(account_id=acct_label, ok=False, message=str(e)))

        if _is_cancelled_ctx(ctx):
            state = "partial" if any(a.ok for a in outputs) else "failed"
        else:
            state = "success" if any(a.ok for a in outputs) else "failed"

        msg = "Cancelled" if _is_cancelled_ctx(ctx) else ""
        if dry_run:
            try:
                log_path = ctx["_write_dry_run_log"](content="\n".join(log_lines).rstrip() + "\n")
                msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"
                if _is_cancelled_ctx(ctx):
                    msg = f"{msg} | Cancelled"
            except Exception:
                msg = "DRY RUN — NO ORDER SUBMITTED"

        return BrokerOutput(broker=BROKER, state=state, accounts=outputs, message=msg)

    except Exception as e:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=str(e))],
            message=str(e),
        )
    finally:
        try:
            if browser is not None:
                await ctx["_close_browser"](browser)
        except Exception:
            pass


def _dispatch(command: str, *, timeout_s: int = 1200, **kwargs) -> BrokerOutput:
    ctx = _build_ctx(kwargs)

    if not ctx["username"] or not ctx["password"]:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Missing WELLSFARGO_USERNAME or WELLSFARGO_PASSWORD")],
            message="Missing credentials",
        )

    async def _run():
        if command == "login":
            return await _cmd_login(ctx)
        if command == "positions":
            return await _cmd_positions(ctx)
        if command == "trade":
            return await _cmd_trade(ctx)
        raise RuntimeError(f"Unknown Wells Fargo command: {command}")

    return _run_coro(lambda: _run(), timeout_s=timeout_s)


# =============================================================================
# Broker interface (Idle Markets calls these)
# =============================================================================

def bootstrap(*args, **kwargs) -> BrokerOutput:
    # compatibility shim; not required by user commands anymore
    return _dispatch("login", timeout_s=900, **kwargs)


def get_holdings(*args, **kwargs) -> BrokerOutput:
    # Legacy-style: positions triggers auth inline (profile persists)
    return _dispatch("positions", timeout_s=1200, **kwargs)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return get_holdings(*args, **kwargs)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    return _dispatch("trade", timeout_s=1200, side=side, qty=qty, symbol=symbol, dry_run=dry_run, **kwargs)


def healthcheck(*args, **kwargs) -> BrokerOutput:
    """
    Probe-only healthchecks are unreliable for this broker (UI/profile + redirects).
    The Legacy-style behavior is: positions/trade rehydrates inline using the persistent profile.
    """
    return BrokerOutput(
        broker=BROKER,
        state="failed",
        accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Probe unsupported. Run positions/trade to authenticate inline.")],
        message="Probe unsupported",
    )
