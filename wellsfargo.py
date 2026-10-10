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

import sys

import broker_logins
from modules.outputs import BrokerOutput, AccountOutput, HoldingRow, find_browser_executable, cleanup_orphaned_chrome
from modules import quiet
from modules import proc
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

#: Per-account cap on loading the trade ticket (page.get), like Fidelity's _nav.
_TRADE_NAV_TIMEOUT_S = 60.0


# =============================================================================
# Paths / env
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _root_dir() -> Path:
    return Path(__file__).resolve().parent


def _sessions_dir() -> Path:
    """This login's session directory — the browser profile and cookie jar.

    Login 1 keeps the original path, so upgrading an install reuses the Chrome
    profile that is already signed in rather than putting everyone through 2FA
    again. Login 2 and up get their own directory: two logins sharing one
    profile would fight over the same cookies and neither would stay signed in.
    """
    d = _root_dir() / "sessions" / "wellsfargo"
    suffix = broker_logins.active_suffix(BROKER)
    if suffix:
        d = d / f"login{suffix}"
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


def _offscreen() -> bool:
    # Run the (headed) WF browser OFF the visible desktop so it works in the
    # background without a window taking over the screen. WF needs a real,
    # non-headless browser (headless stalls on the sign-on page), so we keep it
    # headed but push it off-screen. Default ON; set WELLSFARGO_OFFSCREEN=false to
    # watch the window (e.g. for debugging). Ignored when actually headless.
    v = (_env("WELLSFARGO_OFFSCREEN") or "true").lower().strip()
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


def _is_abandoned_ctx(ctx: Dict[str, Any]) -> bool:
    """Has _dispatch given up waiting on this run (its timeout fired)?"""
    abandoned = ctx.get("_abandoned")
    return abandoned is not None and abandoned.is_set()


def _is_cancelled_ctx(ctx: Dict[str, Any]) -> bool:
    if _is_abandoned_ctx(ctx):
        return True  # _dispatch gave up on this run; stop at the next account
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

class _WorkerCancelled(RuntimeError):
    """The worker's coroutine was cancelled (asyncio.CancelledError) mid-run."""


def _run_coro(coro_factory: Callable[[], Coroutine[Any, Any, Any]], *, timeout_s: int = 900):
    # ALWAYS run the coroutine in a dedicated worker thread (with its own event
    # loop) and enforce timeout_s via t.join(). Do NOT take an "asyncio.run()
    # directly when there's no running loop" shortcut: that path ignored
    # timeout_s entirely, so a hung navigation (zendriver page.get() that never
    # returns, e.g. a headless Chrome that stalls on the WF sign-on page) would
    # block the calling thread — and the per-broker Chrome slot it holds in the
    # GUI — forever, with no self-heal until the app was restarted.
    #
    # The join-based backstop guarantees the caller regains control after
    # timeout_s even when the coro cannot be cancelled. The abandoned daemon
    # thread (and any orphaned Chrome it left behind) is reaped by the next
    # operation's cleanup_orphaned_chrome() / stale-lock cleanup. Creating a
    # fresh loop inside the thread is also the safe way to run this even if the
    # caller happens to already be inside a running loop.
    q: "Queue[Tuple[bool, Any]]" = Queue()

    def runner() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            res = loop.run_until_complete(coro_factory())
            q.put((True, res))
        except asyncio.CancelledError:
            # A BaseException: without this the thread died with nothing in
            # the queue and the caller reported a "timed out after Ns" that
            # never happened (the join returned at once).
            q.put((False, _WorkerCancelled(
                "Wells Fargo operation was cancelled inside its worker before it finished")))
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
        if not t.is_alive():
            raise _WorkerCancelled("Wells Fargo worker ended without a result")
        raise TimeoutError(f"Wells Fargo operation timed out after {timeout_s}s")

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

def _lock_owner_alive(pid: int, since: Optional[float] = None) -> Optional[bool]:
    """Is the process named in the profile lock alive? True / False / None (unknown).

    Never ``os.kill(pid, 0)``: on Windows that is CTRL_C_EVENT, and with no
    console (pythonw) CPython falls through to TerminateProcess -- the probe
    killed the owner, which after a _run_coro timeout is this app itself. Our
    own pid means an abandoned thread of this app holds it: busy, not probed.
    """
    if int(pid) == os.getpid():
        return True
    alive = proc.pid_alive(int(pid))
    # `since` is the lock file's mtime: a live process that started after
    # it is a recycled pid (crash + reboot), not the lock's owner.
    if alive and since is not None and proc.started_after(int(pid), since):
        return False
    return alive


def _is_pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running (unknown counts as alive)."""
    return _lock_owner_alive(pid) is not False


def _acquire_profile_lock(timeout_s: int = 60, poll_s: float = 0.25, stale_s: int = 120) -> Path:
    lock = _lock_file()
    # Clean Chrome singleton files that can block profile reuse
    _clean_chrome_singletons(_sessions_dir() / "profile")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if lock.exists():
                pid_text = ""
                try:
                    pid_text = lock.read_text().strip()
                except Exception:
                    pid_text = ""
                alive: Optional[bool] = None
                if pid_text.isdigit():
                    try:
                        alive = _lock_owner_alive(int(pid_text), lock.stat().st_mtime)
                    except Exception:
                        alive = None
                if alive is False:
                    # Owner is gone: take over (its Chrome is reaped by the
                    # cleanup_orphaned_chrome() that runs once we hold it).
                    try:
                        lock.unlink()
                    except Exception:
                        pass
                elif alive is None:
                    # Age-based staleness only when the owner cannot be told.
                    # A live owner is a browser mid-run on this profile; taking
                    # its lock put a second Chrome on the profile mid-order.
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

    raise RuntimeError("Wells Fargo profile is busy (another browser is running) — nothing was sent. Try again.")


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
    # Lock first, THEN reap orphans: the other way round killed the Chrome of
    # a run still holding the lock (an abandoned attempt mid-order) before we
    # had even waited for it.
    lock = _acquire_profile_lock(timeout_s=60)
    try:
        # Kill any orphaned Chrome still using this profile
        cleanup_orphaned_chrome(profile)
    except Exception:
        pass

    browser_args: List[str] = ["--no-sandbox"]
    if use_headless:
        browser_args.extend(["--headless=new", "--window-size=1920,1080"])
    else:
        common_headed = [
            "--disable-session-crashed-bubble",
            "--disable-infobars",
            "--disable-features=TranslateUI,VizDisplayCompositor",
            "--no-first-run",
            "--disable-default-apps",
            "--disable-extensions",
        ]
        # Headed but parked far off the visible desktop (see modules/quiet.py)
        # so WF runs in the background. An off-screen window still renders fully
        # (a minimized or hidden one gets throttled by Chrome and breaks
        # automation timing); CDP mouse clicks use viewport coords, so they are
        # unaffected by the window position. WELLSFARGO_OFFSCREEN=false puts the
        # window back on screen for debugging.
        browser_args.extend(common_headed if _offscreen() else ["--start-maximized", *common_headed])

    browser_args.extend([
        "--force-device-scale-factor=0.8",
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ])

    # _offscreen() is the WF-specific "keep it out of sight" switch; quiet
    # applies the same parking to every broker that has to run headed.
    browser_args = quiet.browser_args(browser_args, headless=use_headless,
                                      background=_offscreen())

    try:
        browser = await uc.start(browser_args=browser_args, user_data_dir=str(profile), browser_executable_path=find_browser_executable())
        if not use_headless and _offscreen():
            quiet.tame_windows(browser)
        setattr(browser, "_wf_lock_path", str(lock))
        # Pin the profile this browser runs on, like the lock above. The active
        # login (broker_logins) is process-global and moves on after a timeout,
        # so an abandoned attempt that re-resolved _profile_dir() at cleanup
        # would kill the NEXT login's Chrome instead of its own.
        setattr(browser, "_wf_profile_dir", str(profile))
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
            pinned = getattr(browser, "_wf_profile_dir", None)
            cleanup_orphaned_chrome(Path(pinned) if pinned else _profile_dir())
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
    unreadable = 0
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

        if symbol and qty is None:
            unreadable += 1
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

    if not rows and not _holdings_page_loaded(soup):
        # No rows AND no holdings table: the page never arrived (sign-on
        # bounce, interstitial, slow render). "Holds nothing" would be a lie
        # the exits board and auto-sell would act on.
        raise _HoldingsNotLoaded("holdings page did not load")
    if unreadable:
        # A position row whose share count can't be read: dropping it would
        # say "not held" and auto-sell would skip it. Unknown, not empty.
        raise _HoldingsNotLoaded(
            f"holdings page did not load: {unreadable} position row(s) had no readable quantity")

    return rows


class _HoldingsNotLoaded(RuntimeError):
    """The holdings page for one account never rendered its table."""


def _holdings_page_loaded(soup) -> bool:
    """Is this really a rendered holdings page (possibly with zero positions)?"""
    if soup.select("tbody > tr.level1"):
        return True
    for table in soup.select("table"):
        head = " ".join(th.get_text(" ", strip=True) for th in table.select("th")).lower()
        if "symbol" in head and ("quantity" in head or "qty" in head):
            return True
    text = soup.get_text(" ", strip=True).lower()
    return any(p in text for p in (
        "no holdings", "no positions", "you have no", "does not have any",
        "do not have any", "no securities"))


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
        # - headed always when debug/dry_run is explicitly requested
        # - otherwise honor the module's _headless() toggle (WELLSFARGO_HEADLESS/
        #   HEADLESS), which DEFAULTS to headed. WF has no auto-2FA (no TOTP
        #   secret), and headless Chrome stalls on the WF sign-on page on a fresh
        #   login (the initial goto never returns), so a fresh/expired session can
        #   only be logged in headed — where the push-to-phone 2FA path completes
        #   hands-off. Forcing headless here wedged bootstrap on every session
        #   expiry. Set WELLSFARGO_HEADLESS=true to opt back into headless once a
        #   session is warm.
        "headless": (False if (dry_run or force_headed) else _headless()),

        # trade params
        "side": side,
        "qty": qty,
        "symbol": symbol,
        "dry_run": dry_run,
        # Optional: trade only these accounts (a retry of the ones that failed).
        # Empty/absent means every account, which is the normal path.
        "only_accounts": list(kwargs.get("only_accounts") or []),
        # Which login this run is (broker_logins.fan_out): a request naming
        # this login's own failure row means all of this login's accounts.
        "login_idx": broker_logins.active_idx(BROKER),

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

        if not ok:
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Login failed")],
                message="Login failed",
            )

        # Enumerate the real accounts. Bootstrap used to return one placeholder
        # row ("Wells Fargo"), and the app counts len(accounts) — so ten
        # WellsTrade accounts reported as "1 account(s) connected". The overview
        # page is already open behind us and positions parses it from there, so
        # this is the same read, not a second trip.
        accounts: List[AccountOutput] = []
        try:
            accts = await ctx["_fetch_initial_account_data"](page, notify=notify)
        except Exception as e:
            _trace(f"LOGIN | account enumeration failed: {type(e).__name__}: {e}", notify=notify)
            accts = []
        for a in accts:
            label = a.get("account_id") or "Wells Fargo"
            bal = a.get("balance")
            accounts.append(AccountOutput(
                account_id=label, ok=True,
                message="Connected" if bal is None else f"Connected · ${bal:,.2f}"))
        if not accounts:
            # Logged in but the overview didn't parse. Say that, rather than
            # reporting a confident "1 account".
            accounts = [AccountOutput(account_id="Wells Fargo", ok=True,
                                      message="Login ok — account list unavailable")]

        return BrokerOutput(
            broker=BROKER,
            state="success",
            accounts=accounts,
            message=f"Login ok — {len(accts)} account(s)" if accts else "Login ok",
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
            total = acct.get("balance")
            label = f"{acct['account_id']} = ${total:.2f}" if total is not None else f"{acct['account_id']} = ?"
            try:
                rows = await ctx["_fetch_holdings_for_account"](page, acct, notify=notify)
            except _HoldingsNotLoaded as e:
                # Unknown, not empty: this account's positions were never seen.
                outputs.append(AccountOutput(account_id=label, ok=False, message=str(e),
                                             extra={"mask": acct.get("mask"), "balance": total}))
                broker_extra["accounts_failed"] = int(broker_extra["accounts_failed"]) + 1
                continue

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

        ok_ct = sum(1 for a in outputs if a.ok)
        state = "success" if ok_ct == len(outputs) else ("partial" if ok_ct else "failed")
        return BrokerOutput(broker=BROKER, state=state, accounts=outputs,
                            message="" if state == "success" else "holdings page did not load for some accounts",
                            extra=broker_extra)

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


def _norm_dd(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


#: Filler words an opener button label may carry around the chosen value.
_DD_FILLER = {"action", "select", "order", "selected"}


def _label_is_exactly(label: str, option_value: str) -> bool:
    """The opener label shows option_value and nothing else.

    For the side of the order: "Sell Short" contains "Sell" (and the token
    fallback in _dropdown_shows matches it), and a short sale is a different
    order, not a near miss. NEEDS LIVE VERIFICATION: WF's #BuySellBtn label.
    """
    want = _norm_dd(option_value)
    if not want:
        return False
    if _norm_dd(label) == want:
        return True
    have_words = [w for w in re.split(r"[^a-z0-9]+", (label or "").lower())
                  if w and w not in _DD_FILLER]
    want_words = [w for w in re.split(r"[^a-z0-9]+", option_value.lower()) if w]
    return bool(have_words) and have_words == want_words


async def _dropdown_shows(page, opener_selector: str, option_value: str, *,
                          exact: bool = False) -> bool:
    """True if the dropdown's button label reflects option_value, i.e. WF's
    handleCustomSelectClick actually registered the selection. These custom
    selects display the chosen option's label in the opener button (#BuySellBtn /
    #OrderTypeBtn / #TIFBtn). exact=True (the order side) accepts only the
    value itself -- no substring or token match."""
    try:
        opener = await page.select(opener_selector, timeout=2.0)
    except Exception:
        return False
    try:
        txt = getattr(opener, "text_all", "") or ""
    except Exception:
        txt = ""
    if exact:
        return _label_is_exactly(txt, option_value)
    want = _norm_dd(option_value)          # "Good til Cancel" -> "goodtilcancel"
    have = _norm_dd(txt)                    # button "Good 'Til Cancel" -> "goodtilcancel"
    if not want or not have:
        return False
    if want in have or have in want:
        return True
    # distinctive-token fallback (button label may abbreviate, e.g. show only
    # "Cancel" or "GTC"); match on the most specific word of the value.
    tokens = [t for t in re.split(r"[^a-z0-9]+", option_value.lower())
              if len(t) >= 3 and t not in ("til", "the", "for", "and")]
    return any(t in have for t in tokens)


async def _select_dropdown_option(page, dropdown_opener_selector: str, option_value: str, *,
                                  timeout_s: float = 10.0, require: bool = False) -> None:
    # WF's Buy/Sell / OrderType / TIF controls are custom selects (an opener button
    # + an <a data-val='...' data-toggle='handleCustomSelectClick'> menu list).
    # Two failure modes we have to defend against:
    #   1) The menu item is in the DOM immediately but only gets a LAYOUT BOX once
    #      the dropdown is visibly open. scroll_into_view()/mouse_click() call
    #      get_position(), which RAISES "could not find position for <a role=
    #      'menuitem'...>" on an unlaid-out element. (Headed Chrome, which WF now
    #      uses, actually animates the menu open, exposing this race.)
    #   2) The click can "succeed" (no exception) yet WF's handleCustomSelectClick
    #      never fires, so the value silently DOESN'T register — the confirm page
    #      then errors "Please select a Time in Force". This is the intermittent
    #      "sometimes it misses" miss.
    #
    # So: open the dropdown, wait for the item to lay out, click it (real mouse
    # when laid out; layout-independent JS click otherwise / as fallback), then
    # VERIFY the opener label changed and RETRY the whole thing if it didn't.
    option_selector = f"a[data-val='{option_value}']"
    last_exc: Optional[Exception] = None

    for _attempt in range(5):
        # Already selected (e.g. Day is the default, or a prior attempt took)?
        if await _dropdown_shows(page, dropdown_opener_selector, option_value, exact=require):
            return
        try:
            opener = await page.select(dropdown_opener_selector, timeout=timeout_s)
            try:
                await opener.scroll_into_view()
            except Exception:
                pass
            await opener.mouse_click()

            # Poll (re-selecting each round so the handle can't go stale) until the
            # option has a layout box, up to ~4s.
            opt = None
            laid_out = False
            waited = 0.0
            while waited <= 4.0:
                try:
                    cand = await page.select(option_selector, timeout=0.8)
                    if cand is not None:
                        opt = cand
                        if await cand.get_position() is not None:
                            laid_out = True
                            break
                except Exception:
                    pass
                await page.sleep(0.2)
                waited += 0.2

            if opt is None:
                opt = await page.select(option_selector, timeout=timeout_s)

            did = False
            if laid_out:
                try:
                    await opt.mouse_click()  # real click on the visible item
                    did = True
                except Exception as e:
                    last_exc = e
            if not did:
                # JS click needs no layout and reliably fires the anchor's handler.
                await opt.apply("(e) => e.click()")
        except Exception as e:
            last_exc = e

        # Let handleCustomSelectClick settle, then verify it registered.
        await page.sleep(0.4)
        if await _dropdown_shows(page, dropdown_opener_selector, option_value, exact=require):
            return
        await page.sleep(0.4)

    # Never confirmed. Best-effort final JS click, then proceed — WF's confirm page
    # validates TIF/order-type and surfaces a clear error if it truly never took,
    # so we don't want a false-negative label check to fail an order that IS set.
    try:
        opt = await page.select(option_selector, timeout=2.0)
        await opt.apply("(e) => e.click()")
        await page.sleep(0.3)
    except Exception as e:
        last_exc = e

    shown = await _dropdown_shows(page, dropdown_opener_selector, option_value, exact=require)
    if not shown and require:
        # The side of the order: never "proceed and let the confirm page
        # sort it out" — a missed Buy/Sell is a different order, not an error.
        raise RuntimeError(
            f"Could not set {dropdown_opener_selector} to {option_value} on the "
            f"ticket — nothing was sent")
    if not shown and last_exc is not None:
        raise last_exc


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


async def _capture_page_state(page, symbol: str = "") -> str:
    """What the page actually was at the moment something timed out.

    The trade path used to record nothing at all — the nav log jumps straight
    from "POSITIONS | rows=11" to "2 consecutive errors", so a failure could not
    be told apart from any other. A bare "selector not found" names the one thing
    we know isn't there and nothing about what is, which is why #prevdata
    timeouts were unexplainable after the fact.
    """
    try:
        state = await page.evaluate(
            "(function(){var d=document;"
            "var sym=d.querySelector('#Symbol');"
            "var err=d.querySelector('.alert-msg-summary');"
            "return JSON.stringify({"
            "url:location.href,ready:d.readyState,"
            "form:!!d.querySelector('#eqentryfrm'),"
            "symbol:sym?sym.value:null,"
            "prevdata:!!d.querySelector('#prevdata'),"
            "last:!!d.querySelector('#last'),"
            "err:err?(err.innerText||'').slice(0,180):null});})();")
        return f"{state} wanted={symbol}"
    except Exception as e:
        return f"(page state unavailable: {type(e).__name__}: {e})"


async def _quote_ready(page, symbol: str) -> bool:
    """Is the ticket already showing a quote for `symbol`?

    True only when the symbol field really holds this symbol AND the quote block
    is rendered — so a leftover quote for the previous account's symbol can never
    be mistaken for this one's.
    """
    want = re.sub(r"[^A-Za-z0-9.\-]", "", symbol or "").upper()
    if not want:
        return False
    try:
        return bool(await page.evaluate(
            "(function(){var e=document.querySelector('#Symbol');"
            "if(!e||!e.value) return false;"
            f"if(e.value.trim().toUpperCase()!=='{want}') return false;"
            "return !!document.querySelector('#prevdata');})();"))
    except Exception:
        return False


async def _commit_symbol(page, symbol: str) -> bool:
    """Put `symbol` in #Symbol and make the field actually commit it.

    WF fires its quote lookup on the symbol field's change/blur, not on
    keystrokes. Sending TAB usually blurs it, but when the send races the page
    the value never registers and no lookup is ever requested — which is
    indistinguishable, from the outside, from a slow quote. So set the value and
    dispatch change+blur explicitly, then read the field back.
    """
    sym_in = await page.select("#Symbol", timeout=10)
    await sym_in.scroll_into_view()
    try:
        await sym_in.clear_input()
    except Exception:
        pass
    await sym_in.send_keys(symbol)
    # SpecialKeys used to be a free name here — it only existed as a local
    # inside _cmd_trade, so this fallback died with NameError every time it ran.
    try:
        from zendriver import SpecialKeys  # type: ignore
    except Exception:  # pragma: no cover
        SpecialKeys = None  # type: ignore
    if SpecialKeys is not None:
        await sym_in.send_keys(SpecialKeys.TAB)
    else:
        await sym_in.send_keys("\t")
    try:
        got = await page.evaluate(
            "(function(){var e=document.querySelector('#Symbol');"
            "if(!e) return '';"
            "if(e.value) {e.dispatchEvent(new Event('change',{bubbles:true}));"
            "e.dispatchEvent(new Event('blur',{bubbles:true}));}"
            "return e.value||'';})();")
    except Exception:
        return True  # can't verify — let the #prevdata wait be the judge
    return str(got or "").strip().upper() == symbol.upper()


async def _wait_for_quote(page, symbol: str, acct_label: str,
                          notify: Optional[NotifyFn] = None) -> None:
    """Get a quote for `symbol` on the ticket, without racing WF's blur handler.

    #prevdata is the block WF renders when the quote comes back, and the lookup
    is triggered by the symbol field blurring — not by keystrokes. One blur plus
    one fixed 10s wait was the whole strategy, so a blur that never fired and a
    quote WF was slow to return both cost the account permanently, and looked
    identical afterwards.

    The ticket is now opened as equity.do?...&symbol=SYM, so Wells Fargo renders
    the quote server-side and there is no client-side lookup to race. Typing
    stays as the fallback for when that parameter doesn't take.
    """
    if await _quote_ready(page, symbol):
        return

    _trace(f"TRADE | Wells Fargo | {acct_label}: ticket did not preload {symbol}, typing it",
           notify=notify)
    committed = await _commit_symbol(page, symbol)
    if not committed:
        _trace(f"TRADE | Wells Fargo | {acct_label}: symbol field did not take {symbol}",
               notify=notify)
    try:
        await page.select("#prevdata", timeout=12)
        return
    except Exception:
        pass
    # Record what the page was BEFORE the retry mutates it — this is the
    # evidence that says which of the two causes it was: a blur that never fired
    # (symbol field empty / committed False) or a quote WF simply didn't return
    # in time (field holds the symbol, no #prevdata).
    _trace(f"TRADE | Wells Fargo | {acct_label}: no quote after 12s "
           f"(committed={committed}) state={await _capture_page_state(page, symbol)}",
           notify=notify)
    await _commit_symbol(page, symbol)
    await page.sleep(1.0)
    try:
        await page.select("#prevdata", timeout=25)
    except Exception:
        _trace(f"TRADE | Wells Fargo | {acct_label}: still no quote after retry "
               f"state={await _capture_page_state(page, symbol)}", notify=notify)
        raise
    _trace(f"TRADE | Wells Fargo | {acct_label}: quote arrived on retry", notify=notify)


_ORDER_RESULT_JS = (
    "(function(){var d=document;"
    "var b=d.querySelector('.btn-wfa-primary.btn-wfa-submit');"
    "var vis=function(e){return !!(e&&(e.offsetWidth||e.offsetHeight||e.getClientRects().length));};"
    "var t=(d.body&&d.body.innerText)||'';"
    "var a=d.querySelector('.alert-msg-summary');"
    "var ok=/order\\s+(has\\s+been\\s+|was\\s+)?(received|placed|submitted|accepted)"
    "|(confirmation|order|reference)\\s*(number|no\\.?|#)\\s*:?\\s*[A-Z0-9][A-Z0-9-]{3,}"
    "|order\\s+confirmation/i.test(t);"
    "return JSON.stringify({submit:vis(b),ok:ok,"
    "alert:a?(a.innerText||'').trim().replace(/\\s+/g,' ').slice(0,240):'',"
    "url:location.href});})();"
)


async def _read_order_result(page, *, tries: int = 20, wait_s: float = 0.5) -> Dict[str, Any]:
    """What the page says after the submit click.

    {"ok": True} only when the submit button is gone AND the page shows an
    order-received / order-number indicator. Otherwise {"ok": False} plus any
    alert text shown (a rejection). Polls ~10s for the result page to settle;
    never raises.
    """
    last: Dict[str, Any] = {"ok": False, "alert": ""}
    for i in range(tries):
        try:
            raw = await page.evaluate(_ORDER_RESULT_JS)
            st = json.loads(raw) if isinstance(raw, str) and raw else {}
        except Exception:
            st = {}
        if isinstance(st, dict) and st:
            if st.get("ok") and not st.get("submit"):
                return {"ok": True, "alert": str(st.get("alert") or "")}
            last = {"ok": False, "alert": str(st.get("alert") or "")}
        if i < tries - 1:
            await page.sleep(wait_s)
    return last


def _submitted_unverified_msg(e: BaseException) -> str:
    """The account result for an error AFTER the confirm click.

    "submitted" + "verify" is what the app keys on to treat the order as
    possibly live and keep Retry from placing it twice. The raw error stays on
    the end for the logs (asyncio.TimeoutError has an empty str(), hence the
    type name).
    """
    detail = f"{type(e).__name__}: {e}".strip().rstrip(":")
    return ("Order submitted but the confirmation page didn't load — verify in "
            f"Wells Fargo before retrying ({detail})")


def _is_hard_error(msg: str) -> bool:
    """Should this failure stop the whole account list, or just this account?

    Hard means Wells Fargo refusing the order itself — security not allowed,
    account restricted — which it will refuse identically on the other nine
    accounts, so bailing early saves ten minutes of certain failure. A timeout
    waiting for an element is NOT hard: it is this account at this moment, and
    counting it toward the breaker is how two slow quotes turned into five
    unbought accounts.
    """
    m = (msg or "").lower()
    if "timeout" in m and "waiting for element" in m:
        return False
    if "quote loaded but last price" in m:
        return False
    if "did not load" in m:
        # Our own fallback text when even the error banner was missing. That is
        # a page that never arrived, not Wells Fargo stating a reason.
        return False
    return True


def _mask_is_real(mask: Any) -> bool:
    """A parsed last-4 mask ("****1234"), not the "****" fallback."""
    return bool(re.search(r"[0-9A-Za-z]{4}$", str(mask or "").strip()))


def _ticket_account_check(acct: Dict[str, Any], ticket_mask: str) -> None:
    """Raise when the ticket opened on a different account than the one asked.

    The ticket is deep-linked by account INDEX; if WF's list order shifted (a
    new or closed account) the index points at another account, and merely
    relabelling the row would place this account's order there. Only a
    positive mismatch refuses: an unreadable mask on either side proceeds as
    before. NEEDS LIVE VERIFICATION: .acctmask text format on the ticket.
    """
    want = re.sub(r"[^0-9A-Za-z]", "", str(acct.get("mask") or ""))
    have = re.sub(r"[^0-9A-Za-z]", "", str(ticket_mask or ""))
    if not _mask_is_real(acct.get("mask")) or len(want) < 4 or len(have) < 4:
        return
    if have[-4:] != want[-4:]:
        raise RuntimeError(
            f"Ticket opened on account ending {have[-4:]}, expected {want[-4:]} — "
            f"stopped before Continue, nothing was sent")


_LOGIN_PREFIX_RE = re.compile(r"^Wells Fargo (\d+) · ")


def _login_names(idx: int) -> set:
    """Every label a whole-login failure row of login `idx` can carry.

    The module words such a row "Wells Fargo" (login failed, no accounts,
    an error before any Place Order click) and broker_logins.fan_out labels a
    login that raised with its own name ("Wells Fargo 2"); login 2 and up
    then get the "Wells Fargo 2 · " prefix. Bare "Wells Fargo" is login 1's
    alone -- every other login's rows carry the prefix.
    """
    idx = max(1, int(idx or 1))
    base = {"Wells Fargo", f"Wells Fargo {idx}"}
    if idx == 1:
        return base
    pre = f"Wells Fargo {idx} · "
    return {f"Wells Fargo {idx}"} | {pre + b for b in base}


def _row_login_idx(label: str) -> int:
    """The login a result row belongs to, from its fan_out prefix (1 if none)."""
    m = _LOGIN_PREFIX_RE.match(str(label or ""))
    return int(m.group(1)) if m else 1


def _wants_whole_login(only, idx: int) -> bool:
    """True when the caller asked for login `idx`'s failure row back: a retry
    of a login that failed as a whole, before any order was clicked there
    (that is the only time a row is labelled with the login, not an account).
    Like Fidelity's `c.label in only_accounts`: it means every account of
    THIS login, never another login's."""
    names = _login_names(idx)
    return any(str(w).strip() in names for w in (only or ()))


def _account_matches(acct: Dict[str, Any], wanted: set) -> bool:
    """True when this account is one the caller asked to trade.

    Matched on the last-4 mask found anywhere in the requested string, so a
    label copied straight off a result row ("WELLSTRADE (****0012)") works as
    well as a bare "0012".
    """
    mask = str(acct.get("mask") or "").strip()
    if not _mask_is_real(mask):
        mask = ""  # "****" alone would match every requested label
    label = str(acct.get("account_id") or "").strip()
    for w in wanted:
        w = str(w).strip()
        if not w:
            continue
        if w == label or (mask and mask in w) or (mask and w == mask):
            return True
    return False


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
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message="Cancelled before start — nothing was sent")],
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

        # Caller asked for specific accounts (a retry of the ones that failed).
        only = {str(a) for a in (ctx.get("only_accounts") or []) if str(a).strip()}
        if only and _wants_whole_login(only, ctx.get("login_idx") or 1):
            # This login failed as a whole last time (nothing was clicked
            # here), so the retry is every account it has.
            _trace(f"TRADE | Wells Fargo | retrying the whole login "
                   f"({len(accts)} account(s))", notify=notify)
        elif only:
            if any(not _mask_is_real(a.get("mask")) for a in accts):
                # An unparsed mask is the bare "****", which sits inside every
                # requested label — matching on it would trade every account.
                why = ("Cannot match the requested accounts: Wells Fargo account "
                       "numbers could not be read — nothing was sent")
                return BrokerOutput(
                    broker=BROKER,
                    state="failed",
                    accounts=[AccountOutput(account_id="Wells Fargo", ok=False, message=why)],
                    message=why,
                )
            wanted = [a for a in accts if _account_matches(a, only)]
            if not wanted:
                # Quiet, like Fidelity / IBKR: with several logins the requested
                # accounts usually belong to ANOTHER login, and a failed row
                # here read as a failed sell. execute_trade adds the one
                # "none found" row if no login held any of them.
                _trace(f"TRADE | Wells Fargo | none of the requested accounts at "
                       f"this login", notify=notify)
                return BrokerOutput(broker=BROKER, state="success", accounts=[],
                                    message="", extra={"only_unmatched": True})
            _trace(f"TRADE | Wells Fargo | limited to {len(wanted)}/{len(accts)} account(s)", notify=notify)
            accts = wanted

        # Shared with _dispatch (ctx["_outputs"]) so a run it abandons on timeout
        # still reports the accounts that finished. _todo / _current /
        # _clicking tell it which account was mid-click and which never ran.
        outputs: List[AccountOutput] = ctx.get("_outputs") if isinstance(ctx.get("_outputs"), list) else []
        ctx["_outputs"] = outputs
        ctx["_todo"] = [a.get("account_id") or "Wells Fargo" for a in accts]
        _consec_hard_errors = 0  # stop after 2 consecutive hard errors (e.g. security not allowed)

        for _acct_i, acct in enumerate(accts):
            if _acct_i > 0:
                await asyncio.sleep(random.uniform(1.0, 3.0))
            if _is_cancelled_ctx(ctx):
                # A row for every account the cancel kept from its order: a
                # missing row read as nothing to report.
                for remaining in accts[_acct_i:]:
                    outputs.append(AccountOutput(
                        account_id=remaining.get("account_id") or "Wells Fargo", ok=False,
                        message="Skipped: cancelled — nothing was sent"))
                break
            idx = acct.get("index")
            x_param = acct.get("x_param") or ""
            acct_label = acct.get("account_id") or "Wells Fargo"
            ctx["_current"] = acct_label

            _trace(f"TRADE | Wells Fargo | {acct_label} | starting "
                   f"({_acct_i + 1}/{len(accts)}) {action} {qty_int} {symbol}",
                   notify=notify)

            _submitted = False
            try:
                # Deep-link the symbol. WF's own ticket URL carries a `symbol`
                # parameter and we were sending it empty, then typing the symbol
                # in and waiting on the blur-triggered quote AJAX — the race that
                # loses accounts to '#prevdata' timeouts. Filled in, the server
                # renders the quote with the page. selectedAction stays empty on
                # purpose: Buy/Sell is still set explicitly through the dropdown
                # below, so a parameter we are inferring can never flip a side.
                safe_symbol = re.sub(r"[^A-Za-z0-9.\-]", "", symbol).upper()
                trade_url = (f"https://wfawellstrade.wellsfargo.com/BW/equity.do?"
                             f"account={idx}&symbol={safe_symbol}&selectedAction=")
                if x_param:
                    trade_url = f"{trade_url}&{x_param}"

                # Bounded like Fidelity's _nav: a page.get() that never returns
                # held the whole run until the 20-min backstop, and every
                # account after it died with it.
                try:
                    await asyncio.wait_for(page.get(trade_url), timeout=_TRADE_NAV_TIMEOUT_S)
                except asyncio.TimeoutError:
                    raise RuntimeError(
                        f"Trade page did not load within {_TRADE_NAV_TIMEOUT_S:.0f}s for this account")
                await page.wait_for_ready_state("complete")
                await page.wait()

                # The order form is the gate for everything below. Swallowing a
                # miss here is what turned "the ticket never loaded" into a
                # baffling #prevdata timeout ten seconds later, so reload once
                # and then say plainly where we actually are.
                if not await _safe_select(page, "#eqentryfrm", 12):
                    _trace(f"TRADE | Wells Fargo | {acct_label}: order form missing, reloading",
                           notify=notify)
                    await _goto(page, trade_url, f"TRADE[{acct_label}]",
                                notify=notify, settle_s=1.5)
                    if not await _safe_select(page, "#eqentryfrm", 20):
                        u = await _current_url(page)
                        raise RuntimeError(
                            f"Order form did not load for this account (url: {u or 'unknown'})")

                mask = await _get_account_mask(page)
                _ticket_account_check(acct, mask)
                if mask and mask not in acct_label:
                    acct_label = f"{acct_label} [*{mask}]"

                await _select_dropdown_option(page, "#BuySellBtn", action, require=True)

                await _wait_for_quote(page, symbol, acct_label, notify=notify)

                if action == "Sell":
                    try:
                        owned_el = await page.select("#currentSharesOwned .numshares", timeout=10)
                        owned_txt = (getattr(owned_el, "text_all", "") or "").strip()
                        # Read the number as a NUMBER. Deleting every non-digit
                        # broke this twice over: '0.05' lost its decimal point
                        # and became five whole shares, and an empty or not-yet-
                        # rendered field became a confident 0 -- which is how an
                        # account that is holding the stock gets told it owns
                        # none of it and has its sell skipped.
                        m = re.search(r"-?\d[\d,]*(?:\.\d+)?", owned_txt)
                        owned = _to_float_any(m.group(0)) if m else None
                        if owned is None:
                            # Unknown is not zero. The guard exists to spare a
                            # doomed order, not to invent a position count, so
                            # say so and let Wells Fargo reject it if it must.
                            _trace(f"TRADE | Wells Fargo | {acct_label}: shares owned "
                                   f"unreadable ({owned_txt!r}) — proceeding rather "
                                   f"than calling it 0", notify=notify)
                        elif owned <= 0:
                            outputs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Skipped sell: own 0 shares of {symbol}"))
                            continue
                        elif qty_int > owned:
                            outputs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Skipped sell: qty {qty_int} exceeds owned {owned:g} for {symbol}"))
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
                if last_price <= 0:
                    # Like Fidelity: a $0.00 quote means the ticket never
                    # resolved a price, and a $0.01 "limit" off it is a guess.
                    raise RuntimeError(
                        f"Quote loaded but last price (#last) was ${last_price:.2f} — "
                        f"refusing to price an order; nothing was sent")

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
                    if limit_price <= 0:
                        # Sub-penny last: last - 0.01 is zero or negative. Send
                        # the smallest legal price, never a $0.00 limit.
                        limit_price = 0.01
                    price_in = await page.select("#Price", timeout=10)
                    await price_in.scroll_into_view()
                    try:
                        await price_in.clear_input()
                    except Exception:
                        pass
                    await price_in.send_keys(f"{limit_price:.2f}")

                # WF rejects a Day limit order on these (mostly sub-$2 / OTC) names
                # with a "select Good 'til Cancelled" error, so limit orders use GTC;
                # market orders stay Day. Exact #TIFBtn dropdown values from WF's
                # markup: "Day" and "Good til Cancel".
                tif = "Good til Cancel" if order_type == "Limit" else "Day"
                await _select_dropdown_option(page, "#TIFBtn", tif)

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
                    # Before the submit click: nothing was sent, so none of
                    # the may-exist words ("confirmation", "submitted", ...)
                    # belong in this text — they would keep it out of Retry.
                    err_txt = "Order review page did not load — nothing was sent"
                    try:
                        err_el = await page.select(".alert-msg-summary p", timeout=10)
                        err_txt = (getattr(err_el, "text_all", "") or "").strip().replace("\n", " ") or err_txt
                    except Exception:
                        pass
                    outputs.append(AccountOutput(account_id=acct_label, ok=False, message=f"Wells Fargo HARD Error for {symbol}: {err_txt}"))
                    # A soft failure breaks the chain — the counter is
                    # "consecutive refusals", not "failures so far".
                    _consec_hard_errors = _consec_hard_errors + 1 if _is_hard_error(err_txt) else 0
                    if _consec_hard_errors >= 2:
                        _trace(f"TRADE | Wells Fargo | 2 consecutive errors, skipping remaining accounts", notify=notify)
                        for remaining in accts[_acct_i + 1:]:
                            r_label = remaining.get("account_id") or "Wells Fargo"
                            outputs.append(AccountOutput(account_id=r_label, ok=False, message=f"Skipped: {err_txt}"))
                        break
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
                        f"tif: {tif}\n"
                        f"limit_price: {f'{limit_price:.2f}' if limit_price is not None else ''}\n"
                        f"account: {acct_label}\n"
                        f"warning: {warn_txt or ''}"
                    ).strip()

                    outputs.append(AccountOutput(account_id=acct_label, ok=True, message=ticket))

                    log_lines.append(f"[{acct_label}]")
                    log_lines.append(ticket)
                    log_lines.append("")
                    continue

                # From here on the order may be live at Wells Fargo. Flag it
                # BEFORE the click: a click that raises may still have landed,
                # and "verify before retrying" is the safe side of that doubt.
                #
                # Run-level flag for _dispatch's timeout handler, and the order
                # matters: raise the flag FIRST, then look at the abandon event.
                # _dispatch sets the event first and reads the flag second, so
                # either it sees the flag (and says "verify") or we see the
                # event (and never click). A run _dispatch already gave up on
                # must not place an order nobody is waiting to hear about.
                ctx["_clicking"] = acct_label
                ctx["_clicked"] = True
                if _is_abandoned_ctx(ctx):
                    outputs.append(AccountOutput(
                        account_id=acct_label, ok=False,
                        message="Stopped before clicking Place Order: the run timed out — nothing was sent"))
                    break
                _submitted = True
                await confirm_btn.mouse_click()
                await page.wait_for_ready_state("complete", timeout=20)
                await page.wait()
                await page.sleep(0.25)

                # Read what Wells Fargo answered. "No exception" is not a fill:
                # only a success indicator (with the submit button gone) is.
                result = await _read_order_result(page)
                if not result.get("ok"):
                    shown = str(result.get("alert") or "").strip()
                    if shown:
                        smsg = (f"Order submitted but Wells Fargo showed: {shown[:200]} — "
                                f"verify in Wells Fargo before retrying")
                    else:
                        smsg = _submitted_unverified_msg(
                            RuntimeError("no order confirmation on the result page"))
                    outputs.append(AccountOutput(account_id=acct_label, ok=False, message=smsg))
                    _trace(f"TRADE | Wells Fargo | {acct_label} | {smsg} "
                           f"state={await _capture_page_state(page, symbol)}", notify=notify)
                    _consec_hard_errors = 0
                    continue

                msg = f"Placed {action} {qty_int} {symbol} ({order_type}" + (f" @{limit_price:.2f}" if limit_price is not None else "") + f", {tif})"
                if warn_txt:
                    msg += f" | Warning: {warn_txt}"
                outputs.append(AccountOutput(account_id=acct_label, ok=True, message=msg))
                _trace(f"TRADE | Wells Fargo | {acct_label} | {msg}", notify=notify)
                _consec_hard_errors = 0

            except Exception as e:
                if _submitted:
                    # The confirm click went out; a slow confirmation page
                    # (wait_for_ready_state timing out) is not a failed order.
                    # Say so, or a Retry would place it a second time.
                    smsg = _submitted_unverified_msg(e)
                    outputs.append(AccountOutput(account_id=acct_label, ok=False, message=smsg))
                    _trace(f"TRADE | Wells Fargo | {acct_label} | {smsg} "
                           f"state={await _capture_page_state(page, symbol)}", notify=notify)
                    _consec_hard_errors = 0
                    continue
                # Before the confirm click (the ticket, the quote's #prevdata,
                # the preview): no order went out for this account.
                outputs.append(AccountOutput(account_id=acct_label, ok=False,
                                             message=f"{e} — nothing was sent"))
                _trace(f"TRADE | Wells Fargo | {acct_label} | FAILED: {e} "
                       f"state={await _capture_page_state(page, symbol)}", notify=notify)
                # Only a refusal counts toward the breaker. A page timeout is
                # this account's bad luck, not a verdict on the next one.
                _consec_hard_errors = _consec_hard_errors + 1 if _is_hard_error(str(e)) else 0
                if _consec_hard_errors >= 2:
                    _trace(f"TRADE | Wells Fargo | 2 consecutive errors, skipping remaining accounts", notify=notify)
                    for remaining in accts[_acct_i + 1:]:
                        r_label = remaining.get("account_id") or "Wells Fargo"
                        outputs.append(AccountOutput(account_id=r_label, ok=False, message=f"Skipped: {e}"))
                    break

        ok_ct = sum(1 for a in outputs if a.ok)
        if _is_cancelled_ctx(ctx):
            state = "partial" if ok_ct else "failed"
        elif ok_ct and ok_ct == len(outputs):
            state = "success"
        else:
            # Some accounts failed: "success" here hid them from the
            # broker-level status.
            state = "partial" if ok_ct else "failed"

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
        if not ctx.get("_clicked"):
            # Browser start, login, the account list: before any order.
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Wells Fargo", ok=False,
                                        message=f"{e} — nothing was sent")],
                message=str(e),
            )
        # Escaped the account loop after a Place Order click: keep the rows
        # already written and say an order may be live.
        done = list(ctx.get("_outputs") or [])
        done.append(AccountOutput(account_id="Wells Fargo", ok=False, message=(
            f"Wells Fargo failed mid-run ({e}) — an order may have been submitted; "
            f"verify in Wells Fargo before retrying")))
        return BrokerOutput(
            broker=BROKER,
            state="partial" if any(a.ok for a in done) else "failed",
            accounts=done,
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

    if command != "trade":
        return _run_coro(lambda: _run(), timeout_s=timeout_s)

    ctx["_abandoned"] = threading.Event()
    ctx["_clicked"] = False
    ctx["_outputs"] = []
    ctx["_todo"] = []
    ctx["_current"] = None
    ctx["_clicking"] = None
    try:
        return _run_coro(lambda: _run(), timeout_s=timeout_s)
    except _WorkerCancelled as e:
        ctx["_abandoned"].set()
        why = f"Wells Fargo trade stopped before it finished: {e}"
        _trace(f"TRADE | Wells Fargo | {why}")
        accounts = _abandoned_rows(ctx, e, skipped=(
            "Skipped: the Wells Fargo run was cancelled before this account's "
            "order — nothing was sent"))
        return BrokerOutput(
            broker=BROKER,
            state="partial" if any(a.ok for a in accounts) else "failed",
            accounts=accounts or [AccountOutput(account_id="Wells Fargo", ok=False, message=why)],
            message=why,
        )
    except TimeoutError as e:
        # The abandoned run stops at its next account boundary, but orders may
        # already be live on the accounts it got through and their results died
        # with it. Never let that read as a clean, retryable failure.
        #
        # Set the event FIRST, then read the flag (the worker does the mirror
        # image: flag first, then event). That ordering means a run that never
        # reached a Place Order click — hung at login, say — can be reported
        # plainly, and a run that did can't click again after we answer.
        ctx["_abandoned"].set()
        clicked = bool(ctx.get("_clicked")) and not bool(ctx.get("dry_run"))
        if clicked:
            why = (f"Wells Fargo trade did not finish within {timeout_s // 60} min — some "
                   f"orders may have been submitted; verify in Wells Fargo before retrying ({e})")
        else:
            why = (f"Wells Fargo timed out after {timeout_s}s before reaching "
                   f"the Place Order click; no order was sent")
        _trace(f"TRADE | Wells Fargo | {why}")
        accounts = _abandoned_rows(ctx, e, skipped=(
            f"Skipped: Wells Fargo run timed out after {max(1, timeout_s // 60)} min "
            "before this account's order — nothing was sent"))
        if not accounts:
            accounts = [AccountOutput(account_id="Wells Fargo", ok=False, message=why)]
        return BrokerOutput(
            broker=BROKER,
            state="partial" if any(a.ok for a in accounts) else "failed",
            accounts=accounts,
            message=why,
        )


def _abandoned_rows(ctx: Dict[str, Any], e: BaseException, *, skipped: str) -> List[AccountOutput]:
    """Per-account results for a trade run _dispatch gave up on.

    Finished accounts keep their real results; the account whose submit click
    was under way gets "submitted ... verify"; every account the run never
    reached (or stopped short of the click for) gets a nothing-sent Skipped
    row. Empty when the run never got as far as the account list.
    """
    rows = list(ctx.get("_outputs") or [])
    todo = list(ctx.get("_todo") or [])
    clicking = ctx.get("_clicking")
    dry_run = bool(ctx.get("dry_run"))

    def _has_row(label: str) -> bool:
        # The row label may carry a " [*mask]" suffix added mid-ticket.
        return any(str(a.account_id).startswith(str(label)) for a in rows)

    if clicking and not dry_run and not _has_row(clicking):
        rows.append(AccountOutput(account_id=clicking, ok=False,
                                  message=_submitted_unverified_msg(e)))
    for label in todo:
        if _has_row(label) or (clicking and str(clicking).startswith(str(label))):
            continue
        rows.append(AccountOutput(account_id=label, ok=False, message=skipped))
    return rows


# =============================================================================
# Broker interface (RSAMAXXED calls these)
# =============================================================================

def _bootstrap_one(*args, **kwargs) -> BrokerOutput:
    # compatibility shim; not required by user commands anymore
    return _dispatch("login", timeout_s=900, **kwargs)


def _get_holdings_one(*args, **kwargs) -> BrokerOutput:
    # Legacy-style: positions triggers auth inline (profile persists)
    return _dispatch("positions", timeout_s=1200, **kwargs)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    # Deliberately calls the WRAPPED get_holdings: one fan-out, not two.
    return get_holdings(*args, **kwargs)


def _execute_trade_one(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
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

def _wf_login_no(label: str) -> int:
    """Which login a label belongs to: "Wells Fargo 2 · ..." -> 2, else 1."""
    m = re.match(r"\s*Wells Fargo (\d+)(?: ·|\s*$)", str(label or ""))
    return int(m.group(1)) if m else 1


def _row_may_exist(row: AccountOutput) -> bool:
    low = str(getattr(row, "message", "") or "").lower()
    return (not getattr(row, "ok", False)) and (
        "may have been submitted" in low or ("submitted" in low and "verify" in low))


def _requested_unmatched(only: List[str], rows: List[AccountOutput]) -> List[str]:
    """Requested account labels no result row stands for (same match as
    _account_matches: the exact label, or its "****1234" mask).

    A login whose run ended in a login-level may-exist row ("failed mid-run —
    an order may have been submitted; verify") stands for every requested
    account at that login: which account's order went out is unknown, so a
    "not found — nothing was sent" row there would invite a Retry to place
    it a second time.
    """
    labels = {str(a.account_id or "") for a in rows}
    # A login's own name stands for that whole login: found when the run
    # reported any row of that login (its accounts, or its failure again).
    logins = {_row_login_idx(lab) for lab in labels}
    masks = set()
    for lab in labels:
        masks.update(m for m in re.findall(r"\*{4}[0-9A-Za-z]{4}", lab))
    unsure_logins = {_wf_login_no(a.account_id) for a in rows
                     if _row_may_exist(a)
                     and not re.search(r"\*{4}[0-9A-Za-z]{4}", str(a.account_id or ""))}
    out = []
    for w in only:
        if w in labels or any(m in w or w == m[-4:] for m in masks):
            continue
        if any(w in _login_names(i) for i in logins):
            continue
        if _wf_login_no(w) in unsure_logins:
            continue
        out.append(w)
    return out


def execute_trade(**kwargs) -> BrokerOutput:
    out = broker_logins.fan_out(BROKER, _MODULE, _execute_trade_one, **kwargs)
    only = sorted({str(a) for a in (kwargs.get("only_accounts") or []) if str(a).strip()})
    if only and (out.accounts or []):
        # Some requested accounts traded (or failed), others matched nothing
        # at any login: one row each, or a retry of three that found two read
        # as a clean success.
        missing = _requested_unmatched(only, out.accounts or [])
        if missing:
            for w in missing:
                out.accounts.append(AccountOutput(
                    account_id=w, ok=False,
                    message="Skipped: requested account not found — nothing was sent"))
            out.state = "partial" if any(a.ok for a in out.accounts) else "failed"
        return out
    if only and not (out.accounts or []) and out.state == "success":
        # No login held any requested account: one row saying so, not an
        # empty success for a retry that traded nothing.
        why = f"None of the requested accounts were found: {only} — nothing was sent"
        return BrokerOutput(broker=BROKER, state="failed",
                            accounts=[AccountOutput(account_id="Wells Fargo", ok=False,
                                                    message=why)],
                            message="Requested accounts not found", extra=out.extra)
    return out

#: Handed to fan_out so it can reach BrokerOutput/AccountOutput and the
#: _on_login_switch hook without importing this module back.
_MODULE = sys.modules[__name__]
