# modules/brokers/fidelity/fidelity.py
from __future__ import annotations

import asyncio
import csv
import math
import os
import random
import re
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR
from pathlib import Path
from queue import Queue
from threading import Thread
from urllib.parse import urlsplit
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

import pytz
import zendriver as uc
from zendriver import cdp, KeyPressEvent
from zendriver.core.keys import KeyEvents

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow, find_browser_executable, cleanup_orphaned_chrome
from modules._2fa_prompt import universal_2fa_prompt
from modules.ui_keys import runtime_profile

BROKER = "fidelity"
SMART_SELL_SUPPORTED = True
OtpProvider = Callable[[str, int], Optional[str]]
NotifyFn = Callable[[str], None]

# =============================================================================
# URLs (legacy-aligned)
# =============================================================================

LOGIN_URL = (
    "https://digital.fidelity.com/prgw/digital/login/full-page?"
    "AuthRedUrl=https://digital.fidelity.com/ftgw/digital/portfolio/summary"
)
SUMMARY_URL = "https://digital.fidelity.com/ftgw/digital/portfolio/summary"
POSITIONS_URL = "https://digital.fidelity.com/ftgw/digital/portfolio/positions"

# Legacy trade entry uses /orderEntry
TRADE_URL = "https://digital.fidelity.com/ftgw/digital/trade-equity/index/orderEntry"


# =============================================================================
# Env + paths
# =============================================================================

def _env(name: str) -> str:
    return os.getenv(name, "").strip()

def _root_dir() -> Path:
    return Path(__file__).resolve().parent

def _sessions_dir() -> Path:
    d = _root_dir() / "sessions" / "fidelity"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _zen_profile_dir(idx_1based: int) -> Path:
    # legacy naming, but inside RSAMAXXED sessions/
    d = _sessions_dir() / f"ZenFidelity_{idx_1based}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _downloads_dir(idx_1based: int) -> Path:
    d = _sessions_dir() / f"downloads_{idx_1based}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _lock_file(idx_1based: int) -> Path:
    return _sessions_dir() / f".profile_{idx_1based}.lock"


def cleanup_stale_startup() -> Dict[str, int]:
    """
    Best-effort startup cleanup for Fidelity automation artifacts:
    - Terminate stray browser processes still bound to Fidelity automation profiles.
    - Remove lingering profile lock files.
    """
    killed = 0
    removed_locks = 0
    sess = _sessions_dir()
    me = os.getpid()

    # Kill only processes that clearly reference the Fidelity automation profile path.
    try:
        # Use a broadly portable ps invocation and parse PID + command tail.
        out = subprocess.check_output(["ps", "aux"], text=True, stderr=subprocess.DEVNULL)
        for line in (out or "").splitlines()[1:]:
            s = line.rstrip()
            if not s:
                continue
            parts = s.split(None, 10)
            if len(parts) < 11:
                continue
            pid_s, cmd = parts[1], parts[10]
            try:
                pid = int(pid_s)
            except Exception:
                continue
            if pid == me:
                continue
            cmd_l = cmd.lower()
            if "zenfidelity_" not in cmd_l and str(sess).lower() not in cmd_l:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except Exception:
                pass
    except Exception:
        pass

    # Remove lingering lock files so profile lock acquisition won't block/reject.
    try:
        for lf in sess.glob(".profile_*.lock"):
            try:
                lf.unlink()
                removed_locks += 1
            except Exception:
                pass
    except Exception:
        pass

    return {"killed_procs": int(killed), "removed_locks": int(removed_locks)}

def _headless_default() -> bool:
    # Default to headless unless explicitly disabled or debug mode forces headed.
    v = (_env("FIDELITY_HEADLESS") or _env("HEADLESS") or "true").lower().strip()
    return v not in ("0", "false", "no", "off")

_ET = pytz.timezone("America/New_York")

def _logs_dir() -> Path:
    d = _root_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

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
    # CSV sensitive-ish fields
    "account number",
    "account #",
    "acct #",
)

def _key_allowed(k: str) -> bool:
    kl = (k or "").strip().lower()
    if not kl:
        return False
    return not any(bad in kl for bad in _DENY_KEY_SUBSTRS)

def _clean_csv_scalar(v: Any) -> Any:
    """
    Returns a JSON-safe scalar (float or short string) or None.
    - Parses currency/percent/paren negatives into float when possible
    - Limits string length to keep snapshots bounded
    """
    if v is None:
        return None
    s = str(v).strip()
    if not s or s in ("--", "n/a", "N/A", "-"):
        return None

    # numeric-ish cleanup
    ss = s.replace("$", "").replace(",", "").replace("%", "").strip()
    neg = False
    if ss.startswith("(") and ss.endswith(")"):
        neg = True
        ss = ss[1:-1].strip()
    try:
        f = float(ss)
        if neg:
            f = -f
        return f
    except Exception:
        pass

    if len(s) > 200:
        s = s[:200] + "…"
    return s

def _row_extras_from_csv_row(row: Dict[str, Any], *, max_items: int = 60) -> Dict[str, Any]:
    """
    Pull safe scalars from CSV row by header name.
    Skips denylisted keys and keeps snapshot size bounded.
    """
    out: Dict[str, Any] = {}
    n = 0
    for k, v in (row or {}).items():
        if n >= max_items:
            break
        if not isinstance(k, str):
            continue
        if not _key_allowed(k):
            continue
        val = _clean_csv_scalar(v)
        if val is None:
            continue
        out[k] = val
        n += 1
    return out


# =============================================================================
# Terminal helpers
# =============================================================================

def _otp_provider_terminal() -> OtpProvider:
    """OTP provider that prompts in the terminal."""
    def provider(label: str, timeout_s: int) -> Optional[str]:
        try:
            raw = input(universal_2fa_prompt(label) + " ").strip()
            digits = "".join(c for c in raw if c.isdigit())
            return digits if 6 <= len(digits) <= 8 else None
        except (EOFError, KeyboardInterrupt):
            return None
    return provider


def _notify_terminal() -> NotifyFn:
    """Notification function that prints to terminal."""
    def notify(msg: str) -> None:
        try:
            print(f"[Fidelity] {msg}")
        except UnicodeEncodeError:
            print(f"[Fidelity] {msg.encode('ascii', 'replace').decode('ascii')}")
    return notify


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
# Async runner safe inside existing event loop
# =============================================================================

def _run_coro(coro_factory: Callable[[], Coroutine[Any, Any, Any]], *, timeout_s: int = 900):
    try:
        asyncio.get_running_loop()
        in_running = True
    except RuntimeError:
        in_running = False

    if not in_running:
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

    t = Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout_s)

    if q.empty():
        raise TimeoutError("Fidelity operation timed out")

    ok, payload = q.get()
    if ok:
        return payload
    raise payload


# =============================================================================
# Profile lock
# =============================================================================

def _clean_chrome_singletons(profile_dir: Path) -> None:
    for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
        try:
            (profile_dir / name).unlink(missing_ok=True)
        except Exception:
            pass

def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False

def _acquire_profile_lock(idx_1based: int, timeout_s: int = 60, poll_s: float = 0.25, stale_s: int = 120) -> Path:
    lock = _lock_file(idx_1based)
    # Clean Chrome singleton files
    profile_dir = _sessions_dir() / f"profile_{idx_1based}"
    _clean_chrome_singletons(profile_dir)
    deadline = time.time() + timeout_s

    while time.time() < deadline:
        try:
            if lock.exists():
                try:
                    pid_text = lock.read_text().strip()
                    if pid_text.isdigit() and not _is_pid_alive(int(pid_text)):
                        lock.unlink()
                except Exception:
                    pass
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

    raise RuntimeError("Fidelity profile is busy (another Fidelity browser is still running). Try again in ~10s.")

def _release_profile_lock(lock: Path) -> None:
    try:
        lock.unlink()
    except Exception:
        pass


# =============================================================================
# Trace
# =============================================================================

def _trace_enabled() -> bool:
    v = (_env("FIDELITY_TRACE") or "true").lower().strip()
    return v not in ("0", "false", "no", "off")

def _trace_verbose() -> bool:
    v = (_env("FIDELITY_TRACE_VERBOSE") or "false").lower().strip()
    return v in ("1", "true", "yes", "on")

def _trace_path() -> Path:
    return _sessions_dir() / "fidelity_nav.log"

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
    if notify is not None and _trace_verbose():
        try:
            notify(f"Fidelity trace: {msg}")
        except Exception:
            pass


# =============================================================================
# Small utils
# =============================================================================

def _mask_last4(s: str) -> str:
    s = (s or "").strip()
    return f"****{s[-4:]}" if len(s) >= 4 else "****"

def _clean_symbol(sym: str) -> str:
    s = (sym or "").strip().upper()
    return s.replace("*", "").strip()

def _digits_only(s: str) -> str:
    return "".join(c for c in (s or "") if c.isdigit())


def _acct_name_key(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).upper()


def _trade_account_key(acct_name: str, acct_num: str) -> Tuple[str, str]:
    d = _digits_only(acct_num)
    return (_acct_name_key(acct_name), d[-4:] if d else "")


def _holdings_account_key(account_id: str) -> Tuple[str, str]:
    t = (account_id or "").strip()
    m = re.search(r"·\s*(.*?)\s*\(([^)]*)\)", t)
    if m:
        nm = (m.group(1) or "").strip()
        d = _digits_only(m.group(2) or "")
        return (_acct_name_key(nm), d[-4:] if d else "")

    m2 = re.search(r"^(.*?)\s*\(([^)]*)\)", t)
    if m2:
        nm = (m2.group(1) or "").strip()
        d = _digits_only(m2.group(2) or "")
        return (_acct_name_key(nm), d[-4:] if d else "")

    d2 = _digits_only(t)
    return (_acct_name_key(t), d2[-4:] if d2 else "")


def _fmt_smart_qty(shares: float) -> str:
    try:
        f = float(shares)
    except Exception:
        return ""
    if f <= 0:
        return ""
    if abs(f - round(f)) < 1e-9:
        return str(int(round(f)))
    return f"{f:.8f}".rstrip("0").rstrip(".")

async def _settle(page, sleep_s: float = 0.25) -> None:
    try:
        await page.wait_for_ready_state("complete", timeout=10)
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

async def _goto(page, url: str, label: str, notify: Optional[NotifyFn] = None, settle_s: float = 0.6):
    _trace(f"{label} | goto={url}", notify=notify)
    try:
        await page.get(url)
    except Exception as e:
        _trace(f"{label} | goto ERROR: {type(e).__name__}: {e}", notify=notify)
    await _settle(page, sleep_s=settle_s)
    _trace(f"{label} | url={await _current_url(page)}", notify=notify)

async def _safe_select(page, selector: str, timeout_s: float = 5.0):
    try:
        return await page.select(selector, timeout=timeout_s)
    except Exception:
        return None


def _js_str(s: str) -> str:
    """Escape a string for embedding inside a single-quoted JS literal."""
    return str(s).replace("\\", "\\\\").replace("'", "\\'")


# A handle-free click that opens Fidelity PVD dropdowns. A plain el.click() only
# fires a 'click' event, but PVD comboboxes open on pointerdown/mousedown — so the
# old JS fallbacks (b.click()) never opened the menu and the trade failed anyway.
# This dispatches the full pointer+mouse sequence a real click produces.
_JS_POINTER_CLICK = (
    "function __pc(el){if(!el)return false;"
    "try{el.scrollIntoView({block:'center'});}catch(e){}"
    "try{el.focus();}catch(e){}"
    "var o={bubbles:true,cancelable:true,view:window};"
    "function fire(t,C){try{el.dispatchEvent(new C(t,o));}catch(e){"
    "try{el.dispatchEvent(new MouseEvent(t,o));}catch(e2){}}}"
    "var P=window.PointerEvent||MouseEvent;"
    "fire('pointerdown',P);fire('mousedown',MouseEvent);"
    "fire('pointerup',P);fire('mouseup',MouseEvent);fire('click',MouseEvent);"
    "return true;}"
)


async def _element_visible(page, selector: str) -> bool:
    """True if the first element matching `selector` is present and visible."""
    try:
        return bool(
            await page.evaluate(
                "(function(){var el=document.querySelector('" + _js_str(selector) + "');"
                "if(!el)return false;var r=el.getBoundingClientRect();"
                "var st=window.getComputedStyle(el);"
                "return r.width>0&&r.height>0&&st.visibility!=='hidden'&&st.display!=='none';})();"
            )
        )
    except Exception:
        return False


async def _js_pointer_click_selector(page, selector: str) -> bool:
    """Pointer-click the first element matching `selector` (handle-free)."""
    try:
        return bool(
            await page.evaluate(
                "(function(){" + _JS_POINTER_CLICK
                + "return __pc(document.querySelector('" + _js_str(selector) + "'));})();"
            )
        )
    except Exception:
        return False


async def _js_click_option_by_text(page, container_sel: str, item_sel: str, text: str) -> bool:
    """
    Within `container_sel` (or the whole document if absent), pointer-click the first
    `item_sel` element whose text contains `text`. Handle-free, so it survives the
    React re-renders that make zendriver node handles go stale.
    """
    try:
        return bool(
            await page.evaluate(
                "(function(){" + _JS_POINTER_CLICK
                + "var want='" + _js_str(text) + "';"
                "var c=document.querySelector('" + _js_str(container_sel) + "');"
                "var scope=c||document;"
                "var els=scope.querySelectorAll('" + _js_str(item_sel) + "');"
                "for(var i=0;i<els.length;i++){"
                "var t=(els[i].innerText||els[i].textContent||'');"
                "if(t.indexOf(want)>=0){return __pc(els[i]);}}return false;})();"
            )
        )
    except Exception:
        return False


async def _stale_safe_click(page, selector: str, *, tries: int = 4, settle_s: float = 0.4, verify=None) -> bool:
    """
    Click an element (CSS selector) while surviving the React re-renders that make
    zendriver node handles go stale mid-interaction — 'Node with given id does not
    belong to the document' / 'No node with given id found' on DOM.resolveNode.

    A FRESH handle is grabbed on every attempt; on staleness we settle and retry,
    then fall back to a handle-free JS .click() (no node handle left to go stale).
    When `verify` (async () -> bool) is given, the click only counts as done once
    it passes — so a click that lands on a now-detached node and silently no-ops is
    retried rather than slipping through (the 'order type stuck on Order type'
    failure mode). Returns True on success.
    """
    async def _passed() -> bool:
        if verify is None:
            return True
        try:
            return bool(await verify())
        except Exception:
            return False

    for _ in range(max(1, tries)):
        try:
            node = await page.select(selector, timeout=5)
            await node.scroll_into_view()
            await node.mouse_move()
            await node.mouse_click()
            if await _passed():
                return True
        except Exception:
            # Handle went stale (DOM.resolveNode) — settle and re-grab a fresh one.
            pass
        await _settle(page, sleep_s=settle_s)
        if await _passed():
            return True

    # Handle-free JS fallback — pointer sequence so PVD dropdowns actually open.
    await _js_pointer_click_selector(page, selector)
    await _settle(page, sleep_s=settle_s)
    return await _passed()


async def _stale_safe_type(page, selector: str, text: str, *, tries: int = 4, settle_s: float = 0.4, verify=None) -> bool:
    """
    Type `text` into an input (CSS selector), surviving React re-render staleness
    the same way as _stale_safe_click. Grabs a fresh handle each attempt, clears,
    types, and verifies; falls back to a React-style value set that dispatches
    input/change/blur so the ticket registers it. Default verify: the field ends up
    holding `text`. Returns True on success.
    """
    async def _passed() -> bool:
        if verify is not None:
            try:
                return bool(await verify())
            except Exception:
                return False
        try:
            safe = _js_str(selector)
            val = await page.evaluate(
                "(function(){var el=document.querySelector('" + safe + "');"
                "return el?((el.value||el.getAttribute('value')||'')+'').trim():'';})();"
            )
            return (val or "").strip() == str(text).strip()
        except Exception:
            return False

    for _ in range(max(1, tries)):
        try:
            node = await page.select(selector, timeout=5)
            await node.scroll_into_view()
            await node.mouse_click()
            try:
                await node.clear_input_by_deleting()
            except Exception:
                try:
                    await node.clear_input()
                except Exception:
                    pass
            await node.send_keys(str(text))
            if await _passed():
                return True
        except Exception:
            pass
        await _settle(page, sleep_s=settle_s)
        if await _passed():
            return True

    # React-style JS fallback (native setter + dispatched events).
    try:
        safe = _js_str(selector)
        safe_val = _js_str(text)
        await page.evaluate(
            "(function(){var el=document.querySelector('" + safe + "');"
            "if(!el)return false;"
            "var proto=window.HTMLInputElement&&window.HTMLInputElement.prototype;"
            "var desc=proto&&Object.getOwnPropertyDescriptor(proto,'value');"
            "var setter=desc&&desc.set;el.focus();"
            "if(setter)setter.call(el,'" + safe_val + "');else el.value='" + safe_val + "';"
            "el.dispatchEvent(new Event('input',{bubbles:true}));"
            "el.dispatchEvent(new Event('change',{bubbles:true}));"
            "el.dispatchEvent(new Event('blur',{bubbles:true}));return true;})();"
        )
    except Exception:
        pass
    await _settle(page, sleep_s=settle_s)
    return await _passed()


async def _type_with_random_delay(element, text: str, min_delay=0.05, max_delay=0.15):
    """
    Type using the user imprint profile (state/imprint_profile.json via modules.ui_keys).
    Falls back to the old min/max delay behavior if the profile can't be loaded.
    """
    prof = None
    try:
        prof = runtime_profile()
        if not prof or isinstance(prof, dict):
            prof = None
    except Exception:
        prof = None

    payloads = KeyEvents.from_text(text, KeyPressEvent.DOWN_AND_UP)

    for payload in payloads:
        await element._tab.send(cdp.input_.dispatch_key_event(**payload))

        # If we have an imprint profile, use it.
        if prof is not None:
            base = float(prof.delay_mean) + random.uniform(-float(prof.delay_jitter), float(prof.delay_jitter))
            if base < 0.0:
                base = 0.0

            # micro pause
            if random.random() < float(prof.micro_pause_chance):
                base += random.uniform(float(prof.micro_pause_min), float(prof.micro_pause_max))

            # occasional longer pause
            if random.random() < float(prof.pause_chance):
                base += random.uniform(float(prof.pause_min), float(prof.pause_max))

            await asyncio.sleep(base)
        else:
            # fallback: original behavior
            await asyncio.sleep(random.uniform(min_delay, max_delay))


# =============================================================================
# Credentials parsing (supports legacy FIDELITY=... and simple FIDELITY_USERNAME/PASSWORD)
# =============================================================================

@dataclass(frozen=True)
class _LoginCred:
    idx_1based: int
    label: str
    username: str
    password: str
    totp_secret: str

def _load_creds() -> List[_LoginCred]:
    # Prefer legacy-style list: FIDELITY=user:pass:totp,user2:pass2:totp2
    raw = _env("FIDELITY")
    out: List[_LoginCred] = []

    if raw:
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        for i, item in enumerate(parts, 1):
            fields = item.split(":")
            user = (fields[0] or "").strip()
            pw = (fields[1] or "").strip() if len(fields) > 1 else ""
            totp = (fields[2] or "").strip() if len(fields) > 2 else ""
            if user and pw:
                out.append(_LoginCred(idx_1based=i, label=f"Fidelity {i}", username=user, password=pw, totp_secret=totp))
        return out

    # Fallback single-account env
    u = _env("FIDELITY_USERNAME")
    p = _env("FIDELITY_PASSWORD")
    t = _env("FIDELITY_TOTP_SECRET")
    if u and p:
        out.append(_LoginCred(idx_1based=1, label="Fidelity 1", username=u, password=p, totp_secret=t))
    return out


# =============================================================================
# Browser lifecycle (per-login profile)
# =============================================================================

async def _start_browser_for_login(idx_1based: int, *, notify: Optional[NotifyFn] = None, headless: Optional[bool] = None):
    lock = _acquire_profile_lock(idx_1based, timeout_s=60)
    is_headless = _headless_default() if headless is None else bool(headless)
    profile = _zen_profile_dir(idx_1based)

    browser_args: List[str] = ["--no-sandbox", "--force-device-scale-factor=0.8"]
    if is_headless:
        browser_args += [
            "--headless=new",
            "--window-size=1920,1080",
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
            "--disable-blink-features=AutomationControlled",
            "--disable-site-isolation-trials",
            "--disable-features=IsolateOrigins,site-per-process,TranslateUI,VizDisplayCompositor",
            "--disable-session-crashed-bubble",
            "--disable-infobars",
            "--no-first-run",
            "--disable-default-apps",
            "--disable-extensions",
            "--disable-dev-shm-usage",
            "--disable-gpu",
        ]
    else:
        browser_args += [
            "--start-maximized",
            "--disable-session-crashed-bubble",
            "--disable-infobars",
            "--no-first-run",
        ]

    # Kill any orphaned Chrome still using this profile
    cleanup_orphaned_chrome(profile)

    _trace(f"BROWSER | start idx={idx_1based} headless={is_headless} profile={profile}", notify=notify)

    try:
        browser = await uc.start(browser_args=browser_args, user_data_dir=str(profile), browser_executable_path=find_browser_executable())
        setattr(browser, "_fidelity_lock_path", str(lock))
        setattr(browser, "_fidelity_idx", idx_1based)

        if getattr(browser, "tabs", None):
            page = await browser.tabs[0].get("about:blank")
        else:
            page = await browser.get("about:blank")

        return browser, page
    except Exception:
        _release_profile_lock(lock)
        raise

async def _close_browser(browser, notify: Optional[NotifyFn] = None) -> None:
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
            idx = getattr(browser, "_fidelity_idx", None)
            if idx:
                cleanup_orphaned_chrome(_zen_profile_dir(idx))
        except Exception:
            pass
    finally:
        lock_path = getattr(browser, "_fidelity_lock_path", None)
        if lock_path:
            _release_profile_lock(Path(lock_path))
        _trace("BROWSER | closed", notify=notify)


# =============================================================================
# Auth detection + 2FA
# =============================================================================

async def _is_logged_in_soft(page) -> bool:
    """Are we authenticated? Decided on the URL PATH, never the query string.

    The sign-in page carries where it will send you next in ?AuthRedUrl=..., and
    that target IS the summary URL — so testing the whole URL string reports
    "logged in" while sitting on the login form. Fidelity percent-encodes that
    parameter only some of the time (%2F), so this passed on one run and
    false-positived on the next, and the damage showed up far downstream as
    "Timeout waiting for #previewOrderBtn" on a ticket that was really the login
    page. Verified against sessions/fidelity/fidelity_nav.log for 2026-08-10.
    """
    url = (await _current_url(page)).lower()
    if not url:
        return False
    try:
        path = urlsplit(url).path
    except Exception:
        path = url.split("?", 1)[0]
    # Any sign-on path is decisive: we are not logged in, whatever it redirects to.
    if "signin" in path or "login" in path or "signon" in path:
        return False
    if "ftgw/digital/portfolio/summary" in path:
        return True
    try:
        if await page.select("#accountDetails", timeout=1):
            return True
    except Exception:
        pass
    return False

async def _detect_2fa_gate(page) -> bool:
    try:
        return bool(
            await page.evaluate(
                """
                (function() {
                    if (document.getElementById('dom-totp-security-code-input')) return true;
                    if (document.getElementById('dom-push-authenticator-header')) return true;
                    if (document.getElementById('dom-channel-list-header')) return true;
                    if (document.getElementById('dom-otp-code-input')) return true;
                    if (document.querySelector('input[type="tel"]')) return true;
                    return false;
                })();
                """
            )
        )
    except Exception:
        return False

async def _handle_2fa(
    page,
    *,
    totp_secret: str,
    otp_provider: Optional[OtpProvider],
    notify: Optional[NotifyFn],
    label: str = "Fidelity",
) -> bool:
    await _settle(page, sleep_s=0.25)

    # If push page appears, skip it and click "Try another way" to get SMS option
    push_header = await _safe_select(page, "#dom-push-authenticator-header", timeout_s=1.0)
    if push_header is not None:
        _trace("2FA | push detected -> switching to SMS", notify=notify)
        # Look for "Try another way" or similar secondary link
        try:
            switched = await page.evaluate(
                """
                (function() {
                    // Common Fidelity selectors for the alternate-method link
                    var link = document.getElementById('dom-push-secondary-button')
                            || document.querySelector('[data-testid="dom-push-secondary-button"]')
                            || document.querySelector('a[href*="another"]');
                    if (!link) {
                        // Fallback: find any link/button with "another way" or "other options" text
                        var all = document.querySelectorAll('a, button, span[role="link"]');
                        for (var i = 0; i < all.length; i++) {
                            var t = all[i].innerText.toLowerCase();
                            if (t.includes('another') || t.includes('other option') || t.includes('other method')) {
                                link = all[i];
                                break;
                            }
                        }
                    }
                    if (link) { link.click(); return true; }
                    return false;
                })();
                """
            )
        except Exception:
            switched = False

        if switched:
            _trace("2FA | clicked 'try another way'", notify=notify)
            await _settle(page, sleep_s=1.5)
        else:
            _trace("2FA | no alternate link found, falling back to push wait", notify=notify)
            if notify is not None:
                notify("Check Fidelity app on your phone and approve the login request (you have ~2 minutes).")

            try:
                await page.evaluate(
                    """
                    (function() {
                        const cb = document.getElementById('dom-trust-device-checkbox');
                        if (cb && !cb.checked) cb.click();
                    })();
                    """
                )
            except Exception:
                pass

            send_btn = await _safe_select(page, "#dom-push-primary-button", timeout_s=2.0)
            if send_btn is not None:
                try:
                    await send_btn.mouse_click()
                except Exception:
                    pass

            for _ in range(24):
                await page.sleep(5)
                if await _is_logged_in_soft(page):
                    return True
            return False

    channel_header = await _safe_select(page, "#dom-channel-list-header", timeout_s=1.0)
    if channel_header is not None:
        _trace("2FA | channel list detected", notify=notify)
        # Try to pick the first text/phone option if there are radio buttons
        try:
            await page.evaluate(
                """
                (function() {
                    // Click the first radio button for text/call option
                    var radios = document.querySelectorAll('input[type="radio"]');
                    if (radios.length > 0) radios[0].click();
                })();
                """
            )
        except Exception:
            pass
        await _settle(page, sleep_s=0.3)
        text_btn = await _safe_select(page, "#dom-channel-list-primary-button", timeout_s=2.0)
        if text_btn is not None:
            try:
                await text_btn.mouse_click()
            except Exception:
                pass
        await page.sleep(1.0)

    otp_input = await _safe_select(page, "#dom-otp-code-input", timeout_s=5.0)
    if otp_input is not None:
        _trace("2FA | otp input detected", notify=notify)
        code = otp_provider(label, 300) if otp_provider else input("Enter Fidelity SMS code: ").strip()
        if not code:
            return False

        try:
            await page.evaluate(
                """
                (function() {
                    const cb = document.getElementById('dom-trust-device-checkbox');
                    if (cb && !cb.checked) cb.click();
                })();
                """
            )
        except Exception:
            pass

        try:
            await otp_input.clear_input()
        except Exception:
            pass
        await otp_input.send_keys(code)

        submit_btn = await _safe_select(page, "#dom-otp-code-submit-button", timeout_s=2.0)
        if submit_btn is not None:
            try:
                await submit_btn.mouse_click()
            except Exception:
                pass

        for _ in range(15):
            await page.sleep(1)
            if await _is_logged_in_soft(page):
                return True
        return False

    totp_input = await _safe_select(page, "#dom-totp-security-code-input", timeout_s=1.0)
    if totp_input is not None:
        _trace("2FA | totp input detected", notify=notify)

        code: Optional[str] = None
        if totp_secret and totp_secret.lower() not in ("na", "none", "false", "0"):
            try:
                import pyotp  # type: ignore
                code = pyotp.TOTP(totp_secret.replace(" ", "")).now()
            except Exception:
                code = None

        if not code:
            code = otp_provider(label, 300) if otp_provider else input("Enter Fidelity authenticator code: ").strip()
        if not code:
            return False

        try:
            await totp_input.mouse_click()
        except Exception:
            pass
        await totp_input.send_keys(code)

        try:
            await page.evaluate(
                """
                (function() {
                    const cb = document.getElementById('dom-trust-device-checkbox');
                    if (cb && !cb.checked) cb.click();
                })();
                """
            )
        except Exception:
            pass

        cont_btn = await _safe_select(page, "#dom-totp-code-continue-button", timeout_s=5.0)
        if cont_btn is not None:
            try:
                await cont_btn.mouse_click()
            except Exception:
                pass

        for _ in range(20):
            await page.sleep(1)
            if await _is_logged_in_soft(page):
                return True
        return False

    return False


async def _login_on_page(
    page,
    *,
    username: str,
    password: str,
    totp_secret: str,
    otp_provider: Optional[OtpProvider],
    notify: Optional[NotifyFn],
    label: str = "Fidelity",
) -> bool:
    _trace("LOGIN | begin", notify=notify)
    await _goto(page, LOGIN_URL, "LOGIN", notify=notify, settle_s=1.0)

    if await _is_logged_in_soft(page):
        _trace("LOGIN | already logged-in (soft)", notify=notify)
        await _goto(page, SUMMARY_URL, "LOGIN | land summary", notify=notify, settle_s=0.6)
        # Confirm the landing instead of assuming it. On 2026-08-10 this goto
        # was bounced straight back to signin/retail, the bounce was written to
        # the log, and we returned True anyway — so the trade ran unauthenticated
        # and died 15s later on a selector that was never going to be there.
        if await _is_logged_in_soft(page):
            return True
        _trace("LOGIN | soft session was stale (bounced back to sign-on) — logging in properly",
               notify=notify)
        # Land on a clean sign-on form rather than whatever the bounce left us on.
        await _goto(page, LOGIN_URL, "LOGIN | reopen sign-on", notify=notify, settle_s=1.0)

    user_input = None
    for sel in ("#dom-username-input", "input[name='username']", "#userId-input"):
        user_input = await _safe_select(page, sel, timeout_s=5.0)
        if user_input:
            break
    if not user_input:
        _trace("LOGIN | username field not found", notify=notify)
        return False

    pass_input = None
    for sel in ("#dom-pswd-input", "#password"):
        pass_input = await _safe_select(page, sel, timeout_s=5.0)
        if pass_input:
            break
    if not pass_input:
        _trace("LOGIN | password field not found", notify=notify)
        return False

    try:
        await user_input.mouse_move()
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await user_input.mouse_click()
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await user_input.clear_input_by_deleting()
    except Exception:
        pass
    await _type_with_random_delay(user_input, username)

    try:
        await pass_input.mouse_move()
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await pass_input.mouse_click()
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await pass_input.clear_input_by_deleting()
    except Exception:
        pass
    await _type_with_random_delay(pass_input, password)

    login_btn = await _safe_select(page, "#dom-login-button", timeout_s=5.0)
    if not login_btn:
        _trace("LOGIN | login button not found", notify=notify)
        return False

    _trace("LOGIN | click login button", notify=notify)
    try:
        await login_btn.mouse_move()
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await login_btn.mouse_click()
    except Exception:
        try:
            await login_btn.mouse_click()
        except Exception:
            pass

    await asyncio.sleep(0.6)

    start = time.time()
    while (time.time() - start) < 60:
        if await _is_logged_in_soft(page):
            _trace("LOGIN | success -> summary", notify=notify)
            await _goto(page, SUMMARY_URL, "LOGIN | force summary", notify=notify, settle_s=0.8)
            try:
                await page.select("#accountDetails", timeout=10)
            except Exception:
                pass
            return True

        if await _detect_2fa_gate(page):
            _trace("LOGIN | 2FA gate detected", notify=notify)
            ok2fa = await _handle_2fa(
                page,
                totp_secret=totp_secret,
                otp_provider=otp_provider,
                notify=notify,
                label=label,
            )
            if ok2fa:
                _trace("LOGIN | 2FA complete -> summary", notify=notify)
                await _goto(page, SUMMARY_URL, "LOGIN | force summary post-2FA", notify=notify, settle_s=0.8)
                return True
            return False

        await _settle(page, sleep_s=0.25)

    _trace("LOGIN | timeout", notify=notify)
    return False


async def _ensure_logged_in(
    page,
    *,
    username: str,
    password: str,
    totp_secret: str,
    otp_provider: Optional[OtpProvider],
    notify: Optional[NotifyFn],
) -> bool:
    if await _is_logged_in_soft(page):
        return True
    return await _login_on_page(
        page,
        username=username,
        password=password,
        totp_secret=totp_secret,
        otp_provider=otp_provider,
        notify=notify,
    )


# =============================================================================
# Positions CSV
# =============================================================================

async def _set_download_path(page, path: Path) -> None:
    try:
        await page.send(
            cdp.browser.set_download_behavior(
                behavior="allow",
                download_path=str(path),
                events_enabled=True,
            )
        )
    except Exception:
        pass

def _clean_download_dir(d: Path) -> None:
    for f in d.glob("*.csv"):
        try:
            f.unlink()
        except Exception:
            pass
    for f in d.glob("*.crdownload"):
        try:
            f.unlink()
        except Exception:
            pass

async def _download_positions_csv(page, *, idx_1based: int, notify: Optional[NotifyFn]) -> Path:
    d = _downloads_dir(idx_1based)
    _clean_download_dir(d)
    await _set_download_path(page, d)

    await _goto(page, POSITIONS_URL, "POSITIONS | open", notify=notify, settle_s=1.0)

    u = (await _current_url(page)).lower()
    if "prgw/digital/login" in u or "login/full-page" in u:
        raise RuntimeError(f"Bounced to login on positions: {u}")

    kebab = await page.select("[data-testid='kebab-menu']", timeout=10)
    for _ in range(20):
        try:
            if await kebab.get_position() is not None:
                break
        except Exception:
            pass
        await page.sleep(0.25)

    await kebab.scroll_into_view()
    await kebab.mouse_move()
    await kebab.mouse_click()
    await page.sleep(0.35)

    download_btn = await page.select("#kebabmenuitem-download", timeout=10)
    for _ in range(20):
        try:
            if await download_btn.get_position() is not None:
                break
        except Exception:
            pass
        await page.sleep(0.25)

    await download_btn.scroll_into_view()
    await download_btn.mouse_move()
    await download_btn.mouse_click()

    deadline = time.time() + 120
    while time.time() < deadline:
        files = sorted(d.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        partials = list(d.glob("*.crdownload"))
        if files and not partials:
            return files[0]
        await asyncio.sleep(1.0)

    raise RuntimeError("CSV download timed out")

def _parse_positions_csv(path: Path, *, label_prefix: str = "") -> List[AccountOutput]:
    def clean_num(v) -> float:
        if v is None:
            return 0.0
        s = str(v).replace("$", "").replace(",", "").replace("%", "").strip()
        if s in ("", "--", "n/a", "N/A", "-"):
            return 0.0
        # handle (123.45) negatives
        neg = False
        if s.startswith("(") and s.endswith(")"):
            neg = True
            s = s[1:-1].strip()
        try:
            f = float(s)
            return -f if neg else f
        except Exception:
            return 0.0

    buckets: Dict[str, Dict[str, Any]] = {}

    # capture column names for discovery
    fieldnames: List[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = [str(x) for x in (reader.fieldnames or []) if x]

        for row in reader:
            acc_num = (row.get("Account Number") or "").strip()
            acct_name = (row.get("Account Name") or "Account").strip()
            if not acc_num or "and" in acc_num:
                continue
            # Skip junk rows: date footers, non-Fidelity employer plans
            if acc_num.lower().startswith("date "):
                continue
            if "BARRETT" in acct_name.upper():
                continue

            # Fidelity CSV account-number representations can vary across users.
            # Bucket by number + name to avoid collapsing distinct accounts.
            bucket_key = f"{acc_num}||{acct_name}"
            if bucket_key not in buckets:
                buckets[bucket_key] = {
                    "acc_num": acc_num,
                    "acct_name": acct_name,
                    "total": 0.0,
                    "cash": 0.0,
                    "rows": [],
                    "raw_rows": 0,
                    "parsed_rows": 0,
                }

            symbol_raw = (row.get("Symbol") or "").strip()
            desc = (row.get("Description") or "").strip()
            if not row.get("Symbol"):
                continue

            qty = clean_num(row.get("Quantity"))
            last_price = clean_num(row.get("Last Price"))
            current_val = clean_num(row.get("Current Value"))

            if not symbol_raw and "Cash" in desc:
                symbol_raw = "CASH"

            symbol = _clean_symbol(symbol_raw)

            # Hard rule: never show Fidelity cash sweep as a holding, and
            # never let it into the securities total. It is still the account's
            # buying power, though, and it was being dropped on the floor one
            # line before the only place that wanted it — so record it on the
            # side for the Invest page and carry on discarding it here.
            if symbol == "FCASH":
                buckets[bucket_key]["cash"] += current_val
                continue

            buckets[bucket_key]["raw_rows"] += 1
            buckets[bucket_key]["total"] += current_val

            if symbol and (qty > 0 or current_val > 0):
                # holding-level discovery extras: safe columns from the CSV row
                hextra = _row_extras_from_csv_row(row, max_items=70)
                # never persist full account number
                hextra.pop("Account Number", None)
                hextra.pop("Account #", None)
                hextra.pop("Account Name", None)

                # useful computed helpers
                try:
                    if qty and last_price:
                        hextra["market_value_calc"] = float(qty) * float(last_price)
                except Exception:
                    pass
                try:
                    if current_val:
                        hextra["current_value"] = float(current_val)
                except Exception:
                    pass
                if desc:
                    hextra["description"] = desc[:200] + ("…" if len(desc) > 200 else "")

                buckets[bucket_key]["rows"].append(
                    HoldingRow(
                        symbol=(symbol or "UNKNOWN").strip().upper(),
                        shares=float(qty) if qty != 0 else None,
                        price=float(last_price) if last_price != 0 else None,
                        extra=hextra,
                    )
                )
                buckets[bucket_key]["parsed_rows"] += 1

    outs: List[AccountOutput] = []
    csv_name = path.name
    try:
        csv_mtime = float(path.stat().st_mtime)
    except Exception:
        csv_mtime = None  # type: ignore

    for _bucket_key, info in buckets.items():
        acc_num = str(info.get("acc_num") or "")
        acct_name = info["acct_name"]
        total = float(info["total"])
        base = f"{acct_name} ({_mask_last4(acc_num)}) = ${total:.2f}"
        label = f"{label_prefix} · {base}" if label_prefix else base

        acct_extra: Dict[str, Any] = {
            "account_last4": _digits_only(acc_num)[-4:] if _digits_only(acc_num) else (acc_num[-4:] if acc_num else "----"),
            "account_name": acct_name[:120],
            "account_total_value_calc": total,
            "cash": float(info.get("cash") or 0.0),
            "cash_source": "fcash",
            "csv_file": csv_name,
            "csv_mtime_epoch": csv_mtime,
            "csv_columns": fieldnames[:200],
            "raw_rows": int(info.get("raw_rows") or 0),
            "parsed_rows": int(info.get("parsed_rows") or 0),
            "positions_count": int(len(info["rows"])),
        }

        outs.append(AccountOutput(account_id=label, ok=True, message="", holdings=info["rows"], extra=acct_extra))

    if not outs:
        outs.append(AccountOutput(account_id=(label_prefix or "Fidelity"), ok=True, message="(no positions)", holdings=[], extra={
            "csv_file": csv_name,
            "csv_mtime_epoch": csv_mtime,
            "csv_columns": fieldnames[:200],
        }))

    return outs


def _num_from_csv(v) -> float:
    if v is None:
        return 0.0
    s = str(v).replace("$", "").replace(",", "").replace("%", "").strip()
    if s in ("", "--", "n/a", "N/A", "-"):
        return 0.0
    neg = False
    if s.startswith("(") and s.endswith(")"):
        neg = True
        s = s[1:-1].strip()
    try:
        f = float(s)
        return -f if neg else f
    except Exception:
        return 0.0


def _parse_sell_targets_csv(path: Path, *, symbol: str) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """
    Build smart-sell targets from exported positions CSV.
    Keyed by (normalized account name, account last4).
    """
    target_sym = (symbol or "").strip().upper()
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sym = _clean_symbol((row.get("Symbol") or "").strip().upper())
            if sym != target_sym:
                continue

            acct_num = (row.get("Account Number") or "").strip()
            acct_name = (row.get("Account Name") or "Account").strip()
            if not acct_num:
                continue
            d = _digits_only(acct_num)
            if not d:
                continue
            qty = _num_from_csv(row.get("Quantity"))
            if qty <= 0:
                continue

            k = _trade_account_key(acct_name, acct_num)
            prev = out.get(k)
            if prev is None:
                out[k] = {
                    "account_number": acct_num,
                    "account_name": acct_name,
                    "ticker": target_sym,
                    "qty": float(qty),
                }
            else:
                prev["qty"] = float(prev.get("qty") or 0.0) + float(qty)
    return out


# =============================================================================
# Trade helpers (legacy mapping/routing)
# =============================================================================

async def _ensure_expanded_ticket_mode(page, *, notify: Optional[NotifyFn]) -> None:
    # If show-fewer exists, we're already expanded.
    try:
        if await page.select("#show-fewer-trade-selections", timeout=1):
            return
    except Exception:
        pass

    try:
        expand_btn = await page.select("#show-more-trade-selections", timeout=5)
        if expand_btn:
            await expand_btn.scroll_into_view()
            await expand_btn.mouse_move()
            await expand_btn.mouse_click()
            await page.select("#show-fewer-trade-selections", timeout=2)
    except Exception:
        # Non-fatal: layout may have changed; continue
        pass


async def _open_account_dropdown_and_scrape(page) -> List[Dict[str, str]]:
    """
    Legacy-style scrape from #ett-acct-sel-list.
    Returns list of {"acctNum": "...", "name": "..."}.
    """
    out: List[Dict[str, str]] = []

    dropdown_selector = "#dest-acct-dropdown"
    # wait for dropdown presence
    for _ in range(40):
        try:
            exists = await page.evaluate(f'document.querySelector("{dropdown_selector}") !== null')
            if exists:
                break
        except Exception:
            pass
        await page.sleep(0.25)

    # open dropdown
    try:
        await page.evaluate(f'document.querySelector("{dropdown_selector}").click()')
    except Exception:
        # try click via select
        dd = await page.select(dropdown_selector, timeout=10)
        await dd.scroll_into_view()
        await dd.mouse_click()

    # scrape visible options
    scraped = await page.evaluate(
        """
        (function() {
            const list = document.getElementById("ett-acct-sel-list");
            if (!list) return [];
            const buttons = list.querySelectorAll('div[role="option"] button');
            let results = [];
            for (let btn of buttons) {
                results.push(btn.innerText.trim());
            }
            return results;
        })();
        """
    )

    for item in (scraped or []):
        m = re.search(r'(.*?)\s*\((Z?\d+)\)', item)
        if not m:
            continue
        nickname = m.group(1).strip() or "Account"
        acct_num = m.group(2).strip()
        out.append({"acctNum": acct_num, "name": nickname})
    return out


async def _select_account_in_dropdown(page, acct_num: str) -> None:
    dropdown_selector = "#dest-acct-dropdown"

    dd = await page.select(dropdown_selector, timeout=10)
    await dd.scroll_into_view()
    await dd.mouse_move()
    await dd.mouse_click()

    # Legacy parity: hard-wait for the list container
    await page.select("#ett-acct-sel-list", timeout=10)
    await page.sleep(0.15)

    # Legacy parity: best-match search and click
    opt = await page.find(f"({acct_num})", best_match=True)
    if not opt:
        opt = await page.find(acct_num, best_match=True)
    if not opt:
        raise RuntimeError(f"Account option not found in dropdown: {acct_num}")

    await opt.scroll_into_view()
    await opt.mouse_move()
    await opt.mouse_click()
    await page.sleep(0.2)


async def _maybe_force_extended_hours(page) -> bool:
    """
    Legacy behavior: if toggle exists, force it ON and treat as extended.
    """
    try:
        toggle_row = await page.select(".eq-ticket__extended-hrs-toggle-row_dest", timeout=1)
    except Exception:
        toggle_row = None
    if not toggle_row:
        return False

    # try detect on
    is_on = False
    try:
        switch_root = await page.select(".eq-ticket__extendedhour-toggle", timeout=2)
        if switch_root:
            cls = switch_root.attrs.get("class", "")
            if isinstance(cls, list):
                cls = " ".join(cls)
            is_on = "pvd-switch--on" in (cls or "")
    except Exception:
        pass

    if not is_on:
        try:
            toggle_btn = await page.select("#eq-ticket_extendedhour", timeout=2)
            if toggle_btn and toggle_btn.attrs.get("aria-checked") == "true":
                is_on = True
        except Exception:
            pass

    if not is_on:
        # click to enable
        clicked = False
        try:
            toggle_btn = await page.select("#eq-ticket_extendedhour", timeout=2)
            if toggle_btn is not None:
                await toggle_btn.mouse_move()
                await toggle_btn.mouse_click()
                clicked = True
        except Exception:
            pass
        if not clicked:
            try:
                switch_wrapper = await page.select(".eq-ticket__extendedhour-toggle", timeout=2)
                if switch_wrapper is not None:
                    await switch_wrapper.mouse_move()
                    await switch_wrapper.mouse_click()
            except Exception:
                pass
        await _settle(page, sleep_s=0.25)

    return True


# =============================================================================
# Symbol typeahead
# =============================================================================
#
# Typing a ticker opens a suggestion overlay directly under the symbol field —
# and on the equity ticket the Action control sits directly under that field, so
# an open overlay physically covers it. node.mouse_click() clicks a POINT on the
# screen, not an element, so every click aimed at Action landed on a suggestion
# instead. For MBAI the list is [MBAI, MBAIX]; the click took MBAIX, a mutual
# fund, and Fidelity swapped the whole ticket for the fund order form — which
# shares none of the selectors below, so everything after it failed on something
# unrelated. The tell in the state dump was options_open=2 while Action still
# read its 'Action' placeholder: two options with no menu open are suggestions.

# Visible typeahead rows. Two filters keep the ticket's OWN menus out of this:
# they live inside a dropdownlist wrapper, and their labels are control words,
# whereas a suggestion always leads with a ticker token.
_JS_SYMBOL_SUGGESTIONS = (
    "function __sugg(){"
    "var sym=document.querySelector('#eq-ticket-dest-symbol');"
    "if(!sym)return [];"
    "var ids=((sym.getAttribute('aria-controls')||'')+' '"
    "+(sym.getAttribute('aria-owns')||'')).trim();"
    "var opts=[];"
    "if(ids){ids.split(/\\s+/).forEach(function(i){var b=document.getElementById(i);"
    "if(b)opts=opts.concat([].slice.call(b.querySelectorAll('[role=\"option\"],li')));});}"
    "if(!opts.length){opts=[].slice.call(document.querySelectorAll('[role=\"option\"]'))"
    ".filter(function(o){"
    "return !o.closest('[id*=\"dropdownlist\"],[class*=\"dropdownlist\"]');});}"
    "var CTRL=/^(buy|sell|buy to cover|sell short|market|limit|stop.*|trailing.*|"
    "day|good.*|dividend.*|reinvest.*|cash|margin)$/i;"
    "return opts.filter(function(o){"
    "var r=o.getBoundingClientRect();"
    "if(r.width<=0||r.height<=0)return false;"
    "var t=(o.innerText||o.textContent||'').replace(/\\s+/g,' ').trim();"
    "if(!t||CTRL.test(t))return false;"
    "return /^[A-Z][A-Z.\\-]{0,5}\\b/.test(t);});}"
)


async def _symbol_suggestions(page) -> List[str]:
    """Text of the visible symbol-typeahead rows; [] when the overlay is closed."""
    try:
        out = await page.evaluate(
            "(function(){" + _JS_SYMBOL_SUGGESTIONS
            + "return __sugg().map(function(o){"
            "return (o.innerText||o.textContent||'').replace(/\\s+/g,' ').trim();});})();"
        )
        return [str(t) for t in (out or [])]
    except Exception:
        return []


async def _dismiss_symbol_suggestions(page, timeout_s: float = 3.0) -> bool:
    """Close the typeahead overlay and confirm it is actually gone.

    False means something is still showing — the caller must not fire coordinate
    clicks at the ticket while that is true, because they will hit the overlay.
    """
    deadline = time.time() + max(0.0, timeout_s)
    while True:
        if not await _symbol_suggestions(page):
            return True
        if time.time() >= deadline:
            return False
        try:
            await page.evaluate(
                "(function(){var el=document.querySelector('#eq-ticket-dest-symbol');"
                "if(!el)return;"
                "var k={key:'Escape',code:'Escape',keyCode:27,which:27,"
                "bubbles:true,cancelable:true};"
                "try{el.dispatchEvent(new KeyboardEvent('keydown',k));"
                "el.dispatchEvent(new KeyboardEvent('keyup',k));}catch(e){}"
                "try{el.blur();}catch(e){}"
                # An outside pointerdown is what actually dismisses the PVD
                # overlays that ignore Escape. On body, never on a control.
                "try{var o={bubbles:true,cancelable:true,view:window};"
                "document.body.dispatchEvent(new MouseEvent('mousedown',o));"
                "document.body.dispatchEvent(new MouseEvent('mouseup',o));}catch(e){}"
                "})();"
            )
        except Exception:
            pass
        await asyncio.sleep(0.25)


async def _select_symbol_suggestion(page, want: str) -> bool:
    """Click the suggestion row whose ticker is exactly `want`.

    ENTER commits whatever the list has HIGHLIGHTED, which is not necessarily the
    exact match — MBAI's list also carries MBAIX. Picking the row by ticker takes
    the guess out of it. Returns False when no exact row is showing, so the caller
    can fall back to ENTER.
    """
    try:
        return bool(await page.evaluate(
            "(function(){" + _JS_POINTER_CLICK + _JS_SYMBOL_SUGGESTIONS
            + "var want='" + _js_str(want.upper()) + "';"
            "var opts=__sugg();"
            "for(var i=0;i<opts.length;i++){"
            "var t=(opts[i].innerText||opts[i].textContent||'').trim().toUpperCase();"
            "var m=t.match(/^[A-Z.\\-]+/);"
            "if(m&&m[0]===want)return __pc(opts[i]);}"
            "return false;})();"
        ))
    except Exception:
        return False


async def _non_equity_ticket_reason(page, want: str) -> Optional[str]:
    """Why this is no longer the equity ticket — None when it still is.

    Only POSITIVE evidence of a fund ticket counts. A merely missing selector
    stays tolerable (Fidelity does rename things between builds); a fund order
    form does not, because none of the equity selectors exist on it and every
    later step would fail on something that looks unrelated.
    """
    try:
        reason = await page.evaluate(
            "(function(){"
            "var u=(location.href||'').toLowerCase();"
            "if(u.indexOf('mutual-fund')>=0||u.indexOf('mutualfund')>=0)"
            "return 'the ticket is now a mutual-fund order form ('+location.href+')';"
            "var eq=document.querySelector('#eq-ticket-dest-symbol')"
            "||document.querySelector('.eq-ticket');"
            "var mf=document.querySelector('[id*=\"mutual-fund\"],[class*=\"mutual-fund\"],"
            "[id*=\"mf-ticket\"],[class*=\"mf-ticket\"]');"
            "if(mf&&!eq)return 'the ticket is now a mutual-fund order form';"
            "return '';})();"
        )
    except Exception:
        return None
    return (reason or "").strip() or None


async def _enter_symbol_and_get_prices(page, symbol: str) -> Dict[str, float]:
    """
    Legacy DOM parsing: last/bid/ask.
    """
    from zendriver.core.keys import SpecialKeys  # type: ignore

    want = str(symbol).strip().upper()

    async def _loaded_symbol() -> str:
        """Ticker the ticket actually has, normalised. '' if unreadable.

        Fidelity renders the committed symbol as the input's value, sometimes
        decorated ('CSAI - CLOUDASTRUCTURE INC'), so keep only the leading
        ticker token.
        """
        try:
            raw = await page.evaluate(
                "(function(){var el=document.querySelector('#eq-ticket-dest-symbol');"
                "return el?((el.value||el.getAttribute('value')||'')+''):'';})();"
            )
        except Exception:
            return ""
        tok = re.match(r"[A-Za-z.\-]+", (raw or "").strip())
        return tok.group(0).upper() if tok else ""

    async def _symbol_field_present() -> bool:
        """Does the symbol input exist at all?

        This is what separates "the selector changed on this build" (tolerable,
        the old behaviour) from "the field is sitting there empty" (the symbol
        never went in, and nothing downstream will work).
        """
        try:
            return bool(await page.evaluate(
                "!!document.querySelector('#eq-ticket-dest-symbol')"))
        except Exception:
            return False

    # Same React re-render staleness as the account dropdown: grab a fresh handle
    # and retry rather than letting a "No node with given id found" kill the trade.
    # CRITICAL: clear before typing. send_keys APPENDS, so a field still holding a
    # previous ticker (prior account in the same loop, or a Fidelity prefill)
    # became e.g. 'MVISCSAI' and the ticket resolved some other security — a
    # silent wrong-symbol order. Nothing verified it afterwards.
    _sym_err: Optional[Exception] = None
    _committed = False
    for _attempt in range(3):
        try:
            symbol_input = await page.select("#eq-ticket-dest-symbol", timeout=10)
            await symbol_input.scroll_into_view()
            await symbol_input.mouse_click()
            try:
                await symbol_input.clear_input_by_deleting()
            except Exception:
                try:
                    await symbol_input.clear_input()
                except Exception:
                    pass
            # Belt-and-braces clear: some PVD inputs ignore the handle-level clear.
            try:
                await page.evaluate(
                    "(function(){var el=document.querySelector('#eq-ticket-dest-symbol');"
                    "if(!el)return;var s=Object.getOwnPropertyDescriptor("
                    "window.HTMLInputElement.prototype,'value').set;s.call(el,'');"
                    "el.dispatchEvent(new Event('input',{bubbles:true}));"
                    "el.dispatchEvent(new Event('change',{bubbles:true}));})();"
                )
            except Exception:
                pass
            await symbol_input.send_keys(want)
            # ENTER commits the typed text. This is the path that has always
            # worked. Clicking a suggestion row INSTEAD of pressing ENTER looked
            # tidier and broke it: a synthetic click on that widget does not
            # commit the ticket, so the quote panel never arrived and every
            # account failed on "quote panel never appeared after entering
            # 'MBAI'". Picking a row survives below as a CORRECTION only, where
            # it cannot cost anything — it runs when ENTER resolved the wrong
            # security.
            await symbol_input.send_keys(SpecialKeys.ENTER)
            _sym_err = None
        except Exception as e:
            _sym_err = e
            await _settle(page, sleep_s=0.4)
            continue

        try:
            await page.wait_for("#ett-more-less-quote-link", timeout=10)
        except Exception:
            # A fund ticket explains this exactly, and retrying on one is
            # pointless — the equity quote panel is never coming back.
            _wrong = await _non_equity_ticket_reason(page, want)
            if _wrong:
                raise RuntimeError(
                    f"{_wrong} — {want!r} was requested. A suggestion for a "
                    f"different security was selected; refusing to continue")
            # Record it. This branch used to `continue` with _sym_err already
            # cleared above, so three silent misses left the function returning
            # SUCCESS on an empty ticket — and the trade then died a step later
            # on "Action button reads ''", because Fidelity keeps Action inert
            # until a symbol resolves. The quote panel not arriving is a symbol
            # failure, and it has to be reported as one.
            _sym_err = RuntimeError(
                f"quote panel never appeared after entering {want!r} · "
                f"{await _ticket_state(page)}")
            await _settle(page, sleep_s=0.4)
            continue
        await _settle(page, sleep_s=0.5)

        _wrong = await _non_equity_ticket_reason(page, want)
        if _wrong:
            raise RuntimeError(
                f"{_wrong} — {want!r} was requested. A suggestion for a "
                f"different security was selected; refusing to continue")

        got = await _loaded_symbol()
        if got != want and got:
            # ENTER resolved a DIFFERENT security. For MBAI the typeahead also
            # carries MBAIX, and whichever row was highlighted is what committed.
            # Correcting it by clicking the row whose ticker matches exactly is
            # strictly better than another blind retry — and the result is
            # re-read rather than trusted, because a click on this widget does
            # not reliably commit.
            if await _select_symbol_suggestion(page, want):
                await _settle(page, sleep_s=0.6)
                got = await _loaded_symbol()

        # Only now close the overlay: the correction above needs it open, and
        # everything AFTER this function clicks by coordinates with Action
        # sitting directly underneath it.
        await _dismiss_symbol_suggestions(page)

        if got == want:
            _sym_err = None
            _committed = True
            break
        if not got and not await _symbol_field_present():
            # Field genuinely absent — the selector changed on this build. Keep
            # the old tolerance for that. An EMPTY field that exists is a
            # different thing entirely: the symbol never went in.
            _sym_err = None
            _committed = True
            break
        _sym_err = RuntimeError(
            f"Fidelity ticket shows {(got or '(empty)')!r} but {want!r} was requested")
        await _settle(page, sleep_s=0.4)

    if _sym_err is not None:
        raise _sym_err
    if not _committed:
        raise RuntimeError(f"Symbol {want!r} never registered on the ticket")

    price_data = await page.evaluate(
        """
        (function() {
            function parsePrice(text) {
                if (!text) return 0.0;
                return parseFloat(text.replace(/[$,]/g, '').trim()) || 0.0;
            }

            let last = 0.0, bid = 0.0, ask = 0.0;

            const lastEl = document.querySelector('.last-price');
            if (lastEl) last = parsePrice(lastEl.innerText);

            const blocks = document.querySelectorAll('.eq-ticket__quote--block');
            for (let block of blocks) {
                const title = block.querySelector('.block-title');
                const num = block.querySelector('.number');
                if (title && num) {
                    if (title.innerText.includes('Bid')) bid = parsePrice(num.innerText);
                    else if (title.innerText.includes('Ask')) ask = parsePrice(num.innerText);
                }
            }
            return { last: last, bid: bid, ask: ask };
        })();
        """
    )
    last = float(price_data.get("last", 0.0) or 0.0)
    bid = float(price_data.get("bid", 0.0) or 0.0)
    ask = float(price_data.get("ask", 0.0) or 0.0)
    return {"last": last, "bid": bid, "ask": ask}


async def _ticket_state(page) -> str:
    """What the order ticket actually looks like right now.

    "button reads ''" is not a diagnosis — it cannot tell a missing element from
    a disabled one from an unlabelled one, and those have completely different
    causes. Fidelity keeps Action disabled until the symbol registers, so the
    symbol field's real value belongs in the same snapshot.

    ``options_open`` was in that snapshot but not what it looked like: the 2
    options in the MBAI failure were the symbol typeahead's rows, not an open
    Action menu. Both are now named separately, and so is whatever is physically
    covering the button.
    """
    try:
        return await page.evaluate(
            """
            (function(){
              """ + _JS_SYMBOL_SUGGESTIONS + """
              var q=function(s){return document.querySelector(s);};
              var b=q('#dest-dropdownlist-button-action');
              var sym=q('#eq-ticket-dest-symbol');
              var dd=[].slice.call(
                document.querySelectorAll('[id^="dest-dropdownlist-button-"]')
              ).map(function(e){
                var t=(e.innerText||e.textContent||'').replace(/\\s+/g,' ').trim();
                return e.id+'='+(t||'(empty)')+(e.disabled?'[disabled]':'');
              });
              return JSON.stringify({
                url: location.href,
                ready: document.readyState,
                action_btn: !!b,
                action_text: b?((b.innerText||b.textContent||'').replace(/\\s+/g,' ').trim()):null,
                action_aria: b?(b.getAttribute('aria-label')||null):null,
                action_disabled: b?!!(b.disabled||b.getAttribute('aria-disabled')==='true'):null,
                action_expanded: b?b.getAttribute('aria-expanded'):null,
                symbol_field: sym?(sym.value||''):null,
                preview_btn: !!q('#previewOrderBtn'),
                options_open: document.querySelectorAll('[role="option"]').length,
                symbol_suggestions: __sugg().slice(0,6).map(function(o){
                  return (o.innerText||o.textContent||'').replace(/\\s+/g,' ').trim();
                }),
                dropdowns: dd
              });
            })();
            """
        )
    except Exception as e:
        return f"(ticket state unavailable: {type(e).__name__}: {e})"


async def _wait_action_ready(page, timeout_s: float = 12.0) -> bool:
    """Wait for the Action control to exist and be enabled.

    Fidelity renders the ticket before it finishes wiring it, and keeps Action
    disabled until the symbol registers — so opening the menu too early clicks a
    dead button, three times, and reports an empty label. Waiting for the control
    to be real is not a longer timeout; it is the precondition the picker always
    assumed and never checked.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            ok = await page.evaluate(
                "(function(){var b=document.querySelector('#dest-dropdownlist-button-action');"
                "if(!b) return false;"
                "if(b.disabled||b.getAttribute('aria-disabled')==='true') return false;"
                "return true;})();")
            if ok:
                return True
        except Exception:
            pass
        await asyncio.sleep(0.25)
    return False


async def _action_button_obstruction(page) -> str:
    """'' when a click at the Action button's centre would actually hit it.

    Otherwise a description of whatever is on top. This exists because
    node.mouse_click() targets a POINT, so an overlay covering the button
    silently eats the trade's clicks — and the overlay parked there is the symbol
    typeahead, whose rows are other securities.
    """
    try:
        return (await page.evaluate(
            "(function(){var b=document.querySelector('#dest-dropdownlist-button-action');"
            "if(!b)return '';"
            "try{b.scrollIntoView({block:'center'});}catch(e){}"
            "var r=b.getBoundingClientRect();"
            "if(r.width<=0||r.height<=0)return 'Action button is not visible';"
            "var el=document.elementFromPoint(r.left+r.width/2,r.top+r.height/2);"
            "if(!el)return '';"
            "if(el===b||b.contains(el)||el.contains(b))return '';"
            # Name the row, not the <span> inside it.
            "el=el.closest('[role=\"option\"],li,[id]')||el;"
            "var d=el.id?('#'+el.id):((''+(el.className||'')).trim()"
            ".split(/\\s+/)[0]||el.tagName);"
            "var t=(el.innerText||el.textContent||'').replace(/\\s+/g,' ').trim().slice(0,40);"
            "return 'covered by '+d+(t?(' ('+t+')'):'');})();"
        ) or "").strip()
    except Exception:
        return ""


# The Action menu's own option list. The picker used to scan the WHOLE document
# for [role="option"], which is also what the symbol typeahead renders.
_JS_ACTION_MENU_SCOPE = (
    "function __ascope(){"
    "var b=document.querySelector('#dest-dropdownlist-button-action');"
    "if(!b)return null;"
    "var ac=(b.getAttribute('aria-controls')||b.getAttribute('aria-owns')||'').trim();"
    "if(ac){var s=document.getElementById(ac.split(/\\s+/)[0]);if(s)return s;}"
    "return b.closest('[class*=\"dropdownlist\"],[id*=\"dropdownlist\"]')||b.parentElement;}"
)


def _js_action_option_finder(label: str) -> str:
    """JS declaring __aopt(): the Action option reading `label`, or null.

    Scoped to the Action menu, and any row the typeahead is showing is skipped
    outright — a click meant for Buy must never be able to land on a ticker.
    """
    return (
        _JS_SYMBOL_SUGGESTIONS
        + _JS_ACTION_MENU_SCOPE
        + "function __aopt(){var want='" + _js_str(label) + "';"
        "var sels=['[role=\"option\"]','li[role=\"option\"]',"
        "'.pvd-menu__list-item','[data-action]'];"
        "var sg=__sugg();"
        "var scopes=[__ascope(),document].filter(Boolean);"
        "for(var s=0;s<scopes.length;s++){for(var i=0;i<sels.length;i++){"
        "var opts=scopes[s].querySelectorAll(sels[i]);"
        "for(var j=0;j<opts.length;j++){var o=opts[j];"
        "if(sg.indexOf(o)>=0)continue;"
        "var t=(o.innerText||o.textContent||'').trim();"
        "var da=(o.getAttribute('data-action')||'').trim();"
        "if(t===want||da===want)return o;}}}"
        "return null;}"
    )


async def _select_action(page, action_upper: str) -> Tuple[bool, str]:
    """Commit the ticket's Action (Buy/Sell).

    Returns (committed, seen_text). ``seen_text`` is whatever the button actually
    read when we gave up, so the caller can put it in the error instead of the
    useless "never committed".

    Every path here used to click and ``return`` without checking, so a click
    that missed left Action on its placeholder — and because Order type is
    disabled until Action is set, the failure surfaced later and misleadingly as
    "Could not enter quantity" / "Limit price field not found". Callers MUST
    treat False as fatal: proceeding with an uncommitted (or worse, opposite)
    action risks sending the wrong side.
    """
    from zendriver.core.keys import SpecialKeys  # type: ignore

    label = "Buy" if action_upper == "BUY" else "Sell"

    async def _action_text() -> str:
        """Whatever the Action button currently reads, whitespace-collapsed."""
        try:
            txt = await page.evaluate(
                "(function(){var b=document.querySelector('#dest-dropdownlist-button-action');"
                "if(!b)return '';var t=(b.innerText||b.textContent||'')+'';"
                "if(!t.trim())t=(b.getAttribute('aria-label')||b.value||'')+'';"
                "return t.replace(/\\s+/g,' ').trim();})();"
            )
            return (txt or "").strip()
        except Exception:
            return ""

    def _matches(txt: str) -> bool:
        """Word-boundary match, with the dangerous look-alikes excluded.

        Exact equality was too strict — Fidelity decorates the button label, so a
        successful Buy read as something else and the picker looped forever
        re-selecting Buy. A bare substring test is the opposite failure: it would
        accept 'Buy to Cover' as 'Buy' and place the wrong order. So: require the
        word, and reject the compound actions explicitly.
        """
        norm = (txt or "").lower()
        if not norm:
            return False
        if label == "Buy":
            return "buy to cover" not in norm and bool(re.search(r"\bbuy\b", norm))
        return "sell short" not in norm and bool(re.search(r"\bsell\b", norm))

    async def _action_committed(wait_s: float = 0.0) -> bool:
        """True once the button reads the wanted action. wait_s>0 polls, because
        the label lands a beat after the React re-render; 0 is a single read so
        the common paths stay fast across ~10 accounts."""
        deadline = time.time() + max(0.0, wait_s)
        while True:
            if _matches(await _action_text()):
                return True
            if time.time() >= deadline:
                return False
            await asyncio.sleep(0.2)

    # Already on the wanted action — don't re-open (that only risks toggling).
    if await _action_committed():
        return True, ""

    # The control has to be real before clicking it means anything. Without this
    # the three attempts below hammer a not-yet-wired button for ~80s and then
    # report an empty label, which reads as "Fidelity changed the ticket".
    if not await _wait_action_ready(page):
        return False, f"control never became ready · {await _ticket_state(page)}"

    for _attempt in range(3):
        if await _select_action_once(page, label, action_upper, _action_committed):
            return True, ""
        # Menu may have been left open by a failed pass; settle before re-trying
        # so the next open-click isn't interpreted as a close.
        await _settle(page, sleep_s=0.5)
        if await _action_committed(wait_s=1.0):
            return True, ""

    _blocked = await _action_button_obstruction(page)
    return False, (f"{await _action_text()!r}"
                   + (f" · {_blocked}" if _blocked else "")
                   + f" · {await _ticket_state(page)}")


async def _select_action_once(page, label: str, action_upper: str, _action_committed) -> bool:
    """One open-menu-and-pick pass. True only if the action verifiably committed."""
    from zendriver.core.keys import SpecialKeys  # type: ignore

    # Never fire a coordinate click while something is on top of the button. The
    # symbol typeahead renders directly over Action, so mouse_click() at Action's
    # coordinates picked a SUGGESTION instead — MBAIX for MBAI — and loaded a
    # mutual-fund ticket. Clear the overlay first; if the button is still covered,
    # drive it handle-free, where the events go to the element and not to a point.
    blocked = await _action_button_obstruction(page)
    if blocked:
        await _dismiss_symbol_suggestions(page)
        blocked = await _action_button_obstruction(page)
    if blocked:
        await _js_pointer_click_selector(page, "#dest-dropdownlist-button-action")
        await _settle(page, sleep_s=0.4)
    else:
        # Stale-safe. The raw select+click here was throwing DOM.resolveNode
        # 'Node with given id does not belong to the document' when the ticket
        # re-rendered on the just-loaded quote; _stale_safe_click re-grabs a fresh
        # handle and falls back to a pointer sequence (PVD opens on pointerdown).
        await _stale_safe_click(page, "#dest-dropdownlist-button-action", settle_s=0.4)
    dd = await _safe_select(page, "#dest-dropdownlist-button-action", 5)
    await _settle(page, sleep_s=0.4)
    # Wait up to ~3s for options to render, trying broadened selectors.
    target_id = None
    for _ in range(15):
        target_id = await page.evaluate(
            "(function(){" + _js_action_option_finder(label)
            + "var o=__aopt();"
            "return o?(o.id||'__match__'):null;})();"
        )
        if target_id:
            break
        await asyncio.sleep(0.2)

    if target_id and not target_id.startswith("__match__"):
        try:
            opt = await page.select(f"#{target_id}", timeout=5)
            if opt:
                await opt.scroll_into_view()
                await opt.mouse_move()
                await opt.mouse_click()
                await _settle(page, sleep_s=0.3)
                if await _action_committed(wait_s=1.5):
                    return True
        except Exception:
            # Node handle went stale as the menu re-rendered ("No node with
            # given id found") — fall through to the stale-proof JS click below
            # instead of failing the whole trade.
            pass

    # JS-driven click as a robust fallback (no element ID needed). Handle-free and
    # scoped, so it cannot reach a typeahead row however the menu re-rendered.
    clicked = await page.evaluate(
        "(function(){" + _JS_POINTER_CLICK + _js_action_option_finder(label)
        + "var o=__aopt();return o?__pc(o):false;})();"
    )
    if clicked:
        await _settle(page, sleep_s=0.3)
        if await _action_committed(wait_s=1.5):
            return True

    # Keyboard fallback: Buy is usually first, Sell second. "Usually" is why the
    # verify below is mandatory — a blind arrow count can land on the OPPOSITE
    # action, and this used to return with nobody checking.
    #
    # It is only safe while the Action menu is the thing listening. With the
    # symbol typeahead open the arrows walk ITS list and Enter commits a ticker —
    # that is the other way MBAI turned into MBAIX. Skip the fallback entirely
    # rather than gamble on who has focus.
    if await _symbol_suggestions(page):
        await _dismiss_symbol_suggestions(page)
    if dd is None:
        dd = await _safe_select(page, "#dest-dropdownlist-button-action", 5)
    if dd is not None and not await _symbol_suggestions(page):
        try:
            presses = 1 if action_upper == "BUY" else 2
            for _ in range(presses):
                await dd.send_keys(SpecialKeys.ARROW_DOWN)
                await asyncio.sleep(0.1)
            await dd.send_keys(SpecialKeys.ENTER)
            await _settle(page, sleep_s=0.3)
        except Exception:
            pass

    return await _action_committed(wait_s=1.5)


async def _order_type_menu_open(page) -> bool:
    """
    True if the order-type dropdown is currently expanded.

    Re-clicking the button while the menu is already open *closes* it, which is
    how the ticket can get stuck on the 'Order type' placeholder. Callers use
    this to open the menu only when it is closed.
    """
    try:
        return bool(
            await page.evaluate(
                """
                (function() {
                    const b = document.querySelector('#dest-dropdownlist-button-ordertype');
                    if (b && b.getAttribute('aria-expanded') === 'true') return true;
                    // Only treat the menu as open when the ORDER-TYPE options are
                    // actually visible — a visible option reading exactly 'Market'
                    // AND one reading exactly 'Limit'. The old generic
                    // [role="option"] check false-positived on ANY other open
                    // combobox on the ticket (e.g. the action menu), so
                    // _set_order_type believed this menu was already open, never
                    // clicked to open it, found no Market/Limit options, and every
                    // click/keyboard fallback no-opped -> ticket stuck on the
                    // 'Order type' placeholder ("Limit price field not found").
                    const isVis = (el) => {
                        const r = el.getBoundingClientRect();
                        const st = window.getComputedStyle(el);
                        return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none';
                    };
                    const sels = ['[role="option"]', 'li[role="option"]',
                                  '.pvd-menu__list-item'];
                    let sawMarket = false, sawLimit = false;
                    for (const sel of sels) {
                        for (const opt of document.querySelectorAll(sel)) {
                            if (!isVis(opt)) continue;
                            // PVD options can be two-line ('Limit\n<description>'),
                            // so match the FIRST line exactly rather than the whole
                            // innerText. Exact-on-whole used to false-NEGATIVE on a
                            // decorated label — the detector then thought the open
                            // menu was closed, re-clicked the button, and toggled it
                            // shut, leaving the ticket stuck on 'Order type'. First
                            // line still can't match the action menu's 'Buy'/'Sell'.
                            const t = (opt.innerText || opt.textContent || '').trim();
                            const first = (t.split('\\n')[0] || '').trim();
                            if (first === 'Market') sawMarket = true;
                            else if (first === 'Limit') sawLimit = true;
                        }
                    }
                    return sawMarket && sawLimit;
                })();
                """
            )
        )
    except Exception:
        return False


async def _set_order_type(page, *, order_type: str, is_extended: bool) -> None:
    from zendriver.core.keys import SpecialKeys  # type: ignore

    label = "Limit" if order_type == "Limit" else "Market"

    async def _committed() -> bool:
        return label.lower() in (await _order_type_label(page)).lower()

    # Already on the wanted type — do NOT re-open/re-toggle (that only risks
    # closing the menu and undoing a good selection).
    if await _committed():
        return

    # Drive the order-type dropdown the SAME way as the (working) action dropdown:
    # open it, then select by KEYBOARD. Fidelity's order-type control is a custom
    # widget (class `ett-dropdownlist-btn`, no aria-expanded) whose options are NOT
    # [role=option]/.pvd-menu__list-item, so `_order_type_menu_open` can never see
    # them. The old code GATED the keyboard fallback on that detector, so the
    # selection never ran and the ticket sat on the 'Order type' placeholder
    # ("Limit price field not found"). The reliable success signal is the button's
    # own text (`_committed`), which needs no option selector.
    presses = 1 if label == "Market" else 2
    first_letter = label[0]  # 'L' -> Limit, 'M' -> Market; both unique (Stop* -> S)

    for _pass in range(3):
        # Open with a single click (stale-safe). Do NOT consult _order_type_menu_open
        # — it is blind to this widget and would only cause toggle-close churn.
        dd = await _safe_select(page, "#dest-dropdownlist-button-ordertype", 5)
        clicked_open = False
        if dd is not None:
            try:
                await dd.scroll_into_view()
                await dd.mouse_move()
                await dd.mouse_click()
                clicked_open = True
            except Exception:
                clicked_open = False
        if not clicked_open:
            await _stale_safe_click(page, "#dest-dropdownlist-button-ordertype", tries=2)
            dd = await _safe_select(page, "#dest-dropdownlist-button-ordertype", 5)
        await _settle(page, sleep_s=0.4)

        # Best-effort: click a real option if the DOM happens to expose one (broadened
        # to Fidelity's dropdownlist ids). Harmless when it matches nothing.
        try:
            clicked = await page.evaluate(
                "(function(){"
                + _JS_POINTER_CLICK
                + "var sels=['[role=\"option\"]','li[role=\"option\"]','.pvd-menu__list-item',"
                "'[id*=\"dropdownlist-item-ordertype\"]','[id*=\"ordertype\"] li','ul[id*=\"ordertype\"] li'];"
                "for(var s=0;s<sels.length;s++){var opts=document.querySelectorAll(sels[s]);"
                "for(var i=0;i<opts.length;i++){var o=opts[i];"
                "var t=(o.innerText||o.textContent||'').trim();var f=(t.split('\\n')[0]||'').trim();"
                "if(f==='" + label + "'){return __pc(o);}}}return false;})();"
            )
        except Exception:
            clicked = False
        if clicked:
            await _settle(page, sleep_s=0.3)
            if await _committed():
                return

        # Keyboard selection — the reliable path (mirrors the working action
        # dropdown). UNGATED. Primary: type-ahead by first letter ('L'/'M'),
        # unambiguous so no off-by-one. Backup: positional ArrowDowns (Market=1,
        # Limit=2 in the Market/Limit/Stop/StopLimit order).
        if dd is not None:
            for _method in ("typeahead", "arrows"):
                try:
                    if _method == "typeahead":
                        await dd.send_keys(first_letter)
                        await asyncio.sleep(0.2)
                        await dd.send_keys(SpecialKeys.ENTER)
                    else:
                        for _ in range(presses):
                            await dd.send_keys(SpecialKeys.ARROW_DOWN)
                            await asyncio.sleep(0.15)
                        await dd.send_keys(SpecialKeys.ENTER)
                    await _settle(page, sleep_s=0.4)
                    if await _committed():
                        return
                except Exception:
                    # dd went stale mid-keypress — retry with a fresh open next pass.
                    break

        # Not committed — close any open menu with Escape so the next pass's click
        # opens from a clean state instead of toggling it shut.
        if dd is not None:
            try:
                await dd.send_keys(SpecialKeys.ESCAPE)
                await _settle(page, sleep_s=0.2)
            except Exception:
                pass

    # Best effort: leave without raising. Market orders need no follow-up field;
    # for Limit, _fill_limit_price detects the missing field and fails safe.


async def _order_type_label(page) -> str:
    """Current text of the order-type dropdown button (e.g. 'Limit', 'Market')."""
    try:
        txt = await page.evaluate(
            """
            (function() {
                const b = document.querySelector('#dest-dropdownlist-button-ordertype');
                return b ? (b.innerText || b.textContent || '').trim() : '';
            })();
            """
        )
        return (txt or "").strip()
    except Exception:
        return ""


async def _dump_order_type_state(page) -> str:
    """
    JSON snapshot for a 'stuck on Order type' failure. Opens the menu (pointer
    click) first, lets it render, then reports the button's aria wiring plus the
    parent chain (tag#id.class[role]) of every element whose text is exactly
    'Market'/'Limit' — so we see the REAL option selector instead of guessing.
    """
    try:
        await _js_pointer_click_selector(page, "#dest-dropdownlist-button-ordertype")
    except Exception:
        pass
    await _settle(page, sleep_s=0.5)
    try:
        return await page.evaluate(
            "(function(){"
            "function vis(el){if(!el)return false;var r=el.getBoundingClientRect();"
            "var s=window.getComputedStyle(el);"
            "return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';}"
            "function desc(el){if(!el)return '';"
            "var c=((el.className||'')+'').trim().split(/\\s+/).filter(Boolean).slice(0,3).join('.');"
            "return (el.tagName||'?').toLowerCase()+(el.id?('#'+el.id):'')+(c?('.'+c):'')+"
            "(el.getAttribute&&el.getAttribute('role')?('[role='+el.getAttribute('role')+']'):'');}"
            "var b=document.querySelector('#dest-dropdownlist-button-ordertype');"
            "var info={btn:!!b};"
            "if(b){info.text=(b.innerText||b.textContent||'').trim();"
            "info.disabled=b.disabled===true;"
            "info.ariaControls=b.getAttribute('aria-controls');"
            "info.ariaOwns=b.getAttribute('aria-owns');"
            "info.ariaHaspopup=b.getAttribute('aria-haspopup');"
            "info.ariaExpanded=b.getAttribute('aria-expanded');"
            "info.cls=((b.className||'')+'').slice(0,120);}"
            "var hits=[];var all=document.querySelectorAll('*');"
            "for(var i=0;i<all.length;i++){var el=all[i];"
            "var t=(el.innerText||el.textContent||'').trim();"
            "if((t==='Market'||t==='Limit')&&el.children.length<=1){"
            "var chain=[];var p=el;for(var d=0;d<4&&p;d++){chain.push(desc(p));p=p.parentElement;}"
            "hits.push({t:t,vis:vis(el),chain:chain});}}"
            "info.optionHits=hits.slice(0,8);"
            "var q=document.querySelector('#eqt-shared-quantity');"
            "info.qty=q?((q.value||q.getAttribute('value')||'')+'').trim():null;"
            "return JSON.stringify(info);})();"
        ) or "{}"
    except Exception as e:
        return "dump-failed:" + str(e)


async def _resolve_limit_price_selector(page) -> Optional[str]:
    """
    Return a CSS selector string for the Limit price input, or None.

    Detects the field's existence via JS (no node handle is held, so the result
    can't go stale). Tries the known id first, then an attribute/label search so
    a Fidelity DOM rename doesn't break the flow. The field only renders once the
    order-type dropdown commits to Limit, so None also signals it may not have
    switched yet.
    """
    try:
        found_id = await page.evaluate(
            """
            (function() {
                if (document.querySelector('#eqt-mts-limit-price')) return 'eqt-mts-limit-price';
                const inputs = Array.from(document.querySelectorAll('input'));
                const isVis = (el) => {
                    if (!el) return false;
                    const r = el.getBoundingClientRect();
                    const st = window.getComputedStyle(el);
                    return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none';
                };
                const hay = (el) => [
                    el.id, el.name, el.getAttribute('aria-label'),
                    el.getAttribute('placeholder'), el.getAttribute('data-testid')
                ].map(s => (s || '').toLowerCase()).join(' ');
                let cand = inputs.find(el => isVis(el) && hay(el).includes('limit') && hay(el).includes('price') && !hay(el).includes('stop'));
                if (!cand) cand = inputs.find(el => isVis(el) && /limit/.test(hay(el)) && !/stop/.test(hay(el)));
                if (!cand) return null;
                if (!cand.id) cand.id = 'rsamaxxed-limit-price';
                return cand.id;
            })();
            """
        )
    except Exception:
        found_id = None
    return f"#{found_id}" if found_id else None


_DP_ERR_RE = re.compile(r"(\d+)\s*decimal\s*places?\s*or\s*fewer", re.I)


def _decimals_wanted_from_error(err_txt: str) -> Optional[int]:
    """Pull the allowed decimal count out of Fidelity's price-format rejection.

    e.g. "Enter a price with 2 decimal places or fewer" -> 2. Returns None for
    any other error so the caller doesn't retry on unrelated failures.
    """
    m = _DP_ERR_RE.search(err_txt or "")
    if not m:
        return None
    try:
        dp = int(m.group(1))
    except Exception:
        return None
    return dp if 0 <= dp <= 6 else None


def _decimals_allowed(price: float) -> int:
    """Reg NMS increments the ticket enforces: $0.01 at/above $1, $0.0001 below."""
    return 4 if 0 < price < 1.00 else 2


def _quantize_limit_price(price: float, *, side: str, max_dp: Optional[int] = None) -> str:
    """Format a limit price the way the ticket will accept it.

    The bid/ask scraped off the quote block can carry more decimals than the
    ticket allows ("Enter a price with 2 decimal places or fewer"), and
    ``str(float)`` can leak binary artifacts, so quantize with Decimal rather
    than typing the raw number. Round in the direction that keeps the order
    marketable — up for BUY, down for SELL. A limit is a ceiling/floor, not the
    fill price, so the extra increment never changes what we actually pay.
    """
    dp = _decimals_allowed(price) if max_dp is None else max_dp
    step = Decimal(1).scaleb(-dp)
    rounding = ROUND_CEILING if str(side).upper() == "BUY" else ROUND_FLOOR
    try:
        # Snap float noise first, else a 0.30000000000000004 ceils a whole
        # increment up to 0.3001.
        d = Decimal(str(price)).quantize(Decimal(1).scaleb(-(dp + 2)))
        d = d.quantize(step, rounding=rounding)
    except Exception:
        d = Decimal(0)
    if d <= 0:
        # A sub-increment price floored to 0 (e.g. $0.0034 sell at 2dp). Send the
        # smallest legal price instead of a zero the ticket would reject.
        d = step
    s = format(d, "f")
    if "." in s:
        # Trailing zeros still count as decimal places to the ticket's validator,
        # so 0.10 goes in as "0.10" rather than "0.1000".
        whole, _, frac = s.partition(".")
        frac = frac.rstrip("0").ljust(2, "0")
        s = f"{whole}.{frac}"
    return s


async def _fill_limit_price(page, limit_price, *, side: str = "BUY", is_extended: bool = False) -> None:
    """
    Ensure the ticket is in Limit mode, then enter the limit price.

    ``limit_price`` may be a float (quantized here for ``side``) or an
    already-formatted string (used by the decimal-places retry).

    Two failure modes are handled:
      * The limit-price field only appears after the order-type dropdown commits
        to Limit. If it is missing we re-assert the Limit selection (the original
        cause of the '#eqt-mts-limit-price' timeout for sub-$1 buys).
      * Right after the switch the ticket is still re-rendering, so a node handle
        grabbed too early goes stale ('No node with given id found' on
        DOM.resolveNode). We detect existence via JS, let the render settle, then
        grab a FRESH node per attempt and retry on staleness, with a JS fallback.
    """
    price_str = (
        limit_price.strip()
        if isinstance(limit_price, str)
        else _quantize_limit_price(float(limit_price), side=side)
    )

    # Phase 1: make sure the field exists (re-assert Limit if it doesn't).
    # (Kept short so a stuck order-type surfaces its diagnostic fast instead of
    # grinding through the full retry cascade.)
    sel = None
    for _ in range(2):
        sel = await _resolve_limit_price_selector(page)
        if sel:
            break
        if "limit" not in (await _order_type_label(page)).lower():
            try:
                await _set_order_type(page, order_type="Limit", is_extended=is_extended)
            except Exception:
                pass
        await _settle(page, sleep_s=0.5)

    if not sel:
        diag = await _dump_order_type_state(page)
        raise RuntimeError(
            "Limit price field not found "
            f"(order type stuck on '{await _order_type_label(page) or 'unknown'}') "
            f"| diag={diag}"
        )

    # Let the post-switch re-render finish before touching the node.
    await _settle(page, sleep_s=0.4)

    # Phase 2: fill with a fresh node each attempt; retry on stale-node errors.
    for _ in range(3):
        try:
            node = await page.select(sel, timeout=3)
            await node.scroll_into_view()
            await node.mouse_click()
            try:
                await node.focus()
            except Exception:
                pass
            try:
                await node.clear_input_by_deleting()
            except Exception:
                try:
                    await node.clear_input()
                except Exception:
                    pass
            await node.send_keys(price_str)
            try:
                await page.mouse_click(0, 0)
            except Exception:
                pass
            if await _limit_price_value_ok(page, sel, price_str):
                return
        except Exception:
            # Node likely went stale mid-interaction; settle and re-resolve.
            await _settle(page, sleep_s=0.4)
            new_sel = await _resolve_limit_price_selector(page)
            if new_sel:
                sel = new_sel

    # Phase 3: JS fallback — set the value React-style and dispatch events.
    safe_sel = sel.replace("'", "\\'")
    ok = await page.evaluate(
        """
        (function() {
            const el = document.querySelector('"""
        + safe_sel
        + """');
            if (!el) return false;
            const proto = window.HTMLInputElement && window.HTMLInputElement.prototype;
            const desc = proto && Object.getOwnPropertyDescriptor(proto, 'value');
            const setter = desc && desc.set;
            el.focus();
            if (setter) setter.call(el, '"""
        + price_str
        + """'); else el.value = '"""
        + price_str
        + """';
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            el.dispatchEvent(new Event('blur', { bubbles: true }));
            return (el.value || '').trim() !== '';
        })();
        """
    )
    if not bool(ok) or not await _limit_price_value_ok(page, sel, price_str):
        raise RuntimeError("Could not enter limit price (field kept going stale)")


async def _limit_price_value_ok(page, sel: str, expected: str) -> bool:
    """True if the limit-price input now holds a non-empty value matching expected."""
    safe_sel = sel.replace("'", "\\'")
    try:
        val = await page.evaluate(
            """
            (function() {
                const el = document.querySelector('"""
            + safe_sel
            + """');
                return el ? ((el.value || el.getAttribute('value') || '').trim()) : '';
            })();
            """
        )
    except Exception:
        return False
    val = (val or "").strip()
    if not val:
        return False
    try:
        return abs(float(val.replace(",", "").replace("$", "")) - float(expected)) < 1e-9
    except Exception:
        return val == expected


async def _preview_and_check_error(page) -> Tuple[bool, str]:
    # Click preview. The ticket may still be re-rendering from the limit-price
    # step, so a node grabbed too early goes stale ("No node with given id
    # found"). Grab a FRESH handle per attempt, retry on staleness, then fall
    # back to a stale-proof JS click.
    clicked = False
    for _ in range(3):
        try:
            preview = await page.select("#previewOrderBtn", timeout=10)
            await preview.mouse_move()
            await preview.mouse_click()
            clicked = True
            break
        except Exception:
            await _settle(page, sleep_s=0.4)
    if not clicked:
        try:
            await page.evaluate(
                "(function(){const b=document.querySelector('#previewOrderBtn'); if(b) b.click();})();"
            )
        except Exception:
            pass

    await _settle(page, sleep_s=0.25)

    # success indicator: place order button exists
    try:
        if await page.select("#placeOrderBtn", timeout=2):
            return True, ""
    except Exception:
        pass

    # error content
    try:
        err = await page.select(".pvd-inline-alert__content", timeout=2)
        if err:
            txt = await page.evaluate("document.querySelector('.pvd-inline-alert__content').innerText")
            return False, (txt or "Preview error").strip()
    except Exception:
        pass

    # modal exists but not parsed
    try:
        if await page.select(".pvd-modal__dialog", timeout=2):
            return False, "Error modal detected (details could not be parsed)"
    except Exception:
        pass

    return False, "Preview failed (unknown)"


def _format_smart_sell_test_message(summary: Dict[str, str]) -> str:
    return (
        "🧪 Fidelity Sell-Smart (TEST ORDER)\n\n"
        "Place order button: PRESENT (not clicked)\n\n"
        f"Account: {summary.get('Account', '').strip()}\n"
        f"Symbol: {summary.get('Symbol', '').strip()}\n"
        f"Action: {summary.get('Action', '').strip()}\n"
        f"Quantity: {summary.get('Quantity', '').strip()}\n"
        f"Order type: {summary.get('Order type', '').strip()}\n"
        f"Time in force: {summary.get('Time in force', '').strip()}\n"
        f"Estimated value: {summary.get('Estimated value', '').strip()}"
    ).strip()


async def _extract_preview_summary_for_test(page) -> Dict[str, str]:
    """
    Dry-run only:
    - Gate T1: Place order button visible+enabled (do not click).
    - Gate T2: Scroll trade ticket to summary and confirm required labels are visible in ticket container.
    - Gate T3: Extract non-empty label->value pairs.
    """
    payload = await page.evaluate(
        """
        (function() {
            const REQUIRED = ['Account', 'Symbol', 'Action', 'Quantity', 'Order type', 'Time in force', 'Estimated value'];
            const norm = (s) => (s || '').replace(/\\s+/g, ' ').trim().toLowerCase();
            const isVis = (el) => {
                if (!el) return false;
                const st = window.getComputedStyle(el);
                if (st.visibility === 'hidden' || st.display === 'none') return false;
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
            };
            const nameOf = (el) => ((el.innerText || el.textContent || el.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim());
            const allButtons = Array.from(document.querySelectorAll('button,[role="button"]'));
            const placeBtn = allButtons.find((b) => norm(nameOf(b)) === 'place order' && isVis(b) && !b.disabled);
            if (!placeBtn) {
                return { ok: false, stage: 'T1', error: 'Gate T1 failed: Place order button not visible/enabled after preview' };
            }

            const isScrollable = (el) => !!el && (el.scrollHeight > (el.clientHeight + 8));
            const hasReqText = (el) => {
                const txt = norm((el && el.innerText) || '');
                return txt.includes('estimated value') && txt.includes('account') && txt.includes('symbol');
            };
            let container = null;
            const dialog = placeBtn.closest('[role="dialog"]');
            if (dialog) container = dialog;
            if (!container) {
                let p = placeBtn.parentElement;
                while (p) {
                    if (isScrollable(p) && hasReqText(p)) { container = p; break; }
                    p = p.parentElement;
                }
            }
            if (!container) {
                const cands = Array.from(document.querySelectorAll('[role="dialog"], [class*="drawer"], [class*="trade"], [id*="trade"], main, section'));
                container = cands.find((el) => el.contains(placeBtn) && hasReqText(el)) || cands.find((el) => hasReqText(el)) || document.body;
            }

            const inContainerView = (el) => {
                if (!el || !container) return false;
                if (!isVis(el)) return false;
                if (container === document.body) return true;
                const er = el.getBoundingClientRect();
                const cr = container.getBoundingClientRect();
                return er.bottom >= cr.top && er.top <= cr.bottom;
            };
            const labelNodes = () => Array.from(container.querySelectorAll('dt,th,label,strong,b,span,div,p'));
            const values = {};
            const seenLabels = new Set();

            const rowValueFor = (labelEl, labelTxt) => {
                const target = norm(labelTxt);
                const tryRows = [];
                let p = labelEl;
                for (let i = 0; i < 4 && p; i++) {
                    tryRows.push(p);
                    p = p.parentElement;
                }
                for (const row of tryRows) {
                    const kids = Array.from(row.children || []).filter((k) => isVis(k));
                    if (kids.length >= 2) {
                        for (const k of kids) {
                            const t = (nameOf(k) || '').trim();
                            if (!t) continue;
                            if (norm(t) === target) continue;
                            if (norm(t).startsWith(target + ' ')) {
                                const rest = t.slice(labelTxt.length).trim();
                                if (rest) return rest;
                            } else {
                                return t;
                            }
                        }
                    }
                    const rt = (nameOf(row) || '').trim();
                    if (rt) {
                        const lines = rt.split(/\\n+/).map((x) => x.trim()).filter(Boolean);
                        for (let i = 0; i < lines.length; i++) {
                            if (norm(lines[i]) === target && lines[i + 1]) return lines[i + 1];
                            if (norm(lines[i]).startsWith(target + ' ')) {
                                const rest = lines[i].slice(labelTxt.length).trim();
                                if (rest) return rest;
                            }
                        }
                    }
                }
                return '';
            };

            const scan = () => {
                for (const req of REQUIRED) {
                    const reqN = norm(req);
                    const n = labelNodes().find((el) => inContainerView(el) && norm(nameOf(el)) === reqN);
                    if (!n) continue;
                    seenLabels.add(req);
                    if (!values[req]) {
                        const v = (rowValueFor(n, req) || '').trim();
                        if (v) values[req] = v;
                    }
                }
            };

            if (container !== document.body) {
                try { container.scrollTop = 0; } catch (_) {}
            } else {
                try { window.scrollTo(0, 0); } catch (_) {}
            }
            scan();
            for (let i = 0; i < 30 && seenLabels.size < REQUIRED.length; i++) {
                if (container !== document.body) {
                    const step = Math.max(80, Math.floor(container.clientHeight * 0.7));
                    const before = container.scrollTop;
                    container.scrollTop = Math.min(container.scrollTop + step, container.scrollHeight);
                    if (container.scrollTop === before) break;
                } else {
                    const step = Math.max(200, Math.floor(window.innerHeight * 0.7));
                    const before = window.scrollY;
                    window.scrollTo(0, before + step);
                    if (window.scrollY === before) break;
                }
                scan();
            }

            const missingLabels = REQUIRED.filter((k) => !seenLabels.has(k));
            if (missingLabels.length) {
                return {
                    ok: false,
                    stage: 'T2',
                    error: 'Gate T2 failed: summary labels not visible in trade ticket: ' + missingLabels.join(', '),
                };
            }

            // Fallback parse from container text for any missing values.
            const lines = ((container && container.innerText) || '')
                .split(/\\n+/)
                .map((x) => x.trim())
                .filter(Boolean);
            for (const req of REQUIRED) {
                if (values[req] && String(values[req]).trim()) continue;
                const reqN = norm(req);
                for (let i = 0; i < lines.length; i++) {
                    const ln = lines[i];
                    const lnN = norm(ln);
                    if (lnN === reqN) {
                        if (lines[i + 1]) {
                            values[req] = lines[i + 1].trim();
                            break;
                        }
                    } else if (lnN.startsWith(reqN + ' ')) {
                        const rest = ln.slice(req.length).trim();
                        if (rest) {
                            values[req] = rest;
                            break;
                        }
                    }
                }
            }

            const blanks = REQUIRED.filter((k) => !String(values[k] || '').trim());
            if (blanks.length) {
                return {
                    ok: false,
                    stage: 'T3',
                    error: 'Gate T3 failed: blank summary values for: ' + blanks.join(', '),
                    values,
                };
            }
            return { ok: true, values };
        })();
        """
    )
    if not isinstance(payload, dict):
        raise RuntimeError("Gate T1/T2/T3 failed: unexpected preview summary payload")
    if not bool(payload.get("ok")):
        raise RuntimeError(str(payload.get("error") or "Gate T1/T2/T3 failed"))
    vals = payload.get("values") or {}
    if not isinstance(vals, dict):
        raise RuntimeError("Gate T3 failed: preview summary values missing")
    return {str(k): str(v) for k, v in vals.items()}


async def _open_trade_drawer_from_current_page(page) -> None:
    """
    Open Fidelity's trade drawer from the current logged-in page (no URL navigation).
    """
    opened = await page.evaluate(
        """
        (function() {
            const exact = (el) => ((el.innerText || el.textContent || '').trim() === 'Trade')
                || ((el.getAttribute && (el.getAttribute('aria-label') || '').trim()) === 'Trade');
            const cands = Array.from(document.querySelectorAll('button,[role="button"]'));
            const btn = cands.find(exact);
            if (!btn) return false;
            btn.click();
            return true;
        })();
        """
    )
    if not opened:
        raise RuntimeError("Trade button not found on current page")

    # Core drawer readiness gates.
    await page.select("#dest-acct-dropdown", timeout=12)
    await page.select("#previewOrderBtn", timeout=12)
    await page.select("#eq-ticket-dest-symbol", timeout=12)


def _is_hard_error(msg: str) -> bool:
    """Should this failure stop the rest of this login's accounts, or just this one?

    Hard means Fidelity refusing the order — security not allowed, account
    restricted — which it will refuse identically on the next account, so bailing
    early saves minutes of certain failure. A timeout or a ticket that never came
    up is NOT hard: it is this account at this moment, and counting it toward the
    breaker is how two slow page loads turn into a whole login's accounts going
    unbought and reported as "Skipped".
    """
    m = (msg or "").lower()
    if "timeout" in m and "waiting for element" in m:
        return False
    if "did not load" in m or "not up" in m:
        return False
    if "stale" in m or "node with given id" in m:
        return False
    return True


def _fid_account_matches(acct: Dict[str, Any], label: str, wanted: set) -> bool:
    """True when this destination account is one the caller asked to trade.

    Matched on the account number appearing in the requested string, so a label
    copied straight off a result row ("Fidelity 1 · ROTH IRA (Z12345678)") works
    as well as a bare account number.
    """
    num = str(acct.get("acctNum") or "").strip()
    for w in wanted:
        w = str(w).strip()
        if not w:
            continue
        if w == label or (num and w == num):
            return True
        # Substring only for a number long enough to be unambiguous — a short
        # one can appear inside a different account's number and trade the
        # wrong account, which is the one mistake this must never make.
        if num and len(num) >= 5 and num in w:
            return True
    return False


async def _wait_for_trade_ticket(page, *, label: str = "",
                                 notify: Optional[NotifyFn] = None,
                                 first_s: float = 20.0,
                                 retry_s: float = 30.0) -> None:
    """Wait until order entry is really up, re-navigating once if it isn't.

    `page.get()` returns when the document commits, but order entry is a React
    app that only mounts #previewOrderBtn after it hydrates — so a single fixed
    wait is racing Fidelity's boot time, and on a slow morning it loses. The old
    15s wait then failed the whole account for what was, most of the time, a
    page that would have been ready a second later.

    A session quietly bounced to login produces the identical symptom — the
    selector simply isn't there — which is why the failure message has to name
    the URL we actually landed on. "Selector not found" sent us looking at the
    ticket code for a problem that was never in it.
    """
    await _settle(page, sleep_s=0.4)
    if await _safe_select(page, "#previewOrderBtn", first_s):
        return

    url = await _current_url(page)
    _trace(f"TRADE | {label} | ticket not up after {first_s:.0f}s (url={url}) — reloading",
           notify=notify)
    await _goto(page, TRADE_URL, f"TRADE[{label}]", notify=notify, settle_s=1.0)
    if await _safe_select(page, "#previewOrderBtn", retry_s):
        return

    url = await _current_url(page)
    low = (url or "").lower()
    hint = ""
    if any(k in low for k in ("login", "signin", "sso", "auth")):
        hint = " — the session was bounced back to login"
    raise RuntimeError(
        f"Fidelity order ticket did not load after two attempts "
        f"(url: {url or 'unknown'}){hint}")


async def _click_enter_new_order_if_present(page) -> bool:
    """
    On confirmation screen, click 'Enter new order' if present so next target starts cleanly.
    """
    try:
        clicked = await page.evaluate(
            """
            (function() {
                const cands = Array.from(document.querySelectorAll('button,[role="button"]'));
                const btn = cands.find(el => ((el.innerText || el.textContent || '').trim() === 'Enter new order'));
                if (!btn) return false;
                btn.click();
                return true;
            })();
            """
        )
        if clicked:
            await page.select("#previewOrderBtn", timeout=10)
            return True
    except Exception:
        pass
    return False


# =============================================================================
# Broker interface
# =============================================================================

def bootstrap(*args, **kwargs) -> BrokerOutput:
    """
    Compatibility shim: run a session rehydrate for all configured Fidelity logins.
    Not required by user commands anymore.
    """
    otp_provider = _otp_provider_terminal()
    notify = _notify_terminal()
    force_headed = bool(kwargs.get("debug") or False)
    creds = _load_creds()
    if not creds:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fidelity", ok=False, message="Missing FIDELITY or FIDELITY_USERNAME/FIDELITY_PASSWORD")],
            message="Missing credentials",
        )

    async def _run_all() -> BrokerOutput:
        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False

        for c in creds:
            browser = None
            page = None
            try:
                browser, page = await _start_browser_for_login(
                    c.idx_1based,
                    notify=notify,
                    headless=(False if force_headed else _headless_default()),
                )
                ok = await _ensure_logged_in(
                    page,
                    username=c.username,
                    password=c.password,
                    totp_secret=c.totp_secret,
                    otp_provider=otp_provider,
                    notify=notify,
                )
                # Enumerate the real destination accounts.
                #
                # This used to return ONE row per login and count sub-accounts
                # out of a cached positions CSV, so a login with ten accounts
                # reported as "1 account(s) connected" whenever that file was
                # stale or missing — the app counts len(accounts).
                #
                # The ticket's own dropdown is the live, authoritative list, and
                # opening it here also proves the session genuinely works. That
                # is the check that would have caught the soft-login false
                # positive at bootstrap instead of at trade time.
                sub: List[Dict[str, str]] = []
                if ok:
                    try:
                        await page.get(TRADE_URL)
                        await _wait_for_trade_ticket(page, label=c.label, notify=notify)
                        sub = await _open_account_dropdown_and_scrape(page)
                        _trace(f"BOOTSTRAP | {c.label} | {len(sub)} destination account(s)",
                               notify=notify)
                    except Exception as e:
                        _trace(f"BOOTSTRAP | {c.label} | account enumeration failed: "
                               f"{type(e).__name__}: {e}", notify=notify)
                        sub = []

                if ok and sub:
                    for a in sub:
                        outs.append(AccountOutput(
                            account_id=f"{c.label} · {a.get('name', 'Account')} ({a['acctNum']})",
                            ok=True, message="Connected"))
                else:
                    # Fall back to the cached CSV count, then to a bare row.
                    n_sub = 0
                    if ok:
                        try:
                            dl_dir = _root_dir() / "sessions" / "fidelity" / f"downloads_{c.idx_1based}"
                            csvs = sorted(dl_dir.glob("Portfolio_Positions_*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
                            if csvs:
                                sub_accounts = _parse_positions_csv(csvs[0], label_prefix=c.label)
                                n_sub = len([a for a in sub_accounts if a.ok])
                        except Exception:
                            pass
                    msg = f"ok ({n_sub} accounts)" if ok and n_sub > 1 else ("ok" if ok else "auth failed")
                    outs.append(AccountOutput(account_id=c.label, ok=ok, message=msg))
                any_ok = any_ok or ok
                any_fail = any_fail or (not ok)
            except Exception as e:
                outs.append(AccountOutput(account_id=c.label, ok=False, message=str(e)))
                any_fail = True
            finally:
                try:
                    if browser is not None:
                        await _close_browser(browser, notify=notify)
                except Exception:
                    pass

        state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="")

    return _run_coro(lambda: _run_all(), timeout_s=900)


def get_holdings(*args, **kwargs) -> BrokerOutput:
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fidelity", ok=False, message="Cancelled before start")],
            message="Cancelled",
        )

    otp_provider = _otp_provider_terminal()
    notify = _notify_terminal()
    force_headed = bool(kwargs.get("debug") or False)
    creds = _load_creds()
    if not creds:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fidelity", ok=False, message="Missing FIDELITY or FIDELITY_USERNAME/FIDELITY_PASSWORD")],
            message="Missing credentials",
        )

    async def _run_all() -> BrokerOutput:
        outs: List[AccountOutput] = []
        any_ok = False
        any_fail = False

        broker_extra: Dict[str, Any] = {
            "login_profiles": int(len(creds)),
            "csv_downloads_ok": 0,
            "csv_downloads_failed": 0,
        }

        for c in creds:
            if _is_cancelled(kwargs):
                break
            browser = None
            page = None
            try:
                # positions can work headless; keep env setting
                browser, page = await _start_browser_for_login(
                    c.idx_1based,
                    notify=notify,
                    headless=(False if force_headed else _headless_default()),
                )

                ok = await _ensure_logged_in(
                    page,
                    username=c.username,
                    password=c.password,
                    totp_secret=c.totp_secret,
                    otp_provider=otp_provider,
                    notify=notify,
                )
                if not ok:
                    outs.append(AccountOutput(account_id=c.label, ok=False, message="auth failed", holdings=[]))
                    any_fail = True
                    broker_extra["csv_downloads_failed"] = int(broker_extra["csv_downloads_failed"]) + 1
                    continue

                csv_path = await _download_positions_csv(page, idx_1based=c.idx_1based, notify=notify)
                broker_extra["csv_downloads_ok"] = int(broker_extra["csv_downloads_ok"]) + 1
                broker_extra[f"csv_{c.idx_1based}_file"] = csv_path.name

                acct_outs = _parse_positions_csv(csv_path, label_prefix=c.label)
                outs.extend(acct_outs)
                any_ok = True

            except Exception as e:
                outs.append(AccountOutput(account_id=c.label, ok=False, message=str(e), holdings=[]))
                any_fail = True
                broker_extra["csv_downloads_failed"] = int(broker_extra["csv_downloads_failed"]) + 1
            finally:
                try:
                    if browser is not None:
                        await _close_browser(browser, notify=notify)
                except Exception:
                    pass

        if _is_cancelled(kwargs):
            state = "partial" if any_ok else "failed"
        else:
            state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")
        broker_extra["accounts_ok"] = int(sum(1 for a in outs if a.ok))
        broker_extra["accounts_failed"] = int(sum(1 for a in outs if not a.ok))

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message="", extra=broker_extra)

    return _run_coro(lambda: _run_all(), timeout_s=1200)


def get_accounts(*args, **kwargs) -> BrokerOutput:
    return get_holdings(*args, **kwargs)


def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False, **kwargs) -> BrokerOutput:
    """
    Legacy-faithful Fidelity trade path:
      - open trade page
      - ensure expanded ticket
      - scrape destination accounts from dropdown list
      - for each destination account: select via legacy best-match click (NO page.evaluate args)
      - optionally force extended hours toggle if present
      - enter symbol, read last/bid/ask
      - set action, qty, order type, limit price
      - preview -> detect errors -> (dry_run ticket / live submit)
    """
    if _is_cancelled(kwargs):
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fidelity", ok=False, message="Cancelled before start")],
            message="Cancelled",
        )

    otp_provider = _otp_provider_terminal()
    notify = _notify_terminal()
    force_headed = bool(kwargs.get("debug") or False)
    creds = _load_creds()
    if not creds:
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Fidelity", ok=False, message="Missing FIDELITY or FIDELITY_USERNAME/FIDELITY_PASSWORD")],
            message="Missing credentials",
        )

    side_upper = (side or "").strip().upper()
    if side_upper not in ("BUY", "SELL"):
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid side: {side!r}")

    sym = (symbol or "").strip().upper()
    if not sym:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message="Invalid symbol")

    # Optional: trade only these destination accounts (a retry of the ones that
    # failed). Empty means every account, which is the normal path.
    only_accounts = {str(a).strip() for a in (kwargs.get("only_accounts") or [])
                     if str(a).strip()}

    smart_sell = bool(kwargs.get("smart_sell") or False) and side_upper == "SELL"
    forced_order_type = str(kwargs.get("order_type") or "").strip().lower()
    if forced_order_type not in ("", "market", "limit"):
        forced_order_type = ""
    forced_limit_price: Optional[float] = None
    if forced_order_type == "limit":
        try:
            forced_limit_price = float(str(kwargs.get("limit_price") or "").strip())
            if forced_limit_price <= 0:
                raise ValueError()
        except Exception:
            return BrokerOutput(
                broker=BROKER,
                state="failed",
                accounts=[AccountOutput(account_id="Fidelity", ok=False, message=f"Invalid limit price: {kwargs.get('limit_price')!r}")],
                message="Invalid limit price",
            )

    qty_int = 0
    if not smart_sell:
        try:
            qty_int = int(float(qty))
            if qty_int <= 0:
                raise ValueError()
        except Exception:
            return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid qty: {qty!r}")

    async def _run_all() -> BrokerOutput:
        outs: List[AccountOutput] = []
        log_lines: List[str] = []
        processed_targets: set[Tuple[str, str]] = set()
        hard_stop = False
        # Did any login actually hold one of the requested accounts? Without
        # this a retry naming an account nobody owns returns an empty success-
        # shaped result, which reads as "nothing to do" instead of "not found".
        matched_any = not only_accounts

        if dry_run:
            log_lines.append("DRY RUN — NO ORDER SUBMITTED")
            log_lines.append(f"broker: {BROKER}")
            log_lines.append(f"time_et: {datetime.now(_ET).isoformat()}")
            req_qty = ("ALL (smart_sell)" if smart_sell else str(qty_int))
            log_lines.append(f"requested: side={side_upper} symbol={sym} qty={req_qty}")
            log_lines.append("")

        any_ok = False
        any_fail = False

        for c in creds:
            if _is_cancelled(kwargs):
                break
            if hard_stop:
                break
            browser = None
            page = None
            try:
                # legacy: dry-run must be headed to avoid UI oddities
                headless = (False if dry_run or force_headed else _headless_default())
                browser, page = await _start_browser_for_login(c.idx_1based, notify=notify, headless=headless)

                ok = await _ensure_logged_in(
                    page,
                    username=c.username,
                    password=c.password,
                    totp_secret=c.totp_secret,
                    otp_provider=otp_provider,
                    notify=notify,
                )
                if not ok:
                    outs.append(AccountOutput(account_id=c.label, ok=False, message="auth failed"))
                    if dry_run:
                        log_lines.append(f"[{c.label}] ERROR: auth failed")
                        log_lines.append("")
                    any_fail = True
                    continue

                _trace(f"TRADE | {c.label} | auth ok, preparing trade", notify=notify)

                smart_targets: Dict[Tuple[str, str], Dict[str, Any]] = {}
                if smart_sell:
                    csv_path = await _download_positions_csv(page, idx_1based=c.idx_1based, notify=notify)
                    smart_targets = _parse_sell_targets_csv(csv_path, symbol=sym)
                    if dry_run:
                        log_lines.append(f"[{c.label}] smart_sell_targets={len(smart_targets)} from_csv={csv_path.name}")
                    if not smart_targets:
                        outs.append(AccountOutput(account_id=c.label, ok=False, message=f"Smart Sell: no holdings found for {sym}"))
                        any_fail = True
                        continue

                # Open trade context (smart-sell stays on current page; standard path uses trade URL)
                if smart_sell:
                    await _open_trade_drawer_from_current_page(page)
                else:
                    _trace(f"TRADE | {c.label} | navigating to trade page", notify=notify)
                    await page.get(TRADE_URL)
                    _trace(f"TRADE | {c.label} | waiting for trade form", notify=notify)
                    await _wait_for_trade_ticket(page, label=c.label, notify=notify)
                    await _ensure_expanded_ticket_mode(page, notify=notify)

                # Scrape destination accounts (legacy)
                _trace(f"TRADE | {c.label} | scraping account list", notify=notify)
                acct_list = await _open_account_dropdown_and_scrape(page)
                if not acct_list:
                    outs.append(AccountOutput(account_id=c.label, ok=False, message="No destination accounts found on trade ticket"))
                    if dry_run:
                        log_lines.append(f"[{c.label}] ERROR: no destination accounts found")
                        log_lines.append("")
                    any_fail = True
                    continue

                # Caller asked for specific accounts (a retry of the ones that
                # failed). A login holding none of them is skipped silently —
                # the requested accounts live under one of the other logins.
                if only_accounts:
                    if c.label in only_accounts:
                        # A login-level failure (ticket never loaded, auth) is
                        # reported as the bare login label because no account was
                        # ever reached. Asking for it back means the whole login,
                        # not nothing.
                        matched_any = True
                        _trace(f"TRADE | {c.label} | retrying the whole login", notify=notify)
                    else:
                        wanted = [a for a in acct_list
                                  if _fid_account_matches(
                                      a, f"{c.label} · {a.get('name', 'Account')} ({a['acctNum']})",
                                      only_accounts)]
                        if not wanted:
                            _trace(f"TRADE | {c.label} | none of the requested accounts are here, skipping",
                                   notify=notify)
                            continue
                        matched_any = True
                        _trace(f"TRADE | {c.label} | limited to {len(wanted)}/{len(acct_list)} account(s)",
                               notify=notify)
                        acct_list = wanted

                # Iterate destination accounts
                _consec_errors = 0  # stop after 2 consecutive errors
                for _acct_i, acct in enumerate(acct_list):
                    if _acct_i > 0:
                        await asyncio.sleep(random.uniform(1.0, 3.0))
                    if _is_cancelled(kwargs):
                        break
                    if hard_stop:
                        break
                    acct_num = acct["acctNum"]
                    acct_name = acct.get("name") or "Account"
                    acct_key = _trade_account_key(acct_name, acct_num)
                    target_id = (_digits_only(acct_num), sym)
                    if smart_sell:
                        if acct_key not in smart_targets:
                            continue
                        if target_id in processed_targets:
                            continue
                    acct_label = f"{c.label} · {acct_name} ({acct_num})"
                    _trace(f"TRADE | {acct_label} | starting ({_acct_i+1}/{len(acct_list)})", notify=notify)

                    try:
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=open_trade")
                        if smart_sell:
                            # confirmation page -> return to editable ticket for next target
                            await _click_enter_new_order_if_present(page)
                            await _open_trade_drawer_from_current_page(page)
                        else:
                            await page.get(TRADE_URL)
                            await _wait_for_trade_ticket(page, label=acct_label,
                                                         notify=notify)
                            await _ensure_expanded_ticket_mode(page, notify=notify)

                        # ------------------------------
                        # Legacy-faithful account select
                        # ------------------------------
                        # IMPORTANT: do NOT use page.evaluate(js, acct_num) due to zendriver arg mapping quirks.
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=select_account acct={acct_num}")

                        # The account dropdown lives on a React ticket that keeps
                        # re-rendering right after navigation, so a node handle
                        # grabbed a beat too early goes stale — the raw "No node
                        # with given id found" (DOM.resolveNode) that was failing
                        # every Fidelity account. Open the dropdown only when it is
                        # closed (re-clicking an open PVD menu toggles it shut), then
                        # pick the account: handle-first for real input events, then
                        # a handle-free JS *pointer* sequence (a plain .click() does
                        # NOT open a PVD dropdown — it opens on pointerdown — which is
                        # why the old b.click() fallback never recovered the trade).
                        _acct_opts_sel = '#ett-acct-sel-list div[role="option"] button'

                        async def _acct_list_open():
                            return await _element_visible(page, _acct_opts_sel)

                        _acct_selected = False
                        _acct_err: Optional[Exception] = None
                        for _sel_try in range(4):
                            try:
                                if not await _acct_list_open():
                                    await _stale_safe_click(
                                        page, "#dest-acct-dropdown",
                                        tries=2, settle_s=0.4, verify=_acct_list_open,
                                    )
                                await page.sleep(0.15)

                                opt = await page.find(f"({acct_num})", best_match=True)
                                if not opt:
                                    opt = await page.find(acct_num, best_match=True)
                                if not opt:
                                    raise RuntimeError(f"Account option not found in dropdown: {acct_num}")

                                await opt.scroll_into_view()
                                await opt.mouse_move()
                                await opt.mouse_click()
                                _acct_selected = True
                                break
                            except Exception as e:
                                _acct_err = e
                                # Stale node / mid-render — settle and retry fresh.
                                await _settle(page, sleep_s=0.5)

                        if not _acct_selected:
                            # Handle-free path: ensure the menu is open via a pointer
                            # sequence, then pointer-click the matching option.
                            if not await _acct_list_open():
                                await _js_pointer_click_selector(page, "#dest-acct-dropdown")
                                await page.sleep(0.3)
                            if await _js_click_option_by_text(
                                page, "#ett-acct-sel-list", 'div[role="option"] button', acct_num
                            ):
                                _acct_selected = True

                        if not _acct_selected:
                            raise _acct_err or RuntimeError(
                                f"Account option not found in dropdown: {acct_num}"
                            )

                        # Stabilize after selection (legacy rhythm)
                        await page.sleep(0.25)
                        try:
                            await page.wait_for_ready_state("complete", timeout=10)
                            await page.wait()
                        except Exception:
                            pass
                        await page.sleep(0.25)

                        # Extended hours toggle priority
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=extended_toggle")
                        is_extended = await _maybe_force_extended_hours(page)

                        # Enter symbol + prices
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=enter_symbol symbol={sym}")
                        prices = await _enter_symbol_and_get_prices(page, sym)
                        last_price = prices["last"]
                        bid_price = prices["bid"]
                        ask_price = prices["ask"]
                        # Traced unconditionally, not only under dry_run: the
                        # nav log used to jump from "starting (1/10)" straight to
                        # a failure 80s later with nothing in between, so there
                        # was no way to tell which step actually went wrong.
                        _trace(f"TRADE | {acct_label} | symbol {sym} "
                               f"last={last_price} bid={bid_price} ask={ask_price}",
                               notify=notify)

                        # Choose reference price like legacy
                        ref_price = 0.0
                        if side_upper == "BUY":
                            ref_price = ask_price if ask_price > 0 else last_price
                        else:
                            ref_price = bid_price if bid_price > 0 else last_price

                        # Action. Fail here rather than downstream: Order type and
                        # Quantity stay disabled until Action commits, so an
                        # unverified miss used to resurface as the confusing
                        # "Could not enter quantity" / "Limit price field not found".
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=select_action side={side_upper}")
                        _act_ok, _act_seen = await _select_action(page, side_upper)
                        _trace(f"TRADE | {acct_label} | action {side_upper} "
                               f"{'set' if _act_ok else 'FAILED'}", notify=notify)
                        if not _act_ok:
                            raise RuntimeError(
                                f"Could not set Action to {side_upper} — "
                                f"{_act_seen} — refusing to continue"
                            )

                        qty_order = str(qty_int)
                        if smart_sell and side_upper == "SELL":
                            # Step Q: focus Quantity input to reveal Sell all / Sell specific controls.
                            if dry_run:
                                log_lines.append(f"[{acct_label}] step=quantity_focus")
                            async def _qty_focused():
                                try:
                                    return bool(await page.evaluate(
                                        "(function(){return (document.activeElement&&document.activeElement.id)==='eqt-shared-quantity';})();"
                                    ))
                                except Exception:
                                    return False

                            await _stale_safe_click(page, "#eqt-shared-quantity", verify=_qty_focused)

                            # Gate Q1: quantity input truly focused.
                            focus_ok = await page.evaluate(
                                """
                                (function() {
                                    const ae = document.activeElement;
                                    if (!ae) return false;
                                    if ((ae.id || '') === 'eqt-shared-quantity') return true;
                                    const role = (ae.getAttribute && (ae.getAttribute('role') || '') || '').toLowerCase();
                                    const name = (
                                        (ae.getAttribute && (ae.getAttribute('aria-label') || ae.getAttribute('name')) || '')
                                    ).toLowerCase();
                                    return role === 'textbox' && name.includes('quantity');
                                })();
                                """
                            )
                            if not bool(focus_ok):
                                raise RuntimeError("Quantity focus gate failed (#eqt-shared-quantity not focused)")

                            # Gate Q2: Sell all / Sell specific now visible in quantity panel.
                            panel_ok = await page.evaluate(
                                """
                                (function() {
                                    const isVis = (el) => {
                                        if (!el) return false;
                                        const r = el.getBoundingClientRect();
                                        const st = window.getComputedStyle(el);
                                        return r.width > 0 && r.height > 0 && st.visibility !== 'hidden' && st.display !== 'none';
                                    };
                                    const buttons = Array.from(document.querySelectorAll('button,[role="button"]'));
                                    const norm = (s) => (s || '').trim().toLowerCase();
                                    const sellAll = buttons.find(b => norm(b.innerText || b.textContent || b.getAttribute('aria-label')) === 'sell all');
                                    const sellSpecific = buttons.find(b => norm(b.innerText || b.textContent || b.getAttribute('aria-label')) === 'sell specific');
                                    const bodyTxt = ((document.body && document.body.innerText) || '').toLowerCase();
                                    const ownedRow = bodyTxt.includes('owned') && bodyTxt.includes('shares');
                                    return {
                                        ok: !!(isVis(sellAll) && isVis(sellSpecific) && ownedRow),
                                        hasSellAll: !!isVis(sellAll),
                                        hasSellSpecific: !!isVis(sellSpecific),
                                        hasOwnedRow: !!ownedRow
                                    };
                                })();
                                """
                            )
                            if not bool((panel_ok or {}).get("ok")):
                                raise RuntimeError(
                                    "Quantity panel gate failed: sell controls not visible "
                                    f"(sell_all={bool((panel_ok or {}).get('hasSellAll'))}, "
                                    f"sell_specific={bool((panel_ok or {}).get('hasSellSpecific'))}, "
                                    f"owned_row={bool((panel_ok or {}).get('hasOwnedRow'))})"
                                )

                            # Step SA: click Sell all.
                            if dry_run:
                                log_lines.append(f"[{acct_label}] step=sell_all")
                            sell_all_btn = await page.find("Sell all", best_match=True)
                            if not sell_all_btn:
                                raise RuntimeError("Sell all button not found after quantity focus")
                            try:
                                await sell_all_btn.scroll_into_view()
                                await sell_all_btn.mouse_move()
                                await sell_all_btn.mouse_click()
                            except Exception:
                                # Handle went stale — pointer-click by text instead.
                                await _js_click_option_by_text(
                                    page, "body", 'button,[role="button"]', "Sell all"
                                )
                            qty_order = "ALL"
                            # Gate SA1: quantity should populate.
                            qty_txt = await page.evaluate(
                                """
                                (function() {
                                    const q = document.querySelector('#eqt-shared-quantity');
                                    if (!q) return '';
                                    return (q.value || q.getAttribute('value') || '').trim();
                                })();
                                """
                            )
                            if not str(qty_txt or "").strip():
                                raise RuntimeError("Sell all did not populate quantity")
                        else:
                            # Qty (standard path). Stale-safe: the raw send_keys here
                            # could throw DOM.resolveNode on the re-rendering ticket,
                            # and a silently-dropped quantity leaves the order-type
                            # control disabled -> 'Limit price field not found'.
                            if dry_run:
                                log_lines.append(f"[{acct_label}] step=set_qty qty={qty_order}")

                            async def _qty_nonempty():
                                try:
                                    v = await page.evaluate(
                                        "(function(){var q=document.querySelector('#eqt-shared-quantity');"
                                        "return q?((q.value||q.getAttribute('value')||'')+'').trim():'';})();"
                                    )
                                    return bool((v or "").strip())
                                except Exception:
                                    return False

                            if not await _stale_safe_type(
                                page, "#eqt-shared-quantity", qty_order, verify=_qty_nonempty
                            ):
                                raise RuntimeError(f"Could not enter quantity ({qty_order})")

                            # Commit the quantity: Fidelity keeps Order Type disabled
                            # until the qty field validates. send_keys alone may not
                            # fire the change/blur React listens for, which reads back
                            # as 'order type stuck on Order type'. Tab out + dispatch.
                            try:
                                from zendriver.core.keys import SpecialKeys as _SK  # type: ignore
                                q_node = await _safe_select(page, "#eqt-shared-quantity", 3)
                                if q_node is not None:
                                    await q_node.send_keys(_SK.TAB)
                            except Exception:
                                pass
                            try:
                                await page.evaluate(
                                    "(function(){var q=document.querySelector('#eqt-shared-quantity');"
                                    "if(q){q.dispatchEvent(new Event('input',{bubbles:true}));"
                                    "q.dispatchEvent(new Event('change',{bubbles:true}));"
                                    "q.dispatchEvent(new Event('blur',{bubbles:true}));}})();"
                                )
                            except Exception:
                                pass
                            await _settle(page, sleep_s=0.4)

                        # Order type rules (legacy + optional explicit override)
                        order_type = "Market"
                        limit_price: Optional[float] = None
                        if forced_order_type == "market":
                            order_type = "Market"
                        elif forced_order_type == "limit":
                            order_type = "Limit"
                            limit_price = float(forced_limit_price or 0.0)
                        else:
                            # Penny stock rule (legacy): BUY < $1 -> LIMIT
                            if ref_price > 0 and ref_price < 1.00 and side_upper == "BUY":
                                order_type = "Limit"

                            # Extended hours forces LIMIT + computed limit price
                            if is_extended:
                                order_type = "Limit"
                                base = ref_price if ref_price > 0 else last_price
                                if side_upper == "BUY":
                                    base2 = ask_price if ask_price > 0 else base
                                    limit_price = math.ceil(base2 * 100) / 100.0
                                else:
                                    base2 = bid_price if bid_price > 0 else base
                                    limit_price = math.floor(base2 * 100) / 100.0

                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=set_order_type type={order_type} ext={is_extended}")
                        await _set_order_type(page, order_type=order_type, is_extended=is_extended)

                        # Limit price input
                        limit_price_str = ""
                        if order_type == "Limit":
                            if limit_price is None:
                                limit_price = ref_price if ref_price > 0 else last_price
                            if not limit_price or float(limit_price) <= 0:
                                # Every price on the ticket read zero, so the
                                # ticket never resolved a security. A $0.00 limit
                                # is never a real order — refuse rather than send
                                # one and find out what Fidelity does with it.
                                raise RuntimeError(
                                    f"Refusing a Limit order for {sym} with no quote "
                                    f"(last={last_price} bid={bid_price} ask={ask_price})")
                            limit_price_str = _quantize_limit_price(
                                float(limit_price), side=side_upper
                            )
                            if dry_run:
                                log_lines.append(
                                    f"[{acct_label}] step=set_limit_price price={limit_price_str}"
                                )
                            await _fill_limit_price(
                                page, limit_price_str, side=side_upper, is_extended=is_extended
                            )

                        # Preview
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=preview")
                        ok_prev, err_txt = await _preview_and_check_error(page)

                        # The ticket decides how many decimals a price may carry
                        # from the security's own price tier, which we can't read
                        # off the quote block — so when it rejects the format,
                        # re-quantize to exactly what it asked for and retry once.
                        if not ok_prev and order_type == "Limit":
                            dp_wanted = _decimals_wanted_from_error(err_txt)
                            if dp_wanted is not None:
                                retry_str = _quantize_limit_price(
                                    float(limit_price), side=side_upper, max_dp=dp_wanted
                                )
                                if retry_str != limit_price_str:
                                    _trace(
                                        f"TRADE | {acct_label} | limit price {limit_price_str} "
                                        f"rejected ({dp_wanted}dp max) -> retrying at {retry_str}",
                                        notify=notify,
                                    )
                                    if dry_run:
                                        log_lines.append(
                                            f"[{acct_label}] step=retry_limit_price price={retry_str}"
                                        )
                                    try:
                                        await _fill_limit_price(
                                            page,
                                            retry_str,
                                            side=side_upper,
                                            is_extended=is_extended,
                                        )
                                        limit_price_str = retry_str
                                        ok_prev, err_txt = await _preview_and_check_error(page)
                                    except Exception as _retry_exc:
                                        err_txt = f"{err_txt} (retry at {retry_str} failed: {_retry_exc})"

                        if not ok_prev:
                            _trace(f"TRADE | {acct_label} | preview failed: {err_txt}", notify=notify)
                            outs.append(
                                AccountOutput(
                                    account_id=acct_label,
                                    ok=False,
                                    message=f"Preview failed: {err_txt}",
                                    extra={"symbol": sym, "qty": qty_order},
                                )
                            )
                            any_fail = True
                            if dry_run:
                                log_lines.append(f"[{acct_label}] ERROR: preview failed: {err_txt}")
                                log_lines.append("")
                            # Stop after 2 consecutive REFUSALS (e.g. security not
                            # allowed). A transient failure breaks the chain
                            # instead of extending it — see _is_hard_error.
                            _consec_errors = _consec_errors + 1 if _is_hard_error(err_txt) else 0
                            if _consec_errors >= 2:
                                _trace(f"TRADE | {c.label} | 2 consecutive errors, skipping remaining accounts", notify=notify)
                                for remaining_acct in acct_list[_acct_i + 1:]:
                                    r_label = f"{c.label} · {remaining_acct.get('name', 'Account')} ({remaining_acct['acctNum']})"
                                    outs.append(AccountOutput(account_id=r_label, ok=False, message=f"Skipped: {err_txt}"))
                                break
                            continue

                        if dry_run:
                            if smart_sell and side_upper == "SELL":
                                log_lines.append(f"[{acct_label}] step=test_preview_extract")
                                summary_vals = await _extract_preview_summary_for_test(page)
                                ticket = _format_smart_sell_test_message(summary_vals)
                            else:
                                ticket = (
                                    "DRY RUN — NO ORDER SUBMITTED\n"
                                    f"side: {side_upper}\n"
                                    f"symbol: {sym}\n"
                                    f"quantity: {qty_order}\n"
                                    f"order_type: {order_type}\n"
                                    f"extended_hours: {is_extended}\n"
                                    f"limit_price: {limit_price_str}\n"
                                    f"account: {acct_label}\n"
                                    f"prices: last={last_price} bid={bid_price} ask={ask_price}"
                                ).strip()

                            outs.append(AccountOutput(account_id=acct_label, ok=True, message=ticket, order_id=None))
                            any_ok = True

                            log_lines.append(f"[{acct_label}] TICKET")
                            log_lines.append(ticket)
                            log_lines.append("")
                            processed_targets.add(target_id)
                            continue

                        # LIVE submit. Stale-safe but double-submit-safe: a
                        # resolveNode failure raises BEFORE the click is dispatched
                        # (the order is NOT sent), so re-grabbing a fresh handle and
                        # retrying is safe; a successful click breaks immediately, so
                        # Place Order is never clicked twice.
                        _trace(f"TRADE | {acct_label} | submitting order", notify=notify)
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=submit")
                        _placed = False
                        for _place_try in range(3):
                            try:
                                place_btn = await page.select("#placeOrderBtn", timeout=10)
                                await place_btn.mouse_move()
                                await place_btn.mouse_click()
                                _placed = True
                                break
                            except Exception:
                                await _settle(page, sleep_s=0.5)
                        if not _placed:
                            # Every handle attempt raised before dispatching (order not
                            # sent) — click once via JS as a last resort.
                            try:
                                _placed = bool(await page.evaluate(
                                    "(function(){var b=document.querySelector('#placeOrderBtn');"
                                    "if(!b)return false;b.click();return true;})();"
                                ))
                            except Exception:
                                _placed = False
                        if not _placed:
                            raise RuntimeError("Could not click Place Order (button kept going stale)")

                        confirmed = False
                        for _ in range(50):
                            await page.sleep(0.5)
                            ok_txt = await page.evaluate(
                                """
                                (function() {
                                    const t = (document.body && document.body.innerText) ? document.body.innerText : '';
                                    return (t.includes('Order Received') || t.includes('Confirmation'));
                                })();
                                """
                            )
                            if ok_txt:
                                confirmed = True
                                break
                            u = (await _current_url(page)).lower()
                            if "confirmation" in u:
                                confirmed = True
                                break

                        msg = "order placed" if confirmed else "order submitted (verify manually)"
                        _trace(f"TRADE | {acct_label} | {msg}", notify=notify)
                        outs.append(AccountOutput(account_id=acct_label, ok=True, message=msg, order_id=None))
                        any_ok = True
                        _consec_errors = 0
                        processed_targets.add(target_id)

                    except Exception as e:
                        _trace(f"TRADE | {acct_label} | ERROR: {e}", notify=notify)
                        outs.append(AccountOutput(account_id=acct_label, ok=False, message=str(e), order_id=None))
                        any_fail = True
                        if dry_run:
                            log_lines.append(f"[{acct_label}] ERROR: {e}")
                            log_lines.append("")
                        # Only hard_stop on auth/browser-level failures, not per-account errors
                        err_str = str(e).lower()
                        if "auth" in err_str or "login" in err_str or "browser" in err_str:
                            hard_stop = True
                            break
                        _consec_errors = _consec_errors + 1 if _is_hard_error(str(e)) else 0
                        if _consec_errors >= 2:
                            _trace(f"TRADE | {c.label} | 2 consecutive errors, skipping remaining accounts", notify=notify)
                            for remaining_acct in acct_list[_acct_i + 1:]:
                                r_label = f"{c.label} · {remaining_acct.get('name', 'Account')} ({remaining_acct['acctNum']})"
                                outs.append(AccountOutput(account_id=r_label, ok=False, message=f"Skipped: {e}"))
                            break

            except Exception as e:
                outs.append(AccountOutput(account_id=c.label, ok=False, message=str(e), order_id=None))
                any_fail = True
                if dry_run:
                    log_lines.append(f"[{c.label}] ERROR: {e}")
                    log_lines.append("")
            finally:
                try:
                    if browser is not None:
                        await _close_browser(browser, notify=notify)
                except Exception:
                    pass

        if _is_cancelled(kwargs):
            state = "partial" if any_ok else "failed"
        else:
            state = "success" if any_ok and not any_fail else ("partial" if any_ok and any_fail else "failed")

        if only_accounts and not matched_any:
            outs.append(AccountOutput(
                account_id="Fidelity", ok=False,
                message=f"None of the requested accounts were found: {sorted(only_accounts)}"))
            state = "failed"

        if smart_sell and (not any_ok) and (not any_fail) and not outs:
            outs.append(AccountOutput(account_id="Fidelity", ok=False, message=f"Smart Sell: no matching destination accounts for {sym}"))
            state = "failed"

        msg = "Cancelled" if _is_cancelled(kwargs) else ""
        if dry_run:
            try:
                log_path = _write_dry_run_log(content="\n".join(log_lines).rstrip() + "\n")
                msg = f"DRY RUN — NO ORDER SUBMITTED | log: {log_path}"
                if _is_cancelled(kwargs):
                    msg = f"{msg} | Cancelled"
            except Exception:
                msg = "DRY RUN — NO ORDER SUBMITTED"

        return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)

    return _run_coro(lambda: _run_all(), timeout_s=1800)


def healthcheck(*args, **kwargs) -> BrokerOutput:
    """
    Probe-only healthchecks are unreliable for UI/profile brokers.
    Legacy behavior is: positions/trade rehydrate inline using the persistent profile.
    """
    return BrokerOutput(
        broker=BROKER,
        state="failed",
        accounts=[AccountOutput(account_id="Fidelity", ok=False, message="Probe unsupported. Run positions/trade to authenticate inline.")],
        message="Probe unsupported",
    )
