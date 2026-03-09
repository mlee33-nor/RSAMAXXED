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
from pathlib import Path
from queue import Queue
from threading import Thread
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
    # legacy naming, but inside Idle Markets sessions/
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
    url = (await _current_url(page)).lower()
    if not url:
        return False
    if "prgw/digital/login" in url or "login/full-page" in url:
        return False
    if "ftgw/digital/portfolio/summary" in url:
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
        return True

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

            # Hard rule: never show Fidelity cash sweep
            if symbol == "FCASH":
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


async def _enter_symbol_and_get_prices(page, symbol: str) -> Dict[str, float]:
    """
    Legacy DOM parsing: last/bid/ask.
    """
    from zendriver.core.keys import SpecialKeys  # type: ignore

    symbol_input = await page.select("#eq-ticket-dest-symbol", timeout=10)
    await symbol_input.send_keys(symbol)
    await symbol_input.send_keys(SpecialKeys.ENTER)

    await page.wait_for("#ett-more-less-quote-link", timeout=10)
    await _settle(page, sleep_s=0.5)

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


async def _select_action(page, action_upper: str) -> None:
    # open dropdown
    dd = await page.select("#dest-dropdownlist-button-action", timeout=10)
    await dd.scroll_into_view()
    await dd.mouse_move()
    await dd.mouse_click()

    if action_upper == "BUY":
        opt = await page.select("#Action0", timeout=10)
        await opt.scroll_into_view()
        await opt.mouse_move()
        await opt.mouse_click()
    else:
        opt = await page.select("#Action1", timeout=10)
        await opt.scroll_into_view()
        await opt.mouse_move()
        await opt.mouse_click()


async def _set_order_type(page, *, order_type: str, is_extended: bool) -> None:
    dd = await page.select("#dest-dropdownlist-button-ordertype", timeout=10)
    await dd.mouse_move()
    await dd.mouse_click()

    if order_type == "Limit":
        target_id = await page.evaluate(
            """
            (function() {
                const options = document.querySelectorAll('div[role="option"]');
                for (const opt of options) {
                    if ((opt.innerText || '').trim() === 'Limit') return opt.id;
                }
                return null;
            })();
            """
        )
        if target_id:
            opt = await page.select(f"#{target_id}", timeout=10)
            if opt:
                await opt.mouse_click()
                return

        fallback_id = "#Order-type0" if is_extended else "#Order-type1"
        opt = await page.select(fallback_id, timeout=10)
        if opt:
            await opt.mouse_click()
        return

    # Market default
    opt = await page.select("#Order-type0", timeout=10)
    await opt.mouse_click()


async def _preview_and_check_error(page) -> Tuple[bool, str]:
    # click preview
    preview = await page.select("#previewOrderBtn", timeout=10)
    await preview.mouse_move()
    await preview.mouse_click()

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
                # Count sub-accounts from any existing positions CSV
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
                    await page.select("#previewOrderBtn", timeout=15)
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

                # Iterate destination accounts
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
                            await page.select("#previewOrderBtn", timeout=15)
                            await _ensure_expanded_ticket_mode(page, notify=notify)

                        # ------------------------------
                        # Legacy-faithful account select
                        # ------------------------------
                        # IMPORTANT: do NOT use page.evaluate(js, acct_num) due to zendriver arg mapping quirks.
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=select_account acct={acct_num}")

                        dd = await page.select("#dest-acct-dropdown", timeout=10)
                        await dd.scroll_into_view()
                        await dd.mouse_move()
                        await dd.mouse_click()

                        # Hard wait for list container
                        await page.select("#ett-acct-sel-list", timeout=10)
                        await page.sleep(0.15)

                        opt = await page.find(f"({acct_num})", best_match=True)
                        if not opt:
                            opt = await page.find(acct_num, best_match=True)
                        if not opt:
                            raise RuntimeError(f"Account option not found in dropdown: {acct_num}")

                        await opt.scroll_into_view()
                        await opt.mouse_move()
                        await opt.mouse_click()

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

                        # Choose reference price like legacy
                        ref_price = 0.0
                        if side_upper == "BUY":
                            ref_price = ask_price if ask_price > 0 else last_price
                        else:
                            ref_price = bid_price if bid_price > 0 else last_price

                        # Action
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=select_action side={side_upper}")
                        await _select_action(page, side_upper)

                        qty_order = str(qty_int)
                        if smart_sell and side_upper == "SELL":
                            # Step Q: focus Quantity input to reveal Sell all / Sell specific controls.
                            if dry_run:
                                log_lines.append(f"[{acct_label}] step=quantity_focus")
                            qty_input = await page.select("#eqt-shared-quantity", timeout=10)
                            await qty_input.scroll_into_view()
                            await qty_input.mouse_move()
                            await qty_input.mouse_click()

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
                            await sell_all_btn.scroll_into_view()
                            await sell_all_btn.mouse_move()
                            await sell_all_btn.mouse_click()
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
                            # Qty (standard path)
                            if dry_run:
                                log_lines.append(f"[{acct_label}] step=set_qty qty={qty_order}")
                            qty_input = await page.select("#eqt-shared-quantity", timeout=10)
                            try:
                                await qty_input.clear_input()
                            except Exception:
                                pass
                            await qty_input.send_keys(qty_order)

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
                        if order_type == "Limit":
                            if dry_run:
                                log_lines.append(f"[{acct_label}] step=set_limit_price")
                            limit_input = await page.select("#eqt-mts-limit-price", timeout=10)
                            await limit_input.mouse_click()
                            await limit_input.focus()
                            try:
                                await limit_input.clear_input_by_deleting()
                            except Exception:
                                pass
                            if limit_price is None:
                                limit_price = ref_price if ref_price > 0 else last_price
                            await limit_input.send_keys(str(limit_price))
                            try:
                                await page.mouse_click(0, 0)
                            except Exception:
                                pass

                        # Preview
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=preview")
                        ok_prev, err_txt = await _preview_and_check_error(page)
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
                            # If same error for all accounts, skip remaining
                            if _acct_i == 0 and "not available" in (err_txt or "").lower():
                                _trace(f"TRADE | {c.label} | symbol not tradeable, skipping remaining accounts", notify=notify)
                                for remaining_acct in acct_list[1:]:
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
                                    f"limit_price: {limit_price if limit_price is not None else ''}\n"
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

                        # LIVE submit
                        _trace(f"TRADE | {acct_label} | submitting order", notify=notify)
                        if dry_run:
                            log_lines.append(f"[{acct_label}] step=submit")
                        place_btn = await page.select("#placeOrderBtn", timeout=10)
                        await place_btn.mouse_move()
                        await place_btn.mouse_click()

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
