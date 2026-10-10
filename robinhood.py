# modules/brokers/robinhood/robinhood.py
from __future__ import annotations

import builtins
import contextlib
import functools
import getpass
import io
import inspect
import logging
import os
import random
import shutil
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from modules.outputs import BrokerOutput, AccountOutput, HoldingRow
from modules import _2fa_prompt
from modules._2fa_prompt import universal_2fa_prompt
from modules import broker_logging as BLOG
from modules import http_timeouts

BROKER = "robinhood"

_RH: Any = None
_QUOTE_UNSUPPORTED: set[str] = set()

# [(display_label, account_number, login_pickle_name)]
_ACCOUNTS: List[Tuple[str, str, str]] = []
#: (login name, why) for each login whose session came back but whose account
#: list could not be read in the last _ensure_session. Trades and holdings
#: report a failed row per entry so the run is partial, not a quiet success.
_LOGIN_LOAD_FAILURES: List[Tuple[str, str]] = []

_ET = ZoneInfo("America/New_York")

#: robin_stocks keeps ONE requests.Session for the whole process, and a login
#: works by writing that login's token into its Authorization header. With two
#: logins, "rehydrate login 2, then read login 1's positions" from two threads
#: reads (or trades) under the wrong token. Every public entry point holds this
#: for its whole run, so each login+call pair sees its own token. Always taken
#: BEFORE _INPUT_PATCH_LOCK, never after, so the two cannot deadlock.
_SESSION_LOCK = threading.RLock()


#: How long a call waits for another Robinhood call to finish. Bounded: a
#: wedged login (or a stuck read) used to queue every later trade behind it
#: with no end, and the app's watchdog wrote the whole broker off.
_SESSION_LOCK_WAIT_S = 900.0


def _serialized(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not _SESSION_LOCK.acquire(timeout=_SESSION_LOCK_WAIT_S):
            msg = (f"Robinhood is still busy with another request after "
                   f"{int(_SESSION_LOCK_WAIT_S)}s — nothing was sent")
            return BrokerOutput(broker=BROKER, state="failed", message=msg,
                                accounts=[AccountOutput(account_id="Robinhood",
                                                        ok=False, message=msg)])
        try:
            return fn(*args, **kwargs)
        finally:
            _SESSION_LOCK.release()
    return wrapper

for _lname in ("robin_stocks", "urllib3", "requests"):
    try:
        logging.getLogger(_lname).setLevel(logging.CRITICAL)
    except Exception:
        pass


@contextlib.contextmanager
def _suppress_console_noise():
    """
    Silence noisy third-party prints/log spam from robin_stocks internals.

    Do NOT catch here. The old version yielded a second time from an
    ``except Exception`` handler, so any error raised inside a
    ``with _suppress_console_noise():`` block was thrown into the generator,
    swallowed, and re-yielded — which makes contextlib raise
    ``RuntimeError: generator didn't stop after throw()`` and discards the real
    exception. Every Robinhood failure came back as that meaningless message.
    The redirect context managers already restore stdout/stderr on the way out.
    """
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
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


class _Tee:
    """Write-through stream: keeps the real console working while recording."""

    def __init__(self, real, buf, on_text=None):
        self._real = real
        self._buf = buf
        self._on_text = on_text

    def write(self, s):
        try:
            self._buf.write(s)
        except Exception:
            pass
        # Watch the stream as it is written, not after. The whole point is to
        # react while the library is still blocked waiting for the user.
        if self._on_text is not None and s:
            try:
                self._on_text(s)
            except Exception:
                pass
        try:
            if self._real is not None:
                self._real.write(s)
        except Exception:
            pass
        return len(s) if s else 0

    def flush(self):
        try:
            if self._real is not None:
                self._real.flush()
        except Exception:
            pass

    def isatty(self):
        try:
            return bool(self._real is not None and self._real.isatty())
        except Exception:
            return False


@contextlib.contextmanager
def _capture_console(buf, on_text=None):
    """Tee stdout/stderr into ``buf`` without hiding them.

    robin_stocks reports the whole verification handshake through print() —
    "Starting verification process...", "Check robinhood app for device
    approvals method...", "Login failed. Check credentials and try again."
    Under pythonw there is no console, so every one of those messages was lost
    and a failed login looked like a silent hang. Tee (never redirect) so a
    terminal run still shows prompts live while the GUI run gets a transcript.

    ``on_text`` sees each chunk as it is written, which is what lets the device
    approval reach the user while the login is still waiting on it.
    """
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout = _Tee(old_out, buf, on_text)
    sys.stderr = _Tee(old_err, buf, on_text)
    try:
        yield
    finally:
        sys.stdout, sys.stderr = old_out, old_err


# =============================================================================
# Device-approval alert
# =============================================================================
#
# Re-login pushes a device approval to the phone and then BLOCKS polling for the
# answer — robin_stocks' prompt branch is `while True:` with no timeout, so a
# push nobody notices is not an error, it is a run that never ends. The only
# announcement the library makes is a print(), which under pythonw goes nowhere.
# Watching the teed stream is the only place to catch it while it still matters.

DEVICE_APPROVAL_MESSAGE = (
    "Robinhood sent a device-approval request to the Robinhood app on your "
    "phone. Open the app and tap Approve to finish signing in."
)

# What robin_stocks prints when it sends the push. Matched case-insensitively.
_DEVICE_APPROVAL_PATTERNS = (
    "check robinhood app for device approvals",
    "device approvals method",
    "check robinhood app",
)

_device_approval_hook: Optional[Callable[[str], None]] = None


def set_device_approval_hook(fn: Optional[Callable[[str], None]]) -> None:
    """Register a callback fired when Robinhood pushes a device approval.

    Called ON THE LOGIN THREAD, from inside a print(), while the login is
    stalled — so the callback must not block and must not call back into this
    module. Pass None to unregister.
    """
    global _device_approval_hook
    _device_approval_hook = fn


def _device_approval_watcher() -> Callable[[str], None]:
    """A console watcher that fires the hook once, on the first push."""
    state = {"fired": False, "tail": ""}

    def _watch(chunk: str) -> None:
        if state["fired"] or not chunk:
            return
        # Match on a rolling tail: the library prints in pieces, so the phrase
        # can straddle two writes and be in neither of them.
        state["tail"] = (state["tail"] + chunk)[-400:]
        low = state["tail"].lower()
        if not any(p in low for p in _DEVICE_APPROVAL_PATTERNS):
            return
        state["fired"] = True
        fn = _device_approval_hook
        if fn is None:
            return
        try:
            fn(DEVICE_APPROVAL_MESSAGE)
        except Exception:
            # A broken listener must never take down a login that is already
            # mid-handshake.
            pass

    return _watch


def _log_login_transcript(pickle_name: str, text: str, secrets: Optional[List[Any]] = None) -> None:
    try:
        BLOG.write_log(
            _log_ctx(),
            broker=BROKER,
            action="bootstrap",
            label="login_transcript",
            filename_prefix="bootstrap_login",
            text=f"profile={pickle_name}\n--- robin_stocks console ---\n{text or '(no output)'}",
            secrets=secrets,
        )
    except Exception:
        pass


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
    except Exception as e:
        return None, f"Missing dependency: robin-stocks ({e})"
    _harden_session(rh)
    return rh, None


#: Login threads _run_login_bounded gave up on. Their next request through
#: robin_stocks' session raises, which ends the thread instead of leaving it
#: polling Robinhood (and burning the rate limit) for the rest of the session.
_ABANDONED_LOGIN_THREADS: set = set()


def _harden_session(rh) -> None:
    """Bound robin_stocks' shared requests.Session.

    request_get passes no timeout at all, so one stalled socket hung a
    holdings read -- or a login, inside _INPUT_PATCH_LOCK -- indefinitely.
    Also lets an abandoned login thread be stopped at its next request.
    Idempotent; never raises.
    """
    try:
        helper = getattr(rh, "helper", None)
        sess = getattr(helper, "SESSION", None)
        if sess is None:
            sess = getattr(getattr(rh, "globals", None), "SESSION", None)
        if sess is None:
            return
        http_timeouts.patch_session(sess)
        if getattr(sess, "_rsa_login_guard", False):
            return
        inner = sess.request

        def request(*args, **kwargs):
            if threading.get_ident() in _ABANDONED_LOGIN_THREADS:
                raise RuntimeError("Robinhood login was abandoned (it timed out)")
            return inner(*args, **kwargs)

        sess.request = request
        sess._rsa_login_guard = True
    except Exception:
        pass


#: How long one interactive Robinhood login may take, device approval
#: included. robin_stocks polls the approval with `while True`, so without a
#: bound an approval that never comes holds _INPUT_PATCH_LOCK forever.
_LOGIN_TIMEOUT_S = 600.0


#: The login failure for a code prompt the user cancelled or let time out.
_CODE_NOT_ENTERED = "Robinhood code not entered — login failed, nothing was sent"


def _run_login_bounded(login_fn: Callable[..., Any], call_kwargs: Dict[str, Any],
                       timeout_s: Optional[float] = None) -> Any:
    """Call robin_stocks' login() in a worker thread and wait at most timeout_s.

    On timeout the thread is marked abandoned (see _harden_session) and this
    raises, so the caller releases the input patch and reports a failure the
    user can retry. Nothing here places an order.
    """
    limit = float(_LOGIN_TIMEOUT_S if timeout_s is None else timeout_s)
    box: Dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = login_fn(**call_kwargs)
        except BaseException as e:      # noqa: BLE001 -- handed to the caller
            box["exc"] = e
        finally:
            # Thread idents are reused once a thread ends.
            _ABANDONED_LOGIN_THREADS.discard(threading.get_ident())

    t = threading.Thread(target=target, name="robinhood-login", daemon=True)
    t.start()
    t.join(limit)
    if t.is_alive():
        if t.ident is not None:
            _ABANDONED_LOGIN_THREADS.add(t.ident)
            if not t.is_alive():        # ended in between: don't strand the id
                _ABANDONED_LOGIN_THREADS.discard(t.ident)
        raise RuntimeError(
            f"Robinhood login did not finish within {int(limit)}s (the device "
            f"approval or code never came through) — run the login again")
    if "exc" in box:
        raise box["exc"]
    return box.get("result")


def _get_login_callable(rh):
    auth = getattr(rh, "authentication", None)
    login_fn = getattr(auth, "login", None) if auth else None
    if callable(login_fn):
        return login_fn
    login_fn = getattr(rh, "login", None)
    if callable(login_fn):
        return login_fn
    return None


# =============================================================================
# Which accounts an order may touch
# =============================================================================

# Individual + Roth IRA + traditional IRA. The joint account is excluded by
# _is_joint_account below, so this bounds what is left: a fourth funded account
# appearing on its own is a surprise, and surprises should not be traded
# automatically. Override with ROBINHOOD_MAX_TRADE_ACCOUNTS (0 = no limit).
#
# PER LOGIN. Counted across every login, a household's second login (three
# more accounts of its own) was cut off entirely as "over the limit".
_DEFAULT_MAX_TRADE_ACCOUNTS = 3


def _max_trade_accounts() -> int:
    raw = _env("ROBINHOOD_MAX_TRADE_ACCOUNTS")
    if not raw:
        return _DEFAULT_MAX_TRADE_ACCOUNTS
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_MAX_TRADE_ACCOUNTS


def _is_joint_account(display_label: str) -> bool:
    """True for a joint account, which must never be traded.

    It holds no cash, so Robinhood rejects every order sent to it — and a
    rejection arrives as an ordinary return value, not an exception, so those
    rejections were being recorded as fills. Matched on the account TYPE, which
    the label carries verbatim ('joint_tenancy_with_ros'), so it survives the
    account being replaced by another joint one. Trading only; holdings still
    cover every account.
    """
    return "joint" in (display_label or "").lower()


def _order_rejection(resp: Any) -> str:
    """Why Robinhood refused this order — '' when it accepted it.

    robin_stocks does NOT raise on a rejected order. request_post treats 400,
    401, 402 and 403 as acceptable status codes and hands back the error body,
    so a refusal reaches the caller looking exactly like a success. Trusting
    "no exception" is what booked a filled buy into a joint account holding no
    cash: order_id came back null, which a real order never does.
    """
    if resp is None:
        return "no response from Robinhood (the request failed)"
    if not isinstance(resp, dict):
        return f"unexpected response from Robinhood: {type(resp).__name__}"

    oid = str(resp.get("id") or "").strip()
    state = str(resp.get("state") or "").strip().lower()

    if oid and state not in ("rejected", "cancelled", "canceled", "failed"):
        # Accepted. Whether it FILLS is a separate question — this only says
        # Robinhood took the order.
        return ""

    if oid:
        reason = str(resp.get("reject_reason")
                     or resp.get("cancel_reason") or "").strip()
        return f"order {state}" + (f": {reason}" if reason else "")

    # No id means an error body. Quote Robinhood rather than inventing a reason.
    for key in ("detail", "error", "message"):
        val = resp.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:300]
    for key, val in resp.items():
        if isinstance(val, list) and val and all(isinstance(x, str) for x in val):
            return f"{key}: {'; '.join(val)}"[:300]
    return "Robinhood returned no order id, so nothing was placed"


def _safe_load_accounts(rh) -> List[Dict[str, Any]]:
    """
    Legacy used: rh.account.load_account_profile(dataType="results")
    Use that first; fallback if needed.

    RAISES when the read itself failed. It used to swallow the error and
    return [], so a read timeout on login 2 left that login's accounts out of
    the run with nothing said, and the trade reported success.
    """
    first_err: Optional[BaseException] = None
    for mod_name in ("account", "profiles"):
        fn = getattr(getattr(rh, mod_name, None), "load_account_profile", None)
        if not callable(fn):
            continue
        try:
            with _suppress_console_noise():
                rows = fn(dataType="results") or []
            return rows if isinstance(rows, list) else []
        except Exception as e:
            first_err = first_err or e
    if first_err is not None:
        raise RuntimeError(
            f"could not load the account list ({type(first_err).__name__}: {first_err})"
        ) from first_err
    return []


def _safe_open_positions(rh, *, account_number: str) -> List[Dict[str, Any]]:
    """The account's open positions. RAISES when the read failed.

    It used to return [] for every failure, and so does robin_stocks:
    request_get answers an HTTP error with [None], which filter_data turns
    into [] -- exactly what an account holding nothing returns. A 401 or 429
    therefore read as "holds no stock", which the exits board and auto-sell
    take as "already sold". So the positions URL is fetched through the
    library's own request_get, where the [None] marker is still visible.
    Library builds without that seam fall back to get_open_stock_positions.
    """
    helper = getattr(rh, "helper", None)
    urls = getattr(rh, "urls", None)
    req = getattr(helper, "request_get", None)
    purl = getattr(urls, "positions_url", None)
    if callable(req) and callable(purl):
        with _suppress_console_noise():
            data = req(purl(account_number=account_number), "pagination",
                       {"nonzero": "true"})
        if not isinstance(data, list) or data == [None]:
            raise RuntimeError("Robinhood positions read failed (Robinhood "
                               "returned an error) — holdings unknown")
        return [row for row in data if isinstance(row, dict)]

    for owner in (getattr(rh, "account", None), rh):
        fn = getattr(owner, "get_open_stock_positions", None)
        if callable(fn):
            with _suppress_console_noise():
                rows = fn(account_number=account_number)
            if not isinstance(rows, list):
                raise RuntimeError("Robinhood positions read failed (no "
                                   "positions in the reply) — holdings unknown")
            return rows
    raise RuntimeError("this robin-stocks build has no positions read")


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

# robin_stocks asks for the MFA code by calling input() from inside its own
# login(), so the only way to answer it is to stand in front of builtins.input.
# That is fine as long as it is done under a lock.
#
# IT WAS NOT. Two places here swapped builtins.input out (the rehydrate guard
# below and bootstrap's login stub) and brokers bootstrap CONCURRENTLY, so a
# rehydrate running inside a bootstrap produced this:
#
#     rehydrate : saved = <real input>  ; installed _blocked
#     bootstrap : saved = _blocked      ; installed the login stub
#     rehydrate : restored <real input>
#     bootstrap : restored _blocked      <-- left installed, for the session
#
# From then on every module in the process that called input() got _blocked,
# which RAISES. That is what stopped Fidelity ever showing its OTP box: the
# RuntimeError escaped its provider and came back as a bare "auth failed" while
# the texted code sat unused on the user's phone. See modules/_2fa_prompt.py.
#
# One lock, held for the whole patch, and every restore goes back to what was
# genuinely there. Non-Robinhood modules ask through modules._2fa_prompt now
# and never touch builtins at all.
_INPUT_PATCH_LOCK = threading.RLock()


@contextlib.contextmanager
def _intercept_input(handler: Callable[[str], str]):
    """Answer robin_stocks' interactive prompts with `handler`, safely."""
    with _INPUT_PATCH_LOCK:
        orig_input = builtins.input
        orig_getpass = getpass.getpass
        builtins.input = handler          # type: ignore[assignment]
        getpass.getpass = handler         # type: ignore[assignment]
        try:
            yield
        finally:
            builtins.input = orig_input
            getpass.getpass = orig_getpass  # type: ignore[assignment]


def _block_interactive_prompts(*, context: str):
    """
    Prevent silent hangs when robin_stocks falls back to interactive input().

    A rehydrate is meant to be non-interactive: it either refreshes the cached
    token or it does not. Being asked for a password here means the pickle is
    dead, and saying so immediately beats blocking a background refresh on a
    dialog the user never asked for.
    """
    def _blocked(prompt: str = "") -> str:
        prompt_txt = str(prompt or "").strip()
        hint = f" Prompt={prompt_txt!r}" if prompt_txt else ""
        raise RuntimeError(
            f"Robinhood requested interactive input during {context}.{hint} "
            "Cached session appears expired/corrupt."
        )

    return _intercept_input(_blocked)


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
                result = login_fn(**call_kwargs)
        if result is None:
            # robin_stocks reports a failed login by printing "Login failed"
            # and returning None, never by raising.
            raise RuntimeError("robin_stocks login() returned no session")
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


def _account_display(profiles: List[Tuple[str, str, str]], pickle_name: str,
                     base_label: str) -> str:
    """The account_id an account is traded and journaled under.

    LOGIN 1 NEVER MOVES. It used to gain a "Robinhood 1 | " prefix the moment
    a second login was added, and trades.json nets buys against sells on this
    exact string -- so adding a login orphaned every open position at the
    first. Only logins 2 and up carry the prefix that tells them apart.
    """
    if profiles and pickle_name == profiles[0][0]:
        return base_label
    return f"{pickle_name} | {base_label}"


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


@_serialized
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

    _code_skipped = {"v": False}

    def _login_prompt(prompt: str = "") -> str:
        """Answer whatever robin_stocks asks for during the login.

        Its text goes through verbatim, because the ask is not always the MFA
        code -- a device-approval flow says "check your Robinhood app", and a
        prompt relabelled by a library upgrade should still reach the user
        rather than being guessed at here.

        RAISES when the user cancels or the prompt times out. It used to
        return "", and robin_stocks does not treat an empty code as an error:
        its challenge loop re-POSTs it every 5 seconds until its own two-minute
        window runs out -- two dozen wrong codes, a lockout risk.
        """
        text = str(prompt or "").strip() or universal_2fa_prompt("Robinhood")
        answer = _2fa_prompt.request_text("Robinhood", text, 300)
        if answer is None or not str(answer).strip():
            # robin_stocks catches this, prints it and returns None; the flag
            # lets the caller say why instead of "did not accept the sign-in".
            _code_skipped["v"] = True
            raise RuntimeError(_CODE_NOT_ENTERED)
        return str(answer)

    # ExitStack rather than a `with` block: the interception has to cover the
    # whole login body, and wrapping it would reindent a hundred lines for no
    # behavioural gain. Closing the stack in the existing `finally` restores
    # builtins.input exactly as the context manager would.
    _prompts = contextlib.ExitStack()
    try:
        _prompts.enter_context(_intercept_input(_login_prompt))

        # Build accounts by logging each profile (legacy-style, one pickle per profile)
        merged_accounts: List[Tuple[str, str, str]] = []
        seen_numbers = set()
        load_failures: List[Tuple[str, str]] = []

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

            # login (OTP happens here if needed — _login_prompt answers it)
            #
            # The console is teed to a transcript log unconditionally. It used
            # to be skipped whenever an OTP provider was set, which was dead
            # weather: the provider was hard-wired to None, so the branch never
            # ran either way. Under pythonw there is no console at all, and the
            # transcript is the only record of which challenge Robinhood
            # actually issued — that is exactly when it is worth having.
            _console = io.StringIO()
            try:
                with _capture_console(_console, on_text=_device_approval_watcher()):
                    # Bounded: an approval that never comes must not hold
                    # _INPUT_PATCH_LOCK (taken above) for the whole session.
                    result = _run_login_bounded(login_fn, call_kwargs)
            finally:
                _log_login_transcript(pickle_name, _console.getvalue(),
                                      secrets=[username, password])
            if result is None and _code_skipped["v"]:
                raise RuntimeError(f"{pickle_name}: {_CODE_NOT_ENTERED}")
            if result is None:
                # robin_stocks does not raise on a refused login: it prints
                # "Login failed" and returns None. Rehydrating anyway reported
                # the misleading "cached session is invalid" instead, or --
                # with an older pickle still on disk -- "Login ok".
                raise RuntimeError(
                    f"{pickle_name}: Robinhood did not accept the sign-in (wrong "
                    f"password, a declined approval, or a rate limit) — wait a "
                    f"few minutes before trying again")

            # immediately rehydrate from the cache (exact legacy habit)
            login_with_cache(rh=rh, pickle_name=pickle_name)

            try:
                rows = _safe_load_accounts(rh)
            except Exception as e:
                # This login signed in but its account list could not be
                # read: fail THIS login only (as _ensure_session does), not
                # every login that bootstrapped fine before or after it.
                load_failures.append((pickle_name, str(e)))
                continue
            for a in rows:
                acct = (a.get("account_number") or "").strip()
                if not acct or acct in seen_numbers:
                    continue
                seen_numbers.add(acct)

                acct_type = (a.get("brokerage_account_type") or a.get("type") or "ACCOUNT").strip()
                base_label = f"{acct_type} (****{acct[-4:]})"

                display = _account_display(profiles, pickle_name, base_label)

                merged_accounts.append((display, acct, pickle_name))

        if load_failures and not merged_accounts:
            raise RuntimeError("; ".join(f"{n}: could not read its accounts ({w})"
                                         for n, w in load_failures))

        _RH = rh
        _ACCOUNTS = merged_accounts

        fail_rows = [AccountOutput(account_id=n, ok=False,
                                   message=f"{n}: signed in, but its accounts could not be read ({w})")
                     for n, w in load_failures]
        return BrokerOutput(
            broker=BROKER,
            state="partial" if fail_rows else "success",
            accounts=[AccountOutput(account_id="Robinhood", ok=True, message=f"Login ok ({len(_ACCOUNTS)} accounts)")]
                     + fail_rows,
            message="Login ok" if not fail_rows else f"Login ok ({len(fail_rows)} login(s) need attention)",
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
        _prompts.close()


def _ensure_session() -> Tuple[bool, str]:
    """
    Legacy mimic:
      - If pickle exists -> call login_with_cache() -> proceed
      - If not -> require interactive bootstrap to create it
    """
    global _RH, _ACCOUNTS, _LOGIN_LOAD_FAILURES

    _LOGIN_LOAD_FAILURES = []
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

            try:
                rows = _safe_load_accounts(rh)
            except Exception as e:
                # This login's accounts are unknown, not absent: report it
                # (see _login_load_failure_rows) and go on with the others.
                _LOGIN_LOAD_FAILURES.append((pickle_name, str(e)))
                continue
            for a in rows:
                acct = (a.get("account_number") or "").strip()
                if not acct or acct in seen_numbers:
                    continue
                seen_numbers.add(acct)

                acct_type = (a.get("brokerage_account_type") or a.get("type") or "ACCOUNT").strip()
                base_label = f"{acct_type} (****{acct[-4:]})"

                display = _account_display(profiles, pickle_name, base_label)

                merged_accounts.append((display, acct, pickle_name))

        _RH = rh
        _ACCOUNTS = merged_accounts

        if not _ACCOUNTS:
            # If we rehydrated but still got no accounts, treat as auth failure.
            why = "; ".join(f"{n}: {w}" for n, w in _LOGIN_LOAD_FAILURES)
            raise RuntimeError("Rehydrated session but loaded zero accounts (token invalid / expired)."
                               + (f" {why}" if why else ""))

        return True, "rehydrated"

    except Exception as e:
        _RH = None
        _ACCOUNTS = []
        _LOGIN_LOAD_FAILURES = []
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

def _login_load_failure_rows(**extra: Any) -> List[AccountOutput]:
    """One failed row per login whose account list could not be read. Only
    ever built before any order for that login: nothing was sent for it."""
    return [AccountOutput(account_id=name, ok=False,
                          message=f"{name}: {why} — its accounts were not traded, nothing was sent",
                          **extra)
            for name, why in (_LOGIN_LOAD_FAILURES or [])]


@_serialized
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
    outs: List[AccountOutput] = _login_load_failure_rows(holdings=[])

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


def _accepts(fn, names) -> bool:
    """True when `fn` takes every keyword in `names` (or **kwargs)."""
    import inspect
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return True
    return all(n in params for n in names)


@_serialized
def execute_trade(*, side: str, qty: str, symbol: str, dry_run: bool = False) -> BrokerOutput:
    ok, why = _ensure_session()
    if not ok:
        # No session: no order request was made.
        row = why if "nothing was sent" in (why or "").lower() else f"{why} — nothing was sent"
        return BrokerOutput(
            broker=BROKER,
            state="failed",
            accounts=[AccountOutput(account_id="Robinhood", ok=False, message=row)],
            message=why,
        )

    rh = _RH

    side_norm = (side or "").lower().strip()
    if side_norm not in ("buy", "sell"):
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid side: {side!r}")

    sym = (symbol or "").upper().strip()
    if not sym:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message="Invalid symbol")

    # Float, not int.
    #
    # Robinhood is one of the three brokers that actually HOLD fractions (see
    # rsa_feed.FRACTIONAL_BROKERS), so a reverse split routinely leaves it with
    # 0.1 of a share to sell. int(float("0.1")) is 0, which failed the guard
    # below and returned "Invalid qty" without ever reaching an order — making
    # the broker most likely to be holding a fraction the only one of the three
    # that could never sell one. Public keeps a Decimal and SoFi keeps a float;
    # this was the odd one out.
    try:
        q_f = float(qty)
        if q_f <= 0:
            raise ValueError
    except Exception:
        return BrokerOutput(broker=BROKER, state="failed", accounts=[], message=f"Invalid qty: {qty!r}")

    # A whole number stays an int, so every order that works today is submitted
    # byte-for-byte as it is now and only the fractional case takes a new path.
    fractional = abs(q_f - round(q_f)) > 1e-9
    q = q_f if fractional else int(round(q_f))

    outs: List[AccountOutput] = _login_load_failure_rows()

    log_lines: List[str] = []
    if dry_run:
        log_lines.append("DRY RUN — NO ORDER SUBMITTED")
        log_lines.append(f"broker: {BROKER}")
        log_lines.append(f"time_et: {datetime.now(_ET).isoformat()}")
        log_lines.append(f"requested: side={side_norm.upper()} symbol={sym} qty={q}")
        log_lines.append("")

    # Prefer legacy-style obj.order() if present; fallback to order_buy_market/order_sell_market
    orders_obj = getattr(rh, "orders", None)

    def _rh_fn(name: str):
        """A robin-stocks helper, wherever this build keeps it.

        The library has exposed these on the module and on its `orders`
        submodule at different versions, and the existing lookup for `order`
        already had to try both — this just gives the other helpers the same
        treatment instead of a second copy of it.
        """
        f = getattr(rh, name, None)
        if not callable(f) and orders_obj is not None:
            f = getattr(orders_obj, name, None)
        return f if callable(f) else None

    order_fn = _rh_fn("order")

    # Decide which accounts this order may touch before sending anything.
    # Skipped accounts are deliberately kept OUT of `outs`: they are not
    # failures, and counting them as such would report every run as "partial".
    # They are named in the message instead, so nothing disappears silently.
    tradable: List[Tuple[str, str, str]] = []
    skipped: List[Tuple[str, str]] = []
    for entry in (_ACCOUNTS or []):
        if _is_joint_account(entry[0]):
            skipped.append((entry[0], "joint account — never traded"))
            continue
        tradable.append(entry)

    # The cap applies to each login separately (entry[2] is its pickle name).
    _cap = _max_trade_accounts()
    if _cap:
        per_login: Dict[str, int] = {}
        kept: List[Tuple[str, str, str]] = []
        for entry in tradable:
            n = per_login.get(entry[2], 0)
            if n >= _cap:
                skipped.append((entry[0], f"over the {_cap}-account limit"))
                continue
            per_login[entry[2]] = n + 1
            kept.append(entry)
        tradable = kept

    skip_note = ""
    if skipped:
        skip_note = "skipped " + ", ".join(f"{lbl} ({why})" for lbl, why in skipped)
        if dry_run:
            for lbl, why in skipped:
                log_lines.append(f"[{lbl}] SKIPPED — {why}")
            log_lines.append("")

    if not tradable:
        # A row, not accounts=[]: with no rows the app counted no failure and
        # the run read as a quiet success. Nothing was sent.
        msg = "No tradable Robinhood accounts" + (f" — {skip_note}" if skip_note else "")
        return BrokerOutput(broker=BROKER, state="failed", message=msg,
                            accounts=[AccountOutput(account_id="Robinhood", ok=False,
                                                    message=msg)])

    for _acct_i, (display_label, acct_num, pickle_name) in enumerate(tradable):
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
                f"order_type: {'MARKET (fractional)' if fractional else 'MARKET'}\n"
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

            if fractional:
                # A fraction has to go through the fractional endpoint. The
                # ordinary market order rejects a quantity below one share, so
                # falling back to it here would turn a working sell into an API
                # error rather than a filled order.
                frac_fn = _rh_fn(f"order_{side_norm}_fractional_by_quantity")
                if frac_fn is None:
                    raise RuntimeError(
                        f"this robin-stocks build has no "
                        f"order_{side_norm}_fractional_by_quantity, so {q} of a "
                        f"share cannot be traded"
                    )
                resp = frac_fn(sym, q, account_number=acct_num, timeInForce="gfd")
            else:
                # Only a missing order() or a signature mismatch may fall back
                # to the market helper — in both cases nothing was sent. A None
                # from a real call is NOT "nothing was sent": request_post
                # swallows timeouts, 5xx and non-JSON bodies and returns None
                # even when Robinhood took the order, so retrying through the
                # market helper there could place it twice.
                # Which call shape this robin-stocks build takes is decided
                # BEFORE anything is sent, from its signature. Catching a
                # TypeError from the call itself and falling through to the
                # market helper was a duplicate-order path: a TypeError raised
                # inside the library after its POST would have sent a second
                # order through the helper.
                use_market = not (callable(order_fn) and _accepts(
                    order_fn, ("symbol", "quantity", "side", "account_number",
                               "timeInForce")))
                if not use_market:
                    resp = order_fn(
                        symbol=sym,
                        quantity=q,
                        side=side_norm,
                        account_number=acct_num,
                        timeInForce="gfd",
                    )
                else:
                    # Fallback: market helpers. Their timeInForce defaults to
                    # "gtc"; every order this app sends is a day order, which
                    # is what the auto-sell order holds assume.
                    fn = _rh_fn(f"order_{side_norm}_market")
                    if fn is None:
                        raise RuntimeError("Robinhood market order function not "
                                           "available — nothing was sent")
                    if not _accepts(fn, ("timeInForce",)):
                        # Without timeInForce robin_stocks sends "gtc": an order
                        # that outlives the day, which the auto-sell holds
                        # (AUTOSELL_DAY_ORDER_BROKERS) assume never happens.
                        # Refuse before anything is sent; the except below adds
                        # "— nothing was sent".
                        raise RuntimeError("Robinhood helper can't send a day order")
                    resp = fn(sym, q, account_number=acct_num, timeInForce="gfd")

            if resp is None:
                # Every order path above has actually been called by now, so
                # silence is ambiguous, not a rejection. Say so in words the
                # app reads as "order may exist" and never auto-retries.
                outs.append(AccountOutput(
                    account_id=display_label, ok=False,
                    message=("Robinhood gave no response — the order may have been "
                             "submitted; verify in Robinhood before retrying"),
                ))
                continue

            # Check what came back. robin_stocks returns a rejection instead of
            # raising one, so "no exception" is not evidence an order exists.
            if resp is not None and not isinstance(resp, dict):
                # Something came back from the order POST that we can't read.
                # Not proof of a refusal: treat like a lost response.
                outs.append(AccountOutput(
                    account_id=display_label, ok=False,
                    message=("Robinhood's reply could not be read — the order may have "
                             "been submitted; verify in Robinhood before retrying"),
                ))
                continue

            rejection = _order_rejection(resp)
            if rejection:
                outs.append(AccountOutput(account_id=display_label, ok=False,
                                          message=f"order rejected: {rejection}"))
                if dry_run:
                    log_lines.append(f"[{display_label}] REJECTED: {rejection}")
                    log_lines.append("")
                continue

            oid = resp.get("id") if isinstance(resp, dict) else None
            outs.append(AccountOutput(account_id=display_label, ok=True, message="order placed", order_id=oid))

        except Exception as e:
            # Every order path above goes through robin_stocks' request_post,
            # which catches everything and returns None (handled above as
            # "may have been submitted"). So an exception reaching here was
            # raised before the order POST -- the session reload, the quote
            # lookup inside order() (IndexError on no quote), a missing
            # helper: nothing was sent.
            outs.append(AccountOutput(account_id=display_label, ok=False,
                                      message=f"{e} — nothing was sent"))

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
    if skip_note:
        msg = f"{msg} | {skip_note}" if msg else skip_note

    return BrokerOutput(broker=BROKER, state=state, accounts=outs, message=msg)


@_serialized
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

                display = _account_display(profiles, pickle_name, base_label)

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
