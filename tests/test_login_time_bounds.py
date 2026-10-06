"""Login / navigation waits are bounded, and an abandoned attempt can't touch
another login's browser profile.

The hang class: zendriver's page.get() (or any CDP call) that never returns.
Unbounded, it held a broker's slot until the app was restarted. Every test here
uses a fake that hangs on purpose, with the bounds shrunk to fractions of a
second. No browser, no network.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import chase
import fidelity
import sofi
import wellsfargo

# Mirrors app._ORDER_MAY_EXIST (app.py is a GUI module; not imported here).
_ORDER_MAY_EXIST = ("submitted", "placed", "accepted", "pending", "queued",
                    "working", "order id", "confirmation", "verify")


class _HangingPage:
    """page.get() never returns (until the test process ends)."""

    def __init__(self):
        self.gets = []

    async def get(self, url):
        self.gets.append(url)
        await asyncio.Event().wait()

    async def sleep(self, *_a):
        pass

    async def wait_for_ready_state(self, *_a, **_k):
        pass

    async def wait(self, *_a, **_k):
        pass

    async def evaluate(self, *_a, **_k):
        return ""


def _blocking_hang(seconds=3.0):
    """A coroutine factory whose coroutine blocks its THREAD — the kind of hang
    asyncio cancellation can't unwind; only a join() backstop gets past it."""
    async def _coro():
        time.sleep(seconds)
        return "too late"
    return _coro


# =============================================================================
# Fidelity: _run_coro honours timeout_s (it used to asyncio.run() inline)
# =============================================================================

def test_fidelity_run_coro_is_bounded_from_a_plain_thread():
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        fidelity._run_coro(_blocking_hang(), timeout_s=0.3)
    assert time.monotonic() - t0 < 2.0


def test_fidelity_run_coro_still_returns_and_raises():
    async def ok():
        return 42

    async def boom():
        raise ValueError("nope")

    assert fidelity._run_coro(ok, timeout_s=5) == 42
    with pytest.raises(ValueError, match="nope"):
        fidelity._run_coro(boom, timeout_s=5)


def test_fidelity_nav_is_bounded(monkeypatch):
    monkeypatch.setattr(fidelity, "NAV_TIMEOUT_S", 0.2)
    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)
    page = _HangingPage()
    t0 = time.monotonic()
    with pytest.raises(fidelity.NavTimeout, match="did not load within"):
        asyncio.run(fidelity._goto(page, fidelity.LOGIN_URL, "LOGIN"))
    assert time.monotonic() - t0 < 2.0
    assert page.gets == [fidelity.LOGIN_URL]


def test_fidelity_goto_still_swallows_ordinary_nav_errors(monkeypatch):
    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)

    class _Page(_HangingPage):
        async def get(self, url):
            raise ConnectionError("net::ERR_ABORTED")

    asyncio.run(fidelity._goto(_Page(), fidelity.SUMMARY_URL, "LOGIN"))  # no raise


def test_fidelity_hung_trade_is_bounded_and_plain_when_no_click(monkeypatch):
    """A trade that outlives its budget returns (it used to never return). This
    one hung before any Place Order click (at browser start), so it must read
    as a plain, retryable failure — none of the app's "order may exist" words."""
    seen = {}

    async def _hang_start(*_a, **_k):
        await asyncio.sleep(1.5)
        raise RuntimeError("abandoned run reached the browser")

    real_run_coro = fidelity._run_coro

    def _short_run_coro(factory, *, timeout_s):
        seen["timeout_s"] = timeout_s
        return real_run_coro(factory, timeout_s=0.3)

    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)
    monkeypatch.setattr(fidelity, "_load_creds", lambda: [fidelity._LoginCred(
        idx_1based=1, label="Fidelity 1", username="u", password="p", totp_secret="")])
    monkeypatch.setattr(fidelity, "_start_browser_for_login", _hang_start)
    monkeypatch.setattr(fidelity, "_run_coro", _short_run_coro)

    t0 = time.monotonic()
    out = fidelity.execute_trade(side="buy", qty="1", symbol="ABC")
    assert time.monotonic() - t0 < 2.0
    assert seen["timeout_s"] == 1800  # one login: the original 30 min
    assert out.state == "failed"
    msg = out.accounts[0].message.lower()
    assert "timed out" in msg
    assert not [w for w in _ORDER_MAY_EXIST if w in msg], msg
    time.sleep(1.5)  # let the orphan finish before monkeypatch teardown


def test_fidelity_close_browser_kills_the_pinned_profile(monkeypatch, tmp_path):
    killed = []
    monkeypatch.setattr(fidelity, "cleanup_orphaned_chrome", lambda p: killed.append(Path(p)))
    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)
    monkeypatch.setattr(fidelity.asyncio, "sleep", _instant_sleep)

    class _B:
        tabs = []

        async def stop(self):
            pass

    b = _B()
    b._fidelity_idx = 1
    b._fidelity_profile_dir = str(tmp_path / "pinned")
    asyncio.run(fidelity._close_browser(b))
    assert killed == [tmp_path / "pinned"]


_real_sleep = asyncio.sleep


async def _instant_sleep(*_a, **_k):
    await _real_sleep(0)


# =============================================================================
# Wells Fargo: cleanup uses the profile captured at start
# =============================================================================

def test_wf_close_browser_kills_the_pinned_profile_not_the_active_login(monkeypatch, tmp_path):
    """The orphaned attempt finishes AFTER broker_logins moved to login 2. Its
    cleanup must kill its own Chrome, not login 2's."""
    killed = []
    monkeypatch.setattr(wellsfargo, "cleanup_orphaned_chrome", lambda p: killed.append(Path(p)))
    monkeypatch.setattr(wellsfargo.asyncio, "sleep", _instant_sleep)
    # The "current" login is now someone else.
    monkeypatch.setattr(wellsfargo, "_profile_dir", lambda: tmp_path / "login2" / "profile")

    class _B:
        tabs = []

        async def stop(self):
            pass

    b = _B()
    b._wf_profile_dir = str(tmp_path / "login1" / "profile")
    asyncio.run(wellsfargo._close_browser(b))
    assert killed == [tmp_path / "login1" / "profile"]


def _wf_hung_dispatch(monkeypatch, *, clicked, dry_run=False):
    seen = {}

    real_run_coro = wellsfargo._run_coro

    def _short(factory, *, timeout_s):
        return real_run_coro(factory, timeout_s=0.3)

    async def _hang(ctx):
        seen["ctx"] = ctx
        if clicked:
            ctx["_clicked"] = True  # what _cmd_trade does right before the click
        await asyncio.sleep(1.0)
        return None

    monkeypatch.setattr(wellsfargo, "_trace", lambda *a, **k: None)
    monkeypatch.setattr(wellsfargo, "_run_coro", _short)
    monkeypatch.setattr(wellsfargo, "_cmd_trade", _hang)
    monkeypatch.setattr(wellsfargo, "_build_ctx", lambda kw: {
        "username": "u", "password": "p", "cancel_event": None, "dry_run": dry_run})

    out = wellsfargo._dispatch("trade", timeout_s=1200, side="buy", qty="1", symbol="ABC")
    time.sleep(1.0)  # let the orphan finish before monkeypatch teardown
    return out, seen


def test_wf_hung_trade_after_click_says_verify_and_stops_the_orphan(monkeypatch):
    out, seen = _wf_hung_dispatch(monkeypatch, clicked=True)
    msg = out.accounts[0].message.lower()
    assert out.state == "failed"
    assert "submitted" in msg and "verify" in msg
    assert wellsfargo._is_cancelled_ctx(seen["ctx"]) is True


def test_wf_hung_trade_before_any_click_is_plain(monkeypatch):
    out, seen = _wf_hung_dispatch(monkeypatch, clicked=False)
    msg = out.accounts[0].message.lower()
    assert out.state == "failed"
    assert "timed out" in msg
    assert not [w for w in _ORDER_MAY_EXIST if w in msg], msg
    assert wellsfargo._is_cancelled_ctx(seen["ctx"]) is True


def test_wf_hung_dry_run_never_says_verify(monkeypatch):
    out, _ = _wf_hung_dispatch(monkeypatch, clicked=True, dry_run=True)
    msg = out.accounts[0].message.lower()
    assert not [w for w in _ORDER_MAY_EXIST if w in msg], msg


# =============================================================================
# Chase: both attempts share ONE deadline
# =============================================================================

@pytest.fixture
def chase_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CHASE_USERNAME", "someone")
    monkeypatch.setenv("CHASE_PASSWORD", "pw")
    monkeypatch.setattr(chase, "_stage", lambda *a, **k: None)
    monkeypatch.setattr(chase, "_set_cookies", lambda c: None)
    monkeypatch.setattr(chase, "_clear_cookies", lambda: None)
    monkeypatch.setattr(chase, "_default_headless", lambda: True)
    monkeypatch.setattr(chase, "_profile_dir", lambda: tmp_path / "chase1" / "profile")
    return tmp_path


def test_chase_hung_attempt_is_bounded_and_not_retried_headed(monkeypatch, chase_env):
    calls = []

    async def _hang(*_a, headless_override=None, **_k):
        calls.append(headless_override)
        time.sleep(2.0)  # uncancellable
        return {}

    monkeypatch.setattr(chase, "_async_login", _hang)
    monkeypatch.setattr(chase, "LOGIN_ATTEMPT_TIMEOUT_S", 0.3)
    monkeypatch.setattr(chase, "LOGIN_TOTAL_TIMEOUT_S", 5.0)
    monkeypatch.setattr(chase, "LOGIN_RETRY_MIN_S", 0.1)

    t0 = time.monotonic()
    out = chase.ensure_session()
    assert time.monotonic() - t0 < 1.5
    assert out.state == "failed"
    assert "did not finish" in out.message
    assert calls == [True]  # a hang is not a 2FA failure: no headed retry


def test_chase_headed_retry_gets_only_what_is_left(monkeypatch, chase_env):
    calls = []

    async def _login(*_a, headless_override=None, profile_dir=None, **_k):
        calls.append((headless_override, profile_dir))
        if headless_override:
            raise RuntimeError("2FA needs a visible browser")
        time.sleep(2.0)  # the headed retry hangs too
        return {}

    monkeypatch.setattr(chase, "_async_login", _login)
    monkeypatch.setattr(chase, "LOGIN_ATTEMPT_TIMEOUT_S", 5.0)
    monkeypatch.setattr(chase, "LOGIN_TOTAL_TIMEOUT_S", 0.5)
    monkeypatch.setattr(chase, "LOGIN_RETRY_MIN_S", 0.1)

    t0 = time.monotonic()
    out = chase.ensure_session()
    # Total stays inside the ONE shared deadline, not 2 x per-attempt.
    assert time.monotonic() - t0 < 1.5
    assert out.state == "failed"
    assert [h for h, _ in calls] == [True, False]
    # Both attempts ran on the profile pinned when ensure_session started.
    assert {p for _, p in calls} == {chase_env / "chase1" / "profile"}


def test_chase_skips_headed_retry_when_too_little_time_left(monkeypatch, chase_env):
    calls = []

    async def _login(*_a, headless_override=None, **_k):
        calls.append(headless_override)
        raise RuntimeError("2FA needs a visible browser")

    monkeypatch.setattr(chase, "_async_login", _login)
    monkeypatch.setattr(chase, "LOGIN_RETRY_MIN_S", 10_000)
    out = chase.ensure_session()
    assert out.state == "failed"
    assert calls == [True]


def test_chase_successful_retry_still_succeeds(monkeypatch, chase_env):
    async def _login(*_a, headless_override=None, **_k):
        if headless_override:
            raise RuntimeError("2FA needs a visible browser")
        return {"cookie": "v"}

    monkeypatch.setattr(chase, "_async_login", _login)
    out = chase.ensure_session()
    assert out.state == "success"


# =============================================================================
# SoFi: per-attempt thread + shared deadline; bounded login navigation
# =============================================================================

@pytest.fixture
def sofi_env(monkeypatch, tmp_path):
    monkeypatch.setenv("SOFI_USERNAME", "someone")
    monkeypatch.setenv("SOFI_PASSWORD", "pw")
    monkeypatch.setattr(sofi.BLOG, "write_log", lambda *a, **k: None)
    monkeypatch.setattr(sofi.BLOG, "log_exception", lambda *a, **k: None)
    monkeypatch.setattr(sofi, "_headless_default", lambda: True)
    monkeypatch.setattr(sofi, "_profile_dir", lambda: tmp_path / "sofi1" / "profile")
    monkeypatch.setattr(sofi, "_save_cookies_to_disk", lambda c: None)
    return tmp_path


def test_sofi_hung_login_is_bounded(monkeypatch, sofi_env):
    calls = []

    async def _hang(*_a, headless_override=None, profile_dir=None, **_k):
        calls.append((headless_override, profile_dir))
        time.sleep(2.0)  # uncancellable
        return {}

    monkeypatch.setattr(sofi, "_async_login", _hang)
    monkeypatch.setattr(sofi, "LOGIN_HEADLESS_TIMEOUT_S", 0.3)
    monkeypatch.setattr(sofi, "LOGIN_TOTAL_TIMEOUT_S", 0.7)
    monkeypatch.setattr(sofi, "LOGIN_RETRY_MIN_S", 0.1)

    t0 = time.monotonic()
    out = sofi._rehydrate_session()
    assert time.monotonic() - t0 < 1.5  # it used to wait forever
    assert out.state == "failed"
    assert "did not finish" in out.message
    # Headless, then a headed retry inside the remaining budget, both on the
    # profile pinned at the start.
    assert [h for h, _ in calls] == [True, False]
    assert {p for _, p in calls} == {sofi_env / "sofi1" / "profile"}


def test_sofi_no_headed_retry_without_time_for_a_human(monkeypatch, sofi_env):
    calls = []

    async def _login(*_a, headless_override=None, **_k):
        calls.append(headless_override)
        raise RuntimeError("bot check")

    monkeypatch.setattr(sofi, "_async_login", _login)
    monkeypatch.setattr(sofi, "LOGIN_RETRY_MIN_S", 10_000)
    out = sofi._rehydrate_session()
    assert out.state == "failed"
    assert calls == [True]


def test_sofi_headed_retry_success_sets_session(monkeypatch, sofi_env):
    async def _login(*_a, headless_override=None, **_k):
        if headless_override:
            raise RuntimeError("bot check")
        return {"cookie": "v"}

    monkeypatch.setattr(sofi, "_async_login", _login)
    monkeypatch.setattr(sofi, "_csrf_from_cookies", lambda c: "csrf")
    monkeypatch.setattr(sofi, "_COOKIES", None)
    monkeypatch.setattr(sofi, "_CSRF", None)
    out = sofi._rehydrate_session()
    assert out.state == "success"
    assert sofi._COOKIES == {"cookie": "v"}


def test_sofi_login_page_nav_is_bounded(monkeypatch, sofi_env):
    monkeypatch.setattr(sofi, "LOGIN_NAV_TIMEOUT_S", 0.2)
    page = _HangingPage()
    t0 = time.monotonic()
    with pytest.raises(RuntimeError, match="did not load within"):
        asyncio.run(sofi._force_login_flow(
            None, page, username="u", password="p", totp_secret="",
            otp_provider=None, headless=True))
    assert time.monotonic() - t0 < 2.0


def test_sofi_backend_auth_poll_survives_a_hung_nav(monkeypatch, sofi_env):
    monkeypatch.setattr(sofi, "LOGIN_NAV_TIMEOUT_S", 0.1)

    async def _cookies(_b):
        return {"x": "y"}

    monkeypatch.setattr(sofi, "_cookies_from_browser", _cookies)
    monkeypatch.setattr(sofi, "_auth_sanity_check", lambda c: None)
    out = asyncio.run(sofi._wait_until_backend_auth(None, _HangingPage(), timeout_s=10))
    assert out == {"x": "y"}
