"""Handing a parked browser window back to the user.

In background mode a headed broker browser is parked off-screen with no
taskbar button. SoFi's human check and a Chase code typed into the page both
need the user's hands in that window, so quiet.reveal_browser() undoes the
parking and _2fa_prompt.notify_user() says so in the app. No real window is
touched here: every Win32 call is replaced with a recorder.
"""
from __future__ import annotations

import types

import pytest

from modules import _2fa_prompt
from modules import quiet


@pytest.fixture(autouse=True)
def _clean_revealed():
    with quiet._revealed_lock:
        quiet._revealed.clear()
    yield
    with quiet._revealed_lock:
        quiet._revealed.clear()


@pytest.fixture
def windows(monkeypatch):
    """Pretend to be Windows in background mode, with two browser windows."""
    shown = []
    monkeypatch.setattr(quiet, "IS_WINDOWS", True)
    monkeypatch.setenv("RSA_BACKGROUND", "true")
    monkeypatch.setattr(quiet, "_process_tree", lambda pid: {pid, pid + 1})
    monkeypatch.setattr(quiet, "_top_level_windows",
                        lambda pids, include_hidden=False: [101, 202])
    monkeypatch.setattr(quiet, "_show_window",
                        lambda hwnd: shown.append(hwnd) or True)
    return shown


def test_reveal_shows_every_browser_window(windows):
    browser = types.SimpleNamespace(_process_pid=4242)
    assert quiet.reveal_browser(browser) is True
    assert windows == [101, 202]
    assert quiet._is_revealed(4242)


def test_reveal_accepts_a_raw_pid(windows):
    assert quiet.reveal_browser(4242) is True
    assert quiet._is_revealed(4242)


def test_reveal_is_a_no_op_outside_background_mode(windows, monkeypatch):
    # RSA_BACKGROUND=false: the window was never parked, so nothing to undo.
    monkeypatch.setenv("RSA_BACKGROUND", "false")
    assert quiet.reveal_browser(4242) is False
    assert windows == []


def test_reveal_without_a_pid_does_nothing(windows):
    assert quiet.reveal_browser(types.SimpleNamespace()) is False
    assert quiet.reveal_browser(None) is False
    assert windows == []


def test_reveal_never_raises(monkeypatch):
    monkeypatch.setattr(quiet, "IS_WINDOWS", True)
    monkeypatch.setenv("RSA_BACKGROUND", "true")

    def boom(*_a, **_k):
        raise OSError("user32 went away")

    monkeypatch.setattr(quiet, "_process_tree", boom)
    assert quiet.reveal_browser(4242) is False


def test_tame_loop_leaves_a_revealed_browser_alone(monkeypatch):
    """A reveal inside the tame loop's window must not be re-parked."""
    parked = []
    monkeypatch.setattr(quiet, "_process_tree", lambda pid: {pid})
    monkeypatch.setattr(quiet, "_top_level_windows", lambda pids: [101])
    monkeypatch.setattr(quiet, "_park_window",
                        lambda hwnd: parked.append(hwnd) or True)
    with quiet._revealed_lock:
        quiet._revealed.add(4242)
    quiet._tame_loop(4242, seconds=5.0)  # returns at once, not after 5s
    assert parked == []


class _User32:
    """Records the calls _show_window makes, in order."""

    def __init__(self, *, iconic=False, foreground_ok=True):
        self.calls = []
        self._iconic = iconic
        self._fg = foreground_ok

    def __getattr__(self, name):
        def _call(*args):
            self.calls.append((name, args))
            if name == "IsIconic":
                return self._iconic
            if name == "SetForegroundWindow":
                return self._fg
            return 1
        return _call


def _fake_win32(user32):
    ctypes = types.SimpleNamespace(windll=types.SimpleNamespace(user32=user32))
    wintypes = types.SimpleNamespace(HWND=lambda v: v)
    return lambda: (ctypes, wintypes)


def test_show_window_brings_it_on_screen_and_in_front(monkeypatch):
    user32 = _User32()
    taskbar = []
    monkeypatch.setattr(quiet, "_win32", _fake_win32(user32))
    monkeypatch.setattr(quiet, "_work_area", lambda: (0, 0, 1366, 728))
    monkeypatch.setattr(quiet, "_set_taskbar_button",
                        lambda hwnd, present: taskbar.append((hwnd, present)))

    assert quiet._show_window(101) is True

    names = [n for n, _ in user32.calls]
    assert ("ShowWindow", (101, 5)) in user32.calls          # SW_SHOW
    # Moved onto the work area, sized to fit a small laptop screen.
    first_pos = next(a for n, a in user32.calls if n == "SetWindowPos")
    hwnd, _after, x, y, w, h, _flags = first_pos
    assert (x, y) == (40, 40)
    assert x >= 0 and y >= 0
    assert w <= 1366 - 80 and h <= 728 - 80
    assert taskbar == [(101, True)]                          # AddTab, not DeleteTab
    assert "SetForegroundWindow" in names
    assert "FlashWindow" not in names


def test_show_window_restores_a_minimised_window(monkeypatch):
    user32 = _User32(iconic=True)
    monkeypatch.setattr(quiet, "_win32", _fake_win32(user32))
    monkeypatch.setattr(quiet, "_work_area", lambda: (0, 0, 1920, 1040))
    monkeypatch.setattr(quiet, "_set_taskbar_button", lambda *a, **k: None)
    quiet._show_window(101)
    assert ("ShowWindow", (101, 9)) in user32.calls          # SW_RESTORE


def test_show_window_flashes_when_focus_is_refused(monkeypatch):
    user32 = _User32(foreground_ok=False)
    monkeypatch.setattr(quiet, "_win32", _fake_win32(user32))
    monkeypatch.setattr(quiet, "_work_area", lambda: (0, 0, 1920, 1040))
    monkeypatch.setattr(quiet, "_set_taskbar_button", lambda *a, **k: None)
    assert quiet._show_window(101) is True
    assert ("FlashWindow", (101, True)) in user32.calls


# --- the in-app notice ------------------------------------------------------

@pytest.fixture
def notices():
    seen = {"show": [], "clear": []}
    _2fa_prompt.set_notice_hooks(
        lambda b, t, m: seen["show"].append((b, t, m)),
        lambda b: seen["clear"].append(b),
    )
    yield seen
    _2fa_prompt.set_notice_hooks(None, None)


def test_notify_user_reaches_the_registered_hook(notices, capsys):
    _2fa_prompt.notify_user("SoFi", "Finish the check", "tick the box")
    _2fa_prompt.clear_notice("SoFi")
    assert notices["show"] == [("SoFi", "Finish the check", "tick the box")]
    assert notices["clear"] == ["SoFi"]
    # Still printed, for CLI runs.
    assert "tick the box" in capsys.readouterr().out


def test_a_broken_notice_hook_never_breaks_the_login():
    def boom(*_a):
        raise RuntimeError("UI gone")

    _2fa_prompt.set_notice_hooks(boom, boom)
    try:
        _2fa_prompt.notify_user("Chase", "t", "m")
        _2fa_prompt.clear_notice("Chase")
    finally:
        _2fa_prompt.set_notice_hooks(None, None)


def test_no_hook_registered_is_fine():
    _2fa_prompt.set_notice_hooks(None, None)
    _2fa_prompt.notify_user("Chase", "t", "m")
    _2fa_prompt.clear_notice("Chase")
