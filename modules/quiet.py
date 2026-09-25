"""Keep the automation off the user's screen.

WHY THIS EXISTS
---------------
A single buy wakes up every linked broker, and four of them (Chase, Fidelity,
SoFi, Wells Fargo) drive a real Chrome. On a purchaser's PC that used to look
like the machine had been taken over: black console windows flashing open and
shut, and Chrome windows appearing on top of whatever they were doing. Two
different leaks, two different fixes.

1. CONSOLE WINDOWS. The app runs under ``pythonw`` (see RSAMAXXED.bat), which
   has no console of its own. On Windows, starting a *console* program from a
   process that has no console makes the OS allocate a brand new one -- a black
   window that pops to the front, steals focus and closes a second later. Every
   browser start called ``subprocess.run(["powershell", ...])`` to sweep up
   orphaned Chrome, so a 4-broker buy flashed at least four windows.
   ``run()``/``popen()`` below pass CREATE_NO_WINDOW + SW_HIDE, which is the
   documented way to say "run it, but never give it a console".

2. BROWSER WINDOWS. Headless Chrome is already invisible, and Chase, Fidelity
   and SoFi default to it. But some logins can only be done headed (Wells
   Fargo's sign-on stalls headless; Chase and SoFi retry headed when a headless
   login hits a human check), and a headed Chrome is a real window on the real
   desktop. ``browser_args()`` parks it far off the visible desktop and
   ``tame_windows()`` strips its taskbar button and keeps it at the bottom of
   the z-order. Off-screen rather than hidden is deliberate: Chrome stops
   compositing a window it believes nobody can see, which breaks the
   screenshot-based diagnostics the browser brokers rely on. Set
   RSA_BROWSER_HIDE=true to trade those away for a truly hidden window.

Set RSA_BACKGROUND=false to watch everything happen, which is what you want
when debugging a broker by eye.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

IS_WINDOWS = sys.platform == "win32"

# Far enough off the desktop that no monitor arrangement can show it, but still
# a real, rendering window as far as Chrome is concerned.
OFFSCREEN_X = -32000
OFFSCREEN_Y = -32000


def _flag(name: str, default: bool) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw not in ("0", "false", "no", "off")


def background_mode() -> bool:
    """True when the automation must stay invisible (the shipped default)."""
    return _flag("RSA_BACKGROUND", True)


def hide_browser_windows() -> bool:
    """Opt in to really hiding browser windows, not just parking them.

    Off by default: a hidden window gets no frames from Chrome, so the
    screenshots SoFi and Fidelity read to spot a human-check wall come back
    blank or time out.
    """
    return background_mode() and _flag("RSA_BROWSER_HIDE", False)


# =============================================================================
# Subprocesses that must not flash a console
# =============================================================================

CREATE_NO_WINDOW = 0x08000000


def no_window_kwargs() -> Dict[str, Any]:
    """subprocess kwargs that suppress the console window on Windows."""
    if not IS_WINDOWS:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": CREATE_NO_WINDOW, "startupinfo": si}


def run(cmd: Sequence[str], **kwargs: Any):
    """subprocess.run that never shows a window."""
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(list(cmd), **no_window_kwargs(), **kwargs)


def popen(cmd: Sequence[str], **kwargs: Any):
    """subprocess.Popen that never shows a window."""
    return subprocess.Popen(list(cmd), **no_window_kwargs(), **kwargs)


def open_path(path: Any) -> bool:
    """Show a file to the user in whatever app owns it, without a shell.

    The old ``Popen(["start", "", path], shell=True)`` route went through
    cmd.exe, which is a console program -- so asking to look at a CAPTCHA image
    opened a black window too. os.startfile talks to the shell directly.
    """
    p = str(path)
    try:
        if IS_WINDOWS:
            os.startfile(p)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            popen(["open", p])
        else:
            popen(["xdg-open", p])
        return True
    except Exception:
        return False


# =============================================================================
# Chrome command line
# =============================================================================

# Chrome throttles -- or stops rendering entirely -- a window it thinks the user
# cannot see. Ours is parked off-screen on purpose, so switch that logic off or
# automation waits start timing out.
_ANTI_THROTTLE_FLAGS = (
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-background-timer-throttling",
)
_ANTI_THROTTLE_DISABLED_FEATURES = ("CalculateNativeWinOcclusion",)

_DEFAULT_WINDOW_SIZE = "1400,1000"


def _merge_disable_features(args: List[str]) -> List[str]:
    """Collapse every --disable-features into one.

    Chrome keeps a single value per switch, so a second --disable-features
    silently throws away the first one. Broker modules already pass their own
    (TranslateUI, IsolateOrigins, ...) and this module needs to add to it, so
    the values have to be merged rather than appended.
    """
    values: List[str] = []
    first_at = -1
    out: List[str] = []
    for arg in args:
        if arg.startswith("--disable-features="):
            if first_at < 0:
                first_at = len(out)
                out.append("")  # placeholder, filled in below
            for part in arg.split("=", 1)[1].split(","):
                part = part.strip()
                if part and part not in values:
                    values.append(part)
        else:
            out.append(arg)
    if first_at >= 0:
        out[first_at] = "--disable-features=" + ",".join(values)
    return out


def browser_args(
    args: Iterable[str],
    *,
    headless: bool,
    background: Optional[bool] = None,
) -> List[str]:
    """Finish a broker's Chrome command line for background operation.

    Headless is already invisible, so it only gets the --disable-features
    merge. A headed browser is parked off-screen and told not to throttle.
    `background=False` hands the list back untouched -- that is the "let me
    watch it" path (WELLSFARGO_OFFSCREEN=false, RSA_BACKGROUND=false).
    """
    out = [a for a in args]
    if background is None:
        background = background_mode()

    if not headless and background:
        # A maximized window is the opposite of what we want.
        out = [a for a in out if a != "--start-maximized"]
        out = [a for a in out if not a.startswith("--window-position=")]
        out.append("--window-position=%d,%d" % (OFFSCREEN_X, OFFSCREEN_Y))
        if not any(a.startswith("--window-size=") for a in out):
            out.append("--window-size=" + _DEFAULT_WINDOW_SIZE)
        for flag in _ANTI_THROTTLE_FLAGS:
            if flag not in out:
                out.append(flag)
        out.append("--disable-features=" + ",".join(_ANTI_THROTTLE_DISABLED_FEATURES))

    return _merge_disable_features(out)


# =============================================================================
# Taming the window Chrome opens anyway
# =============================================================================

def browser_pid(browser: Any) -> Optional[int]:
    """The pid of the Chrome zendriver started, if it is still knowable."""
    pid = getattr(browser, "_process_pid", None)
    if isinstance(pid, int) and pid > 0:
        return pid
    proc = getattr(browser, "_process", None)
    pid = getattr(proc, "pid", None)
    return pid if isinstance(pid, int) and pid > 0 else None


def tame_windows(target: Any, *, seconds: float = 20.0) -> None:
    """Keep a headed browser's windows out of sight, in the background.

    Accepts a zendriver browser or a raw pid. Returns immediately: Chrome's
    window does not exist yet when uc.start() returns, and it can be replaced
    later (a crash-restore, a new profile window), so the work happens on a
    daemon thread that keeps checking for a while.

    Entirely best-effort. Every failure is swallowed -- the worst case is a
    taskbar button, never a broken login.
    """
    if not IS_WINDOWS or not background_mode():
        return
    pid = target if isinstance(target, int) else browser_pid(target)
    if not pid:
        return
    t = threading.Thread(
        target=_tame_loop, args=(int(pid), float(seconds)),
        name="quiet-windows-%d" % int(pid), daemon=True,
    )
    t.start()


def _tame_loop(pid: int, seconds: float) -> None:
    deadline = time.time() + seconds
    handled = set()
    while time.time() < deadline:
        try:
            pids = _process_tree(pid)
            for hwnd in _top_level_windows(pids):
                if hwnd in handled:
                    continue
                if _park_window(hwnd):
                    handled.add(hwnd)
        except Exception:
            return
        time.sleep(0.4)


# --- Win32 plumbing ---------------------------------------------------------

def _win32():
    import ctypes
    from ctypes import wintypes
    return ctypes, wintypes


def _process_tree(root: int) -> set:
    """`root` plus everything it spawned.

    Chrome normally keeps the window on the process we started, but it does
    hand off to a relaunched browser process in some situations, and then the
    window belongs to a child. Walked with the toolhelp API rather than a WMI
    query, because a WMI query would mean another subprocess.
    """
    pids = {root}
    try:
        ctypes, wintypes = _win32()

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260),
            ]

        k32 = ctypes.windll.kernel32
        snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
        if snap in (-1, 0xFFFFFFFF, None):
            return pids
        try:
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            parents: Dict[int, int] = {}
            ok = k32.Process32First(snap, ctypes.byref(entry))
            while ok:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                ok = k32.Process32Next(snap, ctypes.byref(entry))
        finally:
            k32.CloseHandle(snap)
        # Walk each process upward to see whether our pid is one of its
        # ancestors. Depth-capped so a recycled pid cannot spin forever.
        for child, parent in parents.items():
            cur, hops = parent, 0
            while cur and hops < 6:
                if cur in pids:
                    pids.add(child)
                    break
                cur = parents.get(cur, 0)
                hops += 1
    except Exception:
        pass
    return pids


def _top_level_windows(pids: set) -> List[int]:
    """Visible top-level Chrome windows owned by any of `pids`."""
    found: List[int] = []
    try:
        ctypes, wintypes = _win32()
        user32 = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        buf = ctypes.create_unicode_buffer(256)

        def _cb(hwnd, _lparam):
            try:
                owner = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
                if int(owner.value) not in pids:
                    return True
                if not user32.IsWindowVisible(hwnd):
                    return True
                user32.GetClassNameW(hwnd, buf, 256)
                # Chrome's browser window. Skips its invisible message-only
                # windows and any other stray handle on the process.
                if buf.value.startswith("Chrome_WidgetWin"):
                    found.append(int(hwnd))
            except Exception:
                pass
            return True

        user32.EnumWindows(WNDENUMPROC(_cb), 0)
    except Exception:
        pass
    return found


def _park_window(hwnd: int) -> bool:
    """Park one window: no taskbar button, off-screen, never in front."""
    try:
        ctypes, wintypes = _win32()
        user32 = ctypes.windll.user32

        SWP_NOACTIVATE = 0x0010
        SWP_NOSIZE = 0x0001
        SWP_ASYNCWINDOWPOS = 0x4000
        HWND_BOTTOM = 1
        SW_HIDE = 0

        _remove_taskbar_button(hwnd)

        if hide_browser_windows():
            user32.ShowWindow(wintypes.HWND(hwnd), SW_HIDE)
            return True

        # Re-assert the off-screen position: Chrome pulls a restored window
        # back onto the work area when it reuses saved bounds from the profile,
        # so --window-position alone is not always the last word.
        user32.SetWindowPos(
            wintypes.HWND(hwnd), wintypes.HWND(HWND_BOTTOM),
            OFFSCREEN_X, OFFSCREEN_Y, 0, 0,
            SWP_NOACTIVATE | SWP_NOSIZE | SWP_ASYNCWINDOWPOS,
        )
        return True
    except Exception:
        return False


def _remove_taskbar_button(hwnd: int) -> None:
    """ITaskbarList::DeleteTab -- drop the button without touching the window.

    The other way to lose a taskbar button is the WS_EX_TOOLWINDOW style, but
    the shell only re-reads that across a hide/show cycle, and hiding the
    window is exactly what we are trying to avoid. DeleteTab is a plain request
    to the taskbar and leaves the window itself alone.
    """
    try:
        ctypes, wintypes = _win32()
        ole32 = ctypes.windll.ole32

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        clsid = GUID()
        iid = GUID()
        if ole32.CLSIDFromString("{56FDF344-FD6D-11D0-958A-006097C9A090}",
                                 ctypes.byref(clsid)) != 0:
            return
        if ole32.IIDFromString("{56FDF342-FD6D-11D0-958A-006097C9A090}",
                               ctypes.byref(iid)) != 0:
            return

        ole32.CoInitialize(None)
        try:
            ptr = ctypes.c_void_p()
            hr = ole32.CoCreateInstance(
                ctypes.byref(clsid), None, 1,  # CLSCTX_INPROC_SERVER
                ctypes.byref(iid), ctypes.byref(ptr),
            )
            if hr != 0 or not ptr:
                return
            vtbl = ctypes.cast(
                ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
            )[0]
            proto_self = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
            proto_hwnd = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.HWND)
            try:
                proto_self(vtbl[3])(ptr)                       # HrInit
                proto_hwnd(vtbl[5])(ptr, wintypes.HWND(hwnd))  # DeleteTab
            finally:
                proto_self(vtbl[2])(ptr)                       # Release
        finally:
            ole32.CoUninitialize()
    except Exception:
        pass
