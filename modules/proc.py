"""Process liveness and verified termination, safe on Windows.

WHY THIS EXISTS
---------------
The profile locks used to check their owner with ``os.kill(pid, 0)``. On
Windows signal 0 is CTRL_C_EVENT, and a process with no console (the app runs
under pythonw) gets no console event at all -- CPython falls through to
``TerminateProcess(pid)``. So "is the lock owner alive?" killed the owner. When
the lock held the app's own pid (a thread abandoned by a ``_run_coro``
timeout) the app killed itself; when the pid had been reused it killed an
unrelated process.

Rules kept here:

* ``pid_alive`` never signals anything. On Windows it opens the process for
  query only and reads its exit code.
* ``terminate_browser`` only ends a process after checking, through a handle
  that pins it (so the pid cannot be recycled between the check and the kill),
  that its image is a Chromium browser AND its command line names the profile
  directory we own. It never touches ``os.getpid()``.
* The candidate list comes from the toolhelp snapshot, not a WMI/PowerShell
  query: no subprocess, no console flash, no stale pid list.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional

_STILL_ACTIVE = 259
_PROCESS_TERMINATE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_PARAMETER = 87          # OpenProcess on a pid that does not exist
_ProcessCommandLineInformation = 60    # NtQueryInformationProcess, Windows 8.1+

BROWSER_IMAGES = ("chrome.exe", "msedge.exe")


def _is_windows() -> bool:
    return os.name == "nt"


def _k32():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL
    k32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    return ctypes, wintypes, k32


def pid_alive(pid: int) -> Optional[bool]:
    """True alive, False gone, None when it cannot be told. Never signals.

    Access denied means the pid exists (it belongs to another user or a
    protected process), so it counts as alive -- a lock is never stolen on a
    guess.
    """
    try:
        pid = int(pid)
    except Exception:
        return None
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if not _is_windows():
        try:
            os.kill(pid, 0)          # POSIX only: signal 0 is a pure existence probe
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except Exception:
            return None
    try:
        ctypes, wintypes, k32 = _k32()
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            err = ctypes.get_last_error()
            if err == _ERROR_ACCESS_DENIED:
                return True
            if err == _ERROR_INVALID_PARAMETER:
                return False
            return None
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return None
            return code.value == _STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return None


def started_after(pid: int, when: float, slack_s: float = 2.0) -> Optional[bool]:
    """Did process `pid` start more than `slack_s` seconds after epoch time
    `when`? True / False / None (cannot tell). Never signals.

    A profile lock records its owner's pid when the lock is written. After a
    crash and a reboot Windows can hand that pid to an unrelated, long-lived
    process; pid_alive then says "alive" forever and the profile stays locked
    with nothing holding it. A process that started after the lock was
    written cannot be the one that wrote it.
    """
    try:
        pid = int(pid)
    except Exception:
        return None
    if pid <= 0 or pid == os.getpid() or not _is_windows():
        return None
    try:
        ctypes, wintypes, k32 = _k32()
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return None
        try:
            created, exited, kernel, user = (wintypes.FILETIME(), wintypes.FILETIME(),
                                             wintypes.FILETIME(), wintypes.FILETIME())
            k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [
                ctypes.POINTER(wintypes.FILETIME)] * 4
            k32.GetProcessTimes.restype = wintypes.BOOL
            if not k32.GetProcessTimes(h, ctypes.byref(created), ctypes.byref(exited),
                                       ctypes.byref(kernel), ctypes.byref(user)):
                return None
            ticks = (created.dwHighDateTime << 32) | created.dwLowDateTime
            # FILETIME: 100ns ticks since 1601-01-01 UTC.
            start = ticks / 10_000_000 - 11_644_473_600
            return start > float(when) + slack_s
        finally:
            k32.CloseHandle(h)
    except Exception:
        return None


def _image_name(ctypes, wintypes, k32, h) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    size = wintypes.DWORD(len(buf))
    if not k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
        return ""
    return buf.value


def _command_line(ctypes, wintypes, h) -> str:
    """The process's command line, read through the handle (no WMI)."""
    ntdll = ctypes.WinDLL("ntdll")
    fn = ntdll.NtQueryInformationProcess
    fn.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                   ctypes.POINTER(wintypes.ULONG)]
    fn.restype = ctypes.c_long

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                    ("Buffer", ctypes.c_void_p)]

    need = wintypes.ULONG(0)
    fn(h, _ProcessCommandLineInformation, None, 0, ctypes.byref(need))
    size = max(int(need.value), ctypes.sizeof(UNICODE_STRING)) + 64
    buf = ctypes.create_string_buffer(size)
    status = fn(h, _ProcessCommandLineInformation, buf, size, ctypes.byref(need))
    if status < 0:
        return ""
    us = UNICODE_STRING.from_buffer(buf)
    if not us.Buffer or not us.Length:
        return ""
    return ctypes.wstring_at(us.Buffer, us.Length // 2)


def _norm(path) -> str:
    try:
        s = str(Path(path).resolve())
    except Exception:
        s = str(path)
    return s.replace("/", "\\").rstrip("\\").lower()


def cmdline_names_dir(cmdline: str, directory) -> bool:
    """Does `cmdline` reference exactly `directory` (not a sibling sharing a prefix)?

    ``...\\ZenFidelity_1`` must not match a browser running on
    ``...\\ZenFidelity_10``: the character after the path has to end it.
    """
    want = _norm(directory)
    if not want:
        return False
    hay = (cmdline or "").replace("/", "\\").lower()
    start = 0
    while True:
        i = hay.find(want, start)
        if i < 0:
            return False
        end = i + len(want)
        nxt = hay[end] if end < len(hay) else ""
        if nxt in ("", '"', "'", " ", "\t"):
            return True
        if nxt == "\\" and (end + 1 >= len(hay) or hay[end + 1] in ('"', "'", " ", "\t")):
            return True
        start = i + 1


def _list_processes() -> List[tuple]:
    """(pid, exe basename) for every process, from a toolhelp snapshot."""
    ctypes, wintypes, _ = _k32()

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return []
    out: List[tuple] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            out.append((int(entry.th32ProcessID), str(entry.szExeFile)))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return out


def terminate_verified(pid: int, *, directory, images: Iterable[str] = BROWSER_IMAGES) -> bool:
    """End `pid` only if it is (still) one of `images` running on `directory`.

    The image and command line are read through the same handle that is then
    used to terminate, so a recycled pid can never be the one killed.
    """
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0 or pid == os.getpid() or not _is_windows():
        return False
    wanted = {str(i).lower() for i in images}
    try:
        ctypes, wintypes, k32 = _k32()
        h = k32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_TERMINATE, False, pid)
        if not h:
            return False
        try:
            code = wintypes.DWORD()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)) or code.value != _STILL_ACTIVE:
                return False
            image = os.path.basename(_image_name(ctypes, wintypes, k32, h)).lower()
            if image not in wanted:
                return False
            if not cmdline_names_dir(_command_line(ctypes, wintypes, h), directory):
                return False
            return bool(k32.TerminateProcess(h, 1))
        finally:
            k32.CloseHandle(h)
    except Exception:
        return False


def terminate_browsers_on(directory, *, images: Iterable[str] = BROWSER_IMAGES) -> int:
    """Kill every browser process whose command line names `directory`. Windows only."""
    if not _is_windows():
        return 0
    try:
        procs = _list_processes()
    except Exception:
        return 0
    me = os.getpid()
    wanted = {str(i).lower() for i in images}
    killed = 0
    for pid, exe in procs:
        if pid in (0, 4, me) or str(exe).lower() not in wanted:
            continue
        if terminate_verified(pid, directory=directory, images=images):
            killed += 1
    return killed
