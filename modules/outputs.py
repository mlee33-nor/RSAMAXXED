"""Broker output dataclasses and event logging.

All broker files import BrokerOutput, AccountOutput, HoldingRow from here.
An in-memory event log is exposed for the local dashboard.
"""
from __future__ import annotations

import os
import shutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class HoldingRow:
    symbol: str
    shares: Optional[float] = None
    price: Optional[float] = None
    extra: Optional[Dict[str, Any]] = None


@dataclass
class AccountOutput:
    account_id: str
    ok: bool
    message: str = ""
    holdings: List[HoldingRow] = field(default_factory=list)
    order_id: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


@dataclass
class BrokerOutput:
    broker: str
    state: str  # "success" | "failed" | "partial" | …
    accounts: List[AccountOutput] = field(default_factory=list)
    message: str = ""
    extra: Optional[Dict[str, Any]] = None


def find_browser_executable() -> Optional[str]:
    """Find Chrome or Edge executable. Returns path string or None."""
    # Check common Chrome locations
    for candidate in [
        shutil.which("chrome"),
        shutil.which("google-chrome"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    # Fallback to Edge (Chromium-based)
    for candidate in [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
    ]:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def cleanup_orphaned_chrome(profile_dir: Path) -> int:
    """Kill Chrome processes using a specific profile directory.

    Returns the number of processes killed.
    """
    import subprocess
    killed = 0
    profile_str = str(profile_dir.resolve()).replace("/", "\\").lower()
    try:
        # Use PowerShell (always available on Windows 11) since wmic is deprecated
        ps_cmd = (
            "Get-CimInstance Win32_Process -Filter \"name='chrome.exe'\" | "
            "Select-Object ProcessId, CommandLine | "
            "ForEach-Object { $_.ProcessId.ToString() + '|' + $_.CommandLine }"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            pid_str, cmd = line.split("|", 1)
            if profile_str in cmd.lower():
                try:
                    os.kill(int(pid_str.strip()), 9)
                    killed += 1
                except (OSError, ProcessLookupError, ValueError):
                    pass
    except Exception:
        pass
    # Also clean singleton files
    for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
        try:
            (profile_dir / name).unlink(missing_ok=True)
        except Exception:
            pass
    return killed


def display_path(path: Path) -> str:
    """Return a human-friendly representation of a path."""
    try:
        return str(path.resolve())
    except Exception:
        return str(path)


# ---------------------------------------------------------------------------
# In-memory event log (consumed by the dashboard)
# ---------------------------------------------------------------------------

_events: List[Dict[str, Any]] = []
_lock = threading.Lock()


def log_event(*, broker: str, action: str, output: BrokerOutput) -> None:
    """Append a structured event for the dashboard to display."""
    with _lock:
        _events.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "broker": broker,
            "action": action,
            "state": output.state,
            "message": output.message,
            "accounts": [
                {
                    "account_id": a.account_id,
                    "ok": a.ok,
                    "message": a.message,
                    "num_holdings": len(a.holdings),
                }
                for a in output.accounts
            ],
        })


def get_events() -> List[Dict[str, Any]]:
    """Return a copy of the event log."""
    with _lock:
        return list(_events)
