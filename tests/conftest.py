"""Shared test fixtures.

The only thing here is a single Tk root for the whole session. Several test
modules render real widgets, and creating a Tk() per module — never mind per
test — intermittently fails with "Can't find a usable init.tcl" partway
through a full run on this install. One root, created once, torn down at the
end, and the flakiness goes away.
"""

from __future__ import annotations

import os
import sys
import tkinter as tk
from pathlib import Path

# Before anything imports app: it installs logs/crash.log at IMPORT time, which
# is earlier than any fixture can redirect LOG_DIR, and every run was writing
# START / PROCESS EXIT entries into the user's real crash log. See
# app._crash_log_disabled.
os.environ["RSA_NO_CRASH_LOG"] = "1"

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def _keep_tests_out_of_the_real_trade_log(tmp_path, tmp_path_factory, monkeypatch):
    """Every test that runs the real trade worker used to append to the user's
    logs/trade_results.log -- 1,933 fake "BUY 1 SPY on public" entries by
    2026-09-25. The app reads that log back (failure reasons per ticker), so it
    is data, not scratch. Point it at the test's own folder instead.
    """
    mod = sys.modules.get("app")
    if mod is not None:
        logs = tmp_path / "logs"
        monkeypatch.setattr(mod, "LOG_DIR", logs, raising=False)
        monkeypatch.setattr(mod, "TRADE_RESULTS_LOG", logs / "trade_results.log",
                            raising=False)
        # State files a sell path or a quote merge may write: never the
        # user's own.
        monkeypatch.setattr(mod, "PUBLIC_LATE_CHECKED_FILE",
                            tmp_path / "public_late_checked.json", raising=False)
        monkeypatch.setattr(mod, "ROUNDUP_RADAR_FILE",
                            tmp_path / "roundup_radar.json", raising=False)
    _redirect_state_files(tmp_path_factory.mktemp("state"), monkeypatch)
    yield


# Every file the app keeps state in, by module. A test that forgets to point
# one of these somewhere else would otherwise read the user's real trades,
# picks and claims -- or write over them. Tests that need a file of their own
# still monkeypatch it; theirs is applied after this and wins.
_STATE_FILES = {
    "app": ("CUSTOM_ACCOUNTS_FILE", "MIRROR_STATE_FILE", "AUTOSELL_STATE_FILE",
            "WATCHLIST_FILE", "FEED_STATE_FILE", "SELLS_FILE",
            "SELLS_CONFIRMED_FILE", "PICKS_FILE", "PICKS_DONE_FILE",
            "COVERAGE_READ_FILE", "FEED_ARCHIVE_FILE"),
    "lifecycle": ("STATE_FILE",),
    "trade_journal": ("_FILE",),
    "mirror_journal": ("_FILE",),
    "etf_journal": ("ETF_FILE",),
    "balances": ("BALANCES_FILE",),
    "cloud_sync": ("_STATE_FILE", "_TRADES_FILE"),
}


def _redirect_state_files(state, monkeypatch):
    for modname, names in _STATE_FILES.items():
        mod = sys.modules.get(modname)
        if mod is None:
            continue
        for name in names:
            real = getattr(mod, name, None)
            if real is None:
                continue
            monkeypatch.setattr(mod, name, state / f"{modname}.{Path(real).name}")


# The app loads the user's real .env at import, so every test process starts
# with their broker logins and feed token in os.environ. A test that reaches a
# code path reading one of them would sign in, or pull the live board, as the
# user. Strip every key the real .env defines before each test; a test that
# needs one sets it itself.
def _real_env_keys():
    try:
        from dotenv import dotenv_values
        return [k for k in dotenv_values(Path(__file__).resolve().parent.parent / ".env",
                                         interpolate=False)]
    except Exception:
        return []


_REAL_ENV_KEYS = _real_env_keys()


@pytest.fixture(autouse=True)
def _no_real_credentials(monkeypatch):
    for k in _REAL_ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    yield


# No test may talk to the outside world: not a broker, not the feed, not the
# cloud. Loopback stays open (in-process servers, worker pipes).
_LOOPBACK = ("127.0.0.1", "::1", "localhost")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    import socket
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def _host(address):
        return address[0] if isinstance(address, tuple) and address else address

    def guard(self, address, _real=real_connect):
        if _host(address) not in _LOOPBACK and self.family in (socket.AF_INET, socket.AF_INET6):
            raise OSError(f"tests may not open network connections (to {address!r})")
        return _real(self, address)

    def guard_ex(self, address, _real=real_connect_ex):
        if _host(address) not in _LOOPBACK and self.family in (socket.AF_INET, socket.AF_INET6):
            raise OSError(f"tests may not open network connections (to {address!r})")
        return _real(self, address)

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard_ex)
    yield


@pytest.fixture(scope="session")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass
