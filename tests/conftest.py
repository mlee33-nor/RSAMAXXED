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
def _keep_tests_out_of_the_real_trade_log(tmp_path, monkeypatch):
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
