"""Shared test fixtures.

The only thing here is a single Tk root for the whole session. Several test
modules render real widgets, and creating a Tk() per module — never mind per
test — intermittently fails with "Can't find a usable init.tcl" partway
through a full run on this install. One root, created once, torn down at the
end, and the flakiness goes away.
"""

from __future__ import annotations

import sys
import tkinter as tk
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(scope="session")
def tk_root():
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except Exception:
        pass
