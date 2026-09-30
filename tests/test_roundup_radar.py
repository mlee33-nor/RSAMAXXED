"""The round-up radar announces a pass once, and remembers across launches.

The first quote merge after launch flagged a dozen positions and pushed a toast
for each -- a new window per position, and ~4.4s of frozen UI at startup, every
startup, for the same dozen positions.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import trade_journal


class Radar:
    _check_roundup_radar = A.App._check_roundup_radar

    def __init__(self, open_syms):
        self._roundup_flagged = A._load_roundup_flagged()
        self.open_syms = open_syms
        self.notes, self.logs, self.pipeline = [], [], 0

    def _portfolio_summary(self):
        return {"open_positions": [{"symbol": s} for s in self.open_syms]}

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _log(self, msg, tag=None):
        self.logs.append(msg)

    def _render_pipeline(self):
        self.pipeline += 1


@pytest.fixture()
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "ROUNDUP_RADAR_FILE", tmp_path / "radar.json")
    monkeypatch.setattr(trade_journal, "get_trades", lambda: [
        {"side": "buy", "symbol": s, "qty": 1, "fill_price": 1.0}
        for s in ("AGRZ", "IPDN", "LBGJ", "ONFO")])
    return {s: {"price": p} for s, p in
            (("AGRZ", 3.1), ("IPDN", 4.0), ("LBGJ", 1.2), ("ONFO", 9.0))}


def test_many_flags_in_one_pass_are_one_notification(world):
    r = Radar({"AGRZ", "IPDN", "LBGJ", "ONFO"})
    r._check_roundup_radar(world)
    assert len(r.notes) == 1
    msg, kind = r.notes[0]
    assert kind == "warning"
    assert msg.startswith("⚡ Round-up radar: 3 positions flagged — ONFO 9.0×, "
                          "IPDN 4.0×, AGRZ 3.1×")
    assert r._roundup_flagged == {"AGRZ", "IPDN", "ONFO"}


def test_one_flag_keeps_the_single_position_wording(world):
    r = Radar({"IPDN"})
    r._check_roundup_radar(world)
    assert r.notes[0][0].startswith("⚡ IPDN is quoting 4.0× your avg cost")


def test_a_relaunch_does_not_announce_the_same_positions_again(world):
    first = Radar({"AGRZ", "IPDN", "ONFO"})
    first._check_roundup_radar(world)
    relaunched = Radar({"AGRZ", "IPDN", "ONFO"})       # reads the saved file
    relaunched._check_roundup_radar(world)
    assert relaunched.notes == []
    assert relaunched._roundup_flagged == {"AGRZ", "IPDN", "ONFO"}


def test_closed_positions_drop_out_of_the_saved_set(world):
    Radar({"AGRZ", "IPDN"})._check_roundup_radar(world)
    later = Radar({"IPDN"})                            # AGRZ has been sold
    later._check_roundup_radar(world)
    assert later._roundup_flagged == {"IPDN"}
    assert A._load_roundup_flagged() == {"IPDN"}
