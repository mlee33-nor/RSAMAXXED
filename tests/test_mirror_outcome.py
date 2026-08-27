"""What mirror says when a pick doesn't fill, and where the dollar figure comes from.

Two reports, one root cause — a message that described the RUN as though it
described the PLAY:

  "it said sfwl failed buy but i have 38 buys"

SFWL went out to Fidelity alone, because the other five brokers already held it
across 38 accounts. The run filled nothing, so the notification said "filled on
no broker" — true of the run, false of the play. Being short one broker and
owning none of it must not share a sentence.

And on the sells card, the alerter's account counts moved off the broker names
(where they sat beside our own coverage) onto the dollar figure, which is the
only number they actually explain.

App can't be instantiated headlessly, so the real methods run unbound against a
stub — same approach as test_concurrent_orders.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A


# --------------------------------------------------------------------- stub

class Mirror:
    _mirror_record_outcome = A.App._mirror_record_outcome

    def __init__(self):
        self._mirror_failed: set = set()
        self._mirror_failed_notes: dict = {}
        self.logs: list = []
        self.notes: list = []
        self.saves = 0
        self.rendered = 0

    def _mirror_log_msg(self, msg):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _save_mirror_state(self):
        self.saves += 1

    def _render_mirror_failed(self):
        self.rendered += 1

    @property
    def log_text(self):
        return " ".join(self.logs)

    @property
    def toast_text(self):
        return " ".join(m for m, _k in self.notes)


def batch(symbol="SFWL", attempted=("fidelity",), skipped=(), key=None):
    return {
        "symbol": symbol,
        "origin": "mirror",
        "mirror_key": key or ("2026-08-26", symbol),
        "all_brokers": list(attempted),
        "mirror_skipped": list(skipped),
    }


# --------------------------------------------------------- the SFWL report

def test_a_play_the_others_already_hold_is_not_called_filled_nowhere():
    m = Mirror()
    b = batch(attempted=("fidelity",),
              skipped=("public", "wellsfargo", "chase", "robinhood", "fennel"))

    Mirror._mirror_record_outcome(m, b, total_ok=0, total_fail=1)

    assert "filled on NO broker" not in m.log_text
    assert "Fidelity" in m.log_text
    assert "already hold it" in m.log_text
    # The sentence a user with 38 buys needs to read.
    assert "not out of this play" in m.log_text
    assert "no broker" not in m.toast_text


def test_a_genuine_total_failure_still_says_so():
    m = Mirror()
    b = batch(symbol="GCTK", attempted=("public", "chase"), skipped=())

    Mirror._mirror_record_outcome(m, b, total_ok=0, total_fail=24)

    assert "filled on NO broker" in m.log_text
    assert "24 account(s) rejected" in m.log_text
    assert m.notes[0][1] == "error"


def test_the_partial_case_is_a_warning_not_an_error():
    """An error toast for 'you are short one broker' is what made this read as
    a failed buy in the first place."""
    m = Mirror()
    Mirror._mirror_record_outcome(m, batch(skipped=("public",)), 0, 1)
    assert m.notes[0][1] == "warning"


def test_the_reason_is_recorded_per_pick():
    m = Mirror()
    b = batch(skipped=("public",))
    Mirror._mirror_record_outcome(m, b, 0, 1)
    key = ("2026-08-26", "SFWL")
    assert key in m._mirror_failed
    assert "already hold it" in m._mirror_failed_notes[key]


def test_a_fill_clears_both_the_flag_and_its_reason():
    m = Mirror()
    b = batch(skipped=("public",))
    Mirror._mirror_record_outcome(m, b, 0, 1)
    Mirror._mirror_record_outcome(m, b, total_ok=3, total_fail=0)
    assert m._mirror_failed == set()
    assert m._mirror_failed_notes == {}


def test_a_batch_with_no_key_is_ignored():
    m = Mirror()
    Mirror._mirror_record_outcome(m, {"symbol": "X", "mirror_key": ()}, 0, 1)
    assert m._mirror_failed == set()
    assert m.saves == 0
