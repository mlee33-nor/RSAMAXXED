"""The two sweep buttons, and the gates that stand between them and your money.

This replaces test_roundup_sweep.py, which had been failing to even IMPORT
since the round-up sweep was removed on 2026-09-02 — it still referenced
`App._roundup_sweep` and five siblings that no longer exist. A collection error
takes the whole suite down with it, so for a week nobody could run `pytest`
without an error, and the tests in that file which covered LIVE code stopped
running too. Those are restored here, pointed at the buttons that still exist.

What is covered is the part that can lose money by itself: a button that queues
every called exit at every broker in one press. Its protections are

  * two presses, the second one knowing the count and the tickers
  * nothing outside market hours, where a market order pays the whole spread
  * nothing while another trade is in flight
  * the fractional button needs the board pulled; the exits button does not,
    because sells.json is the source and it is on disk

and each refusal has to say so ON THE BUTTON, because the log and the bell are
both on other screens — a sweep that silently declined is indistinguishable
from one that did nothing, and you press it again.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle


class Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class Button:
    def __init__(self):
        self.text = ""

    def configure(self, **kw):
        self.text = kw.get("text", self.text)


class Sweeps:
    """Just enough App for both sweep paths."""

    _SWEEP_BUTTONS = A.App._SWEEP_BUTTONS
    _sweep_button = A.App._sweep_button
    _sweep_say = A.App._sweep_say
    _sweep_disarm = A.App._sweep_disarm
    _sweep_progress = A.App._sweep_progress
    _autosell_sweep = A.App._autosell_sweep
    _fractional_sweep = A.App._fractional_sweep
    _autosell_unclaim = A.App._autosell_unclaim
    _autosell_key = A.App._autosell_key
    _queue_extend = A.App._queue_extend

    def __init__(self, exits=(), fracs=(), rows=("board",), sold=()):
        self._exits = list(exits)
        self._fracs = list(fracs)
        self._track_rows = list(rows)
        self._autosell_queue: list = []
        self._autosell_sold: set = set(sold)
        self._autosell_fails: dict = {}
        self._autosell_dry_run = Var(False)
        self._sweep_armed: dict = {}
        self._sweep_btn = Button()
        self._frac_btn = Button()
        self._trade_in_flight = False
        self.logs: list = []
        self.notes: list = []
        self.pumped = 0
        self.saves = 0

    # -- the bits the real methods call out to
    def _autosell_worklist(self):
        return list(self._exits)

    def _fractional_worklist(self, exits=None):
        return list(self._fracs)

    def after(self, ms, cb=None, *a):
        return "after#1"

    def _log(self, msg, *_a, **_k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _save_autosell_state(self):
        self.saves += 1

    def _autosell_pump(self):
        self.pumped += 1

    # -- helpers for the tests
    def press(self, times=1):
        for _ in range(times):
            Sweeps._autosell_sweep(self)

    def press_frac(self, times=1):
        for _ in range(times):
            Sweeps._fractional_sweep(self)

    @property
    def queued(self):
        return [t.symbol for t in self._autosell_queue]


def task(symbol, status="exit_called", brokers=("Public",), days_old=1):
    d = (date.today() - timedelta(days=days_old)).strftime("%Y-%m-%d")
    return lifecycle.SellTask(symbol=symbol, alert_symbol=symbol, alert_date=d,
                              status=status, brokers=tuple(brokers), accounts=1)


@pytest.fixture(autouse=True)
def market_open(monkeypatch):
    monkeypatch.setattr(A, "_market_status",
                        lambda: ("open", "Market open", datetime.now()))


# --------------------------------------------------------------- the gates

def test_it_takes_two_presses():
    """One press must never place an order. The second one knows the count."""
    s = Sweeps(exits=[task("AAA")])

    s.press()
    assert s.queued == [], "a single press queued an order"
    assert "Confirm: sell 1" in s._sweep_btn.text

    s.press()
    assert s.queued == ["AAA"]


def test_the_confirmation_names_the_tickers_it_is_about_to_sell():
    s = Sweeps(exits=[task("AAA"), task("BBB")])
    s.press()
    assert "AAA, BBB" in s._sweep_btn.text


def test_a_long_confirmation_is_summarised_rather_than_endless():
    s = Sweeps(exits=[task(f"S{i}") for i in range(9)])
    s.press()
    assert "+3 more" in s._sweep_btn.text


def test_it_refuses_outside_market_hours(monkeypatch):
    """A market order with the book shut pays the whole spread."""
    monkeypatch.setattr(A, "_market_status",
                        lambda: ("closed", "Market closed", datetime.now()))
    s = Sweeps(exits=[task("AAA")])

    s.press(2)

    assert s.queued == []
    assert "not selling" in s._sweep_btn.text


def test_it_refuses_while_a_trade_is_running():
    s = Sweeps(exits=[task("AAA")])
    s._trade_in_flight = True

    s.press(2)

    assert s.queued == []
    assert "already running" in s._sweep_btn.text


def test_an_empty_worklist_says_so_on_the_button():
    """The refusal has to be visible where the click was — the log and the
    bell are both on other pages."""
    s = Sweeps(exits=[])

    s.press(2)

    assert s.queued == []
    assert "No called exits you still hold" in s._sweep_btn.text


def test_the_exits_sweep_does_not_need_the_board():
    """sells.json is the source and it is on disk from the last feed pull.
    Gating on the board would have made the button dead until a pull landed."""
    s = Sweeps(exits=[task("AAA")], rows=[])

    s.press(2)

    assert s.queued == ["AAA"]


# ------------------------------------------------------ the fractional half

def test_the_fractional_sweep_does_need_the_board():
    """It reads the TRACK board — no rows, no honest answer about remnants."""
    s = Sweeps(fracs=[task("FRAC", status="fractional")], rows=[])

    s.press_frac(2)

    assert s.queued == []
    assert "Pull the board first" in s._frac_btn.text


def test_the_two_sweeps_arm_independently():
    """A bare bool would let one button's confirm fire the other."""
    s = Sweeps(exits=[task("AAA")], fracs=[task("FRAC", status="fractional")])

    s.press()

    assert s._sweep_armed.get("exits") is True
    assert s._sweep_armed.get("fractional") is not True


def test_each_button_returns_to_its_own_resting_label():
    s = Sweeps()
    Sweeps._sweep_disarm(s, "exits")
    Sweeps._sweep_disarm(s, "fractional")
    assert s._sweep_btn.text == "Sell every called exit now"
    assert s._frac_btn.text == "Sell all fractionals now"


# ---------------------------------------------------------- the sold record

def test_a_previously_attempted_play_is_offered_again():
    """A sweep is an explicit two-click instruction about named tickers, so it
    outranks the sold-once record — including a play that exhausted its
    attempts and would otherwise be stuck for the life of the install."""
    t = task("AAA")
    s = Sweeps(exits=[t])
    key = s._autosell_key(t)
    s._autosell_sold.add(key)

    s.press(2)

    assert s.queued == ["AAA"]
    assert key not in s._autosell_sold


def test_unclaiming_is_scoped_to_the_plays_in_hand():
    """Pressing a sweep must not re-open the whole backlog."""
    mine, other = task("AAA"), task("ZZZ")
    s = Sweeps(exits=[mine])
    s._autosell_sold.update({s._autosell_key(mine), s._autosell_key(other)})

    s.press(2)

    assert s._autosell_key(other) in s._autosell_sold


def test_the_queue_is_handed_to_the_pump_once():
    """One pump call: the queue is drained one play at a time downstream, and
    a second pump here would start a race with the first."""
    s = Sweeps(exits=[task("AAA"), task("BBB")])

    s.press(2)

    assert s.queued == ["AAA", "BBB"]
    assert s.pumped == 1


# ------------------------------------------------- Command Center sells card

class Card:
    """Just enough App for the board-status chip."""

    _board_status_map = A.App._board_status_map
    _SELL_STATUS_CHIP = A.App._SELL_STATUS_CHIP

    def __init__(self, rows=()):
        self._track_rows = list(rows)


def test_the_board_status_answers_to_either_ticker():
    """A renamed play has to be findable under the name the alert used."""

    class Row:
        symbol, sell_symbol, status = "AGAE", "AIFA", "rounded_up"

    board = Card._board_status_map(Card(rows=[Row()]))
    assert board["AGAE"] == "rounded_up"
    assert board["AIFA"] == "rounded_up"


def test_every_board_status_has_plain_english():
    """'pending' and 'new' are the two that actually have to be told apart."""
    import rsa_feed
    for status in rsa_feed.LIFECYCLE_STATUSES:
        assert status in Card._SELL_STATUS_CHIP, status
        text, _colour = Card._SELL_STATUS_CHIP[status]
        assert text and text == text.upper()
