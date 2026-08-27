"""The confirmed round-up sweep, and the guards that decide what it may reach.

The ask was "a sell confirmed round-ups section, with restrictions so it doesn't
go haywire selling old stuff I already sold" — then, on seeing the restrictions,
"no never same play twice, because sometimes the same stock resurfaces".

So the guards are:

  * rounded_up only — 'canceled' sits in the same whole-share group on the page
    but the split never happened
  * only what the journal still shows open (inherited from sell_worklist ->
    held_accounts, which nets sells and is split-adjusted)
  * a window on CONFIRMATION time: never before the watermark this install was
    set up at, plus an optional backtrack
  * explicitly NOT "never the same play twice" — a sweep is an instruction about
    named tickers and outranks the sold-once record

Plus the Command Center sells card, where a play you bought used to render
identically to one you never owned.

App can't be instantiated headlessly, so the real methods run unbound against a
stub — same approach as test_concurrent_orders.
"""

from __future__ import annotations

import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle


# --------------------------------------------------------------------- stub

class Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Button:
    def __init__(self):
        self.text = ""

    def configure(self, **kw):
        self.text = kw.get("text", self.text)


WATERMARK = datetime(2026, 8, 1, tzinfo=timezone.utc)


class Exits:
    """Just enough App for the sweep paths."""

    _SWEEP_BUTTONS = A.App._SWEEP_BUTTONS
    _sweep_button = A.App._sweep_button
    _sweep_say = A.App._sweep_say
    _sweep_disarm = A.App._sweep_disarm
    _sweep_progress = A.App._sweep_progress
    _roundup_watermark = A.App._roundup_watermark
    _roundup_backtrack_days = A.App._roundup_backtrack_days
    _roundup_cutoff = A.App._roundup_cutoff
    _roundup_confirmed_at = A.App._roundup_confirmed_at
    _roundup_in_window = A.App._roundup_in_window
    _roundup_sweep = A.App._roundup_sweep
    _autosell_sweep = A.App._autosell_sweep
    _autosell_unclaim = A.App._autosell_unclaim
    _autosell_key = A.App._autosell_key

    def __init__(self, rows=(), sold=(), backtrack=0, watermark=WATERMARK):
        self._track_rows = list(rows)
        self._autosell_queue: list = []
        self._autosell_sold: set = set(sold)
        self._autosell_fails: dict = {}
        self._autosell_dry_run = Var(False)
        self._roundup_since = watermark.isoformat() if watermark else ""
        self._roundup_backtrack = Var(backtrack)
        self._roundup_chips: dict = {}
        self._sweep_armed: dict = {}
        self._sweep_btn = Button()
        self._roundup_btn = Button()
        self._trade_in_flight = False
        self.logs: list = []
        self.notes: list = []
        self.scheduled: list = []
        self.saves = 0

    def after(self, ms, cb=None, *a):
        self.scheduled.append((ms, cb))
        return f"after#{len(self.scheduled)}"

    def _log(self, msg, *_a, **_k):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _save_autosell_state(self):
        self.saves += 1

    def _autosell_pump(self):
        self.pumped = True

    def press_roundup(self, times=1):
        for _ in range(times):
            Exits._roundup_sweep(self)

    @property
    def queued(self):
        return [t.symbol for t in self._autosell_queue]


def task(symbol, status="rounded_up", days_old=1, brokers=("Public",)):
    d = (date.today() - timedelta(days=days_old)).strftime("%Y-%m-%d")
    return lifecycle.SellTask(symbol=symbol, alert_symbol=symbol, alert_date=d,
                              status=status, brokers=tuple(brokers), accounts=1)


def board_state(*pairs):
    """(task, confirmed_at) -> the lifecycle state shape the sweep reads."""
    rows = {}
    for t, at in pairs:
        key = f"{t.alert_date}:{t.alert_symbol.upper()}"
        rows[key] = {"key": key, "status_changed_at": at.isoformat() if at else ""}
    return {"rows": rows}


@pytest.fixture(autouse=True)
def market_open(monkeypatch):
    monkeypatch.setattr(A, "_market_status",
                        lambda: ("open", "Market open", datetime.now()))


def wire(monkeypatch, tasks, state=None):
    monkeypatch.setattr(A.lifecycle, "sell_worklist",
                        lambda rows, *a, **k: list(tasks))
    monkeypatch.setattr(A.lifecycle, "load_state",
                        lambda *a, **k: state if state is not None else {"rows": {}})


# ------------------------------------------------------------- the restrictions

def test_a_cancelled_play_is_never_swept(monkeypatch):
    """'canceled' shares the whole-share group but the split never happened."""
    good, dead = task("GOOD"), task("DEAD", status="canceled")
    now = datetime.now(timezone.utc)
    wire(monkeypatch, [good, dead], board_state((good, now), (dead, now)))
    e = Exits(rows=["x"])
    e.press_roundup(2)          # arm, then confirm
    assert e.queued == ["GOOD"]


def test_a_fractional_play_is_never_swept_here(monkeypatch):
    frac = task("FRAC", status="fractional")
    wire(monkeypatch, [frac], board_state((frac, datetime.now(timezone.utc))))
    e = Exits(rows=["x"])
    e.press_roundup(2)
    assert e.queued == []
    assert "No confirmed round-ups" in e._roundup_btn.text


def test_a_play_held_nowhere_is_skipped(monkeypatch):
    """sell_worklist scopes brokers through the journal; no brokers, no sweep."""
    t = task("NOTHELD", brokers=())
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"])
    e.press_roundup(2)
    assert e.queued == []


def test_one_press_is_capped(monkeypatch):
    now = datetime.now(timezone.utc)
    many = [task(f"S{i}") for i in range(A.ROUNDUP_SWEEP_MAX + 4)]
    wire(monkeypatch, many, board_state(*((t, now) for t in many)))
    e = Exits(rows=["x"])
    e.press_roundup(2)
    assert len(e.queued) == A.ROUNDUP_SWEEP_MAX
    assert any("wait for the next press" in line for line in e.logs)


# --------------------------------------------------- the confirmation-time window

def test_it_reaches_nothing_confirmed_before_setup(monkeypatch):
    """The whole point of the watermark: a fresh install sweeps nothing
    retroactively, so the button cannot open by selling a backlog."""
    after = task("AFTER")
    before = task("BEFORE")
    wire(monkeypatch, [after, before],
         board_state((after, WATERMARK + timedelta(days=2)),
                     (before, WATERMARK - timedelta(days=2))))
    e = Exits(rows=["x"], backtrack=0)
    e.press_roundup(2)
    assert e.queued == ["AFTER"]
    assert any("confirmed before the sweep window" in line for line in e.logs)


def test_the_backtrack_widens_the_reach(monkeypatch):
    old = task("OLD")
    wire(monkeypatch, [old], board_state((old, WATERMARK - timedelta(days=5))))

    tight = Exits(rows=["x"], backtrack=3)
    tight.press_roundup(2)
    assert tight.queued == [], "3 days should not reach 5 days back"

    wide = Exits(rows=["x"], backtrack=7)
    wide.press_roundup(2)
    assert wide.queued == ["OLD"]


def test_the_window_is_measured_from_confirmation_not_the_alert_date(monkeypatch):
    """A play alerted long ago that rounded up this morning is exactly the case
    an alert-date window threw away."""
    t = task("LATEBLOOM", days_old=90)
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"], backtrack=0)
    e.press_roundup(2)
    assert e.queued == ["LATEBLOOM"]


def test_an_unknown_confirmation_time_counts_as_out(monkeypatch):
    """No timestamp is not evidence of recency."""
    t = task("MYSTERY")
    wire(monkeypatch, [t], {"rows": {}})
    e = Exits(rows=["x"])
    assert Exits._roundup_in_window(e, t, {"rows": {}}) is False


def test_the_watermark_is_stamped_once_and_kept():
    e = Exits(rows=["x"], watermark=None)
    first = Exits._roundup_watermark(e)
    assert first, "nothing was stamped"
    assert Exits._roundup_watermark(e) == first, "the watermark moved"


def test_a_bad_backtrack_value_falls_back_to_none():
    e = Exits()
    e._roundup_backtrack = Var("not a number")
    assert Exits._roundup_backtrack_days(e) == A.ROUNDUP_BACKTRACK_CHOICES[0]
    e._roundup_backtrack = Var(999)
    assert Exits._roundup_backtrack_days(e) == A.ROUNDUP_BACKTRACK_CHOICES[0]


def test_everything_out_of_window_says_so_instead_of_nothing_to_sell(monkeypatch):
    """"Nothing to sell" over a board full of round-ups is the wrong answer."""
    t = task("ANCIENT")
    wire(monkeypatch, [t], board_state((t, WATERMARK - timedelta(days=30))))
    e = Exits(rows=["x"])
    e.press_roundup()
    assert "outside the window" in e._roundup_btn.text
    assert e.notes and "widen the backtrack" in e.notes[0][0]


# --------------------------------------- a sweep is not blocked by past attempts

def test_a_previously_attempted_play_is_offered_again(monkeypatch):
    """No 'never the same play twice' — a ticker can come back around, and a
    play that failed three times must not be stuck for the life of the install."""
    t = task("TRIED")
    key = f"{t.alert_date}:TRIED"
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"], sold={key})
    e._autosell_fails[key] = A.AUTOSELL_MAX_ATTEMPTS

    e.press_roundup(2)

    assert e.queued == ["TRIED"]
    # ...and the claim is released, or the pump would drop it on the way out.
    assert key not in e._autosell_sold
    assert key not in e._autosell_fails


def test_unclaiming_is_scoped_to_the_plays_in_hand():
    """Pressing a sweep must not re-open the whole backlog the way Retry
    skipped does."""
    mine, other = task("MINE"), task("OTHER")
    e = Exits(sold={f"{mine.alert_date}:MINE", f"{other.alert_date}:OTHER"})
    Exits._autosell_unclaim(e, [mine])
    assert f"{mine.alert_date}:MINE" not in e._autosell_sold
    assert f"{other.alert_date}:OTHER" in e._autosell_sold


def test_the_fractional_sweep_also_stops_burying_plays(monkeypatch):
    t = task("FRAC", status="fractional")
    key = f"{t.alert_date}:FRAC"
    wire(monkeypatch, [t])
    e = Exits(rows=["x"], sold={key})
    Exits._autosell_sweep(e)
    Exits._autosell_sweep(e)
    assert e.queued == ["FRAC"]
    assert key not in e._autosell_sold


# --------------------------------------------------------------------- the gates

def test_it_takes_two_presses(monkeypatch):
    t = task("AAA")
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"])
    e.press_roundup()
    assert e.queued == [], "one press placed an order"
    assert "Confirm: sell 1" in e._roundup_btn.text
    e.press_roundup()
    assert e.queued == ["AAA"]


def test_it_refuses_outside_market_hours(monkeypatch):
    monkeypatch.setattr(A, "_market_status",
                        lambda: ("closed", "Market closed", datetime.now()))
    t = task("AAA")
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"])
    e.press_roundup(2)
    assert e.queued == []
    assert "not selling" in e._roundup_btn.text


def test_it_refuses_while_a_trade_is_running(monkeypatch):
    t = task("AAA")
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"])
    e._trade_in_flight = True
    e.press_roundup(2)
    assert e.queued == []
    assert "already running" in e._roundup_btn.text


def test_it_refuses_before_the_board_is_pulled(monkeypatch):
    wire(monkeypatch, [task("AAA")])
    e = Exits(rows=[])
    e.press_roundup(2)
    assert e.queued == []
    assert "Pull the board first" in e._roundup_btn.text


def test_the_two_sweeps_arm_independently(monkeypatch):
    """A bare bool would let one button's confirm fire the other."""
    t = task("AAA")
    wire(monkeypatch, [t], board_state((t, datetime.now(timezone.utc))))
    e = Exits(rows=["x"])
    e.press_roundup()
    assert e._sweep_armed.get("roundup") is True
    assert e._sweep_armed.get("fractional") is not True


def test_each_button_returns_to_its_own_resting_label():
    e = Exits()
    Exits._sweep_disarm(e, "roundup")
    Exits._sweep_disarm(e, "fractional")
    assert e._roundup_btn.text == "Sell confirmed round-ups"
    assert e._sweep_btn.text == "Sell all fractionals now"


# ------------------------------------------------- Command Center sells card

def _exit(symbol, broker="Public"):
    """A sell alert as the feed writes it: one ticker, one brokerage."""
    return {"symbol": symbol, "legs": [{"broker": broker, "accounts_low": 1}]}


class Card:
    _sell_alert_position_map = A.App._sell_alert_position_map
    _sell_alert_scope = A.App._sell_alert_scope
    _sell_alert_state = A.App._sell_alert_state
    _board_status_map = A.App._board_status_map
    _SELL_STATUS_CHIP = A.App._SELL_STATUS_CHIP

    def __init__(self, rows=()):
        self._track_rows = list(rows)


def test_a_bought_play_is_told_apart_from_one_never_owned(monkeypatch):
    """Both used to render as 'not held', which is true and useless."""
    trades = [
        {"symbol": "SOLDOUT", "side": "buy", "broker": "public", "account_id": "1"},
        {"symbol": "SOLDOUT", "side": "sell", "broker": "public", "account_id": "1"},
        {"symbol": "STILLIN", "side": "buy", "broker": "public", "account_id": "2"},
    ]
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda *a, **k: trades)
    monkeypatch.setattr(A.trade_journal, "get_portfolio",
                        lambda: {("public", "STILLIN"): {"qty": 1.0}})

    c = Card()
    open_pairs, bought, sold = Card._sell_alert_position_map(c)

    # The open set keeps the broker now — one broker's exit must not speak for
    # another's position in the same ticker.
    assert open_pairs == {("public", "STILLIN")}
    state = lambda sym: Card._sell_alert_state(
        c, _exit(sym), open_pairs, bought, sold)
    assert state("SOLDOUT") == "sold"
    assert state("STILLIN") == "alerts"
    assert state("NEVER") == "alerts"


def test_a_half_sold_play_lands_in_partial(monkeypatch):
    trades = [
        {"symbol": "HALF", "side": "buy", "broker": "public", "account_id": "1"},
        {"symbol": "HALF", "side": "buy", "broker": "public", "account_id": "2"},
        {"symbol": "HALF", "side": "sell", "broker": "public", "account_id": "1"},
    ]
    monkeypatch.setattr(A.trade_journal, "get_trades", lambda *a, **k: trades)
    monkeypatch.setattr(A.trade_journal, "get_portfolio",
                        lambda: {("public", "HALF"): {"qty": 1.0}})
    c = Card()
    open_pairs, bought, sold = Card._sell_alert_position_map(c)
    assert Card._sell_alert_state(
        c, _exit("HALF"), open_pairs, bought, sold) == "partial"


def test_a_journal_read_failure_does_not_take_the_card_down(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("journal unreadable")
    monkeypatch.setattr(A.trade_journal, "get_portfolio", boom)
    assert Card._sell_alert_position_map(Card()) == (set(), {}, {})


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
