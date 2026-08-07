"""Auto-selling a fraction the moment the board reports one.

A fraction is what is left when a split did NOT round the position up. There is
no round-up coming and nothing to wait for — only a thin post-split name that
drifts down while it sits — so the delay between "the board says fractional" and
"the order is placed" is pure loss. Closing that gap is the point.

It places live orders with nobody watching, so what is tested here is the
GUARDS. Every one of them is the difference between an automation and an
accident, and each has a failure mode worse than not automating at all:

    disarmed          it must be switched on deliberately, once
    market hours      a market order into a closed book pays the whole spread
    sold once, ever   a re-pull, a restart, a renamed ticker: never twice
    a cap per pull    fifteen at once means the board changed shape
    one at a time     _exit_fire refuses while a trade runs, so a parallel
                      queue would place the first order and drop the rest

The decision logic is exercised directly against a stand-in for the app, so no
tkinter, no broker session and no order ever exists.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import types

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import lifecycle  # noqa: E402

# The desktop GUI is `app.py` at the repo root and the web package is also named
# `app` (see the note at the top of test_client_contract). Whichever imports
# first wins `sys.modules["app"]` for the whole session, so `import app` here
# passes alone and fails in the full run. Loading it by path under a name
# nothing else claims makes this test independent of suite order.
_spec = importlib.util.spec_from_file_location(
    "rsamaxxed_desktop_app", REPO_ROOT / "app.py")
desktop_app = importlib.util.module_from_spec(_spec)
sys.modules["rsamaxxed_desktop_app"] = desktop_app
_spec.loader.exec_module(desktop_app)


class _Var:
    """Stands in for tk.BooleanVar."""

    def __init__(self, value=False):
        self._v = value

    def get(self):
        return self._v

    def set(self, v):
        self._v = v


def _row(symbol, status, alert_date="2026-08-06", sell_symbol=""):
    return lifecycle.LifecycleRow(
        symbol=symbol, sell_symbol=sell_symbol or symbol,
        alert_date=alert_date, status=status, kind="standard",
    )


def _trade(symbol, broker, account, side="buy", qty=1.0):
    return {"symbol": symbol, "broker": broker, "account_id": account,
            "side": side, "qty": qty}


# --------------------------------------------------------- the broker scoping

def test_a_fraction_is_only_sellable_where_fractions_exist():
    """The whole reason this is safe to automate: the worklist already refuses
    to offer a fractional play at a broker that paid cash in lieu, so auto-sell
    cannot place an order into an account holding nothing."""
    held = lifecycle.held_accounts([
        _trade("GRNQ", "public", "p1"),
        _trade("GRNQ", "robinhood", "r1"),
        _trade("GRNQ", "chase", "c1"),          # settled to cash, holds nothing
    ])
    task = lifecycle.sell_worklist([_row("GRNQ", "fractional")], held)[0]
    assert set(task.brokers) == {"Public", "Robinhood"}
    assert "Chase" in task.skipped_brokers


def test_a_round_up_is_sellable_everywhere():
    """A whole share came back in every account, so nothing is scoped out."""
    held = lifecycle.held_accounts([
        _trade("HCWB", "public", "p1"), _trade("HCWB", "chase", "c1"),
    ])
    task = lifecycle.sell_worklist([_row("HCWB", "rounded_up")], held)[0]
    assert set(task.brokers) == {"Public", "Chase"}


def test_a_play_we_hold_nowhere_is_not_offered():
    """The board reports every alert, including ones this install never bought."""
    assert lifecycle.sell_worklist([_row("NOTOURS", "fractional")], {}) == []


def test_a_renamed_play_is_found_under_the_ticker_we_bought():
    """We bought AGAE; only AIFA is tradeable. Looking under the sell symbol
    alone finds nothing and the play is silently never sold."""
    held = lifecycle.held_accounts([_trade("AGAE", "public", "p1")])
    task = lifecycle.sell_worklist(
        [_row("AGAE", "fractional", sell_symbol="AIFA")], held)[0]
    assert task.symbol == "AIFA"           # what the order says
    assert task.alert_symbol == "AGAE"     # what we hold
    assert task.brokers == ("Public",)


# ------------------------------------------------------------------ the guards

class _App:
    """The decision half of the app, with the real methods bound to it."""

    def __init__(self, tmp, enabled=True, dry=True, roundups=False, sold=(),
                 market="open", in_flight=False):
        self._autosell_enabled = _Var(enabled)
        self._autosell_dry_run = _Var(dry)
        self._autosell_roundups = _Var(roundups)
        self._autosell_sold = set(sold)
        self._autosell_queue = []
        self._trade_in_flight = in_flight
        self._track_rows = []
        self.logs = []
        self.notes = []
        self.pumped = 0
        self._market = market
        self._statefile = tmp / "autosell_state.json"

        cls = desktop_app.App
        for name in ("_autosell_consider", "_autosell_key", "_save_autosell_state"):
            setattr(self, name, types.MethodType(getattr(cls, name), self))

    # the bits _autosell_consider leans on
    def _log(self, msg, tag=None):
        self.logs.append(msg)

    def _push_notification(self, msg, kind="info"):
        self.notes.append((msg, kind))

    def _autosell_pump(self):
        self.pumped += 1

    def after(self, ms, fn=None):
        return None


@pytest.fixture()
def make_app(tmp_path, monkeypatch):
    def _factory(**kw):
        monkeypatch.setattr(desktop_app, "AUTOSELL_STATE_FILE",
                            tmp_path / "autosell_state.json")
        market = kw.pop("market", "open")
        monkeypatch.setattr(desktop_app, "_market_status",
                            lambda: (market, market.title(), None))
        return _App(tmp_path, market=market, **kw)
    return _factory


def _fractional_change(symbol="GRNQ", alert_date="2026-08-06"):
    """A transition that just crossed into fractional."""
    return types.SimpleNamespace(
        symbol=symbol, alert_date=alert_date, became_fractional=True,
        became_sellable=True, new_status="fractional",
    )


def _setup(app, symbol="GRNQ", status="fractional"):
    app._track_rows = [_row(symbol, status)]
    import lifecycle as lc
    held = {symbol: {"Public": 3, "Robinhood": 2}}
    orig = lc.held_accounts
    lc.held_accounts = lambda trades=None: held
    try:
        app._autosell_consider([_fractional_change(symbol)])
    finally:
        lc.held_accounts = orig


def test_disarmed_does_absolutely_nothing(make_app):
    app = make_app(enabled=False)
    _setup(app)
    assert app._autosell_queue == []
    assert app.pumped == 0


def test_armed_queues_the_play_and_starts_the_pump(make_app):
    app = make_app()
    _setup(app)
    assert [t.symbol for t in app._autosell_queue] == ["GRNQ"]
    assert app.pumped == 1


def test_a_closed_market_holds_rather_than_selling(make_app):
    """A market order into a closed book is how you discover what a wide spread
    costs. It is not dropped — the next pull inside the session takes it."""
    app = make_app(market="closed")
    _setup(app)
    assert app._autosell_queue == []
    assert any("holding until the open" in m for m in app.logs)


def test_pre_market_also_holds(make_app):
    app = make_app(market="pre")
    _setup(app)
    assert app._autosell_queue == []


def test_a_play_already_sold_is_never_sold_again(make_app):
    """The board re-reports rows, pulls repeat hourly, and the app restarts.
    None of those may place a second order."""
    app = make_app(sold=["2026-08-06:GRNQ"])
    _setup(app)
    assert app._autosell_queue == []


def test_only_fractionals_unless_round_ups_are_opted_into(make_app):
    app = make_app(roundups=False)
    app._track_rows = [_row("HCWB", "rounded_up")]
    change = types.SimpleNamespace(
        symbol="HCWB", alert_date="2026-08-06", became_fractional=False,
        became_sellable=True, new_status="rounded_up")
    import lifecycle as lc
    orig = lc.held_accounts
    lc.held_accounts = lambda trades=None: {"HCWB": {"Public": 1}}
    try:
        app._autosell_consider([change])
    finally:
        lc.held_accounts = orig
    assert app._autosell_queue == []


def test_a_flood_is_capped_and_says_what_it_held_back(make_app):
    """Fifteen plays resolving in one pull is a board that changed shape, not
    fifteen corporate actions. Selling the lot is unrecoverable; the cap is."""
    app = make_app()
    symbols = [f"SYM{i}" for i in range(9)]
    app._track_rows = [_row(s, "fractional") for s in symbols]
    changes = [_fractional_change(s) for s in symbols]
    import lifecycle as lc
    orig = lc.held_accounts
    lc.held_accounts = lambda trades=None: {s: {"Public": 1} for s in symbols}
    try:
        app._autosell_consider(changes)
    finally:
        lc.held_accounts = orig
    assert len(app._autosell_queue) == desktop_app.AUTOSELL_MAX_PER_PULL
    assert any("held back" in m for m, _ in app.notes)


def test_the_sold_list_survives_a_restart(make_app, tmp_path):
    """It is the only thing standing between a restart and a second order."""
    app = make_app(sold=["2026-08-06:GRNQ"])
    app._save_autosell_state()
    saved = json.loads((tmp_path / "autosell_state.json").read_text(encoding="utf-8"))
    assert "2026-08-06:GRNQ" in saved["sold"]
    assert saved["enabled"] is True


# -------------------------------------------- against the REAL Transition
# Everything above drives _autosell_consider with a stand-in, which is fine for
# the branching and useless for this: these are properties of the real object,
# and a stand-in that happens to have the right attributes proves nothing about
# whether the real one does.

def _real_changes(board_before, board_after):
    """Run two real pulls and return the transitions the second produced."""
    import rsa_feed
    from datetime import date
    today = date(2026, 8, 6)
    state, _ = lifecycle.apply(
        rsa_feed.parse_lifecycle_message({"content": board_before}, today=today),
        {"rows": {}})
    _, changes = lifecycle.apply(
        rsa_feed.parse_lifecycle_message({"content": board_after}, today=today),
        state)
    return changes


PENDING = "\U0001f514 8/6 - GRNQ ⏳"
FRACTIONAL = "\U0001f514 8/6 - GRNQ \U0001f9e9"


def test_the_transition_really_carries_what_auto_sell_reads_off_it():
    """_autosell_consider keys on c.alert_date and c.symbol. If either were
    missing the pull handler would swallow the AttributeError and auto-sell
    would silently never fire — the worst possible failure for this feature."""
    c = _real_changes(PENDING, FRACTIONAL)[0]
    assert c.alert_date == "2026-08-06"
    assert c.symbol == "GRNQ"
    assert c.became_fractional


def test_the_first_pull_on_a_fresh_install_sells_nothing(make_app):
    """A cold start sees the whole board at once — 80-odd rows, many already
    fractional. They are seeded, not changed, and auto-selling the lot on first
    launch would be catastrophic and completely automatic."""
    import rsa_feed
    from datetime import date
    _, changes = lifecycle.apply(
        rsa_feed.parse_lifecycle_message({"content": FRACTIONAL},
                                         today=date(2026, 8, 6)),
        {"rows": {}})
    assert changes and all(c.seeded for c in changes)
    assert not any(c.became_fractional for c in changes)

    app = make_app()
    app._track_rows = [_row("GRNQ", "fractional")]
    orig = lifecycle.held_accounts
    lifecycle.held_accounts = lambda trades=None: {"GRNQ": {"Public": 3}}
    try:
        app._autosell_consider(changes)
    finally:
        lifecycle.held_accounts = orig
    assert app._autosell_queue == []


def test_cash_in_lieu_is_never_sold():
    """It resolved to CASH. There is no position, so an order would be rejected
    at best and sell something else at worst."""
    assert lifecycle.brokers_for("cash_in_lieu") == ()
    assert lifecycle.sell_worklist(
        [_row("ALUR", "cash_in_lieu")], {"ALUR": {"Public": 3}}) == []


def test_a_play_still_pending_is_never_sold():
    """The split has not happened. Nothing has come back to sell."""
    assert lifecycle.brokers_for("pending") == ()
    assert lifecycle.sell_worklist(
        [_row("HCWB", "pending")], {"HCWB": {"Public": 3}}) == []


def test_the_sweep_catches_what_auto_sell_structurally_cannot(make_app):
    """Auto-sell fires on a TRANSITION, so a position that was already
    fractional when you armed it is never picked up — `became_fractional` is
    false for a row that did not just move. Without the sweep the day-one
    backlog sits there forever while every new play sails past it."""
    app = make_app()
    for name in ("_autosell_sweep", "_autosell_sweep_disarm"):
        setattr(app, name, types.MethodType(getattr(desktop_app.App, name), app))
    app._sweep_btn = types.SimpleNamespace(configure=lambda **kw: None)
    app._track_rows = [_row("GRNQ", "fractional"), _row("HCWB", "rounded_up")]

    orig = lifecycle.held_accounts
    lifecycle.held_accounts = lambda trades=None: {"GRNQ": {"Public": 3},
                                                   "HCWB": {"Public": 1}}
    try:
        # No transitions at all — auto-sell has nothing to react to.
        app._autosell_consider([])
        assert app._autosell_queue == []

        app._autosell_sweep()                 # first click arms
        assert app._autosell_queue == []
        app._autosell_sweep()                 # second click fires
    finally:
        lifecycle.held_accounts = orig

    # GRNQ only: the sweep is for fractionals, and a round-up is not one.
    assert [t.symbol for t in app._autosell_queue] == ["GRNQ"]


def test_the_sweep_will_not_fire_on_one_click(make_app):
    """It can queue a whole backlog at once, so it states the count and waits."""
    app = make_app()
    for name in ("_autosell_sweep", "_autosell_sweep_disarm"):
        setattr(app, name, types.MethodType(getattr(desktop_app.App, name), app))
    seen = []
    app._sweep_btn = types.SimpleNamespace(configure=lambda **kw: seen.append(kw))
    app._track_rows = [_row("GRNQ", "fractional")]
    orig = lifecycle.held_accounts
    lifecycle.held_accounts = lambda trades=None: {"GRNQ": {"Public": 3}}
    try:
        app._autosell_sweep()
    finally:
        lifecycle.held_accounts = orig
    assert app._autosell_queue == []
    assert any("Confirm" in (kw.get("text") or "") for kw in seen)


def test_the_sweep_respects_market_hours(make_app):
    app = make_app(market="closed")
    for name in ("_autosell_sweep", "_autosell_sweep_disarm"):
        setattr(app, name, types.MethodType(getattr(desktop_app.App, name), app))
    app._sweep_btn = types.SimpleNamespace(configure=lambda **kw: None)
    app._track_rows = [_row("GRNQ", "fractional")]
    orig = lifecycle.held_accounts
    lifecycle.held_accounts = lambda trades=None: {"GRNQ": {"Public": 3}}
    try:
        app._autosell_sweep()
        app._autosell_sweep()
    finally:
        lifecycle.held_accounts = orig
    assert app._autosell_queue == []


def test_the_sweep_skips_what_was_already_sold(make_app):
    """Same record auto-sell uses, so the two cannot double up on each other."""
    app = make_app(sold=["2026-08-06:GRNQ"])
    for name in ("_autosell_sweep", "_autosell_sweep_disarm"):
        setattr(app, name, types.MethodType(getattr(desktop_app.App, name), app))
    app._sweep_btn = types.SimpleNamespace(configure=lambda **kw: None)
    app._track_rows = [_row("GRNQ", "fractional")]
    orig = lifecycle.held_accounts
    lifecycle.held_accounts = lambda trades=None: {"GRNQ": {"Public": 3}}
    try:
        app._autosell_sweep()
        app._autosell_sweep()
    finally:
        lifecycle.held_accounts = orig
    assert app._autosell_queue == []


def test_a_play_is_handed_back_when_it_could_not_be_read(make_app):
    """The claim is taken BEFORE the holdings read, because claiming after the
    order risks selling twice. The price of that is that anything failing in
    between would strand the play as 'sold' and it would never sell at all.

    A broker we could not READ is unknown, not empty: a dead session says
    nothing about whether the shares are there."""
    app = make_app()
    app._autosell_retry = types.MethodType(desktop_app.App._autosell_retry, app)
    task = lifecycle.SellTask(
        symbol="GRNQ", alert_symbol="GRNQ", alert_date="2026-08-06",
        status="fractional", brokers=("Public",), accounts=3, skipped_brokers=(),
    )
    app._autosell_sold.add("2026-08-06:GRNQ")
    app._autosell_retry(task, "session dead")
    assert "2026-08-06:GRNQ" not in app._autosell_sold


def test_a_renamed_play_is_keyed_by_what_we_bought(make_app):
    """AGAE -> AIFA is one position. Keyed on the sell symbol it could be sold
    once under each name."""
    app = make_app()
    task = lifecycle.SellTask(
        symbol="AIFA", alert_symbol="AGAE", alert_date="2026-07-02",
        status="fractional", brokers=("Public",), accounts=1, skipped_brokers=(),
    )
    assert app._autosell_key(task) == "2026-07-02:AGAE"
