"""The public Plays board: one shared password, no account, all the detail.

Three things are worth pinning here, and they are the three that would quietly
ruin the page if they broke:

  1. The gate holds. An unset password locks everyone out rather than letting
     everyone in, and a wrong guess is throttled.
  2. Nobody has to sign up. A stranger with the password sees the same board a
     paying customer does.
  3. The board states outcomes, not just alerts. What the split DID to a play is
     the only evidence the product works, so the history must carry the losses
     as well as the round-ups.
"""
from __future__ import annotations

import copy
import os
import pathlib
import re
import sys
import tempfile
from datetime import date

import pytest

WEB_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WEB_ROOT))

_TMP_DB = pathlib.Path(tempfile.gettempdir()) / "rsamaxxed_plays_public.sqlite3"
_TMP_DB.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB.as_posix()}"
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["ENV"] = "development"

from fastapi.testclient import TestClient  # noqa: E402

from app import config  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.routes import plays as plays_routes  # noqa: E402

PASSWORD = "test-board-password"
KEY = {"X-Feed-Key": "test-feed-key"}


@pytest.fixture(scope="module", autouse=True)
def _schema():
    init_db()
    yield
    engine.dispose()
    _TMP_DB.unlink(missing_ok=True)


@pytest.fixture()
def anon(monkeypatch):
    """A stranger's browser. Config is read at import, so patch the resolved
    values (same reason as test_lifecycle_feed) rather than the environment."""
    monkeypatch.setattr(config, "PLAYS_PASSWORD", PASSWORD)
    monkeypatch.setattr(config, "FEED_INGEST_KEY", "test-feed-key")
    # The dev default points at the operator's live picks.json; a test must not
    # depend on what happens to be in it today.
    monkeypatch.setattr(config, "PICKS_FILE", "")
    plays_routes._attempts.clear()
    return TestClient(app)


def _csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "the form carries no CSRF token"
    return m.group(1)


def _unlock(client: TestClient, password: str = PASSWORD):
    gate = client.get("/plays")
    return client.post("/plays", data={"password": password, "csrf_token": _csrf(gate.text)})


# ------------------------------------------------------------------ the gate

def test_the_board_is_not_visible_without_the_password(anon):
    r = anon.get("/plays")
    assert r.status_code == 200
    assert 'name="password"' in r.text        # the gate
    assert 'class="board"' not in r.text      # not the board


def test_the_right_password_opens_it_and_the_browser_stays_open(anon):
    r = _unlock(anon)
    assert r.status_code == 200
    assert 'name="password"' not in r.text

    # And it is remembered, so nobody types it twice.
    again = anon.get("/plays")
    assert again.status_code == 200
    assert 'name="password"' not in again.text


def test_a_wrong_password_says_so_and_shows_nothing(anon):
    r = _unlock(anon, "not-the-password")
    assert "Wrong password" in r.text
    assert 'name="password"' in r.text
    assert 'class="board"' not in r.text


def test_an_unset_password_locks_everyone_out_rather_than_letting_them_in(anon, monkeypatch):
    """The failure mode of forgetting the variable must never be an open door."""
    monkeypatch.setattr(config, "PLAYS_PASSWORD", "")
    r = _unlock(anon, "")
    assert 'name="password"' in r.text
    assert "not configured" in r.text


def test_guessing_is_throttled(anon):
    for _ in range(config.PLAYS_MAX_ATTEMPTS):
        _unlock(anon, "wrong")
    blocked = _unlock(anon, "wrong")
    assert "Too many attempts" in blocked.text
    # And the throttle outranks a correct guess, so it can't be probed around.
    assert "Too many attempts" in _unlock(anon).text


def test_locking_forgets_the_password_on_this_browser(anon):
    page = _unlock(anon)
    anon.post("/plays/lock", data={"csrf_token": _csrf(page.text)})
    assert 'name="password"' in anon.get("/plays").text


def test_the_password_is_remembered_across_visits(anon):
    """Nobody should retype a shared password every time they open the page."""
    r = _unlock(anon)
    cookie = r.cookies.get("rsamaxxed_plays") or anon.cookies.get("rsamaxxed_plays")
    assert cookie, "the board was never remembered"

    # A brand-new browser session carrying only that cookie still gets in —
    # this is what survives a browser restart, where the session cookie doesn't.
    later = TestClient(app, cookies={"rsamaxxed_plays": cookie})
    assert 'name="password"' not in later.get("/plays").text
    assert later.get("/api/v1/public/plays").status_code == 200


def test_changing_the_password_forgets_every_browser(anon, monkeypatch):
    """The only revocation a shared password has. If old cookies survived a
    password change, changing it would accomplish nothing."""
    _unlock(anon)
    cookie = anon.cookies.get("rsamaxxed_plays")
    monkeypatch.setattr(config, "PLAYS_PASSWORD", "a-brand-new-password")
    stale = TestClient(app, cookies={"rsamaxxed_plays": cookie})
    assert 'name="password"' in stale.get("/plays").text
    assert stale.get("/api/v1/public/plays").status_code == 401


def test_the_calculator_remembers_the_account_count():
    """Client-side, so it survives a visit without anything about the reader
    reaching the server."""
    with TestClient(app) as c:
        js = c.get("/static/js/site.js").text
    assert "rsamaxxed.accounts" in js
    assert "localStorage" in js


def test_a_signed_in_customer_never_meets_the_gate(anon):
    """They already identified themselves. Asking a paying account for a second,
    weaker secret is friction that protects nothing."""
    browser = TestClient(app)
    page = browser.get("/signup?plan=plays")
    browser.post("/signup", data={"email": "member@example.com",
                                  "password": "correct-horse-battery",
                                  "plan": "plays", "csrf_token": _csrf(page.text)})
    board = browser.get("/plays")
    assert board.status_code == 200
    assert 'name="password"' not in board.text
    # And their session reads the feed API without carrying the key around.
    assert browser.get("/api/v1/public/plays").status_code == 200


def test_the_old_dashboard_url_still_lands_on_the_board(anon):
    r = anon.get("/app/plays", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] == "/plays"


def test_a_logged_out_visitor_is_told_the_board_exists(anon):
    """A password nobody can find the door for is not a product."""
    assert '<a href="/plays"' in anon.get("/").text


# ------------------------------------------------------- what the board shows

@pytest.fixture()
def board(anon):
    """Publish one alert of each outcome, then open the board."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={
        "buys": [
            {"source_id": "t:1", "symbol": "HCWB", "kind": "standard",
             "alert_date": "2026-08-01", "ratio": "1:15", "ratio_n": 15,
             "entry_price": 0.25, "est_profit": 3.5, "last_buy_date": "2099-01-01",
             "roundup_history": "3/3 rounded up", "strategy": "1 Share/Account"},
            {"source_id": "t:2", "symbol": "AGAE", "kind": "otc",
             "alert_date": "2026-07-02", "ratio": "1:20", "entry_price": 0.4,
             "last_buy_date": "2026-07-04"},
            {"source_id": "t:3", "symbol": "NUKK", "kind": "standard",
             "alert_date": "2026-07-03", "last_buy_date": "2026-07-05"},
        ],
        "sells": [
            {"source_id": "t:s1", "symbol": "AGAE", "sell_date": "2026-07-20",
             "exit_price": 6.1, "proceeds_low": 47.5, "proceeds_high": 61.0,
             "legs": [{"broker": "Robinhood", "accounts_low": 3, "accounts_high": 3}],
             "note": "sold across every account"},
        ],
        "roundups": [{"source_id": "t:r1", "symbol": "AGAE", "confirmed_date": "2026-07-18"}],
        "lifecycle": [
            {"source_id": "2026-07-02:AGAE", "symbol": "AGAE", "sell_symbol": "AIFA",
             "alert_date": "2026-07-02", "status": "rounded_up", "kind": "otc"},
            {"source_id": "2026-07-03:NUKK", "symbol": "NUKK", "sell_symbol": "NUKK",
             "alert_date": "2026-07-03", "status": "cash_in_lieu", "kind": "standard"},
            {"source_id": "2026-08-01:HCWB", "symbol": "HCWB", "sell_symbol": "HCWB",
             "alert_date": "2026-08-01", "status": "pending", "kind": "standard"},
        ],
    })
    return _unlock(anon).text


def test_open_plays_carry_every_detail_the_alert_gave_us(board):
    assert "HCWB" in board
    for fact in ("1:15", "$0.25", "1 Share/Account", "3/3 rounded up"):
        assert fact in board, f"the open play lost {fact!r}"


def test_the_history_reports_what_the_split_actually_did(board):
    """Including the outcomes nobody wants to advertise."""
    assert "Rounded up" in board
    assert "Cash in lieu" in board, "the record hides the bad outcomes"
    assert "Split pending" in board


def test_the_history_names_the_post_split_ticker(board):
    """AGAE holdings can only be sold as AIFA. Getting this wrong means an
    order that can never fill."""
    assert "AIFA" in board


def test_exits_carry_price_proceeds_and_the_brokers_they_ran_in(board):
    assert "$6.10" in board            # exit price
    assert "$47.50" in board           # proceeds, low end of the range
    assert "Robinhood" in board


def test_the_page_states_when_the_feed_last_changed(board):
    """A board with no freshness stamp cannot be distinguished from a dead one."""
    assert "Updated" in board


def test_the_risk_language_survives(board):
    flat = re.sub(r"\s+", " ", board)
    for phrase in ("not advice", "you can lose money", "varies by broker"):
        assert phrase in flat, f"the disclaimer lost {phrase!r}"


def test_the_board_makes_no_promise(board):
    flat = re.sub(r"\s+", " ", board).lower()
    for weasel in ("guaranteed", "risk-free", "riskless"):
        assert weasel not in flat


def test_the_five_sections_are_tabs_that_work_without_javascript(board):
    """CSS tabs, not scripted ones: the CSP forbids inline script, and a board
    someone paid for must render with JS blocked."""
    for tab in ("tab-dash", "tab-cal", "tab-buys", "tab-sells", "tab-track"):
        assert f'id="{tab}"' in board, f"the {tab} tab went missing"
        assert f'for="{tab}"' in board, f"the {tab} tab has no label to click"
    assert board.count('type="radio" name="ptab"') == 5
    # Every pane is in the HTML — tabs hide, they don't defer-load.
    for pane in ("p-dash", "p-cal", "p-buys", "p-sells", "p-track"):
        assert f'class="pane {pane}' in board


def test_the_dashboard_reads_before_javascript_runs(board):
    """Charts need a script; numbers must not. Everything is server-rendered
    against a stated basis of one account per broker, so a reader with JS
    blocked still gets real figures and a table."""
    flat = re.sub(r"\s+", " ", board)
    assert "Theoretical profit" in flat
    assert "1 account at each broker" in flat
    assert 'id="monthly-table"' in board          # the table view twin
    assert "never a forecast" in flat             # and it says what it isn't


def test_the_settings_gear_offers_every_broker(board):
    """The account counts are the multiplier for the whole dashboard, so all ten
    brokers have to be settable — and the three that hold fractions marked."""
    for key in ("bbae", "chase", "dspac", "fennel", "fidelity",
                "public", "robinhood", "schwab", "sofi", "wellsfargo"):
        assert f'data-broker="{key}"' in board, f"no account input for {key}"
    assert board.count('data-broker=') == 10


def test_a_broker_named_by_an_alert_can_be_told_apart_from_yours(board):
    """The Sells and Tracking tabs list the brokers the ALERT named, with the
    ALERTER's account counts. Unmarked, "Schwab x1" on an exit reads as "you
    hold one Schwab account" — and the profit figures have always excluded it,
    so the page was contradicting its own arithmetic."""
    from app.playsfeed import broker_key

    # The fixture's exit is at Robinhood, and it is tagged.
    assert 'data-broker-tag="robinhood"' in board

    # The tag has to be spelled exactly as broker_key spells it, or the browser
    # looks the wrong name up in the account profile, finds nothing, and marks a
    # broker you DO hold as unheld — the same bug pointing the other way.
    tags = set(re.findall(r'data-broker-tag="([^"]*)"', board))
    assert tags, "no broker on the page is tagged at all"
    for name in ("Robinhood", "Wells Fargo", "Chase", "Public"):
        assert broker_key(name) not in ("", None)
    assert all(t == broker_key(t) for t in tags), (
        f"tags that broker_key would spell differently: "
        f"{[t for t in tags if t != broker_key(t)]}")


def test_the_calendar_marks_the_days_a_window_shuts(board):
    """A deadline you can't see is a deadline you miss."""
    assert 'class="calgrid"' in board
    assert 'data-day=' in board


# ------------------------------------------------- marking what you've bought
# The one piece of state on this board that belongs to the READER. Eleven open
# alerts look identical to someone who acted on four of them yesterday.

def test_every_open_play_can_be_ticked_off(board):
    """Otherwise the list can't answer the question it exists to answer: which
    of these have I not bought yet."""
    assert board.count('class="ownbox"') >= 1
    assert 'aria-label="Mark HCWB as bought"' in board


def test_a_mark_is_keyed_to_the_alert_and_not_to_a_row_id(board):
    """The deploy runs an ephemeral database and re-ingests the feed, so row ids
    move under a browser that is still holding notes. date:SYMBOL doesn't."""
    assert 'data-play="2026-08-01:HCWB"' in board


def test_a_mark_carries_the_post_split_ticker_too(anon):
    """A reverse split renames the company. An exit published under the new
    ticker still has to match the alert that was ticked under the old one, so
    the mark carries both names."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={
        "buys": [{"source_id": "rn:1", "symbol": "OLDCO", "kind": "standard",
                  "alert_date": "2026-08-02", "last_buy_date": "2099-01-01"}],
        "lifecycle": [{"source_id": "2026-08-02:OLDCO", "symbol": "OLDCO",
                       "sell_symbol": "NEWCO", "alert_date": "2026-08-02",
                       "status": "rounded_up", "kind": "standard"}],
    })
    assert 'data-syms="OLDCO,NEWCO"' in _unlock(anon).text


def test_exits_say_which_symbol_and_day_they_closed(board):
    """What lets the Sells tab flag the exits that close something you marked
    bought — and the date is what stops it flagging the ticker's PREVIOUS
    reverse split, which you never held."""
    assert 'data-sym="AGAE"' in board
    assert 'data-sold="2026-07-20"' in board


def test_the_open_list_is_addressable_apart_from_the_closed_one(board):
    """'How many are left to buy' must never count a window that already shut."""
    assert 'id="open-plays"' in board


def test_the_marks_never_reach_the_server():
    """There is no account behind this board — one shared password identifies
    nobody — so a note about what someone bought has nowhere to live but their
    own browser, and no business anywhere else."""
    with TestClient(app) as c:
        js = c.get("/static/js/site.js").text
    assert "rsamaxxed.bought" in js
    assert "localStorage" in js
    # The page does make one request — it polls the feed for new alerts — so
    # "no network at all" is no longer the guarantee. This is: nothing is ever
    # UPLOADED. No request body, no verb but the default GET, no beacon. There
    # is therefore no path by which a mark could leave the browser.
    for upload in ("body:", "method:", "sendBeacon", "XMLHttpRequest", "FormData"):
        assert upload not in js, f"site.js can send data to the server via {upload}"


# --------------------------------------------------- the new-alert chime

def test_the_board_offers_a_chime_and_leaves_it_off(board):
    """A browser refuses to make a sound until the page has been clicked, so an
    'on by default' toggle would be a lie on first load. The click that turns it
    on is the gesture that makes audio legal in the first place."""
    assert 'id="sound-toggle"' in board
    assert 'aria-pressed="false"' in board
    assert "Chime off" in board


def test_an_open_tab_learns_about_new_alerts_without_being_reloaded():
    """The board is a server-rendered snapshot — without a poll, a tab left open
    all day would never find out that anything had landed."""
    with TestClient(app) as c:
        js = c.get("/static/js/site.js").text
    assert "/api/v1/public/plays" in js
    assert "setInterval(poll" in js


def test_the_poll_reads_the_feed_off_the_same_cookie_the_board_uses(anon):
    """No key in the JavaScript: the page is already through the gate, and the
    feed door accepts that. A password pasted into a static asset would be
    published to everyone who can read the asset — which is everyone."""
    _unlock(anon)
    assert anon.get("/api/v1/public/plays").status_code == 200

    stranger = TestClient(app)
    assert stranger.get("/api/v1/public/plays").status_code == 401

    with TestClient(app) as c:
        js = c.get("/static/js/site.js").text
    assert PASSWORD not in js
    assert "credentials: 'same-origin'" in js


def test_the_chime_needs_no_audio_file():
    """default-src 'self' forbids a data: URI for media, and a served sound file
    would be one more asset to cache-bust. It is synthesised instead."""
    with TestClient(app) as c:
        js = c.get("/static/js/site.js").text
        csp = c.get("/plays").headers["content-security-policy"]
    assert "createOscillator" in js
    assert "<audio" not in js
    assert "media-src" not in csp        # nothing had to be loosened for it


def test_the_checkbox_is_hidden_until_the_script_that_makes_it_work_has_run():
    """Every other control on this board works with JavaScript blocked. This one
    cannot — so it must be absent rather than present and quietly amnesiac."""
    with TestClient(app) as c:
        css = c.get("/static/css/site.css").text
        js = c.get("/static/js/site.js").text
    assert ".own,.markbar{display:none}" in css
    assert "html.js .own" in css
    assert "classList.add('js')" in js


def test_a_parser_bug_in_a_note_can_be_corrected(anon):
    """An exit's note is the ONE field ingest may rewrite.

    Price, date and brokers are facts the alerter published, and insert-only is
    what makes them unforgeable. A note is this parser's reading of the prose
    around them — so a parser bug writes a caption that no amount of
    republishing can take back. It happened: a missing "+" on one total line
    published "$159.84**" against two unrelated tickers.
    """
    payload = {"sells": [{"source_id": "note:1", "symbol": "BYAH",
                          "sell_date": "2026-08-07", "exit_price": 3.22,
                          "proceeds_low": 19.32, "note": "$159.84**",
                          "legs": [{"broker": "Chase", "accounts_low": 6,
                                    "accounts_high": 6}]}]}
    assert anon.post("/api/v1/plays/ingest", headers=KEY,
                     json=payload).json()["inserted"]["sells"] == 1

    payload["sells"][0]["note"] = ""
    again = anon.post("/api/v1/plays/ingest", headers=KEY, json=payload).json()
    assert again["inserted"]["sells"] == 0        # nothing republished
    assert again["inserted"]["notes"] == 1        # the caption was repaired

    board = _board_of(anon)
    row = next(e for e in board.exits if e.source_id == "note:1")
    assert row.note == ""
    # And the facts are untouched by the correction.
    assert row.exit_price == 3.22 and row.proceeds_low == 19.32


def test_the_money_on_an_exit_can_never_be_rewritten(anon):
    """The other half of that promise. Re-sending an exit with a different
    price must change nothing — otherwise anyone holding the ingest key could
    restate what a play was worth after the fact."""
    first = {"sells": [{"source_id": "immutable:1", "symbol": "ZZTOP",
                        "sell_date": "2026-08-07", "exit_price": 1.00,
                        "proceeds_low": 10.0, "legs": []}]}
    anon.post("/api/v1/plays/ingest", headers=KEY, json=first)

    tampered = copy.deepcopy(first)
    tampered["sells"][0]["exit_price"] = 999.0
    tampered["sells"][0]["proceeds_low"] = 9990.0
    anon.post("/api/v1/plays/ingest", headers=KEY, json=tampered)

    row = next(e for e in _board_of(anon).exits if e.source_id == "immutable:1")
    assert row.exit_price == 1.00
    assert row.proceeds_low == 10.0


# ------------------------------------------------------ the payout arithmetic
# The rule the whole dashboard rests on, and the one the naive version got
# wrong: a play pays YOUR accounts AT THE BROKERS IT ACTUALLY PAID IN. Not
# "per-account profit x total accounts".

def _board_of(anon):
    from app.db import SessionLocal
    from app import playsfeed
    db = SessionLocal()
    try:
        return playsfeed.load_board(db)
    finally:
        db.close()


@pytest.fixture()
def payouts(anon):
    """One play sold only at Chase, one that rounded up with no exit yet, and
    one that came back fractional."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={
        "buys": [
            {"source_id": "p:1", "symbol": "ONLYCHASE", "alert_date": "2026-07-10",
             "ratio": "1:11", "entry_price": 1.0, "last_buy_date": "2026-07-11"},
            {"source_id": "p:2", "symbol": "WHOLE", "alert_date": "2026-07-10",
             "ratio": "1:11", "entry_price": 1.0, "last_buy_date": "2026-07-11"},
            {"source_id": "p:3", "symbol": "FRAC", "alert_date": "2026-07-10",
             "ratio": "1:11", "entry_price": 1.0, "last_buy_date": "2026-07-11"},
        ],
        "sells": [
            {"source_id": "p:s1", "symbol": "ONLYCHASE", "sell_date": "2026-07-20",
             "exit_price": 11.0, "proceeds_low": 10.0,
             "legs": [{"broker": "Chase", "accounts_low": 1, "accounts_high": 1}]},
        ],
        "roundups": [
            {"source_id": "p:r1", "symbol": "ONLYCHASE", "confirmed_date": "2026-07-18"},
            {"source_id": "p:r2", "symbol": "WHOLE", "confirmed_date": "2026-07-18"},
        ],
        "lifecycle": [
            {"source_id": "2026-07-10:ONLYCHASE", "symbol": "ONLYCHASE",
             "alert_date": "2026-07-10", "status": "rounded_up", "kind": "standard"},
            {"source_id": "2026-07-10:WHOLE", "symbol": "WHOLE",
             "alert_date": "2026-07-10", "status": "rounded_up", "kind": "standard"},
            {"source_id": "2026-07-10:FRAC", "symbol": "FRAC",
             "alert_date": "2026-07-10", "status": "fractional", "kind": "standard"},
        ],
    })
    board = _board_of(anon)
    return {r["sym"]: r for r in board.payout_rows}, board


def _expected(board, acc):
    """The rule, written out longhand, to check the engine against."""
    return sum(r["per"] * sum(acc.get(b, 0) for b in r["brokers"])
               for r in board.payout_rows)


def test_only_brokers_with_a_confirmed_sell_pay(payouts):
    """A round-up is per broker, not per play. 'Rounded up' on the TRACK board
    means it rounded up SOMEWHERE — Wells Fargo turning a fraction into a whole
    share says nothing about what Fidelity did with the same position. Only the
    sell alert names brokers, so only those brokers pay."""
    rows, _ = payouts
    assert rows["ONLYCHASE"]["brokers"] == ["chase"]


def test_a_roundup_nobody_has_sold_yet_pays_nothing(payouts):
    """WHOLE rounded up and has no exit. Until a sell alert names the brokers it
    actually cleared at, it is worth nothing on a figure the page calls
    confirmed — the conservative direction, deliberately."""
    rows, board = payouts
    assert "WHOLE" not in rows
    assert not any(r["sym"] == "WHOLE" for r in board.payout_rows)


def test_a_fractional_play_with_no_exit_pays_nothing(payouts):
    """Same rule, and it matters more here: a fraction only exists at three
    brokers to begin with, and even there it has to be sold to be worth
    anything."""
    rows, _ = payouts
    assert "FRAC" not in rows


def test_the_tracker_still_reports_what_it_knows(payouts):
    """The outcome stats keep every play, sold or not — the record is the
    record. It is only the MONEY that waits for a confirmed sell."""
    _, board = payouts
    statuses = {s for s, _, _ in board.history_by_status}
    assert "rounded_up" in statuses and "fractional" in statuses


def test_the_board_ships_what_buying_everything_would_have_cost(payouts):
    """payout_rows is the winners. On its own it can only flatter — two thirds
    of resolved alerts come back fractional and pay this reader nothing — so a
    profit figure with no capital behind it has no denominator."""
    _rows, board = payouts
    cap = {r["sym"]: r for r in board.capital_rows}

    # All three cost money to buy, whatever they later did.
    for sym in ("ONLYCHASE", "WHOLE", "FRAC"):
        assert sym in cap, f"{sym} cost money and is missing from the cost side"
        assert cap[sym]["entry"] == 1.0

    # And only ONLYCHASE ever paid, which is the whole point of having both.
    paid = {r["sym"] for r in board.payout_rows}
    assert "ONLYCHASE" in paid
    assert {"WHOLE", "FRAC"} & paid == set()


def test_an_alert_nobody_could_have_bought_costs_nothing(anon):
    """A watch-only alert has no declared split, so nobody buys it. Counting
    its cost would invent capital that was never committed — which would
    understate the return exactly as badly as ignoring cost overstates it."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={
        "buys": [
            {"source_id": "cap:watch", "symbol": "WATCHME", "kind": "conditional",
             "alert_date": "2026-08-04", "entry_price": 2.0},
            {"source_id": "cap:noprice", "symbol": "NOPRICE", "kind": "standard",
             "alert_date": "2026-08-04", "last_buy_date": "2099-01-01"},
            {"source_id": "cap:real", "symbol": "REALBUY", "kind": "standard",
             "alert_date": "2026-08-04", "entry_price": 0.5,
             "last_buy_date": "2099-01-01"},
        ],
    })
    cap = {r["sym"] for r in _board_of(anon).capital_rows}
    assert "REALBUY" in cap
    assert "WATCHME" not in cap, "a watch-only alert was counted as capital"
    assert "NOPRICE" not in cap, "an alert with no price cannot be costed"


def test_the_totals_engine_multiplies_broker_by_broker(payouts):
    """Checked against the rule written out longhand, over several profiles —
    including lopsided ones, where a flat account count would diverge most."""
    _, board = payouts
    for acc in ({}, {"chase": 1}, {"robinhood": 10},
                {"chase": 2, "sofi": 3}, {"fidelity": 4, "public": 1, "chase": 1}):
        assert abs(board.totals(acc)["total"] - _expected(board, acc)) < 0.01, acc


def test_accounts_at_a_broker_you_do_not_use_add_nothing(payouts):
    """An empty profile pays nothing at all, and a broker set to zero is the
    same as not having it."""
    _, board = payouts
    assert board.totals({})["total"] == 0
    assert board.totals({"chase": 0})["total"] == 0
    assert board.totals({"chase": 2})["total"] == pytest.approx(
        board.totals({"chase": 1})["total"] * 2, rel=1e-6)


def test_totals_bucket_by_the_month_the_play_was_booked(payouts):
    """Not the month it was alerted. ONLYCHASE was alerted in July and sold
    2026-07-20, so it books to July — crediting it to the alert month would put
    payouts in the wrong month whenever a split straddles one."""
    _, board = payouts
    months = {m["key"] for m in board.totals({"chase": 1})["months"]}
    assert "2026-07" in months


def test_a_tracked_split_with_no_matching_alert_is_still_listed(anon):
    """A status with no buy alert behind it is exactly the case where someone is
    holding something and can't find out what happened to it."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={"lifecycle": [
        {"source_id": "2020-01-01:ORPHAN", "symbol": "ORPHAN", "sell_symbol": "ORPHAN",
         "alert_date": "2020-01-01", "status": "fractional", "kind": "standard"},
    ]})
    page = _unlock(anon).text
    assert "ORPHAN" in page
    assert "tracked without a matching alert" in page


# ------------------------------------------------- the account-free JSON door
# The feed is a paid tier. An HTML page behind a password whose JSON twin is
# wide open would be a gate with a hole cut in the wall beside it.

FEED_ROUTES = ("/api/v1/public/plays", "/api/v1/public/plays/picks",
               "/api/v1/public/plays/lifecycle")


@pytest.mark.parametrize("path", FEED_ROUTES)
def test_the_feed_api_is_not_readable_without_the_password(path, anon):
    assert anon.get(path).status_code == 401


@pytest.mark.parametrize("path", FEED_ROUTES)
def test_the_password_reads_the_feed_with_no_account(path, anon):
    """What a subscriber's terminal does: no signup, no pairing, just the key."""
    r = anon.get(path, headers={"X-Plays-Key": PASSWORD})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("path", FEED_ROUTES)
def test_an_unset_password_locks_the_feed_rather_than_opening_it(path, anon, monkeypatch):
    monkeypatch.setattr(config, "PLAYS_PASSWORD", "")
    assert anon.get(path, headers={"X-Plays-Key": "anything"}).status_code == 503


def test_a_browser_that_typed_the_password_can_read_the_json(anon):
    _unlock(anon)
    assert anon.get("/api/v1/public/plays").status_code == 200


def test_the_desktop_client_sends_the_key_it_is_given(monkeypatch):
    """The server half is useless if cloud_sync doesn't present the key."""
    import importlib.util

    # Loaded by path rather than imported: the repo root also holds app.py (the
    # tkinter GUI), and putting it on sys.path here would shadow the web app's
    # own `app` package.
    spec = importlib.util.spec_from_file_location(
        "cloud_sync_probe", WEB_ROOT.parent / "cloud_sync.py")
    cs = importlib.util.module_from_spec(spec)
    # Register before executing: @dataclass resolves its annotations through
    # sys.modules[cls.__module__], which is None for a module that isn't there.
    sys.modules[spec.name] = cs
    try:
        spec.loader.exec_module(cs)
    finally:
        sys.modules.pop(spec.name, None)

    monkeypatch.setenv("RSAMAXXED_PLAYS_KEY", PASSWORD)
    sent: dict = {}

    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return {"buys": []}

    def _fake_get(url, headers=None, timeout=None):
        sent["url"] = url
        sent["headers"] = headers or {}
        return _Resp()

    monkeypatch.setattr(cs.requests, "get", _fake_get)
    cs.CloudSync(base_url="https://example.invalid")._get_public("/plays")

    assert sent["headers"].get("X-Plays-Key") == PASSWORD
    assert sent["url"].endswith("/api/v1/public/plays")


# ------------------------------------------------------- the dashboard shape
#
# The Dashboard is drawn by site.js into hosts it finds by id, and rewritten
# against the reader's own account profile. Rename a host in the template and
# nothing errors — the chart just silently never appears. These pin the
# contract between the two files.

DASH_HOSTS = ("chart-monthly", "chart-brokers", "chart-outcomes", "hero-spark")


def test_the_dashboard_carries_every_chart_host_the_script_draws_into(board):
    for host in DASH_HOSTS:
        assert f'id="{host}"' in board, f"the script draws into #{host}; the page has no such node"


def test_the_dashboard_renders_its_figures_without_javascript(board):
    """Money is finished in the browser, but a real figure with a stated basis
    has to survive the script being blocked — that is the whole reason the
    server renders against one account per broker."""
    assert 'id="hero-total"' in board and "$" in board
    assert 'id="funnel"' in board and "data-base=" in board


def test_the_funnel_can_never_widen(board):
    """Each stage is a strict subset of the one before it. Widths are drawn as
    a share of the first stage, so a stage that grew would render an arrow
    pointing at a bar longer than its own parent — a picture that lies."""
    counts = [int(n) for n in re.findall(r'class="fv"[^>]*>(\d+)<', board)]
    assert len(counts) == 4, f"expected four funnel stages, found {len(counts)}"
    assert counts == sorted(counts, reverse=True), f"the funnel widens: {counts}"


def test_the_funnel_bars_never_exceed_full_width(board):
    for w in re.findall(r'class="ftrack">\s*<i[^>]*style="width:([\d.]+)%"', board):
        assert float(w) <= 100.0, f"a funnel stage drew itself at {w}% of the total"


# ------------------------------------------------- the funnel can never widen
#
# The Dashboard draws alerted -> sold -> priced -> paid as a funnel, each bar
# a share of the first. That picture is only honest while every stage is a
# subset of the one before it.
#
# The tempting third stage is "rounded up", and it is WRONG. A play that came
# back fractional and then sold at the three brokers that hold fractions pays
# real money while never being a round-up, so "paid" would exceed its own
# parent and the funnel would visibly widen. That is what these pin.

@pytest.fixture()
def fractional_sale(anon):
    """A fractional play that sold, beside a round-up that has not."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={
        "buys": [
            {"source_id": "fn:1", "symbol": "FRAC", "kind": "standard",
             "alert_date": "2026-07-01", "ratio": "1:20", "ratio_n": 20,
             "entry_price": 0.50, "last_buy_date": "2026-07-03"},
            {"source_id": "fn:2", "symbol": "WHOLE", "kind": "standard",
             "alert_date": "2026-07-02", "ratio": "1:10", "ratio_n": 10,
             "entry_price": 0.60, "last_buy_date": "2026-07-04"},
        ],
        "lifecycle": [
            {"source_id": "2026-07-01:FRAC", "symbol": "FRAC", "alert_date": "2026-07-01",
             "status": "fractional", "kind": "standard"},
            {"source_id": "2026-07-02:WHOLE", "symbol": "WHOLE", "alert_date": "2026-07-02",
             "status": "rounded_up", "kind": "standard"},
        ],
        "sells": [
            {"source_id": "fn:s1", "symbol": "FRAC", "sell_date": "2026-07-20",
             "exit_price": 10.0, "proceeds_low": 9.5,
             "legs": [{"broker": "Fennel", "accounts_low": 1}]},
        ],
    })
    return _board_of(anon)


def test_a_fractional_play_that_sold_pays_without_ever_being_a_round_up(fractional_sale):
    rounded = {l.play.symbol for l in fractional_sale.rounded_history}
    paying = {r["sym"] for r in fractional_sale.payout_rows}
    assert "FRAC" not in rounded, "the fixture stopped exercising the fractional path"
    assert "FRAC" in paying, "a fractional play sold at Fennel still pays"
    assert "WHOLE" not in paying, "a round-up with no exit must pay nothing"


def test_every_funnel_stage_contains_the_next(fractional_sale):
    alerted = len(fractional_sale.history)
    sold = len(fractional_sale.sold_history)
    priced = len(fractional_sale.payout_rows)
    paid = fractional_sale.totals()["plays"]
    assert alerted >= sold >= priced >= paid, (
        f"the funnel widens: alerted={alerted} sold={sold} priced={priced} paid={paid}")


def test_paid_is_not_a_subset_of_rounded_up(fractional_sale):
    """The stage this funnel deliberately does not use, kept as a test so the
    reason survives the next person who thinks it belongs there.

    Stated as the set relation rather than as a count: counts drift with
    whatever else the module has published by now, but "something pays that
    never rounded up" is the whole point and is true whatever else is here."""
    rounded = {l.play.symbol for l in fractional_sale.rounded_history}
    paying = {r["sym"] for r in fractional_sale.payout_rows}
    assert not paying <= rounded, (
        "every paying play happens to be a round-up here, so this test has "
        "stopped demonstrating why rounded-up cannot be the funnel's parent")


# ------------------------------------------------------------- this month
#
# The tile a reader checking back looks at first. It cannot be served by the
# period chips: those exist only for months that HAVE payouts, so that no chip
# can select nothing — and the month in progress is very often such a month,
# especially early in it, which is exactly when someone wants to see it.

def test_this_month_is_present_even_when_it_has_paid_nothing(payouts):
    _, board = payouts
    totals = board.totals(today=date(2099, 12, 25))
    assert totals["this_month"]["key"] == "2099-12"
    assert totals["this_month"]["total"] == 0.0, "a month with no payouts must read zero"
    assert totals["this_month"]["plays"] == 0
    assert totals["this_month"] not in totals["months"], \
        "an empty month must not be invented as a period chip"


def test_this_month_reports_that_month_and_not_the_whole_record(payouts):
    _, board = payouts
    months = board.totals()["months"]
    assert months, "the fixture stopped publishing anything payable"
    picked = months[0]
    totals = board.totals(today=date.fromisoformat(picked["key"] + "-15"))
    assert totals["this_month"]["total"] == pytest.approx(picked["total"])
    assert totals["this_month"]["total"] <= totals["total"] + 1e-9


# ------------------------------------------------- the two ingest paths
#
# An alert can reach the board two ways, and they key the SAME real alert
# differently: the publisher uses the Discord message id, picks.json uses
# picks:SYM:DATE. Deduping on source_id alone therefore lets one alert land
# twice — once complete from the publisher and once bare from the file, with a
# dash where its ratio, entry price and buy deadline should be. On a public
# board that reads as two plays, one of which looks broken.

def _picks_file(tmp_path, rows):
    import json
    p = tmp_path / "picks.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return str(p)


def test_the_picks_file_never_shadows_an_alert_the_publisher_already_sent(anon, tmp_path):
    from app import playsfeed
    from app.db import SessionLocal

    anon.post("/api/v1/plays/ingest", headers=KEY, json={"buys": [
        {"source_id": "1509000000000000001:0", "symbol": "DUPE", "kind": "standard",
         "alert_date": "2026-08-05", "ratio": "1:80", "ratio_n": 80,
         "entry_price": 0.1231, "est_profit": 9.72, "last_buy_date": "2026-08-07"},
    ]})

    path = _picks_file(tmp_path, [{"symbol": "DUPE", "note": "Reg Alert",
                                   "date": "2026-08-05"}])
    db = SessionLocal()
    try:
        assert playsfeed.import_picks_file(db, path) == 0, \
            "the bare copy was inserted alongside the complete one"
        board = playsfeed.load_board(db)
    finally:
        db.close()

    dupes = [l for l in board.history if l.play.symbol == "DUPE"]
    assert len(dupes) == 1, f"DUPE appears {len(dupes)} times on the board"
    kept = dupes[0].play
    assert kept.ratio == "1:80" and kept.entry_price == 0.1231, \
        "the complete row lost to the bare one"
    assert kept.last_buy_date == "2026-08-07", "the buy deadline was dropped"


def test_the_picks_file_still_adds_an_alert_the_publisher_has_not_sent(anon, tmp_path):
    from app import playsfeed
    from app.db import SessionLocal

    path = _picks_file(tmp_path, [{"symbol": "ONLYPICK", "note": "Reg Alert",
                                   "date": "2026-08-04"}])
    db = SessionLocal()
    try:
        assert playsfeed.import_picks_file(db, path) == 1
        # and running it again is still a no-op
        assert playsfeed.import_picks_file(db, path) == 0
    finally:
        db.close()
