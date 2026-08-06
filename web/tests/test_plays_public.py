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

import os
import pathlib
import re
import sys
import tempfile

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


def test_the_four_sections_are_tabs_that_work_without_javascript(board):
    """CSS tabs, not scripted ones: the CSP forbids inline script, and a board
    someone paid for must render with JS blocked."""
    for tab in ("tab-buys", "tab-sells", "tab-track", "tab-profit"):
        assert f'id="{tab}"' in board, f"the {tab} tab went missing"
        assert f'for="{tab}"' in board, f"the {tab} tab has no label to click"
    assert board.count('type="radio" name="ptab"') == 4
    # Every pane is in the HTML — tabs hide, they don't defer-load.
    for pane in ("p-buys", "p-sells", "p-track", "p-profit"):
        assert f'class="pane {pane}' in board


def test_the_profit_tab_multiplies_a_real_basis(board):
    """The calculator's per-account figure is entry x (ratio - 1) over the
    CONFIRMED round-ups: 0.4 x 19 = 7.60 for the one in the fixture."""
    m = re.search(r'data-per-account="([\d.]+)"', board)
    assert m, "the calculator lost its basis"
    assert abs(float(m.group(1)) - 7.6) < 0.01
    # Server-rendered at the default 10 accounts, so it reads correctly with
    # the script blocked.
    assert "$76.00" in board


def test_only_round_ups_count_toward_every_account(anon):
    """The rule from lifecycle.brokers_for(): a rounded-up play left a whole
    share EVERYWHERE, a fractional one left something only at the three brokers
    that hold fractions. Mixing them into one account count would overstate the
    fractional side by more than three times."""
    anon.post("/api/v1/plays/ingest", headers=KEY, json={
        "buys": [
            {"source_id": "f:1", "symbol": "WHOLE", "alert_date": "2026-07-10",
             "ratio": "1:11", "entry_price": 1.0, "last_buy_date": "2026-07-11"},
            {"source_id": "f:2", "symbol": "FRAC", "alert_date": "2026-07-10",
             "ratio": "1:21", "entry_price": 1.0, "last_buy_date": "2026-07-11"},
        ],
        "roundups": [{"source_id": "f:r", "symbol": "WHOLE", "confirmed_date": "2026-07-12"}],
        "lifecycle": [
            {"source_id": "2026-07-10:WHOLE", "symbol": "WHOLE", "alert_date": "2026-07-10",
             "status": "rounded_up", "kind": "standard"},
            {"source_id": "2026-07-10:FRAC", "symbol": "FRAC", "alert_date": "2026-07-10",
             "status": "fractional", "kind": "standard"},
        ],
    })
    page = _unlock(anon).text

    # WHOLE (1.0 x 10) lands in the round-up basis; FRAC (1.0 x 20) does not.
    per_all = float(re.search(r'data-per-account="([\d.]+)"', page).group(1))
    per_frac = float(re.search(r'data-per-frac="([\d.]+)"', page).group(1))
    assert per_frac >= 20.0, "the fractional play never reached its own bucket"
    assert per_all < per_frac, "a fractional play leaked into the every-account total"

    # And each row says where it actually paid.
    assert 'data-scope="frac"' in page
    assert "Public / Robinhood / SoFi only" in page
    assert "is not profit" in page


def test_the_profit_tab_says_what_it_is_not(board):
    flat = re.sub(r"\s+", " ", board)
    assert "not a projection" in flat
    assert "Theoretical total" in flat


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
