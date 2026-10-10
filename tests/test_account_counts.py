"""Account counts come from THIS user's brokers and journal, never a table.

app.py used to ship `_KNOWN_ACCOUNT_COUNTS = {fidelity: 10, wellsfargo: 10,
robinhood: 3}` — one operator's own fleet — and max()'d it over everything
live. A customer with one Fidelity and one Robinhood account read 13 accounts
on the dashboard, "3/13" on every coverage bar, and no pick ever left Partial.

Also pinned here, because they are the other launch-blocking basics that live
at module level: the icon-font and mono-font fallbacks and the version string.
No Tk window is created anywhere in this file.
"""
from __future__ import annotations

import json
import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as A
import balances
import trade_journal


@pytest.fixture
def world(tmp_path, monkeypatch):
    """An empty journal, no balances on record, nothing live, and only the
    brokers a test links. Every file lives in tmp."""
    monkeypatch.setattr(trade_journal, "_FILE", tmp_path / "trades.json")
    monkeypatch.setattr(trade_journal, "_cache", {"key": None, "rows": []})
    monkeypatch.setattr(balances, "BALANCES_FILE", tmp_path / "balances.json")
    monkeypatch.setattr(A, "_LIVE_ACCOUNT_COUNTS", {})
    monkeypatch.setattr(A, "_COVERAGE_MEMO", {})
    monkeypatch.setattr(A, "_load_done_picks", lambda: set())
    linked: set = set()
    monkeypatch.setattr(A, "_broker_has_creds", lambda b: b in linked)

    def buys(rows):
        stamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        trade_journal._FILE.write_text(json.dumps([
            {"id": f"t{i}", "timestamp": stamp, "broker": b, "account_id": a,
             "side": "buy", "symbol": sym, "qty": 1, "fill_price": 1.0}
            for i, (b, a, sym) in enumerate(rows)]), encoding="utf-8")
        A._COVERAGE_MEMO.clear()

    return types.SimpleNamespace(linked=linked, buys=buys, tmp=tmp_path)


def test_there_is_no_table_of_someone_elses_accounts():
    assert not hasattr(A, "_KNOWN_ACCOUNT_COUNTS")


def test_a_new_customer_counts_one_account_per_linked_broker(world):
    world.linked.update({"fidelity", "robinhood"})
    assert A._account_counts_by_broker() == {"fidelity": 1, "robinhood": 1}
    assert A._account_universe_static() == 2
    # And a broker that is not linked counts as nothing at all.
    assert "wellsfargo" not in A._account_counts_by_broker()


def test_status_rows_show_no_count_until_something_reports_one(world):
    world.linked.add("fidelity")
    assert A._account_count_evidence().get("fidelity") is None


def test_a_pick_bought_in_every_account_leaves_partial(world):
    """The customer from the bug report: one Fidelity, one Robinhood. Before,
    the denominator was 13 and this pick was stuck in Partial forever."""
    world.linked.update({"fidelity", "robinhood"})
    world.buys([("fidelity", "Fidelity 1 (0001)", "AAAA"),
                ("robinhood", "individual (****0002)", "AAAA")])
    pick = [{"symbol": "AAAA", "date": datetime.now().strftime("%Y-%m-%d")}]
    key = ("AAAA", pick[0]["date"])
    assert key in A._fully_covered_pick_keys(pick)
    assert key not in A._partial_pick_keys(pick)


def test_a_pick_owed_an_account_stays_partial(world):
    world.linked.update({"fidelity", "robinhood"})
    world.buys([("fidelity", "Fidelity 1 (0001)", "AAAA"),
                ("robinhood", "individual (****0002)", "BBBB")])
    A._LIVE_ACCOUNT_COUNTS["fidelity"] = 1
    pick = [{"symbol": "AAAA", "date": datetime.now().strftime("%Y-%m-%d")}]
    key = ("AAAA", pick[0]["date"])
    assert A._account_universe_static() == 2
    assert key in A._partial_pick_keys(pick)


def test_a_live_count_raises_the_denominator_over_the_journal(world):
    """A broker that lists more accounts this session than the journal has
    ever bought into still owes those accounts. Trusting the journal alone
    read a 3-account broker with 1 account bought as fully covered."""
    world.linked.update({"robinhood", "fennel"})
    world.buys([("robinhood", f"acct ({n})", "AAAA") for n in range(3)]
               + [("fennel", "Fennel Account 1", "AAAA")])
    A._LIVE_ACCOUNT_COUNTS.update({"robinhood": 4, "fennel": 5})
    assert A._tradable_account_counts() == {"robinhood": 4, "fennel": 5}
    assert A._account_universe_static() == 9
    assert A._account_counts_by_broker() == {"robinhood": 4, "fennel": 5}
    pick = [{"symbol": "AAAA", "date": datetime.now().strftime("%Y-%m-%d")}]
    key = ("AAAA", pick[0]["date"])
    assert key in A._partial_pick_keys(pick)


def test_the_journal_is_a_floor_under_a_smaller_live_count(world):
    """The numerator counts journal accounts, so the denominator never drops
    below them — a bar can never read 3/2."""
    world.linked.add("robinhood")
    world.buys([("robinhood", f"acct ({n})", "AAAA") for n in range(3)])
    A._LIVE_ACCOUNT_COUNTS["robinhood"] = 2
    assert A._tradable_account_counts() == {"robinhood": 3}


def test_without_a_live_count_the_journal_comes_first(world):
    """Before any bootstrap this session, a stale stored refresh is not
    trusted over what was actually bought."""
    now = datetime.now(timezone.utc).isoformat()
    balances.BALANCES_FILE.write_text(json.dumps(
        {"version": 1, "brokers": {"fennel": {
            f"Fennel Account {n}": {"seen_at": now} for n in range(5)}}}),
        encoding="utf-8")
    world.linked.add("fennel")
    world.buys([("fennel", "Fennel Account 1", "AAAA")])
    assert A._tradable_account_counts() == {"fennel": 1}
    # ...while the dashboard reports what the broker last said it holds.
    assert A._account_counts_by_broker() == {"fennel": 5}


def test_mark_done_still_clears_a_pick_owed_a_never_traded_account(world, monkeypatch):
    """A joint account the user never buys into keeps picks in Partial now;
    Mark done is the way out, and it must still work."""
    world.linked.add("robinhood")
    world.buys([("robinhood", "individual (1)", "AAAA")])
    A._LIVE_ACCOUNT_COUNTS["robinhood"] = 2
    pick = [{"symbol": "AAAA", "date": datetime.now().strftime("%Y-%m-%d")}]
    key = ("AAAA", pick[0]["date"])
    assert key in A._partial_pick_keys(pick)
    monkeypatch.setattr(A, "_load_done_picks", lambda: {key})
    assert key not in A._partial_pick_keys(pick)
    assert key in A._purchased_pick_keys(pick)


def test_a_live_count_is_used_where_nothing_has_been_bought_yet(world):
    world.linked.update({"public"})
    A._LIVE_ACCOUNT_COUNTS["public"] = 7
    assert A._tradable_account_counts() == {"public": 7}
    assert A._account_counts_by_broker() == {"public": 7}


def test_the_last_refresh_on_record_survives_a_restart(world):
    """balances.json is written by every Refresh All. Some brokers put the
    cash IN the label, so older refreshes leave rows that must not count."""
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=3)).isoformat()
    fresh = now.isoformat()
    book = {f"WELLSTRADE (****000{n}) = $1.0{n}": {"seen_at": old} for n in range(4)}
    book.update({f"WELLSTRADE (****000{n}) = $2.0{n}": {"seen_at": fresh}
                 for n in range(4)})
    balances.BALANCES_FILE.write_text(json.dumps(
        {"version": 1, "brokers": {"wellsfargo": book}}), encoding="utf-8")
    world.linked.add("wellsfargo")
    assert A._balances_account_counts() == {"wellsfargo": 4}
    assert A._account_counts_by_broker() == {"wellsfargo": 4}
    assert A._tradable_account_counts() == {"wellsfargo": 4}


def test_update_total_accounts_moves_the_denominator_too(world):
    """The count must reach _account_universe_static (which the pick tabs and
    coverage bars read), not only the dashboard widget."""
    world.linked.update({"fidelity", "chase"})
    shown = {}
    fake = types.SimpleNamespace(
        _broker_account_counts={},
        _dash_accounts=types.SimpleNamespace(
            configure=lambda **kw: shown.update(kw)))
    A.App._update_total_accounts(fake, "fidelity", 5)
    assert A._LIVE_ACCOUNT_COUNTS == {"fidelity": 5}
    assert fake._broker_account_counts == {"fidelity": 5, "chase": 1}
    assert shown["text"] == "6"
    assert A._account_universe_static() == 6
    # A zero-account "success" is no evidence and must not erase a real count.
    A.App._update_total_accounts(fake, "fidelity", 0)
    assert A._LIVE_ACCOUNT_COUNTS == {"fidelity": 5}


def test_coverage_bar_and_purchased_gate_share_one_denominator(world):
    world.linked.update({"fidelity"})
    A._LIVE_ACCOUNT_COUNTS["fidelity"] = 3
    fake = types.SimpleNamespace(_broker_account_counts={"fidelity": 99})
    assert A.App._account_universe(fake) == A._account_universe_static() == 3


# ------------------------------------------------------------------ icons

@pytest.fixture
def icon_state(monkeypatch):
    monkeypatch.setattr(A, "ICON_FONT", "Segoe Fluent Icons")
    monkeypatch.setattr(A, "ICONS", dict(A.ICONS))


def test_fluent_is_used_when_the_machine_has_it(icon_state):
    clock = A.icon("clock")
    assert A._select_icon_font(["Segoe UI", "Segoe Fluent Icons",
                                "Segoe MDL2 Assets"]) == "Segoe Fluent Icons"
    assert A.ICON_FONT == "Segoe Fluent Icons"
    assert A.icon("clock") == clock


def test_windows_10_falls_back_to_mdl2(icon_state):
    assert A._select_icon_font(["Segoe UI", "Segoe MDL2 Assets"]) == "Segoe MDL2 Assets"
    assert A.ICON_FONT == "Segoe MDL2 Assets"
    # Fluent's clock (E917) is absent from MDL2; the substitute is used.
    assert A.icon("clock") == chr(0xE823)
    assert A.icon("dashboard") == chr(0xE80A)       # shared code point, unchanged


def test_no_icon_font_at_all_changes_nothing(icon_state):
    assert A._select_icon_font(["DejaVu Sans"]) == "Segoe Fluent Icons"


def test_every_icon_exists_in_both_fonts_where_installed():
    """Checks the real cmaps when this machine has both fonts (Windows 11
    ships both). Skipped elsewhere rather than guessing."""
    ttlib = pytest.importorskip("fontTools.ttLib")
    fonts = Path(r"C:\Windows\Fonts")
    fluent_p, mdl2_p = fonts / "SegoeIcons.ttf", fonts / "segmdl2.ttf"
    if not (fluent_p.exists() and mdl2_p.exists()):
        pytest.skip("Segoe icon fonts not installed here")
    fluent = ttlib.TTFont(str(fluent_p)).getBestCmap()
    mdl2 = ttlib.TTFont(str(mdl2_p)).getBestCmap()
    for name, glyph in A.ICONS.items():
        assert ord(glyph) in fluent, f"{name} missing from Segoe Fluent Icons"
        fallback = A._MDL2_SUBSTITUTES.get(name, glyph)
        assert ord(fallback) in mdl2, f"{name} missing from Segoe MDL2 Assets"


# ------------------------------------------------------------------ mono font

@pytest.fixture
def mono_state(monkeypatch):
    """Put FONT_MONO and every App attribute built from it back afterwards."""
    monkeypatch.setattr(A, "FONT_MONO", "Cascadia Code")
    for attr, val in list(vars(A.App).items()):
        if isinstance(val, tuple) and val and val[0] == "Cascadia Code":
            monkeypatch.setattr(A.App, attr, val)


def test_cascadia_is_kept_when_installed(mono_state):
    assert A._select_mono_font(["Segoe UI", "Cascadia Code", "Consolas"]) == "Cascadia Code"
    assert A.App._WF_PRICE[0] == "Cascadia Code"


def test_missing_cascadia_falls_back_to_consolas(mono_state):
    before = dict(vars(A.App))
    assert A._select_mono_font(["Segoe UI", "Consolas"]) == "Consolas"
    assert A.FONT_MONO == "Consolas"
    # The font tuples App built at import follow, keeping size and weight.
    assert A.App._WF_PRICE == ("Consolas", 16, "bold")
    assert A.App._SF_MONO == ("Consolas", 9)
    leftovers = [k for k, v in vars(A.App).items()
                 if isinstance(v, tuple) and v and v[0] == "Cascadia Code"]
    assert leftovers == []
    # Nothing else on the class was touched.
    changed = {k for k, v in vars(A.App).items() if before.get(k) is not v}
    assert all(isinstance(before[k], tuple) and before[k][0] == "Cascadia Code"
               for k in changed)


def test_neither_mono_font_changes_nothing(mono_state):
    assert A._select_mono_font(["DejaVu Sans"]) == "Cascadia Code"
    assert A.App._WF_PRICE[0] == "Cascadia Code"


# ------------------------------------------------------------------ version

def test_the_release_is_versioned():
    assert A.APP_VERSION == "1.0.1"
