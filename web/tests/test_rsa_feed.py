"""Parsing the TRACK lifecycle board.

The sample below is copied out of a real message in the alert channel, keeping
the parts that are easy to get wrong: the U+0336 strikethrough woven through the
past dates, the ``AGAE ↔️ AIFA`` rename, the bracketed text statuses, and the
header + code fence that must be skipped without complaint.
"""
from __future__ import annotations

import pathlib
import sys
from datetime import date

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import rsa_feed  # noqa: E402

# Dates on the board carry a combining strike; these are byte-for-byte real.
BOARD = """**RSA Alert Tracker**
```text
\U0001f48a 6̶/̶1̶ - KPEA ⏳
\U0001f6ab 6̶/̶1̶ - WETO [canceled]
\U0001f514 6̶/̶1̶1̶ - AGAE ↔️ AIFA ✅
\U0001f4dd 6̶/̶1̶8̶ - WLDS ✅
\U0001f514 6̶/̶1̶7̶ - ALUR \U0001f4b5
\U0001f514 7̶/̶1̶7̶ - TOMZ \U0001f9e9
\U0001f514 7̶/̶3̶1̶ - LBGJ \U0001f195
\U0001f6a7 8/3 - WORX [low odds]
```"""

# The board is undated; pin "now" so the year inference is deterministic.
TODAY = date(2026, 7, 31)


def _rows():
    return rsa_feed.parse_lifecycle_message({"content": BOARD}, today=TODAY)


def test_parses_every_row_and_skips_the_furniture():
    rows = _rows()
    assert len(rows) == 8                      # header + both fences dropped
    assert [r.symbol for r in rows] == [
        "KPEA", "WETO", "AGAE", "WLDS", "ALUR", "TOMZ", "LBGJ", "WORX"]


def test_strikethrough_dates_still_parse():
    by_symbol = {r.symbol: r for r in _rows()}
    assert by_symbol["KPEA"].alert_date == "2026-06-01"
    assert by_symbol["TOMZ"].alert_date == "2026-07-17"
    # Undated on the board and not yet struck through — still a real date.
    assert by_symbol["WORX"].alert_date == "2026-08-03"


def test_every_status_glyph_is_recognised():
    got = {r.symbol: r.status for r in _rows()}
    assert got == {
        "KPEA": "pending",
        "WETO": "canceled",
        "AGAE": "rounded_up",
        "WLDS": "rounded_up",
        "ALUR": "cash_in_lieu",
        "TOMZ": "fractional",
        "LBGJ": "new",
        "WORX": "low_odds",
    }
    # An unrecognised glyph must never masquerade as a sellable status.
    assert not any(r.status == "unknown" for r in _rows())


def test_rename_is_carried_into_sell_symbol():
    agae = next(r for r in _rows() if r.symbol == "AGAE")
    assert agae.sell_symbol == "AIFA"       # what you can actually place an order in
    assert agae.renamed
    assert agae.status == "rounded_up"      # the glyph trails the alias
    # Everything else keeps its own ticker.
    assert all(not r.renamed for r in _rows() if r.symbol != "AGAE")


def test_alert_kind_comes_from_the_leading_glyph():
    by_symbol = {r.symbol: r for r in _rows()}
    assert by_symbol["KPEA"].kind == "otc"           # 💊
    assert by_symbol["WLDS"].kind == "conditional"   # 📝
    assert by_symbol["AGAE"].kind == "standard"      # 🔔
    # Undocumented glyphs fall back to standard rather than guessing.
    assert by_symbol["WORX"].kind == "standard"      # 🚧


def test_only_finished_plays_are_sellable():
    sellable = {r.symbol for r in _rows() if r.is_sellable}
    assert sellable == {"WETO", "AGAE", "WLDS", "TOMZ"}
    # Cash-in-lieu left nothing in the account; the rest haven't resolved.
    assert "ALUR" not in sellable
    assert "KPEA" not in sellable and "LBGJ" not in sellable


def test_key_matches_the_buy_alert_identity():
    agae = next(r for r in _rows() if r.symbol == "AGAE")
    assert agae.key == "2026-06-11:AGAE"     # keyed on the ORIGINAL ticker


def test_year_rolls_back_for_a_date_far_in_the_future():
    """A December row read on January 3rd belongs to the year just ended."""
    rows = rsa_feed.parse_lifecycle_message(
        {"content": "\U0001f514 12/28 - FOO \U0001f9e9"}, today=date(2027, 1, 3))
    assert rows[0].alert_date == "2026-12-28"


def test_newest_message_wins_across_a_pull():
    old = {"id": "1", "content": "\U0001f514 7/17 - TOMZ ⏳"}
    new = {"id": "2", "content": "\U0001f514 7/17 - TOMZ \U0001f9e9"}
    rows = rsa_feed.parse_lifecycle_messages([old, new], today=TODAY)
    assert len(rows) == 1
    assert rows[0].status == "fractional"


def test_only_three_brokers_return_a_fraction():
    """The routing rule for fractional auto-sell. Everyone else pays cash."""
    assert rsa_feed.FRACTIONAL_BROKERS == ("Public", "Robinhood", "SoFi")
    assert rsa_feed.returns_fraction("robinhood")
    assert rsa_feed.returns_fraction("Public")
    assert rsa_feed.returns_fraction("sofi")
    for broker in ("Fidelity", "Schwab", "Chase", "Wells Fargo",
                   "BBAE", "DSPAC", "Fennel"):
        assert not rsa_feed.returns_fraction(broker), broker
    # The two sets partition the ten brokers we execute in.
    assert (set(rsa_feed.FRACTIONAL_BROKERS) | set(rsa_feed.CASH_IN_LIEU_BROKERS)
            == set(rsa_feed.SUPPORTED_BROKERS))


def test_from_pick_round_trips_through_to_pick():
    pick = {"symbol": "tomz", "note": "OTC", "date": "2026-07-17"}
    alert = rsa_feed.from_pick(pick)
    assert alert is not None
    assert alert.symbol == "TOMZ" and alert.kind == "otc"
    # The source_id must match what the web importer mints for the same row,
    # so a pick arriving by both routes is inserted once.
    assert alert.source_id == "picks:TOMZ:2026-07-17"
    assert rsa_feed.to_pick(alert) == {
        "symbol": "TOMZ", "note": "OTC", "date": "2026-07-17"}
    assert rsa_feed.from_pick({"symbol": "", "date": "2026-07-17"}) is None
