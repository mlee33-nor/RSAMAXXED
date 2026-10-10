"""Command Center pick rows: the details line under the ticker.

Display only — last day to buy, ratio / price / estimate, round-up history,
our own history with the symbol and mirror's view of the pick. These tests pin
the formatting, the archive enrichment, the tolerance of junk fields, the
Quick Picks urgency order, and a headless draw of a real row (withdrawn root,
nothing shown) whose captions never run into the coverage bar.
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import rsa_feed
from modules.canvas_rows import RowCanvas

SAT = date(2026, 10, 10)          # a Saturday
BTOC = {"symbol": "BTOC", "note": "Reg Alert", "date": "2026-10-09",
        "last_buy": "2026-10-14"}
BTOC_ROW = {"alert_date": "2026-10-09", "entry_price": 0.2151, "est_profit": 3.23,
            "kind": "standard", "last_buy_date": "2026-10-14",
            "posted_at": "2026-10-09T21:50:54.739000+00:00", "ratio": "1:16",
            "ratio_n": 16, "roundup_history": "N/A",
            "source_id": "1558235336100806719:0", "symbol": "BTOC"}
DFLI_ROW = {"alert_date": "2026-10-08", "entry_price": 0.6891, "est_profit": 4.82,
            "kind": "standard", "last_buy_date": "2026-10-09",
            "posted_at": "2026-10-08T12:29:12.646000+00:00", "ratio": "1:8",
            "roundup_history": "100% (1/1)", "source_id": "1557731591411859528:0",
            "symbol": "DFLI"}


@pytest.fixture()
def archive(tmp_path, monkeypatch):
    path = tmp_path / "feed_archive.json"
    monkeypatch.setattr(A, "FEED_ARCHIVE_FILE", path)

    def write(rows):
        path.write_text(json.dumps({"buys": {
            (r.get("source_id") if isinstance(r, dict) else None) or str(i): r
            for i, r in enumerate(rows)}}), "utf-8")
        return path
    return write


# ------------------------------------------------------------- formatting

def test_dates():
    assert A._fmt_short_day(date(2026, 10, 9)) == "Fri 10/9"
    assert A._fmt_short_day(date(2026, 10, 14)) == "Wed 10/14"
    assert A._fmt_md(date(2026, 8, 26)) == "8/26"
    assert A._fmt_short_day(None) == "" and A._fmt_md("x") == ""


def test_trading_days_left_weekend_and_holiday():
    # Saturday -> Wednesday: Mon, Tue, Wed.
    assert A._last_day_urgency(date(2026, 10, 14), SAT) == ("3 trading days left",
                                                           A.TEXT_SECONDARY)
    # Thanksgiving 2026 (Thu 11/26) is no session: Wed + Fri.
    assert A._trading_days_left(date(2026, 11, 27), date(2026, 11, 25)) == 2
    # Saturday -> Monday is one session away, and that is urgent.
    assert A._last_day_urgency(date(2026, 10, 12), SAT) == ("1 trading day left", A.YELLOW)
    assert A._last_day_urgency(date(2026, 10, 14), date(2026, 10, 14)) == ("today", A.YELLOW)
    assert A._last_day_urgency(date(2026, 10, 9), SAT) == ("closed", A.TEXT_MUTED)
    # A last day ON the weekend, seen that weekend: nothing left to buy in.
    assert A._last_day_urgency(SAT, SAT) == ("closed", A.TEXT_MUTED)
    assert A._last_day_urgency(None, SAT) == ("", "")


def test_prices_ratio_estimate():
    assert A._fmt_price(0.2151) == "$0.2151"
    assert A._fmt_price(3.51) == "$3.51"
    assert A._fmt_price(1234.5) == "$1,234.50"
    assert A._fmt_price(0.00345) == "$0.00345"
    for junk in (None, "", "abc", -1, 0, float("nan"), True, [1]):
        assert A._fmt_price(junk) == ""
    assert A._fmt_est(3.23) == "est +$3.23/acct"
    assert A._fmt_est("nope") == ""
    assert A._fmt_ratio("1:16") == "1:16"
    assert A._fmt_ratio("1-for-20") == "1:20"
    assert A._fmt_ratio("1:3-for-1") == "1:3"
    assert A._fmt_ratio("garbage") == "" and A._fmt_ratio(None) == ""


def test_history_colouring():
    assert A._history_style("100% (2/2)") == ("100% (2/2)", A.GREEN)
    assert A._history_style("50% (1/2)") == ("50% (1/2)", A.YELLOW)
    assert A._history_style("0% (0/3)") == ("0% (0/3)", A.RED)
    for none in ("N/A", "", None, "  n/a "):
        assert A._history_style(none) == ("no history", A.TEXT_MUTED)
    assert A._history_style("rounded up at Fidelity")[1] == A.TEXT_SECONDARY


def test_fit_parts_truncates_with_ellipsis():
    measure = lambda t, _s: len(t) * 10                       # noqa: E731
    parts = [("Alerted Fri 10/9", "f", "a"), ("  ·  ", "f", "b"), ("Last day", "f", "c")]
    assert A._fit_parts(parts, 10_000, measure) == parts
    cut = A._fit_parts(parts, 200, measure)
    assert sum(measure(t, s) for t, s, _ in cut) <= 200
    assert cut[-1][0].endswith("…")
    assert A._fit_parts(parts, 0, measure) == []


# ------------------------------------------------------------- data

def test_to_pick_from_pick_round_trip():
    buy = rsa_feed.BuyAlert(source_id="1:0", symbol="BTOC", alert_date="2026-10-09",
                            ratio="1:16", ratio_n=16, entry_price=0.2151, est_profit=3.23,
                            last_buy_date="2026-10-14", roundup_history="N/A",
                            posted_at="2026-10-09T21:50:54+00:00")
    pick = rsa_feed.to_pick(buy)
    assert pick == {"symbol": "BTOC", "note": "Reg Alert", "date": "2026-10-09",
                    "last_buy": "2026-10-14", "ratio": "1:16", "entry_price": 0.2151,
                    "est_profit": 3.23, "roundup_history": "N/A",
                    "posted_at": "2026-10-09T21:50:54+00:00"}
    back = rsa_feed.from_pick(json.loads(json.dumps(pick)))
    assert (back.symbol, back.alert_date, back.ratio, back.ratio_n, back.entry_price,
            back.est_profit, back.last_buy_date, back.roundup_history) == (
        "BTOC", "2026-10-09", "1:16", 16, 0.2151, 3.23, "2026-10-14", "N/A")
    # An old three-key pick still maps, with nothing invented.
    old = rsa_feed.from_pick({"symbol": "x", "note": "Reg Alert", "date": "2026-10-09"})
    assert (old.ratio, old.entry_price, old.posted_at) == ("", None, "")


def test_from_pick_drops_garbage_extras():
    b = rsa_feed.from_pick({"symbol": "ABC", "date": "2026-10-09", "note": "OTC",
                            "entry_price": "lots", "est_profit": [1], "ratio": 7,
                            "posted_at": "yesterday", "roundup_history": None})
    assert (b.entry_price, b.est_profit, b.ratio_n, b.posted_at, b.roundup_history) == (
        None, None, None, "", "")
    json.dumps(rsa_feed.FeedBatch(buys=[b]).to_json())     # still publishable


def test_mirror_keys_unchanged_by_extras():
    rich = dict(BTOC, ratio="1:16", entry_price=0.2151)
    assert A.App._mirror_key(rich) == A.App._mirror_key(BTOC) == ("2026-10-09", "BTOC")
    assert A._merge_picks([rich], [BTOC]) == [rich]


def test_feed_copy_keeps_cached_extras():
    local = [dict(BTOC, ratio="1:16", entry_price=0.2151)]
    out = A._carry_pick_extras([dict(BTOC)], local)
    assert out[0]["ratio"] == "1:16" and out[0]["entry_price"] == 0.2151
    assert out[0]["last_buy"] == BTOC["last_buy"]
    assert A._carry_pick_extras([BTOC], "junk") == [BTOC]


def test_archive_enrichment_and_cache(archive, monkeypatch):
    archive([BTOC_ROW, DFLI_ROW, {"symbol": "DFLI", "alert_date": "2026-08-26",
                                  "source_id": "old"}, "junk", {"symbol": ""}])
    by_key, dates = A._feed_archive_index()
    assert dates["DFLI"] == {"2026-08-26", "2026-10-08"}
    det = A._pick_details({"symbol": "btoc", "note": "Reg Alert", "date": "2026-10-09"},
                          by_key)
    assert det["last_buy"] == date(2026, 10, 14)
    assert (det["ratio"], det["entry_price"], det["est_profit"]) == ("1:16", 0.2151, 3.23)
    assert det["has_history"] and det["history"] == "N/A"
    # The pick's own values win over the archive's.
    own = A._pick_details(dict(BTOC, entry_price=0.3), by_key)
    assert own["entry_price"] == 0.3
    # Cached: an unchanged file is not read again.
    monkeypatch.setattr(A.json, "loads", lambda *_a, **_k: pytest.fail("re-read"))
    assert A._feed_archive_index()[0] is by_key


def test_archive_missing_or_corrupt(archive, tmp_path):
    p = archive([])
    p.write_text("{not json", "utf-8")
    assert A._feed_archive_index() == ({}, {})
    p.unlink()
    assert A._feed_archive_index() == ({}, {})


def test_details_tolerate_garbage():
    det = A._pick_details({"symbol": None, "date": 5, "last_buy": "soon",
                           "entry_price": "x", "ratio": {}, "roundup_history": 7})
    assert det["alert"] is None and det["last_buy"] is None and det["ratio"] == ""
    assert A._pick_details(None)["alert"] is None             # never raises


# ------------------------------------------------------------- ordering

def test_quick_picks_ordered_by_urgency():
    picks = [
        {"symbol": "OLD", "note": "Reg Alert", "date": "2026-10-09"},           # no last day
        {"symbol": "LATE", "note": "Reg Alert", "date": "2026-10-08", "last_buy": "2026-10-16"},
        {"symbol": "SOON", "note": "Reg Alert", "date": "2026-10-06", "last_buy": "2026-10-12"},
        {"symbol": "SOON2", "note": "Reg Alert", "date": "2026-10-09", "last_buy": "2026-10-12"},
        {"symbol": "SHUT", "note": "Reg Alert", "date": "2026-10-07", "last_buy": "2026-10-09"},
        {"symbol": "NEW", "note": "Reg Alert", "date": "2026-10-10"},
    ]
    details = {id(p): A._pick_details(p) for p in picks}
    groups = A.App._pick_groups(picks, "available", details, SAT)
    order = [p["symbol"] for _t, _a, rows in groups for p in rows]
    assert order == ["SOON2", "SOON", "LATE", "NEW", "OLD", "SHUT"]
    assert groups[0][0] == "LAST DAY  MONDAY, OCTOBER 12"
    assert groups[0][1] == "1 trading day left"
    assert groups[-1][0] == "LAST DAY PASSED"
    # Partial / Purchased keep the alert-date grouping, newest first.
    part = A.App._pick_groups(picks, "partial", details, SAT)
    assert [t for t, _a, _r in part][0] == "OCTOBER 10, 2026"


# ------------------------------------------------------------- captions + draw

class _Rows:
    """Just enough of App to build and draw pick rows."""
    for _n in ("_pick_row_recipe", "_pick_caption_lines", "_pick_mirror_status",
               "_note_style", "_NOTE_STYLE", "_mirror_row_state", "_mirror_key",
               "_pick_dates_by_symbol", "_mirror_max_age_days"):
        locals()[_n] = A.App.__dict__[_n]
    for _n in [n for n in A.App.__dict__ if n.startswith("_PF_")]:
        locals()[_n] = A.App.__dict__[_n]

    def __init__(self, picks=()):
        self._quick_picks = list(picks)
        self._pick_expanded = set()

    def _quick_pick_buy(self, s):
        pass

    _prefill_trade = _mark_pick_done = _unmark_pick_done = _toggle_pick_detail = \
        lambda self, *a, **k: None


def _ctx(rows, buys=None, mirror=None):
    archive_by_key, dates = A._feed_archive_index()
    return {"archive": archive_by_key, "archive_dates": dates,
            "pick_dates": rows._pick_dates_by_symbol(), "buys": buys or {},
            "today": SAT, "mirror": mirror or rows._mirror_row_state()}


def _texts(lines):
    return ["".join(t for t, _c in line) for line in lines]


def test_caption_text(archive):
    archive([BTOC_ROW, DFLI_ROW, {"symbol": "DFLI", "alert_date": "2026-08-26",
                                  "source_id": "old", "posted_at": "2026-08-26T10:00:00"}])
    rows = _Rows([BTOC])
    by_key, _ = A._feed_archive_index()
    lines = rows._pick_caption_lines(BTOC, "BTOC", "2026-10-09",
                                     A._pick_details(BTOC, by_key), _ctx(rows))
    assert _texts(lines) == [
        "Last day Wed 10/14  ·  3 trading days left  ·  Alerted Fri 10/9  ·  1:16 split"
        "  ·  $0.2151  ·  est +$3.23/acct",
        "no round-up history"]

    dfli = {"symbol": "DFLI", "note": "Reg Alert", "date": "2026-10-08"}
    buys = {"DFLI": [("2026-08-27", "fidelity", "X1"), ("2026-08-27", "fidelity", "X2"),
                     ("2026-10-08", "schwab", "S1")]}
    mirror = (True, frozenset(), (("2026-10-08", "DFLI", "wellsfargo"),), (),
              frozenset(), 2)
    lines = rows._pick_caption_lines(dfli, "DFLI", "2026-10-08",
                                     A._pick_details(dfli, by_key),
                                     _ctx(rows, buys, mirror))
    assert _texts(lines)[1] == ("Round-up history 100% (1/1)  ·  re-alert — first alerted"
                                " 8/26, bought 2 accts  ·  mirror owed at Wells Fargo"
                                "  ·  bought at 1 broker")
    assert ("100% (1/1)", A.GREEN) in lines[1]
    assert "closed" in _texts(lines)[0]


def test_caption_mirror_skip_and_queue():
    rows = _Rows()
    otc = {"symbol": "ABC", "note": "OTC", "date": "2026-10-09"}
    on = (True, frozenset(), (), (), frozenset(), 2)
    assert A.App._pick_mirror_status(otc, "ABC", "2026-10-09", 0, on, SAT) == (
        "mirror skips — OTC — mirror doesn't auto-buy these", A.TEXT_MUTED)
    q = (True, frozenset({("2026-10-09", "ABC")}), (), (), frozenset(), 2)
    assert A.App._pick_mirror_status(otc, "ABC", "2026-10-09", 0, q, SAT)[0] == "mirror queued"
    off = (False, frozenset(), (), (), frozenset(), 2)
    assert A.App._pick_mirror_status(otc, "ABC", "2026-10-09", 0, off, SAT) == ("", "")
    old = {"symbol": "ABC", "note": "Reg Alert", "date": "2026-09-01"}
    assert "trading-day limit" in A.App._pick_mirror_status(old, "ABC", "2026-09-01", 0,
                                                            on, SAT)[0]
    # Junk state never raises.
    assert A.App._pick_mirror_status(otc, "ABC", "2026-10-09", 0, "junk", SAT) == ("", "")
    # A three-key pick with no archive shows only what it has.
    lines = rows._pick_caption_lines(otc, "ABC", "2026-10-09", A._pick_details(otc),
                                     _ctx(rows))
    assert _texts(lines) == ["Alerted Fri 10/9"]


def _draw(tk_root, rows, pick, mode, n_acct, caption, width):
    rc = RowCanvas(tk_root, bg=A.BG_CARD, min_width=width)
    rc.set_rows([rows._pick_row_recipe(pick, pick["symbol"], pick["date"], mode, n_acct,
                                       12, False, caption)])
    return rc


def test_row_draws_captions_clear_of_coverage(tk_root, archive):
    archive([BTOC_ROW])
    rows = _Rows([BTOC])
    by_key, _ = A._feed_archive_index()
    long_pick = dict(BTOC, roundup_history="67% (2/3) " + "very long history " * 6)
    caption = rows._pick_caption_lines(
        long_pick, "BTOC", "2026-10-09", A._pick_details(long_pick, by_key),
        _ctx(rows, {"BTOC": [("2026-10-09", "fidelity", "A1")]},
             (True, frozenset(), (("2026-10-09", "BTOC", "chase"),), (), frozenset(), 2)))
    rc = _draw(tk_root, rows, long_pick, "partial", 1, caption, 900)
    try:
        texts = [rc.itemcget(i, "text") for i in rc.find_all()
                 if rc.type(i) == "text"]
        joined = " | ".join(texts)
        # Font metrics vary by machine, so only the leading parts are pinned;
        # whatever doesn't fit is cut with an ellipsis (asserted below).
        assert "Last day Wed 10/14" in joined and "3 trading days left" in joined
        assert any(t.endswith("…") for t in texts)       # cut, not overlapped
        bar_x0 = min(rc.coords(i)[0] for i in rc.find_all()
                     if rc.type(i) == "rectangle" and rc.itemcget(i, "fill") == A.BG_ELEVATED)
        cov_text_x0 = min(rc.bbox(i)[0] for i in rc.find_all()
                          if rc.type(i) == "text" and "accounts" in rc.itemcget(i, "text"))
        limit = min(bar_x0, cov_text_x0)
        caps = rc.find_withtag("pick_caption")
        assert len(caps) >= 4
        assert max(rc.bbox(i)[2] for i in caps) <= limit
    finally:
        rc.destroy()


def test_row_without_captions_still_draws(tk_root):
    rows = _Rows()
    pick = {"symbol": "ZZZ", "note": "Reg Alert", "date": "2026-10-09"}
    for caption in (None, [], [[]]):
        rc = _draw(tk_root, rows, pick, "available", 0, caption, 600)
        try:
            assert not rc.find_withtag("pick_caption")
            assert "ZZZ" in [rc.itemcget(i, "text") for i in rc.find_all()
                             if rc.type(i) == "text"]
        finally:
            rc.destroy()


def test_signature_moves_with_details(monkeypatch, archive):
    archive([BTOC_ROW])
    rows = _Rows([BTOC])
    rows._pick_tab_lists = {"picks": [BTOC]}
    rows._picks_show_older = set()
    rows._account_universe = lambda: 12
    sig = A.App._pick_tab_signature
    monkeypatch.setattr(A, "_load_done_picks", lambda: set())
    a = sig(rows, "picks")
    rows._pick_tab_lists = {"picks": [dict(BTOC, entry_price=0.3)]}
    b = sig(rows, "picks")
    assert a != b
    rows._mirror_owed = [{"broker": "chase", "symbol": "BTOC", "date": "2026-10-09"}]
    assert sig(rows, "picks") != b
