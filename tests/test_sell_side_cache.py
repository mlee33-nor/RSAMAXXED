"""The sell side's journal restatement is cached -- and never serves stale rows.

An Exits render asked for the restated journal eight times and the share
ledger nine, each a full pass over trades.json: half a second per tab switch,
with the old page showing through. Both are now cached on the journal's
revision and the rename map. These pin the part that matters more than speed:
a trade recorded, a sell, a delete, or a learnt rename is seen on the very
next call.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as A
import lifecycle
import trade_journal


def _setup(monkeypatch):
    monkeypatch.setattr(lifecycle, "saved_renames", lambda: {})
    A._SELL_ROWS_CACHE.clear()


def test_a_new_trade_is_seen_on_the_next_call(monkeypatch):
    _setup(monkeypatch)
    trade_journal.record_trade("public", "Public 1 BROKERAGE (0001)", "buy", "CACH", 1, 0.5)
    assert A._sell_share_ledger()[("public", "CACH")] == [1.0, 0.0]
    assert A._leg_open_accounts("public", "CACH") == [("Public 1 BROKERAGE (0001)", 1.0)]

    t = trade_journal.record_trade("public", "Public 1 BROKERAGE (0001)", "sell", "CACH", 1, 5.0)
    assert A._sell_share_ledger()[("public", "CACH")] == [1.0, 1.0]
    assert A._leg_open_accounts("public", "CACH") == []

    assert trade_journal.delete_trade(t["id"])
    assert A._sell_share_ledger()[("public", "CACH")] == [1.0, 0.0]


def test_repeat_calls_do_not_restate_the_journal_again(monkeypatch):
    _setup(monkeypatch)
    trade_journal.record_trade("chase", "Chase (0002)", "buy", "CACX", 2, 0.5)
    calls = []
    real = trade_journal.split_adjusted
    counting = lambda rows=None: calls.append(1) or real(rows)  # noqa: E731
    monkeypatch.setattr(trade_journal, "split_adjusted", counting)
    monkeypatch.setattr(A, "_SELL_ROWS_SOURCES", (
        trade_journal.get_trades, counting, trade_journal.fold_renames))
    for _ in range(5):
        A._sell_side_rows()
        A._sell_share_ledger()
    assert len(calls) == 1


def test_a_learnt_rename_is_its_own_entry(monkeypatch):
    _setup(monkeypatch)
    trade_journal.record_trade("fidelity", "Fidelity 1 (Z0001)", "buy", "OLDN", 1, 0.5)
    trade_journal.record_trade("fidelity", "Fidelity 1 (Z0001)", "sell", "NEWN", 1, 3.0)
    assert {t["symbol"] for t in A._sell_side_rows()} >= {"OLDN", "NEWN"}
    folded = A._sell_side_rows({"NEWN": "OLDN"})
    assert "NEWN" not in {t["symbol"] for t in folded}


def test_callers_cannot_poison_the_cache(monkeypatch):
    _setup(monkeypatch)
    trade_journal.record_trade("sofi", "SoFi (0003)", "buy", "CACP", 1, 0.5)
    led = A._sell_share_ledger()
    led[("sofi", "CACP")][0] += 99
    led.clear()
    rows = A._sell_side_rows()
    rows.clear()
    assert A._sell_share_ledger()[("sofi", "CACP")] == [1.0, 0.0]
    assert any(t["symbol"] == "CACP" for t in A._sell_side_rows())


def test_a_swapped_journal_source_is_never_served_from_the_cache(monkeypatch):
    _setup(monkeypatch)
    trade_journal.record_trade("chase", "Chase (0004)", "buy", "CACS", 1, 0.5)
    assert A._sell_share_ledger()[("chase", "CACS")] == [1.0, 0.0]   # cached
    fake = [{"broker": "chase", "symbol": "CACS", "side": "buy", "qty": 7,
             "account_id": "Chase (0004)", "fill_price": 0.5}]
    monkeypatch.setattr(trade_journal, "get_trades", lambda *a, **k: list(fake))
    assert A._sell_share_ledger()[("chase", "CACS")] == [7.0, 0.0]


def test_account_key_is_unchanged_by_its_cache():
    for label, want in [("Fidelity 1 · Individual (Z123)", "Z123"),
                        ("Public 2 BROKERAGE (0043)", "L2:0043"),
                        ("SoFi (manual entry)", "sofi (manual entry)"),
                        (None, ""), ("Public 1 X (0001) = $61.32", "0001")]:
        assert trade_journal.account_key(label) == want
