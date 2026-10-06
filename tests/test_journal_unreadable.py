"""A journal that cannot be read must never be treated as an empty one.

`_load()` used to return [] on any read or parse error. record_trade then saved
`[] + new row` over the whole history, and the .bak was refreshed on every
save -- so two saves after one bad read (a BOM, a Drive/antivirus lock, a torn
read during a non-atomic external write) destroyed every row in both files.
"""

from __future__ import annotations

import codecs
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import trade_journal


def _row(sym: str, i: int) -> dict:
    return {"id": f"{sym}-{i}", "timestamp": f"2026-09-0{i}T00:00:00+00:00",
            "broker": "public", "account_id": "Public 1 (1234)", "side": "buy",
            "symbol": sym, "qty": 1.0, "fill_price": 0.25, "order_id": None,
            "price_source": "fill"}


HISTORY = [_row("SMTK", 1), _row("GRNQ", 2), _row("MASK", 3)]


@pytest.fixture()
def path(tmp_path, monkeypatch):
    p = tmp_path / "trades.json"
    monkeypatch.setattr(trade_journal, "_FILE", p)
    monkeypatch.setattr(trade_journal, "_READ_DELAY", 0.0)
    trade_journal._cache.clear()
    yield p
    trade_journal._cache.clear()


def _rows(p: Path) -> list:
    return json.loads(p.read_text(encoding="utf-8-sig"))


def _buy():
    return trade_journal.record_trade(broker="public", account_id="Public 1 (1234)",
                                      side="buy", symbol="TOPT", qty=1,
                                      fill_price=1.0)


def test_missing_file_is_an_empty_journal(path):
    assert trade_journal._load() == []
    assert trade_journal.get_trades() == []


def test_a_bom_saved_file_loads(path):
    path.write_bytes(codecs.BOM_UTF8 + json.dumps(HISTORY).encode("utf-8"))
    assert len(trade_journal._load()) == 3
    _buy()
    assert len(_rows(path)) == 4


def test_corrupt_file_recovers_from_bak_and_loses_nothing(path):
    bak = path.with_suffix(".bak")
    bak.write_text(json.dumps(HISTORY), encoding="utf-8")
    path.write_text('[{"id": "SMTK-1", "sym', encoding="utf-8")     # torn

    assert [r["id"] for r in trade_journal._load()] == ["SMTK-1", "GRNQ-2", "MASK-3"]
    assert trade_journal.last_error() and "recovered" in trade_journal.last_error()

    _buy()
    assert len(_rows(path)) == 4
    # The corrupt file never became the backup, and the backup is intact.
    assert len(_rows(bak)) == 3
    # The damaged file was kept for a human to look at.
    assert list(path.parent.glob("trades.unreadable-*.json"))

    _buy()                      # the second save is what used to wipe the .bak
    assert len(_rows(path)) == 5
    assert len(_rows(bak)) == 4


@pytest.mark.parametrize("bak_content", [None, "not json {"])
def test_corrupt_file_and_no_usable_bak_refuses_to_write(path, bak_content):
    bad = '[{"id": "SMTK-1", "sym'
    path.write_text(bad, encoding="utf-8")
    bak = path.with_suffix(".bak")
    if bak_content is not None:
        bak.write_text(bak_content, encoding="utf-8")

    for write in (_buy,
                  lambda: trade_journal.record_close("public", "a", "SMTK", 1),
                  lambda: trade_journal.delete_trade("SMTK-1")):
        with pytest.raises(trade_journal.JournalUnreadable):
            write()

    assert path.read_text(encoding="utf-8") == bad
    if bak_content is None:
        assert not bak.exists()
    else:
        assert bak.read_text(encoding="utf-8") == bak_content


def test_a_persistent_read_lock_raises_instead_of_using_a_stale_bak(path, monkeypatch):
    path.write_text(json.dumps(HISTORY), encoding="utf-8")
    path.with_suffix(".bak").write_text(json.dumps(HISTORY[:1]), encoding="utf-8")
    real = Path.read_text

    def locked(self, *a, **kw):
        if self == path:
            raise PermissionError(13, "locked by another process")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", locked)
    with pytest.raises(trade_journal.JournalUnreadable):
        _buy()
    monkeypatch.setattr(Path, "read_text", real)
    assert len(_rows(path)) == 3


def test_a_transient_read_lock_is_retried(path, monkeypatch):
    path.write_text(json.dumps(HISTORY), encoding="utf-8")
    real = Path.read_text
    fails = {"n": 2}

    def flaky(self, *a, **kw):
        if self == path and fails["n"]:
            fails["n"] -= 1
            raise PermissionError(13, "Drive is uploading it")
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", flaky)
    _buy()
    monkeypatch.setattr(Path, "read_text", real)
    assert len(_rows(path)) == 4


def test_read_only_callers_degrade_instead_of_crashing(path):
    path.write_text(json.dumps(HISTORY), encoding="utf-8")
    assert len(trade_journal.get_trades()) == 3
    path.write_text("garbage", encoding="utf-8")             # no .bak either
    # Serves the last rows it did read rather than raising into the GUI.
    assert len(trade_journal.get_trades()) == 3
    trade_journal.get_portfolio()
    trade_journal.split_adjusted()
    trade_journal._cache.clear()
    assert trade_journal.get_trades() == []                   # nothing cached


def test_bak_is_not_clobbered_by_a_shrunk_file(path):
    path.write_text(json.dumps(HISTORY), encoding="utf-8")
    _buy()                                                    # .bak = 3 rows
    bak = path.with_suffix(".bak")
    assert len(_rows(bak)) == 3

    path.write_text("[]", encoding="utf-8")                   # something truncated it
    _buy()
    _buy()
    assert len(_rows(bak)) == 3, "the backup must outlive a truncated journal"


def test_an_intentional_delete_still_saves(path):
    path.write_text(json.dumps(HISTORY), encoding="utf-8")
    assert trade_journal.delete_trade("GRNQ-2") is True
    assert [r["id"] for r in _rows(path)] == ["SMTK-1", "MASK-3"]
    assert len(_rows(path.with_suffix(".bak"))) == 3          # pre-delete copy
