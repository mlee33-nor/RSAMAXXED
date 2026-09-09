"""trades.json is the product, and it used to be written where a crash could eat it.

Every share this tool bought or sold, the cost basis under every open position,
and the whole realized-P/L figure live in one JSON file that nothing else can
reconstruct: the brokers do not know which of your shares came from here, and
the cloud feed carries plays, not your fills.

It was written with a plain `write_text` — truncate, then write. Force-quit the
GUI, lose power, or hit a full disk in between and the journal is empty or cut
in half. The app then opens on a portfolio with nothing in it and every open
position reads as closed. This was known: etf_journal has been atomic since the
day it was added, with a docstring naming trade_journal as the one still
exposed.

These tests are about the guarantee, not the mechanism — that the file is
either the old contents or the new contents, and never a fragment.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import trade_journal


@pytest.fixture()
def journal(tmp_path, monkeypatch):
    """A journal in a temp dir, with one trade already recorded."""
    path = tmp_path / "trades.json"
    monkeypatch.setattr(trade_journal, "_FILE", path)
    trade_journal._cache.clear()
    trade_journal.record_trade(broker="public", account_id="Public 1 (1234)",
                               side="buy", symbol="SMTK", qty=1, fill_price=0.25)
    trade_journal._cache.clear()
    return path


def test_a_recorded_trade_survives_a_reread(journal):
    rows = json.loads(journal.read_text(encoding="utf-8"))
    assert [r["symbol"] for r in rows] == ["SMTK"]


def test_the_write_leaves_no_temp_file_behind(journal):
    """A stray trades.tmp beside the journal is how the next reader gets
    confused about which file is real."""
    assert not list(journal.parent.glob("*.tmp"))


def test_a_failed_write_leaves_the_previous_journal_intact(journal, monkeypatch):
    """THE WHOLE POINT. The old code truncated the real file first, so a
    failure here left nothing at all. Now the failure happens to the temp file
    and the journal is untouched."""
    before = journal.read_text(encoding="utf-8")

    real_replace = trade_journal.os.replace

    def die(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(trade_journal.os, "replace", die)
    with pytest.raises(OSError):
        trade_journal.record_trade(broker="public", account_id="Public 1 (1234)",
                                   side="sell", symbol="SMTK", qty=1,
                                   fill_price=4.75)

    monkeypatch.setattr(trade_journal.os, "replace", real_replace)
    assert journal.read_text(encoding="utf-8") == before
    assert json.loads(journal.read_text(encoding="utf-8"))    # still valid JSON


def test_the_previous_version_is_kept_as_a_backup(journal):
    """Cheapest possible insurance on the one file with no other source."""
    trade_journal._cache.clear()
    trade_journal.record_trade(broker="public", account_id="Public 1 (1234)",
                               side="sell", symbol="SMTK", qty=1, fill_price=4.75)

    backup = journal.with_suffix(".bak")
    assert backup.exists()
    # The backup is the state BEFORE the sell — one trade, not two.
    assert len(json.loads(backup.read_text(encoding="utf-8"))) == 1
    assert len(json.loads(journal.read_text(encoding="utf-8"))) == 2


def test_a_missing_backup_never_blocks_the_save(journal, monkeypatch):
    """A failed backup is worth a save; a failed save is not worth a backup."""
    def die(src, dst):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(trade_journal.shutil, "copy2", die)
    trade_journal._cache.clear()
    trade_journal.record_trade(broker="public", account_id="Public 1 (1234)",
                               side="sell", symbol="SMTK", qty=1, fill_price=4.75)

    assert len(json.loads(journal.read_text(encoding="utf-8"))) == 2
