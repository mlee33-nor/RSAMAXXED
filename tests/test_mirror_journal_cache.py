"""mirror_journal keeps the journal in memory and writes it in the background.

The file is ~1.3MB and used to be parsed and rewritten on the Tk main thread
once per broker leg. These pin the contract that made moving that write off
the main thread safe: a read right after a write sees it, writes land on disk
in order with nothing lost, flush() really drains, and the page cache moves
once per change rather than once more when the file catches up.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mirror_journal as mj


@pytest.fixture
def journal(tmp_path, monkeypatch):
    mj.flush()      # nothing of a previous test may land in this one's file
    monkeypatch.setattr(mj, "_FILE", tmp_path / "mirror_runs.json")
    monkeypatch.setattr(mj, "_cache", None)
    monkeypatch.setattr(mj, "_cache_stat", None)
    monkeypatch.setattr(mj, "_dirty", False)
    monkeypatch.setattr(mj, "_inflight", False)
    yield mj
    mj.flush()


def on_disk(j):
    return json.loads(j._FILE.read_text(encoding="utf-8"))


def leg(broker, ok=1):
    return {"broker": broker, "state": "success", "ok_accounts": ok,
            "fail_accounts": 0, "shares": 1.0, "errors": [],
            "accounts": [{"account_id": f"{broker}-1", "ok": True, "message": "ok"}]}


def test_a_read_straight_after_a_write_sees_it(journal):
    run = journal.start_run(symbol="aifa", side="buy", qty="1", brokers=["public"])
    journal.record_leg(run, leg("public"))
    got = journal.runs()
    assert got[0]["id"] == run
    assert got[0]["legs"][0]["broker"] == "public"


def test_flush_puts_everything_on_disk_in_order(journal):
    run = journal.start_run(symbol="AIFA", side="buy", qty="1",
                            brokers=["a", "b", "c", "d"])
    for b in "abcd":
        journal.record_leg(run, leg(b))
    journal.finish_run(run, ok_accounts=4, fail_accounts=0, shares=4.0, elapsed=1.0)
    assert journal.flush() is True
    data = on_disk(journal)
    (saved,) = data["runs"]
    assert [l["broker"] for l in saved["legs"]] == list("abcd")
    assert saved["finished_at"] and saved["ok_accounts"] == 4


def test_the_background_writer_gets_there_without_a_flush(journal):
    journal.record_scan(trigger="schedule", considered=3, queued=1,
                        skipped=[{"symbol": "X", "reason": "old"}])
    deadline = time.time() + 5
    while time.time() < deadline:
        if journal._FILE.exists() and on_disk(journal)["scans"]:
            break
        time.sleep(0.02)
    assert on_disk(journal)["scans"][0]["skipped"][0]["symbol"] == "X"


def test_the_file_is_written_compact(journal):
    journal.record_scan(trigger="t")
    journal.flush()
    assert "\n" not in journal._FILE.read_text(encoding="utf-8")


def test_the_version_moves_once_per_change_not_again_on_the_write(journal):
    v0 = journal.version()
    journal.record_scan(trigger="t")
    v1 = journal.version()
    assert v1 != v0
    journal.flush()
    assert journal.version() == v1     # the disk catching up is not a change


def test_a_change_made_by_something_else_is_picked_up(journal):
    journal.record_scan(trigger="ours")
    journal.flush()
    v = journal.version()
    other = on_disk(journal)
    other["scans"].append({"at": "2099-01-01T00:00:00", "trigger": "theirs",
                           "slot": "", "considered": 0, "queued": 0, "skipped": []})
    time.sleep(0.01)
    journal._FILE.write_text(json.dumps(other), encoding="utf-8")
    assert journal.version() != v
    assert journal.scans()[0]["trigger"] == "theirs"


def test_readers_share_one_parse(journal, monkeypatch):
    journal.record_scan(trigger="t")
    journal.flush()
    parses = []
    real = journal._read_file
    monkeypatch.setattr(journal, "_read_file",
                        lambda: parses.append(1) or real())
    journal.runs()
    journal.scans()
    journal.summary(days=30)
    assert parses == []


def test_a_corrupt_file_still_reads_as_empty(journal):
    journal._FILE.write_text("{not json", encoding="utf-8")
    assert journal.runs() == [] and journal.scans() == []
