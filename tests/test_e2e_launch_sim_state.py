"""End-to-end launch simulation, part 3: single instance, damaged state files
at launch, and a seeded concurrency stress run. See test_e2e_launch_sim."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from sim_harness import A, ALL_BROKERS
from test_e2e_launch_sim import FRI, _idle, boot, sim, standard_feed  # noqa: F401
from test_e2e_launch_sim_failures import (assert_no_duplicates, exit_called,
                                          held_everywhere, run_for, split_everywhere)

ROOT = Path(__file__).resolve().parent.parent


# ===================================================== 8. single instance

def _name():
    return f"Local\\RSAMAXXED-simtest-{uuid.uuid4().hex[:12]}"


def test_8_second_copy_in_the_same_process_is_refused(tmp_path):
    name = _name()
    lock = tmp_path / "x.lock"
    assert A._acquire_single_instance(name, lock)
    try:
        assert A._acquire_single_instance(name, lock) is False
    finally:
        A._release_single_instance(name)
    assert A._acquire_single_instance(name, lock)
    A._release_single_instance(name)


def test_8_file_lock_fallback_refuses_a_second_holder(tmp_path):
    lock = tmp_path / "x.lock"
    a, b = _name(), _name()
    assert A._acquire_single_instance(a, lock, use_mutex=False)
    try:
        assert A._acquire_single_instance(b, lock, use_mutex=False) is False
    finally:
        A._release_single_instance(a)
    assert A._acquire_single_instance(b, lock, use_mutex=False)
    A._release_single_instance(b)


def _probe(name, lock, use_mutex):
    code = ("import os,sys; os.environ['RSA_NO_CRASH_LOG']='1'; "
            f"sys.path.insert(0, {str(ROOT)!r}); import app; "
            f"sys.exit(0 if app._acquire_single_instance({name!r}, app.Path({str(lock)!r}), "
            f"use_mutex={use_mutex}) else 3)")
    env = dict(os.environ, RSA_NO_CRASH_LOG="1")
    return subprocess.run([sys.executable, "-c", code], env=env, cwd=str(lock.parent),
                          capture_output=True, timeout=120,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).returncode


@pytest.mark.parametrize("use_mutex", [True, False])
def test_8_a_second_process_is_refused_while_the_first_runs(tmp_path, use_mutex):
    """The real double-launch: another PROCESS. Only the guard function runs
    there -- importing app builds no window."""
    name, lock = _name(), tmp_path / "x.lock"
    assert A._acquire_single_instance(name, lock, use_mutex=use_mutex)
    try:
        assert _probe(name, lock, use_mutex) == 3
    finally:
        A._release_single_instance(name)
    assert _probe(name, lock, use_mutex) == 0


def test_8_the_refused_copy_exits_before_touching_any_state(tmp_path, monkeypatch):
    name = _name()
    monkeypatch.setattr(A, "_single_instance_name", lambda root=None: name)
    told = []
    monkeypatch.setattr(A, "_notify_already_running", lambda *a, **k: told.append(1))
    state = tmp_path / "state"
    state.mkdir()
    (state / "mirror_state.json").write_text('{"enabled": true}', encoding="utf-8")
    before = {p.name: p.read_bytes() for p in state.iterdir()}
    assert A._acquire_single_instance(name, tmp_path / "x.lock")
    try:
        with pytest.raises(SystemExit) as exc:
            A._single_instance_or_exit()
        assert exc.value.code == 0 and told == [1]
    finally:
        A._release_single_instance(name)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == before


# ============================================ 9. damaged state at launch

BOM = b"\xef\xbb\xbf"


def _bytes(p: Path):
    return p.read_bytes() if p.exists() else None


def _two_picks(sim):
    """AAA already bought everywhere (journal), BBB new."""
    standard_feed(sim, ("AAA", "BBB"))
    held_everywhere(sim, "AAA")


@pytest.mark.parametrize("damage", ["garbage", "empty", "truncated"])
def test_9_unreadable_trades_json_buys_nothing_and_keeps_the_file(sim, damage):
    _two_picks(sim)
    sim.seed_mirror()
    p = sim.path("trades")
    for bak in p.parent.glob("trades*.bak"):
        bak.unlink()
    good = p.read_bytes()
    bad = {"garbage": b'{"not": "a list"', "empty": b"",
           "truncated": good[: len(good) // 2]}[damage]
    p.write_bytes(bad)
    boot(sim)
    run_for(sim, 2 * 3600)
    assert sim.orders() == []
    assert any(k == "error" and "journal" in m.lower() for m, k in sim.app.notes), sim.app.notes
    assert p.read_bytes() == bad, "the unreadable journal was overwritten"
    assert sim.idle_ok() == []


def test_9_corrupt_trades_json_with_a_backup_recovers_and_rebuys_nothing(sim):
    _two_picks(sim)
    sim.seed_mirror()
    p = sim.path("trades")
    assert any(p.parent.glob("trades*.bak")), "harness: no backup was written"
    p.write_bytes(b'[{"id": "torn')
    boot(sim)
    run_for(sim, 3600)
    assert_no_duplicates(sim)
    assert not sim.orders(symbol="AAA")
    assert sim.ledger(side="buy") == sim.every_account("BBB")
    assert len(sim.journal(symbol="AAA")) == 25, "recovered history lost"
    assert sim.idle_ok() == []


def test_9_bom_trades_json_reads_cleanly(sim):
    _two_picks(sim)
    sim.seed_mirror()
    p = sim.path("trades")
    p.write_bytes(BOM + p.read_bytes())
    boot(sim)
    assert not sim.orders(symbol="AAA")
    assert sim.ledger(side="buy") == sim.every_account("BBB")
    assert sim.idle_ok() == []


@pytest.mark.parametrize("damage", ["garbage", "empty"])
def test_9_unreadable_mirror_state_keeps_mirror_off_and_the_file(sim, damage):
    _two_picks(sim)
    sim.seed_mirror()
    p = sim.path("mirror_state")
    bad = {"garbage": b'{"enabled": true, "executed": [["2026-10-02", "AAA"]', "empty": b""}[damage]
    p.write_bytes(bad)
    boot(sim)
    run_for(sim, 2 * 3600)
    assert sim.orders() == []
    assert any(k == "error" and "mirror" in m.lower() for m, k in sim.app.notes), sim.app.notes
    assert p.read_bytes() == bad
    assert sim.idle_ok() == []


def test_9_bom_mirror_state_keeps_its_executed_record(sim):
    """A pick mirror launched (executed, run on record) whose fills never
    reached the journal (the orders may be live): never bought again."""
    standard_feed(sim, ("AAA", "BBB"))
    run = A.mirror_journal.start_run(symbol="AAA", side="buy", qty="1",
                                     brokers=list(ALL_BROKERS), pick_date=FRI)
    A.mirror_journal.flush()
    assert run
    sim.seed_mirror(executed=[[FRI, "AAA"]])
    p = sim.path("mirror_state")
    p.write_bytes(BOM + p.read_bytes())
    boot(sim)
    run_for(sim, 2 * 3600)
    assert not sim.orders(symbol="AAA")
    assert sim.ledger(side="buy") == sim.every_account("BBB")
    assert sim.idle_ok() == []


def _sell_setup(sim):
    held_everywhere(sim, "AAA")
    split_everywhere(sim, "AAA")
    exit_called(sim, "AAA")
    sim.clock.set_et(datetime(2026, 10, 5, 10, 0, 0))
    sim.seed_mirror(enabled=False)


@pytest.mark.parametrize("damage", ["garbage", "empty"])
def test_9_unreadable_autosell_state_sells_nothing_and_keeps_the_file(sim, damage):
    _sell_setup(sim)
    p = sim.path("autosell_state")
    bad = {"garbage": b'{"enabled": true, "sold": ["2026-10-05:AAA:', "empty": b""}[damage]
    p.write_bytes(bad)
    sim.launch()
    run_for(sim, 2 * 3600)
    assert sim.orders(side="sell") == []
    assert any(k == "error" and "auto-sell" in m.lower() for m, k in sim.app.notes), sim.app.notes
    assert p.read_bytes() == bad
    assert sim.idle_ok() == []


def test_9_bom_autosell_state_is_loud_and_not_wiped(sim):
    _sell_setup(sim)
    sim.seed_autosell(enabled=True, dry_run=False)
    p = sim.path("autosell_state")
    raw = BOM + p.read_bytes()
    p.write_bytes(raw)
    sim.launch()
    run_for(sim, 2 * 3600)
    assert_no_duplicates(sim)
    # Whatever it makes of the BOM: never wiped, and never silent.
    assert p.read_bytes() == raw or json.loads(p.read_text(encoding="utf-8-sig"))["enabled"]
    sold = bool(sim.orders(side="sell"))
    loud = any(k == "error" and "auto-sell" in m.lower() for m, k in sim.app.notes)
    assert sold or loud, sim.app.notes


# FIXED (fix4/sell, was BUG-E): _load_autosell_state reads utf-8-sig.
def test_9_bom_autosell_state_still_sells(sim):
    _sell_setup(sim)
    sim.seed_autosell(enabled=True, dry_run=False)
    p = sim.path("autosell_state")
    p.write_bytes(BOM + p.read_bytes())
    sim.launch()
    run_for(sim, 2 * 3600)
    assert sim.ledger(side="sell") == sim.every_account("AAA", side="sell")


@pytest.mark.parametrize("damage", [
    "clean",
    # FIXED (fix4/sell, was BUG-F): _load_sells reads utf-8-sig, and a file
    # that will not read is kept (atomic.load_state) and never saved over.
    "bom",
    "garbage",
])
def test_9_damaged_sells_json_is_not_wiped_by_the_next_pull(sim, damage):
    _sell_setup(sim)
    sim.seed_autosell(enabled=False)
    # An exit known only locally (imported from the alert channel last week).
    old = {"source_id": "local:OLDX", "symbol": "OLDX", "exit_price": 2.0,
           "sell_date": "2026-10-01", "posted_at": "2026-10-01T15:00:00+00:00",
           "legs": [{"broker": "Public", "accounts_low": 5, "accounts_high": 5}]}
    text = json.dumps([old]).encode("utf-8")
    p = sim.path("sells")
    p.write_bytes({"clean": text, "bom": BOM + text, "garbage": text[:-5]}[damage])
    sim.launch()
    run_for(sim, 600)
    assert "OLDX" in p.read_text(encoding="utf-8-sig", errors="replace")


# ================================================= 10. concurrency stress


STRESS_SEEDS = [20261010, 7, 99]


@pytest.mark.parametrize("seed", STRESS_SEEDS)
def test_10_desk_mirror_autosell_retry_and_env_reload_interleaved(sim, monkeypatch,
                                                                  tmp_path, seed):
    """Desk tickets, Retry, auto-sell checks and mirror checks fired as timers
    while broker threads are mid-order (the clock free-runs while they work),
    with a .env reload hammering broker_logins from its own thread."""
    rng = random.Random(seed)
    picks = [f"PK{c}" for c in "ABCDEF"]
    standard_feed(sim, picks)
    for x in ("XA", "XB", "XC"):
        held_everywhere(sim, x)
        split_everywhere(sim, x)
        exit_called(sim, x, brokers=rng.sample(ALL_BROKERS, 4))
    for b in sim.brokers.values():
        b.latency = (0.002, 0.025)
    sim.seed_mirror()
    sim.seed_autosell(enabled=True, dry_run=False)
    desk_syms = [f"DSK{c}" for c in "ABCDEFGH"]
    for d in desk_syms:
        sim.market.set(d, 1.0)
        for b in ("fidelity", "wellsfargo", "ibkr"):
            sim.brokers[b].set_mode("partial", side="buy", symbol=d, times=1)

    env_file = tmp_path / ".env"
    env_file.write_text("SIM_STRESS_KEY=1\n", encoding="utf-8")
    from dotenv import load_dotenv as real_load
    monkeypatch.setattr(A, "ENV_FILE", env_file)
    monkeypatch.setattr(A, "load_dotenv", real_load)
    stop = threading.Event()
    reloads = [0]

    def hammer():
        while not stop.is_set():
            A._reload_env()
            reloads[0] += 1
            time.sleep(0.0005)
    th = threading.Thread(target=hammer, daemon=True)     # untracked: never "busy"
    th.start()

    stats = {"desk": 0, "refused": 0, "retry": 0, "considered": 0, "checks": 0}
    desk_sent: dict = {}
    desk_batches: list = []

    def desk():
        app = sim.app
        sym = rng.choice(desk_syms)
        brokers = set(rng.sample(ALL_BROKERS, rng.randint(1, 3)))
        app._trade_selected_brokers = brokers
        app._trade_side.set("buy")
        app._trade_symbol.set(sym)
        app._trade_qty.set("1")
        if brokers & app._brokers_in_flight:
            stats["refused"] += 1
        else:
            for b in brokers:
                desk_sent[(b, sym)] = desk_sent.get((b, sym), 0) + 1
            stats["desk"] += 1
        before = getattr(app, "_trade_batch", None)
        app._trade_execute()
        after = getattr(app, "_trade_batch", None)
        if after is not None and after is not before:
            desk_batches.append(after)

    def retry():
        app = sim.app
        for b in desk_batches:
            if b.get("finished") and not b.get("_sim_retried"):
                plan = A.App._failed_account_plan(b["results"])
                if plan:
                    b["_sim_retried"] = True
                    app._retry_plan = plan
                    app._retry_order = {"side": "buy", "symbol": b["symbol"], "qty": "1"}
                    app._retry_failed_accounts()
                    stats["retry"] += 1
                    return

    def consider():
        stats["considered"] += 1
        sim.app._autosell_consider("stress")

    def check():
        stats["checks"] += 1
        sim.app._mirror_check_now("manual")

    sim.launch()
    for _ in range(60):
        action = rng.choices([desk, retry, consider, check], [5, 3, 1, 1])[0]
        sim.app.after(int(rng.uniform(0, 3 * 3600) * 1000), action)
    t0 = time.monotonic()
    try:
        sim.settle(max_fake_s=3 * 3600 + 60, free_run_s=0.5, real_timeout_s=200)
        sim.pump(lambda: _idle(sim) and not sim.app._trade_in_flight,
                 max_fake_s=6 * 3600, free_run_s=0.5, real_timeout_s=200)
        run_for(sim, 3600)
    finally:
        stop.set()
        th.join(5)
        os.environ.pop("SIM_STRESS_KEY", None)
    elapsed = time.monotonic() - t0
    print(f"stress[{seed}]: {stats} reloads={reloads[0]} orders={len(sim.orders())} "
          f"{elapsed:.1f}s")

    assert reloads[0] > 50
    assert stats["refused"] >= 1, "no ticket ever met a busy broker: no interleaving"
    assert stats["retry"] >= 1, "Retry never ran"
    # One order at a time per broker, whoever sent it.
    assert {b: x.max_concurrent for b, x in sim.brokers.items() if x.max_concurrent > 1} == {}
    # Mirror picks: exactly once per account everywhere.
    for s in picks:
        assert sim.ledger(side="buy", symbol=s) == sim.every_account(s), s
    # Exits: every account at the called brokers sold once.
    for x in ("XA", "XB", "XC"):
        got = sim.ledger(side="sell", symbol=x)
        called = sorted({k[0] for k in got})
        assert len(called) == 4, (x, called)
        assert got == sim.every_account(x, side="sell", brokers=called), x
    # Desk + Retry: never more than the user asked for, per account.
    for (b, a, s, side), n in sim.ledger().items():
        if s.startswith("DSK"):
            assert n <= desk_sent.get((b, s), 0), ((b, a, s), n, desk_sent.get((b, s)))
    # No crossed or lost results: every fill journaled once, at its own
    # broker/account/symbol/side, and nothing journaled that did not fill.
    filled: dict = {}
    for o in sim.orders():
        if o.status == "filled":
            k = (o.broker, o.account, o.symbol, o.side)
            filled[k] = filled.get(k, 0) + 1
    journaled = {k: v for k, v in sim.journal_ledger().items()
                 if not (k[3] == "buy" and k[2] in ("XA", "XB", "XC"))}   # seeded
    assert journaled == filled
    assert sim.idle_ok() == [], sim.idle_ok()
    assert sim.callback_errors == [], sim.callback_errors[:1]
