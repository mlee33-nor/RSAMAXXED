"""fix5: the last broker findings before launch, ported from the auditor's
repros (pidtest.py, locktest.py, fid.js, fidcancel.py, schwabmig.py).

  1  CRITICAL  the profile-lock liveness probe was os.kill(pid, 0): on Windows
               that is CTRL_C_EVENT and, with no console (pythonw), CPython
               falls through to TerminateProcess -- the app killed itself (lock
               holding its own pid) or an unrelated process (reused pid).
               Every kill now goes through a pinned, verified handle.
  2  HIGH      a dead lock owner left "profile is busy -- nothing was sent"
               forever after a crash: a dead owner's lock is taken over.
  3  CRITICAL  Fidelity cancel / hard-stop rows in a narrowed run used the bare
               login label, which Retry and a mirror owed leg read as "every
               account at that login" -- filled ones included.
  4  MEDIUM    Fidelity's outer except kept a raw error under the bare login
               label after a click.
  5  MEDIUM    Fidelity's confirmation test missed real confirmations and
               passed an error page.
  6  LOW       Wells Fargo: no nothing-sent row beside a login's may-exist row.
  7  LOW       Schwab cache migration never deletes on a failed move, or a
               cache whose login is just absent from .env.
  8  LOW       Robinhood bootstrap: one login's account-list failure fails
               only that login.
  +            Robinhood's market helper refuses an order it can't make a day
               order.

Only processes these tests spawn themselves are ever probed or terminated.
No window, no browser, no network, no broker, no order.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

import fidelity  # noqa: E402
import robinhood  # noqa: E402
import schwab  # noqa: E402
import wellsfargo  # noqa: E402
from modules import proc  # noqa: E402
from modules.outputs import AccountOutput  # noqa: E402

WINDOWS = os.name == "nt"
_NO_WINDOW = 0x08000000 if WINDOWS else 0


def _nothing(msg: str) -> bool:
    return "nothing was sent" in str(msg).lower()


def _may_exist(msg: str) -> bool:
    low = str(msg).lower()
    return "verify" in low and "submitted" in low


def _spawn_sleeper(*extra: str, seconds: int = 30) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", f"import time; time.sleep({seconds})", *extra],
                            creationflags=_NO_WINDOW)


def _dead_pid() -> int:
    p = subprocess.Popen([sys.executable, "-c", "pass"], creationflags=_NO_WINDOW)
    p.wait()
    return p.pid


@pytest.fixture
def sleeper():
    procs = []

    def _make(*extra):
        p = _spawn_sleeper(*extra)
        procs.append(p)
        return p
    yield _make
    for p in procs:                     # only ever our own children
        if p.poll() is None:
            p.kill()
            p.wait(timeout=10)


# ============================================== 1 liveness never signals

def _kill_calls(path: Path):
    """Calls to os.kill / TerminateProcess / taskkill in a module's code (not its prose)."""
    import ast
    src = path.read_text(encoding="utf-8-sig")
    found = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            f = node.func
            name = (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", ""))
            owner = getattr(getattr(f, "value", None), "id", "")
            if (owner, name) == ("os", "kill") or name == "TerminateProcess":
                found.append((name, node.lineno))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)                 and node.value.strip().lower() == "taskkill":
            found.append(("taskkill", node.lineno))
    return found


def test_no_module_signals_a_pid_except_the_verified_helper():
    for path in list(ROOT.glob("*.py")) + list((ROOT / "modules").rglob("*.py")):
        if path.name == "proc.py":
            continue
        assert _kill_calls(path) == [], path.name
    calls = _kill_calls(ROOT / "modules" / "proc.py")
    # One TerminateProcess (on a verified, pinned handle) and one os.kill: the
    # POSIX-only branch of pid_alive.
    assert sorted(n for n, _ in calls) == ["TerminateProcess", "kill"]
    src = (ROOT / "modules" / "proc.py").read_text(encoding="utf-8")
    i = src.index("os.kill(pid, 0)", src.index("def pid_alive"))
    assert "if not _is_windows():" in src[src.rindex("def pid_alive", 0, i):i]


def test_pid_alive_reports_without_touching_the_process(sleeper):
    child = sleeper()
    time.sleep(0.3)
    assert proc.pid_alive(child.pid) is True
    time.sleep(0.3)
    assert child.poll() is None                  # the probe did not kill it
    assert proc.pid_alive(_dead_pid()) is False
    assert proc.pid_alive(os.getpid()) is True
    assert proc.pid_alive(0) is False


def test_lock_owner_check_never_probes_this_process(monkeypatch):
    def _boom(pid):
        raise AssertionError("own pid must not be probed")
    monkeypatch.setattr(proc, "pid_alive", _boom)
    assert fidelity._lock_owner_alive(os.getpid()) is True
    assert wellsfargo._lock_owner_alive(os.getpid()) is True


@pytest.mark.skipif(not WINDOWS, reason="the CTRL_C_EVENT fall-through is Windows-only")
def test_pythonw_app_survives_a_lock_holding_its_own_pid(tmp_path):
    """pidtest.py + locktest.py 'self': under pythonw (no console) the old
    probe TerminateProcess'd the caller. The child must report SURVIVED."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.exists():
        pytest.skip("no pythonw.exe beside this interpreter")
    out = tmp_path / "child.txt"
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent(f"""
        import os, socket, subprocess, sys, time
        from pathlib import Path
        def _no_net(*a, **k):
            raise OSError("no network in tests")
        socket.socket.connect = _no_net
        sys.path.insert(0, {str(ROOT)!r})
        out = open({str(out)!r}, "w")
        def w(s):
            out.write(s + "\\n"); out.flush()
        import fidelity, wellsfargo
        from modules import proc
        tmp = Path({str(tmp_path)!r})
        fidelity._sessions_dir = lambda: tmp
        wellsfargo._sessions_dir = lambda: tmp
        kid = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                               creationflags=0x08000000)
        time.sleep(0.5)
        w("kid alive=%s" % proc.pid_alive(kid.pid))
        w("kid owner=%s" % fidelity._lock_owner_alive(kid.pid))
        time.sleep(0.3)
        w("kid running=%s" % (kid.poll() is None))
        kid.kill(); kid.wait()
        (tmp / ".profile_1.lock").write_text(str(os.getpid()))
        try:
            fidelity._acquire_profile_lock(1, timeout_s=0.5, poll_s=0.05)
            w("fidelity: ACQUIRED")
        except RuntimeError as e:
            w("fidelity: busy")
        (tmp / ".profile.lock").write_text(str(os.getpid()))
        try:
            wellsfargo._acquire_profile_lock(timeout_s=0.5, poll_s=0.05)
            w("wellsfargo: ACQUIRED")
        except RuntimeError as e:
            w("wellsfargo: busy")
        w("SURVIVED")
    """), encoding="utf-8")
    p = subprocess.run([str(pythonw), str(script)], timeout=120, creationflags=_NO_WINDOW)
    text = out.read_text(encoding="utf-8") if out.exists() else ""
    assert "SURVIVED" in text, (p.returncode, text)
    assert p.returncode == 0
    assert "kid alive=True" in text and "kid owner=True" in text
    assert "kid running=True" in text
    assert "fidelity: busy" in text and "wellsfargo: busy" in text


# ===================================== 1b kills are verified, never by pid

def test_cmdline_match_is_exact_not_a_prefix(tmp_path):
    d1 = tmp_path / "ZenFidelity_1"
    assert proc.cmdline_names_dir(f'chrome.exe --user-data-dir="{d1}" --x', d1)
    assert proc.cmdline_names_dir(f"chrome.exe --user-data-dir={d1}", d1)
    assert not proc.cmdline_names_dir(f'chrome.exe --user-data-dir="{d1}0"', d1)
    assert not proc.cmdline_names_dir(f'chrome.exe --user-data-dir="{d1}\\Default"', d1)
    assert not proc.cmdline_names_dir("chrome.exe --flag", d1)


@pytest.mark.skipif(not WINDOWS, reason="verified termination is Windows-only")
def test_terminate_verified_only_kills_the_process_it_expects(sleeper, tmp_path):
    mine = tmp_path / "Zen_10"
    other = tmp_path / "Zen_1"
    child = sleeper(f"--user-data-dir={mine}")
    time.sleep(0.5)
    image = (Path(sys.executable).name,)
    # Wrong profile (a prefix of ours), wrong image, this process: untouched.
    assert not proc.terminate_verified(child.pid, directory=other, images=image)
    assert not proc.terminate_verified(child.pid, directory=mine)      # not chrome.exe
    assert not proc.terminate_verified(os.getpid(), directory=mine, images=image)
    assert proc.terminate_browsers_on(other, images=image) == 0
    assert child.poll() is None
    # The right one, found by a snapshot (no pid list from elsewhere).
    assert proc.terminate_browsers_on(mine, images=image) == 1
    child.wait(timeout=10)
    assert proc.pid_alive(child.pid) is False


def test_terminate_verified_refuses_a_dead_or_bogus_pid(tmp_path):
    assert not proc.terminate_verified(_dead_pid(), directory=tmp_path)
    assert not proc.terminate_verified(0, directory=tmp_path)
    assert not proc.terminate_verified("x", directory=tmp_path)


def test_orphan_cleanup_goes_through_the_verified_path(monkeypatch, tmp_path):
    from modules import outputs
    seen = []
    monkeypatch.setattr(proc, "terminate_browsers_on", lambda d, **k: seen.append(Path(d)) or 2)
    (tmp_path / "SingletonLock").write_text("x")
    assert outputs.cleanup_orphaned_chrome(tmp_path) == 2
    assert seen == [tmp_path]
    assert not (tmp_path / "SingletonLock").exists()


def test_fidelity_startup_cleanup_frees_only_dead_owners_locks(monkeypatch, tmp_path, sleeper):
    monkeypatch.setattr(fidelity, "_sessions_dir", lambda: tmp_path)
    killed = []
    monkeypatch.setattr(proc, "terminate_browsers_on", lambda d, **k: killed.append(Path(d).name) or 0)
    (tmp_path / "ZenFidelity_1").mkdir()
    live = sleeper()
    (tmp_path / ".profile_1.lock").write_text(str(live.pid))
    (tmp_path / ".profile_2.lock").write_text(str(_dead_pid()))
    (tmp_path / ".profile_3.lock").write_text(str(os.getpid()))
    res = fidelity.cleanup_stale_startup()
    assert killed == ["ZenFidelity_1"]
    assert res["removed_locks"] == 1
    assert (tmp_path / ".profile_1.lock").exists()
    assert not (tmp_path / ".profile_2.lock").exists()
    assert (tmp_path / ".profile_3.lock").exists()
    assert live.poll() is None


def test_wf_reaps_orphans_only_after_it_holds_the_lock():
    import inspect
    src = inspect.getsource(wellsfargo._start_browser)
    assert src.index("_acquire_profile_lock(") < src.index("cleanup_orphaned_chrome(profile)")


# ============================================ 2 dead owner -> take over

def _lock_env(monkeypatch, tmp_path, mod):
    if mod is fidelity:
        lock = tmp_path / ".profile_1.lock"
        monkeypatch.setattr(fidelity, "_lock_file", lambda i: lock)
        acquire = functools.partial(fidelity._acquire_profile_lock, 1)
    else:
        lock = tmp_path / ".profile.lock"
        monkeypatch.setattr(wellsfargo, "_lock_file", lambda: lock)
        acquire = wellsfargo._acquire_profile_lock
    monkeypatch.setattr(mod, "_sessions_dir", lambda: tmp_path)
    monkeypatch.setattr(mod, "_clean_chrome_singletons", lambda p: None)
    return lock, acquire


def _age(lock, seconds):
    old = time.time() - seconds
    os.utime(lock, (old, old))


@pytest.mark.parametrize("mod", [fidelity, wellsfargo], ids=["fidelity", "wellsfargo"])
@pytest.mark.parametrize("old", [True, False], ids=["old", "fresh"])
def test_a_dead_owners_lock_is_taken_over(monkeypatch, tmp_path, mod, old):
    """locktest.py 'dead': this used to stay busy forever after a crash."""
    lock, acquire = _lock_env(monkeypatch, tmp_path, mod)
    lock.write_text(str(_dead_pid()))
    if old:
        _age(lock, 3600)
    assert acquire(timeout_s=2, poll_s=0.05) == lock
    assert lock.read_text() == str(os.getpid())


@pytest.mark.parametrize("mod", [fidelity, wellsfargo], ids=["fidelity", "wellsfargo"])
def test_a_lock_holding_our_own_pid_is_busy(monkeypatch, tmp_path, mod):
    lock, acquire = _lock_env(monkeypatch, tmp_path, mod)
    lock.write_text(str(os.getpid()))
    _age(lock, 3600)
    with pytest.raises(RuntimeError) as ei:
        acquire(timeout_s=0.3, poll_s=0.05)
    assert _nothing(str(ei.value))
    assert lock.read_text() == str(os.getpid())


@pytest.mark.parametrize("mod", [fidelity, wellsfargo], ids=["fidelity", "wellsfargo"])
def test_a_live_owners_old_lock_is_never_stolen(monkeypatch, tmp_path, mod, sleeper):
    """However long a live owner holds its lock (stale_s=0: any age is "old"),
    it is never stolen. The lock is written after the owner started, as a
    real one always is; a lock OLDER than its pid's process is a recycled pid
    (see test_fix6_final)."""
    lock, acquire = _lock_env(monkeypatch, tmp_path, mod)
    live = sleeper()
    time.sleep(0.3)
    lock.write_text(str(live.pid))
    with pytest.raises(RuntimeError):
        acquire(timeout_s=0.3, poll_s=0.05, stale_s=0)
    assert lock.read_text() == str(live.pid)
    assert live.poll() is None


@pytest.mark.parametrize("mod", [fidelity, wellsfargo], ids=["fidelity", "wellsfargo"])
def test_unknown_liveness_keeps_the_age_fallback(monkeypatch, tmp_path, mod):
    lock, acquire = _lock_env(monkeypatch, tmp_path, mod)
    monkeypatch.setattr(mod, "_lock_owner_alive", lambda pid, since=None: None)
    lock.write_text("4242")
    with pytest.raises(RuntimeError):
        acquire(timeout_s=0.3, poll_s=0.05, stale_s=120)      # fresh: still busy
    _age(lock, 3600)
    assert acquire(timeout_s=1, poll_s=0.05, stale_s=120) == lock


# ======================================= 3 narrowed rows never go wide

def _two_logins(monkeypatch):
    monkeypatch.setattr(fidelity, "_load_creds", lambda: [
        fidelity._LoginCred(idx_1based=1, label="Fidelity 1", username="u",
                            password="p", totp_secret=None),
        fidelity._LoginCred(idx_1based=2, label="Fidelity 2", username="u2",
                            password="p2", totp_secret=None)])
    monkeypatch.setattr(fidelity, "_otp_provider", lambda: None)
    monkeypatch.setattr(fidelity, "_trace", lambda *a, **k: None)


def test_fidelity_cancel_rows_in_a_narrowed_run_name_only_the_requested(monkeypatch):
    """fidcancel.py: narrowed to one login-1 account, a cancel returned the
    bare 'Fidelity 1' and 'Fidelity 2' plus a false 'not found'."""
    _two_logins(monkeypatch)
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 1

    want = "Fidelity 1 · Individual (Z12345678)"
    out = fidelity.execute_trade(side="buy", qty="1", symbol="ABCD", dry_run=False,
                                 only_accounts=[want], cancel_event=cancel)
    assert [a.account_id for a in out.accounts] == [want]
    assert _nothing(out.accounts[0].message)
    assert not any("None of the requested" in a.message for a in out.accounts)


def test_fidelity_cancel_rows_in_a_full_run_still_cover_every_login(monkeypatch):
    _two_logins(monkeypatch)
    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        return calls["n"] > 1

    out = fidelity.execute_trade(side="buy", qty="1", symbol="ABCD", cancel_event=cancel)
    assert [a.account_id for a in out.accounts] == ["Fidelity 1", "Fidelity 2"]
    assert all(_nothing(a.message) for a in out.accounts)


def test_fidelity_hard_stop_rows_in_a_narrowed_run_name_only_the_requested(monkeypatch):
    import test_fidelity_order_safety as FOS
    real = fidelity.execute_trade
    want = ["Fidelity 1 · Individual (X11111111)", "Fidelity 2 · Individual (X33333333)"]
    monkeypatch.setattr(fidelity, "execute_trade",
                        functools.partial(real, only_accounts=want))
    page = FOS._Page()
    out = FOS._run(monkeypatch, page, accounts=("X11111111",), logins=2,
                   preview={"X11111111": RuntimeError("browser connection lost")})
    ids = [a.account_id for a in out.accounts]
    assert "Fidelity 2" not in ids and "Fidelity 1" not in ids
    assert ids == want
    assert all(_nothing(a.message) for a in out.accounts)
    assert page.places() == []


def test_fidelity_auth_failure_in_a_narrowed_run_names_only_the_requested(monkeypatch):
    import test_fidelity_order_safety as FOS
    real = fidelity.execute_trade
    want = ["Fidelity 2 · Individual (X22222222)"]

    async def _no(*_a, **_k):
        return False

    def _wrapped(**kw):
        # _run installs a sign-in that succeeds; fail it after it does.
        monkeypatch.setattr(fidelity, "_ensure_logged_in", _no)
        return real(**kw, only_accounts=want)
    monkeypatch.setattr(fidelity, "execute_trade", _wrapped)
    out = FOS._run(monkeypatch, FOS._Page(), accounts=("X22222222",), logins=2)
    assert [a.account_id for a in out.accounts] == want
    assert _nothing(out.accounts[0].message)
    assert not any("None of the requested" in a.message for a in out.accounts)


# ============================== 4 outer except after a click: no wide row

def test_fidelity_outer_failure_after_a_click_never_goes_wide(monkeypatch):
    import test_fidelity_order_safety as FOS
    import app as A
    real = fidelity.execute_trade

    class _Boom:
        @staticmethod
        def uniform(a, b):
            raise RuntimeError("event loop went away")

    def _wrapped(**kw):
        monkeypatch.setattr(fidelity, "random", _Boom)   # between accounts
        return real(**kw)
    monkeypatch.setattr(fidelity, "execute_trade", _wrapped)
    page = FOS._Page()
    out = FOS._run(monkeypatch, page, accounts=("X11111111", "X22222222", "X33333333"))
    rows = {a.account_id: a for a in out.accounts}
    assert "Fidelity 1" not in rows                          # no bare login row
    assert rows["Fidelity 1 · Individual (X11111111)"].ok
    for n in ("X22222222", "X33333333"):
        r = rows[f"Fidelity 1 · Individual ({n})"]
        assert not r.ok and _nothing(r.message)
    assert page.places() == [("place", "X11111111")]
    res = {"broker": "fidelity",
           "accounts": [{"account_id": a.account_id, "ok": a.ok, "message": a.message}
                        for a in out.accounts]}
    plan = A.App._failed_account_plan([res])
    assert plan == {"fidelity": ["Fidelity 1 · Individual (X22222222)",
                                 "Fidelity 1 · Individual (X33333333)"]}


def test_fidelity_outer_failure_on_a_reached_account_is_may_exist(monkeypatch):
    """The account the run was on when it broke, with no row of its own, after
    a click in this run: may-exist wording, never a raw error under the login
    label (and never nothing-sent: we can't prove it)."""
    import test_fidelity_order_safety as FOS
    real = fidelity.execute_trade

    def _trace(msg, *a, **k):
        # Outside the account's own try: escapes to the login-level except.
        if "(X22222222) | starting" in msg:
            raise RuntimeError("log write failed")

    def _wrapped(**kw):
        monkeypatch.setattr(fidelity, "_trace", _trace)
        return real(**kw)
    monkeypatch.setattr(fidelity, "execute_trade", _wrapped)
    page = FOS._Page()
    out = FOS._run(monkeypatch, page, accounts=("X11111111", "X22222222", "X33333333"))
    rows = {a.account_id: a for a in out.accounts}
    assert "Fidelity 1" not in rows
    assert rows["Fidelity 1 · Individual (X11111111)"].ok
    r2 = rows["Fidelity 1 · Individual (X22222222)"]
    assert not r2.ok and "may have been submitted" in r2.message
    assert "verify in fidelity before retrying" in r2.message.lower()
    assert not _nothing(r2.message)
    r3 = rows["Fidelity 1 · Individual (X33333333)"]
    assert not r3.ok and _nothing(r3.message)
    assert page.places() == [("place", "X11111111")]


# ==================================== 5 Fidelity confirmation (node, fid.js)

_NODE = shutil.which("node")

_HARNESS = r"""
const vm = require('vm'), fs = require('fs');
const js = fs.readFileSync(process.argv[2], 'utf8');
const pages = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const el = (vis, cls) => ({className: cls || '', offsetWidth: vis ? 10 : 0,
                          offsetHeight: vis ? 10 : 0, getClientRects: () => vis ? [1] : []});
const out = pages.map(p => vm.runInNewContext(js, {document: {
    querySelector: (s) => s === '#placeOrderBtn' ? (p.btn ? el(true) : null) : null,
    querySelectorAll: (s) => (p.alerts || []).map(a => el(a.vis !== false, a.cls)),
    body: {innerText: p.text || ''},
}}));
process.stdout.write(JSON.stringify(out));
"""


def confirm_js(pages, js=None):
    """Run _ORDER_CONFIRMED_JS over fake pages in node: [{text, btn, alerts}]."""
    if not _NODE:
        pytest.skip("node is not installed")
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="fidjs_"))
    try:
        (d / "h.js").write_text(_HARNESS, encoding="utf-8")
        (d / "c.js").write_text(js or fidelity._ORDER_CONFIRMED_JS, encoding="utf-8")
        (d / "p.json").write_text(json.dumps(pages), encoding="utf-8")
        r = subprocess.run([_NODE, str(d / "h.js"), str(d / "c.js"), str(d / "p.json")],
                           capture_output=True, text=True, timeout=60,
                           creationflags=_NO_WINDOW)
        assert r.returncode == 0, r.stderr
        return json.loads(r.stdout)
    finally:
        shutil.rmtree(d, ignore_errors=True)


_CONFIRMED = [
    "Order received\nOrder number 24A0BC1D",
    "Order Received",
    "Your order has been received. Confirmation number: 24A0BC1D",
    "Your order was received",
    "Order submitted\nOrder number: 24A0BC1D",
    "Order placed. Order #24A0BC1D",
    "Thank you. Your order has been placed.",
    "Order confirmation\nOrder number: c02ab3xy",
    "Order number: 24a0bc1d",
    "Confirmation # 24A0BC1D",
    "Your order has been\nreceived",
    "order\nreceived",
    "ORDER  RECEIVED",
    "Order Received ",
    "Order number 24A0BC1D",
]

_NOT_CONFIRMED = [
    "Order notifications",
    "Order no longer valid",
    "Order number will appear here",
    "Order No. 1 of 10",
    "Order #2026",
    "Order number 2026-10-10",
    "Order numbers 1234 orders",
    "Open orders\nOrder # 24A0BC1D Buy 1 MBAI\nError: This security is not available",
    "Orders received today: 3",
    "Your order could not be placed. Order #24A0BC1D",
    "Order received\nThere was a problem with your request",
]


def test_fid_js_text_cases():
    got = confirm_js([{"text": t} for t in _CONFIRMED + _NOT_CONFIRMED])
    want = [True] * len(_CONFIRMED) + [False] * len(_NOT_CONFIRMED)
    bad = [(t, g) for t, g, w in zip(_CONFIRMED + _NOT_CONFIRMED, got, want) if g != w]
    assert bad == []


def test_fid_js_alerts_and_button():
    ok = "Order received\nOrder number: 24A0BC1D"
    got = confirm_js([
        {"text": ok, "btn": True},                                            # still on ticket
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert pvd-inline-alert--warning"}]},
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert pvd-inline-alert--caution"}]},
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert pvd-inline-alert--info"}]},
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert pvd-inline-alert--error"}]},
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert pvd-inline-alert--danger"}]},
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert"}]},                # untyped
        {"text": ok, "alerts": [{"cls": "pvd-inline-alert--error", "vis": False}]},
        {"text": ok, "alerts": [{"cls": "pvd-modal__dialog"}]},
    ])
    assert got == [False, True, True, True, False, False, False, True, False]


def test_unconfirmed_after_a_click_is_may_exist_never_nothing_sent(monkeypatch):
    import test_fidelity_order_safety as FOS
    page = FOS._Page(confirm=False)
    out = FOS._run(monkeypatch, page)
    [a] = out.accounts
    assert _may_exist(a.message) and not _nothing(a.message)


# ============================================== 6 Wells Fargo unmatched

def test_wf_no_nothing_sent_row_beside_a_logins_may_exist_row():
    """schwabmig.py tail: the may-exist login row stands for the account."""
    rows = [AccountOutput(account_id="Wells Fargo 2", ok=False, message=(
        "x — raised mid-order; the order may have been submitted, verify at "
        "the broker before sending it again"))]
    assert wellsfargo._requested_unmatched(["Wells Fargo 2 · WELLSTRADE (****0012)"], rows) == []
    # Another login's account is still reported.
    assert wellsfargo._requested_unmatched(["WELLSTRADE (****0034)"], rows) == [
        "WELLSTRADE (****0034)"]
    # A nothing-sent login row does not hide it (a retry can fix that one).
    rows2 = [AccountOutput(account_id="Wells Fargo 2", ok=False,
                           message="login failed — nothing was sent")]
    assert wellsfargo._requested_unmatched(["Wells Fargo 2 · WELLSTRADE (****0012)"], rows2) == [
        "Wells Fargo 2 · WELLSTRADE (****0012)"]
    # A nickname that merely starts with digits is login 1, not "login 2020".
    assert wellsfargo._wf_login_no("Wells Fargo 2020 IRA (****0012)") == 1
    assert wellsfargo._wf_login_no("Wells Fargo 3 · IRA (****0012)") == 3
    assert wellsfargo._wf_login_no("Wells Fargo") == 1


# ================================================= 7 Schwab migration

def _h(u):
    return hashlib.md5(u.encode()).hexdigest()


def _mk(d, name, user):
    (d / name).write_text(json.dumps({"cookies": {}, "headers": {}, "username_hash": _h(user),
                                      "password_hash": "x", "totp_secret_hash": "x"}),
                          encoding="utf-8")


@pytest.fixture
def sdir(tmp_path, monkeypatch):
    monkeypatch.setattr(schwab, "_sessions_dir", lambda: tmp_path)
    return tmp_path


def test_schwab_reorder_moves_each_to_its_owner(sdir):
    _mk(sdir, "schwab1.json", "bob")
    _mk(sdir, "schwab2.json", "alice")
    ka, kb = schwab._login_cache_paths(["alice", "bob"])
    assert schwab._cache_owner_hash(ka) == _h("alice")
    assert schwab._cache_owner_hash(kb) == _h("bob")


def test_schwab_cache_of_a_login_absent_from_env_is_kept(sdir):
    _mk(sdir, "schwab1.json", "alice")
    _mk(sdir, "schwab2.json", "carol")          # carol is only missing right now
    (ka,) = schwab._login_cache_paths(["alice"])
    assert (sdir / "schwab2.json").exists()
    assert schwab._cache_owner_hash(ka) == _h("alice")
    # carol comes back: her session migrates instead of being gone.
    _ka, kc = schwab._login_cache_paths(["alice", "carol"])
    assert schwab._cache_owner_hash(kc) == _h("carol")


def test_schwab_failed_move_leaves_the_session_in_place(sdir, monkeypatch):
    _mk(sdir, "schwab1.json", "alice")
    real_replace = Path.replace

    def boom(self, target):
        raise PermissionError(5, "Access is denied")
    monkeypatch.setattr(Path, "replace", boom)
    (ka,) = schwab._login_cache_paths(["alice"])
    assert (sdir / "schwab1.json").exists()            # not deleted
    assert not ka.exists()
    monkeypatch.setattr(Path, "replace", real_replace)
    (ka,) = schwab._login_cache_paths(["alice"])       # next start: migrates
    assert schwab._cache_owner_hash(ka) == _h("alice")


def test_schwab_idempotent_and_foreign_keyed_still_discarded(sdir):
    _mk(sdir, "schwab1.json", "alice")
    (ka,) = schwab._login_cache_paths(["alice"])
    assert schwab._login_cache_paths(["alice"]) == [ka] and ka.exists()
    _mk(sdir, ka.name, "mallory")                      # wrong owner at alice's path
    schwab._login_cache_paths(["alice"])
    assert not ka.exists()


def test_schwab_unreadable_keyed_file_is_not_deleted_on_a_guess(sdir, monkeypatch):
    _mk(sdir, "schwab1.json", "alice")
    (ka,) = schwab._login_cache_paths(["alice"])
    real = Path.read_text

    def locked(self, *a, **k):
        if self == ka:
            raise PermissionError(5, "Access is denied")
        return real(self, *a, **k)
    monkeypatch.setattr(Path, "read_text", locked)
    schwab._login_cache_paths(["alice"])
    monkeypatch.setattr(Path, "read_text", real)
    assert ka.exists()


# ================================================= 8 Robinhood bootstrap

def _rh_boot(monkeypatch, tmp_path, fail_for):
    def login(username=None, password=None, expiresIn=None, store_session=True,
              pickle_path="", pickle_name=""):
        return {"access_token": "t"}
    rh = types.SimpleNamespace(authentication=types.SimpleNamespace(login=login))
    current = {"p": None}
    monkeypatch.setattr(robinhood, "_load_rh", lambda: (rh, None))
    monkeypatch.setattr(robinhood, "_login_profiles",
                        lambda: [("Robinhood 1", "u1", "p1"), ("Robinhood 2", "u2", "p2")])
    monkeypatch.setattr(robinhood, "_pickle_path", lambda: tmp_path)
    monkeypatch.setattr(robinhood, "_log_login_transcript", lambda *a, **k: None)
    monkeypatch.setattr(robinhood, "_log_mfa_decision", lambda *a, **k: None)
    monkeypatch.setattr(robinhood, "login_with_cache",
                        lambda **kw: current.__setitem__("p", kw["pickle_name"]))

    def _accounts(_rh):
        if current["p"] in fail_for:
            raise RuntimeError("accounts endpoint 500")
        n = "11110001" if current["p"] == "Robinhood 1" else "22220002"
        return [{"account_number": n, "brokerage_account_type": "individual"}]
    monkeypatch.setattr(robinhood, "_safe_load_accounts", _accounts)
    monkeypatch.setattr(robinhood, "_RH", None)
    monkeypatch.setattr(robinhood, "_ACCOUNTS", [])
    return robinhood.bootstrap()


def test_rh_bootstrap_one_logins_account_failure_fails_only_that_login(monkeypatch, tmp_path):
    out = _rh_boot(monkeypatch, tmp_path, fail_for={"Robinhood 1"})
    assert out.state == "partial"
    assert [a[2] for a in robinhood._ACCOUNTS] == ["Robinhood 2"]
    bad = [a for a in out.accounts if not a.ok]
    assert [a.account_id for a in bad] == ["Robinhood 1"]


def test_rh_bootstrap_every_login_failing_is_a_failure(monkeypatch, tmp_path):
    out = _rh_boot(monkeypatch, tmp_path, fail_for={"Robinhood 1", "Robinhood 2"})
    assert out.state == "failed" and robinhood._ACCOUNTS == []


def test_rh_bootstrap_all_good_is_success(monkeypatch, tmp_path):
    out = _rh_boot(monkeypatch, tmp_path, fail_for=set())
    assert out.state == "success" and len(robinhood._ACCOUNTS) == 2


def test_rh_market_helper_without_time_in_force_refuses(monkeypatch):
    """The helper would default to a gtc order; Robinhood is a day-order broker."""
    import app as A
    assert "robinhood" in A.AUTOSELL_DAY_ORDER_BROKERS
    calls = []

    class _RH:
        order = None

        def order_buy_market(self, sym, q, account_number=None):
            calls.append((sym, q))
            return {"id": "never"}

    monkeypatch.setattr(robinhood, "_ensure_session", lambda: (True, ""))
    monkeypatch.setattr(robinhood, "_RH", _RH())
    monkeypatch.setattr(robinhood, "_ACCOUNTS",
                        [("INDIVIDUAL (****1234)", "5QR11234", "rh_test")])
    monkeypatch.setattr(robinhood, "login_with_cache", lambda **kw: None)
    monkeypatch.setattr(robinhood, "_max_trade_accounts", lambda: 0)
    monkeypatch.setattr(robinhood.time, "sleep", lambda s: None)
    out = robinhood.execute_trade(side="buy", qty="1", symbol="abcd")
    assert calls == []
    [a] = out.accounts
    assert not a.ok
    assert a.message == "Robinhood helper can't send a day order — nothing was sent"
    assert A._nothing_was_sent(a.message)


# ================================================ 3b app-side guards

def test_app_never_widens_a_narrowed_batch_to_a_whole_login():
    import app as A
    res = {"broker": "fidelity", "accounts": [
        {"account_id": "Fidelity 1", "ok": False, "message": "Skipped: cancelled — nothing was sent"},
        {"account_id": "Fidelity 1 · Individual (Z12345678)", "ok": False,
         "message": "Skipped: cancelled — nothing was sent"}]}
    for batch in ({"origin": "exit"}, {"origin": "retry"},
                  {"origin": "mirror", "mirror_owed_accounts": ["Fidelity 1 · Individual (Z12345678)"]}):
        assert A._batch_was_narrowed(batch)
        assert A.App._failed_account_plan([res], narrowed=A._batch_was_narrowed(batch)) == {
            "fidelity": ["Fidelity 1 · Individual (Z12345678)"]}
    assert not A._batch_was_narrowed({"origin": "desk"})
    assert not A._batch_was_narrowed({"origin": "mirror", "mirror_owed_accounts": []})


def test_mirror_owed_leg_aimed_at_accounts_never_owes_a_whole_login(env):
    import app as A
    from test_fix4_mirror import M
    m = M(brokers=("fidelity",))
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    aimed = ["Fidelity 1 · Individual (Z12345678)", "Fidelity 1 · ROTH IRA (Z87654321)"]
    res = {"broker": "fidelity", "ok_accounts": 1, "fail_accounts": 1, "errors": [],
           "accounts": [
               {"account_id": aimed[0], "ok": True, "message": "order placed"},
               {"account_id": "Fidelity 1", "ok": False,
                "message": "Skipped: cancelled — nothing was sent"}]}
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["fidelity"],
         "mirror_skipped": [], "mirror_owed": "fidelity", "mirror_run": "r",
         "mirror_owed_accounts": aimed, "results": [res]}
    A.App._mirror_owe_failed_legs(m, b)
    assert all("Fidelity 1" not in (o.get("accounts") or []) for o in m._mirror_owed)
    assert not any(o.get("broker") == "fidelity" and not o.get("accounts")
                   for o in m._mirror_owed)
    # Everything that failed positively sent nothing, so the one aimed account
    # the cancelled run never reached is owed on its own; the filled one isn't.
    owed = [a for o in m._mirror_owed if o.get("broker") == "fidelity"
            for a in (o.get("accounts") or [])]
    assert owed == [aimed[1]]


def test_aimed_leg_with_a_maybe_live_row_is_shown_not_owed(env):
    """If any failed row on the leg might have gone out, an unreached account
    can't be told from one whose order is live: show it, owe nothing."""
    import app as A
    from test_fix4_mirror import M
    m = M(brokers=("fidelity",))
    key = ("2026-10-09", "AAA")
    m._mirror_executed.add(key)
    aimed = ["Fidelity 1 · Individual (Z12345678)", "Fidelity 1 · ROTH IRA (Z87654321)"]
    res = {"broker": "fidelity", "ok_accounts": 1, "fail_accounts": 2, "errors": [],
           "accounts": [
               {"account_id": "Fidelity 2 · Individual (Z11112222)", "ok": True,
                "message": "order placed"},
               {"account_id": "Fidelity 1", "ok": False,
                "message": "Skipped: cancelled — nothing was sent"},
               {"account_id": "Fidelity 2 · Joint (Z33334444)", "ok": False,
                "message": "orders may have been submitted — verify in Fidelity "
                           "before retrying"}]}
    b = {"symbol": "AAA", "mirror_key": key, "all_brokers": ["fidelity"],
         "mirror_skipped": [], "mirror_owed": "fidelity", "mirror_run": "r",
         "mirror_owed_accounts": aimed, "results": [res]}
    A.App._mirror_owe_failed_legs(m, b)
    assert not [o for o in m._mirror_owed if o.get("broker") == "fidelity"]
    assert "Fidelity 1" in (m._mirror_failed_notes.get(key) or "")


from test_mirror_fixes_2026_10 import env  # noqa: E402,F401
