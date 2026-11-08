"""Silent updates (modules/updater.py + modules/update_apply.py).

No network and no GUI: GitHub is a fake `http_get`, the "app" the installer
relaunches is a tiny script, and every install happens in a temp folder.
"""
from __future__ import annotations

import base64
import os
import io
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from modules import update_apply as ua
from modules import updater


# ----------------------------------------------------------------- helpers

KEY = Ed25519PrivateKey.generate()
PUB = base64.b64encode(KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


@pytest.fixture(autouse=True)
def _test_key(monkeypatch):
    monkeypatch.setattr(updater, "PUBLIC_KEY_B64", PUB)
    monkeypatch.delenv("RSA_AUTO_UPDATE", raising=False)
    monkeypatch.delenv("RSA_UPDATE_EXPECT", raising=False)


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def sign(payload: dict, key=KEY) -> dict:
    raw = json.dumps(payload, sort_keys=True).encode()
    return {"payload": base64.b64encode(raw).decode(),
            "signature": base64.b64encode(key.sign(raw)).decode()}


def release(version: str, files: dict, **over) -> tuple:
    """(zip_bytes, signed doc) for a release made of `files`."""
    zb = make_zip(files)
    payload = {
        "app": "RSAMAXXED", "version": version, "tag": f"v{version}",
        "zip_name": f"RSAMAXXED-v{version}.zip", "zip_sha256": ua.sha256_bytes(zb),
        "git_tree": "0" * 40,
        "requirements_sha256": ua.text_sha256(files.get("requirements.txt", b"") if
                                              isinstance(files.get("requirements.txt"), bytes)
                                              else (files.get("requirements.txt") or "").encode()),
        "files": {n: ua.sha256_bytes(d if isinstance(d, bytes) else d.encode())
                  for n, d in files.items()},
    }
    payload.update(over)
    return zb, sign(payload)


def fake_github(version: str, zb: bytes, doc: dict):
    tag = f"v{version}"
    urls = {
        updater.LATEST_URL: json.dumps({"tag_name": tag, "assets": [
            {"name": f"RSAMAXXED-{tag}.zip", "browser_download_url": "zip"},
            {"name": f"RSAMAXXED-{tag}.update.json", "browser_download_url": "sig"},
        ]}).encode(),
        "zip": zb,
        "sig": json.dumps(doc).encode(),
    }
    calls = []

    def get(url, *, accept, max_bytes):
        calls.append(url)
        return urls[url]
    get.calls = calls
    return get


def install_dir(tmp_path: Path, files: dict) -> Path:
    app = tmp_path / "app"
    for name, data in files.items():
        p = app / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding="utf-8")
    return app


OLD = {"app.py": "print('old')\n", "modules/x.py": "X = 1\n",
       "gone.py": "old only\n", "requirements.txt": "requests\n"}
NEW = {"app.py": "print('new')\n", "modules/x.py": "X = 2\n",
       "added.py": "new file\n", "requirements.txt": "requests\n"}
PERSONAL = {".env": "SECRET=1\n", "trades.json": "[1]\n", "mirror_state.json": "{}\n",
            "sessions/rh.pkl": "cookie\n", "logs/trade_results.log": "x\n"}


# ----------------------------------------------------------- versions/paths

def test_version_compare():
    assert ua.is_newer("1.1.4", "1.1.3")
    assert ua.is_newer("v1.2.0", "1.1.10")
    assert not ua.is_newer("1.1.3", "1.1.3")
    assert not ua.is_newer("1.1.10", "1.2")
    assert not ua.is_newer("garbage", "1.0.0")


@pytest.mark.parametrize("rel", ["../evil.py", "/abs.py", "C:/x.py", "a//b.py",
                                 ".env", "trades.json", "mirror_state.json",
                                 "sessions/x", "logs/a.log", "updates/x", ".git/config"])
def test_release_may_not_ship_unsafe_or_customer_paths(rel):
    with pytest.raises(ValueError):
        ua.check_rel_path(rel)


def test_release_may_ship_nested_json_and_app_files():
    assert ua.check_rel_path("web/railway.json") == "web/railway.json"
    assert ua.check_rel_path("modules/quiet.py") == "modules/quiet.py"


# ------------------------------------------------------------- signatures

def test_signature_round_trip():
    _, doc = release("1.1.4", NEW)
    assert updater.verify_payload(doc)["version"] == "1.1.4"


def test_wrong_key_is_refused():
    _, doc = release("1.1.4", NEW)
    other = Ed25519PrivateKey.generate()
    raw = base64.b64decode(doc["payload"])
    doc["signature"] = base64.b64encode(other.sign(raw)).decode()
    with pytest.raises(updater.UpdateError, match="signature"):
        updater.verify_payload(doc)


def test_tampered_payload_is_refused():
    _, doc = release("1.1.4", NEW)
    p = json.loads(base64.b64decode(doc["payload"]))
    p["files"]["app.py"] = "0" * 64
    doc["payload"] = base64.b64encode(json.dumps(p, sort_keys=True).encode()).decode()
    with pytest.raises(updater.UpdateError, match="signature"):
        updater.verify_payload(doc)


def test_signed_payload_shipping_a_customer_file_is_refused():
    _, doc = release("1.1.4", {**NEW, ".env": "PWNED=1\n"})
    with pytest.raises(updater.UpdateError, match="customer file"):
        updater.verify_payload(doc)


def test_zip_must_match_signed_list_exactly():
    zb, doc = release("1.1.4", NEW)
    payload = updater.verify_payload(doc)
    extra = make_zip({**NEW, "sneaky.py": "x"})
    with pytest.raises(updater.UpdateError):
        updater.extract_verified(extra, payload, Path("unused"))


# ------------------------------------------------------------ check/stage

def test_stage_newer_release(tmp_path):
    app = install_dir(tmp_path, OLD)
    zb, doc = release("1.1.4", NEW)
    staged = updater.check_and_stage(app, "1.1.3", http_get=fake_github("1.1.4", zb, doc))
    assert staged and staged.name == "1.1.4"
    assert (staged / "files" / "app.py").read_text() == NEW["app.py"]
    assert updater.find_staged(app, "1.1.3") == staged
    assert not updater.needs_pip(app, staged)


def test_same_or_older_release_is_ignored(tmp_path):
    app = install_dir(tmp_path, OLD)
    zb, doc = release("1.1.3", NEW)
    get = fake_github("1.1.3", zb, doc)
    assert updater.check_and_stage(app, "1.1.3", http_get=get) is None
    assert get.calls == [updater.LATEST_URL]      # never downloaded


def test_unsigned_release_is_not_staged(tmp_path):
    app = install_dir(tmp_path, OLD)
    zb, doc = release("1.1.4", NEW)
    doc["signature"] = base64.b64encode(b"\0" * 64).decode()
    logs = []
    assert updater.check_and_stage(app, "1.1.3", logs.append,
                                   http_get=fake_github("1.1.4", zb, doc)) is None
    assert any("signature" in m for m in logs)
    assert updater.find_staged(app, "1.1.3") is None


def test_bad_version_is_never_staged_again(tmp_path):
    app = install_dir(tmp_path, OLD)
    ua.mark_bad(app, "1.1.4", "exited on first start", permanent=True)
    zb, doc = release("1.1.4", NEW)
    assert updater.check_and_stage(app, "1.1.3",
                                   http_get=fake_github("1.1.4", zb, doc)) is None


def test_offline_never_raises(tmp_path):
    app = install_dir(tmp_path, OLD)

    def down(url, **kw):
        raise OSError("no network")
    logs = []
    assert updater.check_and_stage(app, "1.1.3", logs.append, http_get=down) is None
    assert logs and "could not check" in logs[0]


def test_requirements_change_needs_pip(tmp_path):
    app = install_dir(tmp_path, OLD)
    zb, doc = release("1.1.4", {**NEW, "requirements.txt": "requests\nnewlib==1\n"})
    staged = updater.check_and_stage(app, "1.1.3", http_get=fake_github("1.1.4", zb, doc))
    assert updater.needs_pip(app, staged)


def test_crlf_requirements_hash_the_same(tmp_path):
    a = tmp_path / "a"
    a.mkdir()
    (a / "requirements.txt").write_bytes(b"requests\r\nx\r\n")
    assert ua.requirements_sha(a) == ua.text_sha256(b"requests\nx\n")


# ---------------------------------------------------------------- install

def _stage(tmp_path, old=OLD, new=NEW, version="1.1.4"):
    app = install_dir(tmp_path, {**old, **PERSONAL})
    zb, doc = release(version, new)
    staged = updater.check_and_stage(app, "1.1.3", http_get=fake_github(version, zb, doc))
    return app, staged


def test_install_swaps_files_and_never_touches_personal_ones(tmp_path):
    app, staged = _stage(tmp_path)
    # A manifest from the last update says gone.py was ours.
    ua.write_json(ua.updates_dir(app) / ua.MANIFEST_NAME,
                  {"version": "1.1.3", "files": {k: "" for k in OLD}})
    assert ua.install(app, staged, 0, sys.executable, relaunch=False) == "installed"
    for name, data in NEW.items():
        assert (app / name).read_text() == data
    assert not (app / "gone.py").exists()
    for name, data in PERSONAL.items():
        assert (app / name).read_text() == data
    assert not (ua.updates_dir(app) / ua.JOURNAL_NAME).exists()
    assert ua.load_state(app)["installed"]["version"] == "1.1.4"
    assert not staged.exists()


def test_without_a_manifest_nothing_is_deleted(tmp_path):
    app, staged = _stage(tmp_path)
    ua.install(app, staged, 0, sys.executable, relaunch=False)
    assert (app / "gone.py").exists()


def test_tampered_staged_file_aborts_and_restores(tmp_path, monkeypatch):
    app, staged = _stage(tmp_path)
    (staged / "files" / "modules" / "x.py").write_text("X = 666\n")
    monkeypatch.setattr(ua, "launch_app", lambda *a, **k: None)
    assert ua.install(app, staged, 0, sys.executable) == "aborted"
    for name, data in OLD.items():
        assert (app / name).read_text() == data


def _fake_app(app: Path, healthy: bool, version="1.1.4"):
    """app.py that either reports healthy like the real App, or dies."""
    marker = ua.updates_dir(app) / ua.HEALTHY_NAME
    body = (f"import json, pathlib\npathlib.Path({str(marker)!r}).write_text("
            f"json.dumps({{'version': {version!r}}}))\n") if healthy else "raise SystemExit(3)\n"
    return body


def test_new_version_that_dies_is_rolled_back(tmp_path, monkeypatch):
    new = dict(NEW, **{"app.py": _fake_app(tmp_path / "app", healthy=False)})
    app, staged = _stage(tmp_path, new=new)
    launched = []
    real_launch = ua.launch_app

    def launch(app_dir, pythonw, expect, extra_env=None):
        launched.append(expect)
        return real_launch(app_dir, pythonw, expect, extra_env)
    monkeypatch.setattr(ua, "launch_app", launch)
    result = ua.install(app, staged, 0, sys.executable, health_timeout_s=30)
    assert result == "rolled-back"
    assert launched == ["1.1.4", None]          # new, then the old one again
    for name, data in OLD.items():
        assert (app / name).read_text() == data
    assert not (app / "added.py").exists()
    assert "1.1.4" in ua.load_state(app)["bad"]


def test_new_version_that_reports_healthy_is_kept(tmp_path):
    new = dict(NEW, **{"app.py": _fake_app(tmp_path / "app", healthy=True)})
    app, staged = _stage(tmp_path, new=new)
    assert ua.install(app, staged, 0, sys.executable, health_timeout_s=30) == "installed"
    assert (app / "added.py").exists()


def test_installer_waits_for_the_old_app(tmp_path, monkeypatch):
    app, staged = _stage(tmp_path)
    monkeypatch.setattr(ua, "OLD_EXIT_TIMEOUT_S", 0.5)
    import os
    assert ua.install(app, staged, os.getpid(), sys.executable,
                      relaunch=False) == "app-still-running"
    assert (app / "app.py").read_text() == OLD["app.py"]


def _journal(app, **over):
    j = {"phase": "swapping", "helper_pid": 999999, "helper_created": None,
         "mode": "zip", "from_version": "1.1.3", "to_version": "1.1.4",
         "backup": str(ua.updates_dir(app) / "backup" / "1.1.3"),
         "started": datetime.now().isoformat(timespec="seconds"),
         "replaced": [], "created": [], "deleted": []}
    j.update(over)
    ua.write_json(ua.journal_path(app), j)
    return j


def test_interrupted_swap_is_undone_at_next_start(tmp_path):
    app, staged = _stage(tmp_path)
    backup = ua.updates_dir(app) / "backup" / "1.1.3"
    (backup / "app.py").parent.mkdir(parents=True)
    (backup / "app.py").write_text(OLD["app.py"])
    (app / "app.py").write_text(NEW["app.py"])
    (app / "added.py").write_text("half\n")
    _journal(app, replaced=["app.py"], created=["added.py"])
    assert updater.startup_recover(app) == "restart"
    assert (app / "app.py").read_text() == OLD["app.py"]
    assert not (app / "added.py").exists()
    assert not ua.journal_path(app).exists()
    # Interrupted is transient: the version may be tried again tomorrow.
    assert ua.is_bad(app, "1.1.4")
    assert "until" in ua.load_state(app)["bad"]["1.1.4"]


@pytest.mark.parametrize("phase", ["waiting", "swapping", "launched"])
def test_start_refused_while_installer_is_working(tmp_path, phase):
    app = install_dir(tmp_path, OLD)
    _journal(app, phase=phase, helper_pid=os.getpid(),
             helper_created=ua.process_created(os.getpid()))
    assert updater.startup_recover(app) == "busy"


def test_the_copy_the_installer_launched_is_let_through(tmp_path, monkeypatch):
    """QA finding 1: a hand-started copy during 'launched' must wait, but the
    installer's own copy (RSA_UPDATE_EXPECT) must start."""
    app = install_dir(tmp_path, OLD)
    _journal(app, phase="launched", helper_pid=os.getpid(),
             helper_created=ua.process_created(os.getpid()))
    monkeypatch.setenv("RSA_UPDATE_EXPECT", "1.1.4")
    assert updater.startup_recover(app) == "run"


def test_reused_pid_does_not_block_starts_forever(tmp_path):
    """QA finding 2: the helper died; its pid now belongs to someone else
    (here: this test process, with a different creation time)."""
    app = install_dir(tmp_path, OLD)
    _journal(app, phase="swapping", helper_pid=os.getpid(), helper_created=12345)
    assert updater.startup_recover(app) == "restart"


def test_stale_journal_does_not_block_starts(tmp_path):
    app = install_dir(tmp_path, OLD)
    _journal(app, phase="waiting", helper_pid=os.getpid(),
             helper_created=ua.process_created(os.getpid()),
             started="2020-01-01T00:00:00")
    assert updater.startup_recover(app) == "run"


def test_locked_file_in_rollback_does_not_strand_the_rest(tmp_path, monkeypatch):
    """QA finding 4: one file that cannot be restored is reported and left
    for the next start; every other file is still put back."""
    app, staged = _stage(tmp_path)
    backup = ua.updates_dir(app) / "backup" / "1.1.3"
    for name in ("app.py", "modules/x.py"):
        (backup / name).parent.mkdir(parents=True, exist_ok=True)
        (backup / name).write_text(OLD[name])
        (app / name).write_text(NEW[name])
    _journal(app, replaced=["app.py", "modules/x.py"])
    real = ua.copy_into_place

    def flaky(src, dest):
        if dest.name == "app.py":
            raise PermissionError(13, "locked")
        real(src, dest)
    monkeypatch.setattr(ua, "copy_into_place", flaky)
    assert updater.startup_recover(app) == "run"          # kept for next time
    assert (app / "modules/x.py").read_text() == OLD["modules/x.py"]
    assert ua.read_json(ua.journal_path(app))["recover_attempts"] == 1
    monkeypatch.setattr(ua, "copy_into_place", real)
    assert updater.startup_recover(app) == "restart"
    assert (app / "app.py").read_text() == OLD["app.py"]


def test_retry_io_rides_out_a_brief_lock(monkeypatch):
    monkeypatch.setattr(ua.time, "sleep", lambda s: None)
    n = [0]

    def op():
        n[0] += 1
        if n[0] < 3:
            raise PermissionError(13, "in use")
        return "ok"
    assert ua.retry_io(op) == "ok" and n[0] == 3


def test_installer_crash_in_launched_phase_finishes_if_healthy(tmp_path):
    """QA finding 8: the installer died while watching; the new version did
    come up, so the bookkeeping it skipped is done at the next start."""
    app, staged = _stage(tmp_path)
    _journal(app, phase="launched", staged=str(staged))
    ua.write_json(ua.updates_dir(app) / ua.HEALTHY_NAME, {"version": "1.1.4"})
    assert updater.startup_recover(app) == "run"
    assert ua.load_state(app)["installed"]["version"] == "1.1.4"
    assert ua.read_json(ua.updates_dir(app) / ua.MANIFEST_NAME)["version"] == "1.1.4"


def test_startup_launches_installer_only_without_pip(tmp_path, monkeypatch):
    app, staged = _stage(tmp_path)
    launched = []
    monkeypatch.setattr(updater, "launch_installer",
                        lambda a, s, *x, **k: launched.append(s))
    assert updater.startup_install(app, "1.1.3") is True
    assert launched == [staged]


def test_startup_defers_a_pip_update(tmp_path):
    app, staged = _stage(tmp_path, new={**NEW, "requirements.txt": "newlib==2\n"})
    assert updater.startup_install(app, "1.1.3") is False


def test_opt_out(tmp_path, monkeypatch):
    app, staged = _stage(tmp_path)
    monkeypatch.setenv("RSA_AUTO_UPDATE", "false")
    assert updater.startup_install(app, "1.1.3") is False
    assert not updater.Checker(app, "1.1.3", print).start()


def test_healthy_marker_only_when_expected(tmp_path, monkeypatch):
    app = install_dir(tmp_path, OLD)
    updater.write_healthy(app, "1.1.4")
    assert not (ua.updates_dir(app) / ua.HEALTHY_NAME).exists()
    monkeypatch.setenv("RSA_UPDATE_EXPECT", "1.1.4")
    updater.write_healthy(app, "1.1.4")
    assert ua.read_json(ua.updates_dir(app) / ua.HEALTHY_NAME)["version"] == "1.1.4"


class _FakeProc:
    pid = 0


def test_launch_installer_moves_staged_out_and_writes_journal(tmp_path):
    app, staged = _stage(tmp_path)
    seen = {}

    def popen(cmd, **kw):
        seen.update(cmd=cmd, **kw)
        return _FakeProc()
    updater.launch_installer(app, staged, "pythonw.exe", popen=popen)
    helper = Path(seen["cmd"][1])
    assert helper.parent == ua.updates_dir(app) / "run"
    assert helper.read_text(encoding="utf-8") == Path(ua.__file__).read_text(encoding="utf-8")
    assert seen["cwd"] == str(helper.parent)
    # The staged folder now lives under run/, out of prune_staged's reach.
    assert not staged.exists()
    moved = Path(seen["cmd"][seen["cmd"].index("--staged") + 1])
    assert moved.parent == helper.parent and (moved / "payload.json").exists()
    updater.prune_staged(app, keep=None)
    assert moved.exists()
    j = ua.read_json(ua.journal_path(app))
    assert j["phase"] == "waiting" and j["to_version"] == "1.1.4"


def test_every_abort_relaunches_the_app(tmp_path, monkeypatch):
    """QA finding 3: a failed install never leaves the app closed."""
    app, staged = _stage(tmp_path)
    launched = []
    monkeypatch.setattr(ua, "launch_app", lambda *a, **k: launched.append(a[2]))
    shutil.rmtree(staged)                                   # payload gone
    assert ua.install(app, staged, 0, sys.executable) == "aborted"
    assert launched == [None]


def test_installer_crash_still_relaunches(tmp_path, monkeypatch):
    app, staged = _stage(tmp_path)
    launched = []
    monkeypatch.setattr(ua, "launch_app", lambda *a, **k: launched.append(a[2]))

    def boom(*a, **k):
        raise RuntimeError("bug in the installer")
    monkeypatch.setattr(ua, "install", boom)
    assert ua.main(["--app-dir", str(app), "--staged", str(staged),
                    "--pythonw", sys.executable]) == 1
    assert launched == [None]


def test_rollback_restores_old_pins(tmp_path, monkeypatch):
    """QA finding 5: a release that changed requirements and then failed its
    health check puts the OLD pins back with pip, not just the old files."""
    new = dict(NEW, **{"app.py": "raise SystemExit(3)\n",
                       "requirements.txt": "requests\nplaywright==9.9\n"})
    app, staged = _stage(tmp_path, new=new)
    pip_runs, pw_runs = [], []
    monkeypatch.setattr(ua, "run_pip", lambda a, p, l: pip_runs.append(
        (Path(a) / "requirements.txt").read_text()) or True)
    monkeypatch.setattr(ua, "run_playwright_install", lambda p, l: pw_runs.append(1))
    monkeypatch.setattr(ua, "launch_app", _launch_real_but_quiet)
    assert ua.install(app, staged, 0, sys.executable, health_timeout_s=30) == "rolled-back"
    assert pip_runs == [new["requirements.txt"], OLD["requirements.txt"]]
    assert len(pw_runs) == 2                 # playwright pin changed both ways
    assert (app / "requirements.txt").read_text() == OLD["requirements.txt"]


def _launch_real_but_quiet(app_dir, pythonw, expect, extra_env=None):
    """The real launch for the new version (it must actually exit), nothing
    for the old one."""
    if expect is None:
        return None
    return subprocess.Popen([sys.executable, str(Path(app_dir) / "app.py")])


def test_second_copy_exit_code_is_not_a_crash(tmp_path):
    app = install_dir(tmp_path, OLD)
    proc = subprocess.Popen([sys.executable, "-c",
                             f"raise SystemExit({ua.EXIT_ALREADY_RUNNING})"])
    assert ua.wait_healthy(app, proc, "1.1.4", 30) is True


@pytest.mark.parametrize("rel", [".env.", ".env ", "sessions./x", "SESSIO~1/x",
                                 "mirror_state.json ", "web/.env", "web/local.db",
                                 "a/b/.ENV"])
def test_windows_aliases_of_customer_files_are_refused(rel):
    with pytest.raises(ValueError):
        ua.check_rel_path(rel)


def test_transient_bad_mark_expires(tmp_path):
    app = install_dir(tmp_path, OLD)
    ua.mark_bad(app, "1.1.4", "pip failed", permanent=False)
    assert ua.is_bad(app, "1.1.4")
    st = ua.load_state(app)
    st["bad"]["1.1.4"]["until"] = "2000-01-01T00:00:00"
    ua.save_state(app, st)
    assert not ua.is_bad(app, "1.1.4")
    ua.mark_bad(app, "1.1.4", "exited on first start", permanent=True)
    assert ua.is_bad(app, "1.1.4")


# ----------------------------------------------------------------- timing

def ET(y, mo, d, h, mi=0):
    return datetime(y, mo, d, h, mi)


@pytest.mark.parametrize("when,quiet", [
    (ET(2026, 10, 20, 10, 0), False),      # Tuesday, market open
    (ET(2026, 10, 20, 17, 0), False),      # after-hours session
    (ET(2026, 10, 20, 21, 0), True),       # Tuesday night
    (ET(2026, 10, 21, 3, 30), True),       # before pre-market
    (ET(2026, 10, 21, 4, 0), False),       # pre-market starts
    (ET(2026, 10, 24, 12, 0), True),       # Saturday
    (ET(2026, 11, 26, 12, 0), True),       # Thanksgiving
])
def test_quiet_hours(when, quiet):
    assert updater.quiet_hours(when) is quiet


def test_quiet_hours_unknown_time_is_not_quiet():
    assert updater.quiet_hours(None) is False


def test_idle_clock_resets_on_any_busy_sample():
    t = [0.0]
    clock = updater.IdleClock(lambda: t[0])
    assert clock.sample(False) == 0
    t[0] = 300
    assert clock.sample(False) == 300
    assert clock.sample(True) == 0
    t[0] = 400
    assert clock.sample(False) == 0
    t[0] = 1000
    assert clock.sample(False) == 600


# --------------------------------------------------------------------- git

def _git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True,
                          text=True, check=True).stdout.strip()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_checkout_fast_forwards_to_signed_tag(tmp_path, monkeypatch):
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    _git(origin, "config", "user.email", "t@t")
    _git(origin, "config", "user.name", "t")
    (origin / "app.py").write_text("v1\n")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "v1")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True)
    (clone / ".env").write_text("SECRET\n")       # untracked, must survive
    (origin / "app.py").write_text("v2\n")
    _git(origin, "commit", "-qam", "v2")
    _git(origin, "tag", "v1.1.4")
    tree = _git(origin, "rev-parse", "v1.1.4^{tree}")

    assert ua.git_unfit_reason(clone) is None
    payload = {"version": "1.1.4", "tag": "v1.1.4", "git_tree": tree, "mode": "git",
               "from_version": "1.1.3", "files": {"app.py": ""}}
    staged = tmp_path / "staged"
    ua.write_json(staged / "payload.json", payload)
    assert ua.install(clone, staged, 0, sys.executable, relaunch=False) == "installed"
    assert (clone / "app.py").read_text().strip() == "v2"
    assert (clone / ".env").read_text() == "SECRET\n"

    # A tag whose tree is not the signed one is refused, and nothing moves.
    (origin / "app.py").write_text("v3\n")
    _git(origin, "commit", "-qam", "v3")
    _git(origin, "tag", "v1.1.5")
    ua.write_json(staged / "payload.json", dict(payload, version="1.1.5", tag="v1.1.5"))
    monkeypatch.setattr(ua, "launch_app", lambda *a, **k: None)
    assert ua.install(clone, staged, 0, sys.executable) == "aborted"
    assert (clone / "app.py").read_text().strip() == "v2"


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_dirty_git_checkout_is_never_updated(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "app.py").write_text("v1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "v1")
    (repo / "app.py").write_text("work in progress\n")
    assert "local changes" in ua.git_unfit_reason(repo)
    _git(repo, "checkout", "-q", "app.py")
    _git(repo, "checkout", "-qb", "feature")
    assert "feature" in ua.git_unfit_reason(repo)


# ----------------------------------------------------------- release.py

def test_release_build_of_this_repo_verifies_and_unpacks(tmp_path, monkeypatch):
    """The real `git archive` of HEAD, signed the way release.py signs, must
    pass every check a customer's app makes -- including that no tracked
    file is a path the installer refuses."""
    import release
    monkeypatch.setattr(release, "load_key", lambda: KEY)
    zip_path, sig_path = release.build("9.9.9", "HEAD", tmp_path / "dist")
    payload = updater.verify_payload(json.loads(sig_path.read_text()))
    assert payload["version"] == "9.9.9" and "app.py" in payload["files"]
    assert not any(ua.is_protected(p) for p in payload["files"])
    updater.extract_verified(zip_path.read_bytes(), payload, tmp_path / "x")
    assert (tmp_path / "x" / "app.py").exists()


# ------------------------------------------------------- app busy check

def _busy_app(**attrs):
    import app as A
    from types import SimpleNamespace
    ns = SimpleNamespace(_mirror_busy=lambda: attrs.pop("_mirror", False), **attrs)
    return A, ns


@pytest.mark.parametrize("attrs", [
    {"_trade_in_flight": True},
    {"_brokers_in_flight": {"chase"}},
    {"_mirror": True},
    {"_autosell_queue": [object()]},
    {"_queue_busy": True},
    {"_workers_running": 1},
])
def test_update_waits_for_every_kind_of_work(attrs):
    A, ns = _busy_app(**attrs)
    assert A.App._update_busy(ns) is True


def test_update_waits_for_a_held_browser_and_recent_work(monkeypatch):
    import time
    A, ns = _busy_app()
    assert A.App._update_busy(ns) is False
    lock = next(iter(A._browser_locks.values()))
    with lock:
        assert A.App._update_busy(ns) is True
    ns._worker_stamp = time.monotonic() - 60          # a trade a minute ago
    assert A.App._update_busy(ns) is True
    ns._worker_stamp = time.monotonic() - updater.IDLE_BEFORE_INSTALL_S - 1
    assert A.App._update_busy(ns) is False
