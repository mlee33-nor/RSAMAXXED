"""Install a downloaded update while the app is closed, then start it again.

WHY THIS IS A SEPARATE PROCESS
------------------------------
The app cannot safely replace itself while it runs. Its own files are only half
the problem; a release that changes requirements.txt has pip rewrite libraries
the running app has loaded, and Windows refuses to overwrite a loaded .pyd. So
the app (modules/updater.py) stages the update, starts this script, and exits.
This script waits for that process to be gone, swaps the files, runs pip if the
pins changed, starts the new version and watches it come up. If the new
version dies before it reports healthy, every file (and every pin) goes back
the way it was, the old version is started again and that release is not
tried again.

RULES THIS FILE KEEPS
---------------------
* Standard library only, and nothing imported from the app. The updater copies
  this file out of the install folder before running it, so it never executes
  from the folder it is rewriting, and the app's own modules (quiet, proc,
  atomic) may be mid-replacement while it runs. The few lines it needs from
  them are repeated here on purpose.
* A customer's own files are never written: .env (at any depth), every
  top-level .json (trades.json, mirror_state.json ...), sessions/, logs/,
  updates/, .git/ and web/local.db. A release that tries to ship one of those
  paths -- including a Windows alias of one ('.env.', 'SESSIO~1') -- is
  refused outright.
* Every file replaced or deleted is copied to updates/backup/<old version>/
  first, and updates/apply.json records what was done, so a crash halfway
  through can still be undone (the app runs recover() at its next start).
* The app is always started again, whatever happened, unless it never exited.
  A failed update must cost the customer an update, never a morning of mirror
  buys and auto-sells.
* Never os.kill(pid, 0) on Windows: it terminates the target (see
  modules/proc.py). Liveness is read through OpenProcess, and a pid is only
  "the helper" if its creation time matches too -- Windows reuses pids.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

UPDATES_DIRNAME = "updates"
JOURNAL_NAME = "apply.json"
STATE_NAME = "state.json"
HEALTHY_NAME = "healthy.json"
MANIFEST_NAME = "installed_manifest.json"

#: How long the new version has to write updates/healthy.json before it is
#: judged broken. The app writes it 20s after its window is up.
HEALTH_TIMEOUT_S = 180
#: How long to wait for the old copy to exit after it handed over.
OLD_EXIT_TIMEOUT_S = 120
PIP_TIMEOUT_S = 20 * 60
#: A journal older than this is stale whatever its pid says: the longest
#: legitimate install is a pip run plus the health wait.
JOURNAL_STALE_S = 45 * 60
#: How many times recover() retries a rollback that hit locked files before
#: it stops blocking starts on it.
RECOVER_ATTEMPTS = 5

#: Exit code of a copy of the app that found another copy already running
#: (app._single_instance_or_exit). Not a crash: never a reason to roll back.
EXIT_ALREADY_RUNNING = 75

#: Phases in which the install folder is being rewritten or the new version
#: is being watched. A copy started by hand refuses to run during these.
BUSY_PHASES = ("waiting", "swapping", "launched")

#: Top-level folders that belong to the customer, not to the release.
_PROTECTED_DIRS = ("sessions", "logs", UPDATES_DIRNAME, ".git", "__pycache__")
#: Customer files below the top level.
_PROTECTED_NESTED = ("web/local.db",)

#: How long a transient bad mark lasts. "Exited on first start" is permanent.
BAD_RETRY_AFTER = timedelta(hours=24)


# =============================================================================
# Small shared helpers (the updater imports these too)
# =============================================================================

def updates_dir(app_dir: Path) -> Path:
    return Path(app_dir) / UPDATES_DIRNAME


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def text_sha256(data: bytes) -> str:
    """sha256 with CRLF folded to LF. A git checkout on Windows writes text
    files with CRLF (core.autocrlf), the release zip may not; the same
    requirements.txt must hash the same either way."""
    return sha256_bytes(data.replace(b"\r\n", b"\n"))


def requirements_sha(app_dir: Path) -> Optional[str]:
    try:
        return text_sha256((Path(app_dir) / "requirements.txt").read_bytes())
    except OSError:
        return None


def pinned(app_dir: Path, package: str) -> Optional[str]:
    """The `package==X` line of requirements.txt, or None."""
    try:
        text = (Path(app_dir) / "requirements.txt").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(rf"^\s*{re.escape(package)}\s*==\s*(\S+)", text, re.M | re.I)
    return m.group(1) if m else None


def parse_version(v: str) -> tuple:
    """'1.1.4' / 'v1.1.4' -> (1, 1, 4). Anything else -> () (never newer)."""
    s = (v or "").strip().lstrip("vV")
    parts = s.split(".")
    try:
        nums = tuple(int(p) for p in parts)
    except ValueError:
        return ()
    return nums if 1 <= len(nums) <= 4 else ()


def is_newer(candidate: str, current: str) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    return bool(a) and bool(b) and a > b


def check_rel_path(rel: str) -> str:
    """A release path as a clean forward-slash relative path, or ValueError.

    Refuses absolute paths, drive letters, '..', the customer's own files, and
    the Windows spellings that land on one of them: a trailing dot or space is
    stripped by Windows ('.env.' IS .env) and '~' is how 8.3 short names
    ('SESSIO~1') are written.
    """
    if not isinstance(rel, str) or not rel or "\x00" in rel:
        raise ValueError(f"bad path {rel!r}")
    p = rel.replace("\\", "/")
    if p.startswith("/") or ":" in p:
        raise ValueError(f"absolute path in release: {rel!r}")
    parts = p.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"unsafe path in release: {rel!r}")
    if any(part != part.rstrip(". ") or "~" in part for part in parts):
        raise ValueError(f"path Windows would rename: {rel!r}")
    if is_protected(p):
        raise ValueError(f"release tries to ship a customer file: {rel!r}")
    return p


def is_protected(rel: str) -> bool:
    """True for paths an update must never write or delete."""
    p = rel.replace("\\", "/").lstrip("/").lower()
    parts = [part.rstrip(". ") for part in p.split("/")]
    if parts[0] in _PROTECTED_DIRS:
        return True
    if parts[-1] == ".env" or "/".join(parts) in _PROTECTED_NESTED:
        return True
    if len(parts) == 1:
        name = parts[0]
        if name.endswith(".json") or name.startswith("trades"):
            return True
        if name.endswith((".bak", ".lock", ".log")):
            return True
    return False


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path: Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    retry_io(lambda: os.replace(tmp, path))


def load_state(app_dir: Path) -> Dict[str, Any]:
    st = read_json(updates_dir(app_dir) / STATE_NAME, {})
    return st if isinstance(st, dict) else {}


def save_state(app_dir: Path, state: Dict[str, Any]) -> None:
    write_json(updates_dir(app_dir) / STATE_NAME, state)


def mark_bad(app_dir: Path, version: str, why: str, *, permanent: bool) -> None:
    st = load_state(app_dir)
    bad = dict(st.get("bad") or {})
    entry = {"why": why, "at": datetime.now().isoformat(timespec="seconds")}
    if not permanent:
        entry["until"] = (datetime.now() + BAD_RETRY_AFTER).isoformat(timespec="seconds")
    bad[version] = entry
    st["bad"] = bad
    save_state(app_dir, st)


def is_bad(app_dir: Path, version: str) -> bool:
    entry = (load_state(app_dir).get("bad") or {}).get(version)
    if not isinstance(entry, dict):
        return entry is not None
    until = entry.get("until")
    if not until:
        return True
    try:
        return datetime.now() < datetime.fromisoformat(until)
    except ValueError:
        return True


# =============================================================================
# Files on a busy Windows disk
# =============================================================================

def retry_io(fn: Callable[[], Any], attempts: int = 12) -> Any:
    """Run a file operation, retrying while something holds the file.

    Same reason as modules/atomic.replace: Google Drive's sync client and
    antivirus scanners open files the moment they change, and Windows then
    fails a rename or delete with WinError 5 / 32 for a moment.
    """
    delay = 0.1
    for i in range(attempts):
        try:
            return fn()
        except (PermissionError, OSError) as exc:
            transient = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) in (5, 32, 33)
            if not transient or i == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 2.0)


def copy_into_place(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".rsaupd")
    retry_io(lambda: shutil.copy2(src, tmp))
    retry_io(lambda: os.replace(tmp, dest))


def remove_file(path: Path) -> None:
    try:
        retry_io(path.unlink)
    except FileNotFoundError:
        pass


# =============================================================================
# Processes
# =============================================================================

_CREATE_NO_WINDOW = 0x08000000
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def no_window_kwargs() -> Dict[str, Any]:
    """Same as modules.quiet.no_window_kwargs: pip and git are console
    programs, and this script has no console, so without these each one
    would flash a black window on the customer's desktop."""
    if os.name != "nt":
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return {"creationflags": _CREATE_NO_WINDOW, "startupinfo": si}


def run_hidden(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, **no_window_kwargs(), **kwargs)


def popen_detached(cmd: List[str], **kwargs: Any) -> subprocess.Popen:
    """A hidden process that outlives this one.

    Asks to leave any job object too: some launchers put their children in a
    job that is killed when the parent exits, which would take the installer
    down with the app it is waiting for. Not every job allows that, so it
    falls back to a plain hidden start.
    """
    kw = no_window_kwargs()
    if os.name == "nt":
        try:
            return subprocess.Popen(cmd, **dict(
                kw, creationflags=kw["creationflags"] | _CREATE_BREAKAWAY_FROM_JOB),
                **kwargs)
        except OSError:
            pass
    return subprocess.Popen(cmd, **kw, **kwargs)


def _k32():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    return ctypes, wintypes, k32


def pid_alive(pid: int) -> bool:
    """Never signals the process (see module docstring). Unknown -> alive."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name != "nt":
        # The app ships for Windows; this only keeps the module importable
        # elsewhere. No signal of any kind (tests/test_fix5_brokers.py).
        return Path(f"/proc/{pid}").exists()
    ctypes, wintypes, k32 = _k32()
    h = k32.OpenProcess(0x1000, False, pid)     # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ctypes.get_last_error() == 5     # access denied: exists
    try:
        code = wintypes.DWORD()
        if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
            return True
        return code.value == 259                # STILL_ACTIVE
    finally:
        k32.CloseHandle(h)


def process_created(pid: int) -> Optional[int]:
    """The process's creation time (FILETIME ticks), or None when unreadable.
    Together with the pid it names one process, not whoever got the pid next."""
    if os.name != "nt":
        return None
    try:
        ctypes, wintypes, k32 = _k32()
        h = k32.OpenProcess(0x1000, False, int(pid))
        if not h:
            return None
        try:
            t = [wintypes.FILETIME() for _ in range(4)]
            if not k32.GetProcessTimes(h, *(ctypes.byref(x) for x in t)):
                return None
            return (t[0].dwHighDateTime << 32) | t[0].dwLowDateTime
        finally:
            k32.CloseHandle(h)
    except Exception:                           # noqa: BLE001
        return None


def same_process_alive(pid: int, created: Optional[int]) -> bool:
    if not pid_alive(pid):
        return False
    if created is None:
        return True
    now_created = process_created(pid)
    return now_created is None or now_created == created


def wait_pid_exit(pid: int, timeout_s: float, poll_s: float = 0.5) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if not pid_alive(pid):
            return True
        time.sleep(poll_s)
    return not pid_alive(pid)


# =============================================================================
# Logging
# =============================================================================

class Log:
    def __init__(self, app_dir: Path):
        self.path = Path(app_dir) / "logs" / "update.log"

    def __call__(self, msg: str) -> None:
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S}  {msg}\n"
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass


# =============================================================================
# The journal: what an install is doing, for whoever looks next
# =============================================================================

def journal_path(app_dir: Path) -> Path:
    return updates_dir(app_dir) / JOURNAL_NAME


def new_journal(app_dir: Path, staged_dir: Path, payload: Dict[str, Any],
                helper_pid: int, helper_created: Optional[int]) -> Dict[str, Any]:
    old_v = payload.get("from_version") or "?"
    return {
        "phase": "waiting", "helper_pid": helper_pid,
        "helper_created": helper_created,
        "mode": payload.get("mode", "zip"),
        "from_version": old_v, "to_version": payload.get("version"),
        "staged": str(staged_dir),
        "backup": str(updates_dir(app_dir) / "backup" / old_v),
        "started": datetime.now().isoformat(timespec="seconds"),
    }


def helper_running(journal: Dict[str, Any]) -> bool:
    """The process named in the journal is alive AND is still the helper
    (same creation time), AND the journal is not impossibly old."""
    try:
        started = datetime.fromisoformat(journal.get("started") or "")
        if (datetime.now() - started).total_seconds() > JOURNAL_STALE_S:
            return False
    except ValueError:
        return False
    return same_process_alive(journal.get("helper_pid") or 0,
                              journal.get("helper_created"))


# =============================================================================
# Swapping files (ZIP installs)
# =============================================================================

def apply_zip(app_dir: Path, staged_files: Path, payload: Dict[str, Any],
              journal: Dict[str, Any], jpath: Path) -> None:
    """Copy the staged release over the install, backing up what it replaces.

    The journal is written BEFORE each change, so recover() can always undo
    whatever had happened when the process stopped.
    """
    app_dir = Path(app_dir)
    files: Dict[str, str] = payload["files"]
    backup = Path(journal["backup"])
    backup.mkdir(parents=True, exist_ok=True)

    # Every staged file must still match the signed hash before anything moves.
    for rel, digest in files.items():
        check_rel_path(rel)
        src = staged_files / rel
        if not src.is_file() or sha256_file(src) != digest:
            raise RuntimeError(f"staged file does not match the release: {rel}")

    old = read_json(updates_dir(app_dir) / MANIFEST_NAME, {}) or {}
    old_files = set((old.get("files") or {}) if isinstance(old, dict) else ())
    to_delete = sorted(p for p in old_files - set(files)
                       if not is_protected(p) and (app_dir / p).is_file())

    journal.setdefault("replaced", [])
    journal.setdefault("created", [])
    journal.setdefault("deleted", [])

    for rel in sorted(files):
        dest = app_dir / rel
        if dest.is_file():
            if sha256_file(dest) == files[rel]:
                continue                            # already this version
            bk = backup / rel
            bk.parent.mkdir(parents=True, exist_ok=True)
            retry_io(lambda: shutil.copy2(dest, bk))
            journal["replaced"].append(rel)
        else:
            journal["created"].append(rel)
        write_json(jpath, journal)
        copy_into_place(staged_files / rel, dest)

    for rel in to_delete:
        dest = app_dir / rel
        bk = backup / rel
        bk.parent.mkdir(parents=True, exist_ok=True)
        retry_io(lambda: shutil.copy2(dest, bk))
        journal["deleted"].append(rel)
        write_json(jpath, journal)
        remove_file(dest)


def rollback_zip(app_dir: Path, journal: Dict[str, Any], log: Log) -> List[str]:
    """Put every touched file back. Carries on past a file it cannot restore
    and returns those, so one locked file never strands the rest."""
    app_dir = Path(app_dir)
    backup = Path(journal["backup"])
    failed: List[str] = []
    for rel in journal.get("replaced", []) + journal.get("deleted", []):
        bk = backup / rel
        if not bk.is_file():
            log(f"rollback: backup missing for {rel}")
            failed.append(rel)
            continue
        try:
            copy_into_place(bk, app_dir / rel)
        except OSError as exc:
            log(f"rollback: could not restore {rel}: {exc}")
            failed.append(rel)
    for rel in journal.get("created", []):
        try:
            remove_file(app_dir / rel)
        except OSError as exc:
            log(f"rollback: could not remove {rel}: {exc}")
            failed.append(rel)
    return failed


# =============================================================================
# Git installs
# =============================================================================

def git(app_dir: Path, *args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    exe = shutil.which("git") or "git"
    return run_hidden([exe, "-C", str(app_dir), *args], timeout=timeout)


def git_out(app_dir: Path, *args: str, timeout: float = 120) -> Optional[str]:
    try:
        r = git(app_dir, *args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def git_unfit_reason(app_dir: Path) -> Optional[str]:
    """Why this git checkout must not be updated automatically, or None.

    Only a clean checkout of main qualifies. Anything else is someone working
    in the folder (the operator's own repo is one), and moving files under
    them would destroy work.
    """
    if not shutil.which("git"):
        return "git is not installed"
    branch = git_out(app_dir, "rev-parse", "--abbrev-ref", "HEAD")
    if branch is None:
        return "not a readable git checkout"
    if branch != "main":
        return f"checked out on {branch!r}, not main"
    dirty = git_out(app_dir, "status", "--porcelain", "--untracked-files=no")
    if dirty is None:
        return "git status failed"
    if dirty:
        return "has local changes to the app's files"
    return None


def git_prepare(app_dir: Path, payload: Dict[str, Any], *, fetch: bool = True) -> None:
    """Make sure the signed tag is here, is the signed tree, is a fast-forward
    from HEAD, and touches no customer file. Raises RuntimeError otherwise.

    Run while staging (the app is up, the network is likely fine) and again
    by the installer, which only fetches if the tag is somehow missing.
    """
    tag = payload["tag"]
    if git_out(app_dir, "rev-parse", f"{tag}^{{tree}}") != payload["git_tree"]:
        if not fetch:
            raise RuntimeError(f"tag {tag} is not here")
        r = git(app_dir, "fetch", "--no-tags", "origin",
                f"+refs/tags/{tag}:refs/tags/{tag}", timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"git fetch failed: {r.stderr.strip()[:300]}")
        if git_out(app_dir, "rev-parse", f"{tag}^{{tree}}") != payload["git_tree"]:
            raise RuntimeError(f"tag {tag} does not match the signed release")
    if git(app_dir, "merge-base", "--is-ancestor", "HEAD", tag).returncode != 0:
        raise RuntimeError(f"{tag} is not ahead of this checkout")
    changed = git_out(app_dir, "diff", "--name-only", "HEAD", tag) or ""
    for rel in changed.splitlines():
        if rel and is_protected(rel):
            raise RuntimeError(f"{tag} would overwrite a customer file: {rel}")


def apply_git(app_dir: Path, payload: Dict[str, Any], journal: Dict[str, Any],
              jpath: Path) -> None:
    reason = git_unfit_reason(app_dir)
    if reason:
        raise RuntimeError(f"git checkout {reason}")
    git_prepare(app_dir, payload)
    head = git_out(app_dir, "rev-parse", "HEAD")
    if not head:
        raise RuntimeError("cannot read HEAD")
    journal["old_head"] = head
    write_json(jpath, journal)
    r = git(app_dir, "merge", "--ff-only", payload["tag"], timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"git merge failed: {r.stderr.strip()[:300]}")


def rollback_git(app_dir: Path, journal: Dict[str, Any], log: Log) -> List[str]:
    head = journal.get("old_head")
    if not head:
        return []
    r = git(app_dir, "reset", "--hard", head)
    if r.returncode != 0:
        log(f"rollback: git reset failed: {r.stderr.strip()[:300]}")
        return ["<git reset>"]
    return []


# =============================================================================
# The whole install
# =============================================================================

def python_console_exe(pythonw: str) -> str:
    """python.exe next to pythonw.exe: pip must not run under pythonw (no
    stdout to report errors on), and must run under the SAME install."""
    p = Path(pythonw)
    if p.name.lower() == "pythonw.exe":
        cand = p.with_name("python.exe")
        if cand.exists():
            return str(cand)
    return str(p)


def run_pip(app_dir: Path, pythonw: str, log: Log) -> bool:
    exe = python_console_exe(pythonw)
    log(f"installing requirements with {exe}")
    try:
        r = run_hidden([exe, "-m", "pip", "install", "-r",
                        str(Path(app_dir) / "requirements.txt"),
                        "--disable-pip-version-check"],
                       cwd=str(app_dir), timeout=PIP_TIMEOUT_S)
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"pip did not run: {exc}")
        return False
    if r.returncode != 0:
        log("pip failed:\n" + (r.stdout or "")[-2000:] + (r.stderr or "")[-2000:])
        return False
    return True


def run_playwright_install(pythonw: str, log: Log) -> None:
    """INSTALL.bat step 4. A new playwright needs its own browser build, and
    without it Schwab cannot start -- which the health check would not see."""
    exe = python_console_exe(pythonw)
    try:
        r = run_hidden([exe, "-m", "playwright", "install", "firefox"],
                       timeout=PIP_TIMEOUT_S)
        if r.returncode != 0:
            log("playwright install firefox failed: " + (r.stderr or "")[-500:])
    except (OSError, subprocess.SubprocessError) as exc:
        log(f"playwright install did not run: {exc}")


def sync_dependencies(app_dir: Path, pythonw: str, log: Log, *,
                      old_req: Optional[str], old_playwright: Optional[str]) -> bool:
    """Bring the libraries in line with requirements.txt as it is NOW, if it
    differs from `old_req`. Used forwards (after the swap) and backwards
    (after a rollback, so the old code never runs on the new pins)."""
    if requirements_sha(app_dir) == old_req:
        return True
    ok = run_pip(app_dir, pythonw, log)
    if ok and pinned(app_dir, "playwright") != old_playwright:
        run_playwright_install(pythonw, log)
    return ok


def launch_app(app_dir: Path, pythonw: str, expect_version: Optional[str],
               extra_env: Optional[Dict[str, str]] = None) -> subprocess.Popen:
    env = dict(os.environ)
    env.pop("RSA_UPDATE_EXPECT", None)
    if expect_version:
        env["RSA_UPDATE_EXPECT"] = expect_version
    env.update(extra_env or {})
    cmd = [pythonw, str(Path(app_dir) / "app.py")]
    return popen_detached(cmd, cwd=str(app_dir), env=env, close_fds=True)


def wait_healthy(app_dir: Path, proc: subprocess.Popen, version: str,
                 timeout_s: float, poll_s: float = 1.0) -> bool:
    """True once the new copy writes healthy.json for `version`; False when it
    crashes first. Still running at the deadline without a marker counts as
    healthy: a slow PC is not a broken release, and rolling back under a live
    app would swap files beneath it. Exiting because another copy is already
    running is not a crash either."""
    marker = updates_dir(app_dir) / HEALTHY_NAME
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        data = read_json(marker, {}) or {}
        if data.get("version") == version:
            return True
        code = proc.poll()
        if code is not None:
            # One last look: it may have written the marker then quit normally.
            data = read_json(marker, {}) or {}
            return data.get("version") == version or code == EXIT_ALREADY_RUNNING
        time.sleep(poll_s)
    return proc.poll() is None


def rollback(app_dir: Path, journal: Dict[str, Any], log: Log) -> List[str]:
    if journal.get("mode") == "git":
        return rollback_git(app_dir, journal, log)
    return rollback_zip(app_dir, journal, log)


def _count_try(app_dir: Path, version: str, why: str) -> None:
    st = load_state(app_dir)
    tries = dict(st.get("tries") or {})
    tries[version] = int(tries.get(version, 0)) + 1
    st["tries"] = tries
    save_state(app_dir, st)
    if tries[version] >= 3:
        mark_bad(app_dir, version, f"install failed 3 times: {why}", permanent=False)
        st = load_state(app_dir)
        (st.get("tries") or {}).pop(version, None)
        save_state(app_dir, st)


def install(app_dir: Path, staged_dir: Path, old_pid: int, pythonw: str,
            log: Optional[Log] = None, *, relaunch: bool = True,
            health_timeout_s: float = HEALTH_TIMEOUT_S) -> str:
    """Run one update end to end. Returns 'installed', 'rolled-back',
    'aborted' or 'app-still-running'. Every result except the last starts
    the app again (when `relaunch`)."""
    app_dir = Path(app_dir)
    log = log or Log(app_dir)
    jpath = journal_path(app_dir)

    def _relaunch_old() -> None:
        if relaunch:
            launch_app(app_dir, pythonw, None)

    payload = read_json(Path(staged_dir) / "payload.json")
    if not isinstance(payload, dict) or not payload.get("version"):
        log(f"no payload in {staged_dir}; nothing to do")
        jpath.unlink(missing_ok=True)
        if old_pid:
            wait_pid_exit(old_pid, OLD_EXIT_TIMEOUT_S)
        _relaunch_old()
        return "aborted"
    new_v, old_v = payload["version"], payload.get("from_version") or "?"
    journal = new_journal(app_dir, staged_dir, payload, os.getpid(),
                          process_created(os.getpid()))
    write_json(jpath, journal)
    log(f"update {old_v} -> {new_v} ({journal['mode']}): waiting for pid {old_pid} to exit")

    if old_pid and not wait_pid_exit(old_pid, OLD_EXIT_TIMEOUT_S):
        log("the app did not exit; leaving everything as it is")
        jpath.unlink(missing_ok=True)
        return "app-still-running"

    # Stale marker from an earlier update must not vouch for this one.
    (updates_dir(app_dir) / HEALTHY_NAME).unlink(missing_ok=True)
    journal["phase"] = "swapping"
    old_req, old_pw = requirements_sha(app_dir), pinned(app_dir, "playwright")
    journal["old_requirements"], journal["old_playwright"] = old_req, old_pw
    write_json(jpath, journal)

    # What pip was last asked to install: the old pins until the swap is done.
    installed = {"req": old_req, "playwright": old_pw}

    def _undo() -> None:
        failed = rollback(app_dir, journal, log)
        if failed:
            # Leave the journal: the next start's recover() tries again.
            log(f"rollback left {len(failed)} file(s) for the next start: {failed[:5]}")
        # Put the old pins back too, so the old code never runs on new ones.
        sync_dependencies(app_dir, pythonw, log, old_req=installed["req"],
                          old_playwright=installed["playwright"])
        if not failed:
            jpath.unlink(missing_ok=True)

    try:
        if journal["mode"] == "git":
            apply_git(app_dir, payload, journal, jpath)
        else:
            apply_zip(app_dir, Path(staged_dir) / "files", payload, journal, jpath)
        installed = {"req": requirements_sha(app_dir),
                     "playwright": pinned(app_dir, "playwright")}
        if not sync_dependencies(app_dir, pythonw, log, old_req=old_req,
                                 old_playwright=old_pw):
            raise RuntimeError("pip could not install the new requirements")
    except Exception as exc:                    # noqa: BLE001 — undo, then report
        log(f"install failed, rolling back: {exc}")
        _undo()
        _count_try(app_dir, new_v, str(exc))
        _relaunch_old()
        return "aborted"

    journal["phase"] = "launched"
    write_json(jpath, journal)
    if not relaunch:
        finish(app_dir, staged_dir, payload, log)
        return "installed"

    log(f"files in place; starting {new_v}")
    proc = launch_app(app_dir, pythonw, new_v)
    if wait_healthy(app_dir, proc, new_v, health_timeout_s):
        finish(app_dir, staged_dir, payload, log)
        return "installed"

    log(f"{new_v} exited before it reported healthy; restoring {old_v}")
    _undo()
    mark_bad(app_dir, new_v, "exited on first start", permanent=True)
    _relaunch_old()
    return "rolled-back"


def finish(app_dir: Path, staged_dir: Path, payload: Dict[str, Any], log: Log) -> None:
    upd = updates_dir(app_dir)
    if payload.get("mode", "zip") == "zip":
        write_json(upd / MANIFEST_NAME, {"version": payload["version"],
                                         "files": payload["files"]})
    st = load_state(app_dir)
    st["installed"] = {"version": payload["version"],
                       "at": datetime.now().isoformat(timespec="seconds")}
    (st.get("tries") or {}).pop(payload["version"], None)
    save_state(app_dir, st)
    journal_path(app_dir).unlink(missing_ok=True)
    shutil.rmtree(staged_dir, ignore_errors=True)
    # Keep only the newest backup: one step back is the useful one.
    keep = payload.get("from_version")
    bdir = upd / "backup"
    for d in bdir.glob("*") if bdir.is_dir() else ():
        if d.name != keep:
            shutil.rmtree(d, ignore_errors=True)
    log(f"update to {payload['version']} installed")


def recover(app_dir: Path, log: Optional[Log] = None) -> Optional[str]:
    """Run at app start, BEFORE the single-instance lock. Returns:

    'busy'         an install is under way (or watching the new version come
                   up); this copy must not start. The copy the installer
                   itself launched is recognised by RSA_UPDATE_EXPECT.
    'rolled-back'  an interrupted swap was undone; start a clean process.
    'cleared' / None  nothing for the caller to do.
    """
    app_dir = Path(app_dir)
    log = log or Log(app_dir)
    jp = journal_path(app_dir)
    journal = read_json(jp)
    if not isinstance(journal, dict):
        return None
    if helper_running(journal):
        if journal.get("phase") in BUSY_PHASES and \
                os.environ.get("RSA_UPDATE_EXPECT") != journal.get("to_version"):
            return "busy"
        return None
    phase = journal.get("phase")
    if phase == "swapping":
        attempts = int(journal.get("recover_attempts") or 0) + 1
        log(f"found an interrupted update; restoring the previous version "
            f"(attempt {attempts})")
        failed = rollback(app_dir, journal, log)
        if failed and attempts < RECOVER_ATTEMPTS:
            journal["recover_attempts"] = attempts
            write_json(jp, journal)
            return "cleared"            # start anyway; try the rest next time
        mark_bad(app_dir, journal.get("to_version") or "?", "install interrupted",
                 permanent=False)
        jp.unlink(missing_ok=True)
        return "rolled-back"
    if phase == "launched":
        # The installer died while the new version was coming up. If that
        # version did report healthy, finish the bookkeeping it skipped.
        marker = read_json(updates_dir(app_dir) / HEALTHY_NAME, {}) or {}
        staged = Path(journal.get("staged") or "")
        payload = read_json(staged / "payload.json") if journal.get("staged") else None
        if marker.get("version") == journal.get("to_version") and isinstance(payload, dict):
            finish(app_dir, staged, payload, log)
            return "cleared"
    jp.unlink(missing_ok=True)
    return "cleared"


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--app-dir", required=True)
    ap.add_argument("--staged", required=True)
    ap.add_argument("--pid", type=int, default=0)
    ap.add_argument("--pythonw", required=True)
    a = ap.parse_args(list(argv) if argv is not None else None)
    app_dir = Path(a.app_dir)
    log = Log(app_dir)
    try:
        result = install(app_dir, Path(a.staged), a.pid, a.pythonw, log)
    except Exception:                           # noqa: BLE001 — last resort
        import traceback
        log("updater crashed:\n" + traceback.format_exc())
        # Undo whatever was half done, then make sure the app comes back.
        try:
            journal = read_json(journal_path(app_dir))
            if isinstance(journal, dict) and journal.get("phase") == "swapping":
                if not rollback(app_dir, journal, log):
                    journal_path(app_dir).unlink(missing_ok=True)
        except Exception:                       # noqa: BLE001
            log("rollback after crash failed:\n" + traceback.format_exc())
        try:
            if not (a.pid and pid_alive(a.pid)):
                launch_app(app_dir, a.pythonw, None)
        except Exception:                       # noqa: BLE001
            log("could not restart the app:\n" + traceback.format_exc())
        return 1
    log(f"result: {result}")
    return 0 if result in ("installed", "app-still-running") else 1


if __name__ == "__main__":
    sys.exit(main())
