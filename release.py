#!/usr/bin/env python3
"""Publish a release every customer's app installs on its own.

    py -3.13 release.py 1.1.4                 tag, sign, push, publish on GitHub
    py -3.13 release.py 1.1.4 --notes n.md    the same, with release notes from a file
    py -3.13 release.py 1.1.4 --dry-run       build + sign into dist/ only; no tag, no push
    py -3.13 release.py --init-key            one time: make the signing key

Before running it: set APP_VERSION in app.py to the new version, commit, and
have a clean working tree on main. This script refuses anything else, because
what it tags is exactly what every customer gets.

THE SIGNING KEY
---------------
Customers' apps (modules/updater.py) install only releases signed with the
private key this script reads from %USERPROFILE%\\.rsamaxxed\\release_signing_key.pem
(or RSA_RELEASE_KEY). It must never be committed, emailed or synced anywhere
public. Back it up somewhere private: without it no customer can be updated
automatically again, and every one of them would need a manual reinstall of
a build carrying a new public key.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from modules import quiet                      # noqa: E402
from modules import update_apply as ua         # noqa: E402

APP_ID = "RSAMAXXED"
DEFAULT_KEY = Path.home() / ".rsamaxxed" / "release_signing_key.pem"


def key_path() -> Path:
    return Path(os.environ.get("RSA_RELEASE_KEY") or DEFAULT_KEY)


def die(msg: str) -> None:
    print(f"\n  STOPPED: {msg}\n")
    sys.exit(1)


def run(*cmd: str, check: bool = True) -> str:
    r = quiet.run(list(cmd), cwd=str(HERE), capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"{' '.join(cmd)} failed:\n{(r.stderr or r.stdout).strip()}")
    return (r.stdout or "").strip()


# --------------------------------------------------------------------- keys

def init_key() -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    path = key_path()
    if path.exists():
        die(f"{path} already exists. Replacing it would strand every customer "
            f"on their current version; delete it by hand only if you mean that.")
    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    print(f"Private key written to {path}\nBACK IT UP somewhere private.\n")
    print("Public key (goes in modules/updater.py PUBLIC_KEY_B64):")
    print(public_b64(key))


def load_key():
    from cryptography.hazmat.primitives import serialization
    path = key_path()
    if not path.exists():
        die(f"no signing key at {path}. Run: py -3.13 release.py --init-key")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def public_b64(key) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


# ------------------------------------------------------------------ release

def app_version() -> str:
    m = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', (HERE / "app.py").read_text(
        encoding="utf-8"), re.M)
    return m.group(1) if m else ""


def preflight(version: str, dry_run: bool) -> None:
    if not ua.parse_version(version):
        die(f"{version!r} is not a version like 1.1.4")
    if app_version() != version:
        die(f'app.py says APP_VERSION = "{app_version()}". Set it to "{version}" '
            f"and commit first, so the app knows which version it is.")
    from modules import updater
    if public_b64(load_key()) != updater.PUBLIC_KEY_B64:
        die("your signing key does not match PUBLIC_KEY_B64 in modules/updater.py; "
            "customers would refuse this release")
    if dry_run:
        return
    if run("git", "rev-parse", "--abbrev-ref", "HEAD") != "main":
        die("not on main")
    if run("git", "status", "--porcelain", "--untracked-files=no"):
        die("uncommitted changes. Commit or stash them; a release is exactly "
            "what is committed")
    if not shutil.which("gh"):
        die("the GitHub CLI (gh) is not installed: https://cli.github.com")
    # What customers on a git checkout fast-forward to must sit on top of
    # what they have: after a history rewrite their update would fail.
    run("git", "fetch", "origin", "main")
    if quiet.run(["git", "merge-base", "--is-ancestor", "origin/main", "HEAD"],
                 cwd=str(HERE)).returncode != 0:
        die("HEAD is not built on origin/main (history rewritten?). Customers "
            "on a git install could not fast-forward to it")
    tag = f"v{version}"
    if run("git", "tag", "--list", tag):
        # A run that tagged, then failed to push or publish, may be resumed.
        if run("git", "rev-parse", f"{tag}^{{commit}}") != run("git", "rev-parse", "HEAD"):
            die(f"tag {tag} exists and is not this commit")
        if quiet.run(["gh", "release", "view", tag], cwd=str(HERE),
                     capture_output=True).returncode == 0:
            die(f"{tag} is already published")
        print(f"Resuming: {tag} is tagged here but not published yet.")
    latest = quiet.run(["gh", "release", "view", "--json", "tagName", "-q", ".tagName"],
                       cwd=str(HERE), capture_output=True, text=True)
    latest_tag = (latest.stdout or "").strip() if latest.returncode == 0 else ""
    if latest_tag and not ua.is_newer(version, latest_tag):
        die(f"{tag} is not newer than the latest published release {latest_tag}; "
            f"customers only ever move forward")


def build(version: str, ref: str, out_dir: Path) -> tuple[Path, Path]:
    tag = f"v{version}"
    out_dir.mkdir(exist_ok=True)
    zip_path = out_dir / f"{APP_ID}-{tag}.zip"
    run("git", "archive", "--format=zip", "-o", str(zip_path), ref)
    zip_bytes = zip_path.read_bytes()
    files = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                ua.check_rel_path(info.filename)
            except ValueError as exc:
                die(f"the release would ship {info.filename}: {exc}")
            files[info.filename] = ua.sha256_bytes(zf.read(info))
    req = None
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        if "requirements.txt" in zf.namelist():
            req = ua.text_sha256(zf.read("requirements.txt"))
    payload = {
        "app": APP_ID, "version": version, "tag": tag,
        "zip_name": zip_path.name, "zip_sha256": ua.sha256_bytes(zip_bytes),
        "git_tree": run("git", "rev-parse", f"{ref}^{{tree}}"),
        "requirements_sha256": req, "files": files,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = load_key()
    doc = {"payload": base64.b64encode(raw).decode("ascii"),
           "signature": base64.b64encode(key.sign(raw)).decode("ascii")}
    sig_path = out_dir / f"{APP_ID}-{tag}.update.json"
    sig_path.write_text(json.dumps(doc), encoding="utf-8")

    # Check it the way a customer's app will, with the key the app ships.
    from modules import updater
    updater.verify_payload(doc)
    print(f"Built and signed {zip_path.name} ({len(files)} files, "
          f"{len(zip_bytes) // 1024} KB)")
    return zip_path, sig_path


def main() -> None:
    ap = argparse.ArgumentParser(description="Publish a signed RSAMAXXED release.")
    ap.add_argument("version", nargs="?")
    ap.add_argument("--notes", help="release notes file (markdown)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--init-key", action="store_true")
    a = ap.parse_args()
    if a.init_key:
        init_key()
        return
    if not a.version:
        ap.error("give the version, e.g. 1.1.4")
    version = a.version.lstrip("vV")
    preflight(version, a.dry_run)
    out = HERE / "dist"
    if a.dry_run:
        build(version, "HEAD", out)
        print("Dry run: nothing tagged, pushed or published.")
        return

    tag = f"v{version}"
    if not run("git", "tag", "--list", tag):
        run("git", "tag", "-a", tag, "-m", tag)
    zip_path, sig_path = build(version, tag, out)
    run("git", "push", "origin", "main")
    run("git", "push", "origin", tag)
    notes = ["--notes-file", a.notes] if a.notes else ["--generate-notes"]
    run("gh", "release", "create", tag, str(zip_path), str(sig_path),
        "--title", tag, *notes)
    print(f"\nPublished {tag}. Customers' apps pick it up within a few hours and "
          f"install it at their next start or overnight.")


if __name__ == "__main__":
    main()
