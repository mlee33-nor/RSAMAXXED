#!/usr/bin/env python3
"""Publish the desktop app's picks to the live web feed, once.

The desktop app writes the current RSA picks to `picks.json` at the repo root on
its daily Discord pull. Railway only deploys the `web/` directory, so it can't
see that file — this script copies it into `web/picks.json` (which IS in the
deploy) and pushes, so Railway redeploys and the free Plays page re-seeds from
the fresh picks.

Run it right after the daily pull — by hand, from a scheduled task, or from the
desktop app's daily-check. It is a no-op when nothing changed, so running it more
often than needed is harmless.

    python publish_picks.py

Exit codes: 0 = pushed (or nothing to push), 1 = a git step failed.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "picks.json"
DST = ROOT / "web" / "picks.json"


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          capture_output=True, text=True)


def main() -> int:
    if not SRC.exists():
        print(f"no picks to publish: {SRC} does not exist")
        return 0

    # Validate before publishing — never push a picks.json that won't parse.
    try:
        picks = json.loads(SRC.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"refusing to publish: {SRC} is not valid JSON ({e})")
        return 1
    if not isinstance(picks, list):
        print("refusing to publish: picks.json is not a JSON list")
        return 1

    new = SRC.read_text(encoding="utf-8")
    if DST.exists() and DST.read_text(encoding="utf-8") == new:
        print(f"web/picks.json already current ({len(picks)} picks) — nothing to publish")
        return 0

    DST.write_text(new, encoding="utf-8")
    print(f"updated web/picks.json ({len(picks)} picks)")

    add = _git("add", "web/picks.json")
    if add.returncode != 0:
        print("git add failed:\n" + add.stderr)
        return 1

    # Only commit if the add actually staged a change.
    staged = _git("diff", "--cached", "--quiet", "web/picks.json")
    if staged.returncode == 0:
        print("no staged change after add — nothing to commit")
        return 0

    commit = _git("commit", "-m", f"picks: refresh feed ({len(picks)} alerts)")
    if commit.returncode != 0:
        print("git commit failed:\n" + commit.stderr)
        return 1

    push = _git("push", "origin", "HEAD")
    if push.returncode != 0:
        print("git push failed:\n" + push.stderr)
        return 1

    print("published — Railway will redeploy with the fresh feed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
