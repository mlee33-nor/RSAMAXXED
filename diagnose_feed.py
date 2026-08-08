#!/usr/bin/env python3
"""Why is my pick feed empty?  Run from the RSAMAXXED folder:

    py -3.13 diagnose_feed.py

Prints one line per check and, at the end, the single thing to fix.
Reads only; publishes nothing and changes no file.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OK, BAD, INFO = "[ OK ]", "[FAIL]", "[ .. ]"


def main() -> int:
    print("RSAMAXXED feed diagnostic\n" + "=" * 46)

    # 1. Are we in the right folder?
    if not (HERE / "cloud_sync.py").exists():
        print(f"{BAD} cloud_sync.py not found next to this script.")
        print("       Put this file in the RSAMAXXED folder and re-run.")
        return 1
    print(f"{OK} Found the app folder: {HERE}")

    # 2. Does a .env exist at all?  A fresh clone ships .env.example only.
    env_file = HERE / ".env"
    if not env_file.exists():
        print(f"{BAD} There is no .env file.")
        print("       You have .env.example, which is the template, not the")
        print("       real thing. Copy it:   copy .env.example .env")
        print("       then put your plays password in it (see step 4 below).")
        return 1
    print(f"{OK} .env exists")

    # 3. Load it the same way the app does.
    try:
        from dotenv import load_dotenv
    except ImportError:
        print(f"{BAD} python-dotenv is not installed for THIS interpreter.")
        print("       Run:  py -3.13 -m pip install -r requirements.txt")
        print("       (a bare 'pip' installs into the wrong Python)")
        return 1
    load_dotenv(env_file)

    # 4. Is the key present?
    key = (os.environ.get("RSAMAXXED_PLAYS_KEY") or "").strip()
    if not key:
        print(f"{BAD} RSAMAXXED_PLAYS_KEY is not set in .env.")
        print("       THIS IS ALMOST ALWAYS THE PROBLEM. Open .env, find the")
        print("       line 'RSAMAXXED_PLAYS_KEY=' and put the password you")
        print("       were given after the '='. No quotes, no spaces:")
        print()
        print("           RSAMAXXED_PLAYS_KEY=yourpasswordhere")
        print()
        print("       Make sure the line does NOT start with a '#'.")
        return 1
    print(f"{OK} RSAMAXXED_PLAYS_KEY is set ({len(key)} chars, "
          f"starts '{key[:2]}...')")

    if key != key.strip() or " " in key:
        print(f"{INFO} Note: the key contains a space. That is usually a "
              f"copy/paste slip.")

    # 5. Ask the server, through the app's own client.
    sys.path.insert(0, str(HERE))
    try:
        import cloud_sync
    except Exception as exc:                       # noqa: BLE001
        print(f"{BAD} Could not import cloud_sync: {exc}")
        print("       Run:  py -3.13 -m pip install -r requirements.txt")
        return 1

    client = cloud_sync.CloudSync()
    print(f"{INFO} Server: {client.base_url if hasattr(client, 'base_url') else cloud_sync.DEFAULT_BASE_URL}")
    print(f"{INFO} Paired to an account: "
          f"{'yes' if client.device_token else 'no (using the password, which is normal)'}")

    try:
        picks = client.fetch_picks()
    except Exception as exc:                       # noqa: BLE001
        print(f"{BAD} The server refused: {exc}")
        print()
        print("       If it mentions the board password, the key in .env is")
        print("       wrong or expired. Check it opens rsamaxxed.com/plays in")
        print("       a browser -- same password, same spelling.")
        return 1

    print(f"{OK} Server answered. Open picks right now: {len(picks)}")
    for p in picks:
        print(f"        - {p.get('symbol')}  ({p.get('note')}, "
              f"alerted {p.get('date')})")

    if not picks:
        print()
        print(f"{INFO} The connection works and the feed is genuinely empty of")
        print("       OPEN picks at this moment. That is not a bug -- plays")
        print("       close when their buy window passes. The next alert will")
        print("       appear on its own.")
    else:
        print()
        print(f"{OK} Everything is working. If the Watchlist still looks empty")
        print("       in the app, close it fully and relaunch RSAMAXXED.bat --")
        print("       the feed is fetched on launch, then hourly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
