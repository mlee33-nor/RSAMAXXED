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

    # 2. The feed needs no .env, no password and no key (README section 5).
    #    A .env is only loaded so a deployment-specific setting the app would
    #    honour (a custom server URL, an old plays key) is honoured here too.
    env_file = HERE / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
        except ImportError:
            print(f"{BAD} python-dotenv is not installed for THIS interpreter.")
            print("       Run:  py -3.13 -m pip install -r requirements.txt")
            print("       (a bare 'pip' installs into the wrong Python)")
            return 1
        load_dotenv(env_file, interpolate=False)
        print(f"{OK} .env loaded")
    else:
        print(f"{INFO} No .env yet. The feed does not need one; your broker")
        print("       logins will (copy .env.example to .env when you add them).")

    # 3. Ask the server, through the app's own client.
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
          f"{'yes' if client.device_token else 'no (the public feed, which is normal)'}")

    try:
        picks = client.fetch_picks()
    except Exception as exc:                       # noqa: BLE001
        print(f"{BAD} The server refused: {exc}")
        print()
        print("       Check this PC can reach rsamaxxed.com in a browser. If")
        print("       .env sets RSAMAXXED_CLOUD_URL, make sure it is correct.")
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
