"""Put an RSAMAXXED shortcut, with the app's icon, on the user's Desktop.

    py -3.13 make_shortcut.py

Safe to run any number of times: it rewrites the same RSAMAXXED.lnk, so it
also repairs a shortcut left pointing at an old copy of the folder.

The shortcut launches RSAMAXXED.bat (which pins Python 3.13 and preflights the
dependencies) in a minimized window, so the only thing the user sees is the
app itself. The Desktop path comes from the shell rather than %USERPROFILE%,
because OneDrive and folder redirection routinely move it.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from modules import quiet  # noqa: E402  -- never a flashing console window

import logo  # noqa: E402

SHORTCUT_NAME = "RSAMAXXED.lnk"

# Paths travel as environment variables, not spliced into the script, so a
# folder name with quotes or spaces can't break (or inject into) the command.
_PS = r"""
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject WScript.Shell
$desktop = $shell.SpecialFolders('Desktop')
$lnk = Join-Path $desktop $env:RSA_LNK_NAME
$s = $shell.CreateShortcut($lnk)
$s.TargetPath = $env:RSA_LNK_TARGET
$s.WorkingDirectory = $env:RSA_LNK_DIR
$s.IconLocation = "$($env:RSA_LNK_ICON),0"
$s.WindowStyle = 7
$s.Description = 'RSAMAXXED - multi-broker reverse-split automation'
$s.Save()
Write-Output $lnk
"""


def make_shortcut() -> Path:
    if sys.platform != "win32":
        raise SystemExit("Desktop shortcuts are only made on Windows.")

    target = ROOT / "RSAMAXXED.bat"
    if not target.exists():
        raise SystemExit(f"Launcher not found: {target}")
    ico = logo.ico_path()  # generates assets/rsamaxxed.ico if it is missing
    if not ico:
        raise SystemExit("Could not find or build assets/rsamaxxed.ico")

    env = dict(os.environ,
               RSA_LNK_NAME=SHORTCUT_NAME,
               RSA_LNK_TARGET=str(target),
               RSA_LNK_DIR=str(ROOT),
               RSA_LNK_ICON=str(Path(ico).resolve()))
    res = quiet.run(["powershell", "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-Command", _PS],
                    env=env, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise SystemExit("Could not create the shortcut:\n"
                         + (res.stderr or res.stdout or "").strip())
    return Path(res.stdout.strip().splitlines()[-1])


if __name__ == "__main__":
    print(f"Shortcut ready: {make_shortcut()}")
