@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title RSAMAXXED Setup

rem One-time setup for RSAMAXXED. Safe to run again at any time -- after an
rem update, or to repair an install. It never touches your .env, trades.json
rem or anything else you have saved.
rem
rem Set RSA_PYTHON to a python.exe path to force a specific interpreter.

rem Double-clicking INSTALL.bat inside the zip (without extracting it) makes
rem Windows copy just this one file to a temp folder and run it there, where
rem nothing else exists. Say so plainly instead of failing at step 3.
if not exist "requirements.txt" goto :not_unzipped

echo.
echo  ============================================================
echo    RSAMAXXED Setup
echo  ============================================================
echo.
echo   This installs everything RSAMAXXED needs. It takes a few
echo   minutes and downloads a few hundred MB. Keep this window
echo   open until it says Done.
echo.

rem Files unzipped from a download carry Windows' "came from the internet"
rem mark, which makes the .bat files ask for permission every time and can
rem stop the app's own files loading. Clear it for this folder. The path goes
rem in through an environment variable so an apostrophe in it cannot break the
rem PowerShell string. Errors are ignored: this is a convenience, not a step.
set "RSA_DIR=%~dp0"
powershell -NoProfile -Command "Get-ChildItem -LiteralPath $env:RSA_DIR -Recurse -Force -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue" >nul 2>&1

rem ---------------------------------------------------------------------------
echo  [1/6] Looking for Python...
call :find_python
if defined PYEXE goto :have_python

echo        Python 3.12 - 3.14 was not found.
where winget >nul 2>&1
if errorlevel 1 goto :no_winget
echo        Installing Python 3.13 with winget. If Windows asks for
echo        permission, click Yes.
winget install -e --id Python.Python.3.13 --scope user --accept-package-agreements --accept-source-agreements
rem winget's exit code is not trusted either way (it is non-zero for "already
rem installed", for one). Whether Python is now findable is what counts. This
rem window's PATH predates the install, so :find_python also checks the
rem default install folder directly.
call :find_python
if not defined PYEXE goto :python_failed

:have_python
for /f "usebackq delims=" %%V in (`call "%PYEXE%" -c "import sys; print(sys.version.split()[0])"`) do set "PYVER=%%V"
echo        Using Python %PYVER%
echo        %PYEXE%
echo.

rem ---------------------------------------------------------------------------
echo  [2/6] Updating pip, the Python package installer...
"%PYEXE%" -m pip --version >nul 2>&1
if errorlevel 1 "%PYEXE%" -m ensurepip --upgrade >nul 2>&1
"%PYEXE%" -m pip install --upgrade pip --disable-pip-version-check
if errorlevel 1 (
    echo.
    echo        Warning: pip could not update itself. Carrying on with the
    echo        version already installed.
)
echo.

rem ---------------------------------------------------------------------------
echo  [3/6] Installing RSAMAXXED's add-ons. This is the long step...
"%PYEXE%" -m pip install -r requirements.txt --disable-pip-version-check
if errorlevel 1 goto :pip_failed

rem Check what is really installed against the pins. A library upgraded by
rem hand (or by another tool) since the last setup -- playwright-stealth 2.x
rem stops Schwab loading at all -- is forced back to the pinned version.
set "RSA_PINS=%TEMP%\rsamaxxed_pins.txt"
"%PYEXE%" -m modules.depcheck --specs > "%RSA_PINS%" 2>nul
if errorlevel 1 (
    echo        Some add-ons are not the tested versions. Reinstalling them...
    "%PYEXE%" -m pip install --force-reinstall --no-deps -r "%RSA_PINS%" --disable-pip-version-check
    "%PYEXE%" -m modules.depcheck
    if errorlevel 1 (
        echo.
        echo        Warning: the add-ons above still do not match. Run
        echo        INSTALL.bat again; if it keeps happening, send this
        echo        window's text to support.
        set "WARNED=1"
    )
)
del "%RSA_PINS%" >nul 2>&1
echo.

rem ---------------------------------------------------------------------------
echo  [4/6] Downloading the browser Schwab signs in with...
"%PYEXE%" -m playwright install firefox
if errorlevel 1 (
    echo.
    echo        Warning: the Schwab browser download failed. Every other
    echo        broker still works. Run INSTALL.bat again later to retry.
    set "WARNED=1"
)
echo.

rem ---------------------------------------------------------------------------
echo  [5/6] Preparing your settings file...
if exist ".env" (
    echo        .env already exists -- left exactly as it is.
) else if exist ".env.example" (
    copy /y ".env.example" ".env" >nul
    if errorlevel 1 (
        echo        Warning: could not create .env. The Brokers page will
        echo        create it the first time you click Save.
        set "WARNED=1"
    ) else (
        echo        Created .env. Add your broker logins on the Brokers page.
    )
) else (
    echo        No .env yet. The Brokers page creates it on your first Save.
)
echo.

rem ---------------------------------------------------------------------------
echo  [6/6] Putting an RSAMAXXED shortcut on your desktop...
"%PYEXE%" make_shortcut.py
if errorlevel 1 (
    echo.
    echo        Warning: the desktop shortcut could not be made. You can
    echo        start the app by double-clicking RSAMAXXED.bat in this folder.
    set "WARNED=1"
)
echo.

echo  ============================================================
echo    Done -- double-click RSAMAXXED on your desktop.
echo  ============================================================
if defined WARNED (
    echo.
    echo   Setup finished with a warning -- see the messages above.
)
echo.
echo   Next: open RSAMAXXED, go to the Brokers page, enter your
echo   broker logins, click Save, then Bootstrap each broker.
echo.
pause
exit /b 0


rem ===========================================================================
rem :find_python -- sets PYEXE to the first usable Python 3.12 - 3.14, trying
rem 3.13 first: it is the version RSAMAXXED is built and tested on.
:find_python
set "PYEXE="
if defined RSA_PYTHON call :try_exe "%RSA_PYTHON%"
if not defined PYEXE call :try_launcher 3.13
if not defined PYEXE call :try_launcher 3.14
if not defined PYEXE call :try_launcher 3.12
if not defined PYEXE call :try_exe "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYEXE call :try_exe "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PYEXE call :try_exe "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYEXE call :try_exe python
exit /b 0

:try_launcher
py -%1 -c "import sys" >nul 2>&1
if errorlevel 1 exit /b 0
for /f "usebackq delims=" %%P in (`py -%1 -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
exit /b 0

rem Accepts a full path or a bare command name. Only 3.12 - 3.14 qualify: the
rem pinned add-ons are not built for anything older.
:try_exe
"%~1" -c "import sys; sys.exit(0 if (3, 12) <= sys.version_info[:2] <= (3, 14) else 1)" >nul 2>&1
if errorlevel 1 exit /b 0
for /f "usebackq delims=" %%P in (`call "%~1" -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
exit /b 0


rem ===========================================================================
:not_unzipped
echo.
echo  ------------------------------------------------------------
echo   Unzip the download first, then run INSTALL.bat from the
echo   unzipped folder.
echo.
echo   Right-click the RSAMAXXED zip, choose "Extract All...",
echo   then open the extracted folder and double-click
echo   INSTALL.bat there.
echo  ------------------------------------------------------------
echo.
pause
exit /b 1

:no_winget
echo.
echo  ------------------------------------------------------------
echo   Python needs to be installed, and this PC can't do it
echo   automatically (the Windows "winget" tool is missing).
echo.
echo   Please install it by hand -- it takes two minutes:
echo.
echo     1. Open  https://www.python.org/downloads/windows/
echo        and download the latest "Python 3.13" Windows
echo        installer, 64-bit.
echo     2. Run it and TICK "Add python.exe to PATH" at the
echo        bottom of the first screen, then Install Now.
echo     3. Double-click INSTALL.bat again.
echo  ------------------------------------------------------------
echo.
pause
exit /b 1

:python_failed
echo.
echo  ------------------------------------------------------------
echo   Python was installed but can't be found yet.
echo.
echo   Close this window and double-click INSTALL.bat again.
echo   If that still fails, restart the PC and try once more,
echo   or install Python 3.13 by hand from
echo     https://www.python.org/downloads/windows/
echo   ticking "Add python.exe to PATH".
echo  ------------------------------------------------------------
echo.
pause
exit /b 1

:pip_failed
echo.
echo  ------------------------------------------------------------
echo   Installing the add-ons failed -- see the error above.
echo.
echo   Most often this is a dropped internet connection or an
echo   antivirus blocking the download. Check your connection
echo   and double-click INSTALL.bat again; it picks up where it
echo   left off.
echo  ------------------------------------------------------------
echo.
pause
exit /b 1
