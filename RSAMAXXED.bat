@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem Starts the RSAMAXXED app. First-time setup is INSTALL.bat.
rem
rem Several Pythons can sit side by side on one PC, and a bare "pythonw" runs
rem whichever is first on PATH -- often one WITHOUT the app's dependencies,
rem which dies at "import customtkinter" with no window and no message. So use
rem the first interpreter that can actually import them, trying 3.13 first
rem (the version INSTALL.bat installs), then 3.14, then 3.12.
rem
rem Set RSA_PYTHON to a python.exe path to force a specific interpreter.

set "PYEXE="
if defined RSA_PYTHON call :try_exe "%RSA_PYTHON%"
if not defined PYEXE call :try_launcher 3.13
if not defined PYEXE call :try_launcher 3.14
if not defined PYEXE call :try_launcher 3.12
if not defined PYEXE call :try_exe "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not defined PYEXE call :try_exe "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
if not defined PYEXE call :try_exe "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYEXE call :try_exe python
if not defined PYEXE goto :missing

rem pythonw runs without a console window. It sits next to python.exe.
for %%I in ("%PYEXE%") do set "PYWEXE=%%~dpIpythonw.exe"
if not exist "%PYWEXE%" set "PYWEXE=%PYEXE%"

start "" "%PYWEXE%" app.py
exit /b 0


rem ---------------------------------------------------------------------------
rem :try_launcher 3.13  -- via the "py" launcher. Sets PYEXE on success.
:try_launcher
py -%1 -c "import customtkinter, dotenv" >nul 2>&1
if errorlevel 1 exit /b 0
for /f "usebackq delims=" %%P in (`py -%1 -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
exit /b 0

rem :try_exe "C:\path\python.exe"  (or a bare command name). Sets PYEXE on success.
:try_exe
"%~1" -c "import customtkinter, dotenv" >nul 2>&1
if errorlevel 1 exit /b 0
for /f "usebackq delims=" %%P in (`call "%~1" -c "import sys; print(sys.executable)"`) do set "PYEXE=%%P"
exit /b 0


:missing
rem The desktop shortcut starts this file minimized (make_shortcut.py), so the
rem console text below is never seen from there. Put up a real message box
rem first. The folder goes in through an environment variable so a path with
rem an apostrophe in it cannot break the PowerShell string.
set "RSA_DIR=%~dp0"
powershell -NoProfile -Command "$n=[Environment]::NewLine; Add-Type -AssemblyName System.Windows.Forms; [void][System.Windows.Forms.MessageBox]::Show('RSAMAXXED could not start.'+$n+$n+'No Python with the add-ons RSAMAXXED needs was found on this PC.'+$n+$n+'Fix: double-click INSTALL.bat in this folder, let it finish, then start RSAMAXXED again.'+$n+$n+'Folder: '+$env:RSA_DIR, 'RSAMAXXED', 'OK', 'Error', 'Button1', 'DefaultDesktopOnly')" >nul 2>&1
if not errorlevel 1 exit /b 1

rem No PowerShell (or it failed): fall back to the console.
echo.
echo   RSAMAXXED could not start.
echo.
echo   No Python with the app's add-ons installed was found on this PC.
echo.
echo   Fix: double-click INSTALL.bat in this folder, let it finish,
echo   then start RSAMAXXED again.
echo.
echo   Folder: %~dp0
echo.
pause
exit /b 1
