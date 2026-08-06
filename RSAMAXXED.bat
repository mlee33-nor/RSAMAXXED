@echo off
cd /d "%~dp0"

rem Pin the interpreter. Python 3.12 and 3.14 are also installed and come first
rem on PATH, so a bare "pythonw" picks one of them -- and only 3.13 has the
rem app's dependencies. Launching under the wrong one dies at "import
rem customtkinter" with no window and no message.
set "PY=py -3.13"
set "PYW=pyw -3.13"

rem Preflight: pythonw has no console, so an import error would be invisible.
rem Check here, where we can actually show it.
%PY% -c "import customtkinter, dotenv" >nul 2>&1
if errorlevel 1 (
    echo.
    echo   RSAMAXXED could not start -- Python 3.13 or one of its
    echo   dependencies is missing. The error was:
    echo.
    %PY% -c "import customtkinter, dotenv"
    echo.
    echo   Fix it with:  py -3.13 -m pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

start "" %PYW% app.py
