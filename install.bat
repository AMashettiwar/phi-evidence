@echo off
rem One-time setup for the PHI exposure scan. Double-click to run.
cd /d "%~dp0"
echo.
echo  PHI exposure scan: one-time setup
echo  This downloads about 1 GB (language models and a browser) and takes 5 to 15 minutes.
echo.

py -3.11 -c "import sys" >nul 2>nul
if errorlevel 1 (
    echo  Python 3.11 is not installed on this computer.
    echo  1. Open https://www.python.org/downloads/release/python-3119/
    echo  2. Download the "Windows installer, 64-bit" and run it with the default options.
    echo  3. Double-click install.bat again.
    echo.
    pause
    exit /b 1
)

if not exist .venv\Scripts\python.exe (
    echo  [1/3] Creating a private Python environment in this folder ...
    py -3.11 -m venv .venv
    if errorlevel 1 goto failed
)

echo  [2/3] Installing the scanner and its language models ...
.venv\Scripts\python.exe -m pip install --quiet --disable-pip-version-check -r requirements.lock
if errorlevel 1 goto failed

echo  [3/3] Installing the browser the scanner uses ...
.venv\Scripts\python.exe -m playwright install chromium
if errorlevel 1 goto failed

echo.
echo  Setup finished. Double-click start.bat to open the scanner.
echo.
pause
exit /b 0

:failed
echo.
echo  Setup did not finish. Check the internet connection and run install.bat again.
echo  If it fails again, send a screenshot of this window to whoever gave you the scanner.
echo.
pause
exit /b 1
