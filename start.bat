@echo off
rem Opens the PHI exposure scan in your browser. Double-click to run.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo  The scanner is not set up yet. Double-click install.bat first.
    pause
    exit /b 1
)
.venv\Scripts\python.exe -m phi_scan.launcher
pause
