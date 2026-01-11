@echo off
REM ═══════════════════════════════════════════════════════════════════════════════
REM  HydraRecon Enterprise - Windows Installer
REM ═══════════════════════════════════════════════════════════════════════════════

echo.
echo ═══════════════════════════════════════════════════════════════════
echo         HydraRecon Enterprise - Windows Installer
echo ═══════════════════════════════════════════════════════════════════
echo.

REM Check Python
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.10+ from python.org
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version') do set PYVER=%%v
echo Found Python %PYVER%

REM Create virtual environment
echo.
echo [2/4] Creating virtual environment...
if not exist "venv" (
    python -m venv venv
)
call venv\Scripts\activate.bat

REM Install dependencies
echo.
echo [3/4] Installing dependencies (this may take a few minutes)...
pip install --upgrade pip -q
pip install -q PyQt6 PyQt6-WebEngine
pip install -q -r requirements.txt

REM Create start script
echo.
echo [4/4] Creating launch scripts...
(
echo @echo off
echo call "%~dp0venv\Scripts\activate.bat"
echo python "%~dp0launcher.py" %%*
) > start.bat

(
echo @echo off
echo call "%~dp0venv\Scripts\activate.bat"
echo python "%~dp0lite.py" %%*
) > start-lite.bat

echo.
echo ═══════════════════════════════════════════════════════════════════
echo SUCCESS: HydraRecon installed!
echo ═══════════════════════════════════════════════════════════════════
echo.
echo To start HydraRecon:
echo   start.bat          - Full mode
echo   start-lite.bat     - Lite mode (faster)
echo.
echo NOTE: First launch requires license acceptance.
echo.
pause
