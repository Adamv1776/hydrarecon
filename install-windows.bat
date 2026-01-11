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
echo [4/5] Creating launch scripts...
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

REM Create Desktop Shortcut
echo.
echo [5/5] Creating Desktop shortcut...
set "DESKTOP=%USERPROFILE%\Desktop"
set "INSTALL_DIR=%~dp0"

REM Create VBS script to make shortcut
(
echo Set oWS = WScript.CreateObject^("WScript.Shell"^)
echo sLinkFile = "%DESKTOP%\HydraRecon.lnk"
echo Set oLink = oWS.CreateShortcut^(sLinkFile^)
echo oLink.TargetPath = "%INSTALL_DIR%start.bat"
echo oLink.WorkingDirectory = "%INSTALL_DIR%"
echo oLink.Description = "HydraRecon - Enterprise Security Assessment Suite"
echo oLink.IconLocation = "%INSTALL_DIR%gui\icons\hydrarecon.ico"
echo oLink.WindowStyle = 1
echo oLink.Save
) > create_shortcut.vbs

cscript //nologo create_shortcut.vbs
del create_shortcut.vbs

if exist "%DESKTOP%\HydraRecon.lnk" (
    echo Desktop shortcut created successfully!
) else (
    echo Note: Could not create desktop shortcut automatically.
    echo You can create one manually by right-clicking start.bat
)

echo.
echo ═══════════════════════════════════════════════════════════════════
echo SUCCESS: HydraRecon installed!
echo ═══════════════════════════════════════════════════════════════════
echo.
echo A shortcut has been added to your Desktop!
echo.
echo To start HydraRecon:
echo   - Double-click "HydraRecon" on your Desktop
echo   - Or run: start.bat
echo   - Lite mode: start-lite.bat
echo.
echo NOTE: First launch requires license acceptance.
echo.
pause
