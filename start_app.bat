@echo off

cd /d "%~dp0"

echo Starting Digital Evidence Vault...
echo.

start "" /B "%~dp0venv\Scripts\python.exe" "%~dp0app.py"

echo Waiting for Flask server to start...
echo.

:WAIT
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'http://127.0.0.1:5000/login' -UseBasicParsing -TimeoutSec 1 | Out-Null; exit 0 } catch { exit 1 }"

if errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto WAIT
)

echo.
echo Flask server is ready!
echo Opening Login Page...
echo.

start "" "http://127.0.0.1:5000/login"

exit