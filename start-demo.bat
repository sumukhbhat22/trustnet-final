@echo off
REM One-click local demo: installs dependencies, starts the backend (8010) and frontend (8080).
REM Requires Python 3.12+ and Node 22+ on PATH. Local demo only - never use in production.
setlocal
cd /d "%~dp0"

where python >nul 2>nul || (echo Python is not installed or not on PATH. & pause & exit /b 1)
where npm >nul 2>nul || (echo Node.js/npm is not installed or not on PATH. & pause & exit /b 1)

if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment...
  python -m venv .venv || (echo Failed to create venv. & pause & exit /b 1)
)
echo Installing backend dependencies...
".venv\Scripts\python.exe" -m pip install -q -r backend\requirements.txt || (echo pip install failed. & pause & exit /b 1)

if not exist "node_modules" (
  echo Installing frontend dependencies...
  call npm install || (echo npm install failed. & pause & exit /b 1)
)

set TRUSTNET_ENV=development
set DEMO_MODE=1
set TRUSTNET_DB_PATH=backend/data/trustnet.db
set TRUSTNET_DEMO_ALLOW_NEW_DEVICE=1
set TRUSTNET_TOTP_KEY=local-demo-totp-key-change-this-32-chars
set TRUSTNET_ALERT_EMAILS=sumukhbhat66@gmail.com
set TRUSTNET_AUDIT_CHECKPOINT_KEY=local-demo-audit-key-change-this-32-chars
set TRUSTNET_CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080,http://localhost:8081,http://127.0.0.1:8081,http://localhost:5173,http://127.0.0.1:5173

echo Starting backend on http://localhost:8010 ...
start "TrustNet backend" cmd /k ".venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8010"

echo Starting frontend on http://localhost:8080 ...
start "TrustNet frontend" cmd /k "npm run dev"

echo.
echo Open http://localhost:8080/login.html
echo Login:  username  sumukh   password  sumukh@123
echo (Wait ~10 seconds for both windows to finish starting. Keep them open.)
endlocal
