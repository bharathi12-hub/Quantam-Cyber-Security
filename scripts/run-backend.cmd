@echo off
REM QuantumShield - backend launcher (API on http://127.0.0.1:8000)
setlocal
cd /d "%~dp0..\backend"

if not exist ".venv" (
  echo [QuantumShield] Creating Python virtual environment...
  python -m venv .venv
)

echo [QuantumShield] Installing backend dependencies...
call ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt

echo [QuantumShield] Seeding demo data (idempotent)...
call ".venv\Scripts\python.exe" -m app.seed

echo [QuantumShield] Starting API on http://127.0.0.1:8000  (docs at /docs)
call ".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
