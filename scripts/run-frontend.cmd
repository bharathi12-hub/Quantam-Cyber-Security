@echo off
REM QuantumShield - frontend launcher (dashboard on http://localhost:5173)
setlocal
cd /d "%~dp0..\frontend"

if not exist "node_modules" (
  echo [QuantumShield] Installing frontend dependencies...
  call npm install
)

echo [QuantumShield] Starting dashboard on http://localhost:5173
call npm run dev
