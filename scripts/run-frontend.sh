#!/usr/bin/env bash
# QuantumShield - frontend launcher (dashboard on http://localhost:5173)
set -euo pipefail

cd "$(dirname "$0")/.."/frontend

if [ ! -d "node_modules" ]; then
  echo "[QuantumShield] Installing frontend dependencies..."
  npm install
fi

echo "[QuantumShield] Starting dashboard on http://localhost:5173"
exec npm run dev
