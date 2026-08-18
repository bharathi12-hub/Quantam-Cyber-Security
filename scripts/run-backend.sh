#!/usr/bin/env bash
# QuantumShield - backend launcher (API on http://127.0.0.1:8000)
set -euo pipefail

cd "$(dirname "$0")/.."/backend

if [ ! -x ".venv/bin/python" ]; then
  echo "[QuantumShield] Creating Python virtual environment..."
  rm -rf .venv
  python3 -m venv .venv
fi

echo "[QuantumShield] Installing backend dependencies..."
.venv/bin/python -m pip install --quiet -r requirements.txt

echo "[QuantumShield] Seeding demo data (idempotent)..."
.venv/bin/python -m app.seed

echo "[QuantumShield] Starting API on http://127.0.0.1:8000  (docs at /docs)"
exec .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
