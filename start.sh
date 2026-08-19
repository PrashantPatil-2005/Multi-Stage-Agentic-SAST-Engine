#!/usr/bin/env bash
set -euo pipefail

# ── Build frontend ──────────────────────────────────────────────────────
echo "→ Installing frontend dependencies…"
cd frontend
npm ci --prefer-offline --no-audit --no-fund

echo "→ Building frontend…"
npm run build
cd ..

# ── Install backend ─────────────────────────────────────────────────────
echo "→ Installing backend dependencies…"
cd backend
pip install --no-cache-dir .
cd ..

# ── Start backend (serves API + frontend static files) ──────────────────
echo "→ Starting server…"
cd backend
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
