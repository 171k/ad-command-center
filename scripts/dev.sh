#!/usr/bin/env bash
# Run backend + frontend for local development (Linux/macOS).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
./.venv/bin/pip install -q -r requirements-dev.txt
./.venv/bin/python -m app.admin status >/dev/null 2>&1 || true
./.venv/bin/uvicorn app.main:app --reload --port 8000 &
BACK=$!

cd "$ROOT/frontend"
[ -d node_modules ] || npm install
npm run dev &
FRONT=$!

trap 'kill $BACK $FRONT 2>/dev/null || true' EXIT
echo "Backend :8000  Frontend :5173  (Ctrl-C to stop)"
wait
