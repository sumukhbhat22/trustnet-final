#!/usr/bin/env bash
# One-click local demo (macOS/Linux): backend on 8010, frontend on 8080. Local demo only.
set -e
cd "$(dirname "$0")"

command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
command -v npm >/dev/null || { echo "npm not found"; exit 1; }

[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q -r backend/requirements.txt
[ -d node_modules ] || npm install

export TRUSTNET_ENV=development
export DEMO_MODE=1
export TRUSTNET_DB_PATH=backend/data/trustnet.db
export TRUSTNET_DEMO_ALLOW_NEW_DEVICE=1
export TRUSTNET_TOTP_KEY=local-demo-totp-key-change-this-32-chars
export TRUSTNET_AUDIT_CHECKPOINT_KEY=local-demo-audit-key-change-this-32-chars
export TRUSTNET_CORS_ORIGINS=http://localhost:8080,http://127.0.0.1:8080,http://localhost:8081,http://127.0.0.1:8081,http://localhost:5173,http://127.0.0.1:5173

.venv/bin/python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8010 &
BACKEND_PID=$!
trap 'kill $BACKEND_PID 2>/dev/null' EXIT

echo "Open http://localhost:8080/login.html  (username: sumukh, password: sumukh@123)"
npm run dev
