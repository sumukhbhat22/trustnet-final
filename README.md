# TrustNet AI

Zero-trust behavioural security demo: React + Vite frontend, FastAPI backend, SQLite storage, ML risk scoring,
an agent layer (Investigator -> Response -> Orchestrator, analyst feedback/learning), tamper-evident audit chain,
notifications, and WebSocket live updates.

> **Status: security-hardened checkpoint, NOT production-ready** (frontend checks, dependency audits and an end-to-end run are still unverified). See `docs/STATUS.md` for the canonical implementation state, exact verification results and remaining blockers.

## Architecture

```
React/Vite/TS (src/)  --HTTP+cookie/Bearer, WebSocket-->  FastAPI (backend/main.py)  -->  SQLite (TRUSTNET_DB_PATH)
                                                           |-- models/: auth, MFA, refresh tokens, device registry, geo policy,
                                                           |            risk engine, ML (Isolation Forest + classifier), audit chain
                                                           '-- agents/: Investigator -> Response -> Orchestrator (+ analyst feedback)
```
Event/login -> validation + feature vector -> anomaly/risk scoring -> classification -> incident -> Investigator evidence ->
Response recommendation (sensitive actions need approval) -> audit chain -> verdict.

## Prerequisites
Python 3.12 (tested with 3.12.3), Node 22 + npm 10, and network access for `pip install` / `npm ci`. Docker is optional.

## Environment variables (see `.env.example`; never commit real values)
`TRUSTNET_ENV` (`production` enforces a >=32-char `TRUSTNET_JWT_SECRET`, Secure cookies, no demo features) | `TRUSTNET_JWT_SECRET` |
`TRUSTNET_DB_PATH` | `TRUSTNET_CORS_ORIGINS` (comma list, `*` ignored) | `DEMO_MODE` (never in production) | `VITE_ML_API_URL` |
`TRUSTNET_SMTP_HOST/PORT/USER/PASSWORD/FROM/STARTTLS` | `TRUSTNET_BOOTSTRAP_ADMIN_EMAIL/PASSWORD` | `TRUSTNET_ALLOWED_COUNTRIES` |
`TRUSTNET_BUSINESS_TIMEZONE` | `TRUSTNET_RATE_LIMIT_ENABLED/LOGIN_PER_MIN/API_PER_MIN` | `TRUSTNET_APPROVAL_TTL_MINUTES` |
`TRUSTNET_TEMP_BLOCK_MINUTES` | `TRUSTNET_NOTIFY_COOLDOWN_MINUTES` | `TRUSTNET_EVENT_RETENTION_DAYS` | `TRUSTNET_INCIDENT_CORRELATION_MINUTES`.

## Database initialisation
Automatic on first backend start (schema creation and migrations for existing SQLite files). Optional fictional history: `DEMO_MODE=1 python backend/seed.py`.

## ML model and dataset limitations
- All bundled training and evaluation data is **synthetic** (`generate_training_data`, `evaluate_synthetic.py`). No real-world attack dataset is in the repository, so no real-world accuracy is claimed.
- `docs/SYNTHETIC_EVALUATION.json` is reproducible (seed 42; re-running gives identical output). Its near-perfect scores come from separable generated distributions, and a transparent rules-only baseline scores as well as the model. Do not read them as operational performance.
- `train()` metrics are computed on the training data; use the held-out evaluation script for comparisons.
- The per-session model cannot see an attacker who keeps every feature inside the normal range (low-and-slow); `test_ml_detector.py` records this as a known limitation.
- The system scores risk and flags anomalies; it does **not** predict when an attack will occur.
- Model files are loaded with `joblib` (pickle). Only load model files you created.

## Known limitations
Access tokens live only in memory; after a reload the app silently restores the session from the HttpOnly refresh cookie (implemented, not yet browser-tested); rate limiting is in-memory and single-process; the audit chain is not externally anchored; GeoIP uses an online provider; one primary response action per incident; no hosted deployment exists. Details and open gates: `docs/STATUS.md`.

## Run locally
Quickest path: run `start-demo.bat` (Windows) or `./start-demo.sh` (macOS/Linux). It installs dependencies, starts the backend (8010) and frontend (8080) with the demo settings, then open `http://localhost:8080/login.html` and sign in as `sumukh` / `sumukh@123`. "Failed to fetch" at login means the backend is not running on port 8010.

```bash
# backend (http://localhost:8010)
cd backend
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example ../.env                           # then edit; never commit .env
uvicorn main:app --host 127.0.0.1 --port 8010

# frontend (new terminal, project root; http://localhost:8080 or Vite's printed URL)
npm ci
npm run dev
```
Health check: `GET http://localhost:8010/api/health`. The SQLite DB is created automatically at `TRUSTNET_DB_PATH`.
Local demo accounts exist only when `TRUSTNET_ENV` is not `production` (see `backend/models/security_auth.py`).

## Tests and release gates

The canonical evidence is maintained in [`docs/STATUS.md`](docs/STATUS.md). In the current environment, the backend core/MFA/demo unit suites and API/agent suites passed when run separately. Frontend gates, dependency audits, Docker Compose and a hosted demo remain unverified because the required registry/tools were unavailable.

Run locally:
```bash
cd backend && python -m unittest test_core_security test_mfa test_refresh_tokens test_geo_policy test_ml_detector test_demo_replay test_demo_scenarios test_incident_correlation test_learning_idempotency test_request_policy test_attack_classifier -q
cd backend && python -m unittest test_backend_api -q
cd backend && python -m unittest test_agents -q
cd .. && python test_ml_models.py && (cd backend && python evaluate_synthetic.py)
npm ci && npx tsc -p tsconfig.app.json --noEmit && npm run lint && npm test && npm run build
```

## Security behaviour implemented
- Approvals: no self-approval (403), only admin/analyst (403), atomic single execution, 409 once decided,
  expiry (`TRUSTNET_APPROVAL_TTL_MINUTES`, default 60), crash recovery of stuck `executing` approvals (marked failed).
  An account can never dismiss, resolve, reject or label an incident/action that targets itself (403, audited).
- Autonomy: kill switch, autonomy mode, hourly cap and protected admin/analyst accounts re-checked immediately before
  automatic execution. Sensitive account actions (`temp_block_account`) always need recorded human approval.
- Account restrictions: expiring temporary blocks (default 30 min, max 24 h, never permanent) enforced in login,
  every authenticated route, and WebSocket tickets; released early via `POST /api/account-restrictions/{id}/release`.
- Notifications: persistent, per-user unread count and mark-read, persistent dedup/cooldown
  (`TRUSTNET_NOTIFY_COOLDOWN_MINUTES`), SMTP failure keeps the in-app record, SMTP secrets redacted.
- Rate limiting: enforced per-IP limiter (429), on by default only when `TRUSTNET_ENV=production`
  (`TRUSTNET_RATE_LIMIT_ENABLED`, `..._API_PER_MIN`, `..._LOGIN_PER_MIN`). In-memory, single-process only.
- Persistent login lockout (existing), security headers and env-based CORS allowlist (existing).
- WebSocket: single-use 60 s tickets; sockets are re-validated on every message, closed on logout and after the
  15-minute access-token lifetime.

## Production notes
Set `TRUSTNET_ENV=production`, a 32+ char `TRUSTNET_JWT_SECRET`, `TRUSTNET_BOOTSTRAP_ADMIN_EMAIL/PASSWORD`, and
`TRUSTNET_CORS_ORIGINS`. Docker: `docker build -f Dockerfile.backend -t trustnet-backend .` (backend only; serve the
built frontend (`npm run build` -> `dist/`) from any static host). No hosted deployment has been performed or verified.


### Investigator attack-family classification

The Investigator provides a deterministic, evidence-based attack-family label (`stolen_credentials`, `brute_force`, `data_exfiltration`, `after_hours_insider`, or `unknown`) with a confidence estimate and a recommended next step. This is an explainable demo rule layer, not a trained LSTM or a claim of real-world detection accuracy. Recommendations do not bypass the existing response safeguards or human approval. See `docs/STATUS.md` for verification limits.


### Demo-data and evaluation disclosure
The Overview page does not send random fabricated behavior metrics to the ML API. Its historical risk chart stays empty until persisted history is available. Behavior Analytics charts that use generated examples are explicitly labelled **DEMO DATA** and are not automatically submitted as real-user telemetry. The reproducible synthetic holdout output is in `docs/SYNTHETIC_EVALUATION.json`; these figures describe generated data only and do not establish real-world detection accuracy.

### Safe demo reset

The backend exposes `POST /api/demo/reset` for repeatable demonstrations. It is hidden unless `DEMO_MODE=true` (or `1`, `yes`, `on`) is explicitly set, and it requires an administrator with the `manage_users` permission. It stops the attack-chain simulator and clears demo activity such as incidents, risk state, devices, baselines, agent actions, feedback and notifications. It deliberately preserves accounts, login history, security events, the append-only audit chain, protected assets and access policies, and records the reset in the audit chain. Do not enable `DEMO_MODE` in a production deployment.

### Repeatable synthetic demo scenarios and evaluation

`backend/demo_scenarios.py` prints a deterministic catalogue of five fictional scenarios. It does not execute attacks or send network requests. Run it from the repository root with `python -m backend.demo_scenarios`. The saved catalogue is `docs/DEMO_SCENARIOS.json`.

`backend/evaluate_synthetic.py` compares a fixed-threshold rules-only baseline with the Isolation Forest detector on a reproducible synthetic 80/20 holdout split (seed 42). The generated results are stored in `docs/SYNTHETIC_EVALUATION.json`. In the current split the rules-only baseline scores better than Isolation Forest; these synthetic metrics must not be represented as operational or real-world detection accuracy.

### Opt-in seed and scenario tools

`DEMO_MODE=1 python backend/seed.py` creates fictional identities/devices and 21 days of synthetic history in the configured local database. `backend/scenarios.py` replays scenario IDs through the running API at a controlled interval and requires `TRUSTNET_DEMO_TOKEN`; `backend/client.py` can make metadata-only protected-asset requests using `TRUSTNET_TRUSTED_TOKEN` or `TRUSTNET_ROGUE_TOKEN`. These tools never run real attacks.

### Docker Compose

Copy `.env.example` to `.env`, replace `TRUSTNET_JWT_SECRET` with a random secret of at least 32 characters, and run `docker compose up --build`. This path is defined but has **not** been built or verified in the current environment.

Compose now defaults to `TRUSTNET_ENV=production` and the backend container runs as a non-root user. In production set
`TRUSTNET_BOOTSTRAP_ADMIN_EMAIL` and `TRUSTNET_BOOTSTRAP_ADMIN_PASSWORD` for the first admin. For a local demo with seeded accounts, set
`TRUSTNET_ENV=development` and `DEMO_MODE=1` in `.env` (never on a public host). Generate a secret with
`python -c "import secrets; print(secrets.token_urlsafe(48))"`. Still unbuilt/unverified here (no Docker or network).


## F-28 / F-32 (added)
- Asset criticality: `GET /api/assets` (any authenticated role), `PUT /api/assets/{asset_id}/criticality` body `{"criticality": 1-5}` (admin only). Saved in SQLite; used by the risk engine and topology.
- Incident PDF: `GET /api/incidents/{id}/report.pdf` (analyst/admin). Requires `reportlab` (in backend/requirements.txt).
- Tests: `cd backend && python -m unittest test_asset_criticality_core test_incident_report_core test_assets_pdf_api`

## Project status and ML notes

See [`docs/STATUS.md`](docs/STATUS.md) for the canonical, evidence-based implementation status and remaining release gates, [`docs/EVIDENCE.md`](docs/EVIDENCE.md) for recorded verification and manual acceptance checks, and [`docs/ml/`](docs/ml/) for model notes. This is demonstration software using synthetic data; synthetic scores are not real-world accuracy claims. Do not treat the project as production-ready until the listed security, frontend, audit, Docker, and end-to-end release gates pass.

## Sensitive synthetic demo endpoints

- `GET /api/hr/records` returns synthetic HR rows only to authorized roles and audits access attempts.
- `GET /api/files/export` returns synthetic export metadata only and audits access attempts. Both follow the protected-asset role policy and return `403` when unauthorized.

### Analyst feedback learning replay

Authorized dashboard users can inspect the recorded before/after risk-score evidence for an incident at `GET /api/incidents/{incident_id}/learning-replay`. The response reports the stored score comparison, delta, policy version, and behavior profile where available. If no feedback comparison has been recorded, it explicitly returns `no_feedback_effect` instead of inventing numbers. This is a transparent bounded rule adjustment; it does not claim ML model retraining.
