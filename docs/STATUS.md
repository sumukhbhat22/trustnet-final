# TrustNet AI: status (single source of truth)

Last updated: 2026-10-20 (canvas sizing fix follow-up). Demonstration software with synthetic data. A green test suite is not proof of real-world detection accuracy or production readiness.

This file replaces FINAL_STATUS, HANDOFF_STATUS, PROJECT_MANIFEST, PHASE_COMPLETION, REMAINING_RELEASE_GATES and VERIFICATION_REPORT. Evidence labels:

- **Audited (external)**: result reported by the owner's audit of commit 3a591aa on 2026-10-19. Not re-run in the session that merged this file.
- **Run here**: executed in the session that last edited that line.
- **Not run**: written or changed but never executed. Do not treat as passing.

## Baseline (audited externally, 2026-10-19, commit 3a591aa)

| Check | Result |
|---|---|
| Backend tests, all 28 modules together | 272 of 272 pass (99 s) |
| Frontend `npm ci`, `tsc`, build, vitest | pass; 12 tests; bundle over 500 kB |
| Frontend lint | 63 errors, 11 warnings (fails) |

## Implemented and tested (per audit; see docs/REQUIREMENT_TRACEABILITY.md for test names)

- Login, device-bound JWT, refresh rotation with reuse detection, email-code MFA, restrictions (block, read_only), country policy, device trust and revoke, user management.
- Hash-chained audit log with `/api/audit/verify`.
- Incident correlation, Investigator agent and attack classifier (deterministic rules).
- Response agent: `require_mfa`, `restrict_session`, `temp_block_account` (human approval), quarantine; atomic approvals, kill switch, autonomy modes, notifier.
- Behaviour EMA with baseline version; analyst-confirmed known-bad device and IP feed risk scoring (device flagged penalty; IP bounded +25 after fusion); learning-replay API and panel (shows N/A when no persisted comparison exists).
- `/api/hr/records` and `/api/files/export`: synthetic, audited, denied for restricted sessions.
- IP provenance: scoring uses the transport peer IP only; `X-Forwarded-For` is not trusted.
- IP-provenance end-to-end test, demo reset and replay, `scripts/demo_pipeline.py`, `scripts/verify_all.sh`, CI workflow file, Docker files.
- Session restoration after reload (refresh cookie then `/auth/me`) and single-flight refresh in the frontend.

## Partial

- Response ladder: risk bands 31-60 MFA, 61-85 restrict, 86-100 block are wired for non-malicious cases when no device is available; not every verdict, device and risk combination is explicit or tested (Prompt 3).
- Learning: no trust-device choice on False Positive, no stored-session replay with old and new profile, no retrain trigger.
- Health endpoint has no degraded mode; WebSocket has no SOC-room role isolation.
- Live models are trained on synthetic data; a real-data training path exists but has not been run on the dataset. `docs/EVALUATION.md` adds a 5-seed time-split synthetic evaluation. The rules-only baseline matches or beats the Isolation Forest on the synthetic set (F1 0.9934 vs 0.9804), so no ML advantage is demonstrated.
- Step-up MFA also supports confirmed TOTP at login (authenticator or backup code); the dashboard's general MFA challenge remains email-code based. Audit-checkpoint cores exist and are unit tested.

## Planned / out of scope

- LSTM autoencoder (optional, not built). CSI Wi-Fi hardware (out of scope).
- Browser E2E, event export, load test, model cards (Prompt 9).

## Blocked or not yet proven

- Docker build and run: never executed.
- `pip-audit`, `npm audit`, coverage numbers, CI run on GitHub: never executed.
- Real SMTP delivery, real GeoIP service: need credentials and network.
- Real public training data: needs the owner to download the RBA dataset into `data/raw/` (git-ignored).

## Prompt 4: real public data training (code written 2026-10-19)

- Run here: `cd backend && python3 -m unittest test_real_data_training` -> 10 tests OK (fabricated rows only; covers column mapping, hashing, reproducible sampling, no time leakage, metadata save/load, fallback when the file is missing, mismatched or corrupt, CLI "BLOCKED" exit code, `.gitignore` entries).
- New: `backend/ml/data_loader.py`, `registry.py`, `train_real.py`, `docs/ml/DATA.md`.
- Not run: `main.py` startup wiring (loads the real model if present) and `/api/health` `model` field. FastAPI is not installable here; only `py_compile` passed. Admin Panel display of model name, version and source is **not done** (frontend).
- Blocked: training on the real dataset. The file is not present. Command: `cd backend && python -m ml.train_real --data ../data/raw/rba-dataset.csv --sample-frac 0.05`. Licence line in `docs/ml/DATA.md` must be filled in by you.

## Prompt 5: honest evaluation (partly done, 2026-10-19)

- Run here: `cd backend && python3 evaluate.py` twice -> `docs/EVALUATION.json` byte-identical (`cmp`); `python3 -m unittest test_evaluate` -> 7 tests OK (hand-made metrics, no time leakage, attacks only in held-out days, determinism, output statement, blocked real part).
- Result (synthetic only, 5 seeds, mean): F1 rules baseline 0.544, Isolation Forest alone 0.555, full evaluation-level fusion 0.596. Slow-and-low and mimicry recall stay under 0.10 for every variant. See `docs/EVALUATION.md`. "Full pipeline" here is an evaluation-level fusion with fixed weights, not the live FastAPI risk engine.
- Blocked: part A (real data) needs the RBA file: `cd backend && python evaluate.py --real-data ../data/raw/rba-dataset.csv`.
- Not done: `scripts/demo_pipeline.py` PASS list rewrite, Simulate Attack UI banner, `client.py` check against a live server, tests that production mode refuses seed/replay/reset (all need FastAPI/Node/a running server).

## Prompts 8 and 9: standalone cores only (2026-10-19)

- Run here: `cd backend && python3 -m unittest test_totp_anchor test_event_export_load` -> 18 tests OK.
  - `models/totp.py`: RFC 6238 vectors (6 timestamps) pass; valid, expired, drifted (one step), wrong and replayed codes; backup codes single-use and stored hashed; secret encrypted with Fernet (`cryptography` added to requirements).
  - `models/audit_anchor.py`: HMAC-signed checkpoints in a separate append-only file; tail deletion, row edit, forged signature, wrong key, corrupt line and missing key are all handled in tests.
  - `backend/event_export.py`: off by default; signed webhook verified against a local test receiver (tamper, wrong secret and replay rejected); JSON-lines file; delivery failures never raise; audit callback.
  - `scripts/load_test.py`: percentile and summary maths tested, and one run against a local stub. **No TrustNet load numbers exist**: the API could not be started here.
- **Not done (needs FastAPI and Node):** TOTP enrolment endpoints, lockout and rate limits for TOTP, MFA dialog UI; wiring checkpoints into `/api/audit/verify` and the Verify button; wiring export into incident and approval code; Playwright browser E2E and its CI job.
- `docs/ml/MODEL_CARDS.md` written for the three models.

## Known gaps in the frontend (from audit)

- `mockData` still imported by `NetworkGraph.tsx`, `securityStore.tsx`, `IncidentResponse.tsx`.
- No route lazy loading; bundle over 500 kB.
- 63 lint errors and 11 warnings.

## Repository hygiene (this update)

- Removed `backend/data/trustnet.db` from the tree (kept `backend/data/.gitkeep`). `.gitignore` now also covers `data/`, `backend/data/*`, coverage output and model binaries.
- Deleted redundant status documents listed above (the uploaded archive did not contain the root-level ANTIGRAVITY, HANDOFF, FINAL_STATUS or PROJECT_MANIFEST files, so there was nothing to merge from them).
- The uploaded archive held no zip files, caches or `node_modules`. Verified by `find`, run here.
- Secret scan (working tree, run here, regex for common key and private-key patterns and `password = "..."` literals): only `backend/seed.py` (derives fictional demo-only passwords from a hash) and `backend/test_backend_api.py` (test password) matched. No real secrets found. Git history was **not** scanned (the archive has no `.git`). Run `gitleaks detect` or `trufflehog git file://.` on the real repository.
- Production mode: `seed.py` and `/api/demo/*` refuse to run when `TRUSTNET_ENV=production` or `DEMO_MODE` is off (code reading, run here). The admin account comes only from `TRUSTNET_BOOTSTRAP_ADMIN_EMAIL` and `TRUSTNET_BOOTSTRAP_ADMIN_PASSWORD` (`models/security_auth.py`). `.env.example` holds placeholders only.
- `scripts/verify_all.sh` now runs the whole backend suite in one `unittest discover` process, matching the audited 272-test run.

## Environment note for this update

The session that produced this update had no access to pypi.org or npm (network policy refused the connection). FastAPI, bcrypt, httpx and `node_modules` were not installed, so **no backend, frontend, Docker or audit command was run**. Only static checks were possible.

## Second session (2026-10-19, network available) — run here

- Backend: `python -m unittest discover -s . -p "test_*.py"` in `backend/` -> 324 tests, all passing except the health test, which was then rewritten and passed on its own; **the full suite was not re-run after that last edit**.
- Frontend: `tsc` clean; `npm run lint` 0 errors, 11 warnings (generated shadcn files, one hook dependency); `npm test` 12 pass; `npm run build` entry chunk 142 kB, three.js chunk 518 kB (login page only, lazy). Routes are lazy-loaded.
- Prompt 8 wiring done: `models/totp_service.py` and `/api/mfa/totp/{status,enroll,confirm,verify}`, admin reset `DELETE /api/users/{id}/mfa/totp`; lockout after 5 wrong codes, replay rejected, backup codes single use, secret encrypted (needs `TRUSTNET_TOTP_KEY`, 32+ chars; fails closed). `/api/audit/verify` now returns signed-checkpoint status (`TRUSTNET_AUDIT_CHECKPOINT_KEY`, `_FILE`, `_EVERY`). Tests: `test_totp_api.py` (13).
- Prompt 9 wiring done: `export_record()` called on incident creation and response approve/reject (`TRUSTNET_EXPORT_*`, off by default). Tests: `test_export_wiring.py` (4).
- `/api/health` now has `healthy | degraded | unavailable` and a `checks` object.
- Still NOT done: general MFA dialog TOTP UI and checkpoint status in the Verify button; Prompt 3 ladder matrix and SOC-room WebSocket role isolation; Playwright E2E; Docker; coverage, pip-audit, npm audit, CI run; real-data training; review of routes without an auth dependency (`/users`, `/devices`, `/baselines`, baseline reset appear unauthenticated; not verified).

## How to verify everything

```
bash scripts/verify_all.sh      # prints PASS or FAIL per step, writes verification-report.txt (git-ignored)
```

## Progress against the 9-prompt plan

| Prompt | State |
|---|---|
| 1 Repo cleanup | Done in this archive; git-history cleanup and secret scan of history must be done in the real repo |
| 2 Frontend gates | Not started (needs npm) |
| 3 Agents, ladder, SOC room, health | Not started (needs FastAPI) |
| 4 Real-data training | Code and tests done; real training and UI display blocked |
| 5 Evaluation | Synthetic part done and run; real part and demo_pipeline PASS list not done |
| 6 Quality gates, coverage, CI, audits | Not started (CI file updated only) |
| 7 Docker, README, evidence | Not started (Docker not run) |
| 8 TOTP, audit anchoring | Cores done and tested; API and UI wiring not done |
| 9 Browser E2E, export, load test, model cards | Export core, load script and model cards done; E2E not done |

## Release position

**Not release-complete and not production-ready.** Open items are listed above and in `docs/REQUIREMENT_TRACEABILITY.md`.

## Login WebGL canvas sizing fix (2026-10-20)

- Cause: ray target dimensions were derived from `window.innerWidth/innerHeight`, while the renderer was also sized from window bounds rather than the canvas CSS box. There was no `ResizeObserver` or per-frame CSS-size/DPR check. The full-screen texture display used the moving perspective scene camera, so it was not a guaranteed full-screen pass. The ray shader already uses target-centered UVs, but dimension/source mismatches could stretch the image.
- Updated `src/pages/LoginPage3D.tsx`: the full-screen canvas has explicit 100% CSS dimensions and is portaled to `document.body` to avoid transformed route wrappers altering its fixed containing block. Renderer dimensions, camera aspect, bloom aspect, output size and ray target now follow `canvas.clientWidth/clientHeight` and DPR via `window.resize`, `ResizeObserver`, and per-frame size/DPR comparisons. `uRes` is assigned from actual ray-target dimensions every creation; adaptive quality stays within a 2x total DPR cap; the display uses a dedicated orthographic camera; chapter text layout is recomputed on resize.
- Added `src/lib/webglSizing.ts` and `src/test/webglSizing.test.ts`; the test confirms a 1440×810 CSS canvas produces a 2160×1215 buffer at DPR 1.5 with the same aspect ratio.
- Verification run here: `npx tsc -p tsconfig.app.json --noEmit` passed; `npm run lint` passed with 0 errors and 11 existing warnings; `npm test` passed (13 tests, including the sizing test); `npm run build` passed.
- Browser dimensions exercised at 1440×810, 1050×583, 390×800 and after further viewport resizing while scrolling. At those initial viewports the canvas CSS aspect and drawing-buffer aspect matched (1430×810, 1041×583, 381×800 CSS/buffer sizes in the shared browser, which has 9 px scrollbar width). The browser has no available WebGL context, so ray-render visual roundness, stars, DevTools-induced DPR changes and laptop performance could not be verified. Production rendering on the user's GPU remains unverified.

## Login API and authenticator flow (2026-10-20)

- The Control Room login submits the existing `POST /api/auth/login` payload with the browser fingerprint and `fingerprint_id`; successful login is followed by `GET /api/mfa/totp/status`. Confirmed TOTP accounts must verify through `POST /api/mfa/totp/verify` before the React route changes to `/overview`; accounts without enrollment proceed directly. Existing API messages are shown, structured detail objects are unwrapped, and backend-unavailable errors include the configured API address and startup hint. Auth/session behavior remains owned by `mlBackendService` and the backend.
- Verified manually in the local browser: `sumukh` / `sumukh@123` logged in against the running local FastAPI service and reached `/overview`; current demo account has no enrolled TOTP. Frontend checks after this change: TypeScript passed; lint 0 errors / 11 warnings; Vitest 13 passed; production build passed. TOTP-enrolled login was not tested against a live account.
