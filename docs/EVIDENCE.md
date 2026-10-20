# Verification evidence

## Current recorded output
- `python -m compileall -q backend`: PASS.
- Core/security/feature backend suite: 123 tests, PASS.
- API integration suite: 46 tests, PASS.
- Agent pipeline suite: 45 tests, PASS.
- `npm ci --ignore-scripts`: did not finish in the current execution window; frontend checks are not claimed.
- Docker, dependency audits, browser walkthrough and live deployment: not verified.

## Manual release checklist
- [ ] Login, refresh, reload and session persistence.
- [ ] MFA challenge: success, incorrect code, lockout and expiry.
- [ ] Run each of the four synthetic attack scenarios and inspect the incident's evidence/reasons and investigator steps.
- [ ] Confirm restriction and approval safeguards; verify rejected actions do not enforce.
- [ ] Submit a verdict and inspect measured learning proof; if scores do not change, UI says “no measurable change”.
- [ ] Verify audit chain passes; tamper with a disposable database copy and verify the check fails.
- [ ] Confirm viewer role cannot access sensitive routes or SOC-room events.
- [ ] Confirm trusted and rogue demo clients behave differently as expected.
- [ ] Capture screenshots for incident evidence, MFA, restriction, approval, learning proof, audit verification, evaluation, and green CI.
- [ ] Run Docker Compose health checks and a demo scenario on a clean machine.

## Incident learning replay frontend (latest update)
- Added a replay section to `src/pages/IncidentResponse.tsx` backed by authenticated API calls; it does not use the page's mock incident array as replay evidence.
- Added `getIncidentLearningReplay()` and its response type to `src/services/mlBackendService.ts`.
- Targeted backend verification: `python -m compileall -q backend` passed; `python -m unittest test_learning_replay test_behavior_learning_profile test_behavior_profiles -q` passed (7 tests).
- Not verified: frontend npm build, lint, Vitest, Docker, dependency audit, full E2E.


### IP indicator canonicalization update (2026-10-19)
- Added canonical matching for IPv4/IPv6 indicator values, including compressed IPv6 and IPv4-mapped IPv6 forms.
- Verification: `python -m compileall -q .` passed; targeted unittest suites (`test_known_bad_scoring`, `test_behavior_learning_profile`, `test_learning_replay`, `test_behavior_profiles`) passed: 12 tests.
- Scope limitation: no CIDR/range matching, third-party reputation feed, or full frontend/build/E2E validation was performed in this update.


### Observed client IP passed into scoring (2026-10-19)
- The real login detection route now passes the transport peer IP (`request.client.host` via `_client_ip`) into `record_signals`, so the canonicalized known-bad IP indicator can affect the login risk score.
- The simulated threat ingestion route also supplies its transport peer IP. Arbitrary `X-Forwarded-For` values are deliberately not trusted; deployments behind a proxy must configure a trusted-proxy strategy before using forwarded IP headers.
- Verification: `python -m compileall -q backend` passed; selected backend security, learning/replay, behavior-profile and risk-ingest suites passed (84 tests). This is not a full project test run. Frontend build, Docker, dependency audit, and full E2E remain unverified.

### Synthetic end-to-end IP risk regression (2026-10-19)
- Added `backend/test_e2e_ip_pipeline.py`: temporary SQLite DB, analyst-confirmed canonical IPv6 indicator, synthetic suspicious-login event, scoring assertion (+25 known-bad IP points), incident evidence/linkage, investigation/response generation, audit-chain verification, and unlisted-IP negative control.
- Verification: Python compilation passed; `test_e2e_ip_pipeline`, `test_known_bad_scoring`, and `test_learning_replay` passed (10 tests).
- Synthetic tests do not demonstrate production detection accuracy. Full backend suite, frontend build/tests, Docker, dependency audit, and deployment remain unverified.


## Verification runner coverage update (2026-10-19)
- `scripts/verify_all.sh` now explicitly includes `test_e2e_ip_pipeline`, `test_known_bad_scoring`, `test_learning_replay`, `test_behavior_learning_profile`, `test_behavior_profiles`, and `test_response_risk_ladder`.
- Attempted full unittest discovery; it exceeded the execution limit and is recorded as inconclusive, not passing. Attempted frontend dependency installation; it timed out, so frontend checks remain unverified.


### Analytics mock-data isolation update (2026-10-19)
- Legacy `src/pages/BehaviorAnalytics.tsx` now re-exports `BehaviorAnalyticsPage` instead of rendering generated demo charts and hard-coded location/deviation values.
- The persisted-event analytics page uses `mlBackendService.getNetworkEvents()` and shows an empty-state message when there are no stored events.
- This removes a misleading fallback path; it does not guarantee that the backend has production telemetry. Frontend build/test execution remains pending.

### Analytics time-window regression coverage (2026-10-19)
- Added unit tests for persisted-event range filtering: inclusive boundaries, malformed timestamps, events outside the selected range, and invalid/reversed ranges.
- The UI page calls the tested helper instead of duplicating timestamp parsing inline.
- Verification actually run: `python -m compileall -q backend`; `bash -n scripts/verify_all.sh`; `cd backend && python -m unittest test_e2e_ip_pipeline test_learning_replay test_behavior_learning_profile test_behavior_profiles -q` (9 passed).
- `npm ci --ignore-scripts --no-audit --no-fund` timed out. Therefore frontend Vitest/build/lint remain unverified; test source is included in the ZIP.

## CI regression coverage update (2026-10-19)
- `.github/workflows/ci.yml` now runs the six newer backend regression modules explicitly, so they are covered by CI independently of the broader legacy suites.
- npm caching is enabled for frontend and audit jobs.
- Local checks: YAML parse passed; backend compilation passed; verification shell syntax passed; selected regression modules passed (19 tests).
- Limitation: the workflow itself has not been run on GitHub in this session; frontend dependency install timed out locally, so frontend build/lint/tests are still not confirmed.


## Threat injection request-context regression fix (2026-10-19)
- Fixed `/api/inject-threat` to accept FastAPI `Request` explicitly before using `_client_ip(request)` for the observed transport peer IP. Previously, valid threat injection reached this call without a `request` parameter and returned HTTP 500.
- Focused verification after the fix: `test_backend_api.BackendApiTests.test_threat_injection_validates_payload_and_runs_models` passed. The preceding 50-test batch had one failure caused by the missing request argument; do not count that batch as passing. Full backend/frontend release checks remain open.

## Threat injection IP provenance regression (2026-10-19)
- Test command: `python -m compileall -q backend` — PASS.
- Test command: `cd backend && python -m unittest test_backend_api.BackendApiTests.test_threat_injection_validates_payload_and_runs_models test_e2e_ip_pipeline test_known_bad_scoring -q` — PASS (8 tests).
- Test confirms `attacker_ip` remains scenario metadata, `observed_source_ip` reflects the transport peer (`testclient` in the test client), and spoofed `X-Forwarded-For` is not used for risk scoring.
- Frontend build/lint/Vitest, complete backend suite, Docker and dependency audits remain unverified.
