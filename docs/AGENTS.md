# TrustNet agent layer

Flow: event -> fused risk -> persistent incident (TN-00001 numbering) -> Investigator -> Response decision ->
backend enforcement or human approval -> notification + audit chain -> analyst verdict -> measured learning.

| Piece | File | Notes |
|---|---|---|
| Investigator | `backend/agents/investigator.py` | Read-only SQLite connection (`PRAGMA query_only`). Five rules: credential_attack, untrusted_device, multi_ip_activity, model_consensus, suspicious_request_pattern. |
| Response | `backend/agents/response.py` | Actions: monitor, notify_analyst, quarantine_device. Quarantine is enforced via the device registry, so existing device-bound tokens get 403. |
| Orchestrator | `backend/agents/orchestrator.py` | Idempotent; re-investigates when login evidence changes (failed logins, IPs, device trust), throttled otherwise (15 s). |
| Learning | `backend/agents/learning.py` | Analyst verdicts adjust rule weights only. Applied only with >= 10 labels AND leave-one-out accuracy not worse than defaults. |
| Notifier | `backend/agents/notifier.py` | Every notification stored; SMTP only if `TRUSTNET_SMTP_HOST` is set, otherwise status `skipped` (never reported as sent). |

## Autonomy safeguards (default: `recommend` = nothing destructive without a human)
Automatic quarantine requires ALL of: kill switch off, `autonomy_mode=auto_contain`, confidence >= `auto_min_confidence`,
verdict likely_malicious, target account not admin/analyst, device present and not already quarantined, hourly cap not
reached, no prior analyst rejection on the incident. Each check is stored on the response record and shown in the UI.
Responses cannot be approved or rejected by the account they target, and an account cannot dismiss, resolve or label an
incident that targets itself (403 + audit entry). The legacy `POST /incidents/{id}/approve` shares the same rules: no
self-approval, and it creates/claims a real approval record before enforcing.

## New endpoints (all under `/api`, JWT + permission checked)
`GET /incidents/{id}/agent`, `POST /incidents/{id}/investigate`, `POST /incidents/{id}/responses/{rid}/approve|reject`,
`POST /incidents/{id}/verdict`, `GET /agents/activity`, `GET /agents/learning`, `GET|PUT /agents/autonomy` (PUT = admin),
`GET /notifications`. WebSocket pushes `agent_activity` events to `/ws/admin`.

## Hardening added
CORS restricted to explicit origins (`TRUSTNET_CORS_ORIGINS`), security headers, `/api/csf/train|score` now require auth,
audit entries for every agent/human response action, validated autonomy settings.

## Not done / known limits
See the end-of-session report: no account-level containment action (failed-login incidents have no device), no external
audit anchoring, learning is rule-weight only and needs >= 10 verdicts, SMTP delivery untested against a real server.
