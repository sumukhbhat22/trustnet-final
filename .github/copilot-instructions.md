# TrustNet AI contribution rules

Project: FastAPI + SQLite backend (`backend/`), React/Vite/TypeScript frontend (`src/`), agent layer (`backend/agents/`). Read `docs/STATUS.md`, `docs/AGENTS.md`, and `docs/REQUIREMENT_TRACEABILITY.md` before changing code.

- Preserve the existing architecture and working behavior; inspect implementation and tests before editing.
- Python 3.12 target; backend tests use `unittest`; frontend tests use Vitest.
- Synthetic/fictional data only. Never put real credentials, tokens, or secrets in code, logs, tests, or commits. Never seed demo users in production.
- Do not weaken authentication, authorization, rate limits, audit integrity, approval safeguards, or tests to obtain a pass.
- Irreversible actions must remain pending until recorded human approval. Language-model output may summarize evidence only and may not choose or authorize actions.
- Every state-changing/security-relevant action must be audited.
- Run the relevant tests after each change. Report exact commands and actual output; mark unavailable checks Blocked, never imply they passed.
- Keep `docs/STATUS.md` as the single source of truth; update `docs/AGENTS.md` when agent behavior changes and update the 53-item traceability matrix with test/file evidence.
- Do not commit generated databases, caches, `node_modules`, `dist`, ZIPs, or secrets. Work on a feature branch and do not push directly to main.
