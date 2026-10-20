# TrustNet AI — Copilot Run Guide

This archive contains the complete TrustNet AI project, including the existing React/Vite security console and the newly integrated interactive UI.

## Quick UI preview

From the `trustnet_all` directory:

```bash
npm ci
npm run dev
```

Open the URL printed by Vite, then visit:

```text
/demo
```

For example: `http://localhost:5173/demo`

The public demo does not require the FastAPI backend. It includes the interactive security graph, attack-chain simulation, signal stream, response plan, approval interaction, and activity feed.

## Full application

Start the backend in one terminal:

```bash
cd backend
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8010
```

Start the frontend in a second terminal from `trustnet_all`:

```bash
npm ci
npm run dev
```

Open `/login` for the authenticated console. Development demo credentials are shown on the login screen when running a development build.

## Dashboard interaction

Once authenticated, use the **COMMAND CENTER** button in the top bar or press **Ctrl + K** to search and jump between the dashboard workspaces.

## Available checks

```bash
npx tsc -p tsconfig.app.json --noEmit
npm run lint
npm test
npm run build
```

The source archive was prepared without `node_modules`, Python virtual environments, databases, or secret `.env` files. Dependencies are restored by the commands above.
