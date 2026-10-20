# TrustNet AI Guardian ML Backend

FastAPI demo backend for TrustNet AI Guardian. It exposes password-based JWT authentication with role permissions, login/device-baseline analysis, request-level network monitoring, risk scoring, incident response, network propagation, and a WebSocket-driven attack simulation.

## Overview

The service initializes its models during startup using **synthetic demo data**:

### **Models Included**

1. **Isolation Forest Anomaly Detection**
   - Detects unusual patterns in user behavior
   - Identifies insider threats and compromised accounts
   - Real-time anomaly scoring

2. **Risk Scoring Engine**
   - Weighted behavioral deviation analysis
   - Multi-dimensional threat assessment
   - Automatic risk level classification (Low/Medium/High/Critical)

3. **Network Propagation Analyzer**
   - Analyzes risk spread through network nodes
   - Identifies critical nodes vulnerable to compromise
   - Attack path detection

4. **Supervised threat classifier**
  - Random Forest + Gradient Boosting ensemble
  - Demo classes: benign, credential theft, session hijack, brute force, and insider threat

5. **Explainability helpers**
  - Fingerprint differences, risk-factor breakdowns, classifier contributors, and propagation summaries

## Architecture

```
backend/
├── main.py                    # Active FastAPI application and routes
├── attack_chain.py            # Six-phase demonstration attack
├── requirements.txt
├── test_backend_api.py        # API integration tests
├── models/
│   ├── optimized_models.py    # Isolation Forest, risk scorer, graph analyzer
│   ├── threat_classifier.py   # RF + Gradient Boosting classifier
│   ├── login_detector.py      # Fingerprints, GeoIP and in-memory baselines
│   ├── security_auth.py       # SQLite users/history/revocations, bcrypt, JWTs and RBAC
│   ├── security_events.py     # Validated events and local hash-chain verification
│   ├── network_topology.py    # Stored users/devices, demo assets and deny-by-default policies
│   ├── network_monitor.py     # Bounded in-memory request window and pattern detectors
│   ├── risk_engine.py         # Explainable behavior/device/network fusion
│   ├── device_registry.py     # Manual trust state
│   ├── incident_store.py      # Incident lifecycle
│   └── explainability.py      # XAI summaries
└── routes/schemas.py          # Pydantic request/response types
```

## Installation

### Prerequisites
- Python 3.10+
- pip or conda

### Setup Steps

1. **Create virtual environment**
  ```powershell
  cd backend
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  ```

2. **Activate virtual environment**
  - Windows PowerShell: `\.venv\Scripts\Activate.ps1`
  - Windows cmd: `.venv\Scripts\activate.bat`
  - macOS/Linux: `source .venv/bin/activate`

3. **Install dependencies**
   ```bash
  python -m pip install -r requirements.txt
   ```

## Running

### Start the Backend Server

```powershell
uvicorn main:app --host 0.0.0.0 --port 8010 --reload
```

Run this command from the backend directory. The frontend defaults to port **8080**, and the backend listens on **8010**. Model training runs at startup, so the health endpoint stays unavailable until both models are ready.

### API Documentation

Once running, visit:
- **Swagger UI**: `http://localhost:8010/docs`
- **OpenAPI JSON**: `http://localhost:8010/openapi.json`

## API Endpoints

### Health Check
```
GET /api/health
```
Reports whether model startup has completed.

### Calculate Risk Score
```
POST /api/risk-score
```
Calculates behavioral risk score for a user based on multiple metrics.

**Request:**
```json
{
  "user_id": "u1",
  "behavior_metrics": {
    "normal_login_time": 9.2,
    "actual_login_time": 19.5,
    "normal_session_duration": 4.5,
    "actual_session_duration": 0.3,
    "normal_data_volume": 120,
    "actual_data_volume": 850,
    "normal_api_calls": 45,
    "actual_api_calls": 312,
    "normal_geo_distance": 0,
    "actual_geo_distance": 9847
  },
  "anomaly_score": 0.85
}
```

### Detect Anomalies
```
POST /api/anomaly-detection
```
Detects anomalies in behavioral records using Isolation Forest.

**Request:**
```json
{
  "records": [
    {"session_duration": 4.2, "data_volume": 110, "api_calls": 48},
    {"session_duration": 0.3, "data_volume": 850, "api_calls": 312}
  ]
}
```

### Analyze Network Propagation
```
POST /api/propagation-analysis
```
Analyzes risk propagation through network topology.

Other active routes: `POST /api/anomaly-detection`, `POST /api/train-anomaly-detector`, `POST /api/batch-risk-analysis`, `POST /api/login`, `GET /api/baselines`, `POST /api/baselines/reset`, `GET /api/live-threat`, `POST /api/live-threat/reset`, `POST /api/inject-threat`, and `POST/GET /api/attack-chain/*`. Admin dashboard events are streamed through `WS /ws/admin`.

### Authentication and RBAC

- `POST /api/auth/login` accepts a username or email, password, and browser fingerprint. Password verification runs before device analysis. Successful device/risk checks return a 30-minute JWT.
- `GET /api/auth/me` returns the active user and permissions; `POST /api/auth/logout` stores the token revocation in SQLite.
- `POST /api/auth/register` creates analyst/viewer users and requires `manage_users` (admin role only). `GET /api/users` and `GET /api/users/{id}/login-history` are also admin-only.
- Protected API requests require `Authorization: Bearer <token>`. Permissions are `admin`: all; `analyst`: dashboard, device management, incident response; `viewer`: dashboard read-only.
- Failed credential attempts are recorded, and five failures in a rolling 15-minute window lock that account for the remainder of the window.

### Network activity

- `GET /api/network/events?ip=...&user_id=...&limit=200` lists retained request records.
- `GET /api/network/anomalies` returns only flagged request patterns; both endpoints support IP/user filters.
- `GET /api/network/topology` builds the graph from stored accounts, devices, active incidents, protected assets, and role policy. `GET /api/protected-assets/{asset_id}` enforces the demo read policy.
- `GET /api/incidents/{id}/events` returns persisted security records correlated to an incident. `GET /api/audit/verify` validates the local event hash chain.
- Every API request is recorded with source IP, authenticated user (when available), route, method, status, and elapsed time. Rules flag over 60 requests/minute per IP/user, 10+ sensitive endpoint requests/minute, a previously unseen IP for an authenticated user, and failed authentication against 5+ distinct users from one IP/minute.
- Anomaly signals contribute 20% of the explainable fused risk score and feed incident creation. The Network Activity dashboard consumes the same bounded in-memory event stream.

## Tests

From the backend directory, run `python -m unittest test_backend_api -v`. From the repository root, run `python test_ml_models.py` for the standalone model smoke test.

## Demo limitations

- Credentials are hard-coded demonstration credentials; this is not production authentication.
- Users, login attempts, JWT revocations, devices, incidents, security events, audit-chain records, risk signals, and login baselines are stored in SQLite. Recent network detector windows are reconstructed from persisted requests/login attempts after restart. Live threat broadcast state and model objects remain process-local; simultaneous worker windows are not transactionally coordinated.
- Demo identities retain the project's legacy credentials, although every password is stored as a bcrypt hash. Newly registered accounts require a 12-character password. Configure `TRUSTNET_JWT_SECRET` with a strong secret in deployments; an unset secret is randomly generated per process and invalidates sessions on restart.
- The browser holds its access token in memory only (not localStorage); reloading requires signing in again. JWT signing uses `TRUSTNET_JWT_SECRET` when configured.
- The middleware observes requests reaching this API process; it is not packet capture or full network/egress monitoring. Client IP uses the direct ASGI peer address; deploy behind a correctly configured trusted proxy before interpreting forwarded client addresses.
- Both models train on generated synthetic examples. Reported metrics measure that generated dataset only; they are not evidence of production detection accuracy.
- GeoIP lookup uses ipinfo.io for public IPs and degrades to `Unknown` if the provider is unavailable.
- The audit chain is stored in the same SQLite database it verifies. SQLite triggers and hashes detect ordinary row edits, but a privileged attacker can rewrite the database and recompute the chain; external immutable anchoring is not implemented.
- Asset authorization is a small demo policy and the protected-asset endpoint returns metadata, not a production application’s real data. RBAC, local rate detection, and this policy are not substitutes for TLS, key management, distributed abuse controls, trusted-proxy configuration, or an independently anchored audit service. Do not expose publicly as-is.

**Request:**
```json
{
  "nodes": [
    {"id": "n1", "label": "Server A", "type": "server", "propagationRisk": 45, ...},
    {"id": "n2", "label": "User 1", "type": "user", "propagationRisk": 30, ...}
  ],
  "edges": [
    {"from": "n1", "to": "n2", "active": true, "attackPath": false}
  ]
}
```

### Batch Risk Analysis
```
POST /api/batch-risk-analysis
```
Analyzes multiple users in a single request.

## Machine Learning Details

### Isolation Forest
- **Algorithm**: Isolation Forest (scikit-learn)
- **Purpose**: Identify outliers/anomalies in behavioral data
- **Training**: Trained on synthetic normal behavior patterns
- **Output**: Anomaly score (0-1), where higher = more anomalous

### Risk Scoring
- **Weights Applied**:
  - Login time deviation: 15%
  - Session duration deviation: 12%
  - Data volume deviation: 20%
  - API calls deviation: 18%
  - Geographic distance deviation: 25%
  - Anomaly score: 10%

- **Risk Levels**:
  - Safe: 0-10
  - Low: 10-30
  - Medium: 30-50
  - High: 50-75
  - Critical: 75-100

### Network Propagation
- Calculates risk spread based on:
  - Node risk score
  - Neighbor influence
  - Active attack paths

## Frontend Integration

The React frontend communicates with the backend via:

1. **ML Backend Service** (`src/services/mlBackendService.ts`)
   - Handles all API calls to the backend
   - Includes error handling and retries

2. **useMLBackend Hook** (`src/hooks/useMLBackend.ts`)
   - React hook for backend integration
   - Auto-detects backend availability
   - Provides async ML operations

### Usage in Components

```typescript
import { useMLBackend } from '@/hooks/useMLBackend';

const MyComponent = () => {
  const { isConnected, calculateRisk } = useMLBackend();

  const analyzeUser = async (userId: string, metrics: any) => {
    const result = await calculateRisk(userId, metrics);
    console.log('Risk Score:', result?.overall_score);
  };

  return (
    <div>
      Backend: {isConnected ? '✓ Connected' : '⚠ Disconnected'}
    </div>
  );
};
```

## Performance

- **Anomaly Detection**: ~10-50ms per record
- **Risk Scoring**: ~5ms per user
- **Propagation Analysis**: ~100-500ms depending on network size
- **Batch Operations**: Optimized for handling 100+ records

## Production Considerations

### Model Training
For production, you should train models on actual data:

```python
from backend.models.ml_models import anomaly_detector
import numpy as np

# Your historical data
historical_data = np.array([...])  # (n_samples, n_features)
feature_names = ['feature1', 'feature2', ...]

result = anomaly_detector.train(historical_data, feature_names)
anomaly_detector.save('path/to/model.pkl')
```

### Security
- Enable HTTPS in production
- Restrict CORS origins
- Implement authentication
- Rate limit endpoints
- Use environment variables for configuration

### Scaling
- Use containerization (Docker)
- Deploy multiple backend instances
- Load balance with Nginx or similar
- Consider async job queues for batch operations

## Troubleshooting

### Backend not connecting
1. Ensure backend is running: `http://localhost:8000/docs`
2. Check frontend environment variable: `REACT_APP_ML_API_URL`
3. Verify CORS settings in `main.py`

### Memory issues with large datasets
- Reduce batch size
- Process data in chunks
- Use stream processing for real-time analysis

### Model accuracy concerns
- Retrain models with more data
- Tune contamination parameter in IsolationForest
- Add feature engineering pipeline

## Technologies

- **FastAPI**: Modern Python web framework
- **scikit-learn**: Machine learning library
- **NumPy/Pandas**: Data processing
- **Pydantic**: Data validation
- **Uvicorn**: ASGI server

## License

Same as TrustNet AI Guardian main project

## Support

For issues or questions, refer to the main TrustNet documentation.
