/**
 * ML Backend API Service
 * Communicates with the Python FastAPI backend for ML model predictions
 */
import type { DeviceFingerprint } from "@/services/fingerprintService";
import { getAuthSession, setAuthSession, type SessionUser, type UserRole } from "@/services/authSession";

// Dynamically use the current page's hostname so it works from any device on the network
const _host = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
const ML_API_BASE_URL = (import.meta.env.VITE_ML_API_URL as string) || `http://${_host}:8010/api`;
const WS_BASE_URL = ML_API_BASE_URL.replace(/\/api$/, '').replace(/^http/, 'ws');

/** Loosely-typed JSON object returned by the backend (shape checked by callers). */
export type ApiJson = Record<string, unknown>;

/** Minimal shape of POST /auth/login; pages may pass their own narrower type to login<T>(). */
export interface LoginApiResponse {
  login_status: string;
  message?: string;
  username?: string;
  access_token?: string;
  user?: SessionUser;
  [key: string]: unknown;
}

export interface IncidentTransitionResult {
  incident: unknown;
  device?: { label: string } | null;
  [key: string]: unknown;
}

export interface BaselineEntry {
  device_type?: string;
  location?: string;
  normal_login_hour?: number;
  created_at?: string;
}

export interface RiskScorePayload {
  user_id: string;
  behavior_metrics: {
    normal_login_time: number;
    actual_login_time: number;
    normal_session_duration: number;
    actual_session_duration: number;
    normal_data_volume: number;
    actual_data_volume: number;
    normal_api_calls: number;
    actual_api_calls: number;
    normal_geo_distance: number;
    actual_geo_distance: number;
  };
  anomaly_score: number;
}

export interface RiskScoreResponse {
  overall_score: number;
  threat_level: "safe" | "low" | "medium" | "high" | "critical";
  deviations: Record<string, number>;
  recommendation: string;
}

interface AnomalyRecord {
  [key: string]: number | boolean | string;
  is_anomaly: boolean;
  anomaly_score: number;
  risk_level: string;
}

export interface PropagationNode {
  id: string;
  label: string;
  type: string;
  x: number;
  y: number;
  compromised: boolean;
  propagationRisk: number;
}

export interface PropagationEdge {
  from: string;
  to: string;
  active: boolean;
  attackPath: boolean;
}

export interface PropagationNodeAnalysis {
  node_id: string;
  node_label: string;
  propagation_risk: number;
  criticality: 'low' | 'medium' | 'high' | 'critical';
}

export interface PropagationAnalysisResult {
  total_network_risk: number;
  critical_count: number;
  critical_nodes: PropagationNodeAnalysis[];
  all_nodes: PropagationNodeAnalysis[];
}

export interface NetworkTopology {
  nodes: PropagationNode[];
  edges: PropagationEdge[];
  assets: Array<{
    asset_id: string;
    label: string;
    asset_type: string;
    criticality: number;
    classification: string;
  }>;
  policy_default: 'deny';
}

export interface RegisteredDevice {
  device_id: string;
  user_id: string;
  fingerprint_hash: string;
  first_seen: string;
  last_seen: string;
  trust_status: 'trusted' | 'unknown' | 'flagged' | 'revoked';
  label: string;
  quarantined: boolean;
}

export interface DashboardSummary {
  generated_at: string;
  overall_risk: { average: number; maximum: number; users_scored: number };
  active_incident_count: number;
  network_anomalies: number;
  device_counts: { total: number; trusted: number; unknown: number; flagged: number };
  recent_incidents: BackendIncident[];
  data_scope: string;
  // Authoritative contract aliases (same values as the fields above)
  systemRisk?: number;
  avgUserRisk?: number;
  openIncidents?: number;
  anomalies?: number;
  trustedDevices?: number;
  devicesToReview?: number;
  networkAnomalies?: number;
  mlStatus?: 'available' | 'initializing' | string;
  dataSource?: string;
}

export interface RiskPolicyThreshold {
  restrict_threshold: number;
  minimum: number;
  maximum: number;
}

export interface NetworkEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  user_id: string | null;
  endpoint: string;
  method: string;
  status_code: number | null;
  response_time_ms: number | null;
  anomaly_types: string[];
  evidence?: string | null;
}

export interface AuthenticationEvent {
  id: string;
  timestamp: string;
  event_type: "authentication_attempt";
  outcome: "SUCCESS" | "FAILURE";
  username: string;
  source_ip: string | null;
  reason: string | null;
  event_source: "LIVE" | "LIVE_TEST";
  status_code: number | null;
}

export interface DemoAccountStatus {
  account: { id: string; email: string; role: string; is_active: boolean } | null;
  restriction: AccountRestriction | null;
  restriction_history: AccountRestriction[];
}

export interface DemoLoginResult {
  httpStatus: number;
  body: {
    login_status?: string;
    message?: string;
    authentication_event_id?: string;
    authentication_event_timestamp?: string;
    login_attempt_reason?: string;
    attacker_ip?: string;
  };
}

export interface CsiSimulationSample {
  sample_id: string;
  timestamp: string;
  scenario: "MATCH" | "MISMATCH";
  reference_fingerprint: number[];
  test_fingerprint: number[];
  similarity_score: number;
  result: "MATCH" | "MISMATCH";
  explanation: string;
  simulation_only: true;
  hardware_connected: false;
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  user_id: string | null;
  ip_address: string | null;
  request_path: string;
  http_method: string;
  status_code: number | null;
  event_category: string;
  risk_indicators: string[];
  event_payload: Record<string, unknown>;
}

export interface BackendIncident {
  id: string;
  title: string;
  severity: string;
  user_id: string;
  device_id: string | null;
  risk_score: number;
  status: 'open' | 'investigating' | 'resolved' | 'dismissed';
  created_at: string;
  updated_at: string;
  evidence: string[];
  response_action: string | null;
  risk_breakdown: Record<string, unknown>;
  incident_label?: string | null;
  incident_number?: number | null;
}

export interface AgentRuleResult {
  rule_id: string;
  name: string;
  fired: boolean;
  weight: number;
  detail: string;
  evidence: string[];
}

export interface AgentAttackType {
  type: 'stolen_credentials' | 'brute_force' | 'data_exfiltration' | 'after_hours_insider' | 'unknown';
  confidence: number;
  recommended_action: string;
  method: 'deterministic_evidence_rules';
  evidence_summary: { failed_logins: number; successful_logins: number; sensitive_events: number; fired_rules: string[] };
}

export interface AgentInvestigation {
  verdict: 'likely_malicious' | 'suspicious' | 'inconclusive';
  confidence: number;
  attack_type?: AgentAttackType;
  fired_rules: string[];
  rules: AgentRuleResult[];
  investigated_at: string;
  read_only: boolean;
}

export interface AgentSafeguard {
  name: string;
  passed: boolean;
  detail: string;
}

export interface AgentResponseAction {
  id: string;
  incident_id: string;
  action: string;
  target: string | null;
  mode: string;
  status: 'proposed' | 'pending_approval' | 'executing' | 'executed' | 'rejected' | 'blocked' | 'failed' | 'expired';
  rationale: string;
  safeguards: AgentSafeguard[];
  decided_by: string | null;
  executed_at: string | null;
  expires_at?: string | null;
}

export interface AccountRestriction {
  id: string;
  user_id: string;
  status: 'active' | 'expired' | 'released';
  incident_id: string | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  released_by: string | null;
  released_at?: string | null;
  reason?: string | null;
}

export interface AgentActivityEntry {
  id: string;
  incident_id: string | null;
  agent: string;
  action: string;
  summary: string;
  created_at: string;
}

export interface AgentNotification {
  id: string;
  recipient: string;
  subject: string;
  status: 'queued' | 'sent' | 'failed' | 'skipped';
  error: string | null;
}

export interface AgentIncidentView {
  incident_id: string;
  investigation: AgentInvestigation | null;
  responses: AgentResponseAction[];
  feedback: Array<{ id: string; verdict: string; notes: string; analyst_id: string; created_at: string }>;
  activity: AgentActivityEntry[];
  notifications: AgentNotification[];
}

export interface AgentLearningResult {
  labeled_incidents: number;
  min_labels_required: number;
  default_accuracy: number | null;
  learned_accuracy: number | null;
  accuracy_delta: number | null;
  applied: boolean;
  status: 'insufficient_data' | 'applied' | 'rejected';
  note?: string;
  active_weights: Record<string, number>;
}

export interface AgentAutonomySettings {
  autonomy_mode: 'off' | 'recommend' | 'auto_contain';
  kill_switch: boolean;
  auto_max_per_hour: number;
  auto_min_confidence: number;
}

export type WsState = 'live' | 'reconnecting' | 'offline';

export interface ProtectedAsset {
  asset_id: string;
  label: string;
  asset_type: string;
  criticality: number;
  classification: string;
}

export interface RiskPolicy {
  version: number;
  weights: Record<string, number>;
  sensitivity: number;
  device_trust_enabled: boolean;
  geo_enabled: boolean;
  learning_rate: number;
  restrict_threshold?: number;
  ranges?: { sensitivity: [number, number]; learning_rate: [number, number]; max_weight_sum: number };
}

export interface VerdictScoreEffect {
  incident_id: string;
  user_id: string;
  verdict: string;
  score_before: number;
  score_after: number;
  user_adjustment: number;
  policy_version: number;
  mechanism: string;
}

export interface IncidentLearningReplay {
  incident_id: string;
  status: 'recorded' | 'no_feedback_effect' | string;
  incident_score: number | null;
  verdict: string | null;
  score_before: number | null;
  score_after: number | null;
  score_delta: number | null;
  policy_version: string | number | null;
  user_adjustment?: number | null;
  message: string;
  learning_type: string;
  profile?: Record<string, unknown> | null;
}

class MLBackendService {
  private wsState: WsState = 'offline';
  private wsStateListeners: Array<(state: WsState, lastMessageAt: number | null) => void> = [];
  private wsAttempts = 0;
  private wsLastMessageAt: number | null = null;
  private baseUrl: string;
  private ws: WebSocket | null = null;
  private wsListeners: Array<(data: ApiJson) => void> = [];
  private wsReconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private wsTicketPending = false;

  constructor() {
    this.baseUrl = ML_API_BASE_URL;
  }

  private refreshInFlight: Promise<string | null> | null = null;

  /**
   * Single-flight refresh. Concurrent 401s share one /auth/refresh call; the backend rotates the
   * refresh cookie on every call and treats reuse of a consumed token as theft (revokes the family),
   * so parallel refreshes would otherwise sign the user out.
   */
  private refreshAccessToken(): Promise<string | null> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = (async () => {
        try {
          const refreshed = await fetch(`${this.baseUrl}/auth/refresh`, { method: "POST", credentials: "include" });
          if (!refreshed.ok) return null;
          const body = await refreshed.json();
          return typeof body.access_token === "string" && body.access_token ? body.access_token : null;
        } finally {
          this.refreshInFlight = null;
        }
      })();
    }
    return this.refreshInFlight;
  }

  private restoreInFlight: Promise<boolean> | null = null;

  /**
   * Restore a signed-in session after a page reload using the HttpOnly refresh cookie.
   * Memory-only: nothing is written to browser storage. Returns false when there is no valid cookie.
   * Never throws and never retries, so it cannot loop.
   */
  restoreSession(): Promise<boolean> {
    if (getAuthSession()?.token) return Promise.resolve(true);
    if (!this.restoreInFlight) {
      this.restoreInFlight = (async () => {
        try {
          const token = await this.refreshAccessToken();
          if (!token) return false;
          const me = await fetch(`${this.baseUrl}/auth/me`, {
            headers: { Authorization: `Bearer ${token}` },
            credentials: "include",
          });
          if (!me.ok) return false;
          const body = await me.json();
          if (!body?.user || !Array.isArray(body.permissions)) return false;
          setAuthSession({ token, user: body.user, permissions: body.permissions });
          return true;
        } catch {
          return false;
        } finally {
          this.restoreInFlight = null;
        }
      })();
    }
    return this.restoreInFlight;
  }

  private async request(input: RequestInfo | URL, init: RequestInit = {}, allowRefresh = true): Promise<Response> {
    const headers = new Headers(init.headers);
    const session = getAuthSession();
    const token = session?.token;
    if (token) headers.set("Authorization", `Bearer ${token}`);
    // Required for the API's HttpOnly refresh cookie when the frontend and API use different local ports.
    let response = await fetch(input, { ...init, headers, credentials: "include" });
    const path = String(input);
    if (response.status === 401 && allowRefresh && session && !path.includes("/auth/refresh") && !path.includes("/auth/login") && !path.includes("/auth/logout")) {
      try {
        const newToken = await this.refreshAccessToken();
        if (newToken) {
          setAuthSession({ ...(getAuthSession() ?? session), token: newToken });
          const retryHeaders = new Headers(init.headers);
          retryHeaders.set("Authorization", `Bearer ${newToken}`);
          // Single retry only: the retried request is never refreshed again, so no loops.
          response = await fetch(input, { ...init, headers: retryHeaders, credentials: "include" });
        }
      } catch {
        // Preserve the original 401; callers decide whether to sign out or show an error.
      }
    }
    if (response.status === 403 && typeof window !== "undefined" && !path.includes("/mfa/")) {
      const body = await response.clone().json().catch(() => null);
      if (body?.detail?.code === "MFA_REQUIRED") {
        window.dispatchEvent(new CustomEvent("trustnet:mfa-required"));
      }
    }
    return response;
  }

  requestMfaChallenge(): Promise<{ status: string; expires_in_seconds: number; delivery: string; demo_code?: string }> {
    return this.agentJson('/mfa/challenge', { method: 'POST' });
  }

  verifyMfaCode(code: string): Promise<{ status: string; verified_at: string }> {
    return this.agentJson('/mfa/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) });
  }

  getTotpStatus(): Promise<{ enrolled: boolean; [key: string]: unknown }> {
    return this.agentJson('/mfa/totp/status');
  }

  verifyTotpLogin(code: string): Promise<{ status: string; method: string }> {
    return this.agentJson('/mfa/totp/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) });
  }

  // ── WebSocket for instant threat push ──

  async connectWebSocket(): Promise<void> {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return; // Already connected
    }
    const token = getAuthSession()?.token;
    if (!token || this.wsTicketPending) return;
    if (this.wsAttempts > 0) this.setWsState('reconnecting');
    this.wsTicketPending = true;
    try {
      const ticketResponse = await this.request(`${this.baseUrl}/auth/ws-ticket`, { method: "POST" });
      if (!ticketResponse.ok) throw new Error(`Dashboard ticket request failed: ${ticketResponse.status}`);
      const { ticket } = await ticketResponse.json();
      if (getAuthSession()?.token !== token || this.ws) return;
      const wsUrl = `${WS_BASE_URL}/ws/admin?ticket=${encodeURIComponent(ticket)}`;
      console.log(`[WS] Connecting to ${WS_BASE_URL}/ws/admin with one-use ticket`);
      this.ws = new WebSocket(wsUrl);
    } catch (error) {
      console.warn("[WS] Could not authorize dashboard stream", error);
      this.scheduleWsReconnect();
    } finally {
      this.wsTicketPending = false;
    }

    if (!this.ws) return;

    this.ws.onopen = () => {
      console.log('[WS] Connected — dashboard will receive instant threat events');
      this.wsAttempts = 0;
      this.setWsState('live');
      // Keep alive ping every 30s
      const ping = setInterval(() => {
        if (this.ws?.readyState === WebSocket.OPEN) {
          this.ws.send('ping');
        } else {
          clearInterval(ping);
        }
      }, 30000);
    };

    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        this.wsLastMessageAt = Date.now();
        if (data.type === 'pong') { this.notifyWsState(); return; } // heartbeat reply
        // Notify all listeners
        this.wsListeners.forEach(fn => fn(data));
      } catch { /* ignore parse errors */ }
    };

    this.ws.onclose = () => {
      console.log('[WS] Disconnected');
      this.ws = null;
      this.scheduleWsReconnect();
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  onThreatEvent(callback: (data: ApiJson) => void): () => void {
    this.wsListeners.push(callback);
    // Return unsubscribe function
    return () => {
      this.wsListeners = this.wsListeners.filter(fn => fn !== callback);
    };
  }

  disconnectWebSocket(): void {
    if (this.wsReconnectTimer) clearTimeout(this.wsReconnectTimer);
    this.wsAttempts = 0;
    this.ws?.close();
    this.ws = null;
    this.setWsState('offline');
  }

  /** Exponential backoff (1s, 2s, 4s ... capped at 30s) with jitter; stays 'reconnecting' until the socket opens. */
  private scheduleWsReconnect(): void {
    this.ws = null;
    if (!getAuthSession()?.token) { this.setWsState('offline'); return; }
    this.wsAttempts += 1;
    this.setWsState(this.wsAttempts >= 6 ? 'offline' : 'reconnecting');
    const delay = Math.min(30000, 1000 * 2 ** (this.wsAttempts - 1)) + Math.random() * 250;
    if (this.wsReconnectTimer) clearTimeout(this.wsReconnectTimer);
    this.wsReconnectTimer = setTimeout(() => void this.connectWebSocket(), delay);
  }

  private setWsState(state: WsState): void {
    this.wsState = state;
    this.notifyWsState();
  }

  private notifyWsState(): void {
    this.wsStateListeners.forEach((fn) => fn(this.wsState, this.wsLastMessageAt));
  }

  getWsState(): WsState { return this.wsState; }

  onWsState(callback: (state: WsState, lastMessageAt: number | null) => void): () => void {
    this.wsStateListeners.push(callback);
    callback(this.wsState, this.wsLastMessageAt);
    return () => { this.wsStateListeners = this.wsStateListeners.filter((fn) => fn !== callback); };
  }

  async getRiskPolicy(): Promise<RiskPolicy> {
    const response = await this.request(`${this.baseUrl}/risk-policy`);
    if (!response.ok) throw new Error(`Failed to fetch risk policy: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async updateRiskPolicy(update: Partial<Pick<RiskPolicy, 'weights' | 'sensitivity' | 'device_trust_enabled' | 'geo_enabled' | 'learning_rate'>>): Promise<RiskPolicy> {
    const response = await this.request(`${this.baseUrl}/risk-policy`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(update),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(typeof detail?.detail === 'string' ? detail.detail : `Risk policy update failed: ${response.status}`);
    }
    return response.json();
  }

  /**
   * Health check endpoint
   */
  async healthCheck(): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/health`);
      if (!response.ok) throw new Error("Backend health check failed");
      const health = await response.json();
      if (health.status !== "healthy") {
        throw new Error(health.message || "ML backend is not ready yet.");
      }
      return health;
    } catch (error) {
      console.error("Health check error:", error);
      throw error;
    }
  }

  /**
   * Calculate risk score for a user
   */
  async calculateRiskScore(payload: RiskScorePayload): Promise<RiskScoreResponse> {
    try {
      const response = await this.request(`${this.baseUrl}/risk-score`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Risk score calculation failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Risk score calculation error:", error);
      throw error;
    }
  }

  /**
   * Detect anomalies in behavioral records
   */
  async detectAnomalies(records: Record<string, number>[]): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/anomaly-detection`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ records }),
      });

      if (!response.ok) {
        throw new Error(`Anomaly detection failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Anomaly detection error:", error);
      throw error;
    }
  }

  /**
   * Analyze network propagation risks
   */
  async analyzePropagation(
    nodes: PropagationNode[],
    edges: PropagationEdge[]
  ): Promise<PropagationAnalysisResult> {
    try {
      const response = await this.request(`${this.baseUrl}/propagation-analysis`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ nodes, edges }),
      });

      if (!response.ok) {
        throw new Error(`Propagation analysis failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Propagation analysis error:", error);
      throw error;
    }
  }

  /**
   * Train the anomaly detector with historical data
   */
  async trainAnomalyDetector(data: number[][], features: string[]): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/train-anomaly-detector`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ data, features }),
      });

      if (!response.ok) {
        throw new Error(`Model training failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Training error:", error);
      throw error;
    }
  }

  /**
   * Batch risk analysis for multiple users
   */
  async batchRiskAnalysis(usersData: ApiJson[]): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/batch-risk-analysis`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(usersData),
      });

      if (!response.ok) {
        throw new Error(`Batch analysis failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Batch analysis error:", error);
      throw error;
    }
  }

  /**
   * Check if backend is available
   */
  async isBackendAvailable(): Promise<boolean> {
    try {
      await this.healthCheck();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Poll live threat feed (for real-time attack demo)
   */
  async getLiveThreat(): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/live-threat`);
      if (!response.ok) throw new Error("Failed to fetch live threat");
      return await response.json();
    } catch (error) {
      return null;
    }
  }

  /**
   * Reset live threat state
   */
  async resetLiveThreat(): Promise<void> {
    try {
      await this.request(`${this.baseUrl}/live-threat/reset`, { method: "POST" });
    } catch {
      // ignore
    }
  }

  /**
   * Real login — sends device fingerprint to backend.
   * Backend does GeoIP, baseline comparison, ML analysis, and pushes result via WS.
   */
  async login<T = LoginApiResponse>(username: string, password: string, fingerprint: DeviceFingerprint, fingerprintId?: string): Promise<T> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      const response = await this.request(`${this.baseUrl}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, fingerprint, fingerprint_id: fingerprintId }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (!response.ok) {
        const detail = await response.json().catch(() => null);
        throw new Error(detail?.detail || `Login failed: ${response.status} ${response.statusText}`);
      }
      const result = await response.json();
      if (result.login_status === "allowed" && result.access_token && result.user) {
        setAuthSession({ token: result.access_token, user: result.user as SessionUser, permissions: [] });
        const verifiedSession = await this.getAuthMe();
        setAuthSession({ token: result.access_token, user: verifiedSession.user, permissions: verifiedSession.permissions });
      }
      return result as T;
    } catch (error: unknown) {
      if (error instanceof Error && error.name === 'AbortError') {
        console.error("Login request timed out");
        throw new Error('Login request timed out. Please try again.');
      }
      console.error("Login detection error:", error);
      throw error;
    }
  }

  /**
   * Get stored baselines for admin view
   */
  async getBaselines(): Promise<{ baselines: Record<string, BaselineEntry>; count: number }> {
    const response = await this.request(`${this.baseUrl}/baselines`);
    if (!response.ok) {
      throw new Error(`Failed to fetch baselines: ${response.status} ${response.statusText}`);
    }
    const result = await response.json();
    if (!result || typeof result.baselines !== 'object' || typeof result.count !== 'number') {
      throw new Error('Backend returned an invalid baseline response.');
    }
    return result;
  }

  async getDevices(userId?: string): Promise<{ devices: RegisteredDevice[]; count: number }> {
    const path = userId ? `/devices/${encodeURIComponent(userId)}` : '/devices';
    const response = await this.request(`${this.baseUrl}${path}`);
    if (!response.ok) throw new Error(`Failed to fetch devices: ${response.status} ${response.statusText}`);
    return await response.json();
  }

  async trustDevice(deviceId: string): Promise<ApiJson> {
    const response = await this.request(`${this.baseUrl}/devices/${encodeURIComponent(deviceId)}/trust`, { method: 'POST' });
    if (!response.ok) throw new Error(`Failed to trust device: ${response.status} ${response.statusText}`);
    return await response.json();
  }

  async getUserRisk(userId: string): Promise<ApiJson> {
    const response = await this.request(`${this.baseUrl}/risk/${encodeURIComponent(userId)}`);
    if (!response.ok) throw new Error(`Failed to fetch user risk: ${response.status} ${response.statusText}`);
    return await response.json();
  }

  async getIncidents(status?: string): Promise<{ incidents: BackendIncident[]; count: number }> {
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    const response = await this.request(`${this.baseUrl}/incidents${query}`);
    if (!response.ok) throw new Error(`Failed to fetch incidents: ${response.status} ${response.statusText}`);
    return await response.json();
  }

  async getIncidentLearningReplay(incidentId: string): Promise<IncidentLearningReplay> {
    const response = await this.request(`${this.baseUrl}/incidents/${encodeURIComponent(incidentId)}/learning-replay`);
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.detail || `Failed to fetch learning replay: ${response.status} ${response.statusText}`);
    }
    return response.json();
  }

  async getIncident(incidentId: string): Promise<BackendIncident> {
    const response = await this.request(`${this.baseUrl}/incidents/${encodeURIComponent(incidentId)}`);
    if (!response.ok) throw new Error(`Failed to fetch incident: ${response.status} ${response.statusText}`);
    return await response.json();
  }

  async getIncidentEvents(incidentId: string): Promise<{ events: SecurityEvent[]; count: number }> {
    const response = await this.request(`${this.baseUrl}/incidents/${encodeURIComponent(incidentId)}/events`);
    if (!response.ok) throw new Error(`Failed to fetch incident events: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async transitionIncident(incidentId: string, action: 'approve' | 'dismiss' | 'escalate' | 'resolve'): Promise<IncidentTransitionResult> {
    const response = await this.request(`${this.baseUrl}/incidents/${encodeURIComponent(incidentId)}/${action}`, { method: 'POST' });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.detail || `Incident action failed: ${response.status} ${response.statusText}`);
    }
    return await response.json();
  }

  private async agentJson<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await this.request(`${this.baseUrl}${path}`, init);
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      const message = typeof detail?.detail === 'string' ? detail.detail : (detail?.detail?.message || detail?.detail?.code || `Request failed: ${response.status} ${response.statusText}`);
      throw new Error(message);
    }
    return await response.json();
  }

  listAssets(): Promise<{ assets: ProtectedAsset[]; range: [number, number] }> {
    return this.agentJson('/assets');
  }

  setAssetCriticality(assetId: string, criticality: number): Promise<{ asset_id: string; previous: number; criticality: number; changed: boolean }> {
    return this.agentJson(`/assets/${encodeURIComponent(assetId)}/criticality`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ criticality }),
    });
  }

  /** Downloads the incident PDF through the authenticated request wrapper (bearer token is never put in a URL). */
  async downloadIncidentReport(incidentId: string): Promise<void> {
    const response = await this.request(`${this.baseUrl}/incidents/${encodeURIComponent(incidentId)}/report.pdf`);
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(typeof detail?.detail === 'string' ? detail.detail : `Report export failed: ${response.status}`);
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = `trustnet-incident-${incidentId}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  getIncidentAgentView(incidentId: string): Promise<AgentIncidentView> {
    return this.agentJson(`/incidents/${encodeURIComponent(incidentId)}/agent`);
  }

  reinvestigateIncident(incidentId: string): Promise<{ view: AgentIncidentView }> {
    return this.agentJson(`/incidents/${encodeURIComponent(incidentId)}/investigate`, { method: 'POST' });
  }

  decideAgentResponse(incidentId: string, actionId: string, decision: "approve" | "reject"): Promise<unknown> {
    return this.agentJson(`/incidents/${encodeURIComponent(incidentId)}/responses/${encodeURIComponent(actionId)}/${decision}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
  }

  submitIncidentVerdict(incidentId: string, verdict: 'true_positive' | 'false_positive', notes = ''): Promise<{ learning: AgentLearningResult; duplicate?: boolean; score_effect?: VerdictScoreEffect | null }> {
    return this.agentJson(`/incidents/${encodeURIComponent(incidentId)}/verdict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict, notes }),
    });
  }

  getAgentLearning(): Promise<AgentLearningResult> {
    return this.agentJson('/agents/learning');
  }

  verifyAuditChain(): Promise<{ valid: boolean; checked: number; broken_event_id?: string | null; reason?: string; untracked_event_count?: number; head_hash?: string }> {
    return this.agentJson('/audit/verify');
  }

  replayDemoScenario(scenarioId: string): Promise<{ status: string; scenario_id: string; scenario_title: string; synthetic_only: boolean; risk: { score: number; level: string }; incident: BackendIncident | null; notice: string }> {
    return this.agentJson(`/demo/scenarios/${encodeURIComponent(scenarioId)}/replay`, { method: 'POST' });
  }

  resetDemo(): Promise<{ status: string; message: string; preserved: string[] }> {
    return this.agentJson('/demo/reset', { method: 'POST' });
  }

  getAgentActivity(limit = 20): Promise<{ activity: AgentActivityEntry[] }> {
    return this.agentJson(`/agents/activity?limit=${limit}`);
  }

  getUnreadNotificationCount(): Promise<{ unread_count: number }> {
    return this.agentJson('/notifications/unread-count');
  }

  markNotificationRead(notificationId?: string): Promise<{ marked_read: number; unread_count: number }> {
    const path = notificationId ? `/notifications/${encodeURIComponent(notificationId)}/read` : '/notifications/read-all';
    return this.agentJson(path, { method: 'POST' });
  }

  getAccountRestrictions(userId?: string): Promise<{ restrictions: AccountRestriction[] }> {
    return this.agentJson(`/account-restrictions${userId ? `?user_id=${encodeURIComponent(userId)}` : ''}`);
  }

  releaseAccountRestriction(restrictionId: string): Promise<{ restriction: AccountRestriction }> {
    return this.agentJson(`/account-restrictions/${encodeURIComponent(restrictionId)}/release`, { method: 'POST' });
  }

  getAgentAutonomy(): Promise<AgentAutonomySettings> {
    return this.agentJson('/agents/autonomy');
  }

  async getDashboardSummary(): Promise<DashboardSummary> {
    const response = await this.request(`${this.baseUrl}/dashboard/summary`);
    if (!response.ok) throw new Error(`Failed to fetch dashboard summary: ${response.status} ${response.statusText}`);
    return await response.json();
  }

  async getRestrictThreshold(): Promise<RiskPolicyThreshold> {
    const response = await this.request(`${this.baseUrl}/policies/restrict-threshold`);
    if (!response.ok) throw new Error(`Failed to fetch risk policy: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async setRestrictThreshold(restrictThreshold: number): Promise<RiskPolicyThreshold> {
    const response = await this.request(`${this.baseUrl}/policies/restrict-threshold`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ restrict_threshold: restrictThreshold }),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.detail || `Failed to update risk policy: ${response.status}`);
    }
    return response.json();
  }

  async getNetworkEvents(filters: { ip?: string; userId?: string; limit?: number } = {}): Promise<{ events: NetworkEvent[]; count: number }> {
    const query = new URLSearchParams();
    if (filters.ip) query.set("ip", filters.ip);
    if (filters.userId) query.set("user_id", filters.userId);
    if (filters.limit) query.set("limit", String(filters.limit));
    const response = await this.request(`${this.baseUrl}/network/events?${query}`);
    if (!response.ok) throw new Error(`Failed to fetch network events: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async getAuthenticationEvents(limit = 100): Promise<{ events: AuthenticationEvent[]; count: number; data_scope: string }> {
    const response = await this.request(`${this.baseUrl}/auth/events?limit=${limit}`);
    if (!response.ok) throw new Error(`Failed to fetch authentication events: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async submitDemoLogin(password: string, fingerprint: DeviceFingerprint, fingerprintId: string): Promise<DemoLoginResult> {
    const response = await fetch(`${this.baseUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "omit",
      body: JSON.stringify({
        username: "trustnet-demo",
        password,
        fingerprint,
        fingerprint_id: fingerprintId,
      }),
    });
    const rawBody: unknown = await response.json().catch(() => null);
    const result = rawBody && typeof rawBody === "object" && !Array.isArray(rawBody)
      ? rawBody as Record<string, unknown>
      : {};
    const body = {
      login_status: typeof result.login_status === "string" ? result.login_status : undefined,
      message: typeof result.message === "string" ? result.message : undefined,
      authentication_event_id: typeof result.authentication_event_id === "string" ? result.authentication_event_id : undefined,
      authentication_event_timestamp: typeof result.authentication_event_timestamp === "string" ? result.authentication_event_timestamp : undefined,
      login_attempt_reason: typeof result.login_attempt_reason === "string" ? result.login_attempt_reason : undefined,
      attacker_ip: typeof result.attacker_ip === "string" ? result.attacker_ip : undefined,
    };
    return { httpStatus: response.status, body };
  }

  async getDemoAccountStatus(): Promise<DemoAccountStatus> {
    const response = await this.request(`${this.baseUrl}/demo/account`);
    if (!response.ok) throw new Error(`Failed to fetch demo account status: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async setupDemoAccount(password: string): Promise<void> {
    const response = await this.request(`${this.baseUrl}/demo/account/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      throw new Error(body?.detail || `Failed to initialize demo account: ${response.status}`);
    }
  }

  async restrictDemoAccount(): Promise<AccountRestriction> {
    const response = await this.request(`${this.baseUrl}/demo/account/restrict`, { method: "POST" });
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.detail || `Failed to restrict demo account: ${response.status}`);
    return body.restriction;
  }

  async releaseDemoAccount(): Promise<AccountRestriction> {
    const response = await this.request(`${this.baseUrl}/demo/account/release`, { method: "POST" });
    const body = await response.json().catch(() => null);
    if (!response.ok) throw new Error(body?.detail || `Failed to release demo account: ${response.status}`);
    return body.restriction;
  }

  async getCsiSimulationSample(scenario: "match" | "mismatch"): Promise<CsiSimulationSample> {
    const response = await this.request(`${this.baseUrl}/csi/simulation/sample?scenario=${scenario}`);
    if (!response.ok) throw new Error(`Failed to generate CSI simulation sample: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async getNetworkTopology(): Promise<NetworkTopology> {
    const response = await this.request(`${this.baseUrl}/network/topology`);
    if (!response.ok) throw new Error(`Failed to fetch network topology: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async getNetworkAnomalies(filters: { ip?: string; userId?: string; limit?: number } = {}): Promise<{ anomalies: NetworkEvent[]; count: number }> {
    const query = new URLSearchParams();
    if (filters.ip) query.set("ip", filters.ip);
    if (filters.userId) query.set("user_id", filters.userId);
    if (filters.limit) query.set("limit", String(filters.limit));
    const response = await this.request(`${this.baseUrl}/network/anomalies?${query}`);
    if (!response.ok) throw new Error(`Failed to fetch network anomalies: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async getAuthMe(): Promise<{ user: SessionUser; permissions: string[] }> {
    const response = await this.request(`${this.baseUrl}/auth/me`);
    if (!response.ok) throw new Error(`Session is not valid: ${response.status} ${response.statusText}`);
    return response.json();
  }

  async logout(): Promise<void> {
    try {
      if (getAuthSession()?.token) await this.request(`${this.baseUrl}/auth/logout`, { method: "POST" });
    } finally {
      setAuthSession(null);
      this.disconnectWebSocket();
    }
  }

  async registerUser(payload: { email: string; password: string; role: Exclude<UserRole, "admin"> }): Promise<SessionUser> {
    const response = await this.request(`${this.baseUrl}/auth/register`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.detail || `User registration failed: ${response.status}`);
    }
    const result = await response.json();
    return result.user as SessionUser;
  }

  async getUsers(): Promise<SessionUser[]> {
    const response = await this.request(`${this.baseUrl}/users`);
    if (!response.ok) throw new Error(`Failed to fetch accounts: ${response.status} ${response.statusText}`);
    const result = await response.json();
    return result.users as SessionUser[];
  }

  async getLoginHistory(userId: string): Promise<Array<Record<string, unknown>>> {
    const response = await this.request(`${this.baseUrl}/users/${encodeURIComponent(userId)}/login-history`);
    if (!response.ok) throw new Error(`Failed to fetch login history: ${response.status} ${response.statusText}`);
    const result = await response.json();
    return result.attempts as Array<Record<string, unknown>>;
  }

  /**
   * Clear stored device baselines. A successful next login establishes a new baseline.
   */
  async resetBaselines(username?: string): Promise<{ status: string; username?: string }> {
    const response = await this.request(`${this.baseUrl}/baselines/reset`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(username ? { username } : {}),
    });
    if (!response.ok) {
      throw new Error(`Failed to clear baselines: ${response.status} ${response.statusText}`);
    }
    const result = await response.json();
    if (!result || typeof result.status !== 'string') {
      throw new Error('Backend returned an invalid baseline reset response.');
    }
    return result;
  }

  // ── Attack Chain Simulation ──

  async startAttackChain(): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/attack-chain/start`, { method: "POST" });
      if (!response.ok) throw new Error("Failed to start attack chain");
      return await response.json();
    } catch (error) {
      console.error("Attack chain start error:", error);
      throw error;
    }
  }

  async stopAttackChain(): Promise<ApiJson> {
    try {
      const response = await this.request(`${this.baseUrl}/attack-chain/stop`, { method: "POST" });
      if (!response.ok) throw new Error("Failed to stop attack chain");
      return await response.json();
    } catch (error) {
      console.error("Attack chain stop error:", error);
      throw error;
    }
  }

  async getAttackChainStatus(): Promise<{ running: boolean }> {
    try {
      const response = await this.request(`${this.baseUrl}/attack-chain/status`);
      if (!response.ok) return { running: false };
      return await response.json();
    } catch {
      return { running: false };
    }
  }
}

export const mlBackendService = new MLBackendService();

export type { AnomalyRecord };
