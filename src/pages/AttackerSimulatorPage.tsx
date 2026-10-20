import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Layout } from "@/components/Layout";
import PageTransition from "@/components/PageTransition";
import { collectFingerprint, getFingerprintId } from "@/services/fingerprintService";
import {
  mlBackendService,
  type AuthenticationEvent,
  type DemoAccountStatus,
  type DemoLoginResult,
} from "@/services/mlBackendService";
import { useAuth } from "@/store/authContext";

const MAX_ATTEMPTS = 3;

export default function AttackerSimulatorPage() {
  const { hasPermission } = useAuth();
  const [events, setEvents] = useState<AuthenticationEvent[]>([]);
  const [eventsError, setEventsError] = useState("");

  const refreshEvents = useCallback(async () => {
    try {
      setEvents((await mlBackendService.getAuthenticationEvents(100)).events);
      setEventsError("");
    } catch (error) {
      setEventsError(error instanceof Error ? error.message : "Could not load live authentication events.");
    }
  }, []);

  useEffect(() => {
    void refreshEvents();
    const unsubscribe = mlBackendService.onThreatEvent((event) => {
      if (event?.type === "authentication_event") void refreshEvents();
    });
    const intervalId = window.setInterval(() => void refreshEvents(), 15000);
    return () => {
      unsubscribe();
      window.clearInterval(intervalId);
    };
  }, [refreshEvents]);

  return (
    <PageTransition>
      <Layout>
        <div className="risk-page-topbar">
          <div>
            <div className="heading" style={{ fontSize: 20 }}>Attacker Simulator</div>
            <div className="sim-subtitle">Send real login requests at the demo account and watch the defence respond</div>
          </div>
          <span className="badge badge-medium">Development demo</span>
        </div>

        <div className="tn-content risk-page-content">
          <div className="two-col sim-columns">
            <AttackerConsole onAttempt={refreshEvents} />
            {hasPermission("manage_users") ? <DefenderControl /> : <DefenderLocked />}
          </div>
          <AuthenticationActivity events={events} loadError={eventsError} />
        </div>
      </Layout>
    </PageTransition>
  );
}

function AttackerConsole({ onAttempt }: { onAttempt: () => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [attempts, setAttempts] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<DemoLoginResult | null>(null);
  const [error, setError] = useState("");
  const attemptsRemaining = Math.max(0, MAX_ATTEMPTS - attempts);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (submitting || attemptsRemaining === 0) return;
    const submittedPassword = password;
    setPassword("");
    setSubmitting(true);
    setError("");
    setResult(null);
    setAttempts((value) => value + 1);
    try {
      const fingerprint = collectFingerprint();
      setResult(await mlBackendService.submitDemoLogin(submittedPassword, fingerprint, getFingerprintId(fingerprint)));
      void onAttempt();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not reach the TrustNet backend.");
    } finally {
      setSubmitting(false);
    }
  };

  const response = result?.body;
  const success = response?.login_status === "allowed";
  const verdict = success
    ? { text: "Login success", cls: "badge-ok" }
    : response?.login_attempt_reason === "account_restricted"
      ? { text: "Account restricted", cls: "badge-high" }
      : response?.login_attempt_reason === "invalid_credentials" || response?.login_attempt_reason === "unknown_account"
        ? { text: "Invalid credentials", cls: "badge-high" }
        : { text: "Login denied", cls: "badge-high" };

  return (
    <section className="panel panel-glow overview-panel">
      <div className="overview-panel-heading">
        <div>
          <div className="heading" style={{ fontSize: 15 }}>Attacker Console</div>
          <div className="sim-subtitle">Ordinary login requests against the backend. Demo account only.</div>
        </div>
        <span className="badge badge-high">Offence</span>
      </div>

      <form className="tn-field sim-form" onSubmit={(event) => void submit(event)}>
        <label>
          Username
          <input value="trustnet-demo" readOnly aria-label="Demo username" />
        </label>
        <label>
          Demo account password
          <input
            type="password"
            autoComplete="off"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            disabled={submitting || attemptsRemaining === 0}
          />
        </label>
        <div className="sim-actions">
          <button className="btn btn-danger" type="submit" disabled={submitting || attemptsRemaining === 0 || !password}>
            {submitting ? "Sending…" : "Submit login request"}
          </button>
          <span className="sim-hint">{attemptsRemaining} of {MAX_ATTEMPTS} requests remaining this session</span>
        </div>
        <div className="sim-hint">The password is cleared after each submission and is not retained by this page.</div>
      </form>

      {error && <div className="sim-alert" role="alert">{error}</div>}
      {result && (
        <div className="sim-result" aria-live="polite">
          <div className="device-registry-heading">
            <strong className="kpi-label">Actual backend response</strong>
            <span className={`badge ${verdict.cls}`}>{verdict.text}</span>
          </div>
          <dl className="sim-kv">
            <dt>HTTP status</dt><dd className="mono">{result.httpStatus}</dd>
            <dt>Outcome</dt><dd>{success ? "SUCCESS" : "FAILURE"}</dd>
            <dt>Message</dt><dd>{response?.message ?? "Backend returned no message."}</dd>
            <dt>Source IP</dt><dd className="mono">{response?.attacker_ip ?? "Unavailable"}</dd>
            <dt>Event ID</dt><dd className="mono">{response?.authentication_event_id ?? "Not returned"}</dd>
            <dt>Timestamp (UTC)</dt><dd className="mono">{response?.authentication_event_timestamp ?? "Not returned"}</dd>
          </dl>
        </div>
      )}
      <div className="sim-hint" style={{ marginTop: 16 }}>
        Events are created only by the backend authentication endpoint. This page does not fabricate events or keep tokens.
      </div>
    </section>
  );
}

function DefenderLocked() {
  return (
    <section className="panel panel-glow overview-panel">
      <div className="overview-panel-heading">
        <div className="heading" style={{ fontSize: 15 }}>Defender Control Room</div>
        <span className="badge badge-medium">Admin only</span>
      </div>
      <div className="device-empty">Account restriction controls are available to administrators.</div>
    </section>
  );
}

function DefenderControl() {
  const [status, setStatus] = useState<DemoAccountStatus | null>(null);
  const [setupPassword, setSetupPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const refresh = useCallback(async () => {
    try {
      setStatus(await mlBackendService.getDemoAccountStatus());
      setError("");
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : "Unable to load demo account state.");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const intervalId = window.setInterval(() => void refresh(), 10000);
    return () => window.clearInterval(intervalId);
  }, [refresh]);

  const runAction = async (action: "setup" | "restrict" | "release") => {
    setLoading(true);
    setError("");
    setMessage("");
    const password = setupPassword;
    if (action === "setup") setSetupPassword("");
    try {
      if (action === "setup") await mlBackendService.setupDemoAccount(password);
      else if (action === "restrict") await mlBackendService.restrictDemoAccount();
      else await mlBackendService.releaseDemoAccount();
      setMessage(action === "setup" ? "Dedicated demo account initialized." : action === "restrict" ? "Demo account restricted." : "Demo account restriction released.");
      await refresh();
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : `Unable to ${action} the demo account.`);
    } finally {
      setLoading(false);
    }
  };

  const activeRestriction = status?.restriction;

  return (
    <section className="panel panel-glow overview-panel">
      <div className="overview-panel-heading">
        <div>
          <div className="heading" style={{ fontSize: 15 }}>Defender Control Room</div>
          <div className="sim-subtitle">Backend-enforced account restriction · administrators only</div>
        </div>
        <span className={`badge ${activeRestriction ? "badge-high" : "badge-ok"}`}>{activeRestriction ? "Restricted" : "Not restricted"}</span>
      </div>

      {error && <div className="sim-alert" role="alert">{error}</div>}
      {message && <div className="sim-note" role="status">{message}</div>}

      <div className="device-registry-heading">
        <div>
          <strong>trustnet-demo</strong>
          <div className="sim-hint">{status?.account ? `${status.account.email} · ${status.account.role}` : "Account is not initialized"}</div>
        </div>
        {status?.account && <span className={`badge ${status.account.is_active ? "badge-ok" : "badge-high"}`}>{status.account.is_active ? "Active" : "Disabled"}</span>}
      </div>

      {!status ? (
        <div className="device-empty">Loading demo account state…</div>
      ) : !status.account ? (
        <form
          className="tn-field sim-form"
          onSubmit={(event) => {
            event.preventDefault();
            void runAction("setup");
          }}
        >
          <label htmlFor="demo-account-password">
            Set dedicated demo password (12+ characters)
            <input
              id="demo-account-password"
              type="password"
              autoComplete="new-password"
              minLength={12}
              value={setupPassword}
              onChange={(event) => setSetupPassword(event.target.value)}
              required
              disabled={loading}
            />
          </label>
          <div className="sim-actions">
            <button className="btn btn-primary" type="submit" disabled={loading || setupPassword.length < 12}>
              {loading ? "Initializing…" : "Initialize demo account"}
            </button>
          </div>
        </form>
      ) : (
        <div className="sim-actions" style={{ marginTop: 16 }}>
          {activeRestriction ? (
            <button className="btn btn-primary" type="button" disabled={loading} onClick={() => void runAction("release")}>
              {loading ? "Updating…" : "Release restriction"}
            </button>
          ) : (
            <button className="btn btn-danger" type="button" disabled={loading} onClick={() => void runAction("restrict")}>
              {loading ? "Updating…" : "Restrict for 30 minutes"}
            </button>
          )}
        </div>
      )}

      {activeRestriction && (
        <div className="sim-hint" style={{ marginTop: 12 }}>
          Active restriction {activeRestriction.id}, expires {new Date(activeRestriction.expires_at).toLocaleString()}.
          {activeRestriction.reason ? ` Reason: ${activeRestriction.reason}` : ""}
        </div>
      )}

      <div className="hr" style={{ margin: "18px 0" }} />
      <div className="kpi-label">Restriction audit history</div>
      {status?.restriction_history.length ? (
        <div className="device-registry-list" style={{ marginTop: 8 }}>
          {status.restriction_history.map((item) => (
            <div className="device-registry-row" key={item.id}>
              <div className="device-registry-copy">
                <strong>{item.status.toUpperCase()} · {item.id}</strong>
                <span>
                  Restricted by {item.created_by} at {new Date(item.created_at).toLocaleString()}
                  {item.released_by && ` · released by ${item.released_by} at ${item.released_at ? new Date(item.released_at).toLocaleString() : "unknown time"}`}
                </span>
              </div>
              <span className={`badge ${item.status === "active" ? "badge-high" : "badge-medium"}`}>{item.status}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="device-empty">No account restriction actions recorded.</div>
      )}
    </section>
  );
}

function AuthenticationActivity({ events, loadError }: { events: AuthenticationEvent[]; loadError: string }) {
  const timeline = [...events].slice(0, 12).reverse();
  const times = timeline.map((event) => Date.parse(event.timestamp)).filter(Number.isFinite);
  const minTime = Math.min(...times);
  const span = Math.max(1, Math.max(...times) - minTime);
  const points = timeline.map((event, index) => ({
    event,
    index,
    x: timeline.length < 2 ? 500 : 20 + ((Date.parse(event.timestamp) - minTime) / span) * 960,
    y: event.outcome === "SUCCESS" ? 48 : 132,
  }));

  return (
    <section className="overview-incidents">
      <div className="overview-section-heading">
        <div>
          <div className="heading" style={{ fontSize: 16 }}>Authentication Activity</div>
          <div className="sim-subtitle">Live login requests only · seeded and demo history is excluded</div>
        </div>
      </div>
      {loadError && <div className="sim-alert" role="alert">Authentication events unavailable: {loadError}</div>}

      <div className="panel panel-glow overview-panel" style={{ marginBottom: 12 }}>
        <div className="kpi-label">Recent login timeline</div>
        {points.length ? (
          <>
            <svg viewBox="0 0 1000 170" role="img" aria-label="Timeline of live authentication successes and failures" style={{ width: "100%", height: 150, marginTop: 8 }}>
              <line x1="20" y1="48" x2="980" y2="48" stroke="hsl(var(--foreground) / 0.1)" />
              <line x1="20" y1="132" x2="980" y2="132" stroke="hsl(var(--foreground) / 0.1)" />
              <text x="20" y="30" fill="hsl(var(--muted-foreground))" fontSize="11" fontFamily="IBM Plex Mono, monospace">SUCCESS</text>
              <text x="20" y="118" fill="hsl(var(--muted-foreground))" fontSize="11" fontFamily="IBM Plex Mono, monospace">FAILURE</text>
              {points.length > 1 && <polyline points={points.map(({ x, y }) => `${x},${y}`).join(" ")} fill="none" stroke="hsl(var(--primary) / 0.45)" strokeWidth="2" />}
              {points.map(({ event, x, y, index }) => (
                <circle key={`${event.id}-${index}`} cx={x} cy={y} r="7" fill={event.outcome === "SUCCESS" ? "hsl(var(--threat-safe))" : "hsl(var(--threat-high))"}>
                  <title>{`${event.outcome} · ${event.username} · ${new Date(event.timestamp).toLocaleString(undefined, { timeZone: "UTC" })} UTC`}</title>
                </circle>
              ))}
            </svg>
            <div className="sim-hint">Oldest shown → newest shown · {points.length} persisted live events</div>
          </>
        ) : (
          <div className="device-empty">No live authentication requests recorded yet.</div>
        )}
      </div>

      <div className="panel panel-glow overview-table-wrap">
        <table className="tn-table">
          <thead><tr><th>Timestamp (UTC)</th><th>Outcome</th><th>Username</th><th>Source IP</th><th>Event ID</th><th>Reason</th><th>Source</th></tr></thead>
          <tbody>
            {events.length ? events.map((event) => (
              <tr key={event.id}>
                <td className="mono">{new Date(event.timestamp).toLocaleString(undefined, { timeZone: "UTC" })}</td>
                <td><span className={`badge ${event.outcome === "SUCCESS" ? "badge-ok" : "badge-high"}`}>{event.outcome}</span></td>
                <td>{event.username}</td>
                <td className="mono">{event.source_ip ?? "Unavailable"}</td>
                <td className="mono">{event.id}</td>
                <td>{event.reason ?? "—"}</td>
                <td><span className="badge badge-medium">{event.event_source}</span></td>
              </tr>
            )) : (
              <tr><td colSpan={7} className="overview-empty-row">No live authentication events yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
