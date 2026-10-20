import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Activity, AlertTriangle, Globe2, Search, ShieldAlert, type LucideIcon } from "lucide-react";
import { Layout } from "@/components/Layout";
import PageTransition from "@/components/PageTransition";
import { mlBackendService, type NetworkEvent } from "@/services/mlBackendService";

const FLAG_LABELS: Record<string, string> = {
  rate_anomaly: "Rate anomaly",
  repeated_requests: "Repeated sensitive requests",
  new_ip_for_user: "New IP for user",
  credential_stuffing_pattern: "Credential stuffing pattern",
};

export default function NetworkActivityPage() {
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [anomalies, setAnomalies] = useState<NetworkEvent[]>([]);
  const [ipInput, setIpInput] = useState("");
  const [userInput, setUserInput] = useState("");
  const [ipFilter, setIpFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const refresh = useCallback(async () => {
    try {
      const filters = { ip: ipFilter || undefined, userId: userFilter || undefined, limit: 200 };
      const [eventResult, anomalyResult] = await Promise.all([
        mlBackendService.getNetworkEvents(filters),
        mlBackendService.getNetworkAnomalies(filters),
      ]);
      setEvents(eventResult.events);
      setAnomalies(anomalyResult.anomalies);
      setLastUpdated(new Date());
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load network activity.");
    } finally {
      setLoading(false);
    }
  }, [ipFilter, userFilter]);

  useEffect(() => {
    void refresh();
    const unsubscribe = mlBackendService.onThreatEvent((message) => {
      if (message?.type === "network_event" && message.event) {
        const event = message.event as NetworkEvent;
        if ((!ipFilter || event.source_ip === ipFilter) && (!userFilter || event.user_id === userFilter)) {
          setEvents((current) => [event, ...current.filter((item) => item.id !== event.id)].slice(0, 200));
          if (event.anomaly_types?.length) setAnomalies((current) => [event, ...current.filter((item) => item.id !== event.id)].slice(0, 200));
          setLastUpdated(new Date());
        }
      } else if (message?.type === "dashboard_update") {
        void refresh();
      }
    });
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => {
      unsubscribe();
      window.clearInterval(timer);
    };
  }, [refresh, ipFilter, userFilter]);

  const rateBars = useMemo(() => {
    const now = Date.now();
    return Array.from({ length: 12 }, (_, index) => {
      const bucketEnd = now - (11 - index) * 5 * 60_000;
      const bucketStart = bucketEnd - 5 * 60_000;
      const count = events.filter((event) => {
        const timestamp = Date.parse(event.timestamp);
        return timestamp >= bucketStart && timestamp < bucketEnd;
      }).length;
      return { label: new Date(bucketEnd).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), count };
    });
  }, [events]);
  const maxBar = Math.max(1, ...rateBars.map((item) => item.count));
  const oneMinuteCount = events.filter((event) => Date.now() - Date.parse(event.timestamp) <= 60_000).length;
  const anomalyKinds = new Set(anomalies.flatMap((event) => event.anomaly_types ?? []));

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIpFilter(ipInput.trim());
    setUserFilter(userInput.trim());
  }

  return (
    <PageTransition>
      <Layout>
        <div className="tn-content network-page">
          <div className="network-page-heading">
            <div>
              <div className="heading" style={{ fontSize: 20, fontWeight: 500 }}>Network Activity</div>
              <div className="network-subtitle">Observed API requests and explainable pattern-based detections</div>
            </div>
            <span className="badge badge-ok"><span className="dot pulse" style={{ background: "hsl(var(--threat-safe))" }} /> LIVE REQUEST MONITOR</span>
          </div>

          {error && <div className="overview-load-error" role="alert">{error}</div>}
          <div className="network-kpis">
            <Metric icon={Activity} label="Requests / last minute" value={oneMinuteCount} color="hsl(var(--primary))" />
            <Metric icon={ShieldAlert} label="Flagged events" value={anomalies.length} color="hsl(var(--threat-medium))" />
            <Metric icon={Globe2} label="Anomaly rules active" value={anomalyKinds.size} color="hsl(var(--threat-low))" />
            <Metric icon={AlertTriangle} label="Displayed events" value={events.length} color="hsl(var(--threat-safe))" />
          </div>

          <section className="panel panel-glow network-chart-panel">
            <div className="network-panel-heading">
              <div>
                <div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Request volume</div>
                <div className="network-muted">Five-minute buckets · captured API requests</div>
              </div>
              <span className="badge badge-medium">{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : loading ? "Loading" : "Waiting for traffic"}</span>
            </div>
            <div className="network-chart" role="img" aria-label="Observed requests per five-minute interval">
              {rateBars.map((bar) => (
                <div className="network-bar-column" key={bar.label} title={`${bar.label}: ${bar.count} requests`}>
                  <span className="network-bar-value">{bar.count || ""}</span>
                  <div className="network-bar-track"><div className="network-bar" style={{ height: `${Math.max(3, (bar.count / maxBar) * 100)}%` }} /></div>
                  <span className="network-bar-label">{bar.label}</span>
                </div>
              ))}
            </div>
            <p className="network-method-note">Rules: over 60 requests/minute per IP/user; at least 10 requests to a sensitive path/minute; unseen IP for a known account; and failures against at least 5 distinct users from one IP/minute.</p>
          </section>

          <form className="network-filters panel" onSubmit={applyFilters}>
            <label><span>Source IP</span><input value={ipInput} onChange={(event) => setIpInput(event.target.value)} placeholder="e.g. 203.0.113.10" /></label>
            <label><span>User ID</span><input value={userInput} onChange={(event) => setUserInput(event.target.value)} placeholder="Filter authenticated user" /></label>
            <button className="btn btn-primary" type="submit"><Search size={15} /> Apply filters</button>
            {(ipFilter || userFilter) && <button className="btn btn-ghost" type="button" onClick={() => { setIpInput(""); setUserInput(""); setIpFilter(""); setUserFilter(""); }}>Clear</button>}
          </form>

          <div className="network-data-grid">
            <section className="panel panel-glow network-table-panel">
              <div className="network-panel-heading"><div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Recent requests</div><span className="badge badge-medium">{events.length} events</span></div>
              <div className="network-table-scroll">
                <table className="tn-table network-table">
                  <thead><tr><th>Time</th><th>Source IP</th><th>User</th><th>Request</th><th>Status</th><th>Latency</th></tr></thead>
                  <tbody>
                    {events.map((event) => (
                      <tr key={event.id}>
                        <td className="mono">{new Date(event.timestamp).toLocaleTimeString()}</td>
                        <td className="mono">{event.source_ip}</td>
                        <td>{event.user_id ?? <span className="network-muted">anonymous</span>}</td>
                        <td><span className="network-method">{event.method}</span> <span className="mono">{event.endpoint}</span></td>
                        <td><span className={`badge ${event.status_code && event.status_code >= 400 ? "badge-critical" : "badge-ok"}`}>{event.status_code ?? "AUTH"}</span></td>
                        <td className="mono">{event.response_time_ms == null ? "—" : `${event.response_time_ms.toFixed(1)} ms`}</td>
                      </tr>
                    ))}
                    {!loading && events.length === 0 && <tr><td colSpan={6} className="overview-empty-row">No network requests match these filters yet.</td></tr>}
                  </tbody>
                </table>
              </div>
            </section>

            <section className="panel panel-glow network-anomaly-panel">
              <div className="network-panel-heading"><div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Flagged patterns</div><span className="badge badge-high">{anomalies.length}</span></div>
              <div className="network-anomaly-list">
                {anomalies.map((event) => (
                  <article className="network-anomaly" key={event.id}>
                    <div className="network-anomaly-top"><span className="badge badge-critical">{event.anomaly_types.map((item) => FLAG_LABELS[item] ?? item).join(", ")}</span><time>{new Date(event.timestamp).toLocaleTimeString()}</time></div>
                    <div className="mono network-anomaly-endpoint">{event.source_ip} · {event.user_id ?? "anonymous"}</div>
                    <div className="network-muted">{event.evidence || `${event.method} ${event.endpoint}`}</div>
                  </article>
                ))}
                {!loading && anomalies.length === 0 && <div className="device-empty">No pattern-based anomalies detected in the retained event window.</div>}
              </div>
            </section>
          </div>
          <div className="network-retention-note">Request and anomaly records persist in SQLite; this view reads at most 5,000 recent events. Detector windows rebuild from the latest minute of requests and login failures after restart.</div>
        </div>
      </Layout>
    </PageTransition>
  );
}

function Metric({ icon: Icon, label, value, color }: { icon: LucideIcon; label: string; value: number; color: string }) {
  return <div className="panel panel-glow network-metric"><div className="network-metric-icon" style={{ color, background: `${color}18` }}><Icon size={17} /></div><div><div className="network-metric-value">{value}</div><div className="network-muted">{label}</div></div></div>;
}
