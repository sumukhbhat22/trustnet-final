import { useCallback, useEffect, useState } from "react";
import { Layout } from "@/components/Layout";
import PageTransition from "@/components/PageTransition";
import { mlBackendService, type BackendIncident, type SecurityEvent } from "@/services/mlBackendService";
import { useAuth } from "@/store/authContext";
import AgentPanel from "@/components/AgentPanel";

const SEVERITY_BADGE: Record<string, string> = {
  Critical: "badge-critical",
  High: "badge-high",
  Medium: "badge-medium",
  Low: "badge-ok",
};

type Action = "approve" | "dismiss" | "escalate" | "resolve";

export default function IncidentCenterPage() {
  const [incidents, setIncidents] = useState<BackendIncident[]>([]);
  const [relatedEvents, setRelatedEvents] = useState<SecurityEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [filter, setFilter] = useState<"all" | "active">("all");
  const [loading, setLoading] = useState(true);
  const [acting, setActing] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const { hasPermission } = useAuth();
  const selected = incidents.find((incident) => incident.id === selectedId) ?? incidents[0] ?? null;

  useEffect(() => {
    if (!selected) {
      setRelatedEvents([]);
      return;
    }
    let cancelled = false;
    setEventsLoading(true);
    void mlBackendService.getIncidentEvents(selected.id)
      .then((result) => { if (!cancelled) setRelatedEvents(result.events); })
      .catch(() => { if (!cancelled) setRelatedEvents([]); })
      .finally(() => { if (!cancelled) setEventsLoading(false); });
    return () => { cancelled = true; };
  }, [selected?.id]);

  const refreshIncidents = useCallback(async () => {
    try {
      const result = await mlBackendService.getIncidents(filter === "active" ? "active" : undefined);
      setIncidents(result.incidents);
      setSelectedId((current) => result.incidents.some((item) => item.id === current) ? current : result.incidents[0]?.id ?? "");
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load backend incidents.");
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    void refreshIncidents();
    const unsubscribe = mlBackendService.onThreatEvent((event) => {
      if (event?.type === "dashboard_update" || event?.type === "login_threat" || event?.type === "attack_chain" || event?.type === "agent_activity") {
        void refreshIncidents();
      }
    });
    const poll = window.setInterval(() => void refreshIncidents(), 15000);
    return () => {
      unsubscribe();
      window.clearInterval(poll);
    };
  }, [refreshIncidents]);

  const actOnIncident = async (action: Action) => {
    if (!selected) return;
    setActing(true);
    setMessage("");
    setError("");
    try {
      const result = await mlBackendService.transitionIncident(selected.id, action);
      const updated = result.incident as BackendIncident;
      setIncidents((current) => current.map((item) => item.id === updated.id ? updated : item));
      setMessage(action === "approve"
        ? result.device ? `Approved: ${result.device.label} was flagged and quarantined.` : "Approved for manual review; no linked device was available to quarantine."
        : action === "dismiss" ? `Dismissed incident ${updated.id}.`
          : action === "resolve" ? `Resolved incident ${updated.id}.`
            : `Escalated incident ${updated.id} for analyst review.`);
      await refreshIncidents();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The incident action failed.");
    } finally {
      setActing(false);
    }
  };

  const severityBadge = (severity: string) => SEVERITY_BADGE[severity] ?? "badge-medium";

  return (
    <PageTransition>
      <Layout>
        <div className="incident-page-topbar">
          <div>
            <div className="heading" style={{ fontSize: 20, fontWeight: 500 }}>Incident Center</div>
            <div style={{ fontSize: 12.5, color: "var(--text-faint)", marginTop: 2 }}>
              {loading ? "Loading backend incidents…" : `${incidents.filter((item) => item.status === "open" || item.status === "investigating").length} open or investigating`}
            </div>
          </div>
          <div className="incident-filter-control">
            <label htmlFor="incident-filter">View</label>
            <select id="incident-filter" value={filter} onChange={(event) => setFilter(event.target.value as "all" | "active")}>
              <option value="all">All incidents</option>
              <option value="active">Open &amp; investigating</option>
            </select>
          </div>
        </div>

        <div className="tn-content incident-page-content">
          {error && <div className="overview-load-error" role="alert">{error}</div>}
          {message && <div className="incident-action-message" role="status">{message}</div>}
          <div className="incident-layout">
            <section className="incident-list" aria-label="Backend incidents">
              {incidents.map((incident) => (
                <button
                  type="button"
                  key={incident.id}
                  className={`panel card-3d inc-card incident-list-card${incident.id === selected?.id ? " selected" : ""}`}
                  onClick={() => setSelectedId(incident.id)}
                  aria-pressed={incident.id === selected?.id}
                >
                  <span className="incident-list-meta">
                    <span className="mono incident-id">{incident.id}</span>
                    <span className={`badge ${severityBadge(incident.severity)}`}>{incident.severity}</span>
                  </span>
                  <span className="incident-list-title">{incident.title}</span>
                  <span className="incident-list-status">{incident.user_id}{incident.device_id ? ` · ${incident.device_id}` : ""} · {incident.status}</span>
                </button>
              ))}
              {!loading && incidents.length === 0 && <div className="device-empty">No matching incidents have been recorded by the backend.</div>}
            </section>

            {selected ? (
              <section className="panel panel-glow incident-detail">
                <div className="incident-detail-heading">
                  <div>
                    <span className="mono incident-id">{selected.incident_label ? `${selected.incident_label} · ` : ""}{selected.id}</span>
                    <div className="heading incident-title">{selected.title}</div>
                    <div className="incident-list-status">User {selected.user_id}{selected.device_id ? ` · device ${selected.device_id}` : ""}</div>
                  </div>
                  <span className={`badge ${severityBadge(selected.severity)}`}>{selected.severity} · risk {selected.risk_score.toFixed(1)}</span>
                </div>

                <div className="incident-evidence">
                  <div className="incident-section-label">Evidence gathered</div>
                  <div className="incident-evidence-chips">
                    {selected.evidence.length ? selected.evidence.map((item, index) => <span className="evidence-chip" key={`${index}-${item}`}>{item}</span>) : <span className="evidence-chip">No evidence details attached</span>}
                  </div>
                </div>

                {selected.risk_breakdown && <RiskBreakdown breakdown={selected.risk_breakdown} />}
                <AgentPanel incidentId={selected.id} canAct={hasPermission("approve_incidents")} onChanged={() => void refreshIncidents()} />
                <div className="incident-evidence">
                  <div className="incident-section-label">Correlated security events</div>
                  {eventsLoading ? <span className="network-muted">Loading event records…</span> : relatedEvents.length ? (
                    <div className="incident-events-list">
                      {relatedEvents.map((event) => (
                        <article key={event.id} className="incident-event-row">
                          <div className="incident-list-meta">
                            <span className="mono incident-id">{event.id}</span>
                            <span className="badge badge-medium">{event.event_category}</span>
                          </div>
                          <div className="network-muted">
                            {new Date(event.timestamp).toLocaleString()} · {event.user_id ?? "anonymous"} · {event.ip_address ?? "unknown IP"}
                          </div>
                          <div className="mono">{event.http_method} {event.request_path} · {event.status_code ?? "no response"}</div>
                          {event.risk_indicators.length > 0 && <div className="network-muted">Signals: {event.risk_indicators.join(", ")}</div>}
                        </article>
                      ))}
                    </div>
                  ) : <span className="network-muted">No persisted request events are linked to this incident.</span>}
                </div>
                <div className="hr incident-divider" />
                <div className="incident-section-label incident-timeline-label">Incident lifecycle</div>
                <div className="timeline">
                  <div className="t-item"><div className="t-dot" /><div style={{ fontSize: 13, color: "hsl(var(--foreground))", fontWeight: 500 }}>Created</div><div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>{new Date(selected.created_at).toLocaleString()}</div></div>
                  <div className="t-item"><div className="t-dot" style={{ borderColor: selected.status === "open" ? "hsl(var(--threat-medium))" : "hsl(var(--threat-safe))" }} /><div style={{ fontSize: 13, color: "hsl(var(--foreground))", fontWeight: 500 }}>Current status: {selected.status}</div><div style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 2 }}>{selected.response_action ?? "Awaiting analyst action"} · updated {new Date(selected.updated_at).toLocaleString()}</div></div>
                </div>

                {hasPermission("approve_incidents") && <>
                  <div className="hr incident-divider" />
                  <div className="incident-response-row">
                    <div className="incident-recommendation">Recommended response: <b>{selected.device_id ? "flag and quarantine the associated device" : "analyst review; no linked device is available"}</b></div>
                    <div className="incident-actions">
                      <button type="button" className="btn btn-ghost" onClick={() => void actOnIncident("escalate")} disabled={acting || ["dismissed", "resolved"].includes(selected.status)}>Escalate</button>
                      <button type="button" className="btn btn-ghost" onClick={() => void actOnIncident("dismiss")} disabled={acting || ["dismissed", "resolved"].includes(selected.status)}>Dismiss</button>
                      <button type="button" className="btn btn-ghost" onClick={() => void actOnIncident("resolve")} disabled={acting || ["dismissed", "resolved"].includes(selected.status)}>Resolve</button>
                      <button type="button" className="btn btn-primary" onClick={() => void actOnIncident("approve")} disabled={acting || ["dismissed", "resolved"].includes(selected.status)}>{acting ? "Working…" : "Approve action"}</button>
                    </div>
                  </div>
                </>}
              </section>
            ) : (
              <section className="panel panel-glow incident-detail incident-no-selection">
                <div className="heading" style={{ fontSize: 18, fontWeight: 500 }}>{loading ? "Loading incidents" : "No incident selected"}</div>
                <p className="incident-list-status">Incidents are created by the backend risk engine when fused risk crosses its high-risk threshold.</p>
              </section>
            )}
          </div>
        </div>
      </Layout>
    </PageTransition>
  );
}

interface RiskSignal { score?: number | null; label?: string; contribution?: number | null }

function RiskBreakdown({ breakdown }: { breakdown: Record<string, RiskSignal> }) {
  return (
    <div className="incident-risk-breakdown">
      <div className="incident-section-label">Explainable risk signals</div>
      {Array.isArray(breakdown.reasons) && breakdown.reasons.length > 0 && (
        <ul className="incident-risk-reasons" aria-label="Why this score">
          {breakdown.reasons.map((reason: string) => <li key={reason}>{reason}</li>)}
        </ul>
      )}
      {Object.entries(breakdown).filter(([key]) => ["behavioral", "isolation_forest", "classifier", "device_trust", "network", "physical"].includes(key)).map(([key, signal]) => (
        <div className="incident-risk-row" key={key}>
          <span>{key.replaceAll("_", " ")}</span>
          <span>{signal.score == null ? "Not implemented" : typeof signal.score === "number" ? `${signal.score.toFixed(1)} signal` : signal.label}</span>
          <span>{signal.contribution == null ? "—" : `${signal.contribution} pts`}</span>
        </div>
      ))}
    </div>
  );
}
