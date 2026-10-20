import type { ReactNode } from "react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { NetworkGraph } from "@/components/NetworkGraph";
import PageTransition from "@/components/PageTransition";
import { mlBackendService, type BackendIncident, type DashboardSummary, type RegisteredDevice } from "@/services/mlBackendService";
import { useAuth } from "@/store/authContext";
import { useSecurity } from "@/store/securityStore";

export default function OverviewPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [devices, setDevices] = useState<RegisteredDevice[]>([]);
  const [loadError, setLoadError] = useState("");
  const [trustingDevice, setTrustingDevice] = useState<string | null>(null);
  const { hasPermission } = useAuth();
  const { nodes } = useSecurity();

  const refreshDashboard = useCallback(async () => {
    try {
      const [nextSummary, nextDevices] = await Promise.all([
        mlBackendService.getDashboardSummary(),
        mlBackendService.getDevices(),
      ]);
      setSummary(nextSummary);
      setDevices(nextDevices.devices);
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load live dashboard data.");
    }
  }, []);

  useEffect(() => {
    void refreshDashboard();
    const unsubscribe = mlBackendService.onThreatEvent((event) => {
      if (event?.type === "dashboard_update" || event?.type === "login_threat" || event?.type === "attack_chain") {
        void refreshDashboard();
      }
    });
    const intervalId = window.setInterval(() => void refreshDashboard(), 15000);
    return () => {
      unsubscribe();
      window.clearInterval(intervalId);
    };
  }, [refreshDashboard]);

  const trustDevice = async (deviceId: string) => {
    setTrustingDevice(deviceId);
    try {
      await mlBackendService.trustDevice(deviceId);
      await refreshDashboard();
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Unable to trust this device.");
    } finally {
      setTrustingDevice(null);
    }
  };

  const summaryIncidents = summary?.recent_incidents ?? [];
  const activeIncidents = summary?.active_incident_count ?? 0;
  const deviceCounts = summary?.device_counts;

  return (
    <PageTransition>
      <Layout>
        <div className="tn-content">
          <div className="kpi-grid">
            <KpiCard label="Average User Risk" value={summary ? summary.overall_risk.average.toFixed(1) : "—"} badge={{ text: summary ? `${summary.overall_risk.users_scored} scored` : "Loading", cls: "badge-medium" }} sub={summary ? `Maximum risk ${summary.overall_risk.maximum.toFixed(1)} / 100` : "Waiting for backend summary"} />
            <KpiCard label="Active Incidents" value={summary ? String(activeIncidents).padStart(2, "0") : "—"} badge={{ text: activeIncidents ? "Review" : "Clear", cls: activeIncidents ? "badge-high" : "badge-ok" }} sub="Open or investigating" />
            <KpiCard label="Trusted Devices" value={deviceCounts ? String(deviceCounts.trusted).padStart(2, "0") : "—"} badge={{ text: deviceCounts ? `${deviceCounts.total} total` : "Loading", cls: "badge-ok" }} sub="Manually approved fingerprints" />
            <KpiCard
              label="Devices Requiring Review"
              value={deviceCounts ? String(deviceCounts.unknown + deviceCounts.flagged).padStart(2, "0") : "—"}
              badge={{ text: deviceCounts?.flagged ? `${deviceCounts.flagged} flagged` : "Registry", cls: deviceCounts?.flagged ? "badge-critical" : "badge-medium" }}
              sub={deviceCounts ? `${deviceCounts.unknown} unknown · ${deviceCounts.flagged} flagged` : "Waiting for device registry"}
            />
            <Link to="/network-activity" className="overview-network-kpi-link" aria-label="View Network Activity anomalies">
              <KpiCard label="Network Anomalies" value={summary ? String(summary.network_anomalies).padStart(2, "0") : "—"} badge={{ text: "Live", cls: summary?.network_anomalies ? "badge-high" : "badge-ok" }} sub="Flagged request patterns · view activity →" />
            </Link>
          </div>

          {loadError && <div className="overview-load-error" role="status">Live backend data unavailable: {loadError}. Values below may be empty until the API reconnects.</div>}

          <div className="two-col overview-panels">
            <section className="panel panel-glow overview-panel">
              <div className="overview-panel-heading">
                <div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Live Network Topology</div>
                <span className="badge badge-medium">{nodes.length} entities</span>
              </div>
              <div className="bg-radial-amber topology-map" aria-label="Live topology of registered users, devices, and protected assets">
                {nodes.length ? <NetworkGraph width={800} height={260} /> : (
                  <div className="device-empty">Topology data is unavailable until the backend connects.</div>
                )}
              </div>
            </section>

            <section className="panel panel-glow overview-panel">
              <div className="device-registry-heading">
                <div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Registered Devices</div>
                <span className="badge badge-medium">{deviceCounts?.total ?? 0} tracked</span>
              </div>
              <div className="device-registry-list">
                {devices.length === 0 ? (
                  <div className="device-empty">No login fingerprints registered yet.</div>
                ) : devices.slice(0, 6).map((device) => (
                  <div className="device-registry-row" key={device.device_id}>
                    <div className="device-registry-copy">
                      <strong>{device.label}</strong>
                      <span>{device.user_id} · seen {new Date(device.last_seen).toLocaleString()}</span>
                    </div>
                    <span className={`badge ${device.trust_status === "trusted" ? "badge-ok" : device.trust_status === "flagged" ? "badge-critical" : "badge-high"}`}>
                      {device.trust_status}
                    </span>
                    {device.trust_status === "unknown" && hasPermission("manage_devices") && (
                      <button className="device-trust-button" disabled={trustingDevice === device.device_id} onClick={() => void trustDevice(device.device_id)}>
                        {trustingDevice === device.device_id ? "…" : "Trust"}
                      </button>
                    )}
                  </div>
                ))}
              </div>
              <div className="hr overview-csi-divider" />
              <div style={{ fontSize: 11.5, color: "var(--text-faint)", lineHeight: 1.6 }}>
                Browser/device fingerprints are registered as unknown until an administrator approves them. RF/CSI hardware monitoring is not connected.
              </div>
            </section>
          </div>

          <section className="overview-incidents">
            <div className="overview-section-heading">
              <div className="heading" style={{ fontSize: 16, fontWeight: 500 }}>Recent Incidents</div>
              <Link to="/incidents" style={{ fontSize: 13, fontWeight: 500 }}>View all →</Link>
            </div>
            <div className="panel panel-glow overview-table-wrap">
              <table className="tn-table">
                <thead><tr><th>ID</th><th>Summary</th><th>Severity</th><th>Agent</th><th>Status</th></tr></thead>
                <tbody>
                  {summaryIncidents.length ? summaryIncidents.map((incident) => <IncidentRow key={incident.id} incident={incident} />) : (
                    <tr><td colSpan={5} className="overview-empty-row">No backend incidents recorded yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </Layout>
    </PageTransition>
  );
}

function KpiCard({ label, value, badge, sub }: { label: string; value: ReactNode; badge: { text: string; cls: string }; sub: string }) {
  return (
    <div className="panel panel-glow kpi-card">
      <div className="kpi-card-top"><div className="kpi-label">{label}</div><span className={`badge ${badge.cls}`}>{badge.text}</span></div>
      <div className="heading kpi-card-value">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

function IncidentRow({ incident }: { incident: BackendIncident }) {
  const severity = incident.severity.toLowerCase();
  const badge = severity === "critical" ? "badge-critical" : severity === "high" ? "badge-high" : "badge-medium";
  return (
    <tr>
      <td className="mono">{incident.id}</td>
      <td>{incident.title}</td>
      <td><span className={`badge ${badge}`}>{incident.severity}</span></td>
      <td>Risk Engine</td>
      <td><span className={`badge ${incident.status === "resolved" ? "badge-ok" : incident.status === "dismissed" ? "badge-medium" : "badge-high"}`}>{incident.status}</span></td>
    </tr>
  );
}
