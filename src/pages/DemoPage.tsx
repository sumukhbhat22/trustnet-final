import { useMemo, useState } from "react";
import { Activity, AlertTriangle, ArrowRight, CheckCircle2, Shield, Sparkles, Wifi } from "lucide-react";
import { Link } from "react-router-dom";

type DemoTab = "overview" | "signals" | "response";

const baseSignals = [
  { label: "Impossible travel", source: "Identity graph", score: 94, tone: "critical" },
  { label: "New device fingerprint", source: "Device registry", score: 76, tone: "high" },
  { label: "After-hours download", source: "Behavior model", score: 61, tone: "medium" },
];

export default function DemoPage() {
  const [tab, setTab] = useState<DemoTab>("overview");
  const [simulating, setSimulating] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [events, setEvents] = useState(["Baseline synced for 128 users", "Policy graph refreshed 14s ago"]);

  const risk = simulating ? 87 : 32;
  const signals = useMemo(() => simulating ? baseSignals : baseSignals.slice(1), [simulating]);

  const runSimulation = () => {
    setSimulating((active) => !active);
    setAcknowledged(false);
    setEvents((current) => [simulating ? "Attack simulation cleared" : "Attack chain detected from FIN-LT-042", ...current].slice(0, 3));
  };

  return (
    <main className="demo-shell">
      <header className="demo-header">
        <div className="demo-brand"><span className="demo-brand-icon"><Shield className="w-4 h-4" /></span><span><strong>TRUSTNET AI</strong><small>INTERACTIVE COMMAND PREVIEW</small></span></div>
        <div className="demo-header-actions"><span className="badge badge-ok"><span className="dot pulse" /> LIVE DEMO</span><Link className="btn btn-ghost" to="/login">Return to sign in</Link></div>
      </header>

      <section className="demo-hero">
        <div>
          <div className="demo-eyebrow"><Sparkles className="w-3.5 h-3.5" /> EXPLORE THE SECURITY GRAPH</div>
          <h1>See how TrustNet turns weak signals into a clear response.</h1>
          <p>Try the command center without connecting a backend. This preview uses the same red/black visual system as the authenticated console.</p>
        </div>
        <button className={`btn ${simulating ? "btn-ghost" : "btn-primary"}`} onClick={runSimulation}><Activity className="w-4 h-4" />{simulating ? "Reset simulation" : "Simulate attack chain"}</button>
      </section>

      <section className="demo-metrics">
        <Metric label="System risk" value={`${risk}`} detail={simulating ? "Critical path detected" : "Within baseline"} tone={simulating ? "critical" : "ok"} />
        <Metric label="Active signals" value={`${signals.length}`} detail="Explainable detections" tone="high" />
        <Metric label="Protected assets" value="24" detail="Policy-enforced" tone="ok" />
        <Metric label="Response SLA" value="02:41" detail="Median analyst action" tone="medium" />
      </section>

      <section className="demo-grid">
        <div className="panel panel-glow demo-main-panel">
          <div className="demo-tabs" role="tablist" aria-label="Demo views">
            {([["overview", "Command overview"], ["signals", "Signal stream"], ["response", "Response plan"]] as const).map(([id, label]) => (
              <button key={id} className={tab === id ? "chip active" : "chip"} onClick={() => setTab(id)} role="tab" aria-selected={tab === id}>{label}</button>
            ))}
          </div>

          {tab === "overview" && <div className="demo-overview-content"><div className="demo-graph scan"><div className="demo-ring ring-a" /><div className="demo-ring ring-b" /><div className="demo-node node-center"><Shield className="w-4 h-4" /><span>Identity graph</span></div><div className="demo-node node-one"><Wifi className="w-3.5 h-3.5" /><span>FIN-LT-042</span></div><div className="demo-node node-two"><AlertTriangle className="w-3.5 h-3.5" /><span>Payroll API</span></div><div className="demo-node node-three"><CheckCircle2 className="w-3.5 h-3.5" /><span>Vault</span></div></div><div className="demo-callout"><div><span className={`badge ${simulating ? "badge-critical" : "badge-ok"}`}>{simulating ? "REVIEW REQUIRED" : "BASELINE HEALTHY"}</span><h3>{simulating ? "Compromise path contained" : "Your environment is ready"}</h3><p>{simulating ? "Three signals converged on one device. The response agent recommends isolating the session before vault access." : "Run the simulation to see risk propagate through users, devices, and protected assets."}</p></div><ArrowRight className="w-5 h-5" /></div></div>}
          {tab === "signals" && <div className="demo-list">{signals.map((signal) => <div className="demo-signal" key={signal.label}><div className={`demo-signal-icon ${signal.tone}`}><AlertTriangle className="w-4 h-4" /></div><div><strong>{signal.label}</strong><span>{signal.source}</span></div><b>{signal.score}</b></div>)}</div>}
          {tab === "response" && <div className="demo-response"><div className="demo-response-step"><span>01</span><div><strong>Investigate</strong><p>Correlate device fingerprint, location drift, and asset sensitivity.</p></div><span className="badge badge-ok">READY</span></div><div className="demo-response-step"><span>02</span><div><strong>Recommend</strong><p>Temporarily isolate FIN-LT-042 and require MFA for the next session.</p></div><span className="badge badge-high">REVIEW</span></div><div className="demo-response-step"><span>03</span><div><strong>Approve action</strong><p>Human approval is required before a sensitive account action executes.</p></div><button className="btn btn-primary" onClick={() => setAcknowledged(true)}>{acknowledged ? "Approved" : "Review"}</button></div></div>}
        </div>

        <aside className="panel panel-glow demo-activity"><div className="demo-panel-heading"><div><div className="heading">Activity feed</div><small>Local preview events</small></div><span className="status-ring" /></div>{events.map((event) => <div className="demo-event" key={event}><span className="dot" /><span>{event}</span></div>)}<div className="demo-footnote">No data leaves this preview. Connect the FastAPI backend to use live WebSocket events, device registry actions, and persisted incidents.</div></aside>
      </section>
    </main>
  );
}

function Metric({ label, value, detail, tone }: { label: string; value: string; detail: string; tone: string }) {
  return <div className="panel panel-glow demo-metric"><span>{label}</span><strong>{value}</strong><small className={`demo-tone-${tone}`}>{detail}</small></div>;
}
