import { useEffect, useState } from "react";
import { Layout } from "@/components/Layout";
import { NetworkGraph } from "@/components/NetworkGraph";
import PageTransition from "@/components/PageTransition";
import { mlBackendService, type PropagationAnalysisResult } from "@/services/mlBackendService";
import { useSecurity } from "@/store/securityStore";

type SimulationMode = "live" | "whatif";

export default function RiskPropagationPage() {
  const [mode, setMode] = useState<SimulationMode>("live");
  const [whatIfAnalysis, setWhatIfAnalysis] = useState<PropagationAnalysisResult | null>(null);
  const { nodes, edges, systemRiskScore, isAttackSimulated, attackChainRunning, liveThreatPhase } = useSecurity();
  const whatIf = mode === "whatif";
  const highestRiskUser = nodes.filter((node) => node.type === "user")
    .sort((left, right) => right.propagationRisk - left.propagationRisk)[0];
  const isolateUserId = highestRiskUser?.propagationRisk ? highestRiskUser.id : null;
  const isolatedEdges = whatIf && isolateUserId
    ? edges.filter((edge) => edge.from !== isolateUserId && edge.to !== isolateUserId)
      .map((edge) => ({ ...edge, attackPath: false }))
    : edges;

  useEffect(() => {
    if (!whatIf || !isolateUserId) {
      setWhatIfAnalysis(null);
      return;
    }
    let cancelled = false;
    const analysisEdges = edges.filter((edge) => edge.from !== isolateUserId && edge.to !== isolateUserId)
      .map((edge) => ({ ...edge, attackPath: false }));
    void mlBackendService.analyzePropagation(nodes, analysisEdges)
      .then((result) => { if (!cancelled) setWhatIfAnalysis(result); })
      .catch(() => { if (!cancelled) setWhatIfAnalysis(null); });
    return () => { cancelled = true; };
  }, [edges, isolateUserId, nodes, whatIf]);

  const analysisByNode = new Map(
    (whatIfAnalysis?.all_nodes ?? []).map((node) => [node.node_id, node]),
  );
  const displayNodes = whatIf && whatIfAnalysis
    ? nodes.map((node) => {
      const analysis = analysisByNode.get(node.id);
      const criticality = String(analysis?.criticality ?? "").toLowerCase();
      return analysis ? {
        ...node,
        propagationRisk: analysis.propagation_risk,
        compromised: criticality === "critical" || criticality === "high",
      } : node;
    })
    : nodes;
  const compromisedNodes = displayNodes.filter((node) => node.compromised);
  const attackPathEdges = (whatIf ? isolatedEdges : edges).filter((edge) => edge.attackPath);
  const attackPathLabels = attackPathEdges.map((edge) => {
    const from = displayNodes.find((node) => node.id === edge.from)?.label ?? edge.from;
    const to = displayNodes.find((node) => node.id === edge.to)?.label ?? edge.to;
    return `${from} → ${to}`;
  });
  const liveScore = Math.round(Math.max(systemRiskScore, ...nodes.map((node) => node.propagationRisk), 0));
  const propagationScore = whatIf
    ? (whatIfAnalysis ? Math.round(whatIfAnalysis.total_network_risk) : liveScore)
    : liveScore;
  const scoreColor = propagationScore >= 70 ? "hsl(var(--threat-critical))" : propagationScore >= 40 ? "hsl(var(--threat-medium))" : "hsl(var(--threat-safe))";

  const sourceUser = nodes.filter((node) => node.type === "user")
    .sort((left, right) => right.propagationRisk - left.propagationRisk)[0];
  const targetAsset = nodes.filter((node) => node.id.startsWith("asset:"))
    .sort((left, right) => right.propagationRisk - left.propagationRisk || left.label.localeCompare(right.label))[0];
  const shortestPath: typeof nodes = [];
  if (sourceUser && targetAsset) {
    const pending: Array<{ nodeId: string; path: typeof nodes }> = [{ nodeId: sourceUser.id, path: [sourceUser] }];
    const visited = new Set<string>();
    while (pending.length && !shortestPath.length) {
      const current = pending.shift()!;
      if (visited.has(current.nodeId)) continue;
      visited.add(current.nodeId);
      if (current.nodeId === targetAsset.id) {
        shortestPath.push(...current.path);
        break;
      }
      for (const edge of edges) {
        if (edge.active && edge.from === current.nodeId && !visited.has(edge.to)) {
          const next = nodes.find((node) => node.id === edge.to);
          if (next) pending.push({ nodeId: next.id, path: [...current.path, next] });
        }
      }
    }
  }

  return (
    <PageTransition>
      <Layout>
        <div className="risk-page-topbar">
          <div>
            <div className="heading" style={{ fontSize: 20, fontWeight: 500 }}>Risk Propagation</div>
            <div style={{ fontSize: 12.5, color: "var(--text-faint)", marginTop: 2 }}>
              Attack-path simulation toward restricted assets
            </div>
          </div>
          <div className="risk-mode-buttons" role="group" aria-label="Simulation mode">
            <button type="button" className={`btn ${whatIf ? "btn-primary" : "btn-ghost"}`} aria-pressed={whatIf} onClick={() => setMode("whatif")}>
              What-if
            </button>
            <button type="button" className={`btn ${!whatIf ? "btn-primary" : "btn-ghost"}`} aria-pressed={!whatIf} onClick={() => setMode("live")}>
              <span className="dot pulse risk-live-dot" /> Live Simulation
            </button>
          </div>
        </div>

        <div className="tn-content risk-page-content">
          <div className="risk-page-grid">
            <section className="panel panel-glow risk-graph-panel">
              <div className="risk-panel-heading">
                <div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Propagation Graph</div>
                <span className={`badge ${isAttackSimulated ? "badge-critical" : whatIf ? "badge-medium" : "badge-ok"}`}>
                  {isAttackSimulated ? `${compromisedNodes.length} nodes compromised` : whatIf ? "What-if scenario" : "Monitoring network"}
                </span>
              </div>
                <div className={`graph-area bg-radial-amber ${whatIf ? "risk-whatif" : "scan"}`}>
                  <NetworkGraph width={800} height={480} graphNodes={displayNodes} graphEdges={whatIf ? isolatedEdges : edges} />
              </div>
              <div className="risk-legend">
                <span><span className="dot" style={{ background: "hsl(var(--threat-safe))" }} /> Low</span>
                <span><span className="dot" style={{ background: "hsl(var(--muted-foreground))" }} /> Normal</span>
                <span><span className="dot" style={{ background: "hsl(var(--threat-medium))" }} /> Elevated</span>
                <span><span className="dot" style={{ background: "hsl(var(--threat-high))" }} /> Critical path</span>
              </div>
              {isAttackSimulated && compromisedNodes.length > 0 ? (
                <div className="risk-affected-panel" aria-live="polite">
                  <div className="risk-affected-heading">
                    <span className="dot pulse" style={{ background: "hsl(var(--threat-critical))" }} />
                    AFFECTED DEVICES / SYSTEMS ({compromisedNodes.length})
                    {attackChainRunning && <span className="risk-phase">{liveThreatPhase.toUpperCase()} IN PROGRESS</span>}
                  </div>
                  <div className="risk-affected-list">
                    {compromisedNodes.map((node) => (
                      <div className="risk-affected-device" key={node.id}>
                        <span className="risk-device-type">{node.type}</span>
                        <strong>{node.label}</strong>
                        <span className="risk-device-score">RISK {node.propagationRisk}%</span>
                      </div>
                    ))}
                  </div>
                  {attackPathLabels.length > 0 && (
                    <div className="risk-path-edges">
                      <span className="risk-device-type">ACTIVE ATTACK LINKS</span>
                      {attackPathLabels.map((path) => <span key={path}>{path}</span>)}
                    </div>
                  )}
                </div>
              ) : (
                <div className="risk-idle-hint">Use <strong>SIMULATE ATTACK</strong> in the top bar to animate affected devices and active attack links here.</div>
              )}
            </section>

            <div className="risk-side-panels">
              <section className="panel panel-glow risk-gauge-panel">
                <div className="heading" style={{ fontSize: 15, fontWeight: 500, marginBottom: 12 }}>Propagation Risk Score</div>
                <div className="gauge-wrap">
                  <svg viewBox="0 0 220 120" width="220" height="120" aria-hidden="true">
                    <path d="M10,110 A100,100 0 0,1 210,110" fill="none" stroke="hsl(var(--muted))" strokeWidth={14} strokeLinecap="round" />
                    <path d="M10,110 A100,100 0 0,1 168,32" fill="none" stroke={scoreColor} strokeWidth={14} strokeLinecap="round" />
                  </svg>
                  <div className="risk-gauge-value">
                    <div className="heading glow-text" style={{ fontSize: 30, fontWeight: 500 }}>{propagationScore}</div>
                      <div style={{ fontSize: 11, color: "var(--text-faint)" }}>of 100 · {propagationScore >= 70 ? "Critical" : propagationScore >= 40 ? "Elevated" : "Low"}</div>
                  </div>
                </div>
                <div className="risk-gauge-caption">
                  {whatIf
                    ? whatIfAnalysis && highestRiskUser ? `Backend re-analysis with ${highestRiskUser.label} isolated` : "Isolate a user with an active risk signal to calculate impact"
                    : isAttackSimulated ? "Live score from current risk signals and topology" : "No elevated risk is currently recorded in the topology"}
                </div>
              </section>

              <section className="panel panel-glow risk-path-panel">
                <div className="heading" style={{ fontSize: 15, fontWeight: 500, marginBottom: 6 }}>Shortest Path to Asset</div>
                {shortestPath.length ? shortestPath.map((node, index) => {
                  const nextNode = shortestPath[index + 1];
                  return (
                    <div key={node.id} className="path-step">
                      <div className="step-num">{index + 1}</div>
                      <div>
                        <div style={{ fontSize: 13, color: "hsl(var(--foreground))", fontWeight: 500 }}>{node.label}</div>
                        <div style={{ fontSize: 11.5, color: "var(--text-faint)" }}>
                          {whatIf && isolateUserId === node.id ? "Isolated in what-if analysis" : nextNode ? `Connected to ${nextNode.label}` : `Protected asset · risk ${node.propagationRisk}%`}
                        </div>
                      </div>
                    </div>
                  );
                }) : <div className="risk-idle-hint">No connected path from a registered user to a protected asset.</div>}
              </section>
            </div>
          </div>
        </div>
      </Layout>
    </PageTransition>
  );
}
