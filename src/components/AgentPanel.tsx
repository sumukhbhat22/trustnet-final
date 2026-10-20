import { useCallback, useEffect, useState } from "react";
import {
  mlBackendService,
  type AgentAutonomySettings,
  type AgentIncidentView,
  type AgentLearningResult,
  type VerdictScoreEffect,
} from "@/services/mlBackendService";

interface AgentPanelProps {
  incidentId: string;
  canAct: boolean;
  onChanged: () => void;
}

const VERDICT_LABEL: Record<string, string> = {
  likely_malicious: "Likely malicious",
  suspicious: "Suspicious",
  inconclusive: "Inconclusive",
};

const pct = (value: number | null | undefined) => (value == null ? "—" : `${(value * 100).toFixed(0)}%`);

/** Shows real Investigator / Response / Feedback state for one incident, fetched from the backend. */
export default function AgentPanel({ incidentId, canAct, onChanged }: AgentPanelProps) {
  const [view, setView] = useState<AgentIncidentView | null>(null);
  const [learning, setLearning] = useState<AgentLearningResult | null>(null);
  const [scoreEffect, setScoreEffect] = useState<VerdictScoreEffect | null>(null);
  const [autonomy, setAutonomy] = useState<AgentAutonomySettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [incidentView, learningResult, settings] = await Promise.all([
        mlBackendService.getIncidentAgentView(incidentId),
        mlBackendService.getAgentLearning(),
        mlBackendService.getAgentAutonomy(),
      ]);
      setView(incidentView);
      setLearning(learningResult);
      setAutonomy(settings);
      setError("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not load agent activity.");
    }
  }, [incidentId]);

  useEffect(() => {
    setView(null);
    void load();
    const unsubscribe = mlBackendService.onThreatEvent((event) => {
      if (event?.type === "agent_activity" || event?.type === "dashboard_update") void load();
    });
    return unsubscribe;
  }, [load]);

  const run = async (work: () => Promise<unknown>, success: string) => {
    setBusy(true);
    setNote("");
    setError("");
    try {
      await work();
      setNote(success);
      await load();
      onChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Agent action failed.");
    } finally {
      setBusy(false);
    }
  };

  if (error && !view) return <div className="overview-load-error" role="alert">{error}</div>;
  if (!view) return <div className="network-muted">Loading agent activity…</div>;

  const investigation = view.investigation;
  const hasVerdict = view.feedback.length > 0;

  return (
    <div className="incident-evidence" aria-label="Agent activity">
      <div className="incident-section-label">Investigator</div>
      {investigation ? (
        <>
          <div className="incident-list-meta">
            <span className={`badge ${investigation.verdict === "likely_malicious" ? "badge-critical" : investigation.verdict === "suspicious" ? "badge-high" : "badge-ok"}`}>
              {VERDICT_LABEL[investigation.verdict]}
            </span>
            <span className="mono">confidence {pct(investigation.confidence)}</span>
            <span className="network-muted">read-only evidence · {new Date(investigation.investigated_at).toLocaleString()}</span>
          </div>
          {investigation.attack_type && (
            <article className="incident-event-row" aria-label="Deterministic attack classification">
              <div className="incident-list-meta">
                <span className="mono incident-id">Attack type: {investigation.attack_type.type.replace(/_/g, " ")}</span>
                <span className="badge badge-medium">{pct(investigation.attack_type.confidence)} classifier confidence</span>
              </div>
              <div className="network-muted">Recommended next step: {investigation.attack_type.recommended_action.replace(/_/g, " ")}</div>
              <div className="network-muted">Deterministic evidence rules · {investigation.attack_type.evidence_summary.failed_logins} failed logins · {investigation.attack_type.evidence_summary.sensitive_events} sensitive events</div>
            </article>
          )}
          <div className="incident-events-list">
            {investigation.rules.map((rule) => (
              <article key={rule.rule_id} className="incident-event-row">
                <div className="incident-list-meta">
                  <span className="mono incident-id">{rule.rule_id}</span>
                  <span className={`badge ${rule.fired ? "badge-high" : "badge-ok"}`}>{rule.fired ? "fired" : "clear"} · weight {pct(rule.weight)}</span>
                </div>
                <div className="network-muted">{rule.detail}</div>
              </article>
            ))}
          </div>
        </>
      ) : <span className="network-muted">Not investigated yet.</span>}

      <div className="incident-section-label" style={{ marginTop: 14 }}>Response agent</div>
      {view.responses.length === 0 && <span className="network-muted">No response decided yet.</span>}
      {view.responses.map((action) => (
        <article key={action.id} className="incident-event-row">
          <div className="incident-list-meta">
            <span className="mono incident-id">{action.action}{action.target ? ` → ${action.target}` : ""}</span>
            <span className={`badge ${action.status === "executed" ? "badge-ok" : action.status === "pending_approval" ? "badge-high" : "badge-medium"}`}>
              {action.status.replace("_", " ")}{action.status === "executed" ? ` (${action.mode})` : ""}{action.status === "pending_approval" && action.expires_at ? ` · expires ${new Date(action.expires_at).toLocaleTimeString()}` : ""}
            </span>
          </div>
          <div className="network-muted">{action.rationale}</div>
          {action.safeguards.length > 0 && (
            <div className="network-muted">
              Safeguards: {action.safeguards.map((check) => `${check.passed ? "✓" : "✗"} ${check.name.replace(/_/g, " ")}`).join(" · ")}
            </div>
          )}
          {canAct && action.status === "pending_approval" && (
            <div className="incident-actions" style={{ marginTop: 8 }}>
              <button type="button" className="btn btn-ghost" disabled={busy}
                onClick={() => void run(() => mlBackendService.decideAgentResponse(incidentId, action.id, "reject"), "Response rejected.")}>Reject</button>
              <button type="button" className="btn btn-primary" disabled={busy}
                onClick={() => void run(() => mlBackendService.decideAgentResponse(incidentId, action.id, "approve"), "Response approved and enforced by the backend.")}>Approve &amp; enforce</button>
            </div>
          )}
        </article>
      ))}

      {view.notifications.length > 0 && (
        <div className="network-muted" style={{ marginTop: 8 }}>
          Notifications: {view.notifications.length} recorded ({Array.from(new Set(view.notifications.map((n) => n.status))).join(", ")})
        </div>
      )}

      {canAct && (
        <>
          <div className="incident-section-label" style={{ marginTop: 14 }}>Analyst verdict</div>
          <div className="incident-actions">
            <button type="button" className="btn btn-ghost" disabled={busy}
              onClick={() => void run(() => mlBackendService.reinvestigateIncident(incidentId), "Re-investigated.")}>Re-investigate</button>
            <button type="button" className="btn btn-ghost" disabled={busy}
              onClick={() => void run(() => mlBackendService.downloadIncidentReport(incidentId), "PDF report downloaded.")}>Export PDF</button>
            <button type="button" className="btn btn-ghost" disabled={busy}
              onClick={() => void run(() => mlBackendService.submitIncidentVerdict(incidentId, "false_positive").then((r) => setScoreEffect(r.score_effect ?? null)), "Marked as false positive.")}>False positive</button>
            <button type="button" className="btn btn-primary" disabled={busy}
              onClick={() => void run(() => mlBackendService.submitIncidentVerdict(incidentId, "true_positive").then((r) => setScoreEffect(r.score_effect ?? null)), "Marked as true positive.")}>True positive</button>
          </div>
          {hasVerdict && <div className="network-muted">Latest verdict: {view.feedback[view.feedback.length - 1].verdict.replace("_", " ")} by {view.feedback[view.feedback.length - 1].analyst_id}</div>}
        </>
      )}

      {scoreEffect && (
        <div className="panel" style={{ marginTop: 10, padding: 10 }}>
          <div className="incident-section-label">Verdict effect on {scoreEffect.user_id}</div>
          <div className="network-muted">
            Risk score {scoreEffect.score_before} &rarr; {scoreEffect.score_after} · analyst adjustment {scoreEffect.user_adjustment > 0 ? "+" : ""}{scoreEffect.user_adjustment} pts · policy v{scoreEffect.policy_version}
          </div>
          <div className="network-muted">{scoreEffect.mechanism}</div>
        </div>
      )}

      {learning && (
        <div className="network-muted" style={{ marginTop: 10 }}>
          Learning: {learning.labeled_incidents}/{learning.min_labels_required} verdicts · {learning.status.replace("_", " ")}
          {learning.default_accuracy != null && ` · leave-one-out accuracy default ${pct(learning.default_accuracy)}${learning.learned_accuracy != null ? ` vs learned ${pct(learning.learned_accuracy)}` : ""}`}
          {learning.note ? ` — ${learning.note}` : ""}
        </div>
      )}
      {autonomy && (
        <div className="network-muted">
          Autonomy: {autonomy.autonomy_mode.replace("_", " ")}{autonomy.kill_switch ? " · KILL SWITCH ON" : ""} · auto-contain needs confidence ≥ {pct(autonomy.auto_min_confidence)}, max {autonomy.auto_max_per_hour}/hour
        </div>
      )}

      {view.activity.length > 0 && (
        <div className="incident-events-list" style={{ marginTop: 10 }}>
          {view.activity.slice(0, 6).map((entry) => (
            <div className="network-muted" key={entry.id}>{new Date(entry.created_at).toLocaleTimeString()} · {entry.agent} · {entry.summary}</div>
          ))}
        </div>
      )}
      {note && <div className="incident-action-message" role="status">{note}</div>}
      {error && <div className="overview-load-error" role="alert">{error}</div>}
    </div>
  );
}
