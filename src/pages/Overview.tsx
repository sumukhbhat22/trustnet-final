import { motion, AnimatePresence } from 'framer-motion';
import { Shield, AlertTriangle, Activity, TrendingUp, Eye, Lock, CheckCircle, LogIn, Fingerprint, Globe, Clock, Cpu, Loader2, Zap, StopCircle, ChevronRight, ChevronDown, ChevronUp, RotateCcw, Brain, Network, BarChart3, ShieldCheck } from 'lucide-react';
import { useSecurity, getThreatLevel } from '@/store/securityStore';
import { RiskMeter } from '@/components/RiskMeter';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { Fragment, useState, useEffect, type ElementType } from 'react';
import { collectFingerprint, getFingerprintId } from '@/services/fingerprintService';
import { mlBackendService, type DashboardSummary } from '@/services/mlBackendService';

// ── Small shared components ──

const StatCard = ({
  title, value, subtitle, icon: Icon, color, delay = 0,
}: {
  title: string; value: string | number; subtitle: string;
  icon: ElementType; color: string; delay?: number;
}) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ delay, duration: 0.4 }}
    className="cyber-card p-4 rounded-lg"
  >
    <div className="flex items-start justify-between mb-3">
      <div className="w-10 h-10 rounded-lg flex items-center justify-center"
        style={{ background: `${color}20`, border: `1px solid ${color}40` }}>
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <div className="text-[10px] font-mono text-muted-foreground">{title}</div>
    </div>
    <div className="text-2xl font-bold font-mono" style={{ color }}>{value}</div>
    <div className="text-xs text-muted-foreground mt-1">{subtitle}</div>
  </motion.div>
);

const UserCard = ({ user, index }: { user: OverviewUser; index: number }) => {
  const statusConfig = {
    normal: { color: 'hsl(var(--threat-safe))', label: 'NORMAL', bg: 'hsl(var(--threat-safe) / 0.1)' },
    warning: { color: 'hsl(var(--threat-medium))', label: 'WARNING', bg: 'hsl(var(--threat-medium) / 0.1)' },
    restricted: { color: 'hsl(var(--threat-high))', label: 'RESTRICTED', bg: 'hsl(var(--threat-high) / 0.1)' },
    blocked: { color: 'hsl(var(--threat-critical))', label: 'BLOCKED', bg: 'hsl(var(--threat-critical) / 0.15)' },
  };
  const cfg = statusConfig[user.status as keyof typeof statusConfig];
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className="cyber-card rounded-lg p-4 transition-all duration-500"
      style={{
        borderColor: user.status === 'blocked' ? 'hsl(var(--threat-critical) / 0.5)' : user.status === 'restricted' ? 'hsl(var(--threat-high) / 0.4)' : undefined,
        background: user.status === 'blocked' ? 'hsl(var(--card))' : undefined,
        boxShadow: user.status === 'blocked' ? '0 0 20px hsl(var(--threat-critical) / 0.2)' : undefined,
      }}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full flex items-center justify-center text-sm font-bold"
            style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}40` }}>
            {user.name.split(' ').map((n: string) => n[0]).join('')}
          </div>
          <div>
            <div className="text-sm font-medium text-foreground">{user.name}</div>
            <div className="text-[10px] text-muted-foreground font-mono">{user.role}</div>
          </div>
        </div>
        <div className="px-2 py-0.5 rounded text-[9px] font-mono font-bold"
          style={{ background: cfg.bg, color: cfg.color, border: `1px solid ${cfg.color}30` }}>
          {cfg.label}
        </div>
      </div>
      <div className="flex items-center justify-between">
        <div className="text-[10px] text-muted-foreground font-mono">{user.location}</div>
        <div className="flex items-center gap-1">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: cfg.color, boxShadow: `0 0 4px ${cfg.color}` }} />
          <span className="text-sm font-bold font-mono" style={{ color: cfg.color }}>{user.riskScore}</span>
        </div>
      </div>
      {user.anomalies.length > 0 && (
        <div className="mt-3 pt-3 border-t border-border space-y-1">
          {user.anomalies.slice(0, 2).map((a: string, i: number) => (
            <div key={i} className="text-[9px] font-mono text-destructive/80 flex items-center gap-1">
              <div className="w-1 h-1 rounded-full bg-destructive" />{a}
            </div>
          ))}
        </div>
      )}
    </motion.div>
  );
};

const CustomTooltip = ({ active, payload, label }: TooltipProps) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="cyber-card rounded-lg p-3 text-xs font-mono border border-border">
      <div className="text-muted-foreground mb-1">{label}</div>
      {payload.map((p) => (
        <div key={p.name} style={{ color: p.color }}>{p.name}: {p.value.toFixed(0)}</div>
      ))}
    </div>
  );
};

import type { ThreatExplanation, ThreatPrediction, ChainData } from '@/types/threat';

interface FingerprintPreview { platform?: string; screenResolution?: string; timezone?: string; deviceType?: string; canvasHash?: string; webglRenderer?: string; fingerprintId?: string }
interface OverviewUser { name: string; role: string; location: string; status: string; riskScore: number; anomalies: string[] }
interface TooltipProps { active?: boolean; payload?: Array<{ name: string; color: string; value: number }>; label?: string }

// ── Login Result type ──
interface LoginResult {
  login_status?: 'allowed' | 'restricted' | 'denied';
  message?: string;
  risk_score: number;
  threat_level: string;
  anomalies: string[];
  fingerprint_comparison?: { match_score: number; is_same_device: boolean; differences: string[] };
  geo_distance_km?: number;
  geo?: { city: string; country: string };
  ml_result?: { confidence?: number; recommendation?: string; [key: string]: unknown };
  attacker_ip?: string;
  login_hour?: number;
  prediction?: ThreatPrediction;
  explanation?: ThreatExplanation;
}

// ── Explainable AI Panel ──
const severityColor = (s: string) =>
  s === 'critical' ? '#ef4444' : s === 'high' ? '#f57723' : s === 'medium' ? '#f5a623' : s === 'low' ? '#00d4aa' : '#666';

const XAIPanel = ({ explanation }: { explanation: LoginResult['explanation'] }) => {
  const [activeTab, setActiveTab] = useState<'risk' | 'classifier' | 'csf' | 'propagation'>('risk');
  if (!explanation) return null;

  const tabs = [
    { key: 'risk' as const, label: 'Risk Breakdown', icon: BarChart3, available: !!explanation.risk_score },
    { key: 'classifier' as const, label: 'Classifier', icon: Brain, available: !!explanation.classifier },
    { key: 'csf' as const, label: 'Fingerprint', icon: Fingerprint, available: !!explanation.csf },
    { key: 'propagation' as const, label: 'Propagation', icon: Network, available: !!explanation.propagation },
  ].filter(t => t.available);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border p-4 space-y-3"
      style={{ borderColor: '#8b5cf640', background: '#8b5cf608' }}>

      {/* XAI Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md flex items-center justify-center" style={{ background: '#8b5cf620' }}>
            <ShieldCheck className="w-3.5 h-3.5" style={{ color: '#8b5cf6' }} />
          </div>
          <span className="text-[10px] font-mono font-bold" style={{ color: '#8b5cf6' }}>EXPLAINABLE AI</span>
        </div>
        <span className="text-[8px] font-mono text-muted-foreground">Why did the AI decide this?</span>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1">
        {tabs.map(t => (
          <button key={t.key} onClick={() => setActiveTab(t.key)}
            className="flex items-center gap-1 px-2 py-1 rounded text-[8px] font-mono font-bold transition-all"
            style={{
              background: activeTab === t.key ? '#8b5cf620' : 'transparent',
              color: activeTab === t.key ? '#8b5cf6' : '#888',
              border: activeTab === t.key ? '1px solid #8b5cf640' : '1px solid transparent',
            }}>
            <t.icon className="w-2.5 h-2.5" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ═══ Risk Score Breakdown Tab ═══ */}
      {activeTab === 'risk' && explanation.risk_score && (
        <div className="space-y-2.5">
          {/* Summary */}
          <div className="text-[9px] font-mono text-muted-foreground leading-relaxed">
            {explanation.risk_score.summary}
          </div>

          {/* Behavioral breakdown bars */}
          <div className="space-y-1.5">
            <div className="text-[8px] font-mono font-bold text-muted-foreground">BEHAVIORAL DEVIATION BREAKDOWN</div>
            {explanation.risk_score.behavioral_breakdown
              .filter(b => b.deviation_pct > 0)
              .map((b) => (
              <div key={b.factor_key} className="space-y-0.5">
                <div className="flex items-center justify-between">
                  <span className="text-[8px] font-mono text-foreground">{b.factor}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-[7px] font-mono" style={{ color: severityColor(b.severity) }}>
                      {b.deviation_pct.toFixed(0)}% dev
                    </span>
                    <span className="text-[7px] font-mono font-bold" style={{ color: severityColor(b.severity) }}>
                      +{b.contribution.toFixed(0)} pts
                    </span>
                  </div>
                </div>
                <div className="h-1 bg-background/50 rounded-full overflow-hidden">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${Math.min(b.contribution * 2, 100)}%` }}
                    transition={{ duration: 0.6 }} className="h-full rounded-full"
                    style={{ background: severityColor(b.severity) }} />
                </div>
              </div>
            ))}
          </div>

          {/* Threat Amplifiers */}
          {explanation.risk_score.threat_amplifiers.length > 0 && (
            <div className="space-y-1">
              <div className="text-[8px] font-mono font-bold text-muted-foreground">THREAT AMPLIFIERS</div>
              {explanation.risk_score.threat_amplifiers.map((a, i) => (
                <div key={i} className="flex items-center gap-1.5 text-[8px] font-mono">
                  <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: severityColor(a.severity) }} />
                  <span className="text-foreground flex-1">{a.signal}</span>
                  <span className="font-bold" style={{ color: severityColor(a.severity) }}>+{a.impact.toFixed(0)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Propagation influence */}
          <div className="flex items-center justify-between pt-1 border-t border-border/30">
            <span className="text-[8px] font-mono text-muted-foreground">Network Propagation Influence</span>
            <span className="text-[9px] font-mono font-bold" style={{ color: '#f5a623' }}>
              +{explanation.risk_score.propagation_influence.toFixed(0)} pts
            </span>
          </div>

          {/* Formula */}
          <div className="text-[7px] font-mono text-muted-foreground/60 pt-1 border-t border-border/20">
            Formula: {explanation.risk_score.score_formula}
          </div>
        </div>
      )}

      {/* ═══ Classifier Explanation Tab ═══ */}
      {activeTab === 'classifier' && explanation.classifier && (
        <div className="space-y-2.5">
          {/* Reasoning chain */}
          <div className="space-y-1">
            <div className="text-[8px] font-mono font-bold text-muted-foreground">AI REASONING CHAIN</div>
            {explanation.classifier.reasoning_chain.map((r, i) => (
              <div key={i} className="flex items-start gap-1.5 text-[8px] font-mono">
                <span className="text-muted-foreground shrink-0">{i + 1}.</span>
                <span className="text-foreground leading-relaxed">{r}</span>
              </div>
            ))}
          </div>

          {/* Feature importance */}
          <div className="space-y-1.5">
            <div className="text-[8px] font-mono font-bold text-muted-foreground">CLASSIFICATION CONTRIBUTORS</div>
            {Object.entries(explanation.classifier.classification_contributors)
              .sort(([,a], [,b]) => b - a)
              .map(([feat, pct]) => (
              <div key={feat} className="space-y-0.5">
                <div className="flex items-center justify-between">
                  <span className="text-[7px] font-mono text-foreground truncate max-w-[60%]">
                    {feat.replace(/_/g, ' ').replace(/pct|km/g, '').trim()}
                  </span>
                  <span className="text-[7px] font-mono font-bold" style={{ color: pct > 25 ? '#ef4444' : pct > 15 ? '#f5a623' : '#00d4aa' }}>
                    {pct.toFixed(0)}%
                  </span>
                </div>
                <div className="h-1 bg-background/50 rounded-full overflow-hidden">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.5 }} className="h-full rounded-full"
                    style={{ background: pct > 25 ? '#ef4444' : pct > 15 ? '#f5a623' : '#00d4aa' }} />
                </div>
              </div>
            ))}
          </div>

          {/* Global feature importance */}
          <div className="space-y-1 pt-1 border-t border-border/30">
            <div className="text-[8px] font-mono font-bold text-muted-foreground">GLOBAL FEATURE IMPORTANCE (RF)</div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[7px] font-mono">
              {Object.entries(explanation.classifier.global_feature_importance)
                .sort(([,a], [,b]) => b - a)
                .map(([f, v]) => (
                <Fragment key={f}>
                  <span className="text-muted-foreground truncate">{f.replace(/_/g, ' ')}</span>
                  <span className="text-foreground">{v.toFixed(1)}%</span>
                </Fragment>
              ))}
            </div>
          </div>

          {/* Model info */}
          <div className="text-[7px] font-mono text-muted-foreground/60 pt-1 border-t border-border/20">
            Model: {explanation.classifier.model_type} (RF {explanation.classifier.ensemble_weights.random_forest * 100}% + GB {explanation.classifier.ensemble_weights.gradient_boosting * 100}%)
          </div>
        </div>
      )}

      {/* ═══ CSF Fingerprint Tab ═══ */}
      {activeTab === 'csf' && explanation.csf && (
        <div className="space-y-2.5">
          {/* Summary */}
          <div className="text-[9px] font-mono text-muted-foreground leading-relaxed">
            {explanation.csf.summary}
          </div>

          {/* Match meter */}
          <div className="flex items-center gap-2">
            <span className="text-[8px] font-mono text-muted-foreground">Device Match:</span>
            <div className="flex-1 h-2 bg-background/50 rounded-full overflow-hidden">
              <motion.div initial={{ width: 0 }} animate={{ width: `${explanation.csf.match_score_pct}%` }}
                transition={{ duration: 0.8 }} className="h-full rounded-full"
                style={{ background: explanation.csf.is_same_device ? '#00d4aa' : '#ef4444' }} />
            </div>
            <span className="text-[9px] font-mono font-bold"
              style={{ color: explanation.csf.is_same_device ? '#00d4aa' : '#ef4444' }}>
              {explanation.csf.match_score_pct}%
            </span>
          </div>

          {/* Suspicion score */}
          <div className="flex items-center justify-between">
            <span className="text-[8px] font-mono text-muted-foreground">
              Suspicion Level: {explanation.csf.changed_count}/{explanation.csf.total_fields} fields changed
            </span>
            <span className="text-[9px] font-mono font-bold" style={{ color: explanation.csf.overall_suspicion > 50 ? '#ef4444' : '#f5a623' }}>
              {explanation.csf.overall_suspicion.toFixed(0)}/100
            </span>
          </div>

          {/* Field-by-field */}
          <div className="space-y-1">
            <div className="text-[8px] font-mono font-bold text-muted-foreground">FIELD-BY-FIELD ANALYSIS</div>
            {explanation.csf.deviations.map((d) => (
              <div key={d.field} className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ background: d.changed ? '#ef4444' : '#00d4aa' }} />
                <span className="text-[7px] font-mono w-24 truncate text-foreground">{d.field}</span>
                <div className="flex-1 h-1 bg-background/30 rounded-full overflow-hidden">
                  <div className="h-full rounded-full"
                    style={{
                      width: `${d.weight * 100 * 5}%`,
                      background: d.changed ? '#ef4444' : '#00d4aa40',
                    }} />
                </div>
                <span className="text-[7px] font-mono w-8 text-right"
                  style={{ color: d.changed ? '#ef4444' : '#666' }}>
                  {d.changed ? d.suspicion_score.toFixed(0) : '✓'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ═══ Propagation Tab ═══ */}
      {activeTab === 'propagation' && explanation.propagation && (
        <div className="space-y-2.5">
          {/* Summary */}
          <div className="text-[9px] font-mono text-muted-foreground leading-relaxed">
            {explanation.propagation.summary}
          </div>

          {/* Node risk table */}
          <div className="space-y-1">
            <div className="text-[8px] font-mono font-bold text-muted-foreground">NODE RISK PROPAGATION</div>
            {explanation.propagation.node_explanations
              .filter(n => n.propagated_risk > 0)
              .map((n) => (
              <div key={n.node_id} className="flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ background: n.is_compromised ? '#ef4444' : severityColor(n.criticality) }} />
                <span className="text-[7px] font-mono w-20 truncate text-foreground">
                  {n.node_label}
                </span>
                <div className="flex-1 h-1 bg-background/30 rounded-full overflow-hidden">
                  <motion.div initial={{ width: 0 }} animate={{ width: `${n.propagated_risk}%` }}
                    transition={{ duration: 0.6 }} className="h-full rounded-full"
                    style={{ background: severityColor(n.criticality) }} />
                </div>
                <span className="text-[7px] font-mono w-12 text-right" style={{ color: severityColor(n.criticality) }}>
                  {n.propagated_risk.toFixed(0)}
                  {n.received_from_neighbors > 0 && (
                    <span className="text-muted-foreground"> (+{n.received_from_neighbors.toFixed(0)})</span>
                  )}
                </span>
              </div>
            ))}
          </div>

          {/* Edge contributions */}
          {explanation.propagation.edge_contributions.length > 0 && (
            <div className="space-y-1 pt-1 border-t border-border/30">
              <div className="text-[8px] font-mono font-bold text-muted-foreground">TOP RISK PATHWAYS</div>
              {explanation.propagation.edge_contributions.slice(0, 4).map((e, i) => (
                <div key={i} className="flex items-center gap-1 text-[7px] font-mono">
                  <span className="text-foreground truncate">{e.from.split(' ')[0]}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="text-foreground truncate">{e.to.split(' ')[0]}</span>
                  <span className="text-muted-foreground ml-auto">w={e.trust_weight}</span>
                  <span className="font-bold" style={{ color: '#f5a623' }}>+{e.risk_transferred.toFixed(0)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Algorithm info */}
          <div className="text-[7px] font-mono text-muted-foreground/60 pt-1 border-t border-border/20">
            Algorithm: {explanation.propagation.algorithm} | Damping: {explanation.propagation.damping_factor}
          </div>
        </div>
      )}
    </motion.div>
  );
};

// ── Attack Chain Phase definitions (for timeline rendering) ──
const CHAIN_PHASES = [
  { num: 1, name: 'Initial Compromise', icon: '🔓', steps: ['Stolen Credentials Login', 'Abnormal Login Time', 'New Device / IP Detected', 'Geo-location Anomaly Confirmed'] },
  { num: 2, name: 'Privilege Escalation', icon: '⬆️', steps: ['Access to Admin Panel', 'Role Change Attempt', 'Restricted API Access'] },
  { num: 3, name: 'Lateral Movement', icon: '🔀', steps: ['Accessing Internal System', 'Querying Database Server', 'Network Node Scanning'] },
  { num: 4, name: 'Data Exfiltration', icon: '📤', steps: ['Large Data Transfer Spike', 'Sensitive File Access', 'Suspicious Outbound Traffic'] },
  { num: 5, name: 'Risk Propagation', icon: '🌐', steps: ['Risk Spreading Across Graph', 'Neighboring Nodes Risk Rising', 'System-Wide Risk Score Rising'] },
  { num: 6, name: 'Digital Immune Response', icon: '🛡️', steps: ['Step-Up Authentication Triggered', 'Temporary Session Freeze', 'Risk Quarantine of Nodes', 'Alert Generated — Threat Neutralized'] },
];

const AttackChainTimeline = ({ data, running, showFullXAI, onToggleXAI }: { data: ChainData; running: boolean; showFullXAI?: boolean; onToggleXAI?: () => void }) => {
  const currentPhase = data?.phase_number || 0;
  const currentStep = data?.step_number || 0;
  const prediction = data?.prediction;
  const riskScore = data?.risk_score || 0;
  const threatLevel = data?.threat_level || 'safe';
  const anomalies = data?.anomalies || [];

  const riskColor = riskScore <= 30 ? '#00d4aa' : riskScore <= 50 ? '#f5a623' : riskScore <= 70 ? '#f57723' : riskScore <= 85 ? '#ef4444' : '#dc2626';

  return (
    <div className="cyber-card rounded-xl p-5 space-y-4">
      {/* Title bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Zap className="w-4 h-4 text-primary" />
          <span className="text-sm font-bold font-mono text-foreground">Attack Chain Simulation</span>
          {running && (
            <span className="flex items-center gap-1 text-[9px] font-mono text-destructive animate-pulse">
              <div className="w-1.5 h-1.5 rounded-full bg-destructive" /> LIVE
            </span>
          )}
        </div>
        {data && (
          <div className="flex items-center gap-3">
            <span className="text-lg font-black font-mono" style={{ color: riskColor }}>{riskScore}</span>
            <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded"
              style={{ color: riskColor, background: `${riskColor}20` }}>
              {threatLevel.toUpperCase()}
            </span>
          </div>
        )}
      </div>

      {/* Phase progress bar */}
      <div className="flex gap-1">
        {CHAIN_PHASES.map((p) => {
          const isDone = currentPhase > p.num;
          const isActive = currentPhase === p.num;
          return (
            <div key={p.num} className="flex-1 h-2 rounded-full overflow-hidden bg-muted/50">
              <motion.div
                className="h-full rounded-full"
                initial={{ width: 0 }}
                animate={{
                  width: isDone ? '100%' : isActive ? `${(currentStep / p.steps.length) * 100}%` : '0%',
                }}
                transition={{ duration: 0.5 }}
                style={{
                  background: p.num <= 4
                    ? (isDone || isActive ? '#ef4444' : '#333')
                    : p.num === 5
                    ? (isDone || isActive ? '#f5a623' : '#333')
                    : (isDone || isActive ? '#00d4aa' : '#333'),
                }}
              />
            </div>
          );
        })}
      </div>

      {/* Current step highlight */}
      {data && (
        <motion.div
          key={`${currentPhase}-${currentStep}`}
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          className="rounded-lg border p-3 space-y-2"
          style={{
            borderColor: currentPhase <= 4 ? '#ef444460' : currentPhase === 5 ? '#f5a62360' : '#00d4aa60',
            background: currentPhase <= 4 ? '#ef444408' : currentPhase === 5 ? '#f5a62308' : '#00d4aa08',
          }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-base">{data.phase_icon}</span>
              <span className="text-xs font-bold font-mono text-foreground">
                Phase {currentPhase}: {data.phase_name}
              </span>
              <ChevronRight className="w-3 h-3 text-muted-foreground" />
              <span className="text-xs font-mono text-muted-foreground">{data.step_name}</span>
            </div>
            <span className="text-[9px] font-mono text-muted-foreground">
              Step {data.current_step_global}/{data.total_steps}
            </span>
          </div>

          {/* Anomalies for current step */}
          <div className="space-y-0.5">
            {anomalies.map((a: string, i: number) => (
              <motion.div
                key={i}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: i * 0.1 }}
                className="text-[9px] font-mono flex items-center gap-1.5"
                style={{ color: a.startsWith('🛡') ? '#00d4aa' : '#ef9a9a' }}
              >
                <div className="w-1 h-1 rounded-full flex-shrink-0"
                  style={{ background: a.startsWith('🛡') ? '#00d4aa' : '#ef4444' }} />
                {a}
              </motion.div>
            ))}
          </div>

          {/* ML Prediction */}
          {prediction && (
            <div className="flex items-center gap-3 pt-1 border-t border-border/50">
              <span className="text-[10px] font-mono font-black"
                style={{ color: prediction.is_malicious ? '#ef4444' : '#00d4aa' }}>
                {prediction.prediction}
              </span>
              <span className="text-[9px] font-mono text-muted-foreground">
                {prediction.attack_label} — {prediction.confidence}%
              </span>
              <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                prediction.action === 'BLOCK' ? 'bg-destructive/20 text-destructive' :
                prediction.action === 'RESTRICT' ? 'bg-yellow-500/20 text-yellow-500' :
                prediction.action === 'FLAG' ? 'bg-orange-500/20 text-orange-400' :
                'bg-emerald-500/20 text-emerald-400'
              }`}>
                {prediction.action}
              </span>
            </div>
          )}

          {/* XAI Summary Bar */}
          {data?.explanation && (
            <div className="flex items-center gap-2 pt-1 border-t border-border/30 flex-wrap">
              <span className="text-[8px] font-mono font-bold" style={{ color: '#8b5cf6' }}>
                🧩 XAI:
              </span>
              {data.explanation.risk_score?.top_behavioral_deviations?.slice(0, 2).map((d: string, i: number) => (
                <span key={i} className="text-[7px] font-mono text-muted-foreground px-1 py-0.5 rounded bg-background/50">
                  {d.split(':')[0]}
                </span>
              ))}
              {data.explanation.classifier?.top_contributor && (
                <span className="text-[7px] font-mono px-1 py-0.5 rounded" style={{ background: '#8b5cf615', color: '#8b5cf6' }}>
                  Top: {data.explanation.classifier.top_contributor.replace(/_/g, ' ')} ({data.explanation.classifier.top_contributor_pct.toFixed(0)}%)
                </span>
              )}
              {data.explanation.propagation && (
                <span className="text-[7px] font-mono text-muted-foreground">
                  Net: {data.explanation.propagation.affected_node_count}/{data.explanation.propagation.total_nodes} nodes
                </span>
              )}
            </div>
          )}
        </motion.div>
      )}

      {/* Phase grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
        {CHAIN_PHASES.map((p) => {
          const isDone = currentPhase > p.num;
          const isActive = currentPhase === p.num;
          const isPending = currentPhase < p.num;
          return (
            <div
              key={p.num}
              className={`rounded-lg p-2.5 border transition-all duration-500 ${
                isActive ? 'ring-1 ring-primary/50' : ''
              }`}
              style={{
                borderColor: isDone ? '#00d4aa40' : isActive ? '#ef444460' : '#ffffff10',
                background: isDone ? '#00d4aa08' : isActive ? '#ef444408' : '#ffffff03',
                opacity: isPending && !running ? 0.4 : 1,
              }}
            >
              <div className="flex items-center gap-1.5 mb-1.5">
                <span className="text-sm">{p.icon}</span>
                <span className="text-[8px] font-mono font-bold text-foreground truncate">{p.name}</span>
              </div>
              <div className="space-y-0.5">
                {p.steps.map((step, si) => {
                  const stepDone = isDone || (isActive && si < currentStep);
                  const stepActive = isActive && si === currentStep - 1;
                  return (
                    <div key={si} className="flex items-center gap-1">
                      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0 transition-all duration-300"
                        style={{
                          background: stepDone ? '#00d4aa' : stepActive ? '#ef4444' : '#ffffff20',
                          boxShadow: stepActive ? '0 0 6px #ef4444' : 'none',
                        }} />
                      <span className={`text-[7px] font-mono truncate ${
                        stepActive ? 'text-foreground font-bold' : stepDone ? 'text-muted-foreground' : 'text-muted-foreground/50'
                      }`}>
                        {step}
                      </span>
                    </div>
                  );
                })}
              </div>
              {isDone && (
                <div className="text-[7px] font-mono text-emerald-400 mt-1 flex items-center gap-0.5">
                  <CheckCircle className="w-2.5 h-2.5" /> Complete
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ═══ Expandable Full XAI Panel Below Timeline ═══ */}
      {data?.explanation && (
        <div className="space-y-2 pt-2">
          <button onClick={onToggleXAI}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg border transition-all font-mono text-xs font-bold"
            style={{
              borderColor: showFullXAI ? '#8b5cf660' : '#8b5cf640',
              background: showFullXAI ? '#8b5cf618' : '#8b5cf60a',
              color: '#8b5cf6',
            }}>
            <Brain className="w-4 h-4" />
            {showFullXAI ? 'Hide' : 'View'} Explainable AI Analysis
            {showFullXAI ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
          <AnimatePresence>
            {showFullXAI && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden">
                <XAIPanel explanation={data.explanation} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
};

// ══════════════════════════════════════════════
// Main unified page
// ══════════════════════════════════════════════

const Overview = () => {
  const [mlStatus, setMlStatus] = useState<string>('initializing');
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  useEffect(() => {
    let mounted = true;
    const refreshSummary = async () => {
      try {
        const summary = await mlBackendService.getDashboardSummary();
        if (mounted) { setDashboardSummary(summary); setMlStatus(summary.mlStatus ?? 'initializing'); }
      } catch { if (mounted) setMlStatus('unavailable'); }
    };
    void refreshSummary();
    const timer = window.setInterval(() => { void refreshSummary(); }, 15000);
    return () => { mounted = false; window.clearInterval(timer); };
  }, []);
  const { systemRiskScore: localSystemRiskScore, users, incidents, activeAnomalies, isAttackSimulated, setLocalFingerprintId, attackChainData, attackChainRunning, startAttackChain, stopAttackChain, resetSimulation, liveThreatData } = useSecurity();
  // Prefer the backend's shared summary contract so this page agrees with the sidebar and other dashboard views.
  const systemRiskScore = dashboardSummary?.systemRisk ?? dashboardSummary?.overall_risk.maximum ?? localSystemRiskScore;
  const activeAnomaliesCount = dashboardSummary?.anomalies ?? dashboardSummary?.network_anomalies ?? activeAnomalies;
  const activeIncidents = dashboardSummary?.openIncidents ?? dashboardSummary?.active_incident_count ?? incidents.filter(i => i.status === 'active').length;


  const threatLvl = getThreatLevel(systemRiskScore);
  const threatColors: Record<string, string> = {
    safe: 'hsl(var(--threat-safe))', low: 'hsl(var(--threat-safe))', medium: 'hsl(var(--threat-medium))',
    high: 'hsl(var(--threat-high))', critical: 'hsl(var(--threat-critical))',
  };
  const threatColor = threatColors[threatLvl];

  // ── Login state ──
  const [username, setUsername] = useState(import.meta.env.DEV ? 'sumukh' : '');
  const [password, setPassword] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [loginResult, setLoginResult] = useState<LoginResult | null>(null);
  const [loginError, setLoginError] = useState('');
  const [fpPreview, setFpPreview] = useState<FingerprintPreview | null>(null);
  const [showLoginXAI, setShowLoginXAI] = useState(false);
  const [showAttackXAI, setShowAttackXAI] = useState(false);
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(null);

  const handleLogin = async () => {
    if (!username.trim()) { setLoginError('Enter a username'); return; }
    if (!password) { setLoginError('Enter a password'); return; }
    setLoginError(''); setLoginResult(null); setIsLoggingIn(true);
    try {
      const fp = collectFingerprint();
      const fpId = getFingerprintId(fp);
      setFpPreview({ ...fp, fingerprintId: fpId });
      setLocalFingerprintId(fpId);
      const res = await mlBackendService.login<LoginResult>(username.trim(), password, fp, fpId);
      setLoginResult(res);
    } catch (err: unknown) {
      setLoginError((err instanceof Error ? err.message : '') || 'Login detection failed');
    } finally { setIsLoggingIn(false); }
  };

  const riskColor = (s: number) => s <= 30 ? '#00d4aa' : s <= 50 ? '#f5a623' : s <= 70 ? '#f57723' : s <= 85 ? '#ef4444' : '#dc2626';
  const riskLabel = (l: string) => ({ safe: 'SAFE', low: 'LOW', medium: 'MEDIUM', high: 'HIGH', critical: 'CRITICAL' }[l] || l.toUpperCase());

  return (
    <div className="p-4 lg:p-6 space-y-6 overflow-auto">
      {/* Header */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div>
              <h1 className="text-xl font-bold text-foreground">TrustNet AI Guardian</h1>
              <p className="text-xs text-muted-foreground font-mono mt-0.5">
                Real-time threat intelligence &middot; ML Powered: {mlStatus === 'available' ? '\u2713 Active' : '\u26A0 ' + mlStatus} &middot; Last updated: {new Date().toLocaleTimeString()}
              </p>
            </div>
            {isAttackSimulated && (
              <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg font-mono text-xs font-bold animate-threat-alert"
                style={{ background: 'hsl(var(--threat-critical) / 0.15)', border: '1px solid hsl(var(--threat-critical) / 0.5)', color: 'hsl(var(--threat-critical))' }}>
                <AlertTriangle className="w-3.5 h-3.5 animate-threat-pulse" /> ACTIVE THREAT
              </motion.div>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button onClick={resetSimulation}
              className="flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-bold transition-all bg-muted/30 text-muted-foreground border border-border hover:bg-muted/50 hover:text-foreground">
              <RotateCcw className="w-4 h-4" /> Reset System
            </button>
            {attackChainRunning ? (
              <button onClick={stopAttackChain}
                className="flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-bold transition-all bg-destructive/20 text-destructive border border-destructive/40 hover:bg-destructive/30">
                <StopCircle className="w-4 h-4" /> Stop Chain
              </button>
            ) : (
              <button onClick={startAttackChain}
                className="flex items-center gap-2 px-4 py-2 rounded-lg font-mono text-xs font-bold transition-all bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20">
                <Zap className="w-4 h-4" /> Simulate Attack Chain
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ATTACK CHAIN TIMELINE */}
      <AnimatePresence>
        {(attackChainRunning || attackChainData) && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <AttackChainTimeline data={attackChainData} running={attackChainRunning} showFullXAI={showAttackXAI} onToggleXAI={() => setShowAttackXAI(v => !v)} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* TOP: Login + Risk Meter + Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* LOGIN PANEL */}
        <div className="lg:col-span-4 space-y-4">
          <div className="cyber-card rounded-xl p-5">
            <div className="flex items-center gap-2 mb-4">
              <LogIn className="w-4 h-4 text-primary" />
              <span className="text-sm font-bold font-mono text-foreground">Real Login Detection</span>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-mono text-muted-foreground mb-1 block">USERNAME</label>
                <input
                  type="text" value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="sumukh / alex_chen / admin"
                  className="w-full px-3 py-2.5 rounded-lg bg-background border border-border text-foreground font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                  disabled={isLoggingIn}
                />
              </div>

              <div>
                <label className="text-[10px] font-mono text-muted-foreground mb-1 block">PASSWORD</label>
                <input
                  type="password" value={password}
                  onChange={e => setPassword(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleLogin()}
                  placeholder="Enter your password"
                  className="w-full px-3 py-2.5 rounded-lg bg-background border border-border text-foreground font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                  disabled={isLoggingIn}
                />
              </div>

              {loginError && (
                <div className="text-xs text-destructive font-mono flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" /> {loginError}
                </div>
              )}

              <button onClick={handleLogin} disabled={isLoggingIn}
                className="w-full py-2.5 rounded-lg font-mono text-sm font-bold transition-all flex items-center justify-center gap-2 bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                {isLoggingIn
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</>
                  : <><LogIn className="w-4 h-4" /> Login &amp; Detect</>}
              </button>
            </div>

            {/* Fingerprint preview */}
            {fpPreview && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="mt-4 pt-3 border-t border-border">
                <div className="text-[9px] font-mono text-muted-foreground mb-1.5 flex items-center gap-1">
                  <Fingerprint className="w-3 h-3" /> DEVICE FINGERPRINT
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[9px] font-mono">
                  <span className="text-muted-foreground">Platform</span><span className="text-foreground truncate">{fpPreview.platform}</span>
                  <span className="text-muted-foreground">Screen</span><span className="text-foreground">{fpPreview.screenResolution}</span>
                  <span className="text-muted-foreground">Timezone</span><span className="text-foreground">{fpPreview.timezone}</span>
                  <span className="text-muted-foreground">Type</span><span className="text-foreground">{fpPreview.deviceType}</span>
                  <span className="text-muted-foreground">Canvas</span><span className="text-foreground">{fpPreview.canvasHash}</span>
                  <span className="text-muted-foreground">GPU</span><span className="text-foreground truncate">{fpPreview.webglRenderer?.substring(0, 30)}</span>
                  <span className="text-muted-foreground">FP ID</span><span className="text-primary font-bold">{fpPreview.fingerprintId}</span>
                </div>
              </motion.div>
            )}

            {/* ML Result */}
            <AnimatePresence>
              {loginResult && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0 }}
                  className="mt-4 pt-3 border-t border-border space-y-3 overflow-hidden">

                  {/* If admin's own login (allowed + same device) → simple success */}
                  {loginResult.login_status === 'allowed' && loginResult.fingerprint_comparison?.is_same_device ? (
                    <div className="flex flex-col items-center gap-2 py-3">
                      <div className="w-10 h-10 rounded-full flex items-center justify-center"
                        style={{ background: 'hsl(var(--threat-safe) / 0.15)' }}>
                        <CheckCircle className="w-5 h-5" style={{ color: 'hsl(var(--threat-safe))' }} />
                      </div>
                      <span className="text-sm font-bold font-mono" style={{ color: '#00d4aa' }}>Login Successful</span>
                      <span className="text-[9px] font-mono text-muted-foreground text-center">Baseline stored. Now ask your friend to login from their device to trigger threat detection.</span>
                    </div>
                  ) : loginResult.login_status === 'denied' && !loginResult.prediction && !loginResult.ml_result ? (
                    /* Wrong password — no ML ran, show simple denied message */
                    <div className="flex flex-col items-center gap-2 py-3">
                      <div className="w-10 h-10 rounded-full flex items-center justify-center"
                        style={{ background: 'hsl(var(--threat-critical) / 0.15)' }}>
                        <AlertTriangle className="w-5 h-5 text-destructive" />
                      </div>
                      <span className="text-sm font-bold font-mono text-destructive">Access Denied</span>
                      <span className="text-[9px] font-mono text-muted-foreground text-center">{loginResult.message || 'Invalid username or password.'}</span>
                    </div>
                  ) : (
                  /* Attack detected (denied / restricted / different device) → full ML assessment */
                  <>
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] font-mono text-muted-foreground">ML RISK ASSESSMENT</span>
                    <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded"
                      style={{ color: riskColor(loginResult.risk_score), background: `${riskColor(loginResult.risk_score)}20` }}>
                      {riskLabel(loginResult.threat_level)}
                    </span>
                  </div>
                  <div className="flex items-baseline gap-1.5">
                    <span className="text-3xl font-bold font-mono" style={{ color: riskColor(loginResult.risk_score) }}>
                      {loginResult.risk_score}
                    </span>
                    <span className="text-xs text-muted-foreground font-mono">/ 100</span>
                  </div>
                  <div className="h-1.5 bg-background/50 rounded-full overflow-hidden">
                    <motion.div initial={{ width: 0 }} animate={{ width: `${loginResult.risk_score}%` }}
                      transition={{ duration: 1 }} className="h-full rounded-full"
                      style={{ background: riskColor(loginResult.risk_score) }} />
                  </div>

                  {/* ── ML PREDICTION (Supervised Classifier) ── */}
                  {loginResult.prediction && (
                    <div className="rounded-lg border p-2.5 space-y-2"
                      style={{
                        borderColor: loginResult.prediction.is_malicious ? '#ef4444' : '#00d4aa',
                        background: loginResult.prediction.is_malicious ? '#ef444410' : '#00d4aa10',
                      }}>
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] font-mono text-muted-foreground flex items-center gap-1">
                          <Cpu className="w-2.5 h-2.5" /> ML PREDICTION
                        </span>
                        <span className="text-[8px] font-mono text-muted-foreground">
                          {loginResult.prediction.model}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-lg font-black font-mono"
                          style={{ color: loginResult.prediction.is_malicious ? '#ef4444' : '#00d4aa' }}>
                          {loginResult.prediction.prediction}
                        </span>
                        <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                          style={{
                            background: loginResult.prediction.is_malicious ? '#ef444420' : '#00d4aa20',
                            color: loginResult.prediction.is_malicious ? '#ef4444' : '#00d4aa',
                          }}>
                          {loginResult.prediction.confidence}% confidence
                        </span>
                      </div>
                      {loginResult.prediction.is_malicious && (
                        <div className="text-[10px] font-mono font-bold text-destructive">
                          Attack Type: {loginResult.prediction.attack_label}
                        </div>
                      )}
                      <div className="text-[8px] font-mono text-muted-foreground leading-relaxed">
                        {loginResult.prediction.description}
                      </div>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[9px] font-mono text-muted-foreground">Action:</span>
                        <span className={`text-[10px] font-mono font-black px-2 py-0.5 rounded ${
                          loginResult.prediction.action === 'BLOCK' ? 'bg-destructive/20 text-destructive' :
                          loginResult.prediction.action === 'RESTRICT' ? 'bg-yellow-500/20 text-yellow-500' :
                          loginResult.prediction.action === 'FLAG' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-emerald-500/20 text-emerald-400'
                        }`}>
                          {loginResult.prediction.action}
                        </span>
                      </div>
                      {/* Per-class probabilities */}
                      {loginResult.prediction.probabilities && (
                        <div className="space-y-0.5 pt-1 border-t border-border/50">
                          <div className="text-[8px] font-mono text-muted-foreground">CLASS PROBABILITIES</div>
                          {Object.entries(loginResult.prediction.probabilities)
                            .sort(([,a], [,b]) => (b as number) - (a as number))
                            .map(([cls, prob]) => (
                            <div key={cls} className="flex items-center gap-1.5">
                              <span className="text-[7px] font-mono text-muted-foreground w-20 truncate">
                                {cls.replace('_', ' ')}
                              </span>
                              <div className="flex-1 h-1 bg-background/50 rounded-full overflow-hidden">
                                <div className="h-full rounded-full transition-all"
                                  style={{
                                    width: `${prob}%`,
                                    background: cls === 'benign' ? '#00d4aa' : '#ef4444',
                                    opacity: (prob as number) > 10 ? 1 : 0.4,
                                  }} />
                              </div>
                              <span className="text-[7px] font-mono w-8 text-right" style={{
                                color: cls === loginResult.prediction!.attack_type ? (loginResult.prediction!.is_malicious ? '#ef4444' : '#00d4aa') : 'inherit'
                              }}>
                                {prob}%
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Device comparison */}
                  {loginResult.fingerprint_comparison && (
                    <div>
                      <div className="text-[9px] font-mono text-muted-foreground mb-1 flex items-center gap-1">
                        <Fingerprint className="w-2.5 h-2.5" /> DEVICE MATCH
                      </div>
                      <div className="text-xs font-mono font-bold"
                        style={{ color: loginResult.fingerprint_comparison.is_same_device ? '#00d4aa' : '#ef4444' }}>
                        {loginResult.fingerprint_comparison.is_same_device ? 'Same Device' : 'DIFFERENT DEVICE'}
                        <span className="text-muted-foreground font-normal ml-1">
                          ({(loginResult.fingerprint_comparison.match_score * 100).toFixed(0)}%)
                        </span>
                      </div>
                      {loginResult.fingerprint_comparison.differences.length > 0 && (
                        <div className="mt-1 space-y-0.5 max-h-20 overflow-auto">
                          {loginResult.fingerprint_comparison.differences.slice(0, 4).map((d, i) => (
                            <div key={i} className="text-[8px] font-mono text-destructive/70 flex items-center gap-1">
                              <div className="w-1 h-1 rounded-full bg-destructive flex-shrink-0" /> <span className="truncate">{d}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Geo */}
                  <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[9px] font-mono">
                    <span className="text-muted-foreground flex items-center gap-1"><Globe className="w-2.5 h-2.5" /> IP</span>
                    <span className="text-foreground">{loginResult.attacker_ip || 'N/A'}</span>
                    <span className="text-muted-foreground">Location</span>
                    <span className="text-foreground">{loginResult.geo?.city}, {loginResult.geo?.country}</span>
                    <span className="text-muted-foreground">Geo Distance</span>
                    <span className="font-bold" style={{ color: (loginResult.geo_distance_km || 0) > 100 ? '#ef4444' : '#00d4aa' }}>
                      {(loginResult.geo_distance_km || 0).toLocaleString()} km
                    </span>
                    <span className="text-muted-foreground flex items-center gap-1"><Clock className="w-2.5 h-2.5" /> Login Hour</span>
                    <span className="text-foreground">{loginResult.login_hour}:00</span>
                  </div>

                  {/* IF result */}
                  {loginResult.ml_result && (
                    <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[9px] font-mono">
                      <span className="text-muted-foreground flex items-center gap-1"><Cpu className="w-2.5 h-2.5" /> IF Anomaly</span>
                      <span style={{ color: loginResult.ml_result.isolation_forest_anomaly ? '#ef4444' : '#00d4aa' }}>
                        {loginResult.ml_result.isolation_forest_anomaly ? 'YES' : 'No'}
                      </span>
                      <span className="text-muted-foreground">Confidence</span>
                      <span className="text-foreground">{loginResult.ml_result.confidence}%</span>
                      <span className="text-muted-foreground">Action</span>
                      <span className="text-foreground font-bold">{loginResult.ml_result.recommendation?.toUpperCase()}</span>
                    </div>
                  )}

                  {/* Anomalies */}
                  {loginResult.anomalies?.length > 0 && (
                    <div className="space-y-0.5">
                      <div className="text-[9px] font-mono text-muted-foreground flex items-center gap-1">
                        <AlertTriangle className="w-2.5 h-2.5" /> ANOMALIES
                      </div>
                      {loginResult.anomalies.slice(0, 3).map((a, i) => (
                        <div key={i} className="text-[8px] font-mono text-destructive/80 flex items-center gap-1">
                          <div className="w-1 h-1 rounded-full bg-destructive flex-shrink-0" /> {a}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Explainable AI Toggle */}
                  {loginResult.explanation && (
                    <div className="space-y-2">
                      <button onClick={() => setShowLoginXAI(v => !v)}
                        className="w-full flex items-center justify-center gap-2 py-2 rounded-lg border transition-all font-mono text-[10px] font-bold"
                        style={{
                          borderColor: showLoginXAI ? '#8b5cf660' : '#8b5cf640',
                          background: showLoginXAI ? '#8b5cf618' : '#8b5cf60a',
                          color: '#8b5cf6',
                        }}>
                        <Brain className="w-3.5 h-3.5" />
                        {showLoginXAI ? 'Hide' : 'View'} Explainable AI Analysis
                        {showLoginXAI ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                      </button>
                      <AnimatePresence>
                        {showLoginXAI && (
                          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                            <XAIPanel explanation={loginResult.explanation} />
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}
                  </>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Instructions */}
            <div className="mt-4 pt-3 border-t border-border text-[8px] font-mono text-muted-foreground space-y-0.5">
              <div>1. YOU login first - stores baseline (Risk = Low)</div>
              <div>2. FRIEND uses same username from their device - auto-detected</div>
              <div>3. Dashboard updates instantly via WebSocket</div>
            </div>
          </div>
        </div>

        {/* RISK METER CENTER */}
        <div className="lg:col-span-4">
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}
            className="cyber-card rounded-xl p-6 flex flex-col items-center"
            style={{
              borderColor: isAttackSimulated ? 'hsl(var(--threat-critical) / 0.5)' : undefined,
              boxShadow: isAttackSimulated ? '0 0 40px hsl(var(--threat-critical) / 0.2)' : undefined,
            }}>
            <div className="text-[10px] font-mono text-muted-foreground mb-2">SYSTEM THREAT SCORE</div>
            <div className="text-[9px] font-mono text-muted-foreground mb-2">{dashboardSummary?.dataSource === 'runtime' ? 'BACKEND SUMMARY' : dashboardSummary ? 'SAMPLE DATA' : 'LOADING SUMMARY'}</div>
            <RiskMeter score={systemRiskScore} size="lg" />
            <div className="mt-4 text-center">
              <div className="text-xs font-mono" style={{ color: threatColor }}>
                {isAttackSimulated ? 'ACTIVE BREACH DETECTED'
                  : systemRiskScore <= 30 ? 'All systems normal'
                  : systemRiskScore <= 60 ? 'Elevated risk' : 'Intervention required'}
              </div>
            </div>

            <div className="w-full mt-5 space-y-2">
              {[
                { label: 'Network Security', value: isAttackSimulated ? 12 : 94 },
                { label: 'Authentication', value: isAttackSimulated ? 8 : 98 },
                { label: 'Data Integrity', value: isAttackSimulated ? 45 : 100 },
                { label: 'Endpoint Health', value: isAttackSimulated ? 62 : 87 },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div className="flex justify-between text-[10px] font-mono text-muted-foreground mb-1">
                    <span>{label}</span>
                    <span style={{ color: value < 50 ? 'hsl(var(--threat-critical))' : value < 80 ? 'hsl(var(--threat-medium))' : 'hsl(var(--threat-safe))' }}>{value}%</span>
                  </div>
                  <div className="h-1 rounded-full bg-muted overflow-hidden">
                    <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${value}%` }}
                      transition={{ duration: 1, ease: 'easeOut' }}
                      style={{ background: value < 50 ? 'hsl(var(--threat-critical))' : value < 80 ? 'hsl(var(--threat-medium))' : 'hsl(var(--threat-safe))' }} />
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* STATS + CHART */}
        <div className="lg:col-span-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <StatCard title="ANOMALIES" value={activeAnomaliesCount} subtitle="Behavioral deviations" icon={Activity} color="hsl(var(--threat-medium))" delay={0.1} />
            <StatCard title="INCIDENTS" value={activeIncidents} subtitle="Require attention" icon={AlertTriangle}
              color={isAttackSimulated ? 'hsl(var(--threat-critical))' : 'hsl(var(--threat-high))'} delay={0.15} />
            <StatCard title="USERS" value={users.length} subtitle="Monitored" icon={Eye} color="hsl(var(--threat-critical))" delay={0.2} />
            <StatCard title="RESPONSES" value={isAttackSimulated ? 3 : 1} subtitle="Actions today" icon={isAttackSimulated ? Lock : CheckCircle}
              color={isAttackSimulated ? 'hsl(var(--threat-critical))' : 'hsl(var(--threat-safe))'} delay={0.25} />
          </div>

          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
            className="cyber-card rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <div className="text-sm font-medium">Risk Trend &mdash; 7 Day</div>
                <div className="text-[10px] text-muted-foreground font-mono">Historical series unavailable — no persisted trend endpoint</div>
              </div>
              <TrendingUp className="w-4 h-4 text-primary" />
            </div>
            <ResponsiveContainer width="100%" height={140}>
              <AreaChart data={[]}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--threat-critical))" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="hsl(var(--threat-critical))" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3,3" stroke="hsl(220 25% 12%)" />
                <XAxis dataKey="day" tick={{ fontSize: 10, fontFamily: 'IBM Plex Mono', fill: 'hsl(var(--muted-foreground))' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fontFamily: 'IBM Plex Mono', fill: 'hsl(var(--muted-foreground))' }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="riskScore" stroke="hsl(var(--threat-critical))" strokeWidth={2} fill="url(#riskGrad)" />
              </AreaChart>
            </ResponsiveContainer>
            <p className="mt-2 text-[10px] text-muted-foreground font-mono">No historical risk points are plotted. This panel will display data once a persisted risk-history API is available.</p>
          </motion.div>
        </div>
      </div>

      {/* USER CARDS */}
      <div>
        <div className="text-sm font-medium mb-3 flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary" /> Monitored Users &mdash; Cognitive Fingerprints
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">
          {users.map((user, i) => <UserCard key={user.id} user={user} index={i} />)}
        </div>
      </div>

      {/* ACTIVE INCIDENTS */}
      {incidents.filter(i => i.status === 'active').length > 0 && (
        <div>
          <div className="text-sm font-medium mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-destructive" /> Active Incidents
          </div>
          <div className="space-y-2">
            {incidents.filter(i => i.status === 'active').slice(0, 3).map((inc, i) => {
              const isExpanded = expandedIncidentId === inc.id;
              // Use live threat explanation if available, otherwise from attackChainData
              const xaiSource = liveThreatData?.explanation || attackChainData?.explanation || null;
              return (
              <motion.div key={inc.id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.1 }}
                className="cyber-card rounded-lg p-4 border-l-4"
                style={{ borderLeftColor: inc.riskScore > 70 ? 'hsl(var(--threat-critical))' : inc.riskScore > 40 ? 'hsl(var(--threat-medium))' : 'hsl(var(--threat-safe))' }}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono font-bold text-foreground">{inc.type}</span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded"
                    style={{
                      color: inc.riskScore > 70 ? 'hsl(var(--threat-critical))' : 'hsl(var(--threat-medium))',
                      background: inc.riskScore > 70 ? 'hsl(var(--threat-critical) / 0.1)' : 'hsl(var(--threat-medium) / 0.1)',
                    }}>
                    RISK {inc.riskScore}
                  </span>
                </div>
                <div className="text-[10px] font-mono text-muted-foreground">{inc.description}</div>
                <div className="text-[9px] font-mono text-muted-foreground mt-1">{inc.timestamp} &middot; {inc.userName}</div>

                {/* XAI Expand Button */}
                {xaiSource && (
                  <div className="mt-2 space-y-2">
                    <button onClick={() => setExpandedIncidentId(isExpanded ? null : inc.id)}
                      className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg border transition-all font-mono text-[9px] font-bold"
                      style={{
                        borderColor: isExpanded ? '#8b5cf660' : '#8b5cf630',
                        background: isExpanded ? '#8b5cf618' : '#8b5cf608',
                        color: '#8b5cf6',
                      }}>
                      <Brain className="w-3 h-3" />
                      {isExpanded ? 'Hide' : 'View'} Explainable AI
                      {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                          <XAIPanel explanation={xaiSource} />
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                )}
              </motion.div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default Overview;
