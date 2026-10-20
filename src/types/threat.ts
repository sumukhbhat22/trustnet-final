/** Shapes of live-threat / attack-chain events pushed by the backend (WebSocket and polling). */

export type ThreatExplanation = {
    csf?: {
      deviations: Array<{ field: string; baseline: string; current: string; weight: number; suspicion_score: number; changed: boolean }>;
      changed_count: number; total_fields: number; overall_suspicion: number;
      is_same_device: boolean; match_score_pct: number; summary: string;
    };
    classifier?: {
      global_feature_importance: Record<string, number>;
      classification_contributors: Record<string, number>;
      top_contributor: string; top_contributor_pct: number;
      reasoning_chain: string[];
      model_type: string; ensemble_weights: { random_forest: number; gradient_boosting: number };
    };
    risk_score?: {
      overall_score: number; threat_level: string;
      behavioral_breakdown: Array<{ factor: string; factor_key: string; deviation_pct: number; weight: number; contribution: number; severity: string }>;
      threat_amplifiers: Array<{ signal: string; impact: number; severity: string }>;
      propagation_influence: number;
      top_behavioral_deviations: string[];
      score_formula: string; summary: string;
    };
    propagation?: {
      compromised_nodes: string[];
      node_explanations: Array<{ node_id: string; node_label: string; is_compromised: boolean; direct_risk: number; propagated_risk: number; received_from_neighbors: number; criticality: string }>;
      edge_contributions: Array<{ from: string; to: string; trust_weight: number; risk_transferred: number }>;
      total_network_risk: number; affected_node_count: number; total_nodes: number;
      damping_factor: number; algorithm: string; summary: string;
    };
  };

export interface ThreatPrediction {
  prediction: string;
  attack_type: string;
  attack_label: string;
  confidence: number;
  action: string;
  description: string;
  is_malicious: boolean;
  probabilities: Record<string, number>;
  model: string;
  features_used: Record<string, number>;
}

/** Attack-chain simulation step or live-threat event. All fields optional: events differ by `type`. */
export interface ChainData {
  type?: string;
  phase?: string;
  phase_number?: number;
  phase_icon?: string;
  phase_name?: string;
  step_number?: number;
  step_name?: string;
  current_step_global?: number;
  total_steps?: number;
  risk_score?: number;
  threat_level?: string;
  anomalies?: string[];
  prediction?: ThreatPrediction;
  explanation?: ThreatExplanation;
  attack_type?: string;
  attacker_ip?: string;
  attacker_location?: string;
  geo?: { city?: string; country?: string };
  username?: string;
  target_user?: string;
  timestamp?: string;
  source_fingerprint_id?: string;
  compromised_nodes?: string[];
  active?: boolean;
  incident?: { id: string; threatLevel: string; [key: string]: unknown };
}
