import { motion } from 'framer-motion';
import { Settings, Zap, Shield, Sliders, ToggleLeft, ToggleRight, AlertTriangle, UserPlus, Users, ShieldCheck } from 'lucide-react';
import { useSecurity } from '@/store/securityStore';
import { useEffect, useState, type FormEvent } from 'react';
import { mlBackendService } from '@/services/mlBackendService';
import type { SessionUser, UserRole } from '@/services/authSession';
import AssetCriticalityEditor from '@/components/AssetCriticalityEditor';
import { useAuth } from '@/store/authContext';

const AdminPanel = () => {
  const { hasPermission } = useAuth();
  const {
    autonomousMode, setAutonomousMode,
    systemRiskScore, isAttackSimulated, simulateAttack, resetSimulation, isSimulating,
    activeAnomalies,
  } = useSecurity();

  const [sensitivity, setSensitivity] = useState(100); // score multiplier in % (50-150), saved to the backend risk policy
  const [policyVersion, setPolicyVersion] = useState<number | null>(null);
  const [riskPolicyLoaded, setRiskPolicyLoaded] = useState(false);
  const [restrictThreshold, setRestrictThreshold] = useState(61);
  const [policyLoaded, setPolicyLoaded] = useState(false);
  const [learningRate, setLearningRate] = useState(0.25);
  const [geoBlocking, setGeoBlocking] = useState(true);
  const [deviceTrust, setDeviceTrust] = useState(true);
  const [mlModel, setMlModel] = useState<'isolation-forest' | 'lstm'>('isolation-forest');
  const [isExporting, setIsExporting] = useState(false);
  const [isRecalibrating, setIsRecalibrating] = useState(false);
  const [actionMessage, setActionMessage] = useState('');
  const [actionError, setActionError] = useState(false);
  const [managedUsers, setManagedUsers] = useState<SessionUser[]>([]);
  const [accountEmail, setAccountEmail] = useState('');
  const [accountPassword, setAccountPassword] = useState('');
  const [accountRole, setAccountRole] = useState<Exclude<UserRole, 'admin'>>('analyst');
  const [accountBusy, setAccountBusy] = useState(false);
  const [accountMessage, setAccountMessage] = useState('');
  const [selectedHistoryUser, setSelectedHistoryUser] = useState('');
  const [loginAttempts, setLoginAttempts] = useState<Array<Record<string, unknown>>>([]);
  const [auditStatus, setAuditStatus] = useState<{ valid: boolean; checked: number; broken_event_id?: string | null; reason?: string; untracked_event_count?: number; head_hash?: string } | null>(null);
  const [auditBusy, setAuditBusy] = useState(false);
  const [demoBusy, setDemoBusy] = useState(false);
  const [demoMessage, setDemoMessage] = useState('');

  useEffect(() => {
    void mlBackendService.getUsers().then(setManagedUsers).catch((error) => {
      setAccountMessage(error instanceof Error ? error.message : 'Could not load accounts.');
    });
  }, []);

  useEffect(() => {
    void mlBackendService.getRestrictThreshold().then((policy) => {
      setRestrictThreshold(policy.restrict_threshold);
      setPolicyLoaded(true);
    }).catch((error) => {
      setActionMessage(error instanceof Error ? error.message : 'Could not load the persisted risk policy.');
      setActionError(true);
    });
  }, []);

  useEffect(() => {
    void mlBackendService.getRiskPolicy().then((policy) => {
      setSensitivity(Math.round(policy.sensitivity * 100));
      setLearningRate(policy.learning_rate);
      setGeoBlocking(policy.geo_enabled);
      setDeviceTrust(policy.device_trust_enabled);
      setPolicyVersion(policy.version);
      setRiskPolicyLoaded(true);
    }).catch((error) => {
      setActionMessage(error instanceof Error ? error.message : 'Could not load the saved risk policy.');
      setActionError(true);
    });
  }, []);

  useEffect(() => {
    if (!riskPolicyLoaded) return;
    const timer = window.setTimeout(() => {
      void mlBackendService.updateRiskPolicy({
        sensitivity: sensitivity / 100, learning_rate: learningRate,
        geo_enabled: geoBlocking, device_trust_enabled: deviceTrust,
      }).then((policy) => {
        setPolicyVersion(policy.version);
        setActionMessage(`Risk policy saved (version ${policy.version}); the risk engine reads it on every evaluation.`);
        setActionError(false);
      }).catch((error) => {
        setActionMessage(error instanceof Error ? error.message : 'Risk policy update failed.');
        setActionError(true);
      });
    }, 500);
    return () => window.clearTimeout(timer);
  }, [riskPolicyLoaded, sensitivity, learningRate, geoBlocking, deviceTrust]);

  useEffect(() => {
    if (!policyLoaded) return;
    const timer = window.setTimeout(() => {
      void mlBackendService.setRestrictThreshold(restrictThreshold)
        .then(() => {
          setActionMessage(`Restrict threshold saved at ${restrictThreshold}.`);
          setActionError(false);
        })
        .catch((error) => {
          setActionMessage(error instanceof Error ? error.message : 'Risk policy update failed.');
          setActionError(true);
        });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [policyLoaded, restrictThreshold]);

  const createAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAccountBusy(true);
    setAccountMessage('');
    try {
      await mlBackendService.registerUser({ email: accountEmail, password: accountPassword, role: accountRole });
      setManagedUsers(await mlBackendService.getUsers());
      setAccountEmail('');
      setAccountPassword('');
      setAccountMessage('Account created. The password was stored as a bcrypt hash.');
    } catch (error) {
      setAccountMessage(error instanceof Error ? error.message : 'Account creation failed.');
    } finally {
      setAccountBusy(false);
    }
  };

  const showLoginHistory = async (userId: string) => {
    setSelectedHistoryUser(userId);
    try {
      setLoginAttempts(await mlBackendService.getLoginHistory(userId));
    } catch (error) {
      setAccountMessage(error instanceof Error ? error.message : 'Could not load login history.');
    }
  };

  const exportSecurityReport = async () => {
    setIsExporting(true);
    setActionMessage('');
    setActionError(false);

    try {
      let baselineReport: {
        status: 'available' | 'unavailable';
        count: number | null;
        users: Array<{ username: string; deviceType?: string; location?: string; normalLoginHour?: number; createdAt?: string }>;
        note?: string;
      };

      try {
        const result = await mlBackendService.getBaselines();
        baselineReport = {
          status: 'available',
          count: result.count,
          users: Object.entries(result.baselines).map(([username, baseline]) => ({
            username,
            deviceType: baseline.device_type,
            location: baseline.location,
            normalLoginHour: baseline.normal_login_hour,
            createdAt: baseline.created_at,
          })),
        };
      } catch (error) {
        baselineReport = {
          status: 'unavailable',
          count: null,
          users: [],
          note: error instanceof Error ? error.message : 'Could not retrieve backend baselines.',
        };
      }

      const [summary, accounts, devices, incidentResult, topology] = await Promise.all([
        mlBackendService.getDashboardSummary(),
        mlBackendService.getUsers(),
        mlBackendService.getDevices(),
        mlBackendService.getIncidents(),
        mlBackendService.getNetworkTopology(),
      ]);

      const generatedAt = new Date().toISOString();
      const report = {
        reportTitle: 'TrustNet AI Guardian — Security Snapshot',
        generatedAt,
        dataScope: 'Backend snapshot of persisted demo accounts, devices, incidents, policies, topology, and summary metrics. Model state and local simulation controls remain process-local.',
        system: {
          ...summary,
          localSimulation: { active: isAttackSimulated, running: isSimulating },
        },
        dashboardControls: {
          autonomousMode,
          restrictThreshold,
          detectionSensitivity: sensitivity,
          learningRate,
          geoBlocking,
          deviceFingerprintTrust: deviceTrust,
          selectedModel: mlModel,
          note: 'These panel settings are frontend state and are included for reference; they are not all applied as backend model/policy configuration.',
        },
        users: accounts,
        devices: devices.devices,
        incidents: incidentResult.incidents,
        network: topology,
        backendDeviceBaselines: baselineReport,
      };

      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `trustnet-security-report-${generatedAt.replace(/[:.]/g, '-')}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);

      setActionMessage(baselineReport.status === 'available'
        ? 'Security snapshot exported. Backend baseline records are included.'
        : 'Security snapshot exported, but backend baselines could not be retrieved; the report marks them unavailable.');
      setActionError(baselineReport.status === 'unavailable');
    } catch (error) {
      setActionMessage(error instanceof Error ? `Report export failed: ${error.message}` : 'Report export failed.');
      setActionError(true);
    } finally {
      setIsExporting(false);
    }
  };

  const replayScenario = async (scenarioId: string) => {
    setDemoBusy(true); setDemoMessage(`Replaying ${scenarioId.replace(/_/g, ' ')} through the backend risk pipeline…`);
    try {
      const result = await mlBackendService.replayDemoScenario(scenarioId);
      setDemoMessage(`${result.scenario_title}: risk ${result.risk?.score ?? 'n/a'} (${result.risk?.level ?? 'unknown'}). ${result.incident ? `Incident ${result.incident.incident_label || result.incident.id} created/updated.` : 'No incident opened.'} Synthetic data only.`);
    } catch (error) {
      setDemoMessage(error instanceof Error ? error.message : 'Scenario replay failed. Check DEMO_MODE and administrator permissions.');
    } finally { setDemoBusy(false); }
  };

  const resetDemoData = async () => {
    if (!window.confirm('Reset demo activity? Accounts and append-only audit history are preserved. This works only when DEMO_MODE is enabled.')) return;
    setDemoBusy(true); setDemoMessage('Resetting demo activity…');
    try {
      const result = await mlBackendService.resetDemo();
      setDemoMessage(result.message);
    } catch (error) {
      setDemoMessage(error instanceof Error ? error.message : 'Demo reset failed. Check DEMO_MODE and administrator permissions.');
    } finally { setDemoBusy(false); }
  };

  const verifyAudit = async () => {
    setAuditBusy(true);
    setAuditStatus(null);
    try {
      const result = await mlBackendService.verifyAuditChain();
      setAuditStatus(result);
    } catch (error) {
      setAuditStatus({ valid: false, checked: 0, reason: error instanceof Error ? error.message : 'Audit verification failed.' });
    } finally {
      setAuditBusy(false);
    }
  };

  const recalibrateBaselines = async () => {
    const confirmed = window.confirm(
      'Clear every stored device baseline in the backend? Each account will establish a new baseline on its next successful login. This does not retrain the ML models.'
    );
    if (!confirmed) return;

    setIsRecalibrating(true);
    setActionMessage('');
    setActionError(false);
    try {
      const before = await mlBackendService.getBaselines();
      const resetResult = await mlBackendService.resetBaselines();
      if (resetResult.status !== 'all_cleared') {
        throw new Error(`Unexpected reset response: ${resetResult.status}`);
      }
      const after = await mlBackendService.getBaselines();
      if (after.count !== 0) {
        throw new Error(`Backend still reports ${after.count} baseline(s) after reset.`);
      }
      setActionMessage(`Cleared ${before.count} stored device baseline(s). A new successful login will create each user's baseline again.`);
    } catch (error) {
      setActionMessage(error instanceof Error ? `Baseline reset failed: ${error.message}` : 'Baseline reset failed.');
      setActionError(true);
    } finally {
      setIsRecalibrating(false);
    }
  };

  return (
    <div className="p-4 lg:p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold">Admin Panel</h1>
        <p className="text-xs text-muted-foreground font-mono mt-0.5">
          TrustNet account administration · Remaining controls are browser-local demo settings
        </p>
      </div>

      <div className="cyber-card rounded-xl p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-start gap-3">
          <ShieldCheck className="w-5 h-5 text-primary mt-0.5" />
          <div>
            <div className="text-sm font-semibold">Append-only audit chain</div>
            <p className="text-xs text-muted-foreground mt-1">Verify the persisted hash chain. This detects edits in the local chain; it is not externally anchored.</p>
            {auditStatus && <p className={`text-xs mt-2 ${auditStatus.valid ? 'text-emerald-400' : 'text-destructive'}`}>
              {auditStatus.valid ? `Valid · ${auditStatus.checked} entries checked` : `Verification failed · ${auditStatus.reason || 'unknown reason'} · event ${auditStatus.broken_event_id || 'untracked'}`}
            </p>}
          </div>
        </div>
        <button type="button" onClick={() => void verifyAudit()} disabled={auditBusy} className="px-4 py-2 rounded-md border border-primary/40 text-sm disabled:opacity-50">
          {auditBusy ? 'Verifying…' : 'Verify audit chain'}
        </button>
      </div>

      <div className="cyber-card rounded-xl p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            <div className="text-sm font-semibold">Synthetic demo controls</div>
            <p className="mt-1 text-xs text-muted-foreground">These requests use fictional scenario signals and the backend risk/incident pipeline. They are not live attacks.</p>
          </div>
          <button type="button" onClick={() => void resetDemoData()} disabled={demoBusy} className="rounded-md border border-destructive/40 px-3 py-2 text-xs text-destructive disabled:opacity-50">Reset demo activity</button>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          {[
            ['benign_baseline', 'Benign baseline'], ['brute_force', 'Brute force'], ['stolen_credentials', 'Stolen credentials'],
            ['data_exfiltration', 'Data exfiltration'], ['after_hours_sensitive_access', 'After-hours access'],
          ].map(([id, label]) => <button key={id} type="button" disabled={demoBusy} onClick={() => void replayScenario(id)} className="rounded-md border border-primary/30 px-3 py-2 text-xs disabled:opacity-50">{label}</button>)}
        </div>
        {demoMessage && <p className="mt-3 rounded-md bg-muted p-3 text-xs" role="status">{demoMessage}</p>}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Autonomous Mode */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card rounded-xl p-5"
          style={{
            borderColor: autonomousMode ? 'hsl(var(--primary) / 0.3)' : undefined,
          }}
        >
          <div className="flex items-center gap-2 mb-5">
            <Zap className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Digital Immune System</span>
          </div>
          <p className="mb-4 text-[10px] text-warning">These toggles are local demonstration state; they do not change backend enforcement. The backend kill switch and autonomy policy are controlled separately.</p>

          <div className="space-y-4">
            {/* Autonomous toggle */}
            <div className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">Autonomous Mode</div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Bounded response; destructive actions require human approval
                </div>
              </div>
              <button onClick={() => setAutonomousMode(!autonomousMode)} className="flex-shrink-0">
                {autonomousMode ? (
                  <ToggleRight className="w-8 h-8 text-primary" />
                ) : (
                  <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                )}
              </button>
            </div>

            {/* Geo blocking */}
            <div className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">Geo-Location Blocking</div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Block logins from unauthorized countries
                </div>
              </div>
              <button onClick={() => setGeoBlocking(!geoBlocking)} className="flex-shrink-0">
                {geoBlocking ? (
                  <ToggleRight className="w-8 h-8 text-primary" />
                ) : (
                  <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                )}
              </button>
            </div>

            {/* Device trust */}
            <div className="flex items-center justify-between p-3 rounded-lg border border-border">
              <div>
                <div className="text-sm font-medium">Device Fingerprint Trust</div>
                <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                  Flag logins from unrecognized devices
                </div>
              </div>
              <button onClick={() => setDeviceTrust(!deviceTrust)} className="flex-shrink-0">
                {deviceTrust ? (
                  <ToggleRight className="w-8 h-8 text-primary" />
                ) : (
                  <ToggleLeft className="w-8 h-8 text-muted-foreground" />
                )}
              </button>
            </div>
          </div>
        </motion.div>

        {/* Risk thresholds */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="cyber-card rounded-xl p-5"
        >
          <div className="flex items-center gap-2 mb-5">
            <Sliders className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Risk Thresholds</span>
          </div>

          <div className="space-y-5">
            {/* Restrict-tier threshold */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-medium">Restrict Threshold</div>
                <div className="font-mono text-sm font-bold text-destructive">{restrictThreshold}</div>
              </div>
              <input
                type="range"
                min={50}
                max={85}
                value={restrictThreshold}
                onChange={(e) => setRestrictThreshold(Number(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, hsl(var(--primary)) ${((restrictThreshold - 50) / 35) * 100}%, hsl(var(--muted)) ${((restrictThreshold - 50) / 35) * 100}%)`
                }}
              />
              <div className="flex justify-between text-[9px] font-mono text-muted-foreground mt-1">
                <span>50 (Sensitive)</span>
                <span>85 (Block boundary)</span>
              </div>
            </div>

            {/* Sensitivity */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-medium">Detection Sensitivity</div>
                <div className="font-mono text-sm font-bold text-warning">{sensitivity}%</div>
              </div>
              <input
                type="range"
                min={50}
                max={150}
                step={5}
                value={sensitivity}
                onChange={(e) => setSensitivity(Number(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, hsl(var(--threat-medium)) ${sensitivity - 50}%, hsl(var(--muted)) ${sensitivity - 50}%)`
                }}
              />
              <div className="flex justify-between text-[9px] font-mono text-muted-foreground mt-1">
                <span>50% (Fewer alerts)</span>
                <span>150% (More alerts)</span>
              </div>
            </div>

            {/* Learning rate */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-medium">Analyst-Verdict Learning Rate</div>
                <div className="font-mono text-sm font-bold text-primary">{learningRate.toFixed(2)}</div>
              </div>
              <input
                type="range"
                min={0}
                max={0.5}
                step={0.05}
                value={learningRate}
                onChange={(e) => setLearningRate(Number(e.target.value))}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
                style={{
                  background: `linear-gradient(to right, hsl(var(--primary)) ${(learningRate / 0.5) * 100}%, hsl(var(--muted)) ${(learningRate / 0.5) * 100}%)`
                }}
              />
            </div>

            <div className="text-[9px] font-mono text-muted-foreground">
              Sensitivity scales the fused risk score; learning rate sets how many points an analyst verdict moves that user&apos;s score (rate × 20, capped at ±15). {policyVersion !== null ? `Policy version ${policyVersion}.` : ''}
            </div>

            {/* Response level legend */}
            <div className="p-3 rounded-lg border border-border text-[10px] font-mono space-y-1.5">
              <div className="text-muted-foreground font-medium mb-2">AUTO-RESPONSE LEVELS:</div>
              {[
                { range: '0–30', action: 'Normal monitoring', color: 'hsl(var(--threat-safe))' },
                { range: `31–${restrictThreshold - 1}`, action: 'Review / step-up planned', color: 'hsl(var(--threat-medium))' },
                { range: `${restrictThreshold}–85`, action: 'Restrict · incident review', color: 'hsl(var(--threat-high))' },
                { range: '86–100', action: 'Human approval required for containment', color: 'hsl(var(--primary))' },
              ].map((level) => (
                <div key={level.range} className="flex items-center gap-2">
                  <span className="w-14" style={{ color: level.color }}>{level.range}</span>
                  <span className="text-muted-foreground">→</span>
                  <span style={{ color: level.color }}>{level.action}</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* ML Model selection */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="cyber-card rounded-xl p-5"
        >
          <div className="flex items-center gap-2 mb-5">
            <Shield className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Detection Engine</span>
          </div>

          <p className="mb-3 text-[10px] text-warning">Model selection is a UI demo only. Isolation Forest is the implemented detector; LSTM is planned and is not active.</p>
          <div className="space-y-3">
            {[
              {
                id: 'isolation-forest' as const,
                name: 'Isolation Forest',
                desc: 'Fast, real-time anomaly detection. Best for structured data patterns.',
                badge: 'ACTIVE',
              },
              {
                id: 'lstm' as const,
                name: 'LSTM Autoencoder',
                desc: 'Deep learning sequence analysis. Best for temporal behavioral patterns.',
                badge: 'PLANNED',
              },
            ].map((model) => (
              <button
                key={model.id}
                onClick={() => setMlModel(model.id)}
                className="w-full text-left p-4 rounded-lg border transition-all duration-200"
                style={{
                  background: mlModel === model.id ? 'hsl(var(--primary) / 0.08)' : 'hsl(var(--secondary))',
                  borderColor: mlModel === model.id ? 'hsl(var(--primary) / 0.5)' : 'hsl(var(--border))',
                }}
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="text-sm font-medium" style={{ color: mlModel === model.id ? 'hsl(var(--primary))' : undefined }}>
                    {model.name}
                  </div>
                  <div
                    className="text-[9px] font-mono px-2 py-0.5 rounded"
                    style={{
                      background: mlModel === model.id ? 'hsl(var(--primary) / 0.2)' : 'hsl(var(--border))',
                      color: mlModel === model.id ? 'hsl(var(--primary))' : 'hsl(var(--muted-foreground))',
                    }}
                  >
                    {model.badge}
                  </div>
                </div>
                <div className="text-[10px] text-muted-foreground">{model.desc}</div>
              </button>
            ))}
          </div>
        </motion.div>

        {/* Manual override + simulate */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="cyber-card rounded-xl p-5"
        >
          <div className="flex items-center gap-2 mb-5">
            <Settings className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium">Manual Controls</span>
          </div>

          <div className="space-y-3">
            {/* System status */}
            <div className="p-3 rounded-lg border border-border">
              <div className="text-[10px] font-mono text-muted-foreground mb-2">SYSTEM STATUS</div>
              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Risk Score:</span>
                  <span style={{ color: systemRiskScore > 70 ? 'hsl(var(--primary))' : 'hsl(var(--threat-safe))' }}>{systemRiskScore}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Mode:</span>
                  <span className="text-primary">{autonomousMode ? 'AUTO' : 'MANUAL'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Model:</span>
                  <span className="text-primary">{mlModel === 'isolation-forest' ? 'ISO-FOREST' : 'LSTM'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Threshold:</span>
                  <span className="text-warning">{restrictThreshold}</span>
                </div>
              </div>
            </div>

            {/* Simulate button */}
            <motion.button
              whileHover={{ scale: 1.01 }}
              whileTap={{ scale: 0.99 }}
              onClick={isAttackSimulated ? resetSimulation : simulateAttack}
              disabled={isSimulating}
              className="w-full py-3 rounded-lg font-mono text-sm font-bold transition-all flex items-center justify-center gap-2 disabled:opacity-60"
              style={isAttackSimulated ? {
                background: 'hsl(var(--threat-safe) / 0.1)',
                border: '1px solid hsl(var(--threat-safe) / 0.4)',
                color: 'hsl(var(--threat-safe))',
              } : {
                background: 'hsl(var(--primary) / 0.15)',
                border: '1px solid hsl(var(--primary) / 0.5)',
                color: 'hsl(var(--primary))',
                boxShadow: '0 0 30px hsl(var(--primary) / 0.25)',
              }}
            >
              <AlertTriangle className="w-4 h-4" />
              {isSimulating ? 'SIMULATING ATTACK...' : isAttackSimulated ? 'RESET — CLEAR INCIDENT' : 'SIMULATE COMPROMISED LOGIN'}
            </motion.button>

            <button
              type="button"
              onClick={exportSecurityReport}
              disabled={isExporting}
              className="w-full py-2.5 rounded-lg font-mono text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 transition-all"
            >
              {isExporting ? 'EXPORTING REPORT…' : 'EXPORT SECURITY REPORT (JSON)'}
            </button>

            <button
              type="button"
              onClick={recalibrateBaselines}
              disabled={isRecalibrating}
              className="w-full py-2.5 rounded-lg font-mono text-xs font-medium border border-border text-muted-foreground hover:text-foreground hover:border-warning/30 transition-all"
            >
              {isRecalibrating ? 'CLEARING DEVICE BASELINES…' : 'RECALIBRATE DEVICE BASELINES'}
            </button>
            {actionMessage && (
              <div role={actionError ? 'alert' : 'status'} className={`rounded-lg border p-3 text-[10px] font-mono leading-relaxed ${actionError ? 'border-destructive/40 bg-destructive/10 text-destructive' : 'border-success/30 bg-success/10 text-success'}`}>
                {actionMessage}
              </div>
            )}
          </div>
        </motion.div>
      </div>

      <section className="cyber-card rounded-xl p-5 space-y-5" aria-labelledby="user-management-heading">
        <div className="flex items-center gap-2"><Users className="w-4 h-4 text-primary" /><div><h2 id="user-management-heading" className="text-sm font-semibold">User Accounts &amp; Audit Trail</h2><p className="text-[10px] text-muted-foreground font-mono mt-1">RBAC roles · bcrypt password hashes · recent authentication attempts</p></div></div>
        <form onSubmit={(event) => void createAccount(event)} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
          <label className="tn-field !mb-0"><span className="text-[10px] text-muted-foreground">Email</span><input type="email" required value={accountEmail} onChange={(event) => setAccountEmail(event.target.value)} placeholder="analyst@example.org" /></label>
          <label className="tn-field !mb-0"><span className="text-[10px] text-muted-foreground">Temporary password · 12+ characters</span><input type="password" required minLength={12} value={accountPassword} onChange={(event) => setAccountPassword(event.target.value)} autoComplete="new-password" /></label>
          <label className="tn-field !mb-0"><span className="text-[10px] text-muted-foreground">Role</span><select className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" value={accountRole} onChange={(event) => setAccountRole(event.target.value as Exclude<UserRole, 'admin'>)}><option value="analyst">Analyst</option><option value="viewer">Viewer</option></select></label>
          <button className="btn btn-primary" type="submit" disabled={accountBusy}><UserPlus size={15} />{accountBusy ? 'Creating…' : 'Create account'}</button>
        </form>
        {accountMessage && <div className="text-xs font-mono text-muted-foreground" role="status">{accountMessage}</div>}
        <div className="overflow-auto">
          <table className="tn-table"><thead><tr><th>Email</th><th>Role</th><th>Active</th><th>Last login</th><th>Audit</th></tr></thead><tbody>
            {managedUsers.map((managedUser) => <tr key={managedUser.id}><td>{managedUser.email}</td><td className="uppercase">{managedUser.role}</td><td>{managedUser.is_active ? 'Yes' : 'No'}</td><td>{managedUser.last_login_at ? new Date(managedUser.last_login_at).toLocaleString() : 'Never'}</td><td><button type="button" className="text-primary hover:underline" onClick={() => void showLoginHistory(managedUser.id)}>View attempts</button></td></tr>)}
            {!managedUsers.length && <tr><td colSpan={5} className="text-muted-foreground">No account records loaded.</td></tr>}
          </tbody></table>
        </div>
        {selectedHistoryUser && <div className="max-h-56 overflow-auto rounded-lg border border-border p-3"><div className="text-xs font-mono text-muted-foreground mb-2">LOGIN HISTORY · {selectedHistoryUser}</div>{loginAttempts.map((attempt, index) => <div key={`${String(attempt.timestamp)}-${index}`} className="flex flex-wrap gap-x-3 gap-y-1 border-t border-border/60 py-2 text-[10px] font-mono"><span>{String(attempt.timestamp)}</span><span style={{ color: attempt.success ? 'hsl(var(--threat-safe))' : 'hsl(var(--threat-critical))' }}>{attempt.success ? 'SUCCESS' : 'FAILED'}</span><span>{String(attempt.ip ?? 'unknown')}</span><span>{String(attempt.reason ?? '—')}</span></div>)}{!loginAttempts.length && <div className="text-xs text-muted-foreground">No recorded attempts.</div>}</div>}
      </section>
      <AssetCriticalityEditor canEdit={hasPermission('manage_users')} />
    </div>
  );
};

export default AdminPanel;
