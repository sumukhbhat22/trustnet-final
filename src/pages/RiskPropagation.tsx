import { motion } from 'framer-motion';
import { GitBranch, AlertTriangle, Info } from 'lucide-react';
import { NetworkGraph } from '@/components/NetworkGraph';
import { useSecurity } from '@/store/securityStore';
import { RiskMeter } from '@/components/RiskMeter';

const RiskPropagation = () => {
  const { nodes, isAttackSimulated, systemRiskScore } = useSecurity();
  const compromisedNodes = nodes.filter(n => n.compromised);
  const totalRisk = Math.round(nodes.reduce((sum, n) => sum + n.propagationRisk, 0) / nodes.length);

  return (
    <div className="p-4 lg:p-6 space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold">Risk Propagation Graph</h1>
          <p className="text-xs text-muted-foreground font-mono mt-0.5">
            NetworkX-based attack path simulation · Real-time propagation modeling
          </p>
        </div>
        {isAttackSimulated && (
          <motion.div
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="text-xs font-mono px-3 py-2 rounded-lg"
            style={{
              background: 'hsl(var(--threat-critical) / 0.15)',
              border: '1px solid hsl(var(--threat-critical) / 0.5)',
              color: 'hsl(var(--threat-critical))',
            }}
          >
            <AlertTriangle className="w-3.5 h-3.5 inline mr-1 animate-threat-pulse" />
            ATTACK PATH ACTIVE — {compromisedNodes.length} NODES COMPROMISED
          </motion.div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          {
            label: 'TOTAL NODES',
            value: nodes.length,
            color: 'hsl(var(--threat-critical))',
          },
          {
            label: 'COMPROMISED',
            value: compromisedNodes.length,
            color: compromisedNodes.length > 0 ? 'hsl(var(--threat-critical))' : 'hsl(var(--threat-safe))',
          },
          {
            label: 'AVG PROPAGATION RISK',
            value: `${totalRisk}%`,
            color: totalRisk > 50 ? 'hsl(var(--threat-medium))' : 'hsl(var(--threat-safe))',
          },
          {
            label: 'SPREAD PROBABILITY',
            value: isAttackSimulated ? '87%' : '3%',
            color: isAttackSimulated ? 'hsl(var(--threat-critical))' : 'hsl(var(--threat-safe))',
          },
        ].map((stat) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="cyber-card rounded-lg p-4"
          >
            <div className="text-[9px] font-mono text-muted-foreground mb-2">{stat.label}</div>
            <div className="text-2xl font-bold font-mono" style={{ color: stat.color }}>{stat.value}</div>
          </motion.div>
        ))}
      </div>

      {/* Main graph */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
        className="cyber-card rounded-xl p-4"
        style={{
          borderColor: isAttackSimulated ? 'hsl(var(--threat-critical) / 0.3)' : undefined,
        }}
      >
        <div className="flex items-center gap-2 mb-4">
          <GitBranch className="w-4 h-4 text-primary" />
          <span className="text-sm font-medium">Infrastructure Attack Surface Map</span>
          {isAttackSimulated && (
            <span className="ml-auto text-[9px] font-mono px-2 py-0.5 rounded"
              style={{ background: 'hsl(var(--threat-critical) / 0.1)', color: 'hsl(var(--threat-critical))', border: '1px solid hsl(var(--threat-critical) / 0.3)' }}>
              LIVE ATTACK SIMULATION
            </span>
          )}
        </div>
        <NetworkGraph width={800} height={480} />
      </motion.div>

      {/* Node details */}
      {isAttackSimulated && compromisedNodes.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="cyber-card rounded-xl p-5 border"
          style={{ borderColor: 'hsl(var(--threat-critical) / 0.4)' }}
        >
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-4 h-4 text-destructive" />
            <span className="text-sm font-medium text-destructive">Compromised Nodes — Attack Path Analysis</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {compromisedNodes.map((node) => (
              <div
                key={node.id}
                className="rounded-lg p-3 border"
                style={{
                  background: 'hsl(var(--threat-critical) / 0.1)',
                  borderColor: 'hsl(var(--threat-critical) / 0.3)',
                }}
              >
                <div className="text-[9px] font-mono text-muted-foreground mb-1">{node.type.toUpperCase()}</div>
                <div className="text-sm font-medium text-destructive">{node.label}</div>
                <div className="mt-2">
                  <div className="text-[10px] font-mono text-muted-foreground mb-1">Propagation Risk</div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1 rounded-full bg-muted overflow-hidden">
                      <motion.div
                        className="h-full rounded-full bg-destructive"
                        initial={{ width: 0 }}
                        animate={{ width: `${node.propagationRisk}%` }}
                        transition={{ duration: 0.8 }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-destructive">{node.propagationRisk}%</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 p-3 rounded-lg text-xs font-mono"
            style={{ background: 'hsl(var(--threat-critical) / 0.07)', borderColor: 'hsl(var(--threat-critical) / 0.2)' }}>
            <div className="text-destructive font-bold mb-1">PREDICTED ATTACK PATH:</div>
            <div className="text-destructive/70">
              Alex Chen [User] → Web App [Entry Point] → Core Server [Lateral Movement] → Analytics DB [Data Exfiltration]
            </div>
            <div className="mt-1 text-muted-foreground">
              Propagation probability: <span className="text-destructive">87.4%</span> ·
              Estimated time to full breach: <span className="text-warning">~14 minutes</span>
            </div>
          </div>
        </motion.div>
      )}

      {/* Info when no attack */}
      {!isAttackSimulated && (
        <div className="flex items-start gap-3 p-4 rounded-lg border border-border text-xs text-muted-foreground font-mono">
          <Info className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
          <div>
            <span className="text-primary">TIP:</span> Click "SIMULATE ATTACK" in the top bar to see real-time attack path propagation.
            The graph will highlight compromised nodes and predicted lateral movement paths.
          </div>
        </div>
      )}
    </div>
  );
};

export default RiskPropagation;
