import { motion, AnimatePresence } from 'framer-motion';
import { Shield, X, AlertTriangle } from 'lucide-react';
import { useSecurity } from '@/store/securityStore';

export const AlertPopup = () => {
  const { showAlert, alertMessage, alertRiskScore, dismissAlert } = useSecurity();

  return (
    <AnimatePresence>
      {showAlert && (
        <>
          {/* Overlay */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={dismissAlert}
          />

          {/* Alert Panel */}
          <motion.div
            initial={{ scale: 0.8, opacity: 0, y: -50 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.8, opacity: 0, y: -50 }}
            transition={{ type: 'spring', stiffness: 300, damping: 25 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 overflow-y-auto"
          >
            <div
              className="w-[480px] max-w-full rounded-xl border-2 p-5 animate-threat-alert max-h-[90vh] overflow-y-auto"
              style={{
                background: 'hsl(var(--card))',
                borderColor: 'hsl(var(--destructive))',
              }}
            >
              {/* Header */}
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <div
                      className="w-12 h-12 rounded-full flex items-center justify-center"
                      style={{ background: 'hsl(var(--destructive) / 0.2)' }}
                    >
                      <AlertTriangle className="w-6 h-6 text-destructive" />
                    </div>
                    <div className="absolute inset-0 rounded-full pulse-ring border-2 border-destructive opacity-60" />
                  </div>
                  <div>
                    <div className="font-mono text-xs text-destructive/70 mb-1">DIGITAL IMMUNE SYSTEM</div>
                    <div className="font-mono font-bold text-destructive text-sm">THREAT DETECTED</div>
                  </div>
                </div>
                <button
                  onClick={dismissAlert}
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Alert Content */}
              <div
                className="rounded-lg p-4 mb-4 border font-mono text-sm"
                style={{
                  background: 'hsl(var(--threat-critical) / 0.08)',
                  borderColor: 'hsl(var(--threat-critical) / 0.3)',
                }}
              >
                {alertMessage.split('\n').map((line, i) => (
                  <div key={i} className={`${i === 0 ? 'text-destructive font-bold text-base mb-2' : 'text-destructive/80 text-xs mt-1'}`}>
                    {line}
                  </div>
                ))}
              </div>

              {/* Risk Score */}
              <div
                className="rounded-lg p-3 mb-4 flex items-center justify-between"
                style={{ background: 'hsl(var(--threat-critical) / 0.1)' }}
              >
                <span className="text-xs text-muted-foreground font-mono">RISK SCORE</span>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-destructive animate-threat-pulse" />
                  <span className="text-2xl font-bold font-mono text-destructive">{alertRiskScore || 94}</span>
                  <span className="text-xs text-destructive/60">/ 100</span>
                </div>
              </div>

              {/* Auto-response */}
              <div
                className="rounded-lg p-3 mb-5 border text-xs font-mono"
                style={{
                  background: 'hsl(var(--threat-critical) / 0.05)',
                  borderColor: 'hsl(var(--threat-critical) / 0.2)',
                }}
              >
                <div className="text-muted-foreground mb-1">AUTO-RESPONSE TRIGGERED:</div>
                <div className="text-destructive">🔴 Session terminated · Account blocked · Security team alerted</div>
              </div>

              <button
                onClick={dismissAlert}
                className="w-full py-2 rounded-lg font-mono text-sm font-medium transition-all"
                style={{
                  background: 'hsl(var(--threat-critical) / 0.2)',
                  color: 'hsl(var(--destructive))',
                  border: '1px solid hsl(var(--threat-critical) / 0.4)',
                }}
              >
                ACKNOWLEDGE INCIDENT
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
