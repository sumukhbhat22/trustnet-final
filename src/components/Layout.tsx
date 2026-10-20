import { useEffect, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, LayoutDashboard, Activity, GitBranch, Radio,
  AlertTriangle, Settings, Zap, ChevronLeft, ChevronRight, Menu, X, Search, LogOut, UserRound, Crosshair, Wifi
} from 'lucide-react';
import { useSecurity } from '@/store/securityStore';
import { useAuth } from '@/store/authContext';
import { mlBackendService, type WsState } from '@/services/mlBackendService';
import NotificationBell from '@/components/NotificationBell';

const navItems = [
  { to: '/overview', icon: LayoutDashboard, label: 'Overview', exact: true },
  { to: '/behavior', icon: Activity, label: 'Behavior Analytics' },
  { to: '/network-activity', icon: Radio, label: 'Network Activity' },
  { to: '/propagation', icon: GitBranch, label: 'Risk Propagation' },
  { to: '/incidents', icon: AlertTriangle, label: 'Incident Center' },
  { to: '/attacker-simulator', icon: Crosshair, label: 'Attacker Simulator' },
  { to: '/csi-simulator', icon: Wifi, label: 'CSI Simulator' },
  { to: '/admin', icon: Settings, label: 'Admin Panel' },
];

const getThreatColor = (score: number) => {
  if (score <= 30) return 'text-success';
  if (score <= 60) return 'text-warning';
  if (score <= 85) return 'text-[hsl(var(--threat-high))]';
  return 'text-destructive';
};

interface LayoutProps {
  children: ReactNode;
}

export const Layout = ({ children }: LayoutProps) => {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState('');
  const [commandIndex, setCommandIndex] = useState(0);
  const { systemRiskScore, activeAnomalies, isAttackSimulated, simulateAttack, resetSimulation, isSimulating } = useSecurity();
  const [wsState, setWsState] = useState<WsState>(mlBackendService.getWsState());
  const [lastMessageAt, setLastMessageAt] = useState<number | null>(null);
  useEffect(() => mlBackendService.onWsState((state, at) => { setWsState(state); setLastMessageAt(at); }), []);
  const wsBadge = {
    live: { label: 'LIVE', color: 'hsl(var(--primary))' },
    reconnecting: { label: 'RECONNECTING', color: 'hsl(var(--threat-low))' },
    offline: { label: 'OFFLINE', color: 'hsl(var(--threat-critical))' },
  }[wsState];
  const location = useLocation();
  const navigate = useNavigate();
  const { user, hasPermission } = useAuth();
  const visibleNavItems = navItems.filter(({ to }) => to !== '/admin' || hasPermission('manage_users'));
  const commandItems = visibleNavItems.filter(({ label }) => label.toLowerCase().includes(commandQuery.trim().toLowerCase()));

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen((open) => !open);
      }
      if (event.key === 'Escape') setCommandOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    setCommandIndex(0);
  }, [commandQuery, commandOpen]);

  const openCommandCenter = () => {
    setCommandQuery('');
    setCommandIndex(0);
    setCommandOpen(true);
  };

  const runCommand = (to: string) => {
    navigate(to);
    setCommandOpen(false);
  };

  const signOut = async () => {
    await mlBackendService.logout();
    navigate('/login', { replace: true });
  };

  const onCommandKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setCommandIndex((index) => commandItems.length ? (index + 1) % commandItems.length : 0);
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setCommandIndex((index) => commandItems.length ? (index - 1 + commandItems.length) % commandItems.length : 0);
    }
    if (event.key === 'Enter' && commandItems[commandIndex]) {
      event.preventDefault();
      runCommand(commandItems[commandIndex].to);
    }
  };

  const threatColor = getThreatColor(systemRiskScore);

  return (
    <div className="relative flex h-screen overflow-hidden bg-background cyber-grid">
      <div className="space-backdrop" aria-hidden="true">
        <div className="sb-stars sb-stars-a" />
        <div className="sb-stars sb-stars-b" />
        <div className="sb-nebula" />
        <div className="sb-planet sb-planet-gas"><span className="sb-ring" /></div>
        <div className="sb-planet sb-planet-moon" />
        <div className="sb-planet sb-planet-ice" />
      </div>
      {/* Mobile overlay */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 z-40 lg:hidden"
            onClick={() => setMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside
        animate={{ width: collapsed ? 64 : 240 }}
        transition={{ duration: 0.3, ease: 'easeInOut' }}
        className="relative hidden lg:flex flex-col h-full border-r border-border z-30 flex-shrink-0 backdrop-blur-md"
        style={{ background: 'hsl(var(--sidebar-background) / 0.6)' }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 p-4 border-b border-border h-16 flex-shrink-0">
          <Shield className="w-5 h-5 flex-shrink-0 text-primary" strokeWidth={1.5} />
          <AnimatePresence>
            {!collapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                transition={{ duration: 0.2 }}
              >
                <div className="text-sm font-normal uppercase tracking-[0.4em] text-foreground">TrustNet AI</div>
                <div className="mt-0.5 text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">Agentic SOC</div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
          {visibleNavItems.map(({ to, icon: Icon, label }) => {
            const isActive = to === '/overview' ? location.pathname === '/overview' : location.pathname.startsWith(to);
            return (
              <NavLink
                key={to}
                to={to}
                className={`
                  flex items-center gap-3 px-3 py-2.5 transition-colors duration-200 group relative
                  ${isActive
                    ? 'bg-primary/[0.06] text-primary'
                    : 'text-muted-foreground hover:text-foreground'
                  }
                `}
              >
                {isActive && <span className="absolute inset-y-0 left-0 w-0.5 bg-primary" aria-hidden="true" />}
                <Icon className={`w-4 h-4 flex-shrink-0 relative z-10 ${isActive ? 'text-primary' : ''}`} />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="text-sm font-normal relative z-10 whitespace-nowrap"
                    >
                      {label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </NavLink>
            );
          })}
        </nav>

        {/* Signed-in account: keep identity and sign-out with the sidebar footer. */}
        <div className={`mx-2 mb-2 rounded-sm border border-border bg-card ${collapsed ? 'p-2' : 'p-3'}`}>
          <div className={`flex items-center ${collapsed ? 'justify-center' : 'gap-2.5'}`}>
            <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-primary">
              <UserRound className="h-4 w-4" />
            </div>
            {!collapsed && <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-xs font-medium text-foreground" title={user?.email}>{user?.email}</div>
              <div className="mt-1 text-[9px] font-mono uppercase tracking-wider text-muted-foreground">{user?.role} account</div>
            </div>}
          </div>
          <button
            type="button"
            onClick={() => void signOut()}
            title={collapsed ? 'Sign out' : undefined}
            aria-label="Sign out"
            className={`mt-2 flex w-full items-center justify-center gap-2 rounded-md border border-border/70 px-2 py-1.5 text-[10px] font-mono text-muted-foreground transition-colors hover:border-destructive/40 hover:bg-destructive/10 hover:text-destructive ${collapsed ? 'mx-auto w-9' : ''}`}
          >
            <LogOut className="h-3.5 w-3.5" />
            {!collapsed && <span>SIGN OUT</span>}
          </button>
        </div>

        {/* Risk indicator */}
        <AnimatePresence>
          {!collapsed && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="p-3 m-2 rounded-sm border"
              style={{
                background: isAttackSimulated ? 'hsl(var(--threat-critical) / 0.1)' : 'hsl(var(--threat-safe) / 0.05)',
                borderColor: isAttackSimulated ? 'hsl(var(--threat-critical) / 0.3)' : 'hsl(var(--threat-safe) / 0.2)',
              }}
            >
              <div className="text-[9px] font-mono text-muted-foreground mb-1">SYSTEM RISK</div>
              <div className={`text-2xl font-bold font-mono ${threatColor}`}>{systemRiskScore}</div>
              <div className="text-[9px] font-mono text-muted-foreground mt-1">{activeAnomalies} anomalies active</div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Collapse button */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="absolute -right-3 top-20 w-6 h-6 rounded-full border border-border flex items-center justify-center text-muted-foreground hover:text-primary transition-colors z-10"
          style={{ background: 'hsl(var(--sidebar-background))' }}
        >
          {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
        </button>
      </motion.aside>

      {/* Mobile Sidebar */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.aside
            initial={{ x: -240 }}
            animate={{ x: 0 }}
            exit={{ x: -240 }}
            transition={{ duration: 0.3 }}
            className="fixed left-0 top-0 h-full w-60 flex flex-col border-r border-border z-50 lg:hidden"
            style={{ background: 'hsl(var(--sidebar-background))' }}
          >
            <div className="flex items-center justify-between p-4 border-b border-border h-16">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                <span className="font-bold text-sm">TrustNet AI</span>
              </div>
              <button onClick={() => setMobileOpen(false)}>
                <X className="w-4 h-4 text-muted-foreground" />
              </button>
            </div>
            <nav className="flex-1 p-2 space-y-1">
              {visibleNavItems.map(({ to, icon: Icon, label }) => (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all
                    ${isActive ? 'bg-primary/10 text-primary' : 'text-sidebar-foreground hover:bg-sidebar-accent'}`
                  }
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </NavLink>
              ))}
            </nav>
            <div className="mx-3 mb-2 rounded-lg border border-border/70 bg-white/[0.03] p-3">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full border border-primary/30 bg-primary/10 text-primary"><UserRound className="h-4 w-4" /></div>
                <div className="min-w-0 leading-tight">
                  <div className="truncate text-xs font-medium text-foreground">{user?.email}</div>
                  <div className="mt-1 text-[9px] font-mono uppercase tracking-wider text-muted-foreground">{user?.role} account</div>
                </div>
              </div>
              <button type="button" onClick={() => void signOut()} className="mt-3 flex w-full items-center justify-center gap-2 rounded-md border border-border/70 px-2 py-2 text-[10px] font-mono text-muted-foreground hover:border-destructive/40 hover:bg-destructive/10 hover:text-destructive">
                <LogOut className="h-3.5 w-3.5" /> SIGN OUT
              </button>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      {/* Main area */}
      <div className="relative z-10 flex-1 flex flex-col min-h-0 overflow-hidden">
        {/* Top bar */}
        <header
          className="h-16 flex-shrink-0 flex items-center justify-between px-4 lg:px-6 border-b border-border backdrop-blur-md"
          style={{ background: 'hsl(var(--background) / 0.45)' }}
        >
          <div className="flex min-w-0 items-center gap-2">
            <button
              type="button"
              className="command-trigger"
              onClick={openCommandCenter}
              aria-label="Open command center"
            >
              <Search className="w-3.5 h-3.5" />
              <span className="hidden lg:inline">COMMAND CENTER</span>
              <kbd className="hidden sm:inline">CTRL K</kbd>
            </button>
            <button className="lg:hidden text-muted-foreground" onClick={() => setMobileOpen(true)}>
              <Menu className="w-5 h-5" />
            </button>
          </div>

          <div className="flex flex-shrink-0 items-center gap-2 sm:gap-3">
            <NotificationBell />
            {/* Live indicator: reflects the real WebSocket state (live / reconnecting with backoff / offline) */}
            <div className="flex items-center gap-1.5 px-2 py-1 rounded-sm font-mono text-[10px] uppercase tracking-[0.16em] border"
              title={lastMessageAt ? `Last message ${new Date(lastMessageAt).toLocaleTimeString()}` : 'No live message received yet'}
              style={{ background: 'transparent', borderColor: wsBadge.color, color: wsBadge.color }}
            >
              <span className={`dot ${wsState === 'live' ? 'pulse' : ''}`} style={{ background: wsBadge.color }} />
              <span className="hidden sm:inline">{wsBadge.label}</span>
            </div>

            {/* SIMULATE ATTACK BUTTON */}
            {hasPermission('approve_incidents') && <button
              type="button"
              onClick={isAttackSimulated ? resetSimulation : simulateAttack}
              disabled={isSimulating}
              title={isSimulating ? 'Simulating attack' : isAttackSimulated ? 'Reset system' : 'Simulate attack'}
              className={`flex items-center gap-2 rounded-sm border bg-transparent p-2 sm:px-3 sm:py-1.5 font-mono text-[11px] font-medium uppercase tracking-[0.16em] transition-colors duration-200 disabled:opacity-60 ${isAttackSimulated
                ? 'border-[hsl(var(--threat-safe))] text-[hsl(var(--threat-safe))] hover:bg-[hsl(var(--threat-safe))] hover:text-[hsl(var(--primary-foreground))]'
                : 'border-[hsl(var(--threat-high))] text-[hsl(var(--threat-high))] hover:bg-[hsl(var(--threat-high))] hover:text-[hsl(var(--primary-foreground))]'}`}
            >
              <Zap className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">{isSimulating ? 'SIMULATING...' : isAttackSimulated ? 'RESET SYSTEM' : 'SIMULATE ATTACK'}</span>
            </button>}
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            className="h-full"
          >
            {children}
          </motion.div>
        </main>
      </div>

      <AnimatePresence>
        {commandOpen && (
          <motion.div
            className="command-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onMouseDown={(event) => { if (event.target === event.currentTarget) setCommandOpen(false); }}
          >
            <motion.div
              className="command-dialog"
              role="dialog"
              aria-modal="true"
              aria-label="TrustNet command center"
              initial={{ opacity: 0, y: -14, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -8, scale: 0.98 }}
            >
              <div className="command-search-row">
                <Search className="w-4 h-4" aria-hidden="true" />
                <input
                  autoFocus
                  value={commandQuery}
                  onChange={(event) => setCommandQuery(event.target.value)}
                  onKeyDown={onCommandKeyDown}
                  placeholder="Jump to a security workspace…"
                  aria-label="Search security workspaces"
                />
                <button type="button" onClick={() => setCommandOpen(false)} aria-label="Close command center"><X className="w-4 h-4" /></button>
              </div>
              <div className="command-hint">Use ↑ ↓ to navigate · Enter to open · Esc to close</div>
              <div className="command-results">
                {commandItems.length ? commandItems.map(({ to, icon: Icon, label }, index) => (
                  <button
                    type="button"
                    key={to}
                    className={`command-result ${index === commandIndex ? 'is-selected' : ''}`}
                    onMouseEnter={() => setCommandIndex(index)}
                    onClick={() => runCommand(to)}
                  >
                    <span className="command-result-icon"><Icon className="w-4 h-4" /></span>
                    <span>{label}</span>
                    <span className="command-result-path">{to}</span>
                  </button>
                )) : <div className="command-empty">No security workspace matches “{commandQuery}”.</div>}
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
