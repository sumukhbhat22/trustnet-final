import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AnimatePresence } from "framer-motion";
import { BrowserRouter, Routes, Route, useLocation, Navigate } from "react-router-dom";
import { SecurityProvider } from "@/store/securityStore";
import { Layout } from "@/components/Layout";
import { AlertPopup } from "@/components/AlertPopup";
import MFAChallengeDialog from "@/components/MFAChallengeDialog";
import PageTransition from "@/components/PageTransition";
import NotFound from "./pages/NotFound";
import { lazy, Suspense, type ReactNode } from "react";
import { AuthProvider, useAuth } from "@/store/authContext";

const OverviewPage = lazy(() => import("@/pages/OverviewPage"));
const BehaviorAnalyticsPage = lazy(() => import("@/pages/BehaviorAnalyticsPage"));
const RiskPropagationPage = lazy(() => import("@/pages/RiskPropagationPage"));
const IncidentCenterPage = lazy(() => import("@/pages/IncidentCenterPage"));
const AdminPanel = lazy(() => import("@/pages/AdminPanel"));
const LoginPage3D = lazy(() => import("@/pages/LoginPage3D"));
const NetworkActivityPage = lazy(() => import("@/pages/NetworkActivityPage"));
const DemoPage = lazy(() => import("@/pages/DemoPage"));
const AttackerSimulatorPage = lazy(() => import("@/pages/AttackerSimulatorPage"));
const CsiSimulatorPage = lazy(() => import("@/pages/CsiSimulatorPage"));

const queryClient = new QueryClient();

const RouteFallback = () => (
  <div role="status" aria-live="polite" className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
    Loading…
  </div>
);

const withDashboardShell = (page: ReactNode) => (
  <PageTransition>
    <Layout>{page}</Layout>
  </PageTransition>
);

function DashboardRoutes() {
  const location = useLocation();
  const { hasPermission } = useAuth();

  return (
    <SecurityProvider>
      <AlertPopup />
      <MFAChallengeDialog />
      <Suspense fallback={<RouteFallback />}>
      <AnimatePresence mode="wait" initial={false}>
        <Routes location={location} key={location.pathname}>
          <Route path="/overview" element={<OverviewPage />} />
          <Route path="/security-overview" element={<OverviewPage />} />
          <Route path="/behavior" element={<BehaviorAnalyticsPage />} />
          <Route path="/behavior-analytics" element={<BehaviorAnalyticsPage />} />
          <Route path="/network-activity" element={<NetworkActivityPage />} />
          <Route path="/behavior-live" element={<BehaviorAnalyticsPage />} />
          <Route path="/propagation" element={<RiskPropagationPage />} />
          <Route path="/risk-propagation" element={<RiskPropagationPage />} />
          <Route path="/propagation-live" element={<RiskPropagationPage />} />
          <Route path="/incidents" element={<IncidentCenterPage />} />
          <Route path="/incidents-live" element={<IncidentCenterPage />} />
          <Route path="/attacker-simulator" element={<AttackerSimulatorPage />} />
          <Route path="/csi-simulator" element={<CsiSimulatorPage />} />
          <Route path="/admin" element={hasPermission("manage_users") ? withDashboardShell(<AdminPanel />) : withDashboardShell(<NotFound />)} />
          <Route path="*" element={withDashboardShell(<NotFound />)} />
        </Routes>
      </AnimatePresence>
      </Suspense>
    </SecurityProvider>
  );
}

function AnimatedRoutes() {
  const location = useLocation();
  const isLoginRoute = location.pathname === "/" || location.pathname === "/login" || location.pathname === "/login.html";
  const routeGroup = isLoginRoute ? "login" : "dashboard";
  const { isAuthenticated, isRestoring } = useAuth();

  if (isRestoring) {
    return (
      <div role="status" aria-live="polite" className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        Restoring your session…
      </div>
    );
  }

  return (
    <Suspense fallback={<RouteFallback />}>
    <AnimatePresence mode="wait" initial={false}>
      <Routes location={location} key={routeGroup}>
        <Route path="/" element={<Navigate to="/login.html" replace />} />
        <Route path="/login" element={<Navigate to="/login.html" replace />} />
        <Route path="/login.html" element={<LoginPage3D />} />
        <Route path="/demo" element={<PageTransition><DemoPage /></PageTransition>} />
        <Route path="/*" element={isAuthenticated ? <DashboardRoutes /> : <Navigate to="/login" replace />} />
      </Routes>
    </AnimatePresence>
    </Suspense>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <AnimatedRoutes />
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
