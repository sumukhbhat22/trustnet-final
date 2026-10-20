import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { getAuthSession, subscribeAuthSession, type AuthSession } from "@/services/authSession";
import { mlBackendService } from "@/services/mlBackendService";

interface AuthContextValue {
  session: AuthSession | null;
  restoring: boolean;
}

const AuthContext = createContext<AuthContextValue>({ session: null, restoring: false });

export function AuthProvider({ children }: { children: ReactNode }) {
  const session = useSyncExternalStore(subscribeAuthSession, getAuthSession, getAuthSession);
  // On first load try the HttpOnly refresh cookie once so a page reload keeps the user signed in.
  const [restoring, setRestoring] = useState<boolean>(() => !getAuthSession());

  useEffect(() => {
    if (!restoring) return;
    let active = true;
    mlBackendService.restoreSession().finally(() => {
      if (active) setRestoring(false);
    });
    return () => {
      active = false;
    };
  }, [restoring]);

  return <AuthContext.Provider value={{ session, restoring }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const { session, restoring } = useContext(AuthContext);
  return {
    session,
    user: session?.user ?? null,
    role: session?.user.role ?? null,
    isAuthenticated: Boolean(session?.token),
    isRestoring: restoring,
    hasPermission: (permission: string) => session?.permissions.includes(permission) ?? false,
  };
}
