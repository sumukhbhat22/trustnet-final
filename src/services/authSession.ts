export type UserRole = "admin" | "analyst" | "viewer";

export interface SessionUser {
  id: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface AuthSession {
  token: string;
  user: SessionUser;
  permissions: string[];
}

let session: AuthSession | null = null;
const listeners = new Set<() => void>();

export function getAuthSession(): AuthSession | null {
  return session;
}

export function setAuthSession(next: AuthSession | null): void {
  session = next;
  listeners.forEach((listener) => listener());
}

export function subscribeAuthSession(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
