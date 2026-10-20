import { afterEach, describe, expect, it, vi } from "vitest";
import { getAuthSession, setAuthSession, subscribeAuthSession, type AuthSession } from "@/services/authSession";

const session: AuthSession = {
  token: "test-token-not-a-real-credential",
  user: {
    id: "u1",
    email: "u1@example.test",
    role: "analyst",
    is_active: true,
    created_at: "2026-01-01T00:00:00Z",
    last_login_at: null,
  },
  permissions: ["view_dashboard"],
};

describe("authSession (memory-only session store)", () => {
  afterEach(() => setAuthSession(null));

  it("starts empty and stores the session only in memory", () => {
    expect(getAuthSession()).toBeNull();
    setAuthSession(session);
    expect(getAuthSession()).toEqual(session);
    // Nothing may be persisted to browser storage: a reload must require signing in again.
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("notifies subscribers on change and stops after unsubscribe", () => {
    const listener = vi.fn();
    const unsubscribe = subscribeAuthSession(listener);
    setAuthSession(session);
    setAuthSession(null);
    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribe();
    setAuthSession(session);
    expect(listener).toHaveBeenCalledTimes(2);
  });
});
