import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthSession, getAuthSession, type AuthSession } from "@/services/authSession";
import * as svc from "@/services/mlBackendService";

const session: AuthSession = {
  token: "old-token-not-a-real-credential",
  user: { id: "u1", email: "u1@example.test", role: "analyst", is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: null },
  permissions: ["view_dashboard"],
};

type TestClient = { request(url: string): Promise<Response>; restoreSession(): Promise<boolean> };
const getClient = (): TestClient => svc.mlBackendService as unknown as TestClient;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("access-token refresh (single-flight, no loops)", () => {
  beforeEach(() => setAuthSession(session));
  afterEach(() => { setAuthSession(null); vi.unstubAllGlobals(); });

  it("issues one /auth/refresh for concurrent 401s and retries each request once", async () => {
    let refreshCalls = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/auth/refresh")) { refreshCalls++; await new Promise(r => setTimeout(r, 20)); return json(200, { access_token: "new-token" }); }
      const auth = new Headers(init?.headers).get("Authorization");
      return auth === "Bearer new-token" ? json(200, { ok: true }) : json(401, { detail: "expired" });
    });
    vi.stubGlobal("fetch", fetchMock);
    const client = getClient();
    const responses = await Promise.all([1, 2, 3, 4].map(i => client.request(`http://x.test/api/thing${i}`)));
    expect(responses.map(r => r.status)).toEqual([200, 200, 200, 200]);
    expect(refreshCalls).toBe(1);
    expect(getAuthSession()?.token).toBe("new-token");
  });

  it("does not loop when refresh fails: one refresh attempt, original 401 returned", async () => {
    let refreshCalls = 0;
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      if (String(input).includes("/auth/refresh")) { refreshCalls++; return json(401, { detail: "no" }); }
      return json(401, { detail: "expired" });
    }));
    const client = getClient();
    const res = await client.request("http://x.test/api/thing");
    expect(res.status).toBe(401);
    expect(refreshCalls).toBe(1);
  });
});

describe("session restoration after reload (memory-only)", () => {
  afterEach(() => { setAuthSession(null); vi.unstubAllGlobals(); });

  it("restores user and permissions from the refresh cookie and /auth/me, without touching storage", async () => {
    setAuthSession(null);
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/auth/refresh")) return json(200, { access_token: "restored-token" });
      if (url.includes("/auth/me")) return json(200, { user: session.user, permissions: ["view_dashboard"] });
      return json(404, {});
    }));
    const client = getClient();
    await expect(client.restoreSession()).resolves.toBe(true);
    expect(getAuthSession()?.token).toBe("restored-token");
    expect(getAuthSession()?.user.id).toBe("u1");
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });

  it("returns false and stays signed out when there is no valid refresh cookie", async () => {
    setAuthSession(null);
    vi.stubGlobal("fetch", vi.fn(async () => json(401, { detail: { code: "REFRESH_INVALID" } })));
    const client = getClient();
    await expect(client.restoreSession()).resolves.toBe(false);
    expect(getAuthSession()).toBeNull();
  });
});
