import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setAuthSession, type AuthSession } from "@/services/authSession";
import { mlBackendService, type WsState } from "@/services/mlBackendService";

const session: AuthSession = {
  token: "test-token-not-a-real-credential",
  user: { id: "u1", email: "u1@example.test", role: "analyst", is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: null },
  permissions: ["view_dashboard"],
};

class FakeSocket {
  static instances: FakeSocket[] = [];
  static OPEN = 1; static CONNECTING = 0;
  readyState = 0;
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  constructor(public url: string) { FakeSocket.instances.push(this); }
  send() {}
  close() { this.readyState = 3; this.onclose?.(); }
  open() { this.readyState = 1; this.onopen?.(); }
}

describe("dashboard WebSocket state and backoff", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeSocket);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ ticket: "t" }), { status: 200, headers: { "Content-Type": "application/json" } })));
    setAuthSession(session);
  });
  afterEach(() => {
    mlBackendService.disconnectWebSocket();
    setAuthSession(null);
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("goes live on open, reconnecting after a drop, and backs off exponentially", async () => {
    const states: WsState[] = [];
    const off = mlBackendService.onWsState((s) => states.push(s));
    await mlBackendService.connectWebSocket();
    FakeSocket.instances[0].open();
    expect(mlBackendService.getWsState()).toBe("live");

    FakeSocket.instances[0].close(); // drop #1 -> retry after ~1s
    expect(mlBackendService.getWsState()).toBe("reconnecting");
    await vi.advanceTimersByTimeAsync(500);
    expect(FakeSocket.instances.length).toBe(1); // not yet: backoff is >= 1s
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.instances.length).toBe(2);

    FakeSocket.instances[1].close(); // drop #2 -> retry after ~2s, not 1s
    await vi.advanceTimersByTimeAsync(1200);
    expect(FakeSocket.instances.length).toBe(2);
    await vi.advanceTimersByTimeAsync(1500);
    expect(FakeSocket.instances.length).toBe(3);

    FakeSocket.instances[2].open();
    expect(mlBackendService.getWsState()).toBe("live"); // attempts reset on success
    off();
    expect(states).toContain("reconnecting");
  });

  it("is offline after logout and does not reconnect without a session", async () => {
    await mlBackendService.connectWebSocket();
    FakeSocket.instances[0].open();
    setAuthSession(null);
    FakeSocket.instances[0].close();
    expect(mlBackendService.getWsState()).toBe("offline");
    await vi.advanceTimersByTimeAsync(40000);
    expect(FakeSocket.instances.length).toBe(1);
  });
});
