import { afterEach, describe, expect, it, vi } from "vitest";
import { getAuthSession, setAuthSession } from "@/services/authSession";
import { mlBackendService } from "@/services/mlBackendService";
import type { DeviceFingerprint } from "@/services/fingerprintService";

const fingerprint: DeviceFingerprint = {
  userAgent: "TrustNet demo test",
  platform: "test-platform",
  language: "en-US",
  languages: ["en-US"],
  timezone: "UTC",
  timezoneOffset: 0,
  screenResolution: "1280x800",
  colorDepth: 24,
  deviceMemory: null,
  hardwareConcurrency: 4,
  touchSupport: false,
  cookiesEnabled: true,
  doNotTrack: null,
  canvasHash: "test-canvas",
  webglVendor: "test-vendor",
  webglRenderer: "test-renderer",
  deviceType: "desktop",
};

describe("attacker simulator login request", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setAuthSession(null);
  });

  it("uses the ordinary login endpoint without retaining backend tokens", async () => {
    setAuthSession(null);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({
      login_status: "allowed",
      access_token: "token-must-not-be-retained",
      authentication_event_id: "AUTH-DEMO-1",
      authentication_event_timestamp: "2026-01-01T00:00:00Z",
      attacker_ip: "127.0.0.1",
      message: "Login successful.",
    }), { status: 200, headers: { "Content-Type": "application/json" } }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await mlBackendService.submitDemoLogin("demo-password", fingerprint, "demo-fingerprint");
    const init = fetchMock.mock.calls[0][1];
    const requestBody = JSON.parse(String(init?.body));

    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/auth\/login$/);
    expect(init?.credentials).toBe("omit");
    expect(requestBody).toMatchObject({ username: "trustnet-demo", password: "demo-password" });
    expect(result.body).toMatchObject({
      login_status: "allowed",
      authentication_event_id: "AUTH-DEMO-1",
      authentication_event_timestamp: "2026-01-01T00:00:00Z",
    });
    expect(result.body).not.toHaveProperty("access_token");
    expect(getAuthSession()).toBeNull();
  });
});
