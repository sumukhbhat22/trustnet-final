import { describe, expect, it } from "vitest";
import { filterEventsInWindow } from "@/lib/behaviorAnalytics";
import type { NetworkEvent } from "@/services/mlBackendService";

const event = (id: string, timestamp: string): NetworkEvent => ({
  id, timestamp, source_ip: "192.0.2.1", user_id: null, endpoint: "/health",
  method: "GET", status_code: 200, response_time_ms: 4, anomaly_types: [],
});

describe("filterEventsInWindow", () => {
  const start = Date.parse("2026-10-01T00:00:00Z");
  const now = Date.parse("2026-10-02T00:00:00Z");

  it("includes events at both window boundaries", () => {
    expect(filterEventsInWindow([
      event("start", new Date(start).toISOString()),
      event("inside", "2026-10-01T12:00:00Z"),
      event("end", new Date(now).toISOString()),
    ], start, now).map(({ id }) => id)).toEqual(["start", "inside", "end"]);
  });

  it("excludes invalid, older, and future timestamps", () => {
    expect(filterEventsInWindow([
      event("invalid", "not-a-date"),
      event("old", "2026-09-30T23:59:59Z"),
      event("future", "2026-10-02T00:00:01Z"),
    ], start, now)).toEqual([]);
  });

  it("returns no events for an invalid or reversed window", () => {
    const sample = [event("inside", "2026-10-01T12:00:00Z")];
    expect(filterEventsInWindow(sample, Number.NaN, now)).toEqual([]);
    expect(filterEventsInWindow(sample, now, start)).toEqual([]);
  });
});
