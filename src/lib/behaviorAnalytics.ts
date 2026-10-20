import type { NetworkEvent } from "@/services/mlBackendService";

/** Return only events with valid timestamps inside the inclusive time window. */
export function filterEventsInWindow(
  events: NetworkEvent[],
  rangeStart: number,
  now: number,
): NetworkEvent[] {
  if (!Number.isFinite(rangeStart) || !Number.isFinite(now) || rangeStart > now) return [];
  return events.filter((event) => {
    const timestamp = Date.parse(event.timestamp);
    return Number.isFinite(timestamp) && timestamp >= rangeStart && timestamp <= now;
  });
}
