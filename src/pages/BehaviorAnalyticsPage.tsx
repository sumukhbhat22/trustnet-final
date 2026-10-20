import { useCallback, useEffect, useState } from "react";
import { Layout } from "@/components/Layout";
import PageTransition from "@/components/PageTransition";
import { mlBackendService, type NetworkEvent } from "@/services/mlBackendService";
import { filterEventsInWindow } from "@/lib/behaviorAnalytics";

const RANGES = ["24H", "7D", "30D"] as const;

type Range = (typeof RANGES)[number];

function getRangeMs(range: Range): number {
  return range === "24H" ? 24 * 60 * 60_000 : range === "7D" ? 7 * 24 * 60 * 60_000 : 30 * 24 * 60 * 60_000;
}

export default function BehaviorAnalyticsPage() {
  const [range, setRange] = useState<Range>("7D");
  const [events, setEvents] = useState<NetworkEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const result = await mlBackendService.getNetworkEvents({ limit: 1000 });
      setEvents(result.events);
      setLoadError("");
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "Could not load stored behavior events.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const now = Date.now();
  const rangeMs = getRangeMs(range);
  const rangeStart = now - rangeMs;
  const rangedEvents = filterEventsInWindow(events, rangeStart, now);
  const bucketCount = range === "24H" ? 24 : range === "7D" ? 7 : 30;
  const bucketMs = rangeMs / bucketCount;
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const start = rangeStart + index * bucketMs;
    const date = new Date(start);
    return {
      label: range === "24H"
        ? date.toLocaleTimeString([], { hour: "2-digit" })
        : date.toLocaleDateString([], { month: "numeric", day: "numeric" }),
      requests: 0,
      anomalies: 0,
    };
  });
  for (const event of rangedEvents) {
    const index = Math.min(bucketCount - 1, Math.floor((Date.parse(event.timestamp) - rangeStart) / bucketMs));
    if (index < 0 || index >= bucketCount) continue;
    buckets[index].requests += 1;
    if (event.anomaly_types.length) buckets[index].anomalies += 1;
  }

  const maxRequests = Math.max(1, ...buckets.map((bucket) => bucket.requests));
  const maxAnomalies = Math.max(1, ...buckets.map((bucket) => bucket.anomalies));
  const linePoints = (key: "requests" | "anomalies") => buckets.map((bucket, index) => {
    const x = bucketCount <= 1 ? 0 : (index / (bucketCount - 1)) * 1000;
    const max = key === "requests" ? maxRequests : maxAnomalies;
    const y = 190 - (bucket[key] / max) * 150;
    return [x, y] as const;
  });
  const requestLine = linePoints("requests").map(([x, y]) => `${x},${y}`).join(" ");
  const anomalyLine = linePoints("anomalies").map(([x, y]) => `${x},${y}`).join(" ");
  const anomalyFill = `${anomalyLine} 1000,220 0,220`;

  const hourCounts = Array.from({ length: 24 }, () => 0);
  for (const event of rangedEvents) hourCounts[new Date(event.timestamp).getHours()] += 1;
  const maxHourCount = Math.max(1, ...hourCounts);

  const entityCounts = new Map<string, number>();
  for (const event of rangedEvents) {
    if (!event.anomaly_types.length) continue;
    const entity = event.user_id || event.endpoint;
    entityCounts.set(entity, (entityCounts.get(entity) ?? 0) + event.anomaly_types.length);
  }
  const anomalousEntities = [...entityCounts.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 5);
  const maxEntityCount = Math.max(1, ...anomalousEntities.map(([, count]) => count));

  return (
    <PageTransition>
      <Layout>
        <div className="tn-content behavior-page">
          <div className="behavior-page-heading">
            <div>
              <div className="heading" style={{ fontSize: 20, fontWeight: 500 }}>Behavior Analytics</div>
              <div style={{ fontSize: 12.5, color: "var(--text-faint)", marginTop: 2 }}>
                Derived from {rangedEvents.length} persisted request events in the selected window
              </div>
            </div>
            <div className="behavior-range-tabs" role="group" aria-label="Analytics time range">
              {RANGES.map((item) => (
                <button
                  key={item}
                  type="button"
                  className={`chip${range === item ? " active" : ""}`}
                  aria-pressed={range === item}
                  onClick={() => setRange(item)}
                >
                  {item}
                </button>
              ))}
            </div>
          </div>

          {loadError && <div className="overview-load-error" role="alert">Behavior data unavailable: {loadError}</div>}

          <section className="panel panel-glow behavior-timeline">
            <div className="behavior-panel-heading">
              <div className="heading" style={{ fontSize: 15, fontWeight: 500 }}>Anomaly Score Timeline</div>
              <div className="behavior-legend">
                <span><span className="dot" style={{ background: "hsl(var(--threat-high))" }} /> Flagged requests</span>
                <span><span className="dot" style={{ background: "hsl(var(--muted-foreground))" }} /> All requests</span>
              </div>
            </div>
            <svg viewBox="0 0 1000 220" className="behavior-chart" role="img" aria-label={`Observed request and anomaly timeline for ${range}`}>
              <defs>
                <linearGradient id="behaviorFillGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="hsl(var(--threat-high))" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="hsl(var(--threat-high))" stopOpacity={0} />
                </linearGradient>
              </defs>
              <line x1="0" y1="55" x2="1000" y2="55" stroke="hsl(var(--foreground) / 0.08)" />
              <line x1="0" y1="110" x2="1000" y2="110" stroke="hsl(var(--foreground) / 0.08)" />
              <line x1="0" y1="165" x2="1000" y2="165" stroke="hsl(var(--foreground) / 0.08)" />
              <polyline points={requestLine} fill="none" stroke="hsl(var(--muted-foreground))" strokeWidth={1.5} strokeDasharray="4 4" />
              {rangedEvents.length > 0 && <>
                <polygon points={anomalyFill} fill="url(#behaviorFillGrad)" />
                <polyline points={anomalyLine} fill="none" stroke="hsl(var(--threat-high))" strokeWidth={2.5} />
              </>}
            </svg>
            {!loading && rangedEvents.length === 0 && <div className="device-empty">No persisted request records fall within this window.</div>}
          </section>

          <div className="two-col behavior-detail-grid">
            <section className="panel panel-glow behavior-panel">
              <div className="heading behavior-panel-title">Request Activity by Hour</div>
              <div className="heat-grid">
                {hourCounts.map((count, index) => {
                  const opacity = count ? 0.12 + (count / maxHourCount) * 0.75 : 0.04;
                  return (
                  <div
                    key={index}
                    className="heat-cell"
                    aria-label={`Hour ${index}: ${count} observed requests`}
                    title={`${index}:00 · ${count} requests`}
                    style={{ background: `hsl(var(--threat-high) / ${opacity})` }}
                  />
                  );
                })}
              </div>
              <div className="behavior-axis-labels"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>23:59</span></div>
              <div className="behavior-explanation">
                Counts are aggregated from persisted API requests in the selected window; this view does not infer a behavioral baseline that has not been measured.
              </div>
            </section>

            <section className="panel panel-glow behavior-panel">
              <div className="heading behavior-panel-title">Top Flagged Users and Routes</div>
              <div className="behavior-entities">
                {anomalousEntities.map(([entity, count]) => (
                  <div key={entity} className="entity-row">
                    <span className="behavior-entity-name">{entity}</span>
                    <div className="bar-track"><div className="bar-fill" style={{ width: `${(count / maxEntityCount) * 100}%`, background: "hsl(var(--threat-high))" }} /></div>
                    <span className="mono behavior-entity-score" style={{ color: "hsl(var(--threat-high))" }}>{count}</span>
                  </div>
                ))}
                {!loading && anomalousEntities.length === 0 && <div className="device-empty">No flagged users or routes in this window.</div>}
              </div>
            </section>
          </div>

          <section className="panel panel-glow behavior-panel behavior-drift">
            <div className="heading behavior-panel-title">Observed Request Volume</div>
            <div className="behavior-bars" role="img" aria-label={`Observed API request volume for ${range}`}>
              {buckets.map((bucket, index) => {
                const height = bucket.requests ? Math.max(3, (bucket.requests / maxRequests) * 100) : 0;
                const anomalous = bucket.anomalies > 0;
                return (
                  <div
                    key={`${bucket.label}-${index}`}
                    className="behavior-bar"
                    style={{
                      height: `${height}%`,
                      background: anomalous ? "hsl(var(--threat-high))" : "hsl(var(--secondary))",
                      boxShadow: anomalous ? "0 0 24px -4px hsl(var(--threat-high) / 0.55)" : "none",
                    }}
                  />
                );
              })}
            </div>
            <div className="behavior-axis-labels">{buckets.map((bucket, index) => (
              <span key={`${bucket.label}-${index}`}>{bucketCount > 14 && index % 5 !== 0 ? "" : bucket.label}</span>
            ))}</div>
          </section>
        </div>
      </Layout>
    </PageTransition>
  );
}
