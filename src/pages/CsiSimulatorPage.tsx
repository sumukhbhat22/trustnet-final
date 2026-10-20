import { useCallback, useEffect, useState } from "react";
import { Layout } from "@/components/Layout";
import PageTransition from "@/components/PageTransition";
import { mlBackendService, type CsiSimulationSample } from "@/services/mlBackendService";

type Scenario = "match" | "mismatch";

const MATCH_THRESHOLD = 85;

export default function CsiSimulatorPage() {
  const [sample, setSample] = useState<CsiSimulationSample | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [automatic, setAutomatic] = useState(false);
  const [nextScenario, setNextScenario] = useState<Scenario>("match");

  const generate = useCallback(async (scenario: Scenario) => {
    setLoading(true);
    setError("");
    try {
      setSample(await mlBackendService.getCsiSimulationSample(scenario));
      setNextScenario(scenario === "match" ? "mismatch" : "match");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not generate the synthetic CSI sample.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void generate("match");
  }, [generate]);

  useEffect(() => {
    if (!automatic) return undefined;
    const intervalId = window.setInterval(() => void generate(nextScenario), 3000);
    return () => window.clearInterval(intervalId);
  }, [automatic, nextScenario, generate]);

  const matched = sample?.result === "MATCH";

  return (
    <PageTransition>
      <Layout>
        <div className="risk-page-topbar">
          <div>
            <div className="heading" style={{ fontSize: 20 }}>CSI Device Fingerprinting</div>
            <div className="sim-subtitle">Synthetic feature vectors only. No Wi-Fi signal is measured and no physical device is verified.</div>
          </div>
          <span className="badge badge-medium">Simulated · no ESP32 connected</span>
        </div>

        <div className="tn-content risk-page-content">
          <div className="sim-note" role="note">
            Simulation only: CSI values contribute exactly zero to production overall risk, incident counts and automated responses.
          </div>
          {error && <div className="sim-alert" role="alert">CSI simulator unavailable: {error}</div>}

          <div className="two-col sim-columns">
            <section className="panel panel-glow overview-panel" aria-labelledby="csi-vectors-title">
              <div className="overview-panel-heading">
                <div>
                  <div id="csi-vectors-title" className="heading" style={{ fontSize: 15 }}>Feature vectors</div>
                  <div className="sim-subtitle">
                    {sample ? <>Sample <span className="mono">{sample.sample_id}</span> · {new Date(sample.timestamp).toLocaleString(undefined, { timeZone: "UTC" })} UTC</> : "Waiting for a sample"}
                  </div>
                </div>
                {sample && <span className={`badge ${matched ? "badge-ok" : "badge-high"}`}>Simulated {sample.result}</span>}
              </div>

              {!sample ? (
                <div className="device-empty">{loading ? "Generating synthetic sample…" : "No synthetic sample available."}</div>
              ) : (
                <>
                  <div className="csi-legend">
                    <span><i className="csi-key csi-key-reference" />Reference (synthetic)</span>
                    <span><i className="csi-key csi-key-test" />Test (synthetic)</span>
                  </div>
                  <div className="csi-rows">
                    {sample.reference_fingerprint.map((reference, index) => {
                      const test = sample.test_fingerprint[index] ?? 0;
                      return (
                        <div className="csi-row" key={index}>
                          <span className="csi-feature mono">F{index + 1}</span>
                          <div className="csi-bars">
                            <div className="csi-track"><div className="csi-bar csi-bar-reference" style={{ width: `${Math.min(100, reference * 100)}%` }} /></div>
                            <div className="csi-track"><div className={`csi-bar ${matched ? "csi-bar-test" : "csi-bar-test-off"}`} style={{ width: `${Math.min(100, test * 100)}%` }} /></div>
                          </div>
                          <span className="csi-values mono">{reference.toFixed(2)} / {test.toFixed(2)}</span>
                        </div>
                      );
                    })}
                  </div>
                  <div className="sim-hint" style={{ marginTop: 14, lineHeight: 1.6 }}>
                    {sample.explanation} This repeatable software demonstration is not measured ESP32 data, authentication evidence, or a security decision.
                  </div>
                </>
              )}
            </section>

            <section className="panel panel-glow overview-panel">
              <div className="overview-panel-heading">
                <div className="heading" style={{ fontSize: 15 }}>Similarity</div>
                {sample && <span className="badge badge-medium">Scenario: {sample.scenario}</span>}
              </div>
              <div className={`csi-score ${matched ? "is-match" : "is-mismatch"}`}>
                {sample ? sample.similarity_score.toFixed(2) : "—"}<span>%</span>
              </div>
              <div className="csi-meter" aria-hidden="true">
                <div className={`csi-meter-fill ${matched ? "is-match" : "is-mismatch"}`} style={{ width: `${sample ? Math.min(100, sample.similarity_score) : 0}%` }} />
                <div className="csi-meter-threshold" style={{ left: `${MATCH_THRESHOLD}%` }} />
              </div>
              <div className="sim-hint">Match threshold {MATCH_THRESHOLD}% (cosine similarity of the two vectors)</div>

              <div className="hr" style={{ margin: "18px 0" }} />
              <div className="sim-actions">
                <button className="btn btn-primary" type="button" disabled={loading} onClick={() => void generate("match")}>Generate match</button>
                <button className="btn btn-danger" type="button" disabled={loading} onClick={() => void generate("mismatch")}>Generate mismatch</button>
              </div>
              <div className="sim-actions" style={{ marginTop: 10 }}>
                <button className="btn" type="button" onClick={() => setAutomatic((enabled) => !enabled)}>
                  {automatic ? "Pause automatic simulation" : `Start automatic (${nextScenario} next)`}
                </button>
              </div>
            </section>
          </div>
        </div>
      </Layout>
    </PageTransition>
  );
}
