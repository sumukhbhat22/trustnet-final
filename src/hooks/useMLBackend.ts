/**
 * Custom React Hook for ML Backend Integration
 */
import { useEffect, useState, useCallback } from "react";
import { mlBackendService, RiskScoreResponse, type ApiJson, type PropagationNode, type PropagationEdge, type PropagationAnalysisResult, type RiskScorePayload } from "@/services/mlBackendService";

interface UseMLBackendResult {
  isConnected: boolean;
  isLoading: boolean;
  error: string | null;
  calculateRisk: (userId: string, metrics: Record<string, number>) => Promise<RiskScoreResponse | null>;
  detectAnomalies: (records: Record<string, number>[]) => Promise<ApiJson | null>;
  analyzePropagation: (nodes: PropagationNode[], edges: PropagationEdge[]) => Promise<PropagationAnalysisResult | null>;
  batchAnalyzeUsers: (users: ApiJson[]) => Promise<ApiJson | null>;
}

export const useMLBackend = (enableAutoCheck: boolean = true): UseMLBackendResult => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Check backend availability on mount
  useEffect(() => {
    if (!enableAutoCheck) return;

    const checkConnection = async () => {
      try {
        const available = await mlBackendService.isBackendAvailable();
        setIsConnected(available);
        if (!available) {
          console.warn("ML Backend service is not available");
        }
      } catch (err) {
        setIsConnected(false);
      }
    };

    checkConnection();
    // Check connection every 30 seconds
    const interval = setInterval(checkConnection, 30000);
    return () => clearInterval(interval);
  }, [enableAutoCheck]);

  const calculateRisk = useCallback(
    async (userId: string, metrics: Record<string, number>): Promise<RiskScoreResponse | null> => {
      if (!isConnected) {
        setError("ML Backend not connected");
        return null;
      }

      setIsLoading(true);
      setError(null);

      try {
        const payload: RiskScorePayload = {
          user_id: userId,
          behavior_metrics: {
            normal_login_time: metrics.normal_login_time || 9.2,
            actual_login_time: metrics.actual_login_time || 9.2,
            normal_session_duration: metrics.normal_session_duration || 4.5,
            actual_session_duration: metrics.actual_session_duration || 4.5,
            normal_data_volume: metrics.normal_data_volume || 120,
            actual_data_volume: metrics.actual_data_volume || 120,
            normal_api_calls: metrics.normal_api_calls || 45,
            actual_api_calls: metrics.actual_api_calls || 45,
            normal_geo_distance: metrics.normal_geo_distance || 0,
            actual_geo_distance: metrics.actual_geo_distance || 0,
          },
          anomaly_score: metrics.anomaly_score || 0.0,
        };

        const result = await mlBackendService.calculateRiskScore(payload);
        return result;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Risk calculation failed";
        setError(errorMsg);
        console.error("Risk calculation error:", err);
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [isConnected]
  );

  const detectAnomalies = useCallback(
    async (records: Record<string, number>[]): Promise<ApiJson | null> => {
      if (!isConnected) {
        setError("ML Backend not connected");
        return null;
      }

      setIsLoading(true);
      setError(null);

      try {
        const result = await mlBackendService.detectAnomalies(records);
        return result;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Anomaly detection failed";
        setError(errorMsg);
        console.error("Anomaly detection error:", err);
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [isConnected]
  );

  const analyzePropagation = useCallback(
    async (nodes: PropagationNode[], edges: PropagationEdge[]): Promise<PropagationAnalysisResult | null> => {
      if (!isConnected) {
        setError("ML Backend not connected");
        return null;
      }

      setIsLoading(true);
      setError(null);

      try {
        const result = await mlBackendService.analyzePropagation(nodes, edges);
        return result;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Propagation analysis failed";
        setError(errorMsg);
        console.error("Propagation analysis error:", err);
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [isConnected]
  );

  const batchAnalyzeUsers = useCallback(
    async (users: ApiJson[]): Promise<ApiJson | null> => {
      if (!isConnected) {
        setError("ML Backend not connected");
        return null;
      }

      setIsLoading(true);
      setError(null);

      try {
        const result = await mlBackendService.batchRiskAnalysis(users);
        return result;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : "Batch analysis failed";
        setError(errorMsg);
        console.error("Batch analysis error:", err);
        return null;
      } finally {
        setIsLoading(false);
      }
    },
    [isConnected]
  );

  return {
    isConnected,
    isLoading,
    error,
    calculateRisk,
    detectAnomalies,
    analyzePropagation,
    batchAnalyzeUsers,
  };
};
