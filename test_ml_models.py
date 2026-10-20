#!/usr/bin/env python3
"""
Quick test script to verify optimized models performance
Run this to see live model training and performance metrics
"""

import sys
from pathlib import Path

# Add backend to path
backend_path = str(Path(__file__).parent / "backend")
sys.path.insert(0, backend_path)

from models.optimized_models import (
    anomaly_detector, 
    risk_scorer, 
    propagation_analyzer
)
import numpy as np

def main():
    print("\n" + "="*80)
    print("TrustNet AI Guardian - ML Model Performance Test")
    print("="*80)

    # Standalone smoke tests must initialize models themselves; normal model
    # training is performed by the FastAPI startup lifecycle.
    training_result = anomaly_detector.train()
    if training_result.get("status") != "success":
        raise RuntimeError(f"Isolation Forest training failed: {training_result.get('message')}")
    
    # Test 1: Anomaly Detection
    print("\nTEST 1: Anomaly Detection")
    print("-" * 80)
    
    test_records = [
        {"session_duration": 4.5, "data_volume": 150, "cpu": 200, "network": 50, "logins": 10},
        {"session_duration": 0.2, "data_volume": 850, "cpu": 450, "network": 200, "logins": 45},
        {"session_duration": 4.3, "data_volume": 155, "cpu": 205, "network": 52, "logins": 11},
        {"session_duration": 8.2, "data_volume": 950, "cpu": 500, "network": 250, "logins": 50},
    ]
    
    features = list(test_records[0].keys())
    data = np.array([[r.get(f, 0) for f in features] for r in test_records])
    
    predictions, scores = anomaly_detector.predict(data)
    expected_predictions = [1, -1, 1, -1]
    if predictions.tolist() != expected_predictions:
        raise AssertionError(f"Unexpected anomaly classifications: {predictions.tolist()}")
    if not (scores[1] > scores[0] and scores[3] > scores[2]):
        raise AssertionError("Synthetic anomalous records must score higher than normal records.")

    for i, (record, pred, score) in enumerate(zip(test_records, predictions, scores)):
        status = "ANOMALY" if pred == -1 else "NORMAL"
        print(f"  Record {i+1}: {status} (Score: {score:.4f})")
        print(f"    Data: {record}")
    
    # Test 2: Risk Scoring
    print("\nTEST 2: Risk Scoring")
    print("-" * 80)
    
    normal_metrics = {
        "normal_login_time": 9.2,
        "actual_login_time": 9.3,
        "normal_session_duration": 4.5,
        "actual_session_duration": 4.2,
        "normal_data_volume": 120,
        "actual_data_volume": 118,
        "normal_api_calls": 45,
        "actual_api_calls": 48,
        "normal_geo_distance": 0,
        "actual_geo_distance": 12,
    }
    
    attack_metrics = {
        "normal_login_time": 9.2,
        "actual_login_time": 23.8,
        "normal_session_duration": 4.5,
        "actual_session_duration": 0.3,
        "normal_data_volume": 120,
        "actual_data_volume": 850,
        "normal_api_calls": 45,
        "actual_api_calls": 312,
        "normal_geo_distance": 0,
        "actual_geo_distance": 9847,
    }
    
    print("\n  Scenario 1: Normal User Behavior")
    normal_result = risk_scorer.calculate_risk_score(normal_metrics, anomaly_score=0.1)
    print(f"    Risk Score: {normal_result['overall_score']}/100")
    print(f"    Threat Level: {normal_result['threat_level'].upper()}")
    print(f"    Recommendation: {normal_result['recommendation']}")
    print(f"    Confidence: {normal_result.get('confidence', 'N/A')}%")
    
    print("\n  Scenario 2: Active Attack Detected")
    attack_result = risk_scorer.calculate_risk_score(attack_metrics, anomaly_score=0.85)
    print(f"    Risk Score: {attack_result['overall_score']}/100")
    print(f"    Threat Level: {attack_result['threat_level'].upper()}")
    print(f"    Recommendation: {attack_result['recommendation']}")
    print(f"    Confidence: {attack_result.get('confidence', 'N/A')}%")
    if attack_result["overall_score"] <= normal_result["overall_score"]:
        raise AssertionError("Attack behavior must score higher risk than normal behavior.")
    
    # Test 3: Network Propagation
    print("\nTEST 3: Network Propagation Analysis")
    print("-" * 80)
    
    test_nodes = [
        {"id": "n1", "label": "Server A", "type": "server", "x": 0, "y": 0, "compromised": False, "propagationRisk": 30},
        {"id": "n2", "label": "User 1", "type": "user", "x": 1, "y": 1, "compromised": False, "propagationRisk": 45},
        {"id": "n3", "label": "Database", "type": "database", "x": 2, "y": 0, "compromised": False, "propagationRisk": 25},
    ]
    
    test_edges = [
        {"from": "n1", "to": "n2", "active": True, "attackPath": False},
        {"from": "n2", "to": "n3", "active": True, "attackPath": True},
    ]
    
    propagation_result = propagation_analyzer.analyze_network(test_nodes, test_edges)
    if len(propagation_result["all_nodes"]) != len(test_nodes):
        raise AssertionError("Propagation analysis must return every synthetic graph node.")
    print(f"  Total Network Risk: {propagation_result['total_network_risk']}/100")
    print(f"  Critical Nodes: {propagation_result['critical_count']}")
    print(f"  Network Density: {propagation_result.get('network_density', 'N/A')}")
    print(f"\n  Node Analysis:")
    for node in propagation_result['all_nodes']:
        print(f"    {node['node_label']}: {node['propagation_risk']}/100 ({node['criticality']})")
    
    # Performance Summary
    print("\n" + "="*80)
    print("MODEL PERFORMANCE SUMMARY")
    print("="*80)
    
    if hasattr(anomaly_detector, 'metrics') and anomaly_detector.metrics:
        print(f"\nIsolation Forest (Anomaly Detection)")
        print(f"   Precision: {anomaly_detector.metrics.get('precision', 'N/A')*100:.2f}%")
        print(f"   Recall:    {anomaly_detector.metrics.get('recall', 'N/A')*100:.2f}%")
        print(f"   F1-Score:  {anomaly_detector.metrics.get('f1', 'N/A')*100:.2f}%")
    
    if hasattr(anomaly_detector, 'best_params') and anomaly_detector.best_params:
        print(f"\nOptimal Hyperparameters")
        print(f"   N-Estimators: {anomaly_detector.best_params.get('n_estimators')}")
        print(f"   Contamination: {anomaly_detector.best_params.get('contamination')}")
        print(f"   Scaler: {anomaly_detector.best_params.get('scaler')}")
    
    print(f"\nRisk Scorer Weights")
    for factor, weight in risk_scorer.OPTIMAL_WEIGHTS.items():
        print(f"   {factor.replace('_', ' ').title():28s} {weight:.0%}")
    
    print("\n" + "="*80)
    print("Status: Synthetic-data demo model smoke checks passed")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
