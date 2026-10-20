"""API routes for ML endpoints"""
from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any, List
import numpy as np
import sys
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from models.optimized_models import (
    anomaly_detector,
    risk_scorer,
    propagation_analyzer
)
from .schemas import (
    RiskScoreRequest,
    RiskScoreResponse,
    AnomalyDetectionRequest,
    PropagationAnalysisRequest,
    HealthResponse,
    ThreatLevel
)

router = APIRouter(prefix="/api", tags=["ml"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "message": "TrustNet ML Backend is running",
        "version": "1.0.0"
    }


@router.post("/risk-score", response_model=RiskScoreResponse)
async def calculate_risk_score(request: RiskScoreRequest):
    """
    Calculate risk score for a user based on behavior metrics
    
    Uses weighted scoring across multiple behavior dimensions:
    - Login time deviation
    - Session duration deviation  
    - Data volume deviation
    - API calls deviation
    - Geographic distance deviation
    - Anomaly score
    """
    try:
        metrics_dict = request.behavior_metrics.model_dump()
        
        result = risk_scorer.calculate_risk_score(
            behavior_metrics=metrics_dict,
            anomaly_score=request.anomaly_score
        )
        
        return {
            "overall_score": result['overall_score'],
            "threat_level": result['threat_level'],
            "deviations": result['deviations'],
            "recommendation": result['recommendation']
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error calculating risk score: {str(e)}"
        )


@router.post("/anomaly-detection")
async def detect_anomalies(request: AnomalyDetectionRequest):
    """
    Detect anomalies in behavioral records using Isolation Forest
    
    Returns anomaly scores and risk levels for each record
    """
    try:
        if not request.records:
            return {"results": []}
        
        # Prepare data for the model
        features = list(request.records[0].keys())
        data = np.array([
            [record.get(feature, 0.0) for feature in features]
            for record in request.records
        ])
        
        # Perform anomaly detection
        predictions, scores = anomaly_detector.detect(data)
        
        # Format results
        results = []
        for i, record in enumerate(request.records):
            is_anomaly = predictions[i] == -1
            anomaly_score = float(scores[i])
            
            risk_level = "low"
            if anomaly_score > 0.8:
                risk_level = "critical"
            elif anomaly_score > 0.6:
                risk_level = "high"
            elif anomaly_score > 0.3:
                risk_level = "medium"
            
            results.append({
                **record,
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(anomaly_score, 4),
                "risk_level": risk_level
            })
        
        return {"results": results}
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error detecting anomalies: {str(e)}"
        )


@router.post("/train-anomaly-detector")
async def train_anomaly_detector(training_data: Dict[str, Any] = Body(...)):
    """
    Train the anomaly detector on historical data
    
    Expects data in format: {"features": list, "data": list of lists}
    """
    try:
        if "data" not in training_data or "features" not in training_data:
            raise ValueError("Request must include 'data' and 'features'")
        
        data = np.array(training_data["data"])
        features = training_data["features"]
        
        result = anomaly_detector.train(data, features)
        
        return result
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error training model: {str(e)}"
        )


@router.post("/propagation-analysis")
async def analyze_propagation(request: PropagationAnalysisRequest):
    """
    Analyze risk propagation through network graph
    
    Identifies critical nodes and calculates propagation risks based on:
    - Node risk scores
    - Neighbor influence
    - Active attack paths
    """
    try:
        # Convert request data to analysis format
        nodes = [
            {
                "id": node.id,
                "label": node.label,
                "type": node.node_type,
                "x": node.x,
                "y": node.y,
                "compromised": node.compromised,
                "propagationRisk": node.propagationRisk
            }
            for node in request.nodes
        ]
        
        edges = [
            {
                "from": edge.from_node,
                "to": edge.to_node,
                "active": edge.active,
                "attackPath": edge.attackPath
            }
            for edge in request.edges
        ]
        
        analysis_result = propagation_analyzer.analyze_network(nodes, edges)
        
        return {
            "total_network_risk": analysis_result['total_network_risk'],
            "critical_count": len(analysis_result['critical_nodes']),
            "critical_nodes": analysis_result['critical_nodes'],
            "all_nodes": analysis_result['all_nodes']
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing propagation: {str(e)}"
        )


@router.post("/batch-risk-analysis")
async def batch_risk_analysis(users_data: List[Dict[str, Any]] = Body(...)):
    """
    Analyze risk scores for multiple users in batch
    
    Each user record should include behavior metrics
    """
    try:
        results = []
        
        for user in users_data:
            user_id = user.get("id")
            
            # Extract metrics with defaults
            metrics = {
                "normal_login_time": user.get("normal_login_time", 9.2),
                "actual_login_time": user.get("actual_login_time", 9.2),
                "normal_session_duration": user.get("normal_session_duration", 4.5),
                "actual_session_duration": user.get("actual_session_duration", 4.5),
                "normal_data_volume": user.get("normal_data_volume", 120),
                "actual_data_volume": user.get("actual_data_volume", 120),
                "normal_api_calls": user.get("normal_api_calls", 45),
                "actual_api_calls": user.get("actual_api_calls", 45),
                "normal_geo_distance": user.get("normal_geo_distance", 0),
                "actual_geo_distance": user.get("actual_geo_distance", 0),
            }
            
            anomaly_score = user.get("anomaly_score", 0.0)
            
            risk_analysis = risk_scorer.calculate_risk_score(metrics, anomaly_score)
            
            results.append({
                "user_id": user_id,
                "overall_score": risk_analysis['overall_score'],
                "threat_level": risk_analysis['threat_level'],
                "recommendation": risk_analysis['recommendation'],
                "deviations": risk_analysis['deviations']
            })
        
        return {"user_risk_scores": results}
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error in batch analysis: {str(e)}"
        )
