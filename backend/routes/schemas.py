"""Pydantic schemas for API requests and responses"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum


class ThreatLevel(str, Enum):
    safe = "safe"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class UserStatus(str, Enum):
    normal = "normal"
    warning = "warning"
    restricted = "restricted"
    blocked = "blocked"


class BehaviorMetrics(BaseModel):
    """User behavior metrics for analysis"""
    normal_login_time: float = Field(default=9.2, description="Normal login time in hours")
    actual_login_time: float = Field(default=9.2, description="Actual login time in hours")
    normal_session_duration: float = Field(default=4.5, description="Normal session duration")
    actual_session_duration: float = Field(default=4.5, description="Actual session duration")
    normal_data_volume: float = Field(default=120, description="Normal data volume")
    actual_data_volume: float = Field(default=120, description="Actual data volume")
    normal_api_calls: float = Field(default=45, description="Normal API calls")
    actual_api_calls: float = Field(default=45, description="Actual API calls")
    normal_geo_distance: float = Field(default=0, description="Normal geographic distance")
    actual_geo_distance: float = Field(default=0, description="Actual geographic distance")


class RiskScoreRequest(BaseModel):
    """Request for risk score calculation"""
    user_id: str
    behavior_metrics: BehaviorMetrics
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)


class AnomalyDetectionRequest(BaseModel):
    """Request for anomaly detection"""
    records: List[Dict[str, float]]


class NetworkNode(BaseModel):
    """Network node representation"""
    id: str
    label: str
    node_type: str = Field(
        default="user",
        alias="type",
        description="Node type: user, app, device, database, server"
    )
    x: float
    y: float
    compromised: bool
    propagationRisk: float = Field(ge=0.0, le=100.0)


class NetworkEdge(BaseModel):
    """Network edge representation"""
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    active: bool
    attackPath: bool


class PropagationAnalysisRequest(BaseModel):
    """Request for network propagation analysis"""
    nodes: List[NetworkNode]
    edges: List[NetworkEdge]


class RiskScoreResponse(BaseModel):
    """Response with risk score and analysis"""
    overall_score: float
    threat_level: ThreatLevel
    deviations: Dict[str, float]
    recommendation: str


class AnomalyRecord(BaseModel):
    """Record with anomaly detection results"""
    is_anomaly: bool
    anomaly_score: float
    risk_level: str
    additional_data: Dict[str, Any] = {}


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    message: str
    version: str = "1.0.0"
    model: Optional[Dict[str, Any]] = None
    checks: Optional[Dict[str, Any]] = None
