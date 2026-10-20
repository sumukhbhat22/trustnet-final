"""
ML Models for TrustNet AI Guardian
Includes anomaly detection, risk scoring, and behavioral analysis
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib
from typing import Dict, List, Tuple, Any
import json

class AnomalyDetector:
    """Isolation Forest-based anomaly detection for user behavior"""
    
    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=5)
        self.trained = False
        self.feature_names = []
        
    def train(self, data: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
        """Train the anomaly detector on historical data"""
        try:
            self.feature_names = feature_names
            
            # Scale the data
            scaled_data = self.scaler.fit_transform(data)
            
            # Apply dimensionality reduction for better anomaly detection
            reduced_data = self.pca.fit_transform(scaled_data)
            
            # Train the model
            self.model.fit(reduced_data)
            self.trained = True
            
            return {
                "status": "success",
                "message": "Model trained successfully",
                "samples": len(data),
                "features": len(feature_names),
                "contamination": self.contamination
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def detect(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detect anomalies in new data
        Returns: predictions (1 for normal, -1 for anomaly), scores
        """
        if not self.trained:
            raise ValueError("Model must be trained before prediction")
        
        scaled_data = self.scaler.transform(data)
        reduced_data = self.pca.transform(scaled_data)
        
        predictions = self.model.predict(reduced_data)
        scores = -self.model.score_samples(reduced_data)  # Negative for anomaly score
        
        return predictions, scores
    
    def batch_detect(self, records: List[Dict[str, float]]) -> List[Dict[str, Any]]:
        """Detect anomalies in a batch of records"""
        if not records:
            return []
        
        # Convert records to numpy array
        feature_order = list(records[0].keys())
        data = np.array([[r.get(f, 0) for f in feature_order] for r in records])
        
        predictions, scores = self.detect(data)
        
        results = []
        for record, pred, score in zip(records, predictions, scores):
            results.append({
                **record,
                "is_anomaly": bool(pred == -1),
                "anomaly_score": float(score),
                "risk_level": self._score_to_risk(float(score))
            })
        
        return results
    
    @staticmethod
    def _score_to_risk(score: float) -> str:
        """Convert anomaly score to risk level"""
        if score < 0.3:
            return "low"
        elif score < 0.6:
            return "medium"
        elif score < 0.8:
            return "high"
        else:
            return "critical"
    
    def save(self, path: str):
        """Save the trained model"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'pca': self.pca,
            'feature_names': self.feature_names,
            'contamination': self.contamination,
            'trained': self.trained
        }, path)
    
    def load(self, path: str):
        """Load a trained model"""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.pca = data['pca']
        self.feature_names = data['feature_names']
        self.contamination = data['contamination']
        self.trained = data['trained']


class RiskScorer:
    """Behavioral risk scoring model"""
    
    # Risk weights for different factors
    RISK_WEIGHTS = {
        'login_deviation': 0.15,
        'session_deviation': 0.12,
        'data_volume_deviation': 0.20,
        'api_calls_deviation': 0.18,
        'geo_distance_deviation': 0.25,
        'anomaly_score': 0.10
    }
    
    @staticmethod
    def calculate_deviation(normal: float, actual: float) -> float:
        """Calculate percentage deviation"""
        if normal == 0:
            return 0 if actual == 0 else 100
        return abs((actual - normal) / normal) * 100
    
    @classmethod
    def calculate_risk_score(cls, behavior_metrics: Dict[str, float], 
                            anomaly_score: float = 0.0) -> Dict[str, Any]:
        """Calculate overall risk score from behavior metrics"""
        
        deviations = {
            'login_deviation': cls.calculate_deviation(
                behavior_metrics.get('normal_login_time', 9.2),
                behavior_metrics.get('actual_login_time', 9.2)
            ),
            'session_deviation': cls.calculate_deviation(
                behavior_metrics.get('normal_session_duration', 4.5),
                behavior_metrics.get('actual_session_duration', 4.5)
            ),
            'data_volume_deviation': cls.calculate_deviation(
                behavior_metrics.get('normal_data_volume', 120),
                behavior_metrics.get('actual_data_volume', 120)
            ),
            'api_calls_deviation': cls.calculate_deviation(
                behavior_metrics.get('normal_api_calls', 45),
                behavior_metrics.get('actual_api_calls', 45)
            ),
            'geo_distance_deviation': cls.calculate_deviation(
                behavior_metrics.get('normal_geo_distance', 0),
                behavior_metrics.get('actual_geo_distance', 0)
            ),
            'anomaly_score': min(anomaly_score * 100, 100)  # Convert to 0-100
        }
        
        # Calculate weighted risk score
        risk_score = sum(
            deviations[key] * cls.RISK_WEIGHTS[key]
            for key in cls.RISK_WEIGHTS.keys()
        )
        
        # Normalize to 0-100
        risk_score = min(max(risk_score, 0), 100)
        
        return {
            'overall_score': round(risk_score, 2),
            'deviations': {k: round(v, 2) for k, v in deviations.items()},
            'threat_level': cls._score_to_threat_level(risk_score),
            'recommendation': cls._get_recommendation(risk_score)
        }
    
    @staticmethod
    def _score_to_threat_level(score: float) -> str:
        """Convert risk score to threat level"""
        if score < 10:
            return "safe"
        elif score < 30:
            return "low"
        elif score < 50:
            return "medium"
        elif score < 75:
            return "high"
        else:
            return "critical"
    
    @staticmethod
    def _get_recommendation(score: float) -> str:
        """Get action recommendation based on risk score"""
        if score < 30:
            return "monitor"
        elif score < 60:
            return "review"
        elif score < 80:
            return "restrict"
        else:
            return "block"


class PropagationAnalyzer:
    """Analyze risk propagation through network"""
    
    @staticmethod
    def calculate_propagation_risk(
        node_risk: float,
        neighbors_risk: List[float],
        attack_paths: int = 0
    ) -> Dict[str, Any]:
        """Calculate propagation risk for a network node"""
        
        if not neighbors_risk:
            neighbors_risk = []
        
        avg_neighbor_risk = np.mean(neighbors_risk) if neighbors_risk else 0
        
        # Propagation risk = own risk + influence from neighbors
        propagation_risk = (0.6 * node_risk + 0.3 * avg_neighbor_risk + 
                           0.1 * (attack_paths * 10))
        
        propagation_risk = min(max(propagation_risk, 0), 100)
        
        return {
            'node_risk': round(node_risk, 2),
            'neighbor_influence': round(avg_neighbor_risk, 2),
            'propagation_risk': round(propagation_risk, 2),
            'criticality': 'high' if propagation_risk > 70 else 
                         'medium' if propagation_risk > 40 else 'low',
            'attack_paths': attack_paths
        }
    
    @staticmethod
    def analyze_network(
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze entire network for propagation risks"""
        
        if not nodes:
            return {'total_risk': 0, 'nodes': []}
        
        node_graph = {node['id']: node for node in nodes}
        
        analyzed_nodes = []
        for node in nodes:
            neighbors = [n['id'] for n in nodes 
                        if any((e['from'] == node['id'] or e['to'] == node['id']) 
                               for e in edges)]
            
            neighbors_risk = [node_graph[n]['propagationRisk'] 
                             for n in neighbors if n in node_graph]
            
            attack_paths = sum(1 for e in edges 
                              if e.get('attackPath') and 
                              (e['from'] == node['id'] or e['to'] == node['id']))
            
            propagation = PropagationAnalyzer.calculate_propagation_risk(
                node.get('propagationRisk', 0),
                neighbors_risk,
                attack_paths
            )
            
            propagation['node_id'] = node['id']
            propagation['node_label'] = node.get('label', '')
            analyzed_nodes.append(propagation)
        
        total_risk = np.mean([n['propagation_risk'] for n in analyzed_nodes])
        
        return {
            'total_network_risk': round(total_risk, 2),
            'critical_nodes': [n for n in analyzed_nodes 
                              if n['criticality'] == 'high'],
            'all_nodes': analyzed_nodes
        }


# Initialize models
anomaly_detector = AnomalyDetector(contamination=0.15)
risk_scorer = RiskScorer()
propagation_analyzer = PropagationAnalyzer()
