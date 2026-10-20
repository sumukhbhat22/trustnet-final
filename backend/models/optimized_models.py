"""
Advanced Model Training and Optimization for TrustNet AI Guardian
Uses best practices: cross-validation, hyperparameter tuning, feature engineering
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, silhouette_score
import joblib
from typing import Dict, Tuple, Any, List
import warnings
warnings.filterwarnings('ignore')


class OptimizedAnomalyDetector:
    """Isolation-Forest anomaly detector with contamination tuning.

    NOTE: the bundled training data is SYNTHETIC (see generate_training_data). Metrics returned by
    train() are computed on the training split itself and are not a generalisation estimate; use
    evaluate_synthetic.py for a held-out (still synthetic) comparison.
    """
    
    def __init__(self):
        self.model = None
        self.scaler = RobustScaler()  # Better for outliers
        self.feature_names = []
        self.trained = False
        self.metrics = {}
        self.best_params = {}
        
    def generate_training_data(self, n_samples: int = 5000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate diverse training data with realistic patterns
        """
        np.random.seed(42)
        
        # Normal behavior patterns
        normal_sessions = np.random.normal(
            loc=[4.5, 150, 200, 50, 10],
            scale=[0.8, 30, 40, 10, 3],
            size=(int(n_samples * 0.85), 5)
        )
        
        # Some mild anomalies (15%)
        mild_anomalies = np.random.normal(
            loc=[8.0, 300, 400, 100, 20],
            scale=[2.0, 100, 100, 30, 8],
            size=(int(n_samples * 0.15), 5)
        )
        
        # Combine
        data = np.vstack([normal_sessions, mild_anomalies])
        
        # Labels: 1 for normal, -1 for anomaly
        labels = np.hstack([
            np.ones(int(n_samples * 0.85)),
            -np.ones(int(n_samples * 0.15))
        ])
        
        return data, labels
    
    def find_optimal_contamination(self, X: np.ndarray) -> float:
        """
        Find optimal contamination parameter using silhouette score
        """
        contamination_values = [0.05, 0.10, 0.15, 0.20, 0.25]
        scores = []
        
        for cont in contamination_values:
            model = IsolationForest(
                contamination=cont,
                n_estimators=200,
                max_features=min(X.shape[1], 10),
                random_state=42,
                n_jobs=-1
            )
            predictions = model.fit_predict(X)
            
            # Silhouette scoring is quadratic in sample count; score a fixed,
            # reproducible subset so the API can start promptly on a laptop.
            if len(np.unique(predictions)) > 1:
                sample_size = min(800, len(X))
                sample_indices = np.linspace(0, len(X) - 1, sample_size, dtype=int)
                score = silhouette_score(X[sample_indices], predictions[sample_indices])
            else:
                score = -1
            
            scores.append(score)
            print(f"  Contamination: {cont:.2f} -> Silhouette: {score:.4f}")
        
        best_contamination = contamination_values[np.argmax(scores)]
        print(f"\nOptimal contamination: {best_contamination}")
        return best_contamination
    
    def train(self, X: np.ndarray = None, feature_names: List[str] = None, 
              y: np.ndarray = None) -> Dict[str, Any]:
        """
        Train the optimized anomaly detector
        """
        try:
            # Generate data if not provided
            if X is None:
                print("Generating synthetic training data (5000 samples)...")
                X, y = self.generate_training_data(5000)
            
            if feature_names is None:
                feature_names = [f"feature_{i}" for i in range(X.shape[1])]
            
            self.feature_names = feature_names
            
            print(f"\nTraining Configuration:")
            print(f"  Samples: {X.shape[0]}")
            print(f"  Features: {X.shape[1]}")
            
            # Scale data
            print("\nScaling features (RobustScaler - resistant to outliers)...")
            X_scaled = self.scaler.fit_transform(X)
            
            # Find optimal contamination
            print("\nFinding optimal contamination parameter...")
            best_contamination = self.find_optimal_contamination(X_scaled)
            
            # Train final model with optimal parameters
            print("\nTraining final Isolation Forest model...")
            self.model = IsolationForest(
                n_estimators=300,  # More trees for better accuracy
                contamination=best_contamination,
                max_samples=min(256, X.shape[0]),
                max_features=min(X.shape[1], 10),
                bootstrap=True,
                random_state=42,
                n_jobs=-1,
                verbose=0
            )
            
            self.model.fit(X_scaled)
            self.trained = True
            
            # Calculate metrics
            predictions = self.model.predict(X_scaled)
            scores = -self.model.score_samples(X_scaled)
            
            print("\nModel Performance Metrics:")
            
            # If we have true labels, calculate additional metrics
            if y is not None:
                # Convert predictions to binary (1=normal, 0=anomaly)
                pred_binary = (predictions == 1).astype(int)
                y_binary = (y == 1).astype(int)
                
                precision = precision_score(y_binary, pred_binary)
                recall = recall_score(y_binary, pred_binary)
                f1 = f1_score(y_binary, pred_binary)
                
                print(f"  Precision: {precision:.4f}")
                print(f"  Recall: {recall:.4f}")
                print(f"  F1-Score: {f1:.4f}")
                
                self.metrics = {
                    'precision': precision,
                    'recall': recall,
                    'f1': f1
                }
            
            # Anomaly statistics
            n_anomalies = (predictions == -1).sum()
            print(f"  Detected anomalies: {n_anomalies} ({n_anomalies/len(predictions)*100:.1f}%)")
            print(f"  Anomaly score range: [{scores.min():.4f}, {scores.max():.4f}]")
            
            self.best_params = {
                'n_estimators': 300,
                'contamination': best_contamination,
                'max_samples': min(256, X.shape[0]),
                'scaler': 'RobustScaler'
            }
            
            return {
                "status": "success",
                "message": "Model trained with optimal parameters",
                "metrics": self.metrics,
                "best_params": self.best_params,
                "samples": X.shape[0],
                "features": len(feature_names)
            }
        
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions on new data"""
        if not self.trained or self.model is None:
            raise ValueError("Model must be trained first")
        
        X = np.asarray(X, dtype=float)
        if X.ndim != 2:
            raise ValueError(f"Expected a 2-D array of shape (n_samples, n_features), got {X.ndim}-D")
        expected = getattr(self.scaler, "n_features_in_", None)
        if expected is not None and X.shape[1] != expected:
            raise ValueError(f"Expected {expected} features, got {X.shape[1]}")
        if X.shape[0] == 0:
            raise ValueError("Empty input")
        if not np.isfinite(X).all():
            raise ValueError("Input contains NaN or infinite values")
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        scores = -self.model.score_samples(X_scaled)
        
        return predictions, scores
    
    def save(self, path: str):
        """Save trained model"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'metrics': self.metrics,
            'best_params': self.best_params,
            'trained': self.trained
        }, path)
        print(f"\nModel saved to {path}")
    
    def load(self, path: str):
        """Load trained model"""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.feature_names = data['feature_names']
        self.metrics = data.get('metrics', {})
        self.best_params = data.get('best_params', {})
        self.trained = data['trained']
        print(f"Model loaded from {path}")


class AdvancedRiskScorer:
    """Optimized risk scoring with adaptive weights"""
    
    # Hand-chosen heuristic weights (not fitted to real-world attack data)
    OPTIMAL_WEIGHTS = {
        'login_deviation': 0.18,      # Increased - most suspicious
        'session_deviation': 0.15,    # Increased
        'data_volume_deviation': 0.22, # Highest weight
        'api_calls_deviation': 0.20,   # Increased
        'geo_distance_deviation': 0.20, # Increased
        'anomaly_score': 0.05           # Lower - ML model already captured
    }
    
    @staticmethod
    def calculate_adaptive_deviation(normal: float, actual: float, 
                                    sensitivity: float = 1.0) -> float:
        """
        Calculate deviation with sensitivity adjustment
        Handles edge cases better
        """
        if normal == 0:
            return 0 if actual == 0 else min(100, abs(actual) * sensitivity)
        
        deviation = abs((actual - normal) / normal) * 100
        
        # Apply sensitivity
        deviation = deviation * sensitivity
        
        # Cap at 200% to prevent extreme values
        return min(200, deviation)
    
    @classmethod
    def calculate_risk_score(cls, behavior_metrics: Dict[str, float],
                            anomaly_score: float = 0.0,
                            sensitivity: float = 1.0) -> Dict[str, Any]:
        """
        Calculate risk score with optimized weights
        """
        deviations = {
            'login_deviation': cls.calculate_adaptive_deviation(
                behavior_metrics.get('normal_login_time', 9.2),
                behavior_metrics.get('actual_login_time', 9.2),
                sensitivity
            ),
            'session_deviation': cls.calculate_adaptive_deviation(
                behavior_metrics.get('normal_session_duration', 4.5),
                behavior_metrics.get('actual_session_duration', 4.5),
                sensitivity * 1.2  # More sensitive to session changes
            ),
            'data_volume_deviation': cls.calculate_adaptive_deviation(
                behavior_metrics.get('normal_data_volume', 120),
                behavior_metrics.get('actual_data_volume', 120),
                sensitivity * 1.3  # Most sensitive to data changes
            ),
            'api_calls_deviation': cls.calculate_adaptive_deviation(
                behavior_metrics.get('normal_api_calls', 45),
                behavior_metrics.get('actual_api_calls', 45),
                sensitivity
            ),
            'geo_distance_deviation': cls.calculate_adaptive_deviation(
                behavior_metrics.get('normal_geo_distance', 0),
                behavior_metrics.get('actual_geo_distance', 0),
                sensitivity * 1.1
            ),
            'anomaly_score': min(anomaly_score * 100, 100)
        }
        
        # Calculate weighted risk with better normalization
        risk_score = sum(
            min(deviations[key], 200) * cls.OPTIMAL_WEIGHTS[key]
            for key in cls.OPTIMAL_WEIGHTS.keys()
        )
        
        # Scale to 0-100 range (max weighted sum ~195, factor 0.52 maps to ~100)
        risk_score = min(max(risk_score * 0.52, 0), 100)
        
        return {
            'overall_score': round(risk_score, 2),
            'deviations': {k: round(v, 2) for k, v in deviations.items()},
            'threat_level': cls._score_to_threat_level(risk_score),
            'recommendation': cls._get_recommendation(risk_score),
            'confidence': cls._get_confidence(deviations)
        }
    
    @staticmethod
    def _score_to_threat_level(score: float) -> str:
        """Convert risk score to threat level (optimized thresholds)"""
        if score < 15:
            return "safe"
        elif score < 35:
            return "low"
        elif score < 55:
            return "medium"
        elif score < 75:
            return "high"
        else:
            return "critical"
    
    @staticmethod
    def _get_recommendation(score: float) -> str:
        """Get action recommendation"""
        if score < 35:
            return "monitor"
        elif score < 60:
            return "review"
        elif score < 80:
            return "restrict"
        else:
            return "block"
    
    @staticmethod
    def _get_confidence(deviations: Dict[str, float]) -> float:
        """Calculate confidence based on agreement across metrics"""
        suspicious_metrics = sum(1 for v in deviations.values() if v > 50)
        confidence = (suspicious_metrics / len(deviations)) * 100
        return min(100, round(confidence, 1))


class OptimizedPropagationAnalyzer:
    """Network propagation analysis with graph optimization"""
    
    @staticmethod
    def calculate_propagation_risk(
        node_risk: float,
        neighbors_risk: List[float],
        attack_paths: int = 0,
        network_density: float = 0.5
    ) -> Dict[str, Any]:
        """
        Calculate propagation risk with network topology consideration
        """
        if not neighbors_risk:
            neighbors_risk = []
        
        neighbor_count = len(neighbors_risk)
        avg_neighbor_risk = np.mean(neighbors_risk) if neighbors_risk else 0
        max_neighbor_risk = np.max(neighbors_risk) if neighbors_risk else 0
        
        # Improved propagation formula
        propagation_risk = (
            0.5 * node_risk +              # Own risk
            0.25 * avg_neighbor_risk +      # Average neighbor influence
            0.15 * max_neighbor_risk +      # Worst neighbor influence
            0.10 * (attack_paths * 8)      # Attack paths effect
        )
        
        # Apply network density factor
        propagation_risk = propagation_risk * (0.8 + 0.4 * network_density)
        propagation_risk = min(max(propagation_risk, 0), 100)
        
        return {
            'node_risk': round(node_risk, 2),
            'neighbor_influence': round(avg_neighbor_risk, 2),
            'max_neighbor_risk': round(max_neighbor_risk, 2),
            'neighbor_count': neighbor_count,
            'propagation_risk': round(propagation_risk, 2),
            'criticality': 'critical' if propagation_risk > 80 else
                         'high' if propagation_risk > 60 else
                         'medium' if propagation_risk > 40 else 'low',
            'attack_paths': attack_paths
        }
    
    @staticmethod
    def analyze_network(
        nodes: List[Dict[str, Any]],
        edges: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze entire network with optimizations"""
        
        if not nodes:
            return {
                'total_network_risk': 0,
                'network_density': 0,
                'critical_count': 0,
                'critical_nodes': [],
                'all_nodes': [],
            }
        
        # Build adjacency
        node_graph = {node['id']: node for node in nodes}
        adjacency = {node['id']: [] for node in nodes}
        
        for edge in edges:
            if edge['from'] in adjacency and edge['to'] in adjacency:
                adjacency[edge['from']].append(edge['to'])
                adjacency[edge['to']].append(edge['from'])
        
        # Calculate network density
        max_edges = len(nodes) * (len(nodes) - 1) / 2
        network_density = len(edges) / max_edges if max_edges > 0 else 0
        
        analyzed_nodes = []
        for node in nodes:
            neighbors = adjacency.get(node['id'], [])
            neighbors_risk = [
                node_graph[n]['propagationRisk'] 
                for n in neighbors if n in node_graph
            ]
            
            attack_paths = sum(1 for e in edges 
                              if e.get('attackPath') and 
                              (e['from'] == node['id'] or e['to'] == node['id']))
            
            propagation = OptimizedPropagationAnalyzer.calculate_propagation_risk(
                node.get('propagationRisk', 0),
                neighbors_risk,
                attack_paths,
                network_density
            )
            
            propagation['node_id'] = node['id']
            propagation['node_label'] = node.get('label', '')
            analyzed_nodes.append(propagation)
        
        total_risk = np.mean([n['propagation_risk'] for n in analyzed_nodes])
        critical_nodes = [n for n in analyzed_nodes if n['criticality'] in ['critical', 'high']]
        
        return {
            'total_network_risk': round(total_risk, 2),
            'network_density': round(network_density, 2),
            'critical_count': len(critical_nodes),
            'critical_nodes': critical_nodes,
            'all_nodes': analyzed_nodes
        }


# Initialize model objects only. Training is performed once in FastAPI's
# startup event; training at import time delays Uvicorn before it can bind.
anomaly_detector = OptimizedAnomalyDetector()
risk_scorer = AdvancedRiskScorer()
propagation_analyzer = OptimizedPropagationAnalyzer()
