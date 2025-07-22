"""
Machine learning-based risk assessment for ICS cybersecurity.
"""

import asyncio
import json
import pickle
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from collections import defaultdict, deque

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import xgboost as xgb
from loguru import logger


@dataclass
class RiskScore:
    """Data structure for risk assessment results."""
    timestamp: float
    source_ip: str
    destination_ip: str
    risk_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    threat_level: str  # 'low', 'medium', 'high', 'critical'
    contributing_factors: List[str]
    ml_model: str
    features: Dict[str, float]
    description: str = ""


@dataclass
class ModelPerformance:
    """Data structure for model performance metrics."""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_alarm_rate: float
    mcc: float
    training_time: float
    prediction_time: float
    last_updated: float


class MLRiskScorer:
    """Machine learning-based risk assessment system."""
    
    def __init__(self, config: Dict):
        """Initialize ML risk scorer."""
        self.config = config
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.performance_metrics = {}
        
        # Model configuration
        self.model_types = config.get('models', ['random_forest', 'svm', 'xgboost'])
        self.test_size = config.get('test_size', 0.2)
        self.random_state = config.get('random_state', 42)
        self.feature_window = config.get('feature_window', 60)
        self.anomaly_threshold = config.get('anomaly_threshold', 0.8)
        
        # Model storage
        self.model_path = Path(config.get('model_path', 'models/'))
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Data storage
        self.training_data = []
        self.risk_scores = []
        self.feature_history = defaultdict(deque)
        
        # Callbacks
        self.risk_callbacks = []
        self.anomaly_callbacks = []
        
        logger.info("ML risk scorer initialized")
    
    def _initialize_models(self):
        """Initialize machine learning models."""
        for model_type in self.model_types:
            try:
                if model_type == 'random_forest':
                    model = RandomForestClassifier(
                        n_estimators=100,
                        max_depth=10,
                        random_state=self.random_state
                    )
                elif model_type == 'svm':
                    model = SVC(
                        kernel='rbf',
                        probability=True,
                        random_state=self.random_state
                    )
                elif model_type == 'xgboost':
                    model = xgb.XGBClassifier(
                        n_estimators=100,
                        max_depth=6,
                        learning_rate=0.1,
                        random_state=self.random_state
                    )
                else:
                    logger.warning(f"Unknown model type: {model_type}")
                    continue
                
                self.models[model_type] = model
                self.scalers[model_type] = StandardScaler()
                self.label_encoders[model_type] = LabelEncoder()
                
                logger.info(f"Initialized {model_type} model")
                
            except Exception as e:
                logger.error(f"Error initializing {model_type} model: {e}")
    
    def extract_features(self, packet_data: Dict, threat_data: List[Dict] = None) -> Dict[str, float]:
        """Extract features from packet and threat data."""
        features = {}
        
        try:
            # Basic packet features
            features['packet_size'] = float(packet_data.get('packet_size', 0))
            features['protocol'] = self._encode_protocol(packet_data.get('protocol', ''))
            features['source_port'] = float(packet_data.get('source_port', 0))
            features['destination_port'] = float(packet_data.get('destination_port', 0))
            features['ttl'] = float(packet_data.get('ttl', 0))
            
            # TCP flags
            flags = packet_data.get('flags', {})
            features['syn_flag'] = float(flags.get('syn', False))
            features['ack_flag'] = float(flags.get('ack', False))
            features['fin_flag'] = float(flags.get('fin', False))
            features['rst_flag'] = float(flags.get('rst', False))
            features['psh_flag'] = float(flags.get('psh', False))
            features['urg_flag'] = float(flags.get('urg', False))
            
            # Window size and sequence numbers
            features['window_size'] = float(packet_data.get('window_size', 0))
            features['sequence_number'] = float(packet_data.get('sequence_number', 0))
            features['acknowledgment_number'] = float(packet_data.get('acknowledgment_number', 0))
            
            # Time-based features
            timestamp = packet_data.get('timestamp', time.time())
            features['hour_of_day'] = datetime.fromtimestamp(timestamp).hour
            features['day_of_week'] = datetime.fromtimestamp(timestamp).weekday()
            
            # Threat-based features
            if threat_data:
                features['threat_count'] = len(threat_data)
                features['high_severity_threats'] = sum(1 for t in threat_data if t.get('severity') == 'high')
                features['medium_severity_threats'] = sum(1 for t in threat_data if t.get('severity') == 'medium')
                features['low_severity_threats'] = sum(1 for t in threat_data if t.get('severity') == 'low')
            else:
                features['threat_count'] = 0.0
                features['high_severity_threats'] = 0.0
                features['medium_severity_threats'] = 0.0
                features['low_severity_threats'] = 0.0
            
            # Historical features
            source_ip = packet_data.get('source_ip', '')
            dest_ip = packet_data.get('destination_ip', '')
            
            features['source_packet_count'] = self._get_historical_count(source_ip)
            features['dest_packet_count'] = self._get_historical_count(dest_ip)
            features['source_threat_count'] = self._get_historical_threat_count(source_ip)
            features['dest_threat_count'] = self._get_historical_threat_count(dest_ip)
            
            # ICS-specific features
            features['is_ics_protocol'] = self._is_ics_protocol(packet_data.get('destination_port', 0))
            features['is_authorized_ip'] = self._is_authorized_ip(source_ip)
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return default features
            features = {f'feature_{i}': 0.0 for i in range(20)}
        
        return features
    
    def _encode_protocol(self, protocol: str) -> float:
        """Encode protocol string to numeric value."""
        protocol_encodings = {
            'TCP': 1.0,
            'UDP': 2.0,
            'ICMP': 3.0,
            'modbus': 4.0,
            'ethernet/ip': 5.0,
            'dnp3': 6.0
        }
        return protocol_encodings.get(protocol.upper(), 0.0)
    
    def _is_ics_protocol(self, port: int) -> float:
        """Check if port corresponds to ICS protocol."""
        ics_ports = {502, 44818, 20000, 47808, 102, 4840}
        return 1.0 if port in ics_ports else 0.0
    
    def _is_authorized_ip(self, ip: str) -> float:
        """Check if IP is in authorized list."""
        authorized_ips = self.config.get('authorized_ips', [])
        return 1.0 if ip in authorized_ips else 0.0
    
    def _get_historical_count(self, ip: str) -> float:
        """Get historical packet count for IP."""
        if ip in self.feature_history:
            return float(len(self.feature_history[ip]))
        return 0.0
    
    def _get_historical_threat_count(self, ip: str) -> float:
        """Get historical threat count for IP."""
        # This would be implemented based on threat history
        return 0.0
    
    def train_models(self, training_data: List[Dict]):
        """Train all machine learning models."""
        if not training_data:
            logger.warning("No training data provided")
            return
        
        try:
            # Prepare training data
            X, y = self._prepare_training_data(training_data)
            
            if len(X) == 0:
                logger.warning("No valid training samples")
                return
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=self.test_size, random_state=self.random_state
            )
            
            # Train each model
            for model_name, model in self.models.items():
                try:
                    logger.info(f"Training {model_name} model...")
                    start_time = time.time()
                    
                    # Scale features
                    X_train_scaled = self.scalers[model_name].fit_transform(X_train)
                    X_test_scaled = self.scalers[model_name].transform(X_test)
                    
                    # Train model
                    model.fit(X_train_scaled, y_train)
                    
                    # Make predictions
                    y_pred = model.predict(X_test_scaled)
                    
                    # Calculate metrics
                    accuracy = accuracy_score(y_test, y_pred)
                    precision = precision_score(y_test, y_pred, average='weighted')
                    recall = recall_score(y_test, y_pred, average='weighted')
                    f1 = f1_score(y_test, y_pred, average='weighted')
                    
                    # Calculate false alarm rate
                    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
                    far = fp / (fp + tn) if (fp + tn) > 0 else 0
                    
                    # Calculate MCC
                    mcc = (tp * tn - fp * fn) / np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) if (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn) > 0 else 0
                    
                    training_time = time.time() - start_time
                    
                    # Store performance metrics
                    self.performance_metrics[model_name] = ModelPerformance(
                        model_name=model_name,
                        accuracy=accuracy,
                        precision=precision,
                        recall=recall,
                        f1_score=f1,
                        false_alarm_rate=far,
                        mcc=mcc,
                        training_time=training_time,
                        prediction_time=0.0,
                        last_updated=time.time()
                    )
                    
                    # Save model
                    self._save_model(model_name, model, self.scalers[model_name])
                    
                    logger.info(f"{model_name} trained successfully - Accuracy: {accuracy:.3f}, F1: {f1:.3f}")
                    
                except Exception as e:
                    logger.error(f"Error training {model_name} model: {e}")
            
        except Exception as e:
            logger.error(f"Error in model training: {e}")
    
    def _prepare_training_data(self, training_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for model training."""
        X = []
        y = []
        
        for sample in training_data:
            try:
                # Extract features
                features = self.extract_features(sample.get('packet_data', {}), 
                                               sample.get('threat_data', []))
                
                # Create feature vector
                feature_vector = list(features.values())
                X.append(feature_vector)
                
                # Create label (1 for threat, 0 for normal)
                label = 1 if sample.get('is_threat', False) else 0
                y.append(label)
                
            except Exception as e:
                logger.error(f"Error preparing training sample: {e}")
                continue
        
        return np.array(X), np.array(y)
    
    def assess_risk(self, packet_data: Dict, threat_data: List[Dict] = None) -> RiskScore:
        """Assess risk for a given packet and threat data."""
        try:
            # Extract features
            features = self.extract_features(packet_data, threat_data)
            
            # Get predictions from all models
            predictions = {}
            confidences = {}
            
            for model_name, model in self.models.items():
                try:
                    # Scale features
                    feature_vector = np.array(list(features.values())).reshape(1, -1)
                    scaled_features = self.scalers[model_name].transform(feature_vector)
                    
                    # Get prediction and probability
                    prediction = model.predict(scaled_features)[0]
                    probabilities = model.predict_proba(scaled_features)[0]
                    
                    predictions[model_name] = prediction
                    confidences[model_name] = max(probabilities)
                    
                except Exception as e:
                    logger.error(f"Error getting prediction from {model_name}: {e}")
                    predictions[model_name] = 0
                    confidences[model_name] = 0.5
            
            # Ensemble prediction
            if predictions:
                # Weighted average based on model performance
                ensemble_score = 0.0
                total_weight = 0.0
                
                for model_name, prediction in predictions.items():
                    if model_name in self.performance_metrics:
                        weight = self.performance_metrics[model_name].f1_score
                        ensemble_score += prediction * weight
                        total_weight += weight
                    else:
                        ensemble_score += prediction
                        total_weight += 1.0
                
                risk_score = ensemble_score / total_weight if total_weight > 0 else 0.5
                confidence = np.mean(list(confidences.values()))
            else:
                risk_score = 0.5
                confidence = 0.5
            
            # Determine threat level
            threat_level = self._determine_threat_level(risk_score)
            
            # Identify contributing factors
            contributing_factors = self._identify_contributing_factors(features, risk_score)
            
            # Create risk score object
            risk_assessment = RiskScore(
                timestamp=time.time(),
                source_ip=packet_data.get('source_ip', ''),
                destination_ip=packet_data.get('destination_ip', ''),
                risk_score=risk_score,
                confidence=confidence,
                threat_level=threat_level,
                contributing_factors=contributing_factors,
                ml_model=list(predictions.keys())[0] if predictions else 'ensemble',
                features=features,
                description=self._generate_risk_description(risk_score, contributing_factors)
            )
            
            # Store risk score
            self.risk_scores.append(risk_assessment)
            
            # Update feature history
            source_ip = packet_data.get('source_ip', '')
            self.feature_history[source_ip].append(time.time())
            
            # Keep only recent history
            cutoff_time = time.time() - self.feature_window
            self.feature_history[source_ip] = deque(
                [t for t in self.feature_history[source_ip] if t > cutoff_time],
                maxlen=1000
            )
            
            # Notify callbacks
            for callback in self.risk_callbacks:
                try:
                    callback(risk_assessment)
                except Exception as e:
                    logger.error(f"Error in risk callback: {e}")
            
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Error in risk assessment: {e}")
            # Return default risk score
            return RiskScore(
                timestamp=time.time(),
                source_ip=packet_data.get('source_ip', ''),
                destination_ip=packet_data.get('destination_ip', ''),
                risk_score=0.5,
                confidence=0.5,
                threat_level='medium',
                contributing_factors=['error_in_assessment'],
                ml_model='none',
                features={},
                description='Error in risk assessment'
            )
    
    def _determine_threat_level(self, risk_score: float) -> str:
        """Determine threat level based on risk score."""
        if risk_score >= 0.8:
            return 'critical'
        elif risk_score >= 0.6:
            return 'high'
        elif risk_score >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _identify_contributing_factors(self, features: Dict[str, float], risk_score: float) -> List[str]:
        """Identify factors contributing to the risk score."""
        factors = []
        
        # Check various feature thresholds
        if features.get('threat_count', 0) > 0:
            factors.append('active_threats')
        
        if features.get('high_severity_threats', 0) > 0:
            factors.append('high_severity_threats')
        
        if features.get('is_ics_protocol', 0) > 0:
            factors.append('ics_protocol_targeted')
        
        if features.get('is_authorized_ip', 0) == 0:
            factors.append('unauthorized_source')
        
        if features.get('syn_flag', 0) > 0 and features.get('ack_flag', 0) == 0:
            factors.append('suspicious_tcp_flags')
        
        if features.get('source_threat_count', 0) > 5:
            factors.append('source_threat_history')
        
        return factors
    
    def _generate_risk_description(self, risk_score: float, factors: List[str]) -> str:
        """Generate human-readable risk description."""
        if risk_score >= 0.8:
            level = "Critical"
        elif risk_score >= 0.6:
            level = "High"
        elif risk_score >= 0.4:
            level = "Medium"
        else:
            level = "Low"
        
        description = f"{level} risk detected"
        
        if factors:
            description += f" due to: {', '.join(factors)}"
        
        return description
    
    def _save_model(self, model_name: str, model, scaler):
        """Save trained model to disk."""
        try:
            model_file = self.model_path / f"{model_name}_model.pkl"
            scaler_file = self.model_path / f"{model_name}_scaler.pkl"
            
            with open(model_file, 'wb') as f:
                pickle.dump(model, f)
            
            with open(scaler_file, 'wb') as f:
                pickle.dump(scaler, f)
            
            logger.info(f"Saved {model_name} model to {model_file}")
            
        except Exception as e:
            logger.error(f"Error saving {model_name} model: {e}")
    
    def _load_model(self, model_name: str):
        """Load trained model from disk."""
        try:
            model_file = self.model_path / f"{model_name}_model.pkl"
            scaler_file = self.model_path / f"{model_name}_scaler.pkl"
            
            if model_file.exists() and scaler_file.exists():
                with open(model_file, 'rb') as f:
                    model = pickle.load(f)
                
                with open(scaler_file, 'rb') as f:
                    scaler = pickle.load(f)
                
                self.models[model_name] = model
                self.scalers[model_name] = scaler
                
                logger.info(f"Loaded {model_name} model from {model_file}")
                return True
            
        except Exception as e:
            logger.error(f"Error loading {model_name} model: {e}")
        
        return False
    
    async def start(self):
        """Start the ML risk scorer service."""
        logger.info("Starting ML risk scorer service")
        
        # Initialize models
        self._initialize_models()
        
        # Load pre-trained models if available
        for model_type in self.model_types:
            self._load_model(model_type)
        
        # Start periodic model retraining
        asyncio.create_task(self._periodic_retraining())
    
    async def _periodic_retraining(self):
        """Periodically retrain models with new data."""
        retrain_interval = self.config.get('retrain_interval', 3600)  # 1 hour
        
        while True:
            try:
                await asyncio.sleep(retrain_interval)
                
                # Check if we have enough new data
                if len(self.training_data) > 100:
                    logger.info("Starting periodic model retraining...")
                    self.train_models(self.training_data)
                
            except Exception as e:
                logger.error(f"Error in periodic retraining: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
    
    async def stop(self):
        """Stop the ML risk scorer service."""
        logger.info("Stopping ML risk scorer service")
    
    def get_performance_metrics(self) -> Dict[str, ModelPerformance]:
        """Get performance metrics for all models."""
        return self.performance_metrics
    
    def get_recent_risk_scores(self, limit: int = 100) -> List[Dict]:
        """Get recent risk assessment results."""
        return [asdict(score) for score in self.risk_scores[-limit:]]
    
    def add_training_data(self, packet_data: Dict, is_threat: bool, threat_data: List[Dict] = None):
        """Add data point for model training."""
        training_sample = {
            'packet_data': packet_data,
            'is_threat': is_threat,
            'threat_data': threat_data or []
        }
        
        self.training_data.append(training_sample)
        
        # Limit training data size
        if len(self.training_data) > 10000:
            self.training_data = self.training_data[-5000:] 