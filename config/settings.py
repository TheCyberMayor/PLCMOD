"""
Configuration management for ICS Cybersecurity System.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_analysis.attack_graph import Node, Edge
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class NetworkConfig(BaseSettings):
    """Network monitoring configuration."""
    
    # Packet capture settings
    interface: str = Field(default="eth0", description="Network interface to monitor")
    packet_count: int = Field(default=1000, description="Number of packets to capture")
    timeout: int = Field(default=30, description="Capture timeout in seconds")
    
    # Protocol filters
    protocols: list = Field(default=["modbus", "ethernet/ip", "dnp3"], 
                           description="ICS protocols to monitor")
    
    # Log collection
    log_sources: list = Field(default=["/var/log/syslog", "/var/log/auth.log"],
                             description="System log sources")
    log_interval: int = Field(default=60, description="Log collection interval in seconds")
    
    # MITRE ATT&CK integration
    mitre_attack_db: str = Field(default="data/mitre_attack_ics.json",
                                description="MITRE ATT&CK ICS database path")
    
    authorized_ips: list = Field(default=[], description="List of authorized IP addresses")
    
    class Config:
        env_prefix = "NETWORK_"


class GraphConfig(BaseSettings):
    """Graph analysis configuration."""
    
    # Neo4j database settings
    neo4j_uri: str = Field(default="bolt://localhost:7687", description="Neo4j database URI")
    neo4j_user: str = Field(default="neo4j", description="Neo4j username")
    neo4j_password: str = Field(default="password", description="Neo4j password")
    
    # Graph analysis parameters
    centrality_metrics: list = Field(default=["betweenness", "closeness", "eigenvector"],
                                    description="Centrality metrics to compute")
    max_path_length: int = Field(default=10, description="Maximum attack path length")
    
    # Visualization settings
    graph_layout: str = Field(default="spring", description="Graph layout algorithm")
    node_size: int = Field(default=20, description="Default node size")
    edge_width: int = Field(default=2, description="Default edge width")
    
    class Config:
        env_prefix = "GRAPH_"


class MLConfig(BaseSettings):
    """Machine learning configuration."""
    
    # Model settings
    models: list = Field(default=["random_forest", "svm", "xgboost"],
                        description="ML models to use")
    
    # Training parameters
    test_size: float = Field(default=0.2, description="Test set size ratio")
    random_state: int = Field(default=42, description="Random seed")
    
    # Feature engineering
    feature_window: int = Field(default=60, description="Feature extraction window in seconds")
    anomaly_threshold: float = Field(default=0.8, description="Anomaly detection threshold")
    
    # Model storage
    model_path: str = Field(default="models/", description="Path to store trained models")
    
    class Config:
        env_prefix = "ML_"


class MitigationConfig(BaseSettings):
    """Threat mitigation configuration."""
    
    # Response strategies
    response_levels: Dict[str, list] = Field(
        default={
            "low": ["log_alert", "increase_monitoring"],
            "medium": ["block_ip", "isolate_device", "update_rules"],
            "high": ["emergency_shutdown", "full_lockdown", "alert_authorities"]
        },
        description="Response strategies by threat level"
    )
    
    # Reinforcement learning
    rl_algorithm: str = Field(default="q_learning", description="RL algorithm to use")
    learning_rate: float = Field(default=0.1, description="RL learning rate")
    discount_factor: float = Field(default=0.9, description="RL discount factor")
    
    # Automation settings
    auto_response: bool = Field(default=True, description="Enable automatic responses")
    manual_approval: bool = Field(default=False, description="Require manual approval for high-level threats")
    
    class Config:
        env_prefix = "MITIGATION_"


class APIConfig(BaseSettings):
    """API configuration."""
    
    host: str = Field(default="0.0.0.0", description="API host")
    port: int = Field(default=8000, description="API port")
    
    # Authentication
    api_key_header: str = Field(default="X-API-Key", description="API key header name")
    enable_auth: bool = Field(default=True, description="Enable API authentication")
    
    # Rate limiting
    rate_limit: int = Field(default=100, description="Requests per minute")
    
    # CORS
    cors_origins: list = Field(default=["*"], description="Allowed CORS origins")
    
    class Config:
        env_prefix = "API_"


class DashboardConfig(BaseSettings):
    """Dashboard configuration."""
    
    host: str = Field(default="0.0.0.0", description="Dashboard host")
    port: int = Field(default=8050, description="Dashboard port")
    
    # Theme and appearance
    theme: str = Field(default="dark", description="Dashboard theme")
    refresh_interval: int = Field(default=5000, description="Refresh interval in milliseconds")
    
    # Charts and visualizations
    max_data_points: int = Field(default=1000, description="Maximum data points in charts")
    chart_height: int = Field(default=400, description="Default chart height")
    
    class Config:
        env_prefix = "DASHBOARD_"


class ValidationConfig(BaseSettings):
    """Model validation configuration."""
    
    # Test environments
    testbeds: list = Field(default=["minicps", "digital_twin"], description="Available test environments")
    
    # Performance metrics
    metrics: list = Field(default=["accuracy", "precision", "recall", "f1", "mcc"],
                         description="Performance metrics to compute")
    
    # Testing parameters
    test_duration: int = Field(default=3600, description="Test duration in seconds")
    attack_scenarios: list = Field(default=["reconnaissance", "initial_access", "execution"],
                                  description="Attack scenarios to test")
    
    class Config:
        env_prefix = "VALIDATION_"


class SystemConfig:
    """Main system configuration."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration."""
        self.config_path = config_path or "config/settings.yaml"
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file and environment variables."""
        # Load from YAML file if it exists
        if Path(self.config_path).exists():
            with open(self.config_path, 'r') as f:
                yaml_config = yaml.safe_load(f)
        else:
            yaml_config = {}
        
        # Initialize configuration objects
        self.network = NetworkConfig(**yaml_config.get('network', {}))
        self.graph = GraphConfig(**yaml_config.get('graph', {}))
        self.ml_models = MLConfig(**yaml_config.get('ml_models', {}))
        self.mitigation = MitigationConfig(**yaml_config.get('mitigation', {}))
        self.api = APIConfig(**yaml_config.get('api', {}))
        self.dashboard = DashboardConfig(**yaml_config.get('dashboard', {}))
        self.validation = ValidationConfig(**yaml_config.get('validation', {}))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'network': self.network.dict(),
            'graph': self.graph.dict(),
            'ml_models': self.ml_models.dict(),
            'mitigation': self.mitigation.dict(),
            'api': self.api.dict(),
            'dashboard': self.dashboard.dict(),
            'validation': self.validation.dict()
        }
    
    def save_config(self, path: Optional[str] = None):
        """Save configuration to YAML file."""
        config_path = path or self.config_path
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, 'w') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, indent=2)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration and return as dictionary."""
    config = SystemConfig(config_path)
    return config.to_dict()


def create_default_config(config_path: str = "config/settings.yaml"):
    """Create default configuration file."""
    config = SystemConfig()
    config.save_config(config_path)
    return config


if __name__ == "__main__":
    # Create default configuration
    create_default_config()
    print("Default configuration created at config/settings.yaml") 