"""
RESTful API for ICS cybersecurity system.
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.graph_analysis.attack_graph import Node, Edge
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from loguru import logger


# Pydantic models for API requests/responses
class ThreatData(BaseModel):
    """Threat data model."""
    source_ip: str
    destination_ip: str
    threat_type: str
    severity: str = Field(default="medium")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str = ""
    mitre_technique: Optional[str] = None
    timestamp: Optional[float] = None


class RiskAssessment(BaseModel):
    """Risk assessment model."""
    source_ip: str
    destination_ip: str
    risk_score: float = Field(ge=0.0, le=1.0)
    threat_level: str
    confidence: float = Field(ge=0.0, le=1.0)
    contributing_factors: List[str] = []
    description: str = ""


class MitigationRequest(BaseModel):
    """Mitigation request model."""
    threat_data: ThreatData
    response_level: str = Field(default="medium")
    auto_execute: bool = Field(default=True)
    priority: int = Field(default=3, ge=1, le=5)


class SystemStatus(BaseModel):
    """System status model."""
    overall_status: str
    components: Dict[str, str]
    uptime: float
    last_update: str
    statistics: Dict[str, Any]


class GraphNode(BaseModel):
    """Graph node model."""
    id: str
    type: str
    ip_address: str
    hostname: str
    criticality: float = Field(ge=0.0, le=1.0)
    vulnerabilities: List[str] = []
    location: str = ""
    description: str = ""


class GraphEdge(BaseModel):
    """Graph edge model."""
    source: str
    target: str
    protocol: str
    port: int
    attack_probability: float = Field(default=0.5, ge=0.0, le=1.0)
    impact: float = Field(default=0.5, ge=0.0, le=1.0)
    vulnerability: Optional[str] = None
    description: str = ""


class AttackPath(BaseModel):
    """Attack path model."""
    path_id: str
    nodes: List[str]
    total_risk: float = Field(ge=0.0, le=1.0)
    attack_steps: List[str] = []
    mitre_techniques: List[str] = []
    estimated_time: int = Field(ge=0)


# Security
security = HTTPBearer()


def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    """Verify API key."""
    # In a real implementation, this would check against a database or config
    valid_keys = ["test-api-key-123", "admin-key-456"]
    return credentials.credentials in valid_keys


def create_api_app(components: Dict[str, Any]) -> FastAPI:
    """Create the FastAPI application."""
    
    app = FastAPI(
        title="ICS Cybersecurity API",
        description="RESTful API for Industrial Control System cybersecurity",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register routes
    register_api_routes(app, components)
    
    logger.info("API application created")
    return app


def register_api_routes(app: FastAPI, components: Dict[str, Any]):
    """Register all API routes."""
    
    @app.get("/", response_model=Dict[str, str])
    async def root():
        """Root endpoint."""
        return {
            "message": "ICS Cybersecurity API",
            "version": "1.0.0",
            "status": "operational"
        }
    
    @app.get("/health", response_model=Dict[str, Any])
    async def health_check():
        """Health check endpoint."""
        try:
            # Check component health
            component_status = {}
            for name, component in components.items():
                if hasattr(component, 'running'):
                    component_status[name] = "running" if component.running else "stopped"
                else:
                    component_status[name] = "unknown"
            
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "components": component_status,
                "uptime": time.time()  # In a real app, track actual uptime
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise HTTPException(status_code=500, detail="Health check failed")
    
    # Threat endpoints
    @app.get("/threats", response_model=List[Dict[str, Any]])
    async def get_threats(
        limit: int = 100,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        time_range: Optional[str] = "24h",
        api_key: bool = Depends(verify_api_key)
    ):
        """Get recent threats."""
        try:
            network_monitor = components.get('network_monitor')
            if not network_monitor:
                raise HTTPException(status_code=503, detail="Network monitor not available")
            
            threats = network_monitor.get_recent_threats(limit=limit)
            
            # Apply filters
            if severity:
                threats = [t for t in threats if t.get('severity') == severity]
            
            if source_ip:
                threats = [t for t in threats if source_ip in t.get('source_ip', '')]
            
            # Filter by time range
            if time_range:
                cutoff_time = time.time() - parse_time_range(time_range).total_seconds()
                threats = [t for t in threats if t.get('timestamp', 0) > cutoff_time]
            
            return threats
            
        except Exception as e:
            logger.error(f"Error getting threats: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve threats")
    
    @app.post("/threats", response_model=Dict[str, Any])
    async def create_threat(
        threat: ThreatData,
        api_key: bool = Depends(verify_api_key)
    ):
        """Create a new threat."""
        try:
            # Add timestamp if not provided
            if not threat.timestamp:
                threat.timestamp = time.time()
            
            # In a real implementation, this would be stored in the database
            threat_dict = threat.dict()
            
            # Notify components
            network_monitor = components.get('network_monitor')
            if network_monitor and hasattr(network_monitor, 'add_threat_callback'):
                # Trigger threat callbacks
                pass
            
            return {
                "message": "Threat created successfully",
                "threat_id": f"threat_{int(threat.timestamp)}",
                "threat": threat_dict
            }
            
        except Exception as e:
            logger.error(f"Error creating threat: {e}")
            raise HTTPException(status_code=500, detail="Failed to create threat")
    
    # Risk assessment endpoints
    @app.post("/risk/assess", response_model=RiskAssessment)
    async def assess_risk(
        packet_data: Dict[str, Any],
        threat_data: Optional[List[Dict[str, Any]]] = None,
        api_key: bool = Depends(verify_api_key)
    ):
        """Assess risk for packet data."""
        try:
            risk_scorer = components.get('risk_scorer')
            if not risk_scorer:
                raise HTTPException(status_code=503, detail="Risk scorer not available")
            
            risk_assessment = risk_scorer.assess_risk(packet_data, threat_data)
            
            return RiskAssessment(
                source_ip=risk_assessment.source_ip,
                destination_ip=risk_assessment.destination_ip,
                risk_score=risk_assessment.risk_score,
                threat_level=risk_assessment.threat_level,
                confidence=risk_assessment.confidence,
                contributing_factors=risk_assessment.contributing_factors,
                description=risk_assessment.description
            )
            
        except Exception as e:
            logger.error(f"Error assessing risk: {e}")
            raise HTTPException(status_code=500, detail="Failed to assess risk")
    
    @app.get("/risk/scores", response_model=List[Dict[str, Any]])
    async def get_risk_scores(
        limit: int = 100,
        api_key: bool = Depends(verify_api_key)
    ):
        """Get recent risk assessments."""
        try:
            risk_scorer = components.get('risk_scorer')
            if not risk_scorer:
                raise HTTPException(status_code=503, detail="Risk scorer not available")
            
            return risk_scorer.get_recent_risk_scores(limit=limit)
            
        except Exception as e:
            logger.error(f"Error getting risk scores: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve risk scores")
    
    @app.get("/risk/performance", response_model=Dict[str, Any])
    async def get_model_performance(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get ML model performance metrics."""
        try:
            risk_scorer = components.get('risk_scorer')
            if not risk_scorer:
                raise HTTPException(status_code=503, detail="Risk scorer not available")
            
            return risk_scorer.get_performance_metrics()
            
        except Exception as e:
            logger.error(f"Error getting model performance: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve model performance")
    
    # Graph analysis endpoints
    @app.get("/graph/nodes", response_model=List[GraphNode])
    async def get_graph_nodes(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get all nodes in the attack graph."""
        try:
            graph_analyzer = components.get('graph_analyzer')
            if not graph_analyzer:
                raise HTTPException(status_code=503, detail="Graph analyzer not available")
            
            nodes = []
            for node in graph_analyzer.nodes.values():
                nodes.append(GraphNode(
                    id=node.id,
                    type=node.type,
                    ip_address=node.ip_address,
                    hostname=node.hostname,
                    criticality=node.criticality,
                    vulnerabilities=node.vulnerabilities,
                    location=node.location,
                    description=node.description
                ))
            
            return nodes
            
        except Exception as e:
            logger.error(f"Error getting graph nodes: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve graph nodes")
    
    @app.get("/graph/edges", response_model=List[GraphEdge])
    async def get_graph_edges(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get all edges in the attack graph."""
        try:
            graph_analyzer = components.get('graph_analyzer')
            if not graph_analyzer:
                raise HTTPException(status_code=503, detail="Graph analyzer not available")
            
            edges = []
            for edge in graph_analyzer.edges.values():
                edges.append(GraphEdge(
                    source=edge.source,
                    target=edge.target,
                    protocol=edge.protocol,
                    port=edge.port,
                    attack_probability=edge.attack_probability,
                    impact=edge.impact,
                    vulnerability=edge.vulnerability,
                    description=edge.description
                ))
            
            return edges
            
        except Exception as e:
            logger.error(f"Error getting graph edges: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve graph edges")
    
    @app.post("/graph/paths", response_model=List[AttackPath])
    async def find_attack_paths(
        source_node: str,
        target_node: str,
        max_paths: int = 10,
        api_key: bool = Depends(verify_api_key)
    ):
        """Find attack paths between two nodes."""
        try:
            graph_analyzer = components.get('graph_analyzer')
            if not graph_analyzer:
                raise HTTPException(status_code=503, detail="Graph analyzer not available")
            
            attack_paths = graph_analyzer.find_attack_paths(source_node, target_node, max_paths)
            
            return [
                AttackPath(
                    path_id=path.path_id,
                    nodes=path.nodes,
                    total_risk=path.total_risk,
                    attack_steps=path.attack_steps,
                    mitre_techniques=path.mitre_techniques,
                    estimated_time=path.estimated_time
                )
                for path in attack_paths
            ]
            
        except Exception as e:
            logger.error(f"Error finding attack paths: {e}")
            raise HTTPException(status_code=500, detail="Failed to find attack paths")
    
    @app.get("/graph/critical-nodes", response_model=List[Dict[str, Any]])
    async def get_critical_nodes(
        top_k: int = 10,
        api_key: bool = Depends(verify_api_key)
    ):
        """Get most critical nodes in the network."""
        try:
            graph_analyzer = components.get('graph_analyzer')
            if not graph_analyzer:
                raise HTTPException(status_code=503, detail="Graph analyzer not available")
            
            critical_nodes = graph_analyzer.identify_critical_nodes(top_k)
            
            return [
                {
                    "node_id": node_id,
                    "score": score,
                    "node_info": graph_analyzer.nodes.get(node_id, {})
                }
                for node_id, score in critical_nodes
            ]
            
        except Exception as e:
            logger.error(f"Error getting critical nodes: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve critical nodes")
    
    @app.get("/graph/statistics", response_model=Dict[str, Any])
    async def get_graph_statistics(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get graph statistics."""
        try:
            graph_analyzer = components.get('graph_analyzer')
            if not graph_analyzer:
                raise HTTPException(status_code=503, detail="Graph analyzer not available")
            
            return graph_analyzer.get_graph_statistics()
            
        except Exception as e:
            logger.error(f"Error getting graph statistics: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve graph statistics")
    
    # Response endpoints
    @app.post("/response/execute", response_model=Dict[str, Any])
    async def execute_response(
        request: MitigationRequest,
        api_key: bool = Depends(verify_api_key)
    ):
        """Execute threat response."""
        try:
            response_system = components.get('response_system')
            if not response_system:
                raise HTTPException(status_code=503, detail="Response system not available")
            
            # Convert threat data
            threat_dict = request.threat_data.dict()
            
            # Create system status
            system_status = {
                "overall_status": "normal",
                "components": {"response_system": "active"}
            }
            
            # Execute response
            result = await response_system.execute_response(threat_dict, system_status)
            
            if result:
                return {
                    "message": "Response executed successfully",
                    "action_id": result.action_id,
                    "success": result.success,
                    "execution_time": result.execution_time,
                    "description": result.description
                }
            else:
                return {
                    "message": "No response strategy selected",
                    "action_id": None,
                    "success": False,
                    "execution_time": 0,
                    "description": "No applicable response strategy"
                }
            
        except Exception as e:
            logger.error(f"Error executing response: {e}")
            raise HTTPException(status_code=500, detail="Failed to execute response")
    
    @app.get("/response/history", response_model=List[Dict[str, Any]])
    async def get_response_history(
        limit: int = 50,
        api_key: bool = Depends(verify_api_key)
    ):
        """Get response history."""
        try:
            response_system = components.get('response_system')
            if not response_system:
                raise HTTPException(status_code=503, detail="Response system not available")
            
            return response_system.get_recent_responses(limit=limit)
            
        except Exception as e:
            logger.error(f"Error getting response history: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve response history")
    
    @app.get("/response/statistics", response_model=Dict[str, Any])
    async def get_response_statistics(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get response system statistics."""
        try:
            response_system = components.get('response_system')
            if not response_system:
                raise HTTPException(status_code=503, detail="Response system not available")
            
            return response_system.get_response_statistics()
            
        except Exception as e:
            logger.error(f"Error getting response statistics: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve response statistics")
    
    @app.get("/response/q-table", response_model=Dict[str, Any])
    async def get_q_table(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get Q-Learning table."""
        try:
            response_system = components.get('response_system')
            if not response_system:
                raise HTTPException(status_code=503, detail="Response system not available")
            
            return response_system.get_q_table()
            
        except Exception as e:
            logger.error(f"Error getting Q-table: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve Q-table")
    
    # System endpoints
    @app.get("/system/status", response_model=SystemStatus)
    async def get_system_status(
        api_key: bool = Depends(verify_api_key)
    ):
        """Get overall system status."""
        try:
            # Get component statuses
            component_statuses = {}
            for name, component in components.items():
                if hasattr(component, 'running'):
                    component_statuses[name] = "running" if component.running else "stopped"
                else:
                    component_statuses[name] = "unknown"
            
            # Get statistics
            statistics = {}
            
            # Network statistics
            network_monitor = components.get('network_monitor')
            if network_monitor and hasattr(network_monitor, 'get_statistics'):
                statistics['network'] = network_monitor.get_statistics()
            
            # Response statistics
            response_system = components.get('response_system')
            if response_system and hasattr(response_system, 'get_response_statistics'):
                statistics['response'] = response_system.get_response_statistics()
            
            # Graph statistics
            graph_analyzer = components.get('graph_analyzer')
            if graph_analyzer and hasattr(graph_analyzer, 'get_graph_statistics'):
                statistics['graph'] = graph_analyzer.get_graph_statistics()
            
            # Determine overall status
            if all(status == "running" for status in component_statuses.values()):
                overall_status = "operational"
            elif any(status == "running" for status in component_statuses.values()):
                overall_status = "degraded"
            else:
                overall_status = "down"
            
            return SystemStatus(
                overall_status=overall_status,
                components=component_statuses,
                uptime=time.time(),  # In real app, track actual uptime
                last_update=datetime.now().isoformat(),
                statistics=statistics
            )
            
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            raise HTTPException(status_code=500, detail="Failed to retrieve system status")
    
    @app.post("/system/export")
    async def export_system_data(
        data_type: str = "all",
        format: str = "json",
        api_key: bool = Depends(verify_api_key)
    ):
        """Export system data."""
        try:
            export_data = {}
            
            if data_type in ["all", "threats"]:
                network_monitor = components.get('network_monitor')
                if network_monitor:
                    export_data['threats'] = network_monitor.get_recent_threats(limit=1000)
            
            if data_type in ["all", "risk"]:
                risk_scorer = components.get('risk_scorer')
                if risk_scorer:
                    export_data['risk_scores'] = risk_scorer.get_recent_risk_scores(limit=1000)
            
            if data_type in ["all", "responses"]:
                response_system = components.get('response_system')
                if response_system:
                    export_data['responses'] = response_system.get_recent_responses(limit=1000)
            
            if data_type in ["all", "graph"]:
                graph_analyzer = components.get('graph_analyzer')
                if graph_analyzer:
                    export_data['graph'] = {
                        'nodes': [asdict(node) for node in graph_analyzer.nodes.values()],
                        'edges': [asdict(edge) for edge in graph_analyzer.edges.values()],
                        'statistics': graph_analyzer.get_graph_statistics()
                    }
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"export_{data_type}_{timestamp}.json"
            filepath = Path("exports") / filename
            filepath.parent.mkdir(exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            return {
                "message": "Data exported successfully",
                "filename": filename,
                "filepath": str(filepath),
                "data_types": list(export_data.keys())
            }
            
        except Exception as e:
            logger.error(f"Error exporting data: {e}")
            raise HTTPException(status_code=500, detail="Failed to export data")
    
    # Error handlers
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc: HTTPException):
        return {
            "error": "Not found",
            "message": "The requested resource was not found",
            "path": request.url.path
        }
    
    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: HTTPException):
        return {
            "error": "Internal server error",
            "message": "An internal server error occurred",
            "path": request.url.path
        }


def parse_time_range(time_range: str) -> timedelta:
    """Parse time range string to timedelta."""
    if time_range == "1h":
        return timedelta(hours=1)
    elif time_range == "6h":
        return timedelta(hours=6)
    elif time_range == "24h":
        return timedelta(days=1)
    elif time_range == "7d":
        return timedelta(days=7)
    else:
        return timedelta(hours=24)  # Default to 24 hours 