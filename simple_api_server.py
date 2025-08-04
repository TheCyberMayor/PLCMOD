#!/usr/bin/env python3
"""
Simplified ICS Cybersecurity System API Server
This provides a basic API server for testing the system functionality.
"""

import json
import time
import random
from datetime import datetime
from typing import Dict, List, Any
import sys
import os

# Add src to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

try:
    from fastapi import FastAPI, HTTPException, Depends, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from pydantic import BaseModel, Field
    from loguru import logger
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    print("FastAPI not available. Install with: pip install fastapi uvicorn")
    FASTAPI_AVAILABLE = False

# Import our simple test class
from simple_test import SimpleICSTest

# Pydantic models
class ThreatData(BaseModel):
    """Threat data model."""
    source_ip: str
    destination_ip: str
    threat_type: str
    severity: str = Field(default="medium")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    description: str = ""

class SystemStatus(BaseModel):
    """System status model."""
    overall_status: str
    uptime: float
    last_update: str
    statistics: Dict[str, Any]

# Security
security = HTTPBearer()

def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    """Verify API key."""
    api_key = "test-api-key-123"  # Default test key
    return credentials.credentials == api_key

def create_api_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ICS Cybersecurity System API",
        description="Industrial Control System Cybersecurity Platform API",
        version="1.0.0"
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Initialize the ICS system
    ics_system = SimpleICSTest()
    
    @app.get("/", response_model=Dict[str, str])
    async def root():
        """Root endpoint."""
        return {
            "message": "ICS Cybersecurity System API",
            "version": "1.0.0",
            "status": "operational"
        }
    
    @app.get("/health", response_model=Dict[str, Any])
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "uptime": time.time() - ics_system.start_time,
            "version": "1.0.0"
        }
    
    @app.get("/threats", response_model=List[Dict[str, Any]])
    async def get_threats(
        limit: int = 100,
        severity: str = None,
        api_key: bool = Depends(verify_api_key)
    ):
        """Get threats."""
        threats = ics_system.threats
        
        if severity:
            threats = [t for t in threats if t["severity"] == severity]
        
        return threats[:limit]
    
    @app.post("/threats", response_model=Dict[str, Any])
    async def create_threat(
        threat: ThreatData,
        api_key: bool = Depends(verify_api_key)
    ):
        """Create a new threat."""
        threat_dict = threat.dict()
        new_threat = ics_system.add_threat(threat_dict)
        return {
            "message": "Threat created successfully",
            "threat": new_threat
        }
    
    @app.get("/system/status", response_model=SystemStatus)
    async def get_system_status(api_key: bool = Depends(verify_api_key)):
        """Get system status."""
        return ics_system.get_system_status()
    
    @app.get("/graph", response_model=Dict[str, Any])
    async def get_attack_graph(api_key: bool = Depends(verify_api_key)):
        """Get attack graph."""
        return ics_system.get_attack_graph()
    
    @app.get("/risk/scores", response_model=List[Dict[str, Any]])
    async def get_risk_scores(
        limit: int = 100,
        api_key: bool = Depends(verify_api_key)
    ):
        """Get risk scores."""
        return ics_system.risk_scores[:limit]
    
    @app.get("/response/history", response_model=List[Dict[str, Any]])
    async def get_response_history(
        limit: int = 50,
        api_key: bool = Depends(verify_api_key)
    ):
        """Get response history."""
        return ics_system.response_history[:limit]
    
    return app

def main():
    """Main function to run the API server."""
    if not FASTAPI_AVAILABLE:
        print("❌ FastAPI dependencies not available.")
        print("Install with: pip install -r requirements_minimal.txt")
        return
    
    print("🚀 Starting ICS Cybersecurity System API Server...")
    print("API will be available at: http://localhost:8000")
    print("API Key: test-api-key-123")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    
    app = create_api_app()
    
    # Run the server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )

if __name__ == "__main__":
    main() 