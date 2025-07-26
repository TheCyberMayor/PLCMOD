#!/usr/bin/env python3
"""
ICS Cybersecurity System - Main Entry Point

This module orchestrates all components of the ICS cybersecurity system:
1. Data Collection
2. Graph Analysis
3. Risk Assessment
4. Threat Mitigation
5. Dashboard
6. API Server
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Dict, Any

from loguru import logger
import uvicorn
from fastapi import FastAPI

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

from src.data_collection.network_monitor import NetworkMonitor
from src.graph_analysis.attack_graph import AttackGraphAnalyzer
from src.risk_assessment.ml_risk_scorer import MLRiskScorer
from src.threat_mitigation.response_system import ThreatResponseSystem
from src.dashboard.app import create_dashboard_app
from src.api.main import create_api_app
from src.validation.model_validator import ModelValidator
from config.settings import load_config


class ICSCybersecuritySystem:
    """Main orchestrator for the ICS cybersecurity system."""
    
    def __init__(self, config_path: str = "config/settings.yaml"):
        """Initialize the ICS cybersecurity system."""
        self.config = load_config(config_path)
        self.components: Dict[str, Any] = {}
        self.running = False
        
        # Setup logging
        logger.add(
            "logs/ics_system.log",
            rotation="1 day",
            retention="30 days",
            level="INFO"
        )
        
        logger.info("Initializing ICS Cybersecurity System")
        
    async def initialize_components(self):
        """Initialize all system components."""
        try:
            # 1. Data Collection
            logger.info("Initializing Network Monitor")
            self.components['network_monitor'] = NetworkMonitor(self.config['network'])
            
            # 2. Graph Analysis
            logger.info("Initializing Attack Graph Analyzer")
            self.components['graph_analyzer'] = AttackGraphAnalyzer(self.config['graph'])
            
            # 3. Risk Assessment
            logger.info("Initializing ML Risk Scorer")
            self.components['risk_scorer'] = MLRiskScorer(self.config['ml_models'])
            
            # 4. Threat Mitigation
            logger.info("Initializing Threat Response System")
            self.components['response_system'] = ThreatResponseSystem(self.config['mitigation'])
            
            # 5. Model Validation
            logger.info("Initializing Model Validator")
            self.components['validator'] = ModelValidator(self.config['validation'])
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    async def start_services(self):
        """Start all background services."""
        try:
            # Start network monitoring
            await self.components['network_monitor'].start()
            
            # Start graph analysis
            await self.components['graph_analyzer'].start()
            
            # Start risk assessment
            await self.components['risk_scorer'].start()
            
            # Start threat response system
            await self.components['response_system'].start()
            
            logger.info("All services started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start services: {e}")
            raise
    
    async def stop_services(self):
        """Stop all background services."""
        logger.info("Stopping all services...")
        
        for name, component in self.components.items():
            try:
                if hasattr(component, 'stop'):
                    await component.stop()
                logger.info(f"Stopped {name}")
            except Exception as e:
                logger.error(f"Error stopping {name}: {e}")
    
    def create_web_applications(self):
        """Create and configure web applications."""
        # Create API app
        api_app = create_api_app(self.components)
        
        # Create dashboard app
        dashboard_app = create_dashboard_app(self.components)
        
        return api_app, dashboard_app
    
    async def run(self):
        """Run the complete ICS cybersecurity system."""
        try:
            # Initialize components
            await self.initialize_components()
            
            # Start services
            await self.start_services()
            
            # Create web applications
            api_app, dashboard_app = self.create_web_applications()
            
            # Start only the API server (FastAPI)
            api_config = uvicorn.Config(
                api_app,
                host=self.config['api']['host'],
                port=self.config['api']['port'],
                log_level="info"
            )
            
            self.running = True
            logger.info("ICS Cybersecurity System is running")
            logger.info(f"API available at: http://{self.config['api']['host']}:{self.config['api']['port']}")
            logger.info(f"Dashboard available at: http://{self.config['dashboard']['host']}:{self.config['dashboard']['port']}")
            logger.info("To start the dashboard, run: python src/dashboard/app.py")
            
            # Run only the API server
            api_server = uvicorn.Server(api_config)
            await api_server.serve()
            
        except Exception as e:
            logger.error(f"System error: {e}")
            await self.stop_services()
            raise
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down gracefully...")
            self.running = False
            asyncio.create_task(self.stop_services())
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


async def main():
    """Main entry point."""
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Initialize and run the system
    system = ICSCybersecuritySystem()
    system.setup_signal_handlers()
    
    try:
        await system.run()
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        await system.stop_services()


if __name__ == "__main__":
    asyncio.run(main()) 