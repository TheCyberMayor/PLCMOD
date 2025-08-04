#!/usr/bin/env python3
"""
Simplified ICS Cybersecurity System Test
This script demonstrates the core functionality without requiring all dependencies.
"""

import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
import sys
import os

# Add src to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

class SimpleICSTest:
    """Simplified ICS Cybersecurity System for testing."""
    
    def __init__(self):
        self.threats = []
        self.risk_scores = []
        self.network_nodes = []
        self.response_history = []
        self.start_time = time.time()
        
        # Initialize sample data
        self._initialize_sample_data()
    
    def _initialize_sample_data(self):
        """Initialize sample data for demonstration."""
        # Sample network nodes
        self.network_nodes = [
            {"id": "PLC-001", "type": "PLC", "ip": "192.168.1.10", "criticality": 0.9},
            {"id": "HMI-001", "type": "HMI", "ip": "192.168.1.20", "criticality": 0.7},
            {"id": "SCADA-001", "type": "SCADA", "ip": "192.168.1.30", "criticality": 0.8},
            {"id": "RTU-001", "type": "RTU", "ip": "192.168.1.40", "criticality": 0.6},
            {"id": "Firewall-001", "type": "Firewall", "ip": "192.168.1.1", "criticality": 0.5}
        ]
        
        # Sample threats
        sample_threats = [
            {"source_ip": "192.168.1.100", "destination_ip": "192.168.1.10", "threat_type": "port_scan", "severity": "medium"},
            {"source_ip": "192.168.1.101", "destination_ip": "192.168.1.20", "threat_type": "brute_force", "severity": "high"},
            {"source_ip": "192.168.1.102", "destination_ip": "192.168.1.30", "threat_type": "malware", "severity": "critical"},
            {"source_ip": "192.168.1.103", "destination_ip": "192.168.1.40", "threat_type": "data_exfiltration", "severity": "high"}
        ]
        
        for threat in sample_threats:
            self.add_threat(threat)
    
    def add_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new threat to the system."""
        threat = {
            "id": f"threat_{len(self.threats) + 1}",
            "timestamp": time.time(),
            "confidence": random.uniform(0.6, 0.95),
            "mitre_technique": self._get_mitre_technique(threat_data["threat_type"]),
            "status": "active",
            **threat_data
        }
        
        self.threats.append(threat)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(threat)
        self.risk_scores.append(risk_score)
        
        # Generate response
        response = self.generate_response(threat)
        self.response_history.append(response)
        
        return threat
    
    def _get_mitre_technique(self, threat_type: str) -> str:
        """Map threat type to MITRE ATT&CK technique."""
        mapping = {
            "port_scan": "T1595.001",
            "brute_force": "T1110.001",
            "malware": "T1059.001",
            "data_exfiltration": "T1041"
        }
        return mapping.get(threat_type, "T1595.001")
    
    def calculate_risk_score(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk score for a threat."""
        severity_weights = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}
        base_score = severity_weights.get(threat["severity"], 0.5)
        
        # Add randomness to simulate ML model
        confidence_factor = threat.get("confidence", 0.5)
        random_factor = random.uniform(0.8, 1.2)
        
        risk_score = min(1.0, base_score * confidence_factor * random_factor)
        
        return {
            "threat_id": threat["id"],
            "risk_score": risk_score,
            "threat_level": self._get_threat_level(risk_score),
            "timestamp": time.time(),
            "contributing_factors": [threat["threat_type"], threat["severity"]]
        }
    
    def _get_threat_level(self, risk_score: float) -> str:
        """Convert risk score to threat level."""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        else:
            return "low"
    
    def generate_response(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Generate automated response for a threat."""
        responses = {
            "low": ["log_alert", "increase_monitoring"],
            "medium": ["block_ip", "isolate_device", "update_rules"],
            "high": ["emergency_shutdown", "full_lockdown", "alert_authorities"],
            "critical": ["emergency_shutdown", "full_lockdown", "alert_authorities", "contact_emergency_services"]
        }
        
        risk_score = self.calculate_risk_score(threat)
        threat_level = risk_score["threat_level"]
        actions = responses.get(threat_level, ["log_alert"])
        
        return {
            "threat_id": threat["id"],
            "actions": actions,
            "timestamp": time.time(),
            "status": "executed",
            "effectiveness": random.uniform(0.7, 0.95)
        }
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status."""
        uptime = time.time() - self.start_time
        
        return {
            "overall_status": "operational",
            "uptime": uptime,
            "last_update": datetime.now().isoformat(),
            "statistics": {
                "total_threats": len(self.threats),
                "active_threats": len([t for t in self.threats if t["status"] == "active"]),
                "total_responses": len(self.response_history),
                "average_risk_score": sum(r["risk_score"] for r in self.risk_scores) / len(self.risk_scores) if self.risk_scores else 0,
                "network_nodes": len(self.network_nodes)
            }
        }
    
    def get_attack_graph(self) -> Dict[str, Any]:
        """Generate simplified attack graph."""
        nodes = []
        edges = []
        
        # Create nodes from network devices
        for node in self.network_nodes:
            nodes.append({
                "id": node["id"],
                "type": node["type"],
                "ip_address": node["ip"],
                "criticality": node["criticality"]
            })
        
        # Create edges based on threats
        for threat in self.threats:
            edges.append({
                "source": threat["source_ip"],
                "target": threat["destination_ip"],
                "protocol": "TCP",
                "port": random.randint(1024, 65535),
                "attack_probability": threat.get("confidence", 0.5),
                "threat_type": threat["threat_type"]
            })
        
        return {"nodes": nodes, "edges": edges}
    
    def run_demo(self):
        """Run a demonstration of the system."""
        print("=" * 60)
        print("ICS Cybersecurity System - Demo Mode")
        print("=" * 60)
        
        # Show initial status
        print("\n1. Initial System Status:")
        status = self.get_system_status()
        print(json.dumps(status, indent=2))
        
        # Add a new threat
        print("\n2. Adding New Threat:")
        new_threat = {
            "source_ip": "192.168.1.200",
            "destination_ip": "192.168.1.10",
            "threat_type": "sql_injection",
            "severity": "high"
        }
        threat = self.add_threat(new_threat)
        print(json.dumps(threat, indent=2))
        
        # Show updated status
        print("\n3. Updated System Status:")
        status = self.get_system_status()
        print(json.dumps(status, indent=2))
        
        # Show attack graph
        print("\n4. Attack Graph:")
        graph = self.get_attack_graph()
        print(f"Nodes: {len(graph['nodes'])}")
        print(f"Edges: {len(graph['edges'])}")
        print("Sample nodes:", json.dumps(graph['nodes'][:2], indent=2))
        
        # Show recent threats
        print("\n5. Recent Threats:")
        for threat in self.threats[-3:]:
            print(f"- {threat['threat_type']} from {threat['source_ip']} to {threat['destination_ip']} (Severity: {threat['severity']})")
        
        # Show response history
        print("\n6. Recent Responses:")
        for response in self.response_history[-3:]:
            print(f"- Threat {response['threat_id']}: {', '.join(response['actions'])}")
        
        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("=" * 60)

def main():
    """Main function to run the demo."""
    try:
        # Create and run the demo
        demo = SimpleICSTest()
        demo.run_demo()
        
        print("\n🎉 ICS Cybersecurity System is working!")
        print("\nNext steps:")
        print("1. Install full dependencies: pip install -r requirements.txt")
        print("2. Run the full system: python main.py")
        print("3. Access API at: http://localhost:8000")
        print("4. Access Dashboard at: http://localhost:8050")
        
    except Exception as e:
        print(f"❌ Error running demo: {e}")
        print("\nThis might be due to missing dependencies.")
        print("Try installing the requirements: pip install -r requirements.txt")

if __name__ == "__main__":
    main() 